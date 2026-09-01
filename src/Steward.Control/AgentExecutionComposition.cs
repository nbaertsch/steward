using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Steward.Agents;
using Steward.Application;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;

namespace Steward.Control;

internal sealed class AgentExecutionOptions
{
    public bool Enabled { get; set; }
    public string Executable { get; set; } = string.Empty;
    public List<string> Arguments { get; set; } = [];
    public string WorkingRoot { get; set; } = string.Empty;
    public string PoolId { get; set; } = string.Empty;
    public int MaximumOutputBytes { get; set; } = 1024 * 1024;
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(1);
    public List<string> DeclaredTools { get; set; } = [];
    public Dictionary<string, string> EnvironmentManifest { get; set; } = [];

    public ValidatedAgentExecutionOptions Validate()
    {
        if (!Enabled) return new(false, string.Empty, [], string.Empty, default,
            MaximumOutputBytes, PollInterval, [], new Dictionary<string, string>());
        if (!Path.IsPathFullyQualified(Executable) || !File.Exists(Executable) ||
            Path.GetExtension(Executable) is ".cmd" or ".bat" or ".ps1" or ".sh")
            throw new InvalidOperationException("Agents executable must be an existing absolute non-shell program.");
        if (!Path.IsPathFullyQualified(WorkingRoot) || !Domain.PoolId.TryParse(PoolId, out var pool) ||
            MaximumOutputBytes is <= 0 or > 16 * 1024 * 1024 ||
            PollInterval <= TimeSpan.Zero || PollInterval > TimeSpan.FromMinutes(1) ||
            Arguments.Count > 128 || Arguments.Any(x => x.Length > 4096) ||
            DeclaredTools.Count > AgentLimits.MaximumEnvironmentEntries ||
            EnvironmentManifest.Count > AgentLimits.MaximumEnvironmentEntries)
            throw new InvalidOperationException("Agents runtime configuration is invalid.");
        return new(true, Path.GetFullPath(Executable), Arguments.ToArray(),
            Path.GetFullPath(WorkingRoot), pool, MaximumOutputBytes, PollInterval,
            DeclaredTools.ToArray(), new Dictionary<string, string>(EnvironmentManifest));
    }
}

internal sealed record ValidatedAgentExecutionOptions(
    bool Enabled,
    string Executable,
    IReadOnlyList<string> Arguments,
    string WorkingRoot,
    PoolId PoolId,
    int MaximumOutputBytes,
    TimeSpan PollInterval,
    IReadOnlyList<string> DeclaredTools,
    IReadOnlyDictionary<string, string> EnvironmentManifest);

internal interface IOrchestrationAgentEventSource
{
    Task<RemoteAgentEventPage> ReadEventsAsync(
        ManagedAgentExecution execution, long afterSequence, CancellationToken cancellationToken);
}

internal sealed record RemoteAgentEvent(long NodeSequence, AgentRuntimeEvent Event);
internal sealed record RemoteAgentEventPage(
    IReadOnlyList<RemoteAgentEvent> Events,
    TaskAttemptState? AttemptState,
    RecoveryCertainty? RecoveryCertainty,
    long PageCursor = 0);
internal sealed class RemoteAgentExecutionException(string code, string message)
    : InvalidOperationException(message)
{
    public string Code { get; } = code;
}

internal sealed class ManagedRemoteAgentRuntime(
    IOrchestrationAgentEventSource source,
    ValidatedAgentExecutionOptions options) : IAgentRuntime
{
    public AgentRuntimeDescriptor Descriptor { get; } =
        new("process-jsonl", "1.0.0", false);

    public async IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
        AgentRuntimeRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        long cursor = 0;
        while (true)
        {
            var requestCursor = cursor;
            var page = await source.ReadEventsAsync(
                request.Execution, requestCursor, cancellationToken);
            foreach (var item in page.Events)
            {
                cursor = Math.Max(cursor, item.NodeSequence);
                yield return item.Event;
                if (item.Event is AgentFinalResponse) yield break;
            }
            cursor = Math.Max(cursor, page.PageCursor);
            if (cursor == requestCursor)
                ThrowIfTerminalWithoutFinal(page);
            await Task.Delay(options.PollInterval, cancellationToken);
        }
    }

    private static void ThrowIfTerminalWithoutFinal(RemoteAgentEventPage page)
    {
        var (code, detail) = page.AttemptState switch
        {
            TaskAttemptState.Succeeded => (
                "agent-task-missing-final", "Managed Agent Task succeeded without a durable final response."),
            TaskAttemptState.Failed => ("agent-task-failed", "Managed Agent Task failed without a final response."),
            TaskAttemptState.Cancelled => ("agent-task-cancelled", "Managed Agent Task was cancelled."),
            TaskAttemptState.Interrupted => ("agent-task-interrupted", "Managed Agent Task was interrupted."),
            TaskAttemptState.Recovering when page.RecoveryCertainty == RecoveryCertainty.Ambiguous =>
                ("agent-task-recovering", "Managed Agent Task execution is ambiguous."),
            _ => (null, null)
        };
        if (code is not null) throw new RemoteAgentExecutionException(code, detail!);
    }
}

internal sealed class OrchestrationAgentTaskDispatcher(
    ExecutableWorkloadApplicationService workloads,
    SqliteControlStore store,
    ControlOrchestrator orchestrator,
    ValidatedAgentExecutionOptions options) : IAgentTaskDispatcher, IOrchestrationAgentEventSource
{
    public async Task<ManagedAgentExecution?> DispatchAsync(
        AgentTaskIntent intent, CancellationToken cancellationToken)
    {
        var definition = new Steward.Tasks.Agent.AgentTurnTaskInput(
            intent.AgentId, intent.TurnId, intent.Payload, intent.Provenance.ToString(),
            intent.Context ?? [], options.DeclaredTools, options.EnvironmentManifest,
            "process-jsonl/1.0", options.Executable, options.Arguments, options.MaximumOutputBytes);
        var planId = new PlanRevisionId(DeterministicGuid(
            $"agent-plan:{intent.AgentId}:{intent.TurnId}"));
        var workload = await workloads.SubmitAsync(new(
            "steward-agent-turn", JsonSerializer.SerializeToElement(definition, StewardJson.Options),
            options.PoolId, $"agent:{intent.AgentId}:{intent.TurnId}",
            intent.WorkloadId, planId), cancellationToken);
        var taskId = workload.Payload.TaskIds.Single();
        var attempt = await store.GetLatestTaskAttemptByTaskAsync(taskId, cancellationToken)
            ?? throw new InvalidDataException("Managed Agent TaskAttempt was not persisted.");
        return new(
            DeterministicGuid($"agent-lease:{intent.AgentId}:{intent.TurnId}"),
            workload.Payload.WorkloadId, taskId, attempt.Payload.TaskAttemptId,
            attempt.Payload.Generation, attempt.Payload.HostId,
            attempt.Payload.NodeIncarnationId, attempt.CreatedAt);
    }

    public async Task<ManagedExecutionStatus> ReconcileAsync(
        WorkloadId workloadId, TaskId taskId, ManagedAgentExecution? execution,
        CancellationToken cancellationToken)
    {
        if (execution is null) return new(ManagedExecutionFact.Absent);
        var attempt = await store.GetTaskAttemptAsync(execution.AttemptId, cancellationToken);
        return attempt?.Payload.State switch
        {
            TaskAttemptState.Succeeded => new(
                ManagedExecutionFact.Succeeded, execution,
                await ReadFinalAsync(execution, cancellationToken)),
            TaskAttemptState.Failed => new(ManagedExecutionFact.Failed, execution),
            TaskAttemptState.Cancelled => new(ManagedExecutionFact.Cancelled, execution),
            null => new(ManagedExecutionFact.Absent),
            _ => new(ManagedExecutionFact.Present, execution)
        };
    }

    public async Task<RemoteAgentEventPage> ReadEventsAsync(
        ManagedAgentExecution execution, long afterSequence, CancellationToken cancellationToken)
    {
        var page = await orchestrator.ReadAttemptFactsAsync(
            execution.NodeIncarnationId, execution.AttemptId,
            execution.AttemptGeneration, afterSequence, 1000, cancellationToken);
        var events = page.Facts
            .Select(x => (Fact: x, Value: OrchestrationMessageCodec.DecodeJournaledFact(x.Kind, x.PayloadJson)))
            .Select(x => x.Value switch
            {
                AgentActivityFact activity => new RemoteAgentEvent(
                    x.Fact.Sequence, new AgentActivity(activity.Text, TextProvenance.Runtime)),
                AgentFinalFact final => new RemoteAgentEvent(
                    x.Fact.Sequence, new AgentFinalResponse(final.Text, TextProvenance.Runtime)),
                _ => null
            }).Where(x => x is not null).Cast<RemoteAgentEvent>().ToArray();
        var attempt = await store.GetTaskAttemptAsync(execution.AttemptId, cancellationToken);
        return new(events, attempt?.Payload.State, attempt?.Payload.RecoveryCertainty,
            page.PageCursor);
    }

    private async Task<string?> ReadFinalAsync(
        ManagedAgentExecution execution, CancellationToken cancellationToken)
    {
        long cursor = 0;
        while (true)
        {
            var page = await orchestrator.ReadAttemptFactsAsync(
                execution.NodeIncarnationId, execution.AttemptId,
                execution.AttemptGeneration, cursor, 1000, cancellationToken);
            var final = page.Facts
                .Select(x => OrchestrationMessageCodec.DecodeJournaledFact(x.Kind, x.PayloadJson))
                .OfType<AgentFinalFact>().LastOrDefault()?.Text;
            if (!string.IsNullOrEmpty(final)) return final;
            if (page.PageCursor == cursor) return null;
            cursor = page.PageCursor;
        }
    }

    public Task<bool> ReportTerminalAsync(
        ManagedAgentExecution execution, AgentTerminalReport report,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return PersistTerminalReportAsync(execution, report, cancellationToken);
    }

    public async Task CancelAsync(
        ManagedAgentExecution execution, CancellationToken cancellationToken)
    {
        await orchestrator.CancelAsync(
            execution.WorkloadId, TimeSpan.FromSeconds(5), cancellationToken);
    }

    private async Task<bool> PersistTerminalReportAsync(
        ManagedAgentExecution execution, AgentTerminalReport report, CancellationToken token)
    {
        await using var connection = await store.OpenConnectionAsync(token);
        await using var command = connection.CreateCommand();
        command.CommandText = """
          CREATE TABLE IF NOT EXISTS agent_terminal_reports(
            lease_id TEXT PRIMARY KEY,report_json TEXT NOT NULL,created_at TEXT NOT NULL);
          INSERT OR IGNORE INTO agent_terminal_reports(lease_id,report_json,created_at)
          VALUES($lease,$json,$now);
          SELECT report_json FROM agent_terminal_reports WHERE lease_id=$lease;
          """;
        var json = JsonSerializer.Serialize(report, StewardJson.Options);
        command.Parameters.AddWithValue("$lease", execution.LeaseId.ToString("D"));
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        var existing = (string?)await command.ExecuteScalarAsync(token);
        return existing == json;
    }

    private static Guid DeterministicGuid(string value) =>
        new(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value)).AsSpan(0, 16));

}

internal sealed class AgentTurnBackgroundWorker(
    IAgentStore store,
    StewardAgentService service,
    ValidatedAgentExecutionOptions options,
    ILogger<AgentTurnBackgroundWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            foreach (var agent in await ListAgentIdsAsync(stoppingToken))
            {
                try
                {
                    while (await service.RunNextAsync(agent, cancellationToken: stoppingToken)) { }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { throw; }
                catch (Exception exception) when (exception is AgentConflictException or
                                                   InvalidOperationException or IOException or
                                                   OperationCanceledException)
                {
                    logger.LogWarning("Agent {AgentId} processing deferred with {Code}.",
                        agent, exception is AgentConflictException
                            ? "agent-ownership-conflict" : "agent-operational-failure");
                }
            }
            await Task.Delay(options.PollInterval, stoppingToken);
        }
    }

    private async Task<IReadOnlyList<StewardAgentId>> ListAgentIdsAsync(CancellationToken token)
    {
        if (store is not SqliteAgentStore sqlite) return [];
        return await sqlite.ListAgentIdsAsync(token);
    }
}
