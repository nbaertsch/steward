using System.Runtime.CompilerServices;
using Steward.Domain;

namespace Steward.Agents;

public static class AgentLimits
{
    public const int MaximumTurnBytes = 256 * 1024;
    public const int MaximumResponseBytes = 1024 * 1024;
    public const int MaximumActivityBytes = 64 * 1024;
    public const int MaximumContextBytes = 4 * 1024 * 1024;
    public const int MaximumPendingTurns = 1_000;
    public const int MaximumEnvironmentEntries = 256;

    public static void Text(string value, int maximumBytes, string name)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (System.Text.Encoding.UTF8.GetByteCount(value) > maximumBytes)
            throw new ArgumentException($"{name} exceeds the {maximumBytes}-byte limit.", name);
    }
}

public enum TextProvenance { User, Runtime, Tool, Steward }
public enum AgentTurnStatus { Queued, Dispatching, Running, Recovering, Responded, Failed, Cancelled }
public enum AgentCommandKind { Inspect, Diagnose, Commit, RequestRetry, RequestRestart, ToolOperation, CodingOperation }
public enum ManagedExecutionFact { Absent, Present, Succeeded, Failed, Cancelled }
public enum AgentTerminalKind { Responded, Failed, Cancelled }

public sealed record AgentDescriptor(
    StewardAgentId AgentId,
    string RuntimeName,
    string RuntimeVersion,
    bool SupportsParallelTurns,
    string? ParentRoute,
    long Revision,
    long ResponseCursor,
    long NotificationCursor,
    long PlacementGeneration,
    bool Frozen);

public sealed record AgentTurnRequest(
    AgentTurnId TurnId,
    string Text,
    TextProvenance Provenance = TextProvenance.User,
    string? ClientRequestId = null);

public sealed record ManagedAgentExecution(
    Guid LeaseId,
    WorkloadId WorkloadId,
    TaskId TaskId,
    TaskAttemptId AttemptId,
    int AttemptGeneration,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    DateTimeOffset AcceptedAt)
{
    public ManagedAgentExecution Validate()
    {
        if (LeaseId == Guid.Empty) throw new ArgumentException("Execution lease ID cannot be empty.", nameof(LeaseId));
        if (AttemptGeneration <= 0) throw new ArgumentOutOfRangeException(nameof(AttemptGeneration));
        return this;
    }
}

public sealed record ManagedExecutionStatus(
    ManagedExecutionFact Fact,
    ManagedAgentExecution? Execution = null,
    string? Response = null,
    string? ErrorCode = null);

public sealed record AgentTerminalReport(
    AgentTerminalKind Kind,
    string? Response,
    string? ErrorCode,
    string? SafeDetail);

public sealed record PendingAgentResult(
    StewardAgentId AgentId,
    AgentTurnId TurnId,
    Guid ExecutionLeaseId,
    string Response,
    bool TerminalReported);

public sealed record AgentRuntimeOwnership(
    StewardAgentId AgentId,
    Guid OwnerId,
    DateTimeOffset AcquiredAt,
    DateTimeOffset RenewedAt,
    DateTimeOffset ExpiresAt);

public sealed record AgentTurnRecord(
    StewardAgentId AgentId,
    AgentTurnId TurnId,
    string Text,
    TextProvenance Provenance,
    string? ClientRequestId,
    AgentTurnStatus Status,
    long QueueSequence,
    long? ResponseSequence,
    string? Response,
    string? ErrorCode,
    string? SafeErrorDetail,
    WorkloadId? WorkloadId,
    TaskId? TaskId,
    ManagedAgentExecution? Execution);

public sealed record ContextRecord(
    long Sequence,
    string Text,
    TextProvenance Provenance,
    int TokenEstimate,
    string? CheckpointId,
    string? ParentCheckpointId,
    string? SummarySha256);

public sealed record ContextBudget(int MaximumBytes, int MaximumTokens)
{
    public ContextBudget Validate()
    {
        if (MaximumBytes is <= 0 or > AgentLimits.MaximumContextBytes)
            throw new ArgumentOutOfRangeException(nameof(MaximumBytes));
        if (MaximumTokens <= 0)
            throw new ArgumentOutOfRangeException(nameof(MaximumTokens));
        return this;
    }
}

public sealed record CompactionResult(
    string Summary,
    string Algorithm,
    string SourceSha256,
    IReadOnlyList<ContextRecord> RetainedRecent);

public interface IContextCompactor
{
    ValueTask<CompactionResult> CompactAsync(
        IReadOnlyList<ContextRecord> records,
        ContextBudget budget,
        CancellationToken cancellationToken);
}

public sealed class DeterministicContextCompactor : IContextCompactor
{
    public ValueTask<CompactionResult> CompactAsync(
        IReadOnlyList<ContextRecord> records,
        ContextBudget budget,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        budget.Validate();
        var canonical = string.Join("\n", records.OrderBy(x => x.Sequence)
            .Select(x => $"{x.Sequence}:{x.Provenance}:{x.Text}"));
        var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(canonical)));
        var fullSummary = $"context-checkpoint:{records.Count}:{hash}";
        var summary = fullSummary[..Math.Min(fullSummary.Length, budget.MaximumBytes)];
        return ValueTask.FromResult(new CompactionResult(summary, "steward.test.deterministic.v1", hash, []));
    }
}

public sealed class BoundedExtractiveContextCompactor : IContextCompactor
{
    public ValueTask<CompactionResult> CompactAsync(
        IReadOnlyList<ContextRecord> records,
        ContextBudget budget,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        budget.Validate();
        var canonical = string.Join("\n", records.OrderBy(x => x.Sequence)
            .Select(x => $"{x.Sequence}:{x.Provenance}:{x.Text}"));
        var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(canonical)));
        var fullSummary = $"[context checkpoint source={hash}; records={records.Count}]";
        var summary = fullSummary[..Math.Min(fullSummary.Length, budget.MaximumBytes)];
        var remainingBytes = Math.Max(0, budget.MaximumBytes -
            System.Text.Encoding.UTF8.GetByteCount(summary));
        var remainingTokens = Math.Max(0, budget.MaximumTokens -
            Math.Max(1, (System.Text.Encoding.UTF8.GetByteCount(summary) + 3) / 4));
        var retained = new List<ContextRecord>();
        foreach (var record in records.OrderByDescending(x => x.Sequence))
        {
            var bytes = System.Text.Encoding.UTF8.GetByteCount(record.Text);
            if (bytes > remainingBytes || record.TokenEstimate > remainingTokens) continue;
            retained.Add(record);
            remainingBytes -= bytes;
            remainingTokens -= record.TokenEstimate;
        }
        retained.Reverse();
        return ValueTask.FromResult(new CompactionResult(
            summary, "steward.extractive.v1", hash, retained));
    }
}

public sealed record AgentRuntimeDescriptor(string Name, string Version, bool SupportsParallelTurns = false);
public sealed record ProtectedCredentialReference(string Name, Guid HandleId)
{
    public override string ToString() => $"protected:{Name}:{HandleId:D}";
}

public sealed record AgentRuntimeRequest(
    AgentDescriptor Agent,
    AgentTurnRecord Turn,
    ManagedAgentExecution Execution,
    IReadOnlyList<ContextRecord> Context,
    IReadOnlyList<ProtectedCredentialReference> Credentials);

public abstract record AgentRuntimeEvent(string Text, TextProvenance Provenance);
public sealed record AgentActivity(string Text, TextProvenance Provenance = TextProvenance.Runtime)
    : AgentRuntimeEvent(Text, Provenance);
public sealed record AgentFinalResponse(string Text, TextProvenance Provenance = TextProvenance.Runtime)
    : AgentRuntimeEvent(Text, Provenance);

public interface IAgentRuntime
{
    AgentRuntimeDescriptor Descriptor { get; }
    IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(AgentRuntimeRequest request, CancellationToken cancellationToken);
}

public sealed class DeterministicAgentRuntime : IAgentRuntime
{
    private readonly Func<AgentRuntimeRequest, string> _response;
    public DeterministicAgentRuntime(Func<AgentRuntimeRequest, string>? response = null) =>
        _response = response ?? (request => $"echo:{request.Turn.Text}");
    public AgentRuntimeDescriptor Descriptor { get; } = new("deterministic", "1.0.0");

    public async IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
        AgentRuntimeRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        yield return new AgentActivity("turn-started", TextProvenance.Runtime);
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        yield return new AgentFinalResponse(_response(request), TextProvenance.Runtime);
    }
}

public sealed record ExternalRuntimeInvocation(
    string ExecutableReference,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    int MaximumOutputBytes,
    IReadOnlyList<ProtectedCredentialReference> Credentials);

public interface IExternalAgentProcess
{
    IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
        ExternalRuntimeInvocation invocation,
        string boundedInput,
        CancellationToken cancellationToken);
}

public sealed class ExternalProcessAgentRuntime : IAgentRuntime
{
    private readonly IExternalAgentProcess _process;
    private readonly ExternalRuntimeInvocation _invocation;
    public ExternalProcessAgentRuntime(
        AgentRuntimeDescriptor descriptor,
        IExternalAgentProcess process,
        ExternalRuntimeInvocation invocation)
    {
        Descriptor = descriptor;
        _process = process;
        _invocation = invocation;
    }
    public AgentRuntimeDescriptor Descriptor { get; }
    public IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
        AgentRuntimeRequest request,
        CancellationToken cancellationToken)
    {
        AgentLimits.Text(request.Turn.Text, AgentLimits.MaximumTurnBytes, nameof(request));
        return _process.ExecuteAsync(_invocation with { Credentials = request.Credentials },
            request.Turn.Text, cancellationToken);
    }
}

public sealed record AgentTaskIntent(
    StewardAgentId AgentId,
    AgentTurnId TurnId,
    WorkloadId WorkloadId,
    TaskId TaskId,
    AgentCommandKind Kind,
    string Payload,
    TextProvenance Provenance,
    IReadOnlyList<string>? Context = null);

public interface IAgentTaskDispatcher
{
    Task<ManagedAgentExecution?> DispatchAsync(AgentTaskIntent intent, CancellationToken cancellationToken);
    Task<ManagedExecutionStatus> ReconcileAsync(
        WorkloadId workloadId,
        TaskId taskId,
        ManagedAgentExecution? execution,
        CancellationToken cancellationToken);
    Task<bool> ReportTerminalAsync(
        ManagedAgentExecution execution,
        AgentTerminalReport report,
        CancellationToken cancellationToken);
    Task CancelAsync(ManagedAgentExecution execution, CancellationToken cancellationToken);
}

public sealed record AgentNotification(
    StewardAgentId AgentId,
    long Sequence,
    AgentTurnId TurnId,
    string Kind,
    string Payload,
    TextProvenance Provenance);

public sealed record AgentMigrationState(
    Guid MigrationId,
    StewardAgentId AgentId,
    HostId DestinationHostId,
    string State,
    DateTimeOffset StartedAt);

public interface IParentNotificationOutbox
{
    Task<IReadOnlyList<AgentNotification>> ReadAsync(
        StewardAgentId agentId, long afterSequence, int maximumCount, CancellationToken cancellationToken = default);
    Task AcknowledgeAsync(
        StewardAgentId agentId, long contiguousSequence, CancellationToken cancellationToken = default);
}

public sealed class AgentConflictException(string message) : InvalidOperationException(message);
public sealed class AgentStoreException(string message, Exception? inner = null) : IOException(message, inner);
