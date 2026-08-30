using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Scheduling;
using Steward.Tasks.Compose;
using Steward.Tasks.Process;
using Steward.Tasks.Agent;
using Steward.Workloads.Evals;

namespace Steward.Application;

public sealed record SubmitWorkloadRequest(
    string Kind,
    JsonElement Input,
    PoolId PoolId,
    string IdempotencyKey,
    WorkloadId? WorkloadId = null,
    PlanRevisionId? PlanRevisionId = null);

public sealed record GeneralTaskWorkloadInput(
    JsonElement Definition,
    ResourceRequirements? Resources = null,
    IReadOnlyList<string>? RequiredHostCapabilities = null,
    HostId? RequiredHostId = null,
    int RetryCap = 0);

public interface IWorkloadPlanFactory
{
    string Kind { get; }
    WorkloadPlan Create(
        WorkloadId workloadId,
        PlanRevisionId planRevisionId,
        JsonElement input);
}

public sealed class WorkloadPlanFactoryRegistry
{
    private readonly IReadOnlyDictionary<string, IWorkloadPlanFactory> factories;

    public WorkloadPlanFactoryRegistry(IEnumerable<IWorkloadPlanFactory> factories)
    {
        var values = factories?.ToArray() ?? throw new ArgumentNullException(nameof(factories));
        if (values.Select(x => x.Kind).Distinct(StringComparer.Ordinal).Count() != values.Length)
            throw new ArgumentException("Workload planner kinds must be unique.", nameof(factories));
        this.factories = values.ToDictionary(x => x.Kind, StringComparer.Ordinal);
    }

    public IWorkloadPlanFactory Resolve(string kind) =>
        factories.TryGetValue(kind, out var factory)
            ? factory
            : throw new ApplicationContractException(
                ProblemCodes.CapabilityUnavailable,
                $"Workload kind '{kind}' is not configured.",
                ProblemDisposition.Terminal);

    public IReadOnlyList<string> Kinds => factories.Keys.Order(StringComparer.Ordinal).ToArray();
}

public sealed record EvaluationSubmissionInput(
    EvaluationWorkloadInput Workload,
    HarnessCommandProfile Harness,
    EvaluationSetupProfile Setup);

public sealed class EvaluationWorkloadPlanFactory(string kind) : IWorkloadPlanFactory
{
    public string Kind { get; } = !string.IsNullOrWhiteSpace(kind)
        ? kind : throw new ArgumentException("Planner kind is required.", nameof(kind));

    public WorkloadPlan Create(
        WorkloadId workloadId,
        PlanRevisionId planRevisionId,
        JsonElement input)
    {
        EvaluationSubmissionInput value;
        try
        {
            value = input.Deserialize<EvaluationSubmissionInput>(StewardJson.Options)
                ?? throw new JsonException("Evaluation input is null.");
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException)
        {
            throw new ApplicationContractException(
                "InvalidArgument", "Evaluation input is invalid.");
        }
        try
        {
            EvaluationPlannerBase planner = Kind switch
            {
                "harbor" => new HarborEvaluationPlanner(new HarborEvaluationAdapter(value.Harness), value.Setup),
                "saber" => new SaberEvaluationPlanner(new SaberEvaluationAdapter(value.Harness), value.Setup),
                _ => throw new ApplicationContractException(
                    ProblemCodes.CapabilityUnavailable, $"Evaluation planner '{Kind}' is unavailable.")
            };
            var plan = planner.Plan(new(workloadId, planRevisionId, value.Workload));
            var grants = value.Workload.IdentityCapabilities.ToDictionary(
                x => x.Reference,
                x => ParseGrantId(x.Reference),
                StringComparer.Ordinal);
            if (grants.Count == 0) return plan;
            var tasks = plan.Tasks.Select(task =>
            {
                var referenced = grants.Where(x =>
                        task.Input.CanonicalJson.Contains(
                            JsonSerializer.Serialize(x.Key), StringComparison.Ordinal))
                    .Select(x => x.Value).Distinct().ToArray();
                return task with { IdentityGrantIds = referenced };
            }).ToArray();
            return new(
                plan.WorkloadId, plan.PlanRevisionId, plan.SchemaVersion,
                plan.PlannerType, plan.PlannerVersion, tasks,
                plan.FailurePolicy, plan.MaximumConcurrency);
        }
        catch (ArgumentException)
        {
            throw new ApplicationContractException("InvalidArgument", "Evaluation planning input is invalid.");
        }
    }

    private static IdentityGrantId ParseGrantId(string reference)
    {
        var uri = new Uri(reference, UriKind.Absolute);
        var value = Uri.UnescapeDataString(uri.AbsolutePath.Trim('/'));
        if (string.IsNullOrEmpty(value)) value = uri.Host;
        if (!IdentityGrantId.TryParse(value, out var id))
            throw new ApplicationContractException(
                "InvalidArgument",
                "Identity references used for execution must contain an IdentityGrantId.");
        return id;
    }
}

public sealed class GeneralTaskWorkloadPlanFactory(string kind, bool compose) : IWorkloadPlanFactory
{
    private static readonly JsonSerializerOptions InputOptions = new(StewardJson.Options)
    {
        PropertyNameCaseInsensitive = true
    };
    public string Kind { get; } = kind;

    public WorkloadPlan Create(
        WorkloadId workloadId,
        PlanRevisionId planRevisionId,
        JsonElement input)
    {
        GeneralTaskWorkloadInput request;
        JsonElement normalizedDefinition;
        try
        {
            request = input.Deserialize<GeneralTaskWorkloadInput>(InputOptions)
                ?? throw new JsonException("General Task input is null.");
            if (compose)
            {
                var definition = request.Definition.Deserialize<ComposeTaskDefinition>(InputOptions)
                    ?? throw new JsonException("Compose definition is null.");
                ValidateCompose(definition);
                normalizedDefinition = JsonSerializer.SerializeToElement(
                    definition, StewardJson.Options);
            }
            else
            {
                var definition = request.Definition.Deserialize<ProcessTaskDefinition>(InputOptions)
                    ?? throw new JsonException("Process definition is null.");
                ValidateProcess(definition);
                normalizedDefinition = JsonSerializer.SerializeToElement(
                    definition, StewardJson.Options);
            }
        }

        catch (Exception exception) when (exception is JsonException or ArgumentException)
        {
            throw new ApplicationContractException(
                "InvalidArgument", "General Task input is invalid.");
        }
        if (request.RetryCap is < 0 or > WorkloadPlanLimits.MaximumRetries)
            throw new ApplicationContractException("InvalidArgument", "RetryCap is outside its bound.");
        var taskId = DeterministicTaskId(planRevisionId);
        var type = compose ? "docker-compose" : "process";
        var resources = request.Resources ?? new ResourceRequirements(
            cpuCores: 1, memoryBytes: 256 * 1024 * 1024, diskBytes: 256 * 1024 * 1024,
            processCount: 1, containerCount: compose ? 1 : 0, concurrencyUnits: 1);
        var task = new TaskPlanNode(
            taskId, "task", type, "1.0", resources,
            TaskInput.FromJsonElement("application/json", "1.0", normalizedDefinition),
            [], (request.RequiredHostCapabilities ?? []).ToHashSet(StringComparer.Ordinal),
            null, null, request.RequiredHostId, request.RetryCap,
            InterruptionClass.Restartable, [], "result");
        return new(workloadId, planRevisionId, WorkloadPlan.CurrentSchemaVersion,
            type, "1.0", [task]);
    }

    private static TaskId DeterministicTaskId(PlanRevisionId planRevisionId)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"general-task:{planRevisionId}"));
        return new(new Guid(hash.AsSpan(0, 16)));
    }

    private static void ValidateProcess(ProcessTaskDefinition value)
    {
        if (!Path.IsPathFullyQualified(value.Executable) ||
            Path.GetExtension(value.Executable) is ".bat" or ".cmd" ||
            value.MaxOutputBytes is <= 0 or > int.MaxValue ||
            value.RequiredDiskReserveBytes < 0)
            throw new ArgumentException("Process definition has invalid executable or output bounds.");
    }

    private static void ValidateCompose(ComposeTaskDefinition value)
    {
        if (!Path.IsPathFullyQualified(value.DockerExecutable) ||
            Path.GetExtension(value.DockerExecutable) is ".bat" or ".cmd" ||
            string.IsNullOrWhiteSpace(value.ComposeFile) ||
            Path.IsPathFullyQualified(value.ComposeFile) ||
            value.ComposeFile.Split('/', '\\').Contains("..") ||
            string.IsNullOrWhiteSpace(value.ProjectName) ||
            value.MaxOutputBytes is <= 0 or > int.MaxValue ||
            value.RequiredDiskReserveBytes < 0)
            throw new ArgumentException("Compose definition has invalid executable, path, name, or output bounds.");
    }
}

public sealed class AgentTurnWorkloadPlanFactory : IWorkloadPlanFactory
{
    public string Kind => "steward-agent-turn";
    public WorkloadPlan Create(
        WorkloadId workloadId, PlanRevisionId planRevisionId, JsonElement input)
    {
        var value = input.Deserialize<AgentTurnTaskInput>(StewardJson.Options)
            ?? throw new ApplicationContractException("InvalidArgument", "Agent turn input is invalid.");
        var taskId = new TaskId(new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"agent-turn:{value.AgentId}:{value.TurnId}")).AsSpan(0, 16)));
        return new(workloadId, planRevisionId, WorkloadPlan.CurrentSchemaVersion,
            Kind, "1.0",
            [new(taskId, "agent-turn", Kind, "1.0",
                new ResourceRequirements(1, 512 * 1024 * 1024, 512 * 1024 * 1024,
                    processCount: 1, concurrencyUnits: 1),
                TaskInput.FromJsonElement("application/json", "1.0", input),
                [], new HashSet<string>(), null, $"agent:{value.AgentId}", null, 1,
                InterruptionClass.Restartable, [], $"agent-turn:{value.TurnId}")]);
    }
}

public sealed class ExecutableWorkloadApplicationService(
    ControlOrchestrator orchestrator,
    ControlNodeRegistrationStore nodes,
    WorkloadPlanFactoryRegistry planners,
    HostPoolApplicationService? hostPools = null)
{
    public async Task<ContractEnvelope<WorkloadDto>> SubmitAsync(
        SubmitWorkloadRequest request,
        CancellationToken cancellationToken = default)
    {
        Validate(request);
        var requestHash = HashRequest(request);
        var workloadId = request.WorkloadId ?? DeterministicId<WorkloadId>(
            $"workload:{request.IdempotencyKey}");
        var revisionId = request.PlanRevisionId ?? DeterministicId<PlanRevisionId>(
            $"plan:{request.IdempotencyKey}");
        var plan = planners.Resolve(request.Kind).Create(workloadId, revisionId, request.Input);
        var registrations = (await nodes.ListAsync(cancellationToken)).Where(x => x.Enabled).ToArray();
        if (registrations.Length == 0)
            throw new ApplicationContractException(
                ProblemCodes.CapabilityUnavailable,
                "No enabled Node capacity is registered.",
                ProblemDisposition.RetrySafe);
        try
        {
            var scheduling = await orchestrator.RegisterAndScheduleAsync(
                plan,
                registrations.Where(x => x.PoolId == request.PoolId).Select(x => x.ToSnapshot()).ToArray(),
                request.PoolId,
                DateTimeOffset.UtcNow,
                request.IdempotencyKey,
                requestHash,
                cancellationToken).ConfigureAwait(false);
            if (scheduling.PoolDemands.Count > 0 && hostPools is not null)
                await hostPools.ReconcileAsync(
                    request.PoolId, scheduling.PoolDemands, DateTimeOffset.UtcNow, cancellationToken)
                    .ConfigureAwait(false);
        }
        catch (IdentityResolutionException exception)
        {
            throw new ApplicationContractException(
                ProblemCodes.IdentityRenewalUnavailable,
                exception.SafeDetail,
                ProblemDisposition.RequiresNewUserIntent);
        }
        return await orchestrator.Store.GetWorkloadAsync(workloadId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Scheduled Workload snapshot was not committed.");
    }

    private static void Validate(SubmitWorkloadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Kind) || request.Kind.Length > ApplicationLimits.NameLength)
            throw new ApplicationContractException("InvalidArgument", "Workload kind is invalid.");
        if (string.IsNullOrWhiteSpace(request.IdempotencyKey) ||
            request.IdempotencyKey.Length > ApplicationLimits.IdempotencyKeyLength)
            throw new ApplicationContractException("InvalidArgument", "IdempotencyKey is invalid.");
        if (request.Input.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ||
            Encoding.UTF8.GetByteCount(request.Input.GetRawText()) > TaskInput.MaximumUtf8Bytes)
            throw new ApplicationContractException("InvalidArgument", "Workload input exceeds its bound.");
    }

    private static string HashRequest(SubmitWorkloadRequest request)
    {
        var canonical = TaskInput.FromJsonElement("application/json", "1.0", request.Input).CanonicalJson;
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{request.Kind}\n{request.PoolId}\n{canonical}")));
    }

    private static T DeterministicId<T>(string value) where T : struct, IStewardId
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value))[..16];
        if (new Guid(bytes) == Guid.Empty) bytes[0] = 1;
        return (T)Activator.CreateInstance(typeof(T), new Guid(bytes))!;
    }
}
