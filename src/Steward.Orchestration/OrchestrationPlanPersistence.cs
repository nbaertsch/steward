using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.Scheduling;

namespace Steward.Orchestration;

internal sealed record PersistedResourceRequirements(
    decimal CpuCores,
    long MemoryBytes,
    long DiskBytes,
    int GpuCount,
    int ProcessCount,
    int ContainerCount,
    int VmCount,
    int ConcurrencyUnits);

internal sealed record PersistedTaskPlanNode(
    TaskId TaskId,
    string LogicalKey,
    string TaskType,
    string TaskTypeVersion,
    PersistedResourceRequirements Resources,
    string InputMediaType,
    string InputSchemaVersion,
    string InputJson,
    IReadOnlyList<TaskId> Dependencies,
    IReadOnlyList<string> RequiredHostCapabilities,
    string? SetupFingerprint,
    string? AffinityKey,
    HostId? RequiredHostId,
    int RetryCap,
    InterruptionClass InterruptionClass,
    IReadOnlyList<ExternalRateRequirement> ExternalRates,
    string ResultReductionKey,
    IReadOnlyList<IdentityGrantId> IdentityGrantIds,
    bool IdentityGrantsRenewableAcrossGenerations);

internal sealed record PersistedWorkloadPlan(
    string StorageSchemaVersion,
    WorkloadId WorkloadId,
    PlanRevisionId PlanRevisionId,
    string PlanSchemaVersion,
    string PlannerType,
    string PlannerVersion,
    AggregateFailurePolicy FailurePolicy,
    int MaximumConcurrency,
    IReadOnlyList<PersistedTaskPlanNode> Tasks,
    string DeterministicHash);

internal static class OrchestrationPlanSerializer
{
    public const string StorageSchemaVersion = "1.0";

    public static string Serialize(WorkloadPlan plan)
    {
        var persisted = new PersistedWorkloadPlan(
            StorageSchemaVersion,
            plan.WorkloadId,
            plan.PlanRevisionId,
            plan.SchemaVersion,
            plan.PlannerType,
            plan.PlannerVersion,
            plan.FailurePolicy,
            plan.MaximumConcurrency,
            plan.Tasks.Select(task => new PersistedTaskPlanNode(
                task.TaskId,
                task.LogicalKey,
                task.TaskType,
                task.TaskTypeVersion,
                FromDomain(task.Resources),
                task.Input.MediaType,
                task.Input.SchemaVersion,
                task.Input.CanonicalJson,
                task.Dependencies.ToArray(),
                task.RequiredHostCapabilities.Order(StringComparer.Ordinal).ToArray(),
                task.SetupFingerprint,
                task.AffinityKey,
                task.RequiredHostId,
                task.RetryCap,
                task.InterruptionClass,
                task.ExternalRates.ToArray(),
                task.ResultReductionKey,
                (task.IdentityGrantIds ?? []).ToArray(),
                task.IdentityGrantsRenewableAcrossGenerations)).ToArray(),
            plan.DeterministicHash);
        return JsonSerializer.Serialize(persisted, StewardJson.Options);
    }

    public static WorkloadPlan Deserialize(string json, string expectedHash)
    {
        PersistedWorkloadPlan persisted;
        try
        {
            persisted = JsonSerializer.Deserialize<PersistedWorkloadPlan>(json, StewardJson.Options)
                ?? throw new InvalidDataException("Persisted orchestration plan is null.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Persisted orchestration plan is invalid.", exception);
        }
        if (persisted.StorageSchemaVersion != StorageSchemaVersion)
            throw new InvalidDataException(
                $"Orchestration plan storage schema '{persisted.StorageSchemaVersion}' is unsupported.");
        var plan = new WorkloadPlan(
            persisted.WorkloadId,
            persisted.PlanRevisionId,
            persisted.PlanSchemaVersion,
            persisted.PlannerType,
            persisted.PlannerVersion,
            persisted.Tasks.Select(task => new TaskPlanNode(
                task.TaskId,
                task.LogicalKey,
                task.TaskType,
                task.TaskTypeVersion,
                ToDomain(task.Resources),
                TaskInput.Parse(task.InputMediaType, task.InputSchemaVersion, task.InputJson),
                task.Dependencies,
                task.RequiredHostCapabilities.ToHashSet(StringComparer.Ordinal),
                task.SetupFingerprint,
                task.AffinityKey,
                task.RequiredHostId,
                task.RetryCap,
                task.InterruptionClass,
                task.ExternalRates,
                task.ResultReductionKey,
                task.IdentityGrantIds,
                task.IdentityGrantsRenewableAcrossGenerations)),
            persisted.FailurePolicy,
            persisted.MaximumConcurrency);
        if (!FixedHash(plan.DeterministicHash, expectedHash) ||
            !FixedHash(plan.DeterministicHash, persisted.DeterministicHash))
            throw new InvalidDataException("Persisted orchestration plan hash does not match its immutable content.");
        return plan;
    }

    private static PersistedResourceRequirements FromDomain(ResourceRequirements value) =>
        new(value.CpuCores, value.MemoryBytes, value.DiskBytes, value.GpuCount,
            value.ProcessCount, value.ContainerCount, value.VmCount, value.ConcurrencyUnits);

    private static ResourceRequirements ToDomain(PersistedResourceRequirements value) =>
        new(value.CpuCores, value.MemoryBytes, value.DiskBytes, value.GpuCount,
            value.ProcessCount, value.ContainerCount, value.VmCount, value.ConcurrencyUnits);

    private static bool FixedHash(string left, string right)
    {
        if (left.Length != right.Length) return false;
        try
        {
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(left), Convert.FromHexString(right));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
