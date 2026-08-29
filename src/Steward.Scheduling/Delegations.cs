using Steward.Contracts;
using Steward.Domain;

namespace Steward.Scheduling;

public sealed record DelegationPartitionOptions(
    int MaximumTasks,
    TimeSpan TimeToLive,
    TimeSpan DrainBeforeExpiry,
    long SpoolQuotaBytes,
    int ConcurrencyLimit,
    long RevocationRevision = 0)
{
    public DelegationPartitionOptions Validate()
    {
        if (MaximumTasks <= 0 || MaximumTasks > 1_000) throw new ArgumentOutOfRangeException(nameof(MaximumTasks));
        if (TimeToLive <= TimeSpan.Zero || TimeToLive > TimeSpan.FromDays(7)) throw new ArgumentOutOfRangeException(nameof(TimeToLive));
        if (DrainBeforeExpiry < TimeSpan.Zero || DrainBeforeExpiry >= TimeToLive) throw new ArgumentOutOfRangeException(nameof(DrainBeforeExpiry));
        if (SpoolQuotaBytes <= 0 || ConcurrencyLimit <= 0) throw new ArgumentOutOfRangeException(nameof(SpoolQuotaBytes));
        return this;
    }
}

public static class DelegationPartitioner
{
    public static IReadOnlyList<DelegationDto> Create(
        WorkloadPlan plan,
        SchedulerState state,
        DateTimeOffset now,
        DelegationPartitionOptions options)
    {
        options.Validate();
        var nodes = plan.Tasks.ToDictionary(x => x.TaskId);
        var partitions = new List<DelegationDto>();
        foreach (var group in state.Tasks
                     .Where(x => x.Placement is not null && x.State is ScheduledTaskState.Placed or ScheduledTaskState.Running)
                     .OrderBy(x => x.TaskId.ToString(), StringComparer.Ordinal)
                     .GroupBy(x => (x.Placement!.HostId, x.Placement.IncarnationId)))
        {
            foreach (var chunk in group.Chunk(options.MaximumTasks))
            {
                var tasks = chunk.ToArray();
                var resources = Sum(tasks.Select(x => nodes[x.TaskId].Resources));
                var bindings = tasks.Select(task =>
                {
                    var taskRates = state.RateSlices
                        .Where(x => x.HostId == group.Key.HostId &&
                                    x.TaskId == task.TaskId &&
                                    x.Generation == task.AttemptGeneration &&
                                    x.ExpiresAt > now)
                        .GroupBy(x => x.Scope, StringComparer.Ordinal)
                        .Select(x => new RateLimitDto(x.Key, x.Sum(v => v.Amount), x.Min(v => v.ExpiresAt)))
                        .OrderBy(x => x.Scope, StringComparer.Ordinal)
                        .ToArray();
                    return new TaskAuthorityBindingDto(
                        task.TaskId,
                        task.AttemptGeneration,
                        taskRates,
                        (nodes[task.TaskId].IdentityGrantIds ?? []).Distinct().ToArray());
                }).ToArray();
                var rates = bindings.SelectMany(x => x.RateLimits)
                    .GroupBy(x => x.Scope, StringComparer.Ordinal)
                    .Select(x => new RateLimitDto(x.Key, x.Sum(v => v.MaximumAmount), x.Min(v => v.ExpiresAt)))
                    .OrderBy(x => x.Scope, StringComparer.Ordinal)
                    .ToArray();
                var grants = bindings.SelectMany(x => x.IdentityGrantIds).Distinct().ToArray();
                var expires = now + options.TimeToLive;
                partitions.Add(new(
                    DelegationId.New(), group.Key.HostId, group.Key.IncarnationId, plan.PlanRevisionId,
                    tasks.Select(x => new AttemptGenerationRangeDto(x.TaskId, x.AttemptGeneration,
                        MaximumDelegatedGeneration(nodes[x.TaskId], x))).ToArray(),
                    ToDto(resources), Math.Min(options.ConcurrencyLimit, tasks.Length), options.SpoolQuotaBytes,
                    rates, grants, now, expires - options.DrainBeforeExpiry, expires - options.DrainBeforeExpiry,
                    expires, options.RevocationRevision, bindings));
            }
        }
        return partitions;
    }

    private static ResourceRequirements Sum(IEnumerable<ResourceRequirements> values)
    {
        var list = values.ToArray();
        return new(list.Sum(x => x.CpuCores), list.Sum(x => x.MemoryBytes), list.Sum(x => x.DiskBytes),
            list.Sum(x => x.GpuCount), list.Sum(x => x.ProcessCount), list.Sum(x => x.ContainerCount),
            list.Sum(x => x.VmCount), list.Sum(x => x.ConcurrencyUnits));
    }

    private static ResourceRequirementsDto ToDto(ResourceRequirements value) =>
        new(value.CpuCores, value.MemoryBytes, value.DiskBytes, value.GpuCount, value.ProcessCount,
            value.ContainerCount, value.VmCount, value.ConcurrencyUnits);

    private static int MaximumDelegatedGeneration(TaskPlanNode node, ScheduledTask task)
    {
        // External-rate slices and generation-bound identity grants authorize only this attempt.
        // Control must allocate fresh authority before delegating an offline retry.
        if (node.ExternalRates.Count > 0 ||
            ((node.IdentityGrantIds?.Count ?? 0) > 0 && !node.IdentityGrantsRenewableAcrossGenerations))
            return task.AttemptGeneration;
        return checked(task.AttemptGeneration + Math.Max(0, node.RetryCap - task.RetryCount));
    }
}
