using Steward.Domain;

namespace Steward.Scheduling;

public static class SchedulerStateValidator
{
    public static void Validate(SchedulerState state, WorkloadPlan? plan = null, WorkloadId? expectedWorkloadId = null)
    {
        if (state.WorkloadId == default || state.PlanRevisionId == default || string.IsNullOrWhiteSpace(state.PlanHash) ||
            state.Revision < 0)
            throw new InvalidDataException("Scheduler state identity or revision is invalid.");
        if (expectedWorkloadId is { } expected && state.WorkloadId != expected)
            throw new InvalidDataException("Stored Workload identity does not match its key.");
        if (plan is not null && (state.WorkloadId != plan.WorkloadId ||
            state.PlanRevisionId != plan.PlanRevisionId || state.PlanHash != plan.DeterministicHash))
            throw new SchedulerRevisionConflictException("Plan identity does not match durable scheduler state.");
        if (state.Tasks.Select(x => x.TaskId).Distinct().Count() != state.Tasks.Count)
            throw new InvalidDataException("Scheduler Task IDs must be unique.");
        if (plan is not null && !state.Tasks.Select(x => x.TaskId).ToHashSet().SetEquals(plan.Tasks.Select(x => x.TaskId)))
            throw new InvalidDataException("Scheduler Tasks do not match the immutable plan.");
        if (state.Hosts.Select(x => x.HostId).Distinct().Count() != state.Hosts.Count)
            throw new InvalidDataException("Host snapshot IDs must be unique.");

        foreach (var task in state.Tasks)
        {
            if (task.TaskId == default || task.AttemptGeneration < 0 || task.RetryCount < 0)
                throw new InvalidDataException("Scheduled Task has invalid counters.");
            if (task.Placement is { } placement &&
                (placement.Generation != task.AttemptGeneration || placement.HostId == default || placement.IncarnationId == default))
                throw new InvalidDataException("Placement generation or identity is invalid.");
            if (task.Claim is { } claim &&
                (claim.Generation != task.AttemptGeneration || claim.HostId == default ||
                 task.Placement is null || claim.HostId != task.Placement.HostId))
                throw new InvalidDataException("Attempt claim does not match its placement generation.");
            if (task.State is ScheduledTaskState.Placed or ScheduledTaskState.Running or ScheduledTaskState.Pausing
                    or ScheduledTaskState.Cancelling or ScheduledTaskState.Ambiguous &&
                (task.Placement is null || task.Claim is null))
                throw new InvalidDataException("An active Task requires matching placement and claim.");
            if (task.SelectedTerminalGeneration is { } selected &&
                (selected <= 0 || selected > task.AttemptGeneration || !IsResultTerminal(task.State)))
                throw new InvalidDataException("Selected terminal generation is invalid.");
        }

        foreach (var host in state.Hosts)
        {
            if (host.HostId == default || host.IncarnationId == default || host.PoolId == default)
                throw new InvalidDataException("Host snapshot identity is invalid.");
            ValidateResources(host.Capacity);
            if (host.Capabilities.Any(string.IsNullOrWhiteSpace) || host.SetupFingerprints.Any(string.IsNullOrWhiteSpace))
                throw new InvalidDataException("Host capabilities and setup fingerprints cannot be blank.");
        }

        if (state.RateSlices.Select(x => x.LeaseId).Distinct(StringComparer.Ordinal).Count() != state.RateSlices.Count)
            throw new InvalidDataException("Rate slice lease IDs must be unique.");
        foreach (var slice in state.RateSlices)
            if (string.IsNullOrWhiteSpace(slice.LeaseId) || string.IsNullOrWhiteSpace(slice.Scope) ||
                slice.TaskId == default || slice.Generation <= 0 || slice.HostId == default ||
                slice.Amount <= 0 || slice.ConservativeFloor < 0 || slice.ConservativeFloor > slice.Amount ||
                slice.ExpiresAt <= slice.IssuedAt)
                throw new InvalidDataException("Rate slice is invalid.");

        if (state.Results.GroupBy(x => (x.TaskId, x.Generation)).Any(x => x.Count() != 1))
            throw new InvalidDataException("A Task generation cannot have duplicate result receipts.");
        foreach (var task in state.Tasks.Where(x => x.SelectedTerminalGeneration.HasValue))
            if (state.Results.Count(x => x.TaskId == task.TaskId && x.Generation == task.SelectedTerminalGeneration) != 1)
                throw new InvalidDataException("A selected terminal generation must have exactly one result receipt.");
    }

    private static bool IsResultTerminal(ScheduledTaskState state) =>
        state is ScheduledTaskState.Succeeded or ScheduledTaskState.Failed or ScheduledTaskState.Quarantined;

    private static void ValidateResources(ResourceRequirements resources)
    {
        if (resources.CpuCores < 0 || resources.MemoryBytes < 0 || resources.DiskBytes < 0 ||
            resources.GpuCount < 0 || resources.ProcessCount < 0 || resources.ContainerCount < 0 ||
            resources.VmCount < 0 || resources.ConcurrencyUnits < 0)
            throw new InvalidDataException("Host resource values cannot be negative.");
    }
}
