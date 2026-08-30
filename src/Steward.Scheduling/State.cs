using Steward.Domain;

namespace Steward.Scheduling;

public enum ScheduledTaskState
{
    Blocked, Ready, Placed, Running, Pausing, Paused, Cancelling,
    Succeeded, Failed, Cancelled, Interrupted, Ambiguous, Quarantined, SkippedDependency
}

public sealed record BackoffState(DateTimeOffset NotBefore, TimeSpan Delay, string Reason);
public sealed record PlacementState(HostId HostId, NodeIncarnationId IncarnationId, int Generation, DateTimeOffset PlacedAt);
public sealed record AttemptClaim(TaskAttemptId AttemptId, int Generation, HostId HostId, bool Ambiguous, DateTimeOffset ClaimedAt);
public sealed record ResultReceipt(TaskId TaskId, int Generation, string ReductionKey, string Receipt, bool Success, DateTimeOffset RecordedAt);

public sealed record ScheduledTask(
    TaskId TaskId,
    ScheduledTaskState State,
    int AttemptGeneration = 0,
    int RetryCount = 0,
    PlacementState? Placement = null,
    AttemptClaim? Claim = null,
    BackoffState? Backoff = null,
    string? QuarantineReason = null,
    bool CheckpointAvailable = false,
    int? SelectedTerminalGeneration = null);

public sealed record HostCapacitySnapshot(
    HostId HostId,
    NodeIncarnationId IncarnationId,
    PoolId PoolId,
    ResourceRequirements Capacity,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> SetupFingerprints,
    DateTimeOffset ObservedAt,
    bool Available = true);

public sealed record RateSliceState(
    string LeaseId,
    string Scope,
    TaskId TaskId,
    int Generation,
    HostId HostId,
    decimal Amount,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    ExpiredRateBehavior ExpiredBehavior,
    decimal ConservativeFloor);

public sealed record SchedulerState(
    WorkloadId WorkloadId,
    PlanRevisionId PlanRevisionId,
    string PlanHash,
    long Revision,
    WorkloadDesiredState Intent,
    IReadOnlyList<ScheduledTask> Tasks,
    IReadOnlyList<HostCapacitySnapshot> Hosts,
    IReadOnlyList<RateSliceState> RateSlices,
    IReadOnlyList<ResultReceipt> Results)
{
    public static SchedulerState Create(WorkloadPlan plan) => new(
        plan.WorkloadId, plan.PlanRevisionId, plan.DeterministicHash, 0, WorkloadDesiredState.Active,
        plan.Tasks.Select(x => new ScheduledTask(x.TaskId,
            x.Dependencies.Count == 0 ? ScheduledTaskState.Ready : ScheduledTaskState.Blocked)).ToArray(),
        [], [], []);
}

public sealed class SchedulerRevisionConflictException(string message) : InvalidOperationException(message);
public sealed class SchedulerSchemaException(string message) : InvalidOperationException(message);

public interface ISchedulerStateStore : IAsyncDisposable
{
    Task<SchedulerState?> LoadAsync(WorkloadId workloadId, CancellationToken cancellationToken = default);
    Task<bool> TrySaveAsync(SchedulerState state, long expectedRevision, CancellationToken cancellationToken = default);
}
