using Steward.Domain;

namespace Steward.Scheduling;

public sealed class GlobalRateAllocator(IGlobalRateStateStore store)
{
    public async Task<GlobalRateState> ConfigureAsync(
        string scope,
        decimal capacity,
        decimal refillPerSecond,
        decimal conservativeFloor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        if (capacity <= 0 || refillPerSecond < 0 || conservativeFloor < 0 || conservativeFloor > capacity)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        while (true)
        {
            var current = await store.LoadAsync(scope, cancellationToken).ConfigureAwait(false);
            var next = current is null
                ? new(scope, 0, capacity, refillPerSecond, capacity, now, null, conservativeFloor, [])
                : Refill(current, now) with
                {
                    Revision = current.Revision + 1,
                    Capacity = capacity,
                    RefillPerSecond = refillPerSecond,
                    Available = Math.Min(
                        Math.Max(0, capacity - SpendableLeasedAuthority(current, now)),
                        Refill(current, now).Available),
                    ConservativeFloor = conservativeFloor
                };
            if (await store.TrySaveAsync(next, current?.Revision ?? -1, cancellationToken).ConfigureAwait(false))
                return next;
        }
    }

    public async Task<IReadOnlyList<GlobalRateLease>?> TryClaimAsync(
        WorkloadId workloadId,
        TaskId taskId,
        int generation,
        HostId hostId,
        IReadOnlyList<ExternalRateRequirement> requirements,
        DateTimeOffset now,
        TimeSpan timeToLive,
        CancellationToken cancellationToken = default)
    {
        if (generation <= 0) throw new ArgumentOutOfRangeException(nameof(generation));
        if (timeToLive <= TimeSpan.Zero || timeToLive > TimeSpan.FromDays(7))
            throw new ArgumentOutOfRangeException(nameof(timeToLive));
        var claimed = new List<GlobalRateLease>();
        foreach (var requirement in requirements.OrderBy(x => x.Scope, StringComparer.Ordinal))
        {
            var lease = await TryClaimOneAsync(workloadId, taskId, generation, hostId, requirement, now, timeToLive, cancellationToken)
                .ConfigureAwait(false);
            if (lease is null)
            {
                await ReleasePlacementClaimsAsync(claimed, now, cancellationToken).ConfigureAwait(false);
                return null;
            }
            claimed.Add(lease);
        }
        return claimed;
    }

    private async Task<GlobalRateLease?> TryClaimOneAsync(
        WorkloadId workloadId, TaskId taskId, int generation, HostId hostId,
        ExternalRateRequirement requirement, DateTimeOffset now, TimeSpan ttl, CancellationToken cancellationToken)
    {
        while (true)
        {
            var current = await store.LoadAsync(requirement.Scope, cancellationToken).ConfigureAwait(false)
                ?? throw new KeyNotFoundException($"Global rate bucket '{requirement.Scope}' is not configured.");
            var refilled = Refill(current, now);
            if (refilled.DelayedUntil > now || refilled.Available < requirement.Amount) return null;
            var lease = new GlobalRateLease(
                Guid.NewGuid().ToString("N"),
                requirement.Scope, workloadId, taskId, generation, hostId, requirement.Amount, 0, 0, now, now + ttl,
                refilled.ConservativeFloor > 0 ? ExpiredRateBehavior.ConservativeFloor : ExpiredRateBehavior.Pause,
                Math.Min(refilled.ConservativeFloor, requirement.Amount));
            var next = refilled with
            {
                Revision = current.Revision + 1,
                Available = refilled.Available - requirement.Amount,
                Leases = [.. refilled.Leases, lease]
            };
            if (await store.TrySaveAsync(next, current.Revision, cancellationToken).ConfigureAwait(false)) return lease;
        }
    }

    public async Task ReportRetryAfterAsync(
        string scope, DateTimeOffset retryAfter, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await MutateAsync(scope, state =>
        {
            var refilled = Refill(state, now);
            return refilled with { DelayedUntil = refilled.DelayedUntil > retryAfter ? refilled.DelayedUntil : retryAfter };
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task ConsumeAsync(
        string scope, string leaseId, decimal amount, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (amount <= 0) throw new ArgumentOutOfRangeException(nameof(amount));
        await MutateAsync(scope, state =>
        {
            var leases = state.Leases.ToArray();
            var index = Array.FindIndex(leases, x => x.LeaseId == leaseId);
            if (index < 0) throw new KeyNotFoundException("Global-rate lease does not exist.");
            var lease = leases[index];
            var available = AvailableAt(lease, now);
            if (amount > available) throw new InvalidOperationException("External-rate allocation is exhausted.");
            leases[index] = lease with
            {
                Consumed = lease.Consumed + amount,
                PostExpiryConsumed = lease.PostExpiryConsumed + (now >= lease.ExpiresAt ? amount : 0)
            };
            return state with { Leases = leases };
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task ReleasePlacementClaimsAsync(
        IEnumerable<GlobalRateLease> leases, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        foreach (var group in leases.GroupBy(x => x.Scope, StringComparer.Ordinal))
            await MutateAsync(group.Key, state =>
            {
                var ids = group.Select(x => x.LeaseId).ToHashSet(StringComparer.Ordinal);
                var released = state.Leases.Where(x => ids.Contains(x.LeaseId)).Sum(x => x.Remaining);
                return Refill(state, now) with
                {
                    Available = Math.Min(state.Capacity, Refill(state, now).Available + released),
                    Leases = state.Leases.Where(x => !ids.Contains(x.LeaseId)).ToArray()
                };
            }, cancellationToken).ConfigureAwait(false);
    }

    public async Task ReconcileUnusedAsync(
        string scope,
        string leaseId,
        decimal finalConsumed,
        DateTimeOffset acknowledgedAt,
        bool authorityRevoked,
        CancellationToken cancellationToken = default)
    {
        await MutateAsync(scope, state =>
        {
            var lease = state.Leases.SingleOrDefault(x => x.LeaseId == leaseId)
                ?? throw new KeyNotFoundException("Global-rate lease does not exist.");
            if (finalConsumed < lease.Consumed || finalConsumed > lease.Amount)
                throw new InvalidOperationException("Final consumption cannot contradict durable usage.");
            if (acknowledgedAt < lease.ExpiresAt && !authorityRevoked)
                throw new InvalidOperationException("Unused authority can be returned only after expiry or explicit revocation acknowledgement.");
            var returned = lease.Amount - finalConsumed;
            var refilled = Refill(state, acknowledgedAt);
            return refilled with
            {
                Available = Math.Min(refilled.Capacity, refilled.Available + returned),
                Leases = state.Leases.Where(x => x.LeaseId != leaseId).ToArray()
            };
        }, cancellationToken).ConfigureAwait(false);
    }

    public static decimal AvailableAt(GlobalRateLease lease, DateTimeOffset now) =>
        now < lease.ExpiresAt ? lease.Remaining :
        lease.ExpiredBehavior == ExpiredRateBehavior.ConservativeFloor
            ? Math.Min(lease.Remaining, Math.Max(0, lease.ConservativeFloor - lease.PostExpiryConsumed)) : 0;

    private async Task<GlobalRateState> MutateAsync(
        string scope, Func<GlobalRateState, GlobalRateState> mutation, CancellationToken cancellationToken)
    {
        while (true)
        {
            var current = await store.LoadAsync(scope, cancellationToken).ConfigureAwait(false)
                ?? throw new KeyNotFoundException($"Global rate bucket '{scope}' is not configured.");
            var next = mutation(current) with { Revision = current.Revision + 1 };
            if (await store.TrySaveAsync(next, current.Revision, cancellationToken).ConfigureAwait(false)) return next;
        }
    }

    private static GlobalRateState Refill(GlobalRateState state, DateTimeOffset now)
    {
        if (now <= state.RefilledAt) return state;
        var amount = (decimal)(now - state.RefilledAt).TotalSeconds * state.RefillPerSecond;
        var maximumAvailable = Math.Max(0, state.Capacity - SpendableLeasedAuthority(state, now));
        return state with { Available = Math.Min(maximumAvailable, state.Available + amount), RefilledAt = now };
    }

    private static decimal SpendableLeasedAuthority(GlobalRateState state, DateTimeOffset now) =>
        state.Leases.Sum(x => AvailableAt(x, now));
}

public sealed record ReducedResult(
    int SuccessfulTasks,
    int FailedTasks,
    int PendingTasks,
    bool IsTerminal,
    WorkloadObservedState State,
    IReadOnlyDictionary<string, string> Receipts);

public static class WorkloadResultReducer
{
    public static ReducedResult Reduce(WorkloadPlan plan, SchedulerState state)
    {
        SchedulerStateValidator.Validate(state, plan);
        var selected = state.Results
            .Join(state.Tasks.Where(x => x.SelectedTerminalGeneration.HasValue),
                r => new { r.TaskId, r.Generation },
                t => new { t.TaskId, Generation = t.SelectedTerminalGeneration!.Value },
                (r, _) => r)
            .GroupBy(x => x.TaskId)
            .Select(x => x.Single())
            .ToArray();
        var success = state.Tasks.Count(x => x.State == ScheduledTaskState.Succeeded);
        var failures = state.Tasks.Count(x => x.State is ScheduledTaskState.Failed or ScheduledTaskState.Quarantined
            or ScheduledTaskState.Cancelled or ScheduledTaskState.SkippedDependency);
        var pending = state.Tasks.Count - success - failures;
        var terminal = pending == 0;
        var observed = !terminal
            ? state.Intent == WorkloadDesiredState.Paused ? WorkloadObservedState.Paused : WorkloadObservedState.Running
            : state.Intent is WorkloadDesiredState.Cancelling or WorkloadDesiredState.Cancelled
                ? WorkloadObservedState.Cancelled
                : failures == 0 ? WorkloadObservedState.Succeeded
                : success > 0 && plan.FailurePolicy == AggregateFailurePolicy.PartialSuccess
                    ? WorkloadObservedState.PartiallySucceeded : WorkloadObservedState.Failed;
        return new(success, failures, pending, terminal, observed,
            selected.Where(x => x.Success).ToDictionary(x => x.ReductionKey, x => x.Receipt, StringComparer.Ordinal));
    }
}
