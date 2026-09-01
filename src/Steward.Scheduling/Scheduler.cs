using Steward.Contracts;
using Steward.Domain;
using Steward.Providers.Abstractions;

namespace Steward.Scheduling;

public sealed record PlacementDecision(TaskId TaskId, HostId HostId, int Generation, string Explanation);
public sealed record SchedulingResult(
    SchedulerState State,
    IReadOnlyList<PlacementDecision> Placements,
    IReadOnlyList<PoolDemand> PoolDemands);
public sealed record SchedulingOptions(TimeSpan MaximumHostObservationAge)
{
    public static SchedulingOptions Default { get; } = new(TimeSpan.FromMinutes(5));
    public SchedulingOptions Validate()
    {
        if (MaximumHostObservationAge <= TimeSpan.Zero || MaximumHostObservationAge > TimeSpan.FromDays(1))
            throw new ArgumentOutOfRangeException(nameof(MaximumHostObservationAge));
        return this;
    }
}

public sealed class CompositeScheduler
{
    private readonly ISchedulerStateStore store;
    private readonly GlobalRateAllocator? rateAllocator;
    private readonly TimeSpan rateSliceTimeToLive;

    public CompositeScheduler(
        ISchedulerStateStore store,
        GlobalRateAllocator? rateAllocator = null,
        TimeSpan? rateSliceTimeToLive = null)
    {
        this.store = store;
        this.rateAllocator = rateAllocator;
        this.rateSliceTimeToLive = rateSliceTimeToLive ?? TimeSpan.FromMinutes(5);
        if (this.rateSliceTimeToLive <= TimeSpan.Zero || this.rateSliceTimeToLive > TimeSpan.FromDays(7))
            throw new ArgumentOutOfRangeException(nameof(rateSliceTimeToLive));
    }

    public async Task<SchedulerState> RegisterAsync(WorkloadPlan plan, CancellationToken cancellationToken = default)
    {
        var existing = await store.LoadAsync(plan.WorkloadId, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            if (existing.PlanRevisionId != plan.PlanRevisionId || existing.PlanHash != plan.DeterministicHash)
                throw new SchedulerRevisionConflictException("The Workload already has a different immutable plan.");
            return existing;
        }
        var initial = SchedulerState.Create(plan) with { Revision = 0 };
        if (!await store.TrySaveAsync(initial, -1, cancellationToken).ConfigureAwait(false))
            return await RequireAsync(plan, cancellationToken).ConfigureAwait(false);
        return initial;
    }

    public Task<SchedulerState> SetHostsAsync(
        WorkloadPlan plan, IReadOnlyList<HostCapacitySnapshot> hosts, CancellationToken cancellationToken = default)
    {
        if (hosts.Select(x => x.HostId).Distinct().Count() != hosts.Count)
            throw new ArgumentException("Host capacity snapshots must have unique Host IDs.", nameof(hosts));
        return MutateAsync(plan, s => s with { Hosts = hosts.ToArray() }, cancellationToken);
    }

    public async Task<SchedulingResult> ScheduleAsync(
        WorkloadPlan plan, DateTimeOffset now, PoolId demandPool, CancellationToken cancellationToken = default)
        => await ScheduleAsync(plan, now, demandPool, SchedulingOptions.Default, cancellationToken).ConfigureAwait(false);

    public async Task<SchedulingResult> ScheduleAsync(
        WorkloadPlan plan,
        DateTimeOffset now,
        PoolId demandPool,
        SchedulingOptions options,
        CancellationToken cancellationToken = default)
    {
        options.Validate();
        while (true)
        {
            var current = await RequireAsync(plan, cancellationToken).ConfigureAwait(false);
            var tasks = current.Tasks.ToDictionary(x => x.TaskId);
            ReleaseDependencies(plan, tasks);
            ApplyAggregatePolicy(plan, tasks);
            var hosts = current.Hosts
                .Where(x => x.Available && now - x.ObservedAt <= options.MaximumHostObservationAge)
                .OrderBy(x => x.HostId.ToString(), StringComparer.Ordinal).ToArray();
            var slices = current.RateSlices.ToList();
            var decisions = new List<PlacementDecision>();
            var demands = new List<PoolDemand>();
            var claimed = new List<GlobalRateLease>();

            try
            {
                if (current.Intent == WorkloadDesiredState.Active)
                {
                    var activeCount = tasks.Values.Count(x => IsConcurrencyActive(x.State));
                    foreach (var node in plan.Tasks
                                 .Where(x => tasks[x.TaskId].State == ScheduledTaskState.Ready &&
                                             (tasks[x.TaskId].Backoff is null || tasks[x.TaskId].Backoff!.NotBefore <= now))
                                 .OrderByDescending(x => x.Resources.MemoryBytes)
                                 .ThenBy(x => x.TaskId.ToString(), StringComparer.Ordinal))
                    {
                        if (activeCount >= plan.MaximumConcurrency)
                            break;
                        var candidates = hosts.Where(x => Compatible(node, x) && Fits(node.Resources, Remaining(x, plan, tasks)))
                            .OrderByDescending(x => CacheScore(node, x))
                            .ThenByDescending(x => AffinityScore(node, x, plan, tasks))
                            .ThenBy(x => WastedMemory(node.Resources, Remaining(x, plan, tasks)))
                            .ThenBy(x => x.HostId.ToString(), StringComparer.Ordinal)
                            .ToArray();
                        if (candidates.Length == 0)
                        {
                            demands.Add(new PoolDemand($"{plan.WorkloadId}:{node.TaskId}", node.AffinityKey ?? node.SetupFingerprint));
                            continue;
                        }

                        var host = candidates[0];
                        var item = tasks[node.TaskId];
                        var generation = checked(item.AttemptGeneration + 1);
                        if (node.ExternalRates.Count > 0)
                        {
                            if (rateAllocator is null)
                                throw new InvalidOperationException("External-rate requirements need a global rate allocator.");
                            var leases = await rateAllocator.TryClaimAsync(
                                plan.WorkloadId, node.TaskId, generation, host.HostId, node.ExternalRates,
                                now, rateSliceTimeToLive, cancellationToken).ConfigureAwait(false);
                            if (leases is null) continue;
                            claimed.AddRange(leases);
                            slices.AddRange(leases.Select(x => new RateSliceState(
                                x.LeaseId, x.Scope, x.TaskId, x.Generation, x.HostId, x.Amount,
                                x.IssuedAt, x.ExpiresAt, x.ExpiredBehavior, x.ConservativeFloor)));
                        }
                        var attemptId = DeterministicAttemptId(plan.PlanRevisionId, node.TaskId, generation);
                        tasks[node.TaskId] = item with
                        {
                            State = ScheduledTaskState.Placed,
                            AttemptGeneration = generation,
                            Placement = new(host.HostId, host.IncarnationId, generation, now),
                            Claim = new(attemptId, generation, host.HostId, false, now),
                            Backoff = null
                        };
                        activeCount++;
                        decisions.Add(new(node.TaskId, host.HostId, generation,
                            CacheScore(node, host) > 0 ? "compatible host; setup cache hit" : "compatible host; best resource fit"));
                    }
                }

                var next = current with
                {
                    Revision = current.Revision + 1,
                    Tasks = plan.Tasks.Select(x => tasks[x.TaskId]).ToArray(),
                    RateSlices = slices.ToArray()
                };
                if (await store.TrySaveAsync(next, current.Revision, cancellationToken).ConfigureAwait(false))
                    return new(next, decisions, demands);
            }
            catch
            {
                if (rateAllocator is not null && claimed.Count > 0)
                    await rateAllocator.ReleasePlacementClaimsAsync(claimed, now, cancellationToken).ConfigureAwait(false);
                throw;
            }
            if (rateAllocator is not null && claimed.Count > 0)
                await rateAllocator.ReleasePlacementClaimsAsync(claimed, now, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<PoolReconcileResult> ReconcilePoolDemandsAsync(
        SchedulingResult result,
        PoolCoordinator coordinator,
        PoolPolicy policy,
        DateTimeOffset now,
        Func<Host> hostFactory,
        CancellationToken cancellationToken = default) =>
        await coordinator.ReconcileAsync(policy, result.PoolDemands, now, hostFactory, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public Task<SchedulerState> MarkRunningAsync(
        WorkloadPlan plan, TaskId taskId, int generation, CancellationToken cancellationToken = default) =>
        MutateTaskAsync(plan, taskId, item =>
        {
            RequireGeneration(item, generation);
            if (item.State != ScheduledTaskState.Placed) throw new InvalidOperationException("Only a placed Task can start.");
            return item with { State = ScheduledTaskState.Running };
        }, cancellationToken);

    public Task<SchedulerState> MarkAmbiguousAsync(
        WorkloadPlan plan, TaskId taskId, int generation, CancellationToken cancellationToken = default) =>
        MutateTaskAsync(plan, taskId, item =>
        {
            RequireGeneration(item, generation);
            if (IsTerminal(item.State)) throw new InvalidOperationException("A terminal Task cannot become ambiguous.");
            return item with { State = ScheduledTaskState.Ambiguous, Claim = item.Claim! with { Ambiguous = true } };
        }, cancellationToken);

    public Task<SchedulerState> ResolveAmbiguousAbsentAsync(
        WorkloadPlan plan, TaskId taskId, int generation, DateTimeOffset retryAt, CancellationToken cancellationToken = default) =>
        MutateAsync(plan, state =>
        {
            if (state.Tasks.All(x => x.TaskId != taskId))
                throw new KeyNotFoundException(
                    $"Task '{taskId}' is not in the plan.");
            var items = state.Tasks.ToDictionary(x => x.TaskId);
            var item = items[taskId];
            RequireGeneration(item, generation);
            if (item.State != ScheduledTaskState.Ambiguous) throw new InvalidOperationException("The attempt is not ambiguous.");
            var node = plan.Tasks.Single(x => x.TaskId == taskId);
            if (EligibleForReplacement(node, item))
            {
                items[taskId] = item with
                {
                    State = ScheduledTaskState.Ready,
                    Placement = null,
                    Claim = null,
                    Backoff = new(
                        retryAt,
                        TimeSpan.Zero,
                        "ambiguity resolved absent")
                };
                return state with { Tasks = items.Values.ToArray() };
            }
            items[taskId] = item with
            {
                State = ScheduledTaskState.Failed,
                Placement = null,
                Claim = null,
                SelectedTerminalGeneration = generation
            };
            var results = state.Results.ToList();
            if (!results.Any(x =>
                    x.TaskId == taskId &&
                    x.Generation == generation))
                results.Add(new(
                    taskId,
                    generation,
                    node.ResultReductionKey,
                    $"recovery-absent:{taskId}:{generation}",
                    false,
                    retryAt));
            return state with
            {
                Tasks = items.Values.ToArray(),
                Results = results
            };
        }, cancellationToken);

    public Task<SchedulerState> ResolveAmbiguousPresentAsync(
        WorkloadPlan plan,
        TaskId taskId,
        int generation,
        CancellationToken cancellationToken = default) =>
        MutateTaskAsync(plan, taskId, item =>
        {
            RequireGeneration(item, generation);
            if (item.State != ScheduledTaskState.Ambiguous)
                throw new InvalidOperationException(
                    "The attempt is not ambiguous.");
            return item with
            {
                State = ScheduledTaskState.Running,
                Claim = item.Claim! with { Ambiguous = false }
            };
        }, cancellationToken);

    public Task<SchedulerState> CompleteAsync(
        WorkloadPlan plan,
        TaskId taskId,
        int generation,
        bool success,
        string receipt,
        DateTimeOffset now,
        TimeSpan? retryDelay = null,
        bool poison = false,
        CancellationToken cancellationToken = default) =>
        MutateAsync(plan, state =>
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(receipt);
            var items = state.Tasks.ToDictionary(x => x.TaskId);
            var item = items[taskId];
            RequireGeneration(item, generation);
            if (item.State == ScheduledTaskState.Ambiguous)
                throw new InvalidOperationException("Ambiguous execution must be reconciled before accepting a result.");
            if (item.SelectedTerminalGeneration is not null)
                return state;
            var node = plan.Tasks.Single(x => x.TaskId == taskId);
            var results = state.Results.ToList();
            if (success)
            {
                items[taskId] = item with
                {
                    State = ScheduledTaskState.Succeeded,
                    Placement = null,
                    Claim = null,
                    SelectedTerminalGeneration = generation
                };
                results.Add(new(taskId, generation, node.ResultReductionKey, receipt, true, now));
            }
            else if (poison || item.RetryCount >= node.RetryCap)
            {
                items[taskId] = item with
                {
                    State = poison ? ScheduledTaskState.Quarantined : ScheduledTaskState.Failed,
                    Placement = null,
                    Claim = null,
                    QuarantineReason = poison ? receipt : null,
                    SelectedTerminalGeneration = generation
                };
                results.Add(new(taskId, generation, node.ResultReductionKey, receipt, false, now));
            }
            else
            {
                var delay = retryDelay ?? TimeSpan.FromSeconds(Math.Min(300, Math.Pow(2, item.RetryCount)));
                items[taskId] = item with
                {
                    State = ScheduledTaskState.Ready,
                    RetryCount = item.RetryCount + 1,
                    Placement = null,
                    Claim = null,
                    Backoff = new(now + delay, delay, receipt)
                };
            }
            PropagateTerminalDependencies(plan, items);
            ApplyAggregatePolicy(plan, items);
            var nextTasks = plan.Tasks.Select(x => items[x.TaskId]).ToArray();
            var intent = state.Intent == WorkloadDesiredState.Cancelling && nextTasks.All(x => IsTerminal(x.State))
                ? WorkloadDesiredState.Cancelled : state.Intent;
            return state with { Tasks = nextTasks, Results = results, Intent = intent };
        }, cancellationToken);

    public Task<SchedulerState> HandleHostLossAsync(
        WorkloadPlan plan, HostId hostId, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        MutateAsync(plan, state =>
        {
            var nodes = plan.Tasks.ToDictionary(x => x.TaskId);
            var tasks = state.Tasks.Select(item =>
            {
                if (item.Placement?.HostId != hostId || IsTerminal(item.State)) return item;
                if (item.State == ScheduledTaskState.Ambiguous) return item;
                var node = nodes[item.TaskId];
                var eligible = node.InterruptionClass == InterruptionClass.Restartable ||
                    (node.InterruptionClass == InterruptionClass.CheckpointResumable && item.CheckpointAvailable);
                return eligible && item.RetryCount < node.RetryCap
                    ? item with
                    {
                        State = ScheduledTaskState.Ready,
                        RetryCount = item.RetryCount + 1,
                        Placement = null,
                        Claim = null,
                        Backoff = new(now, TimeSpan.Zero, "Host lost")
                    }
                    : item with { State = ScheduledTaskState.Interrupted, Placement = null, Claim = null };
            }).ToArray();
            return state with
            {
                Tasks = tasks,
                Hosts = state.Hosts.Select(x => x.HostId == hostId ? x with { Available = false } : x).ToArray()
            };
        }, cancellationToken);

    public Task<SchedulerState> SetCheckpointAsync(
        WorkloadPlan plan, TaskId taskId, int generation, CancellationToken cancellationToken = default) =>
        MutateTaskAsync(plan, taskId, item => { RequireGeneration(item, generation); return item with { CheckpointAvailable = true }; }, cancellationToken);

    public Task<SchedulerState> RetryAsync(
        WorkloadPlan plan,
        TaskId taskId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default) =>
        MutateTaskAsync(plan, taskId, item =>
        {
            if (!IsTerminal(item.State))
                throw new InvalidOperationException("Only a terminal Task can be explicitly retried.");
            var node = plan.Tasks.Single(x => x.TaskId == taskId);
            if (item.RetryCount >= node.RetryCap)
                throw new InvalidOperationException("Task retry cap is exhausted.");
            return item with
            {
                State = ScheduledTaskState.Ready,
                RetryCount = item.RetryCount + 1,
                Placement = null,
                Claim = null,
                Backoff = new(now, TimeSpan.Zero, "explicit retry"),
                SelectedTerminalGeneration = null
            };
        }, cancellationToken);

    public Task<SchedulerState> PauseAsync(WorkloadPlan plan, CancellationToken cancellationToken = default) =>
        MutateAsync(plan, state => state with
        {
            Intent = WorkloadDesiredState.Paused,
            Tasks = state.Tasks.Select(x =>
            {
                if (x.State == ScheduledTaskState.Running)
                {
                    var node = plan.Tasks.Single(n => n.TaskId == x.TaskId);
                    return node.InterruptionClass == InterruptionClass.NonInterruptible ? x : x with { State = ScheduledTaskState.Pausing };
                }
                return x.State == ScheduledTaskState.Ready ? x with { State = ScheduledTaskState.Paused } : x;
            }).ToArray()
        }, cancellationToken);

    public Task<SchedulerState> ResumeAsync(WorkloadPlan plan, CancellationToken cancellationToken = default) =>
        MutateAsync(plan, state => state with
        {
            Intent = WorkloadDesiredState.Active,
            Tasks = state.Tasks.Select(x => x.State is ScheduledTaskState.Paused or ScheduledTaskState.Pausing
                ? x with { State = ScheduledTaskState.Ready, Placement = null, Claim = null } : x).ToArray()
        }, cancellationToken);

    public Task<SchedulerState> CancelAsync(WorkloadPlan plan, CancellationToken cancellationToken = default) =>
        MutateAsync(plan, state => state with
        {
            Intent = WorkloadDesiredState.Cancelling,
            Tasks = state.Tasks.Select(x =>
            {
                if (IsTerminal(x.State)) return x;
                var node = plan.Tasks.Single(n => n.TaskId == x.TaskId);
                if (x.State == ScheduledTaskState.Running && node.InterruptionClass == InterruptionClass.NonInterruptible) return x;
                return x.State is ScheduledTaskState.Running or ScheduledTaskState.Pausing
                    ? x with { State = ScheduledTaskState.Cancelling }
                    : x with { State = ScheduledTaskState.Cancelled, Placement = null, Claim = null };
            }).ToArray()
        }, cancellationToken);

    private Task<SchedulerState> MutateTaskAsync(
        WorkloadPlan plan, TaskId taskId, Func<ScheduledTask, ScheduledTask> mutation, CancellationToken cancellationToken) =>
        MutateAsync(plan, state =>
        {
            if (state.Tasks.All(x => x.TaskId != taskId)) throw new KeyNotFoundException($"Task '{taskId}' is not in the plan.");
            return state with { Tasks = state.Tasks.Select(x => x.TaskId == taskId ? mutation(x) : x).ToArray() };
        }, cancellationToken);

    internal async Task<SchedulerState> MutateAsync(
        WorkloadPlan plan, Func<SchedulerState, SchedulerState> mutation, CancellationToken cancellationToken)
    {
        while (true)
        {
            var current = await RequireAsync(plan, cancellationToken).ConfigureAwait(false);
            var changed = mutation(current) with { Revision = current.Revision + 1 };
            if (await store.TrySaveAsync(changed, current.Revision, cancellationToken).ConfigureAwait(false)) return changed;
        }
    }

    private async Task<SchedulerState> RequireAsync(WorkloadPlan plan, CancellationToken cancellationToken)
    {
        var state = await store.LoadAsync(plan.WorkloadId, cancellationToken).ConfigureAwait(false)
            ?? throw new KeyNotFoundException("Workload is not registered.");
        SchedulerStateValidator.Validate(state, plan);
        return state;
    }

    private static void ReleaseDependencies(WorkloadPlan plan, IDictionary<TaskId, ScheduledTask> tasks)
    {
        PropagateTerminalDependencies(plan, tasks);
        foreach (var node in plan.Tasks.Where(x => tasks[x.TaskId].State == ScheduledTaskState.Blocked))
            if (node.Dependencies.All(x => tasks[x].State == ScheduledTaskState.Succeeded))
                tasks[node.TaskId] = tasks[node.TaskId] with { State = ScheduledTaskState.Ready };
    }

    private static void PropagateTerminalDependencies(WorkloadPlan plan, IDictionary<TaskId, ScheduledTask> tasks)
    {
        if (plan.FailurePolicy == AggregateFailurePolicy.FailFast) return;
        bool changed;
        do
        {
            changed = false;
            foreach (var node in plan.Tasks.Where(x => tasks[x.TaskId].State == ScheduledTaskState.Blocked))
            {
                if (!node.Dependencies.Any(x => tasks[x].State is ScheduledTaskState.Failed or ScheduledTaskState.Quarantined
                        or ScheduledTaskState.Cancelled or ScheduledTaskState.SkippedDependency))
                    continue;
                tasks[node.TaskId] = tasks[node.TaskId] with { State = ScheduledTaskState.SkippedDependency };
                changed = true;
            }
        } while (changed);
    }

    private static void ApplyAggregatePolicy(WorkloadPlan plan, IDictionary<TaskId, ScheduledTask> tasks)
    {
        if (plan.FailurePolicy != AggregateFailurePolicy.FailFast ||
            !tasks.Values.Any(x => x.State is ScheduledTaskState.Failed or ScheduledTaskState.Quarantined)) return;
        foreach (var item in tasks.Values.Where(x => x.State is ScheduledTaskState.Blocked or ScheduledTaskState.Ready or ScheduledTaskState.Paused).ToArray())
            tasks[item.TaskId] = item with { State = ScheduledTaskState.Cancelled };
    }

    private static bool Compatible(TaskPlanNode task, HostCapacitySnapshot host) =>
        (task.RequiredHostId is null || task.RequiredHostId == host.HostId) &&
        task.RequiredHostCapabilities.All(host.Capabilities.Contains);

    private static ResourceRequirements Remaining(
        HostCapacitySnapshot host, WorkloadPlan plan, IReadOnlyDictionary<TaskId, ScheduledTask> tasks)
    {
        var active = plan.Tasks.Where(x => tasks[x.TaskId].Placement?.HostId == host.HostId &&
            tasks[x.TaskId].State is ScheduledTaskState.Placed or ScheduledTaskState.Running or
                ScheduledTaskState.Pausing or ScheduledTaskState.Cancelling).Select(x => x.Resources).ToArray();
        return new(
            Math.Max(0, host.Capacity.CpuCores - active.Sum(x => x.CpuCores)),
            Math.Max(0, host.Capacity.MemoryBytes - active.Sum(x => x.MemoryBytes)),
            Math.Max(0, host.Capacity.DiskBytes - active.Sum(x => x.DiskBytes)),
            Math.Max(0, host.Capacity.GpuCount - active.Sum(x => x.GpuCount)),
            Math.Max(0, host.Capacity.ProcessCount - active.Sum(x => x.ProcessCount)),
            Math.Max(0, host.Capacity.ContainerCount - active.Sum(x => x.ContainerCount)),
            Math.Max(0, host.Capacity.VmCount - active.Sum(x => x.VmCount)),
            Math.Max(0, host.Capacity.ConcurrencyUnits - active.Sum(x => x.ConcurrencyUnits)));
    }

    private static bool Fits(ResourceRequirements request, ResourceRequirements remaining) => request.FitsWithin(remaining);
    private static long WastedMemory(ResourceRequirements request, ResourceRequirements remaining) => remaining.MemoryBytes - request.MemoryBytes;
    private static int CacheScore(TaskPlanNode task, HostCapacitySnapshot host) =>
        task.SetupFingerprint is not null && host.SetupFingerprints.Contains(task.SetupFingerprint) ? 1 : 0;
    private static int AffinityScore(
        TaskPlanNode task, HostCapacitySnapshot host, WorkloadPlan plan, IReadOnlyDictionary<TaskId, ScheduledTask> tasks) =>
        task.AffinityKey is null ? 0 : plan.Tasks.Count(x => x.AffinityKey == task.AffinityKey && tasks[x.TaskId].Placement?.HostId == host.HostId);

    private static TaskAttemptId DeterministicAttemptId(PlanRevisionId plan, TaskId task, int generation)
    {
        Span<byte> bytes = stackalloc byte[16];
        plan.Value.TryWriteBytes(bytes);
        Span<byte> taskBytes = stackalloc byte[16];
        task.Value.TryWriteBytes(taskBytes);
        for (var i = 0; i < 16; i++) bytes[i] ^= taskBytes[i];
        BitConverter.TryWriteBytes(bytes[12..], generation);
        if (new Guid(bytes) == Guid.Empty) bytes[0] = 1;
        return new(new Guid(bytes));
    }

    private static bool EligibleForReplacement(TaskPlanNode node, ScheduledTask item) =>
        item.RetryCount < node.RetryCap &&
        (node.InterruptionClass == InterruptionClass.Restartable ||
         (node.InterruptionClass == InterruptionClass.CheckpointResumable && item.CheckpointAvailable));
    private static bool IsTerminal(ScheduledTaskState state) =>
        state is ScheduledTaskState.Succeeded or ScheduledTaskState.Failed or ScheduledTaskState.Cancelled
            or ScheduledTaskState.Quarantined or ScheduledTaskState.SkippedDependency;
    private static bool IsConcurrencyActive(ScheduledTaskState state) =>
        state is ScheduledTaskState.Placed or ScheduledTaskState.Running or
            ScheduledTaskState.Pausing or ScheduledTaskState.Cancelling;
    private static void RequireGeneration(ScheduledTask item, int generation)
    {
        if (item.AttemptGeneration != generation) throw new InvalidOperationException("Stale attempt generation.");
    }
}
