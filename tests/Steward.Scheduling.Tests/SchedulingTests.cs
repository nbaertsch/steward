using Microsoft.Data.Sqlite;
using Steward.Domain;
using Steward.Scheduling;

namespace Steward.Scheduling.Tests;

public sealed class SchedulingTests
{
    [Fact]
    public void Plan_hash_is_deterministic_and_cycles_are_rejected()
    {
        var workload = Id<WorkloadId>(1);
        var revision = Id<PlanRevisionId>(2);
        var a = Node(3);
        var b = Node(4, [a.TaskId]);
        var first = Plan(workload, revision, [a, b]);
        var second = Plan(workload, revision, [b, a]);
        Assert.Equal(first.DeterministicHash, second.DeterministicHash);
        Assert.Throws<ArgumentException>(() => Plan(workload, revision,
            [a with { Dependencies = [b.TaskId] }, b]));
    }

    [Fact]
    public void Canonical_task_input_participates_in_plan_hash()
    {
        var workload = Id<WorkloadId>(5);
        var revision = Id<PlanRevisionId>(6);
        var first = Node(7) with { Input = TaskInput.Parse("application/json", "1.0", """{"b":[2,1],"a":1.0}""") };
        var reordered = Node(7) with { Input = TaskInput.Parse("application/json", "1.0", """{"a":1,"b":[2.0,1e0]}""") };
        var changed = Node(7) with { Input = TaskInput.Parse("application/json", "1.0", """{"a":2,"b":[2,1]}""") };
        Assert.Equal(Plan(workload, revision, [first]).DeterministicHash,
            Plan(workload, revision, [reordered]).DeterministicHash);
        Assert.NotEqual(Plan(workload, revision, [first]).DeterministicHash,
            Plan(workload, revision, [changed]).DeterministicHash);
        var concurrencyOne = new WorkloadPlan(workload, revision, WorkloadPlan.CurrentSchemaVersion,
            "test", "1.0", [first], AggregateFailurePolicy.PartialSuccess, 1);
        var concurrencyTwo = new WorkloadPlan(workload, revision, WorkloadPlan.CurrentSchemaVersion,
            "test", "1.0", [first], AggregateFailurePolicy.PartialSuccess, 2);
        Assert.NotEqual(concurrencyOne.DeterministicHash, concurrencyTwo.DeterministicHash);
        Assert.Throws<ArgumentException>(() => TaskInput.Parse(
            "application/json", "1.0", $"\"{new string('x', TaskInput.MaximumUtf8Bytes)}\""));
    }

    [Fact]
    public async Task Three_hosts_pack_three_hundred_children_without_duplicate_placement()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler1 = new CompositeScheduler(store);
        var scheduler2 = new CompositeScheduler(store);
        var plan = Plan(Id<WorkloadId>(10), Id<PlanRevisionId>(11),
            Enumerable.Range(1, 300).Select(i => Node(1000 + i)).ToArray());
        await scheduler1.RegisterAsync(plan);
        var hosts = Enumerable.Range(1, 3).Select(i => Host(2000 + i, memory: 100)).ToArray();
        await scheduler1.SetHostsAsync(plan, hosts);
        var results = await Task.WhenAll(
            scheduler1.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(90)),
            scheduler2.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(90)));
        var state = results.OrderByDescending(x => x.State.Revision).First().State;
        Assert.Equal(300, state.Tasks.Count(x => x.Placement is not null));
        Assert.Equal(300, state.Tasks.Select(x => (x.TaskId, x.AttemptGeneration)).Distinct().Count());
        Assert.Equal(3, state.Tasks.Select(x => x.Placement!.HostId).Distinct().Count());
    }

    [Fact]
    public async Task Workload_concurrency_caps_three_hundred_tasks_across_many_hosts_and_releases()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var nodes = Enumerable.Range(1, 300).Select(i => Node(3000 + i)).ToArray();
        var plan = new WorkloadPlan(
            Id<WorkloadId>(2990), Id<PlanRevisionId>(2991), WorkloadPlan.CurrentSchemaVersion,
            "test", "1.0", nodes, AggregateFailurePolicy.PartialSuccess, maximumConcurrency: 16);
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan,
            Enumerable.Range(1, 30).Select(i => Host(4000 + i, 100)).ToArray());
        var first = await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(2992));
        Assert.Equal(16, first.Placements.Count);
        Assert.Empty(first.PoolDemands);
        Assert.Equal(16, first.State.Tasks.Count(x => x.State == ScheduledTaskState.Placed));

        var completed = first.Placements[0];
        await scheduler.CompleteAsync(plan, completed.TaskId, completed.Generation, true, "done", DateTimeOffset.UtcNow);
        var second = await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(2992));
        Assert.Single(second.Placements);
        Assert.Equal(16, second.State.Tasks.Count(x =>
            x.State is ScheduledTaskState.Placed or ScheduledTaskState.Running or
                ScheduledTaskState.Pausing or ScheduledTaskState.Cancelling));
    }

    [Fact]
    public async Task Dependency_success_releases_child_and_result_is_exactly_once()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var parent = Node(21);
        var child = Node(22, [parent.TaskId]);
        var plan = Plan(Id<WorkloadId>(20), Id<PlanRevisionId>(23), [parent, child]);
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan, [Host(24, 2)]);
        var scheduled = await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(25));
        Assert.Single(scheduled.Placements);
        await scheduler.CompleteAsync(plan, parent.TaskId, 1, true, "parent", DateTimeOffset.UtcNow);
        var released = await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(25));
        Assert.Contains(released.Placements, x => x.TaskId == child.TaskId);
        var completed = await scheduler.CompleteAsync(plan, child.TaskId, 1, true, "child", DateTimeOffset.UtcNow);
        var duplicate = await scheduler.CompleteAsync(plan, child.TaskId, 1, true, "other", DateTimeOffset.UtcNow);
        Assert.Equal(2, duplicate.Results.Count);
        Assert.Equal(2, WorkloadResultReducer.Reduce(plan, duplicate).SuccessfulTasks);
        Assert.Equal(completed.Results.Count, duplicate.Results.Count);
    }

    [Fact]
    public async Task Ambiguous_attempt_blocks_replacement_and_host_loss_requeues_only_eligible()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var restartable = Node(31) with { InterruptionClass = InterruptionClass.Restartable, RetryCap = 2 };
        var noninterruptible = Node(32) with { InterruptionClass = InterruptionClass.NonInterruptible };
        var plan = Plan(Id<WorkloadId>(30), Id<PlanRevisionId>(33), [restartable, noninterruptible]);
        await scheduler.RegisterAsync(plan);
        var host = Host(34, 2);
        await scheduler.SetHostsAsync(plan, [host]);
        await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(35));
        await scheduler.MarkAmbiguousAsync(plan, restartable.TaskId, 1);
        var lost = await scheduler.HandleHostLossAsync(plan, host.HostId, DateTimeOffset.UtcNow);
        Assert.Equal(ScheduledTaskState.Ambiguous, lost.Tasks.Single(x => x.TaskId == restartable.TaskId).State);
        Assert.Equal(ScheduledTaskState.Interrupted, lost.Tasks.Single(x => x.TaskId == noninterruptible.TaskId).State);
    }

    [Fact]
    public async Task Host_loss_requeues_checkpointed_and_restartable_but_never_completed_tasks()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var restartable = Node(36) with { InterruptionClass = InterruptionClass.Restartable, RetryCap = 2 };
        var resumable = Node(37) with { InterruptionClass = InterruptionClass.CheckpointResumable, RetryCap = 2 };
        var completedNode = Node(38);
        var plan = Plan(Id<WorkloadId>(35), Id<PlanRevisionId>(39), [restartable, resumable, completedNode]);
        await scheduler.RegisterAsync(plan);
        var host = Host(39, 3);
        await scheduler.SetHostsAsync(plan, [host]);
        await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(35));
        await scheduler.SetCheckpointAsync(plan, resumable.TaskId, 1);
        await scheduler.CompleteAsync(plan, completedNode.TaskId, 1, true, "done", DateTimeOffset.UtcNow);
        var state = await scheduler.HandleHostLossAsync(plan, host.HostId, DateTimeOffset.UtcNow);
        Assert.Equal(ScheduledTaskState.Ready, state.Tasks.Single(x => x.TaskId == restartable.TaskId).State);
        Assert.Equal(ScheduledTaskState.Ready, state.Tasks.Single(x => x.TaskId == resumable.TaskId).State);
        Assert.Equal(ScheduledTaskState.Succeeded, state.Tasks.Single(x => x.TaskId == completedNode.TaskId).State);
    }

    [Fact]
    public async Task Failed_attempt_retries_with_backoff_then_stops_at_cap()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var node = Node(45) with { RetryCap = 1 };
        var plan = Plan(Id<WorkloadId>(44), Id<PlanRevisionId>(46), [node]);
        var now = DateTimeOffset.UtcNow;
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan, [Host(47, 1)]);
        await scheduler.ScheduleAsync(plan, now, Id<PoolId>(48));
        var retry = await scheduler.CompleteAsync(plan, node.TaskId, 1, false, "transient", now, TimeSpan.FromSeconds(5));
        Assert.Equal(ScheduledTaskState.Ready, retry.Tasks[0].State);
        Assert.Equal(now.AddSeconds(5), retry.Tasks[0].Backoff!.NotBefore);
        await scheduler.ScheduleAsync(plan, now.AddSeconds(5), Id<PoolId>(48));
        var failed = await scheduler.CompleteAsync(plan, node.TaskId, 2, false, "again", now.AddSeconds(6));
        Assert.Equal(ScheduledTaskState.Failed, failed.Tasks[0].State);
    }

    [Fact]
    public async Task Retry_cap_quarantines_and_pause_cancel_respect_noninterruptible()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var node = Node(41) with { RetryCap = 1, InterruptionClass = InterruptionClass.NonInterruptible };
        var plan = Plan(Id<WorkloadId>(40), Id<PlanRevisionId>(42), [node]);
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan, [Host(43, 1)]);
        await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(44));
        await scheduler.MarkRunningAsync(plan, node.TaskId, 1);
        var paused = await scheduler.PauseAsync(plan);
        Assert.Equal(ScheduledTaskState.Running, paused.Tasks[0].State);
        var cancelled = await scheduler.CancelAsync(plan);
        Assert.Equal(ScheduledTaskState.Running, cancelled.Tasks[0].State);
        var quarantined = await scheduler.CompleteAsync(plan, node.TaskId, 1, false, "bad input", DateTimeOffset.UtcNow, poison: true);
        Assert.Equal(ScheduledTaskState.Quarantined, quarantined.Tasks[0].State);
    }

    [Fact]
    public async Task Pause_and_cancel_propagate_to_interruptible_tasks()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var node = Node(48) with { InterruptionClass = InterruptionClass.CheckpointResumable };
        var plan = Plan(Id<WorkloadId>(47), Id<PlanRevisionId>(49), [node]);
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan, [Host(49, 1)]);
        await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(50));
        await scheduler.MarkRunningAsync(plan, node.TaskId, 1);
        var paused = await scheduler.PauseAsync(plan);
        Assert.Equal(ScheduledTaskState.Pausing, paused.Tasks[0].State);
        var cancelled = await scheduler.CancelAsync(plan);
        Assert.Equal(ScheduledTaskState.Cancelling, cancelled.Tasks[0].State);
    }

    [Fact]
    public async Task Rate_bucket_and_retry_after_bound_allocation()
    {
        await using var store = new InMemorySchedulerStateStore();
        await using var rateStore = new InMemoryGlobalRateStateStore();
        var allocator = new GlobalRateAllocator(rateStore);
        var scheduler = new CompositeScheduler(store, allocator);
        var nodes = Enumerable.Range(1, 3).Select(i =>
            Node(50 + i) with { ExternalRates = [new("inference", 4)] }).ToArray();
        var plan = Plan(Id<WorkloadId>(50), Id<PlanRevisionId>(54), nodes);
        var now = DateTimeOffset.UtcNow;
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan, [Host(55, 3)]);
        await allocator.ConfigureAsync("inference", 10, 0, 0, now);
        var result = await scheduler.ScheduleAsync(plan, now, Id<PoolId>(56));
        Assert.Equal(2, result.Placements.Count);
        Assert.Equal(8, result.State.RateSlices.Sum(x => x.Amount));
        await allocator.ReportRetryAfterAsync("inference", now.AddMinutes(1), now);
        var delayed = await scheduler.ScheduleAsync(plan, now.AddSeconds(10), Id<PoolId>(56));
        Assert.Equal(2, delayed.State.Tasks.Count(x => x.Placement is not null));
        foreach (var slice in delayed.State.RateSlices)
            await allocator.ConsumeAsync(slice.Scope, slice.LeaseId, slice.Amount, now);
        var consumed = await rateStore.LoadAsync("inference");
        Assert.All(consumed!.Leases, x => Assert.Equal(x.Amount, x.Consumed));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            allocator.ConsumeAsync("inference", delayed.State.RateSlices[0].LeaseId, 1, now));
    }

    [Fact]
    public async Task Global_bucket_is_shared_across_workloads_and_429_delays_both()
    {
        await using var globalStore = new InMemoryGlobalRateStateStore();
        var allocator1 = new GlobalRateAllocator(globalStore);
        var allocator2 = new GlobalRateAllocator(globalStore);
        var now = DateTimeOffset.UtcNow;
        await allocator1.ConfigureAsync("shared", 10, 0, 0, now);
        await using var stateStore1 = new InMemorySchedulerStateStore();
        await using var stateStore2 = new InMemorySchedulerStateStore();
        var scheduler1 = new CompositeScheduler(stateStore1, allocator1);
        var scheduler2 = new CompositeScheduler(stateStore2, allocator2);
        var plan1 = Plan(Id<WorkloadId>(501), Id<PlanRevisionId>(502),
            [Node(503) with { ExternalRates = [new("shared", 6)] }]);
        var plan2 = Plan(Id<WorkloadId>(504), Id<PlanRevisionId>(505),
            [Node(506) with { ExternalRates = [new("shared", 6)] }]);
        await scheduler1.RegisterAsync(plan1);
        await scheduler2.RegisterAsync(plan2);
        await scheduler1.SetHostsAsync(plan1, [Host(507, 1)]);
        await scheduler2.SetHostsAsync(plan2, [Host(508, 1)]);
        var results = await Task.WhenAll(
            scheduler1.ScheduleAsync(plan1, now, Id<PoolId>(509)),
            scheduler2.ScheduleAsync(plan2, now, Id<PoolId>(509)));
        Assert.Equal(1, results.Sum(x => x.Placements.Count));
        var global = await globalStore.LoadAsync("shared");
        Assert.True(global!.Leases.Sum(x => x.Amount) <= global.Capacity);

        await allocator1.ReportRetryAfterAsync("shared", now.AddMinutes(1), now);
        var plan3 = Plan(Id<WorkloadId>(510), Id<PlanRevisionId>(511),
            [Node(512) with { ExternalRates = [new("shared", 1)] }]);
        await using var stateStore3 = new InMemorySchedulerStateStore();
        var scheduler3 = new CompositeScheduler(stateStore3, allocator2);
        await scheduler3.RegisterAsync(plan3);
        await scheduler3.SetHostsAsync(plan3, [Host(513, 1)]);
        Assert.Empty((await scheduler3.ScheduleAsync(plan3, now.AddSeconds(1), Id<PoolId>(509))).Placements);
    }

    [Fact]
    public async Task Placement_CAS_loser_returns_its_global_rate_claim()
    {
        await using var globalStore = new InMemoryGlobalRateStateStore();
        var allocator = new GlobalRateAllocator(globalStore);
        var now = DateTimeOffset.UtcNow;
        await allocator.ConfigureAsync("cas", 10, 0, 0, now);
        await using var stateStore = new InMemorySchedulerStateStore();
        var first = new CompositeScheduler(stateStore, allocator);
        var second = new CompositeScheduler(stateStore, allocator);
        var plan = Plan(Id<WorkloadId>(520), Id<PlanRevisionId>(521),
            [Node(522) with { ExternalRates = [new("cas", 10)] }]);
        await first.RegisterAsync(plan);
        await first.SetHostsAsync(plan, [Host(523, 1)]);
        await Task.WhenAll(
            first.ScheduleAsync(plan, now, Id<PoolId>(524)),
            second.ScheduleAsync(plan, now, Id<PoolId>(524)));
        var global = await globalStore.LoadAsync("cas");
        Assert.Single(global!.Leases);
        Assert.Equal(0, global.Available);
    }

    [Fact]
    public async Task Refill_counts_outstanding_leases_against_global_capacity()
    {
        await using var globalStore = new InMemoryGlobalRateStateStore();
        var allocator = new GlobalRateAllocator(globalStore);
        var now = DateTimeOffset.UtcNow;
        await allocator.ConfigureAsync("burst", 10, 1, 0, now);
        var held = await allocator.TryClaimAsync(Id<WorkloadId>(530), Id<TaskId>(531), 1, Id<HostId>(532),
            [new("burst", 10)], now, TimeSpan.FromMinutes(1));
        Assert.NotNull(held);
        var denied = await allocator.TryClaimAsync(Id<WorkloadId>(533), Id<TaskId>(534), 1, Id<HostId>(535),
            [new("burst", 10)], now.AddSeconds(10), TimeSpan.FromMinutes(1));
        Assert.Null(denied);
        var state = await globalStore.LoadAsync("burst");
        Assert.True(state!.Available + state.Leases.Sum(x => GlobalRateAllocator.AvailableAt(x, now.AddSeconds(10))) <= state.Capacity);
    }

    [Fact]
    public async Task Expired_conservative_floor_is_a_cumulative_cap()
    {
        await using var globalStore = new InMemoryGlobalRateStateStore();
        var allocator = new GlobalRateAllocator(globalStore);
        var now = DateTimeOffset.UtcNow;
        await allocator.ConfigureAsync("floor", 10, 0, 2, now);
        var lease = Assert.Single((await allocator.TryClaimAsync(
            Id<WorkloadId>(540), Id<TaskId>(541), 1, Id<HostId>(542),
            [new("floor", 10)], now, TimeSpan.FromSeconds(1)))!);
        var expired = now.AddSeconds(2);
        await allocator.ConsumeAsync("floor", lease.LeaseId, 0.75m, expired);
        await allocator.ConsumeAsync("floor", lease.LeaseId, 0.75m, expired);
        await allocator.ConsumeAsync("floor", lease.LeaseId, 0.5m, expired);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            allocator.ConsumeAsync("floor", lease.LeaseId, 0.01m, expired));
    }

    [Fact]
    public async Task Delegations_are_bounded()
    {
        await using var store = new InMemorySchedulerStateStore();
        await using var globalStore = new InMemoryGlobalRateStateStore();
        var allocator = new GlobalRateAllocator(globalStore);
        var scheduler = new CompositeScheduler(store, allocator);
        var plan = Plan(Id<WorkloadId>(60), Id<PlanRevisionId>(61),
            Enumerable.Range(1, 5).Select(i => Node(60 + i) with
                {
                    ExternalRates = [new("partitioned", 2)],
                    IdentityGrantIds = [Id<IdentityGrantId>(600 + i)]
                }).ToArray());
        var now = DateTimeOffset.UtcNow;
        await allocator.ConfigureAsync("partitioned", 10, 0, 0, now);
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan, [Host(70, 5)]);
        var state = (await scheduler.ScheduleAsync(plan, now, Id<PoolId>(71))).State;
        var parts = DelegationPartitioner.Create(plan, state, now,
            new(2, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5), 1024, 2));
        Assert.Equal(3, parts.Count);
        Assert.All(parts, x => Assert.InRange(x.AllowedGenerations.Count, 1, 2));
        Assert.All(parts.SelectMany(x => x.AllowedGenerations), x => Assert.Equal(x.Minimum, x.Maximum));
        Assert.All(parts, part =>
        {
            Assert.NotNull(part.TaskAuthorityBindings);
            Assert.Equal(part.AllowedGenerations.Count, part.TaskAuthorityBindings!.Count);
            var allowed = part.AllowedGenerations.Select(x => (x.TaskId, x.Minimum)).ToHashSet();
            Assert.All(part.TaskAuthorityBindings, binding =>
            {
                Assert.Contains((binding.TaskId, binding.Generation), allowed);
                Assert.Equal(2, Assert.Single(binding.RateLimits).MaximumAmount);
                var task = plan.Tasks.Single(x => x.TaskId == binding.TaskId);
                Assert.Equal(task.IdentityGrantIds, binding.IdentityGrantIds);
            });
            Assert.Equal(
                part.TaskAuthorityBindings.SelectMany(x => x.RateLimits).Sum(x => x.MaximumAmount),
                part.RateLimits.Sum(x => x.MaximumAmount));
            Assert.Equal(
                part.TaskAuthorityBindings.SelectMany(x => x.IdentityGrantIds).OrderBy(x => x.ToString()),
                part.IdentityGrantIds.OrderBy(x => x.ToString()));
        });
        Assert.Equal(5, parts.SelectMany(x => x.TaskAuthorityBindings!).Select(x => x.TaskId).Distinct().Count());
        Assert.Equal(10, parts.SelectMany(x => x.RateLimits).Sum(x => x.MaximumAmount));
        await Task.WhenAll(state.RateSlices.Select(x =>
            allocator.ConsumeAsync(x.Scope, x.LeaseId, x.Amount, now)));
        var global = await globalStore.LoadAsync("partitioned");
        Assert.All(global!.Leases, x => Assert.Equal(x.Amount, x.Consumed));
    }

    [Fact]
    public async Task Delegation_retries_require_generation_specific_rate_or_identity_authority()
    {
        await using var store = new InMemorySchedulerStateStore();
        await using var globalStore = new InMemoryGlobalRateStateStore();
        var allocator = new GlobalRateAllocator(globalStore);
        var scheduler = new CompositeScheduler(store, allocator);
        var rateTask = Node(710) with { RetryCap = 3, ExternalRates = [new("retry", 1)] };
        var identityTask = Node(711) with
        {
            RetryCap = 3,
            IdentityGrantIds = [Id<IdentityGrantId>(712)]
        };
        var unboundTask = Node(713) with { RetryCap = 3 };
        var plan = Plan(Id<WorkloadId>(714), Id<PlanRevisionId>(715), [rateTask, identityTask, unboundTask]);
        var now = DateTimeOffset.UtcNow;
        await allocator.ConfigureAsync("retry", 1, 0, 0, now);
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan, [Host(716, 3)]);
        var state = (await scheduler.ScheduleAsync(plan, now, Id<PoolId>(717))).State;
        var delegation = Assert.Single(DelegationPartitioner.Create(
            plan, state, now, new(10, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5), 1024, 3)));
        var ranges = delegation.AllowedGenerations.ToDictionary(x => x.TaskId);
        Assert.Equal(ranges[rateTask.TaskId].Minimum, ranges[rateTask.TaskId].Maximum);
        Assert.Equal(ranges[identityTask.TaskId].Minimum, ranges[identityTask.TaskId].Maximum);
        Assert.True(ranges[unboundTask.TaskId].Maximum > ranges[unboundTask.TaskId].Minimum);
        Assert.Equal(3, delegation.TaskAuthorityBindings!.Count);
        Assert.Empty(delegation.TaskAuthorityBindings.Single(x => x.TaskId == unboundTask.TaskId).RateLimits);
        Assert.Empty(delegation.TaskAuthorityBindings.Single(x => x.TaskId == unboundTask.TaskId).IdentityGrantIds);
    }

    [Fact]
    public async Task Stale_host_capacity_creates_demand_instead_of_placement()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var plan = Plan(Id<WorkloadId>(72), Id<PlanRevisionId>(73), [Node(74)]);
        var now = DateTimeOffset.UtcNow;
        await scheduler.RegisterAsync(plan);
        var stale = Host(75, 1) with { ObservedAt = now.AddMinutes(-10) };
        await scheduler.SetHostsAsync(plan, [stale]);
        var result = await scheduler.ScheduleAsync(
            plan, now, Id<PoolId>(76), new SchedulingOptions(TimeSpan.FromMinutes(1)));
        Assert.Empty(result.Placements);
        Assert.Single(result.PoolDemands);
    }

    [Fact]
    public async Task Continue_policy_skips_descendants_and_cancel_waits_for_noninterruptible()
    {
        await using var store = new InMemorySchedulerStateStore();
        var scheduler = new CompositeScheduler(store);
        var parent = Node(90) with { InterruptionClass = InterruptionClass.NonInterruptible, RetryCap = 0 };
        var child = Node(91, [parent.TaskId]);
        var plan = new WorkloadPlan(Id<WorkloadId>(92), Id<PlanRevisionId>(93),
            WorkloadPlan.CurrentSchemaVersion, "test", "1.0", [parent, child], AggregateFailurePolicy.Continue);
        await scheduler.RegisterAsync(plan);
        await scheduler.SetHostsAsync(plan, [Host(94, 1)]);
        await scheduler.ScheduleAsync(plan, DateTimeOffset.UtcNow, Id<PoolId>(95));
        await scheduler.MarkRunningAsync(plan, parent.TaskId, 1);
        var cancelling = await scheduler.CancelAsync(plan);
        Assert.Equal(WorkloadDesiredState.Cancelling, cancelling.Intent);
        Assert.Equal(ScheduledTaskState.Running, cancelling.Tasks.Single(x => x.TaskId == parent.TaskId).State);
        Assert.Equal(ScheduledTaskState.Cancelled, cancelling.Tasks.Single(x => x.TaskId == child.TaskId).State);
        var finished = await scheduler.CompleteAsync(plan, parent.TaskId, 1, true, "done", DateTimeOffset.UtcNow);
        Assert.Equal(WorkloadDesiredState.Cancelled, finished.Intent);
        var reduced = WorkloadResultReducer.Reduce(plan, finished);
        Assert.True(reduced.IsTerminal);
        Assert.Equal(WorkloadObservedState.Cancelled, reduced.State);

        var failurePlan = new WorkloadPlan(Id<WorkloadId>(96), Id<PlanRevisionId>(97),
            WorkloadPlan.CurrentSchemaVersion, "test", "1.0",
            [Node(98) with { RetryCap = 0 }, Node(99, [Id<TaskId>(98)])],
            AggregateFailurePolicy.PartialSuccess);
        await scheduler.RegisterAsync(failurePlan);
        await scheduler.SetHostsAsync(failurePlan, [Host(100, 1)]);
        await scheduler.ScheduleAsync(failurePlan, DateTimeOffset.UtcNow, Id<PoolId>(101));
        var failed = await scheduler.CompleteAsync(failurePlan, Id<TaskId>(98), 1, false, "terminal", DateTimeOffset.UtcNow);
        Assert.Equal(ScheduledTaskState.SkippedDependency, failed.Tasks.Single(x => x.TaskId == Id<TaskId>(99)).State);
        Assert.True(WorkloadResultReducer.Reduce(failurePlan, failed).IsTerminal);
    }

    [Fact]
    public async Task Sqlite_restarts_CASes_and_rejects_schema_skew()
    {
        var path = Path.Combine(AppContext.BaseDirectory, $"{Guid.NewGuid():N}.db");
        try
        {
            var plan = Plan(Id<WorkloadId>(80), Id<PlanRevisionId>(81), [Node(82)]);
            await using (var first = new SqliteSchedulerStateStore(path))
                await new CompositeScheduler(first).RegisterAsync(plan);
            await using (var second = new SqliteSchedulerStateStore(path))
            {
                var state = await second.LoadAsync(plan.WorkloadId);
                Assert.NotNull(state);
                var a = state! with { Revision = state.Revision + 1 };
                Assert.True(await second.TrySaveAsync(a, state.Revision));
                Assert.False(await second.TrySaveAsync(a, state.Revision));
            }
            await using var connection = new SqliteConnection($"Data Source={path}");
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "UPDATE scheduler_states SET state_json='{}'";
            await command.ExecuteNonQueryAsync();
            await using (var corrupt = new SqliteSchedulerStateStore(path))
                await Assert.ThrowsAsync<InvalidDataException>(() => corrupt.LoadAsync(plan.WorkloadId));
            command.CommandText = "UPDATE scheduling_schema SET version=999";
            await command.ExecuteNonQueryAsync();
            Assert.Throws<SchedulerSchemaException>(() => new SqliteSchedulerStateStore(path));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var suffix in new[] { "", "-wal", "-shm" })
                if (File.Exists(path + suffix)) File.Delete(path + suffix);
        }
    }

    [Fact]
    public async Task Global_rate_sqlite_restart_preserves_leases_and_revision()
    {
        var path = Path.Combine(AppContext.BaseDirectory, $"{Guid.NewGuid():N}.rates.db");
        try
        {
            var now = DateTimeOffset.UtcNow;
            GlobalRateLease lease;
            await using (var first = new SqliteGlobalRateStateStore(path))
            {
                var allocator = new GlobalRateAllocator(first);
                await allocator.ConfigureAsync("restart", 20, 0, 0, now);
                lease = Assert.Single((await allocator.TryClaimAsync(
                    Id<WorkloadId>(600), Id<TaskId>(601), 1, Id<HostId>(602),
                    [new("restart", 7)], now, TimeSpan.FromMinutes(5)))!);
            }
            await using (var second = new SqliteGlobalRateStateStore(path))
            {
                var state = await second.LoadAsync("restart");
                Assert.Equal(13, state!.Available);
                Assert.Equal(lease.LeaseId, Assert.Single(state.Leases).LeaseId);
                await new GlobalRateAllocator(second).ReconcileUnusedAsync(
                    "restart", lease.LeaseId, 2, now.AddMinutes(5), authorityRevoked: false);
                Assert.Equal(18, (await second.LoadAsync("restart"))!.Available);
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var suffix in new[] { "", "-wal", "-shm" })
                if (File.Exists(path + suffix)) File.Delete(path + suffix);
        }
    }

    private static WorkloadPlan Plan(WorkloadId workload, PlanRevisionId revision, IReadOnlyList<TaskPlanNode> nodes) =>
        new(workload, revision, WorkloadPlan.CurrentSchemaVersion, "test", "1.0", nodes, AggregateFailurePolicy.PartialSuccess);

    private static TaskPlanNode Node(int id, IReadOnlyList<TaskId>? dependencies = null) =>
        new(Id<TaskId>(id), $"logical-{id}", "test", "1.0", new(memoryBytes: 1, concurrencyUnits: 1),
            TaskInput.Empty, dependencies ?? [], new HashSet<string>(StringComparer.Ordinal) { "test" }, "setup", "affinity",
            null, 1, InterruptionClass.Restartable, [], $"result-{id}");

    private static HostCapacitySnapshot Host(int id, int memory) =>
        new(Id<HostId>(id), Id<NodeIncarnationId>(id + 10000), Id<PoolId>(999),
            new(memoryBytes: memory, concurrencyUnits: memory), ["test"],
            ["setup"], DateTimeOffset.UtcNow);

    private static T Id<T>(int value) where T : struct =>
        (T)Activator.CreateInstance(typeof(T), new Guid(value, 0, 0, new byte[8]))!;
}
