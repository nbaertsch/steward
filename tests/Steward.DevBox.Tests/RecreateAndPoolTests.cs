using System.Text.Json;
using Steward.Domain;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;

namespace Steward.DevBox.Tests;

public sealed class RecreateAndPoolTests
{
    private static readonly ProviderBinding Binding = new("azure-dev-box", "project", "pool");

    [Fact]
    public async Task RecreateIsDurableDeleteCreateBootstrapStateMachine()
    {
        var client = new FakeDevBoxClient();
        client.Add(new("project/me/box", "box", "Succeeded", "Running"));
        var provider = TestProvider.Create(client);
        var bootstrap = new FakeBootstrapper();
        var host = ReadyHost();
        var oldIncarnation = host.NodeIncarnationId;
        var state = new DevBoxRecreateCoordinator(provider, bootstrap).Begin(
            ProviderOperationId.New(), "recreate-key", Binding, "box",
            "project/me/box",
            new DrainRequest(host, [new(InterruptionClass.Restartable)]));

        state = await Restarted(provider, bootstrap).AdvanceAsync(state, host, Package(), Claim(state));
        Assert.Equal(RecreatePhase.Deleting, state.Phase);
        client.Complete(client.LastOperationId);
        state = await Restarted(TestProvider.Create(client), bootstrap).AdvanceAsync(state, host, Package(), Claim(state));
        Assert.Equal(RecreatePhase.Creating, state.Phase);

        provider = TestProvider.Create(client);
        state = await Restarted(provider, bootstrap).AdvanceAsync(state, host, Package(), Claim(state));
        client.Complete(client.LastOperationId);
        state = await Restarted(TestProvider.Create(client), bootstrap).AdvanceAsync(state, host, Package(), Claim(state));
        Assert.Equal(RecreatePhase.BootstrappingAndEnrolling, state.Phase);
        Assert.NotEqual(oldIncarnation, host.NodeIncarnationId);
        Assert.Equal(state.NewIncarnationId, host.NodeIncarnationId);

        state = await Restarted(TestProvider.Create(client), bootstrap).AdvanceAsync(state, host, Package(), Claim(state));
        Assert.Equal(RecreatePhase.Completed, state.Phase);
        Assert.Equal(HostLifecycleState.Ready, host.LifecycleState);
    }

    [Fact]
    public async Task RecreateExposesBootstrapPartialFailure()
    {
        var client = new FakeDevBoxClient { CompleteImmediately = true };
        client.Add(new("project/me/box", "box", "Succeeded", "Running"));
        var provider = TestProvider.Create(client);
        var bootstrap = new FakeBootstrapper { Fail = true };
        var host = ReadyHost();
        var coordinator = new DevBoxRecreateCoordinator(provider, bootstrap);
        var state = coordinator.Begin(
            ProviderOperationId.New(),
            "key",
            Binding,
            "box",
            "project/me/box",
            new DrainRequest(host, []));
        state = await coordinator.AdvanceAsync(state, host, Package(), Claim(state));
        state = await coordinator.AdvanceAsync(state, host, Package(), Claim(state));
        state = await coordinator.AdvanceAsync(state, host, Package(), Claim(state));
        Assert.Equal(RecreatePhase.Failed, state.Phase);
        Assert.Equal("bootstrap/enroll", state.FailedPhase);
        Assert.Equal(HostLifecycleState.Bootstrapping, host.LifecycleState);
    }

    [Fact]
    public void DrainRefusesUnsafeWorkAndForcedDrainRecordsExactLoss()
    {
        var blocked = ReadyHost();
        Assert.Throws<DomainRuleViolationException>(() => LifecycleInterlock.BeginDrain(
            new DrainRequest(blocked, [new(InterruptionClass.NonInterruptible, Description: "task-1")])));

        var checkpointMissingReceipt = ReadyHost();
        Assert.Throws<DomainRuleViolationException>(() => LifecycleInterlock.BeginDrain(
            new DrainRequest(checkpointMissingReceipt, [new(InterruptionClass.CheckpointResumable, true, false)])));

        var forced = ReadyHost();
        LifecycleInterlock.BeginDrain(new DrainRequest(
            forced, [new(InterruptionClass.NonInterruptible, Description: "task-7")], true, ["task-7: running state"]));
        Assert.Equal(["task-7: running state"], forced.ForcedLossManifest);
    }

    [Fact]
    public async Task ConcurrentDemandNeverExceedsHardMaximum()
    {
        var store = new InMemoryPoolStateStore();
        var firstCoordinator = new PoolCoordinator(store);
        var secondCoordinator = new PoolCoordinator(store);
        var poolId = PoolId.New();
        var policy = new PoolPolicy(poolId, 0, 3, TimeSpan.FromMinutes(10));
        var tasks = Enumerable.Range(0, 30).Select(i => (i % 2 == 0 ? firstCoordinator : secondCoordinator).ReconcileAsync(
            policy, [new($"demand-{i}")], DateTimeOffset.UtcNow, () => NewHost(poolId)));
        await Task.WhenAll(tasks);

        var restartedCoordinator = new PoolCoordinator(store);
        var afterRestart = await restartedCoordinator.ReconcileAsync(
            policy, [new("demand-after-restart")], DateTimeOffset.UtcNow, () => NewHost(poolId));
        Assert.Equal(3, afterRestart.Members.Count(x => x.State != PoolMemberState.Deleted));
        Assert.True(afterRestart.State.Revision > 1);
        var roundTripped = JsonSerializer.Deserialize<PoolState>(JsonSerializer.Serialize(afterRestart.State));
        Assert.NotNull(roundTripped);
        Assert.Equal(afterRestart.State.PoolId, roundTripped.PoolId);
        Assert.Equal(afterRestart.State.Revision, roundTripped.Revision);
        Assert.Equal(afterRestart.State.Members.Select(x => x.HostId), roundTripped.Members.Select(x => x.HostId));
    }

    [Fact]
    public async Task ProviderResourceBindingPersistsNameAndCanonicalIdentity()
    {
        var store = new InMemoryPoolStateStore();
        var coordinator = new PoolCoordinator(store);
        var poolId = PoolId.New();
        var planned = await coordinator.ReconcileAsync(
            new(poolId, 0, 1, TimeSpan.Zero),
            [new("create")],
            DateTimeOffset.UtcNow,
            () => NewHost(poolId));
        var member = Assert.Single(planned.Members);

        await coordinator.BindProviderResourceAsync(
            poolId,
            member.HostId,
            "box",
            "project/me/box",
            DateTimeOffset.UtcNow);

        var restarted = await new PoolCoordinator(store).ReconcileAsync(
            new(poolId, 0, 1, TimeSpan.Zero),
            [new("create")],
            DateTimeOffset.UtcNow,
            () => NewHost(poolId));
        var bound = Assert.Single(restarted.Members);
        Assert.Equal("box", bound.ProviderResourceName);
        Assert.Equal("project/me/box", bound.ProviderResourceId);
        var roundTrip = JsonSerializer.Deserialize<PoolState>(
            JsonSerializer.Serialize(restarted.State));
        Assert.Equal(
            "project/me/box",
            Assert.Single(roundTrip!.Members).ProviderResourceId);
    }

    [Fact]
    public async Task ProviderResourceAdoptionHonorsHardMaximum()
    {
        var store = new InMemoryPoolStateStore();
        var coordinator = new PoolCoordinator(store);
        var poolId = PoolId.New();
        var policy = new PoolPolicy(
            poolId,
            0,
            1,
            TimeSpan.FromMinutes(10));
        var first = NewHost(poolId);
        var second = NewHost(poolId);

        await coordinator.AdoptProviderResourceAsync(
            policy,
            first,
            "box-one",
            "project/me/box-one",
            DateTimeOffset.UtcNow);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => coordinator.AdoptProviderResourceAsync(
                policy,
                second,
                "box-two",
                "project/me/box-two",
                DateTimeOffset.UtcNow));
        Assert.Contains("hard maximum", exception.Message);
        Assert.Single((await store.LoadAsync(poolId)).Members);
    }

    [Fact]
    public async Task ProviderResourceAdoptionRejectsDuplicateIdentity()
    {
        var store = new InMemoryPoolStateStore();
        var coordinator = new PoolCoordinator(store);
        var poolId = PoolId.New();
        var policy = new PoolPolicy(
            poolId,
            0,
            2,
            TimeSpan.FromMinutes(10));
        var first = NewHost(poolId);
        var second = NewHost(poolId);

        await coordinator.AdoptProviderResourceAsync(
            policy,
            first,
            "box",
            "project/me/box",
            DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => coordinator.AdoptProviderResourceAsync(
                policy,
                second,
                "box",
                "project/me/box",
                DateTimeOffset.UtcNow));
        Assert.Single((await store.LoadAsync(poolId)).Members);
    }

    [Fact]
    public async Task WarmMinimumIdleScaleAndAffinityAreExplicit()
    {
        var store = new InMemoryPoolStateStore();
        var coordinator = new PoolCoordinator(store);
        var poolId = PoolId.New();
        var now = DateTimeOffset.UtcNow;
        var policy = new PoolPolicy(poolId, 1, 4, TimeSpan.FromMinutes(5));
        var warmResult = await coordinator.ReconcileAsync(policy, [], now, () => NewHost(poolId));
        var warm = warmResult.Members.Single();
        await coordinator.UpdateMemberAsync(poolId, warm.Host.Id, PoolMemberState.Warm, now);

        var assigned = await coordinator.ReconcileAsync(policy, [new("job", "repository-A")], now.AddMinutes(1), () => NewHost(poolId));
        Assert.Contains(assigned.Actions, x => x.Kind == PoolActionKind.Assign && x.AffinityKey == "repository-A");
        Assert.Contains(assigned.Actions, x => x.Kind == PoolActionKind.Create);

        var replacement = assigned.Members.Single(x => x.State == PoolMemberState.Creating);
        await coordinator.UpdateMemberAsync(poolId, replacement.Host.Id, PoolMemberState.Warm, now);
        var keptWarm = await coordinator.ReconcileAsync(policy, [], now.AddMinutes(10), () => NewHost(poolId));
        Assert.DoesNotContain(keptWarm.Actions, x => x.Kind == PoolActionKind.Drain);
    }

    [Fact]
    public async Task StoppedMemberRestartsBeforeNewCapacityIsCreated()
    {
        var store = new InMemoryPoolStateStore();
        var coordinator = new PoolCoordinator(store);
        var poolId = PoolId.New();
        var now = DateTimeOffset.UtcNow;
        var warm = await coordinator.ReconcileAsync(
            new(poolId, 1, 1, TimeSpan.Zero),
            [],
            now,
            () => NewHost(poolId));
        var member = Assert.Single(warm.Members);
        await coordinator.UpdateMemberAsync(
            poolId,
            member.HostId,
            PoolMemberState.Warm,
            now);

        var stopping = await coordinator.ReconcileAsync(
            new(poolId, 0, 1, TimeSpan.Zero),
            [],
            now.AddMinutes(1),
            () => NewHost(poolId));
        Assert.Equal(
            PoolActionKind.Drain,
            Assert.Single(stopping.Actions).Kind);
        await coordinator.UpdateMemberAsync(
            poolId,
            member.HostId,
            PoolMemberState.Stopped,
            now.AddMinutes(1));

        var restarting = await coordinator.ReconcileAsync(
            new(poolId, 1, 1, TimeSpan.Zero),
            [],
            now.AddMinutes(2),
            () => NewHost(poolId));
        var action = Assert.Single(restarting.Actions);
        Assert.Equal(PoolActionKind.Start, action.Kind);
        Assert.Equal(member.HostId, action.Host.Id);
        Assert.DoesNotContain(
            restarting.Actions,
            x => x.Kind == PoolActionKind.Create);
    }

    [Fact]
    public async Task StoppedMemberIsDeletedOnlyAfterConfiguredRetention()
    {
        var store = new InMemoryPoolStateStore();
        var coordinator = new PoolCoordinator(store);
        var poolId = PoolId.New();
        var now = DateTimeOffset.UtcNow;
        var created = await coordinator.ReconcileAsync(
            new(poolId, 1, 1, TimeSpan.Zero),
            [],
            now,
            () => NewHost(poolId));
        var member = Assert.Single(created.Members);
        await coordinator.UpdateMemberAsync(
            poolId,
            member.HostId,
            PoolMemberState.Stopped,
            now);
        var policy = new PoolPolicy(
            poolId,
            0,
            1,
            TimeSpan.Zero,
            TimeSpan.FromDays(7));

        var retained = await coordinator.ReconcileAsync(
            policy,
            [],
            now.AddDays(6),
            () => NewHost(poolId));
        Assert.DoesNotContain(
            retained.Actions,
            x => x.Kind == PoolActionKind.Delete);

        var expired = await coordinator.ReconcileAsync(
            policy,
            [],
            now.AddDays(8),
            () => NewHost(poolId));
        var deletion = Assert.Single(expired.Actions);
        Assert.Equal(PoolActionKind.Delete, deletion.Kind);
        Assert.Equal(member.HostId, deletion.Host.Id);
    }

    [Fact]
    public async Task DemandClaimsAreScopedToTheirPool()
    {
        var store = new InMemoryPoolStateStore();
        var coordinator = new PoolCoordinator(store);
        var firstPool = PoolId.New();
        var secondPool = PoolId.New();

        var first = await coordinator.ReconcileAsync(
            new(firstPool, 0, 1, TimeSpan.Zero), [new("same-demand")], DateTimeOffset.UtcNow, () => NewHost(firstPool));
        var second = await coordinator.ReconcileAsync(
            new(secondPool, 0, 1, TimeSpan.Zero), [new("same-demand")], DateTimeOffset.UtcNow, () => NewHost(secondPool));

        Assert.Single(first.Actions);
        Assert.Single(second.Actions);
        Assert.Contains(first.State.DemandClaims, x => x.DemandId == "same-demand");
        Assert.Contains(second.State.DemandClaims, x => x.DemandId == "same-demand");
    }

    [Fact]
    public async Task FailedCreateClaimCanBeReleasedAndRequeued()
    {
        var store = new InMemoryPoolStateStore();
        var poolId = PoolId.New();
        var policy = new PoolPolicy(poolId, 0, 2, TimeSpan.Zero);
        var firstCoordinator = new PoolCoordinator(store);
        var first = await firstCoordinator.ReconcileAsync(
            policy, [new("retry-me")], DateTimeOffset.UtcNow, () => NewHost(poolId));
        Assert.Single(first.Actions);
        Assert.Equal(PoolDemandClaimState.Claimed, Assert.Single(first.State.DemandClaims).State);

        await firstCoordinator.ReleaseDemandAsync(poolId, "retry-me", DateTimeOffset.UtcNow);
        var retried = await new PoolCoordinator(store).ReconcileAsync(
            policy, [new("retry-me")], DateTimeOffset.UtcNow, () => NewHost(poolId));

        Assert.Single(retried.Actions);
        Assert.Equal(PoolActionKind.Create, retried.Actions[0].Kind);
        Assert.Equal(PoolDemandClaimState.Claimed, Assert.Single(retried.State.DemandClaims).State);
    }

    [Fact]
    public async Task SuccessfulAssignmentCompletesOnceAndCanBePruned()
    {
        var store = new InMemoryPoolStateStore();
        var poolId = PoolId.New();
        var policy = new PoolPolicy(poolId, 1, 2, TimeSpan.FromHours(1));
        var coordinator = new PoolCoordinator(store);
        var warm = await coordinator.ReconcileAsync(policy, [], DateTimeOffset.UtcNow, () => NewHost(poolId));
        await coordinator.UpdateMemberAsync(poolId, warm.Members.Single().HostId, PoolMemberState.Warm, DateTimeOffset.UtcNow);

        var assigned = await coordinator.ReconcileAsync(
            policy, [new("assign-once")], DateTimeOffset.UtcNow, () => NewHost(poolId));
        Assert.Single(assigned.Actions, x => x.DemandId == "assign-once");
        await coordinator.ConfirmDemandAsync(poolId, "assign-once", DateTimeOffset.UtcNow);

        var restarted = new PoolCoordinator(store);
        var duplicate = await restarted.ReconcileAsync(
            policy, [new("assign-once")], DateTimeOffset.UtcNow, () => NewHost(poolId));
        Assert.DoesNotContain(duplicate.Actions, x => x.DemandId == "assign-once");
        Assert.Equal(PoolDemandClaimState.Completed,
            duplicate.State.DemandClaims.Single(x => x.DemandId == "assign-once").State);

        var pruned = await restarted.ReconcileAsync(
            policy,
            [],
            DateTimeOffset.UtcNow,
            () => NewHost(poolId),
            new DemandRetention(new HashSet<string>(), DateTimeOffset.UtcNow.AddMinutes(1)));
        Assert.DoesNotContain(pruned.State.DemandClaims, x => x.DemandId == "assign-once");
    }

    [Fact]
    public async Task RestartPreservesClaimAndCasPreventsDoubleAssignment()
    {
        var store = new InMemoryPoolStateStore();
        var poolId = PoolId.New();
        var policy = new PoolPolicy(poolId, 2, 2, TimeSpan.FromHours(1));
        var setup = new PoolCoordinator(store);
        var warm = await setup.ReconcileAsync(policy, [], DateTimeOffset.UtcNow, () => NewHost(poolId));
        foreach (var member in warm.Members)
            await setup.UpdateMemberAsync(poolId, member.HostId, PoolMemberState.Warm, DateTimeOffset.UtcNow);

        var first = new PoolCoordinator(store);
        var second = new PoolCoordinator(store);
        var reconciliations = await Task.WhenAll(
            first.ReconcileAsync(policy, [new("one-claim")], DateTimeOffset.UtcNow, () => NewHost(poolId)),
            second.ReconcileAsync(policy, [new("one-claim")], DateTimeOffset.UtcNow, () => NewHost(poolId)));

        Assert.Single(reconciliations.SelectMany(x => x.Actions), x => x.DemandId == "one-claim");
        var afterRestart = await new PoolCoordinator(store).ReconcileAsync(
            policy, [new("one-claim")], DateTimeOffset.UtcNow, () => NewHost(poolId));
        Assert.DoesNotContain(afterRestart.Actions, x => x.DemandId == "one-claim");
        Assert.Single(afterRestart.State.DemandClaims, x => x.DemandId == "one-claim");
        Assert.Single(afterRestart.Members, x => x.DemandId == "one-claim");
        Assert.Single(afterRestart.Members, x => x.State == PoolMemberState.Assigned);
    }

    private static DevBoxRecreateCoordinator Restarted(IHostProvider provider, INodeBootstrapper bootstrap) => new(provider, bootstrap);
    private static SignedNodePackage Package() => new(new Uri("https://packages.invalid/node"), "sha256", "signature", "signer");
    private static EnrollmentClaim Claim(DevBoxRecreateState state) =>
        new(
            "one-time-token",
            DateTimeOffset.UtcNow.AddMinutes(5),
            state.ProviderResourceId,
            state.HostId,
            state.NewIncarnationId);

    private static Host ReadyHost()
    {
        var host = NewHost(PoolId.New());
        host.TransitionTo(HostLifecycleState.Provisioning);
        host.TransitionTo(HostLifecycleState.Bootstrapping);
        host.TransitionTo(HostLifecycleState.Enrolling);
        host.TransitionTo(HostLifecycleState.Ready);
        return host;
    }

    private static Host NewHost(PoolId poolId) => new(HostId.New(), poolId, NodeIncarnationId.New());
}
