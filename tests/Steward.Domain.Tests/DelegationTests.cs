namespace Steward.Domain.Tests;

public sealed class DelegationTests
{
    private static readonly DateTimeOffset Accepted = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void DelegationAuthorizesOnlyBoundedAction()
    {
        var taskId = TaskId.New();
        var grantId = IdentityGrantId.New();
        var delegation = CreateDelegation(taskId, grantId);
        var request = new ResourceRequirements(cpuCores: 2, memoryBytes: 100, concurrencyUnits: 1);

        for (var generation = 2; generation <= 4; generation++)
            delegation.AuthorizeStart(taskId, generation, request, 1,
                new Dictionary<string, decimal> { ["inference"] = 20 },
                [grantId], Accepted.AddMinutes(5));
    }

    [Fact]
    public void DelegationRejectsGenerationResourceConcurrencyRateAndIdentityOverreach()
    {
        var taskId = TaskId.New();
        var grantId = IdentityGrantId.New();
        var delegation = CreateDelegation(taskId, grantId);
        var valid = new ResourceRequirements(cpuCores: 1);
        var now = Accepted.AddMinutes(5);

        AssertLimit(() => delegation.AuthorizeStart(taskId, 5, valid, 0, null, null, now));
        AssertLimit(() => delegation.AuthorizeStart(TaskId.New(), 2, valid, 0, null, null, now));
        AssertLimit(() => delegation.AuthorizeStart(taskId, 2, new ResourceRequirements(cpuCores: 5), 0, null, null, now));
        AssertLimit(() => delegation.AuthorizeStart(taskId, 2, valid, 2, null, null, now));
        AssertLimit(() => delegation.AuthorizeStart(taskId, 2, valid, 0, new Dictionary<string, decimal> { ["inference"] = 101 }, null, now));
        AssertLimit(() => delegation.AuthorizeStart(taskId, 2, valid, 0, null, [IdentityGrantId.New()], now));
    }

    [Fact]
    public void ExpiryStopsNewStartsAndDrainIsIndependent()
    {
        var taskId = TaskId.New();
        var delegation = CreateDelegation(taskId, IdentityGrantId.New());
        var request = new ResourceRequirements();

        var atBoundary = Assert.Throws<DomainRuleViolationException>(() =>
            delegation.AuthorizeStart(taskId, 2, request, 0, null, null, Accepted.AddMinutes(10)));
        Assert.Equal(DomainErrorCode.DelegationExpired, atBoundary.Code);
        Assert.True(delegation.MustDrain(Accepted.AddMinutes(20)));
        Assert.True(delegation.HasAuthority(Accepted.AddMinutes(29)));
        Assert.False(delegation.HasAuthority(Accepted.AddMinutes(30)));
    }

    [Fact]
    public void DelegationValidatesOrderedTimesAndUniqueTasks()
    {
        var taskId = TaskId.New();
        Assert.Throws<ArgumentException>(() => new Delegation(
            DelegationId.New(), HostId.New(), NodeIncarnationId.New(), PlanRevisionId.New(),
            [new(taskId, 1, 2), new(taskId, 3, 4)], new(), 1, [], [],
            Accepted, Accepted.AddMinutes(2), Accepted.AddMinutes(1), Accepted.AddMinutes(3)));
    }

    [Theory]
    [InlineData(IdentityRenewalMode.Workload, true)]
    [InlineData(IdentityRenewalMode.LocalBroker, false)]
    [InlineData(IdentityRenewalMode.None, false)]
    public void IdentityRenewalModeReflectsOfflineCapability(IdentityRenewalMode mode, bool expected)
    {
        var grant = new IdentityGrant(
            IdentityGrantId.New(), HostId.New(), NodeIncarnationId.New(), "audience", ["scope"],
            Accepted.AddHours(1), 2, mode, IdentityOfflineBehavior.CheckpointAndPause);
        Assert.Equal(expected, grant.CanRenewWhileControlOffline);
        Assert.Equal(IdentityOfflineBehavior.ContinueWithoutCapability, grant.BehaviorAt(Accepted));
        Assert.Equal(IdentityOfflineBehavior.CheckpointAndPause, grant.BehaviorAt(Accepted.AddHours(1)));
    }

    private static Delegation CreateDelegation(TaskId taskId, IdentityGrantId grantId) =>
        new(
            DelegationId.New(), HostId.New(), NodeIncarnationId.New(), PlanRevisionId.New(),
            [new AttemptGenerationRange(taskId, 2, 4)],
            new ResourceRequirements(cpuCores: 4, memoryBytes: 1_000, diskBytes: 2_000, processCount: 5, concurrencyUnits: 2),
            2,
            [new RateLimit("inference", 100)],
            [grantId],
            Accepted, Accepted.AddMinutes(10), Accepted.AddMinutes(20), Accepted.AddMinutes(30));

    private static void AssertLimit(Action action)
    {
        var error = Assert.Throws<DomainRuleViolationException>(action);
        Assert.Equal(DomainErrorCode.DelegationLimitExceeded, error.Code);
    }
}
