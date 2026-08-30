namespace Steward.Domain.Tests;

public sealed class IdentifierTests
{
    public static TheoryData<Func<IStewardId>, Func<string, IStewardId>, Func<Guid, IStewardId>> IdTypes => new()
    {
        { () => WorkloadId.New(), x => WorkloadId.Parse(x), x => new WorkloadId(x) },
        { () => PlanRevisionId.New(), x => PlanRevisionId.Parse(x), x => new PlanRevisionId(x) },
        { () => TaskId.New(), x => TaskId.Parse(x), x => new TaskId(x) },
        { () => TaskAttemptId.New(), x => TaskAttemptId.Parse(x), x => new TaskAttemptId(x) },
        { () => StewardAgentId.New(), x => StewardAgentId.Parse(x), x => new StewardAgentId(x) },
        { () => AgentTurnId.New(), x => AgentTurnId.Parse(x), x => new AgentTurnId(x) },
        { () => HostId.New(), x => HostId.Parse(x), x => new HostId(x) },
        { () => NodeIncarnationId.New(), x => NodeIncarnationId.Parse(x), x => new NodeIncarnationId(x) },
        { () => PoolId.New(), x => PoolId.Parse(x), x => new PoolId(x) },
        { () => DelegationId.New(), x => DelegationId.Parse(x), x => new DelegationId(x) },
        { () => CommandId.New(), x => CommandId.Parse(x), x => new CommandId(x) },
        { () => IdentityGrantId.New(), x => IdentityGrantId.Parse(x), x => new IdentityGrantId(x) },
        { () => PortableObjectId.New(), x => PortableObjectId.Parse(x), x => new PortableObjectId(x) },
        { () => ProviderOperationId.New(), x => ProviderOperationId.Parse(x), x => new ProviderOperationId(x) },
        { () => NotificationId.New(), x => NotificationId.Parse(x), x => new NotificationId(x) }
    };

    [Theory]
    [MemberData(nameof(IdTypes))]
    public void IdsRoundTripAndRejectEmpty(
        Func<IStewardId> create,
        Func<string, IStewardId> parse,
        Func<Guid, IStewardId> construct)
    {
        var id = create();
        var text = id.ToString()!;

        Assert.NotEqual(Guid.Empty, id.Value);
        Assert.Equal(36, text.Length);
        Assert.Equal(id, parse(text));
        Assert.Throws<ArgumentException>(() => construct(Guid.Empty));
        Assert.Throws<FormatException>(() => parse(Guid.Empty.ToString("D")));
        Assert.Throws<FormatException>(() => parse("not-an-id"));
    }

    [Fact]
    public void TryParseRejectsInvalidAndAcceptsStableText()
    {
        var id = WorkloadId.New();
        Assert.True(WorkloadId.TryParse(id.ToString(), out var parsed));
        Assert.Equal(id, parsed);
        Assert.False(WorkloadId.TryParse(null, out _));
        Assert.False(WorkloadId.TryParse(Guid.Empty.ToString(), out _));
    }
}
