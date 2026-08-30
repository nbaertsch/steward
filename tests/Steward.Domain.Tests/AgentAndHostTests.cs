namespace Steward.Domain.Tests;

public sealed class AgentAndHostTests
{
    [Fact]
    public void AgentLifecycleSupportsTurnsAndMigration()
    {
        var agent = new StewardAgent(StewardAgentId.New());
        agent.TransitionTo(StewardAgentState.Ready);
        agent.TransitionTo(StewardAgentState.HandlingTurn);
        agent.TransitionTo(StewardAgentState.Checkpointing);
        agent.TransitionTo(StewardAgentState.Migrating);
        agent.TransitionTo(StewardAgentState.Restoring);
        agent.TransitionTo(StewardAgentState.Ready);
        Assert.Throws<DomainRuleViolationException>(() => agent.TransitionTo(StewardAgentState.Terminated));
    }

    [Fact]
    public void NotificationCursorIsSeparateFromTurnCompletionAndSupportsReplay()
    {
        var agent = new StewardAgent(StewardAgentId.New());
        agent.TransitionTo(StewardAgentState.Ready);
        var first = RespondedTurn(agent, 1);
        var second = RespondedTurn(agent, 2);

        Assert.Equal(AgentTurnState.Responded, first.State);
        Assert.Equal(0, agent.NotificationCursor);
        agent.AcknowledgeNotifications(1);
        Assert.Equal(AgentTurnState.Notified, first.State);
        Assert.Equal(AgentTurnState.Responded, second.State);
        Assert.Equal(1, agent.NotificationCursor);
        agent.AcknowledgeNotifications(1);
        Assert.Equal(AgentTurnState.Responded, second.State);
        agent.AcknowledgeNotifications(2);
        Assert.Equal(AgentTurnState.Notified, second.State);
        Assert.Throws<DomainRuleViolationException>(() => agent.AcknowledgeNotifications(1));
    }

    [Fact]
    public void TurnLegalAndIllegalTransitionsAreExplicit()
    {
        var turn = new AgentTurn(AgentTurnId.New());
        turn.TransitionTo(AgentTurnState.Delegated);
        turn.TransitionTo(AgentTurnState.Running);
        Assert.Throws<DomainRuleViolationException>(() => turn.TransitionTo(AgentTurnState.Notified));
        turn.TransitionTo(AgentTurnState.Responded, 1);
        Assert.Equal(1, turn.ResponseSequence);
    }

    [Fact]
    public void HostSupportsProvisioningAndDrainedStop()
    {
        var host = ReadyHost();
        host.BeginDrain([new(InterruptionClass.Restartable)]);
        host.TransitionTo(HostLifecycleState.Stopped);
        host.TransitionTo(HostLifecycleState.Starting);
        host.TransitionTo(HostLifecycleState.Ready);
        Assert.Equal(HostLifecycleState.Ready, host.LifecycleState);
    }

    [Fact]
    public void DrainBlocksNonInterruptibleAndIncompletePortableState()
    {
        var host = ReadyHost();
        AssertBlocked(() => host.TransitionTo(HostLifecycleState.Draining));
        AssertBlocked(() => host.BeginDrain([new(InterruptionClass.NonInterruptible)]));
        AssertBlocked(() => host.BeginDrain([new(InterruptionClass.CheckpointResumable, true, false)]));

        host.BeginDrain([new(InterruptionClass.CheckpointResumable, true, true)]);
        host.TransitionTo(HostLifecycleState.Reimaging);
        host.TransitionTo(HostLifecycleState.Bootstrapping);
        var old = host.NodeIncarnationId;
        host.ReplaceIncarnation(NodeIncarnationId.New());
        Assert.NotEqual(old, host.NodeIncarnationId);
    }

    [Fact]
    public void ForcedDrainRequiresAndPreservesLossManifest()
    {
        var host = ReadyHost();
        AssertBlocked(() => host.BeginDrain([new(InterruptionClass.NonInterruptible)], true));
        host.BeginDrain([new(InterruptionClass.NonInterruptible)], true, ["running task may be lost"]);
        Assert.Single(host.ForcedLossManifest);
    }

    private static AgentTurn RespondedTurn(StewardAgent agent, long sequence)
    {
        var turn = agent.QueueTurn(AgentTurnId.New());
        turn.TransitionTo(AgentTurnState.Delegated);
        turn.TransitionTo(AgentTurnState.Running);
        turn.TransitionTo(AgentTurnState.Responded, sequence);
        return turn;
    }

    private static Host ReadyHost()
    {
        var host = new Host(HostId.New(), PoolId.New(), NodeIncarnationId.New());
        foreach (var state in new[] { HostLifecycleState.Provisioning, HostLifecycleState.Bootstrapping, HostLifecycleState.Enrolling, HostLifecycleState.Ready })
            host.TransitionTo(state);
        return host;
    }

    private static void AssertBlocked(Action action)
    {
        var error = Assert.Throws<DomainRuleViolationException>(action);
        Assert.Equal(DomainErrorCode.LifecycleBlockedByActiveWork, error.Code);
    }
}
