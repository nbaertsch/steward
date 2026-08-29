namespace Steward.Domain;

public sealed class AgentTurn
{
    private static readonly IReadOnlyDictionary<AgentTurnState, AgentTurnState[]> Transitions =
        new Dictionary<AgentTurnState, AgentTurnState[]>
        {
            [AgentTurnState.Queued] = [AgentTurnState.Delegated, AgentTurnState.Cancelled],
            [AgentTurnState.Delegated] = [AgentTurnState.Running, AgentTurnState.Failed, AgentTurnState.Cancelled],
            [AgentTurnState.Running] = [AgentTurnState.Responded, AgentTurnState.Failed, AgentTurnState.Cancelled],
            [AgentTurnState.Responded] = [AgentTurnState.Notified]
        };

    public AgentTurnId Id { get; }
    public AgentTurnState State { get; private set; } = AgentTurnState.Queued;
    public long? ResponseSequence { get; private set; }

    public AgentTurn(AgentTurnId id) => Id = id;

    public void TransitionTo(AgentTurnState next, long? responseSequence = null)
    {
        Rule.Transition(State, next, Transitions, nameof(AgentTurn));
        if (next == AgentTurnState.Responded)
        {
            Rule.Require(responseSequence > 0, DomainErrorCode.IllegalStateTransition, "A response requires a positive notification sequence.");
            ResponseSequence = responseSequence;
        }
        State = next;
    }

    internal void MarkNotified() => TransitionTo(AgentTurnState.Notified);
}

public sealed class StewardAgent
{
    private static readonly IReadOnlyDictionary<StewardAgentState, StewardAgentState[]> Transitions =
        new Dictionary<StewardAgentState, StewardAgentState[]>
        {
            [StewardAgentState.Creating] = [StewardAgentState.Ready, StewardAgentState.Suspended, StewardAgentState.Recovering],
            [StewardAgentState.Ready] = [StewardAgentState.HandlingTurn, StewardAgentState.Checkpointing, StewardAgentState.Suspended, StewardAgentState.Recovering],
            [StewardAgentState.HandlingTurn] = [StewardAgentState.Ready, StewardAgentState.Checkpointing, StewardAgentState.Suspended, StewardAgentState.Recovering],
            [StewardAgentState.Checkpointing] = [StewardAgentState.Migrating, StewardAgentState.Suspended, StewardAgentState.Recovering],
            [StewardAgentState.Migrating] = [StewardAgentState.Restoring, StewardAgentState.Suspended, StewardAgentState.Recovering],
            [StewardAgentState.Restoring] = [StewardAgentState.Ready, StewardAgentState.Suspended, StewardAgentState.Recovering],
            [StewardAgentState.Suspended] = [StewardAgentState.Restoring, StewardAgentState.Terminated],
            [StewardAgentState.Recovering] = [StewardAgentState.Ready, StewardAgentState.Suspended, StewardAgentState.Terminated]
        };

    private readonly Dictionary<AgentTurnId, AgentTurn> _turns = [];

    public StewardAgentId Id { get; }
    public StewardAgentState State { get; private set; } = StewardAgentState.Creating;
    public long NotificationCursor { get; private set; }
    public IReadOnlyCollection<AgentTurn> Turns => _turns.Values;

    public StewardAgent(StewardAgentId id) => Id = id;

    public void TransitionTo(StewardAgentState next)
    {
        Rule.Transition(State, next, Transitions, nameof(StewardAgent));
        State = next;
    }

    public AgentTurn QueueTurn(AgentTurnId id)
    {
        Rule.Require(State is StewardAgentState.Ready or StewardAgentState.HandlingTurn,
            DomainErrorCode.IllegalStateTransition, "Turns can only be queued for an available Agent.");
        var turn = new AgentTurn(id);
        if (!_turns.TryAdd(id, turn))
            throw new DomainRuleViolationException(DomainErrorCode.RevisionConflict, "Turn already exists.");
        return turn;
    }

    public void AcknowledgeNotifications(long contiguousCursor)
    {
        Rule.Require(contiguousCursor >= NotificationCursor, DomainErrorCode.RevisionConflict, "Notification cursor cannot move backwards.");
        var maximum = _turns.Values.Where(x => x.ResponseSequence.HasValue).Select(x => x.ResponseSequence!.Value).DefaultIfEmpty(0).Max();
        Rule.Require(contiguousCursor <= maximum, DomainErrorCode.RevisionConflict, "Notification cursor cannot acknowledge an unknown response.");
        NotificationCursor = contiguousCursor;
        foreach (var turn in _turns.Values.Where(x => x.State == AgentTurnState.Responded && x.ResponseSequence <= contiguousCursor))
            turn.MarkNotified();
    }
}

public sealed record DrainObligation(
    InterruptionClass InterruptionClass,
    bool CheckpointComplete = false,
    bool PortableReceiptPresent = false,
    string Description = "");

public sealed class Host
{
    private static readonly IReadOnlyDictionary<HostLifecycleState, HostLifecycleState[]> Transitions =
        new Dictionary<HostLifecycleState, HostLifecycleState[]>
        {
            [HostLifecycleState.Discovered] = [HostLifecycleState.Provisioning, HostLifecycleState.Degraded, HostLifecycleState.Recovering],
            [HostLifecycleState.Provisioning] = [HostLifecycleState.Bootstrapping, HostLifecycleState.Degraded, HostLifecycleState.Recovering],
            [HostLifecycleState.Bootstrapping] = [HostLifecycleState.Enrolling, HostLifecycleState.Degraded, HostLifecycleState.Recovering],
            [HostLifecycleState.Enrolling] = [HostLifecycleState.Ready, HostLifecycleState.Degraded, HostLifecycleState.Recovering],
            [HostLifecycleState.Ready] = [HostLifecycleState.Draining, HostLifecycleState.Degraded, HostLifecycleState.Recovering],
            [HostLifecycleState.Draining] = [HostLifecycleState.Stopped, HostLifecycleState.Reimaging, HostLifecycleState.Deleting, HostLifecycleState.Degraded, HostLifecycleState.Recovering],
            [HostLifecycleState.Stopped] = [HostLifecycleState.Starting, HostLifecycleState.Recovering],
            [HostLifecycleState.Starting] = [HostLifecycleState.Ready, HostLifecycleState.Degraded, HostLifecycleState.Recovering],
            [HostLifecycleState.Reimaging] = [HostLifecycleState.Bootstrapping, HostLifecycleState.Degraded, HostLifecycleState.Recovering],
            [HostLifecycleState.Deleting] = [HostLifecycleState.Deleted, HostLifecycleState.Recovering],
            [HostLifecycleState.Degraded] = [HostLifecycleState.Recovering, HostLifecycleState.Draining],
            [HostLifecycleState.Recovering] = [HostLifecycleState.Ready, HostLifecycleState.Draining, HostLifecycleState.Degraded]
        };

    public HostId Id { get; }
    public PoolId PoolId { get; }
    public NodeIncarnationId NodeIncarnationId { get; private set; }
    public HostLifecycleState LifecycleState { get; private set; } = HostLifecycleState.Discovered;
    public HostConnectionState ConnectionState { get; private set; } = HostConnectionState.Unknown;
    public IReadOnlyList<string> ForcedLossManifest { get; private set; } = [];

    public Host(HostId id, PoolId poolId, NodeIncarnationId nodeIncarnationId)
    {
        Id = id;
        PoolId = poolId;
        NodeIncarnationId = nodeIncarnationId;
    }

    public void SetConnectionState(HostConnectionState state) => ConnectionState = state;

    public void TransitionTo(HostLifecycleState next)
    {
        Rule.Require(next != HostLifecycleState.Draining, DomainErrorCode.LifecycleBlockedByActiveWork, "Use BeginDrain so active work is evaluated.");
        if (next is HostLifecycleState.Stopped or HostLifecycleState.Reimaging or HostLifecycleState.Deleting)
            Rule.Require(LifecycleState == HostLifecycleState.Draining, DomainErrorCode.LifecycleBlockedByActiveWork, "Destructive lifecycle transitions require drain.");
        ApplyTransition(next);
    }

    private void ApplyTransition(HostLifecycleState next)
    {
        Rule.Transition(LifecycleState, next, Transitions, nameof(Host));
        LifecycleState = next;
    }

    public void BeginDrain(IEnumerable<DrainObligation> obligations, bool force = false, IReadOnlyList<string>? lossManifest = null)
    {
        var items = obligations.ToArray();
        var blockers = items.Where(x =>
            x.InterruptionClass == InterruptionClass.NonInterruptible ||
            (x.InterruptionClass == InterruptionClass.CheckpointResumable && (!x.CheckpointComplete || !x.PortableReceiptPresent))).ToArray();

        if (blockers.Length > 0 && !force)
            throw new DomainRuleViolationException(DomainErrorCode.LifecycleBlockedByActiveWork, "Active work or incomplete portable state blocks drain.");

        if (force)
        {
            Rule.Require(lossManifest is { Count: > 0 }, DomainErrorCode.LifecycleBlockedByActiveWork, "Forced drain requires an explicit loss manifest.");
            ForcedLossManifest = lossManifest!;
        }

        ApplyTransition(HostLifecycleState.Draining);
    }

    public void ReplaceIncarnation(NodeIncarnationId incarnationId)
    {
        Rule.Require(LifecycleState is HostLifecycleState.Bootstrapping or HostLifecycleState.Enrolling,
            DomainErrorCode.IllegalStateTransition, "Host incarnation can change only during bootstrap or enrollment.");
        Rule.Require(incarnationId != NodeIncarnationId, DomainErrorCode.RevisionConflict, "Host incarnation must change.");
        NodeIncarnationId = incarnationId;
    }
}
