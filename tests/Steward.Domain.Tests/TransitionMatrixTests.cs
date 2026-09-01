namespace Steward.Domain.Tests;

public sealed class TransitionMatrixTests
{
    [Fact]
    public void EveryDesiredStateTransitionIsExecutable()
    {
        var workloadEdges = new Dictionary<WorkloadDesiredState, WorkloadDesiredState[]>
        {
            [WorkloadDesiredState.Active] = [WorkloadDesiredState.Paused, WorkloadDesiredState.Cancelling],
            [WorkloadDesiredState.Paused] = [WorkloadDesiredState.Active, WorkloadDesiredState.Cancelling],
            [WorkloadDesiredState.Cancelling] = [WorkloadDesiredState.Cancelled]
        };
        Verify(workloadEdges, WorkloadDesiredState.Active,
            () => new Workload(WorkloadId.New(), PlanRevisionId.New()),
            x => x.DesiredState,
            (x, next) => x.SetDesiredState(next));

        var taskEdges = new Dictionary<TaskDesiredState, TaskDesiredState[]>
        {
            [TaskDesiredState.Ready] = [TaskDesiredState.Running, TaskDesiredState.Paused, TaskDesiredState.Cancelled],
            [TaskDesiredState.Running] = [TaskDesiredState.Paused, TaskDesiredState.Cancelled],
            [TaskDesiredState.Paused] = [TaskDesiredState.Ready, TaskDesiredState.Running, TaskDesiredState.Cancelled]
        };
        Verify(taskEdges, TaskDesiredState.Ready,
            () => new StewardTask(TaskId.New(), WorkloadId.New(), PlanRevisionId.New()),
            x => x.DesiredState,
            (x, next) => x.SetDesiredState(next));
    }

    [Fact]
    public void EveryDocumentedWorkloadObservedTransitionIsExecutable()
    {
        var edges = new Dictionary<WorkloadObservedState, WorkloadObservedState[]>
        {
            [WorkloadObservedState.Planning] = [WorkloadObservedState.Queued, WorkloadObservedState.Recovering, WorkloadObservedState.Failed, WorkloadObservedState.Cancelled],
            [WorkloadObservedState.Queued] = [WorkloadObservedState.Running, WorkloadObservedState.Paused, WorkloadObservedState.Recovering, WorkloadObservedState.Cancelled],
            [WorkloadObservedState.Running] = [WorkloadObservedState.Paused, WorkloadObservedState.Recovering, WorkloadObservedState.Succeeded, WorkloadObservedState.PartiallySucceeded, WorkloadObservedState.Failed, WorkloadObservedState.Cancelled],
            [WorkloadObservedState.Paused] = [WorkloadObservedState.Queued, WorkloadObservedState.Running, WorkloadObservedState.Recovering, WorkloadObservedState.Cancelled],
            [WorkloadObservedState.Recovering] = [WorkloadObservedState.Queued, WorkloadObservedState.Running, WorkloadObservedState.Paused, WorkloadObservedState.Succeeded, WorkloadObservedState.PartiallySucceeded, WorkloadObservedState.Failed, WorkloadObservedState.Cancelled]
        };
        Verify(edges, WorkloadObservedState.Planning,
            () => new Workload(WorkloadId.New(), PlanRevisionId.New()),
            x => x.ObservedState,
            (x, next) => x.Observe(next));
    }

    [Fact]
    public void EveryDocumentedTaskObservedTransitionIsExecutable()
    {
        var edges = new Dictionary<TaskObservedState, TaskObservedState[]>
        {
            [TaskObservedState.Blocked] = [TaskObservedState.Queued],
            [TaskObservedState.Queued] = [TaskObservedState.Preparing],
            [TaskObservedState.Preparing] = [TaskObservedState.Ready, TaskObservedState.Recovering, TaskObservedState.Failed, TaskObservedState.Cancelling],
            [TaskObservedState.Ready] = [TaskObservedState.Running, TaskObservedState.Cancelling, TaskObservedState.Recovering],
            [TaskObservedState.Running] = [TaskObservedState.Succeeded, TaskObservedState.Failed, TaskObservedState.Pausing, TaskObservedState.Cancelling, TaskObservedState.Checkpointing, TaskObservedState.Recovering],
            [TaskObservedState.Pausing] = [TaskObservedState.Paused, TaskObservedState.Running, TaskObservedState.Cancelling, TaskObservedState.Recovering],
            [TaskObservedState.Checkpointing] = [TaskObservedState.Paused, TaskObservedState.Interrupted, TaskObservedState.Running, TaskObservedState.Recovering],
            [TaskObservedState.Paused] = [TaskObservedState.Queued, TaskObservedState.Cancelled],
            [TaskObservedState.Cancelling] = [TaskObservedState.Cancelled, TaskObservedState.Recovering],
            [TaskObservedState.Recovering] = [TaskObservedState.Running, TaskObservedState.Interrupted, TaskObservedState.Succeeded, TaskObservedState.Failed, TaskObservedState.Cancelled]
        };
        Verify(edges, TaskObservedState.Blocked,
            () => new StewardTask(TaskId.New(), WorkloadId.New(), PlanRevisionId.New()),
            x => x.ObservedState,
            (x, next) => x.TransitionTo(next));
    }

    [Fact]
    public void EveryDocumentedAttemptTransitionIsExecutable()
    {
        var edges = new Dictionary<TaskAttemptState, TaskAttemptState[]>
        {
            [TaskAttemptState.Reserved] = [TaskAttemptState.Dispatched, TaskAttemptState.Recovering],
            [TaskAttemptState.Dispatched] = [TaskAttemptState.Accepted, TaskAttemptState.Recovering],
            [TaskAttemptState.Accepted] = [TaskAttemptState.Preparing, TaskAttemptState.Recovering],
            [TaskAttemptState.Preparing] = [TaskAttemptState.Launching, TaskAttemptState.Recovering],
            [TaskAttemptState.Launching] = [TaskAttemptState.Running, TaskAttemptState.Recovering],
            [TaskAttemptState.Running] = [TaskAttemptState.Checkpointed, TaskAttemptState.Succeeded, TaskAttemptState.Failed, TaskAttemptState.Cancelled, TaskAttemptState.Interrupted, TaskAttemptState.Recovering],
            [TaskAttemptState.Recovering] = [TaskAttemptState.Running, TaskAttemptState.Checkpointed, TaskAttemptState.Succeeded, TaskAttemptState.Failed, TaskAttemptState.Cancelled, TaskAttemptState.Interrupted]
        };
        Verify(edges, TaskAttemptState.Reserved,
            () => new TaskAttempt(TaskAttemptId.New(), TaskId.New(), 1, HostId.New(), NodeIncarnationId.New()),
            x => x.State,
            (x, next) => x.TransitionTo(next));
    }

    [Fact]
    public void EveryDocumentedAgentTransitionIsExecutable()
    {
        var edges = new Dictionary<StewardAgentState, StewardAgentState[]>
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
        Verify(edges, StewardAgentState.Creating,
            () => new StewardAgent(StewardAgentId.New()),
            x => x.State,
            (x, next) => x.TransitionTo(next));
    }

    [Fact]
    public void EveryDocumentedAgentTurnTransitionIsExecutable()
    {
        var edges = new Dictionary<AgentTurnState, AgentTurnState[]>
        {
            [AgentTurnState.Queued] = [AgentTurnState.Delegated, AgentTurnState.Cancelled],
            [AgentTurnState.Delegated] = [AgentTurnState.Running, AgentTurnState.Failed, AgentTurnState.Cancelled],
            [AgentTurnState.Running] = [AgentTurnState.Responded, AgentTurnState.Failed, AgentTurnState.Cancelled],
            [AgentTurnState.Responded] = [AgentTurnState.Notified]
        };
        Verify(edges, AgentTurnState.Queued,
            () => new AgentTurn(AgentTurnId.New()),
            x => x.State,
            (x, next) => x.TransitionTo(next, next == AgentTurnState.Responded ? 1 : null));
    }

    [Fact]
    public void EveryDocumentedHostTransitionIsExecutable()
    {
        var edges = new Dictionary<HostLifecycleState, HostLifecycleState[]>
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
        Verify(edges, HostLifecycleState.Discovered,
            () => new Host(HostId.New(), PoolId.New(), NodeIncarnationId.New()),
            x => x.LifecycleState,
            (x, next) =>
            {
                if (next == HostLifecycleState.Draining)
                    x.BeginDrain([]);
                else
                    x.TransitionTo(next);
            });
    }

    private static void Verify<TAggregate, TState>(
        IReadOnlyDictionary<TState, TState[]> edges,
        TState initial,
        Func<TAggregate> factory,
        Func<TAggregate, TState> getState,
        Action<TAggregate, TState> transition)
        where TState : notnull
    {
        foreach (var edge in edges)
            foreach (var destination in edge.Value)
            {
                var aggregate = factory();
                foreach (var step in FindRoute(edges, initial, edge.Key))
                    transition(aggregate, step);
                Assert.Equal(edge.Key, getState(aggregate));
                transition(aggregate, destination);
                Assert.Equal(destination, getState(aggregate));
            }
    }

    private static IReadOnlyList<TState> FindRoute<TState>(
        IReadOnlyDictionary<TState, TState[]> edges,
        TState initial,
        TState destination)
        where TState : notnull
    {
        if (EqualityComparer<TState>.Default.Equals(initial, destination))
            return [];

        var queue = new Queue<(TState State, IReadOnlyList<TState> Route)>();
        var visited = new HashSet<TState> { initial };
        queue.Enqueue((initial, []));
        while (queue.TryDequeue(out var item))
        {
            foreach (var next in edges.GetValueOrDefault(item.State) ?? [])
            {
                var route = item.Route.Append(next).ToArray();
                if (EqualityComparer<TState>.Default.Equals(next, destination))
                    return route;
                if (visited.Add(next))
                    queue.Enqueue((next, route));
            }
        }

        throw new InvalidOperationException($"No route from {initial} to {destination}.");
    }
}
