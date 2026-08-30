namespace Steward.Domain;

public sealed class StewardTask
{
    private static readonly IReadOnlyDictionary<TaskObservedState, TaskObservedState[]> Transitions =
        new Dictionary<TaskObservedState, TaskObservedState[]>
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

    public TaskId Id { get; }
    public WorkloadId WorkloadId { get; }
    public PlanRevisionId PlanRevisionId { get; }
    public TaskDesiredState DesiredState { get; private set; } = TaskDesiredState.Ready;
    public TaskObservedState ObservedState { get; private set; } = TaskObservedState.Blocked;
    public int AcceptedGeneration { get; private set; }
    public TaskAttemptId? ActiveAttemptId { get; private set; }
    public bool ExecutionIsAmbiguous { get; private set; }

    public StewardTask(TaskId id, WorkloadId workloadId, PlanRevisionId planRevisionId)
    {
        Id = id;
        WorkloadId = workloadId;
        PlanRevisionId = planRevisionId;
    }

    public void SetDesiredState(TaskDesiredState state)
    {
        IReadOnlyDictionary<TaskDesiredState, TaskDesiredState[]> transitions =
            new Dictionary<TaskDesiredState, TaskDesiredState[]>
            {
                [TaskDesiredState.Ready] = [TaskDesiredState.Running, TaskDesiredState.Paused, TaskDesiredState.Cancelled],
                [TaskDesiredState.Running] = [TaskDesiredState.Paused, TaskDesiredState.Cancelled],
                [TaskDesiredState.Paused] = [TaskDesiredState.Ready, TaskDesiredState.Running, TaskDesiredState.Cancelled]
            };
        Rule.Transition(DesiredState, state, transitions, nameof(StewardTask));
        DesiredState = state;
    }

    public void TransitionTo(TaskObservedState next)
    {
        Rule.Transition(ObservedState, next, Transitions, nameof(StewardTask));
        ObservedState = next;
    }

    public TaskAttempt StartAttempt(int generation, TaskAttemptId attemptId, HostId hostId, NodeIncarnationId incarnationId, bool explicitRerun = false)
    {
        Rule.Require(!ExecutionIsAmbiguous, DomainErrorCode.AmbiguousExecution, "Ambiguous execution must be reconciled before relaunch.");
        Rule.Require(ActiveAttemptId is null, DomainErrorCode.StaleAttemptGeneration, "Only one nonterminal attempt may own the execution right.");
        Rule.Require(generation == AcceptedGeneration + 1, DomainErrorCode.StaleAttemptGeneration, "Attempt generation must increase by exactly one.");
        Rule.Require(!IsTerminal(ObservedState) || explicitRerun, DomainErrorCode.IllegalStateTransition, "A terminal Task requires an explicit rerun.");

        AcceptedGeneration = generation;
        ActiveAttemptId = attemptId;
        if (IsTerminal(ObservedState))
            ObservedState = TaskObservedState.Queued;
        return new TaskAttempt(attemptId, Id, generation, hostId, incarnationId);
    }

    public void CompleteAttempt(TaskAttempt attempt)
    {
        Rule.Require(ActiveAttemptId == attempt.Id && attempt.Generation == AcceptedGeneration,
            DomainErrorCode.StaleAttemptGeneration, "Attempt does not own this Task generation.");
        Rule.Require(attempt.IsTerminal, DomainErrorCode.IllegalStateTransition, "A nonterminal attempt cannot be completed.");

        ActiveAttemptId = null;
        ExecutionIsAmbiguous = false;
        ObservedState = attempt.State switch
        {
            TaskAttemptState.Succeeded => TaskObservedState.Succeeded,
            TaskAttemptState.Failed => TaskObservedState.Failed,
            TaskAttemptState.Cancelled => TaskObservedState.Cancelled,
            TaskAttemptState.Interrupted or TaskAttemptState.Checkpointed => TaskObservedState.Interrupted,
            _ => throw new DomainRuleViolationException(DomainErrorCode.IllegalStateTransition, "Attempt is not terminal.")
        };
    }

    public void MarkExecutionAmbiguous(TaskAttempt attempt)
    {
        Rule.Require(ActiveAttemptId == attempt.Id && attempt.Generation == AcceptedGeneration,
            DomainErrorCode.StaleAttemptGeneration, "Attempt does not own this Task generation.");
        attempt.MarkExecutionAmbiguous();
        ExecutionIsAmbiguous = true;
        ObservedState = TaskObservedState.Recovering;
    }

    public void ReconcileAmbiguousAttempt(TaskAttempt attempt, RecoveryCertainty certainty, TaskAttemptState resolvedState)
    {
        Rule.Require(ExecutionIsAmbiguous && ActiveAttemptId == attempt.Id, DomainErrorCode.AmbiguousExecution, "No matching ambiguous attempt exists.");
        attempt.Reconcile(certainty, resolvedState);
        ExecutionIsAmbiguous = false;
        if (attempt.IsTerminal)
            CompleteAttempt(attempt);
        else
            ObservedState = TaskObservedState.Running;
    }

    private static bool IsTerminal(TaskObservedState state) =>
        state is TaskObservedState.Succeeded or TaskObservedState.Failed or TaskObservedState.Cancelled;
}

public sealed class TaskAttempt
{
    private static readonly IReadOnlyDictionary<TaskAttemptState, TaskAttemptState[]> Transitions =
        new Dictionary<TaskAttemptState, TaskAttemptState[]>
        {
            [TaskAttemptState.Reserved] = [TaskAttemptState.Dispatched, TaskAttemptState.Recovering],
            [TaskAttemptState.Dispatched] = [TaskAttemptState.Accepted, TaskAttemptState.Recovering],
            [TaskAttemptState.Accepted] = [TaskAttemptState.Preparing, TaskAttemptState.Recovering],
            [TaskAttemptState.Preparing] = [TaskAttemptState.Launching, TaskAttemptState.Recovering],
            [TaskAttemptState.Launching] = [TaskAttemptState.Running, TaskAttemptState.Recovering],
            [TaskAttemptState.Running] = [TaskAttemptState.Checkpointed, TaskAttemptState.Succeeded, TaskAttemptState.Failed, TaskAttemptState.Cancelled, TaskAttemptState.Interrupted, TaskAttemptState.Recovering],
            [TaskAttemptState.Recovering] = [TaskAttemptState.Running, TaskAttemptState.Checkpointed, TaskAttemptState.Succeeded, TaskAttemptState.Failed, TaskAttemptState.Cancelled, TaskAttemptState.Interrupted]
        };

    public TaskAttemptId Id { get; }
    public TaskId TaskId { get; }
    public int Generation { get; }
    public HostId HostId { get; }
    public NodeIncarnationId NodeIncarnationId { get; }
    public TaskAttemptState State { get; private set; } = TaskAttemptState.Reserved;
    public RecoveryCertainty RecoveryCertainty { get; private set; } = RecoveryCertainty.Certain;
    public bool IsTerminal => State is TaskAttemptState.Checkpointed or TaskAttemptState.Succeeded or TaskAttemptState.Failed or TaskAttemptState.Cancelled or TaskAttemptState.Interrupted;

    public TaskAttempt(TaskAttemptId id, TaskId taskId, int generation, HostId hostId, NodeIncarnationId nodeIncarnationId)
    {
        if (generation <= 0)
            throw new ArgumentOutOfRangeException(nameof(generation));
        Id = id;
        TaskId = taskId;
        Generation = generation;
        HostId = hostId;
        NodeIncarnationId = nodeIncarnationId;
    }

    public void TransitionTo(TaskAttemptState next)
    {
        Rule.Transition(State, next, Transitions, nameof(TaskAttempt));
        State = next;
        if (next != TaskAttemptState.Recovering)
            RecoveryCertainty = RecoveryCertainty.Certain;
    }

    public void MarkExecutionAmbiguous()
    {
        Rule.Require(!IsTerminal, DomainErrorCode.AmbiguousExecution, "A terminal attempt cannot become ambiguous.");
        if (State != TaskAttemptState.Recovering)
            TransitionTo(TaskAttemptState.Recovering);
        RecoveryCertainty = RecoveryCertainty.Ambiguous;
    }

    public void Reconcile(RecoveryCertainty certainty, TaskAttemptState resolvedState)
    {
        Rule.Require(State == TaskAttemptState.Recovering && RecoveryCertainty == RecoveryCertainty.Ambiguous,
            DomainErrorCode.AmbiguousExecution, "Only an ambiguous recovering attempt can be reconciled.");
        Rule.Require(certainty is RecoveryCertainty.ExecutionAbsent or RecoveryCertainty.ExecutionPresent,
            DomainErrorCode.AmbiguousExecution, "Reconciliation must establish execution presence or absence.");
        Rule.Require(certainty != RecoveryCertainty.ExecutionAbsent || resolvedState is TaskAttemptState.Interrupted or TaskAttemptState.Failed or TaskAttemptState.Cancelled,
            DomainErrorCode.AmbiguousExecution, "Absent execution must resolve to a terminal non-success state.");
        TransitionTo(resolvedState);
        RecoveryCertainty = certainty;
    }
}
