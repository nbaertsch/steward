namespace Steward.Domain;

public sealed class Workload
{
    private static readonly IReadOnlyDictionary<WorkloadDesiredState, WorkloadDesiredState[]> DesiredTransitions =
        new Dictionary<WorkloadDesiredState, WorkloadDesiredState[]>
        {
            [WorkloadDesiredState.Active] = [WorkloadDesiredState.Paused, WorkloadDesiredState.Cancelling],
            [WorkloadDesiredState.Paused] = [WorkloadDesiredState.Active, WorkloadDesiredState.Cancelling],
            [WorkloadDesiredState.Cancelling] = [WorkloadDesiredState.Cancelled]
        };

    private static readonly IReadOnlyDictionary<WorkloadObservedState, WorkloadObservedState[]> ObservedTransitions =
        new Dictionary<WorkloadObservedState, WorkloadObservedState[]>
        {
            [WorkloadObservedState.Planning] = [WorkloadObservedState.Queued, WorkloadObservedState.Recovering, WorkloadObservedState.Failed, WorkloadObservedState.Cancelled],
            [WorkloadObservedState.Queued] = [WorkloadObservedState.Running, WorkloadObservedState.Paused, WorkloadObservedState.Recovering, WorkloadObservedState.Cancelled],
            [WorkloadObservedState.Running] = [WorkloadObservedState.Paused, WorkloadObservedState.Recovering, WorkloadObservedState.Succeeded, WorkloadObservedState.PartiallySucceeded, WorkloadObservedState.Failed, WorkloadObservedState.Cancelled],
            [WorkloadObservedState.Paused] = [WorkloadObservedState.Queued, WorkloadObservedState.Running, WorkloadObservedState.Recovering, WorkloadObservedState.Cancelled],
            [WorkloadObservedState.Recovering] = [WorkloadObservedState.Queued, WorkloadObservedState.Running, WorkloadObservedState.Paused, WorkloadObservedState.Succeeded, WorkloadObservedState.PartiallySucceeded, WorkloadObservedState.Failed, WorkloadObservedState.Cancelled]
        };

    public WorkloadId Id { get; }
    public PlanRevisionId PlanRevisionId { get; private set; }
    public long Revision { get; private set; }
    public WorkloadDesiredState DesiredState { get; private set; } = WorkloadDesiredState.Active;
    public WorkloadObservedState ObservedState { get; private set; } = WorkloadObservedState.Planning;

    public Workload(WorkloadId id, PlanRevisionId planRevisionId)
    {
        Id = id;
        PlanRevisionId = planRevisionId;
    }

    public void SetDesiredState(WorkloadDesiredState next)
    {
        Rule.Transition(DesiredState, next, DesiredTransitions, nameof(Workload));
        DesiredState = next;
        Revision++;
    }

    public void Observe(WorkloadObservedState next)
    {
        Rule.Transition(ObservedState, next, ObservedTransitions, nameof(Workload));
        ObservedState = next;
        Revision++;
    }

    public void PublishPlanRevision(PlanRevisionId next, long expectedRevision, bool hasAcceptedDelegations)
    {
        Rule.Require(expectedRevision == Revision, DomainErrorCode.RevisionConflict, "Expected workload revision does not match.");
        Rule.Require(!hasAcceptedDelegations, DomainErrorCode.RevisionConflict, "An accepted delegation must be finished or revoked before replacing the plan.");
        Rule.Require(next != PlanRevisionId, DomainErrorCode.RevisionConflict, "The plan revision must change.");
        PlanRevisionId = next;
        Revision++;
    }
}
