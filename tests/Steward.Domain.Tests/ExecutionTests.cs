namespace Steward.Domain.Tests;

public sealed class ExecutionTests
{
    private static StewardTask NewTask() => new(TaskId.New(), WorkloadId.New(), PlanRevisionId.New());

    [Fact]
    public void WorkloadKeepsDesiredAndObservedStateSeparate()
    {
        var workload = new Workload(WorkloadId.New(), PlanRevisionId.New());
        workload.SetDesiredState(WorkloadDesiredState.Paused);
        Assert.Equal(WorkloadObservedState.Planning, workload.ObservedState);

        workload.Observe(WorkloadObservedState.Queued);
        workload.Observe(WorkloadObservedState.Paused);
        Assert.Equal(WorkloadDesiredState.Paused, workload.DesiredState);
        Assert.Throws<DomainRuleViolationException>(() => workload.Observe(WorkloadObservedState.Succeeded));
    }

    [Fact]
    public void WorkloadPlanReplacementRequiresExpectedRevisionAndNoAcceptedAuthority()
    {
        var workload = new Workload(WorkloadId.New(), PlanRevisionId.New());
        Assert.Throws<DomainRuleViolationException>(() => workload.PublishPlanRevision(PlanRevisionId.New(), 1, false));
        Assert.Throws<DomainRuleViolationException>(() => workload.PublishPlanRevision(PlanRevisionId.New(), 0, true));
        workload.PublishPlanRevision(PlanRevisionId.New(), 0, false);
        Assert.Equal(1, workload.Revision);
    }

    [Fact]
    public void TaskSupportsDocumentedHighLevelFlow()
    {
        var task = NewTask();
        TaskObservedState[] route =
        [
            TaskObservedState.Queued, TaskObservedState.Preparing, TaskObservedState.Ready,
            TaskObservedState.Running, TaskObservedState.Checkpointing, TaskObservedState.Paused,
            TaskObservedState.Queued, TaskObservedState.Preparing, TaskObservedState.Ready,
            TaskObservedState.Running, TaskObservedState.Recovering, TaskObservedState.Succeeded
        ];
        foreach (var state in route)
            task.TransitionTo(state);
        Assert.Equal(TaskObservedState.Succeeded, task.ObservedState);
        Assert.Throws<DomainRuleViolationException>(() => task.TransitionTo(TaskObservedState.Running));
    }

    [Fact]
    public void AttemptSupportsEveryNormalPhaseAndTerminalOutcome()
    {
        foreach (var terminal in new[]
                 {
                     TaskAttemptState.Checkpointed, TaskAttemptState.Succeeded, TaskAttemptState.Failed,
                     TaskAttemptState.Cancelled, TaskAttemptState.Interrupted
                 })
        {
            var attempt = NewAttempt(1);
            foreach (var state in new[] { TaskAttemptState.Dispatched, TaskAttemptState.Accepted, TaskAttemptState.Preparing, TaskAttemptState.Launching, TaskAttemptState.Running, terminal })
                attempt.TransitionTo(state);
            Assert.True(attempt.IsTerminal);
            Assert.Throws<DomainRuleViolationException>(() => attempt.TransitionTo(TaskAttemptState.Recovering));
        }
    }

    [Fact]
    public void RecoveringCanResolveToEveryDocumentedOutcome()
    {
        foreach (var resolved in new[]
                 {
                     TaskAttemptState.Running, TaskAttemptState.Checkpointed, TaskAttemptState.Succeeded,
                     TaskAttemptState.Failed, TaskAttemptState.Cancelled, TaskAttemptState.Interrupted
                 })
        {
            var attempt = NewAttempt(1);
            attempt.TransitionTo(TaskAttemptState.Recovering);
            attempt.TransitionTo(resolved);
            Assert.Equal(resolved, attempt.State);
        }
    }

    [Fact]
    public void GenerationIsMonotonicAndOnlyOneNonterminalAttemptExists()
    {
        var task = NewTask();
        var first = task.StartAttempt(1, TaskAttemptId.New(), HostId.New(), NodeIncarnationId.New());
        Assert.Throws<DomainRuleViolationException>(() => task.StartAttempt(2, TaskAttemptId.New(), HostId.New(), NodeIncarnationId.New()));
        Assert.Throws<DomainRuleViolationException>(() => task.CompleteAttempt(first));

        RunTo(first, TaskAttemptState.Succeeded);
        task.CompleteAttempt(first);
        Assert.Throws<DomainRuleViolationException>(() => task.StartAttempt(3, TaskAttemptId.New(), HostId.New(), NodeIncarnationId.New(), true));
        var second = task.StartAttempt(2, TaskAttemptId.New(), HostId.New(), NodeIncarnationId.New(), true);
        Assert.Equal(2, second.Generation);
    }

    [Fact]
    public void AmbiguousLaunchBlocksRelaunchUntilAbsenceIsEstablished()
    {
        var task = NewTask();
        var attempt = task.StartAttempt(1, TaskAttemptId.New(), HostId.New(), NodeIncarnationId.New());
        attempt.TransitionTo(TaskAttemptState.Dispatched);
        task.MarkExecutionAmbiguous(attempt);

        var error = Assert.Throws<DomainRuleViolationException>(() =>
            task.StartAttempt(2, TaskAttemptId.New(), HostId.New(), NodeIncarnationId.New()));
        Assert.Equal(DomainErrorCode.AmbiguousExecution, error.Code);
        Assert.Throws<DomainRuleViolationException>(() =>
            task.ReconcileAmbiguousAttempt(attempt, RecoveryCertainty.Ambiguous, TaskAttemptState.Interrupted));

        task.ReconcileAmbiguousAttempt(attempt, RecoveryCertainty.ExecutionAbsent, TaskAttemptState.Interrupted);
        var replacement = task.StartAttempt(2, TaskAttemptId.New(), HostId.New(), NodeIncarnationId.New());
        Assert.Equal(2, replacement.Generation);
    }

    private static TaskAttempt NewAttempt(int generation) =>
        new(TaskAttemptId.New(), TaskId.New(), generation, HostId.New(), NodeIncarnationId.New());

    private static void RunTo(TaskAttempt attempt, TaskAttemptState terminal)
    {
        foreach (var state in new[] { TaskAttemptState.Dispatched, TaskAttemptState.Accepted, TaskAttemptState.Preparing, TaskAttemptState.Launching, TaskAttemptState.Running, terminal })
            attempt.TransitionTo(state);
    }
}
