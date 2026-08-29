namespace Steward.Orchestration;

public interface INodeRateFeedbackSource
{
    ValueTask<IReadOnlyList<RateFeedbackFact>> ReadPendingAsync(
        int maximumCount, CancellationToken cancellationToken);
    ValueTask MarkProcessedAsync(long feedbackSequence, CancellationToken cancellationToken);
}
