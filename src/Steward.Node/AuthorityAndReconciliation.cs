using Steward.Contracts;
using Steward.Domain;

namespace Steward.Node;

public enum DelegationAuthorityState { Active, NoNewStarts, Draining, Expired }

public sealed class DelegatedExecutionAuthority(NodeJournal journal)
{
    public Task<StartAuthorityReservation> ReserveStartAuthorityAsync(
        TaskAttemptId attemptId,
        DelegationId delegationId,
        TaskId taskId,
        int generation,
        ResourceRequirements resources,
        IReadOnlyDictionary<string, decimal>? requestedRates,
        IEnumerable<IdentityGrantId>? requestedIdentities,
        DateTimeOffset now,
        CancellationToken cancellationToken = default) =>
        journal.ReserveStartAuthorityAsync(
            attemptId, delegationId, taskId, generation, resources,
            requestedRates, requestedIdentities, now, cancellationToken);

    public Task<long> RecordTerminalFactAsync(
        Guid reservationId,
        string factType,
        object payload,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken = default) =>
        journal.CompleteStartReservationAsync(reservationId, factType, payload, observedAt, cancellationToken);

    public static DelegationAuthorityState GetState(DelegationDto delegation, DateTimeOffset now) =>
        now >= delegation.AuthorityExpiresAt ? DelegationAuthorityState.Expired :
        now >= delegation.DrainAt ? DelegationAuthorityState.Draining :
        now >= delegation.NoNewStartsAfter ? DelegationAuthorityState.NoNewStarts :
        DelegationAuthorityState.Active;

}

public sealed class ReconciliationService(NodeJournal journal)
{
    public Task<long> EmitAsync(string factType, object payload, DateTimeOffset observedAt, CancellationToken cancellationToken = default) =>
        journal.AppendFactAsync(factType, payload, observedAt, cancellationToken);

    public async Task<IReadOnlyList<JournaledFact>> ReplayUnacknowledgedAsync(int maximumCount = 256, CancellationToken cancellationToken = default)
    {
        var cursor = await journal.GetAcknowledgedCursorAsync(cancellationToken);
        return await journal.ReadFactsAfterAsync(cursor, maximumCount, cancellationToken);
    }

    public Task AcknowledgeAsync(
        Guid sessionId,
        NodeIncarnationId incarnationId,
        long contiguousCursor,
        CancellationToken cancellationToken = default) =>
        journal.AcknowledgeFactsAsync(sessionId, incarnationId, contiguousCursor, cancellationToken);
}
