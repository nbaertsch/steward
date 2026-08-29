using System.Collections.Concurrent;
using Steward.ConnectionHost.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.LiveAcceptance;

internal sealed record DvcGenerationAttestation(
    long ConnectionGeneration,
    int RdpSessionId,
    Guid Nonce,
    long PingSequence,
    TimeSpan? PingRoundTripTime,
    IReadOnlyList<RdCoreDvcEvidenceEvent> OrderedEvidence);

internal interface IDvcGenerationAttestationSource
{
    DvcGenerationAttestation Get(long connectionGeneration);

    Task CloseAsync(
        long connectionGeneration,
        CancellationToken cancellationToken);
}

internal sealed class AttestingProductionEvidenceSource :
    IRdpDvcRuntimeEvidenceSource,
    IDvcGenerationAttestationSource,
    IAsyncDisposable
{
    private static readonly IReadOnlyList<RdCoreDvcEvidenceEvent>
        OrderedEvidence = Enum.GetValues<RdCoreDvcEvidenceEvent>();

    private readonly ProductionRdpDvcRuntimeEvidenceSource inner;
    private readonly IReadOnlyDictionary<string, RdpDvcEvidenceRoute>
        expectedRoutes;
    private readonly ConcurrentDictionary<Guid, RdpDvcRuntimeEvidenceTicket>
        tickets = [];
    private readonly ConcurrentDictionary<long, DvcGenerationAttestation>
        attestations = [];

    internal AttestingProductionEvidenceSource(
        ProductionRdpDvcRuntimeEvidenceSource inner,
        Guid sessionId,
        Guid hostId,
        Guid nodeIncarnationId,
        IReadOnlyList<RemoteBootstrapGeneration> generations)
    {
        this.inner = inner;
        expectedRoutes = generations.ToDictionary(
            static generation => generation.EvidenceReference,
            generation => new RdpDvcEvidenceRoute(
                sessionId,
                hostId,
                nodeIncarnationId,
                0,
                generation.ConnectionNonce),
            StringComparer.Ordinal);
    }

    public bool IsConfigured => inner.IsConfigured;

    public async ValueTask<RdpDvcRuntimeEvidenceTicket>
        RegisterExpectedAsync(
            string evidenceReference,
            string connectionId,
            string runtimeConnectionId,
            long connectionGeneration,
            CancellationToken cancellationToken)
    {
        var ticket = await inner.RegisterExpectedAsync(
                evidenceReference,
                connectionId,
                runtimeConnectionId,
                connectionGeneration,
                cancellationToken)
            .ConfigureAwait(false);
        if (!expectedRoutes.TryGetValue(
                evidenceReference,
                out var expectedRoute) ||
            ticket.Identity.Route != expectedRoute)
        {
            await inner.CancelAsync(ticket).ConfigureAwait(false);
            throw new InvalidDataException(
                "The protected production evidence ticket changed after bootstrap validation.");
        }
        if (!tickets.TryAdd(ticket.TicketId, ticket))
            throw new InvalidOperationException(
                "The DVC evidence ticket collided.");
        return ticket;
    }

    public async Task<RdpDvcRuntimeEvidenceBatch> WaitForEvidenceAsync(
        RdpDvcRuntimeEvidenceTicket ticket,
        CancellationToken cancellationToken)
    {
        if (!tickets.TryGetValue(ticket.TicketId, out var active) ||
            active != ticket)
            throw new InvalidDataException(
                "The DVC evidence ticket is not active.");
        var batch = await inner.WaitForEvidenceAsync(
                ticket,
                cancellationToken)
            .ConfigureAwait(false);
        var external = batch.Evidence.Select(
            static item => item.Event);
        var expectedExternal = OrderedEvidence.Skip(2);
        if (!external.SequenceEqual(expectedExternal))
            throw new InvalidDataException(
                "The authenticated production evidence publication was incomplete or out of order.");
        var route = batch.AuthenticatedRoute?.ValidateBound() ??
            throw new InvalidDataException(
                "The production evidence batch did not retain its authenticated WTS route.");
        var expectedRoute = expectedRoutes[
            ticket.Identity.EvidenceReference];
        if (!expectedRoute.HasSamePreauthorizedBase(route))
            throw new InvalidDataException(
                "The authenticated WTS route changed its preauthorized identity.");
        var attestation = new DvcGenerationAttestation(
            ticket.Identity.ConnectionGeneration,
            route.WtsSessionId,
            route.ConnectionNonce,
            1,
            null,
            OrderedEvidence);
        if (!attestations.TryAdd(
                ticket.Identity.ConnectionGeneration,
                attestation))
            throw new InvalidOperationException(
                "The generation attestation collided.");
        return batch;
    }

    public async ValueTask CancelAsync(
        RdpDvcRuntimeEvidenceTicket ticket)
    {
        tickets.TryRemove(ticket.TicketId, out _);
        await inner.CancelAsync(ticket).ConfigureAwait(false);
    }

    public DvcGenerationAttestation Get(long connectionGeneration) =>
        attestations.TryGetValue(connectionGeneration, out var value)
            ? value
            : throw new InvalidDataException(
                "No production DVC attestation exists for the connected generation.");

    public Task CloseAsync(
        long connectionGeneration,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!attestations.TryRemove(connectionGeneration, out _))
            throw new InvalidDataException(
                "The generation attestation was not retained.");
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => inner.DisposeAsync();
}
