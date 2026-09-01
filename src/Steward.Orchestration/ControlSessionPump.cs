using System.Text;
using Steward.Persistence.Sqlite;
using Steward.Transport;

namespace Steward.Orchestration;

public sealed class ControlSessionPump
{
    private readonly ControlOrchestrator orchestrator;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan pollInterval;
    private readonly IReadOnlyDictionary<StreamKind, IAuxiliaryTransportStreamHandler>
        auxiliaryHandlers;
    private readonly Steward.Domain.HostId hostId;
    private readonly Steward.Domain.NodeIncarnationId nodeIncarnationId;
    private readonly ControlTerminalRouter? terminal;
    private readonly ControlTerminalRevocationStore? revocations;

    public ControlSessionPump(
        ControlOrchestrator orchestrator,
        Steward.Domain.HostId hostId,
        Steward.Domain.NodeIncarnationId nodeIncarnationId,
        ControlTerminalRouter? terminal = null,
        ControlTerminalRevocationStore? revocations = null,
        IEnumerable<IAuxiliaryTransportStreamHandler>? auxiliaryHandlers = null,
        TimeProvider? timeProvider = null,
        TimeSpan? pollInterval = null)
    {
        this.orchestrator = orchestrator ?? throw new ArgumentNullException(nameof(orchestrator));
        this.hostId = hostId;
        this.nodeIncarnationId = nodeIncarnationId;
        this.terminal = terminal;
        this.revocations = revocations;
        this.auxiliaryHandlers =
            AuxiliaryTransportStreamHandlers.Index(auxiliaryHandlers);
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.pollInterval = pollInterval ?? TimeSpan.FromMilliseconds(25);
        if (this.pollInterval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(pollInterval));
    }

    public async Task RunSessionAsync(ITransportConnection connection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (connection.Session.NodeIncarnationId != nodeIncarnationId)
            throw new InvalidOperationException("Control session is bound to another Node incarnation.");
        using var sessionCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var terminalRoute = terminal?.Attach(hostId, connection);
        var sender = new SessionSender(
            connection,
            connection.Session.RemoteResumeCursors.GetValueOrDefault(StreamKind.Control, 0));
        var receivedCursor = connection.Session.LocalResumeCursors.GetValueOrDefault(StreamKind.Events, 0);
        if (receivedCursor > 0)
            await sender.SendAsync(
                OrchestrationMessageCodec.Encode(
                    new FactAcknowledgementMessage(receivedCursor), timeProvider.GetUtcNow()),
                cancellationToken).ConfigureAwait(false);
        var receive = ReceiveFactsAsync(connection, sender, sessionCancellation.Token);
        var send = SendOutboxAsync(connection, sender, sessionCancellation.Token);
        var revoke = FlushRevocationsAsync(sessionCancellation.Token);
        await Task.WhenAny(receive, send).ConfigureAwait(false);
        sessionCancellation.Cancel();
        try { await Task.WhenAll(receive, send, revoke).ConfigureAwait(false); }
        catch (OperationCanceledException) when (sessionCancellation.IsCancellationRequested) { }
    }

    private async Task FlushRevocationsAsync(CancellationToken cancellationToken)
    {
        if (terminal is null || revocations is null) return;
        while (!cancellationToken.IsCancellationRequested)
        {
            foreach (var command in await revocations.ReadAsync(
                         hostId, nodeIncarnationId, cancellationToken))
            {
                var response = await terminal.SendAsync(
                    hostId, "revoke", command, cancellationToken);
                if (response.Status == "ok")
                    await revocations.MarkDeliveredAsync(
                        command.SessionId, command.Revision, cancellationToken);
            }
            await Task.Delay(pollInterval, timeProvider, cancellationToken);
        }
    }

    private async Task SendOutboxAsync(
        ITransportConnection connection,
        SessionSender sender,
        CancellationToken cancellationToken)
    {
        var sent = new HashSet<long>();
        while (!cancellationToken.IsCancellationRequested)
        {
            var outbox = await orchestrator.Store.ReadOutboxAsync(100, timeProvider.GetUtcNow(), cancellationToken)
                .ConfigureAwait(false);
            var pending = outbox.Where(x =>
                IsOrchestrationKind(x.Kind) &&
                !sent.Contains(x.Sequence) &&
                MatchesTarget(x, hostId, nodeIncarnationId)).ToArray();
            if (pending.Length == 0)
            {
                await Task.Delay(pollInterval, timeProvider, cancellationToken).ConfigureAwait(false);
                continue;
            }
            foreach (var item in pending)
            {
                var bytes = Encoding.UTF8.GetBytes(item.PayloadJson);
                _ = OrchestrationMessageCodec.Decode(bytes);
                await sender.SendAsync(bytes, cancellationToken).ConfigureAwait(false);
                sent.Add(item.Sequence);
            }
        }
    }

    private async Task ReceiveFactsAsync(
        ITransportConnection connection,
        SessionSender sender,
        CancellationToken cancellationToken)
    {
        await foreach (var frame in connection.ReceiveAsync(cancellationToken).ConfigureAwait(false))
        {
            if (frame.Stream == StreamKind.Terminal)
            {
                terminal?.Accept(frame);
                continue;
            }
            if (auxiliaryHandlers.TryGetValue(frame.Stream, out var handler))
            {
                await handler.HandleAsync(
                    connection, frame, cancellationToken).ConfigureAwait(false);
                continue;
            }
            if (frame.Stream != StreamKind.Events)
                throw new OrchestrationMessageException("Control accepts orchestration facts only on the Events stream.");
            var decoded = OrchestrationMessageCodec.Decode(frame.Payload);
            if (decoded.Value is LocalMaintenanceResultFact maintenance &&
                (maintenance.HostId != hostId ||
                 maintenance.NodeIncarnationId != nodeIncarnationId))
                throw new OrchestrationMessageException(
                    "Maintenance result targets another Control session.");
            var disposition = await orchestrator.ApplyNodeFactAsync(
                connection.Session.NodeIncarnationId,
                frame.Cursor,
                decoded.Kind,
                decoded.Value,
                cancellationToken).ConfigureAwait(false);
            if (disposition == FactDisposition.Recovery)
                continue;
            var ack = OrchestrationMessageCodec.Encode(
                new FactAcknowledgementMessage(frame.Cursor), timeProvider.GetUtcNow());
            await sender.SendAsync(ack, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsOrchestrationKind(string kind) =>
        kind is OrchestrationMessageKinds.Delegation
            or OrchestrationMessageKinds.ExecuteTask
            or OrchestrationMessageKinds.CancelTask
            or OrchestrationMessageKinds.MaintenanceRequest;

    private static bool MatchesTarget(
        AggregateOutboxItem item,
        Steward.Domain.HostId hostId,
        Steward.Domain.NodeIncarnationId incarnationId)
    {
        var decoded = OrchestrationMessageCodec.Decode(Encoding.UTF8.GetBytes(item.PayloadJson)).Value;
        return decoded switch
        {
            DelegationMessage value =>
                value.Delegation.HostId == hostId &&
                value.Delegation.NodeIncarnationId == incarnationId,
            ExecuteTaskMessage value =>
                value.Identity.HostId == hostId &&
                value.Identity.NodeIncarnationId == incarnationId,
            CancelTaskMessage value =>
                value.Identity.HostId == hostId &&
                value.Identity.NodeIncarnationId == incarnationId,
            LocalMaintenanceRequestMessage value =>
                value.HostId == hostId &&
                value.NodeIncarnationId == incarnationId,
            _ => false
        };
    }

    private sealed class SessionSender(ITransportConnection connection, long initialSequence)
    {
        private readonly SemaphoreSlim gate = new(1, 1);
        private long sequence = initialSequence;

        public async Task SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                sequence++;
                await connection.SendAsync(new(
                    connection.Session.SessionId,
                    connection.Session.NodeIncarnationId,
                    StreamKind.Control,
                    sequence,
                    sequence,
                    payload), cancellationToken).ConfigureAwait(false);
            }
            finally { gate.Release(); }
        }
    }
}
