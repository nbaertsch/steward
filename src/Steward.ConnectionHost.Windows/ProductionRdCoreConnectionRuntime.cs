using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Steward.Domain;
using Steward.RdCore.Windows;
using Steward.Transport;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public interface IRdCoreConnectionLeaseHandle : IAsyncDisposable
{
    RdCoreConnectionState State { get; }
    event EventHandler? Connected;
    event EventHandler? WtsPluginsLoaded;
    Task ConnectAsync(CancellationToken cancellationToken);
    Task DisconnectAsync(CancellationToken cancellationToken);
}

public interface IExternallyProvenRdCoreConnectionLeaseHandle :
    IRdCoreConnectionLeaseHandle
{
    Task ConnectionFailure { get; }
    void ConfirmConnected();
}

public interface IRdCorePresentationLeaseHandle
{
    Task ShowAsync(CancellationToken cancellationToken);
    Task HideAsync(CancellationToken cancellationToken);
}

public interface IRdCoreConnectionLeaseFactory
{
    Task<IRdCoreConnectionLeaseHandle> CreateAsync(
        RdCoreConnectionStartRequest request,
        CancellationToken cancellationToken);
}

public sealed class RdCoreConnectionLeaseFactory(
    RdCoreConnectionFactory factory,
    int maximumRdpContentBytes = 1024 * 1024) :
    IRdCoreConnectionLeaseFactory
{
    private static readonly UTF8Encoding StrictUtf8 =
        new(false, true);

    public async Task<IRdCoreConnectionLeaseHandle> CreateAsync(
        RdCoreConnectionStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (maximumRdpContentBytes is <= 0 or > 4 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(
                nameof(maximumRdpContentBytes));
        using var content = new MemoryStream();
        var buffer = new byte[16 * 1024];
        try
        {
            while (true)
            {
                var read = await request.SignedRdpContent.ReadAsync(
                        buffer,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                    break;
                if (content.Length + read > maximumRdpContentBytes)
                    throw new InvalidDataException(
                        "The signed RDP content exceeds its configured bound.");
                content.Write(buffer, 0, read);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        var bytes = content.ToArray();
        if (content.TryGetBuffer(out var buffered))
            CryptographicOperations.ZeroMemory(
                buffered.AsSpan(0, checked((int)content.Length)));
        string signedRdp;
        try
        {
            signedRdp = StrictUtf8.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
        var lease = await factory.CreateAsync(
                new RdCoreResolvedConnection(
                    signedRdp,
                    request.ProviderResourceUri),
                cancellationToken)
            .ConfigureAwait(false);
        return new RdCoreConnectionLeaseHandle(lease);
    }

    private sealed class RdCoreConnectionLeaseHandle(
        RdCoreConnectionLease lease) : IRdCoreConnectionLeaseHandle
    {
        public RdCoreConnectionState State => lease.State;

        public event EventHandler? Connected
        {
            add => lease.Connected += value;
            remove => lease.Connected -= value;
        }

        public event EventHandler? WtsPluginsLoaded
        {
            add => lease.WtsPluginsLoaded += value;
            remove => lease.WtsPluginsLoaded -= value;
        }

        public Task ConnectAsync(CancellationToken cancellationToken) =>
            lease.ConnectAsync(cancellationToken);

        public Task DisconnectAsync(CancellationToken cancellationToken) =>
            lease.DisconnectAsync(cancellationToken);

        public ValueTask DisposeAsync() => lease.DisposeAsync();
    }
}

public sealed record RdpDvcRuntimeEvidenceBatch(
    string ConnectionId,
    string RuntimeConnectionId,
    long ConnectionGeneration,
    IReadOnlyList<RdCoreRuntimeEvidence> Evidence,
    RdpDvcEvidenceRoute? AuthenticatedRoute = null)
{
    public override string ToString() =>
        $"RdpDvcRuntimeEvidenceBatch {{ Generation = " +
        $"{ConnectionGeneration}, EvidenceCount = {Evidence.Count} }}";
}

public interface IRdpDvcRuntimeEvidenceSource
{
    bool IsConfigured { get; }

    ValueTask<RdpDvcRuntimeEvidenceTicket> RegisterExpectedAsync(
        string evidenceReference,
        string connectionId,
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);

    Task<RdpDvcRuntimeEvidenceBatch> WaitForEvidenceAsync(
        RdpDvcRuntimeEvidenceTicket ticket,
        CancellationToken cancellationToken);

    ValueTask CancelAsync(
        RdpDvcRuntimeEvidenceTicket ticket);
}

public interface IRdpDvcLocalCarrierLease : IAsyncDisposable
{
    Task Completion { get; }
}

public interface IRdpDvcLocalCarrier
{
    Task<IRdpDvcLocalCarrierLease> ConnectAsync(
        RdpDvcRuntimeEvidenceTicket ticket,
        CancellationToken cancellationToken);
}

internal interface IRdpDvcLocalCarrierAttempt : IAsyncDisposable
{
    Task Completion { get; }
}

internal interface IRdpDvcLocalCarrierAttemptFactory
{
    Task<IRdpDvcLocalCarrierAttempt> ConnectAsync(
        CancellationToken cancellationToken);
}

internal sealed class RdpDvcLocalCarrierReconnectSupervisor :
    IRdpDvcLocalCarrierLease
{
    private readonly IRdpDvcLocalCarrierAttemptFactory factory;
    private readonly Func<int, TimeSpan> delayFactory;
    private readonly Func<TimeSpan, CancellationToken, Task> delayAsync;
    private readonly CancellationTokenSource stop = new();
    private readonly Task stopped;
    private readonly Task lifetime;
    private IRdpDvcLocalCarrierAttempt? current;
    private int disposed;

    public RdpDvcLocalCarrierReconnectSupervisor(
        IRdpDvcLocalCarrierAttempt initialAttempt,
        IRdpDvcLocalCarrierAttemptFactory factory,
        Func<int, TimeSpan> delayFactory,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null)
    {
        current = initialAttempt ??
            throw new ArgumentNullException(nameof(initialAttempt));
        this.factory = factory ??
            throw new ArgumentNullException(nameof(factory));
        this.delayFactory = delayFactory ??
            throw new ArgumentNullException(nameof(delayFactory));
        this.delayAsync = delayAsync ?? Task.Delay;
        stopped = Task.Delay(Timeout.InfiniteTimeSpan, stop.Token);
        lifetime = RunAsync();
    }

    public Task Completion => lifetime;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        stop.Cancel();
        try
        {
            await lifetime.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (stop.IsCancellationRequested)
        {
        }
        finally
        {
            stop.Dispose();
        }
    }

    private async Task RunAsync()
    {
        var failures = 0;
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var active = current ??
                    throw new InvalidOperationException(
                        "The reconnect supervisor has no active attempt.");
                var completed = await Task.WhenAny(
                        active.Completion,
                        stopped)
                    .ConfigureAwait(false);
                if (completed == stopped)
                    return;
                try
                {
                    await active.Completion.ConfigureAwait(false);
                    failures = 0;
                }
                catch (Exception exception)
                    when (IsRecoverable(exception))
                {
                    failures = 1;
                }
                await active.DisposeAsync().ConfigureAwait(false);
                current = null;
                await delayAsync(
                        delayFactory(failures),
                        stop.Token)
                    .ConfigureAwait(false);

                while (!stop.IsCancellationRequested)
                {
                    try
                    {
                        current = await factory.ConnectAsync(stop.Token)
                            .ConfigureAwait(false) ??
                            throw new InvalidOperationException(
                                "The reconnect attempt factory returned no attempt.");
                        failures = 0;
                        break;
                    }
                    catch (Exception exception)
                        when (IsRecoverable(exception))
                    {
                        failures = Math.Min(failures + 1, 17);
                        await delayAsync(
                                delayFactory(failures),
                                stop.Token)
                            .ConfigureAwait(false);
                    }
                }
            }
        }
        finally
        {
            if (current is not null)
                await current.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static bool IsRecoverable(Exception exception) =>
        exception is
            EndOfStreamException or
            IOException or
            TimeoutException or
            RdpDvcProtocolException or
            TransportProtocolException or
            CryptographicException or
            TransportDisconnectedException or
            TransientTransportException;
}
internal enum RdpDvcLocalCarrierMode
{
    ReconnectV2,
    RetainedV1Migration
}

internal static class RdpDvcLocalCarrierCompatibility
{
    internal static RdpDvcLocalCarrierMode Select(
        RdpDvcEvidenceRoute route)
    {
        ArgumentNullException.ThrowIfNull(route);
        try
        {
            _ = route.Validate();
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                "The DVC carrier compatibility state is invalid.",
                exception);
        }

        if (route.ProtocolVersion == 2 &&
            route.RetainedV1Endpoint is null)
            return RdpDvcLocalCarrierMode.ReconnectV2;
        if (route.ProtocolVersion == 1 &&
            route.RetainedV1Endpoint is { } retained)
        {
            _ = retained.Validate();
            return RdpDvcLocalCarrierMode.RetainedV1Migration;
        }
        throw new InvalidDataException(
            "The DVC carrier protocol downgrade is not authorized.");
    }
}
internal interface IRdpDvcLocalCarrierV2Connection : IAsyncDisposable
{
    RdpDvcCarrierAttemptIdentity Identity { get; }
    Stream Stream { get; }
    RdpDvcCarrierAuthenticationV2 Authentication { get; }
}

internal interface IRdpDvcLocalCarrierV2Connector
{
    Task<IRdpDvcLocalCarrierV2Connection> ConnectAsync(
        RdpDvcEvidenceTicketIdentity ticket,
        ReadOnlyMemory<byte> carrierSecret,
        CancellationToken cancellationToken);
}

internal sealed class NamedPipeRdpDvcLocalCarrierV2Connector(
    string dvcBrokerPipeName) : IRdpDvcLocalCarrierV2Connector
{
    public async Task<IRdpDvcLocalCarrierV2Connection> ConnectAsync(
        RdpDvcEvidenceTicketIdentity ticket,
        ReadOnlyMemory<byte> carrierSecret,
        CancellationToken cancellationToken)
    {
        var route = ticket.Route.Validate();
        var brokerPipeName = RdpDvcPerConnectionRoute.Create(
            Path.GetTempPath(),
            dvcBrokerPipeName,
            ticket.ConnectionId).BrokerPipeName;
        var source = new RdpDvcCarrierV2NamedPipeWireChannelSource(
            new(
                route.SessionId,
                new HostId(route.HostId),
                new NodeIncarnationId(route.NodeIncarnationId),
                ExpectedReconnectGeneration: null,
                ExpectedAttemptId: null,
                ExpectedRdpSessionId:
                    route.IsWtsWildcard ? null : route.WtsSessionId),
            carrierSecret.Span,
            brokerPipeName,
            TimeSpan.FromMinutes(5));
        var wire = await source.OpenChannelAsync(cancellationToken)
            .ConfigureAwait(false);
        var selected = source.SelectedIdentity ??
            throw new InvalidDataException(
                "The DVC broker returned no authenticated reconnect identity.");
        var carrier = await RdpDvcCarrierHandshakeV2.RespondAsync(
                wire,
                selected,
                carrierSecret,
                TimeSpan.FromMinutes(5),
                cancellationToken)
            .ConfigureAwait(false);
        return new Connection(selected, carrier);
    }

    private sealed class Connection(
        RdpDvcCarrierAttemptIdentity identity,
        RdpDvcConnectedStreamV2 carrier) :
        IRdpDvcLocalCarrierV2Connection
    {
        public RdpDvcCarrierAttemptIdentity Identity { get; } = identity;
        public Stream Stream => carrier.Stream;
        public RdpDvcCarrierAuthenticationV2 Authentication =>
            carrier.Authentication;
        public ValueTask DisposeAsync() => carrier.DisposeAsync();
    }
}

public sealed class ProtectedFileRdpDvcLocalCarrier : IRdpDvcLocalCarrier
{
    private readonly string dvcKeyFile;
    private readonly string dvcBrokerPipeName;
    private readonly string evidencePipeName;
    private readonly string evidenceKeyFile;
    private readonly IConnectionReconnectHighWaterStore reconnectHighWater;
    private readonly IRdpDvcOpaqueControlBridge controlBridge;
    private readonly IRdpDvcLocalCarrierV2Connector v2Connector;
    private readonly Action<string>? diagnosticSink;

    public ProtectedFileRdpDvcLocalCarrier(
        string dvcKeyFile, string dvcBrokerPipeName,
        string evidencePipeName, string evidenceKeyFile,
        IConnectionReconnectHighWaterStore reconnectHighWater,
        IRdpDvcOpaqueControlBridge controlBridge,
        Action<string>? diagnosticSink = null)
        : this(dvcKeyFile, dvcBrokerPipeName, evidencePipeName,
            evidenceKeyFile, reconnectHighWater, controlBridge,
            new NamedPipeRdpDvcLocalCarrierV2Connector(dvcBrokerPipeName),
            diagnosticSink)
    {
    }

    internal ProtectedFileRdpDvcLocalCarrier(
        string dvcKeyFile, string dvcBrokerPipeName,
        string evidencePipeName, string evidenceKeyFile,
        IConnectionReconnectHighWaterStore reconnectHighWater,
        IRdpDvcOpaqueControlBridge controlBridge,
        IRdpDvcLocalCarrierV2Connector v2Connector,
        Action<string>? diagnosticSink = null)
    {
        this.dvcKeyFile = dvcKeyFile;
        this.dvcBrokerPipeName = dvcBrokerPipeName;
        this.evidencePipeName = evidencePipeName;
        this.evidenceKeyFile = evidenceKeyFile;
        this.reconnectHighWater = reconnectHighWater;
        this.controlBridge = controlBridge;
        this.v2Connector = v2Connector ??
            throw new ArgumentNullException(nameof(v2Connector));
        this.diagnosticSink = diagnosticSink;
    }
    public async Task<IRdpDvcLocalCarrierLease> ConnectAsync(
        RdpDvcRuntimeEvidenceTicket ticket,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        var mode = RdpDvcLocalCarrierCompatibility.Select(
            ticket.Identity.Route);
        if (mode == RdpDvcLocalCarrierMode.RetainedV1Migration)
            return await ConnectRetainedV1Async(
                    ticket,
                    cancellationToken)
                .ConfigureAwait(false);

        var initial = await ConnectAttemptAsync(
                ticket,
                publishInitialEvidence: true,
                cancellationToken)
            .ConfigureAwait(false);
        return new RdpDvcLocalCarrierReconnectSupervisor(
            initial,
            new AttemptFactory(this, ticket),
            CreateReconnectDelay);
    }

    private async Task<IRdpDvcLocalCarrierLease>
        ConnectRetainedV1Async(
            RdpDvcRuntimeEvidenceTicket ticket,
            CancellationToken cancellationToken)
    {
        diagnosticSink?.Invoke("key-read");
        var key = await File.ReadAllBytesAsync(
                Path.GetFullPath(dvcKeyFile),
                cancellationToken)
            .ConfigureAwait(false);
        AuthenticatedRdpDvcEvidencePublisher? publisher = null;
        RdpDvcConnectedStream? carrier = null;
        IRdpDvcOpaqueControlBridgeLease? bridgeLease = null;
        try
        {
            var route = ticket.Identity.Route.Validate();
            var retained = route.RetainedV1Endpoint?.Validate() ??
                throw new InvalidDataException(
                    "The retained v1 endpoint state is unavailable.");
            var authentication = new RdpDvcAuthenticationOptions(
                new(
                    route.SessionId,
                    route.HostId,
                    route.NodeIncarnationId,
                    route.IsWtsWildcard
                        ? null
                        : route.WtsSessionId,
                    route.ConnectionNonce),
                key);
            var brokerPipeName = RdpDvcPerConnectionRoute.Create(
                Path.GetTempPath(),
                dvcBrokerPipeName,
                ticket.Identity.ConnectionId).BrokerPipeName;
            var source = new RdpDvcNamedPipeWireChannelSource(
                authentication,
                brokerPipeName,
                TimeSpan.FromMinutes(5));
            diagnosticSink?.Invoke("pipe-open-start");
            var wire = await source.OpenChannelAsync(cancellationToken)
                .ConfigureAwait(false);
            carrier = await RdpDvcStreamHandshake.RespondAsync(
                    wire,
                    authentication,
                    cancellationToken)
                .ConfigureAwait(false);
            publisher =
                AuthenticatedRdpDvcEvidencePublisher.FromProtectedFile(
                    evidencePipeName,
                    evidenceKeyFile);
            var evidence = publisher.CreateTransportSession(
                ticket.Identity);
            var authenticatedRoute = RdpDvcEvidenceRoute.From(
                carrier.Handshake) with
            {
                RetainedV1Endpoint = retained
            };
            evidence.BindAuthenticatedRoute(authenticatedRoute);
            await evidence.PublishAsync(
                    RdpDvcEvidencePublicationEvent
                        .DvcHmacAuthenticated,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var attachment = new RetainedV1CarrierAttachment(
                carrier.Handshake.SessionId,
                new HostId(carrier.Handshake.HostId),
                new NodeIncarnationId(
                    carrier.Handshake.NodeIncarnationId),
                carrier.Handshake.RdpSessionId,
                carrier.Handshake.Nonce,
                retained)
            {
                RouteId = route.HostId
            };
            bridgeLease = await controlBridge.AttachAsync(
                    carrier.Stream,
                    attachment,
                    new(
                        ticket.Identity.ConnectionId,
                        ticket.Identity.ConnectionGeneration),
                    cancellationToken)
                .ConfigureAwait(false);
            if (bridgeLease.Completion.IsCompleted)
                throw new TransportDisconnectedException(
                    "The retained v1 Control session closed during attachment.");
            await evidence.PublishAsync(
                    RdpDvcEvidencePublicationEvent
                        .SecurePeerAuthenticated,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            diagnosticSink?.Invoke("control-secure-accept-complete");
            var result = new LocalCarrierAttempt(
                bridgeLease,
                carrier,
                publisher);
            bridgeLease = null;
            carrier = null;
            publisher = null;
            return result;
        }
        finally
        {
            if (bridgeLease is not null)
                await bridgeLease.DisposeAsync().ConfigureAwait(false);
            if (carrier is not null)
                await carrier.DisposeAsync().ConfigureAwait(false);
            if (publisher is not null)
                await publisher.DisposeAsync().ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(key);
        }
    }
    private async Task<IRdpDvcLocalCarrierAttempt> ConnectAttemptAsync(
        RdpDvcRuntimeEvidenceTicket ticket,
        bool publishInitialEvidence,
        CancellationToken cancellationToken)
    {
        diagnosticSink?.Invoke("key-read");
        var key = await File.ReadAllBytesAsync(
                Path.GetFullPath(dvcKeyFile),
                cancellationToken)
            .ConfigureAwait(false);
        AuthenticatedRdpDvcEvidencePublisher? publisher = null;
        IRdpDvcLocalCarrierV2Connection? carrier = null;
        IRdpDvcOpaqueControlBridgeLease? bridgeLease = null;
        try
        {
            diagnosticSink?.Invoke("pipe-open-start");
            carrier = await v2Connector.ConnectAsync(
                    ticket.Identity,
                    key,
                    cancellationToken)
                .ConfigureAwait(false);
            diagnosticSink?.Invoke("carrier-hmac-accept-complete");
            var selected = carrier.Identity;
            RdpDvcEvidencePublisherSession? evidence = null;
            if (publishInitialEvidence)
            {
                publisher =
                    AuthenticatedRdpDvcEvidencePublisher.FromProtectedFile(
                        evidencePipeName,
                        evidenceKeyFile);
                evidence = publisher.CreateTransportSession(
                    ticket.Identity);
                var authenticatedRoute = new RdpDvcEvidenceRoute(
                    selected.SessionId,
                    selected.HostId.Value,
                    selected.NodeIncarnationId.Value,
                    selected.RdpSessionId,
                    selected.AttemptId,
                    ProtocolVersion: 2);
                evidence.BindAuthenticatedReconnectRoute(
                    authenticatedRoute);
                diagnosticSink?.Invoke(
                    "evidence-hmac-publish-start");
                await evidence.PublishAsync(
                        RdpDvcEvidencePublicationEvent
                            .DvcHmacAuthenticated,
                        cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                diagnosticSink?.Invoke(
                    "evidence-hmac-publish-complete");
            }

            diagnosticSink?.Invoke("control-attach-start");
            bridgeLease = await controlBridge.AttachAsync(
                    carrier.Stream,
                    new ReconnectCarrierAttachment(
                        selected.SessionId,
                        carrier.Authentication.ToTransportBinding()),
                    new(
                        ticket.Identity.ConnectionId,
                        ticket.Identity.ConnectionGeneration),
                    cancellationToken)
                .ConfigureAwait(false);
            diagnosticSink?.Invoke("control-attach-complete");
            await reconnectHighWater.ObserveAsync(
                    ticket.Identity.ConnectionId,
                    selected,
                    cancellationToken)
                .ConfigureAwait(false);
            if (bridgeLease.Completion.IsCompleted)
                throw new TransportDisconnectedException(
                    "The authenticated Control session closed during attachment.");
            if (evidence is not null)
            {
                diagnosticSink?.Invoke(
                    "evidence-secure-publish-start");
                await evidence.PublishAsync(
                        RdpDvcEvidencePublicationEvent
                            .SecurePeerAuthenticated,
                        cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                diagnosticSink?.Invoke(
                    "evidence-secure-publish-complete");
                diagnosticSink?.Invoke(
                    "control-secure-accept-complete");
            }

            var result = new LocalCarrierAttempt(
                bridgeLease,
                carrier,
                publisher);
            bridgeLease = null;
            carrier = null;
            publisher = null;
            return result;
        }
        finally
        {
            if (bridgeLease is not null)
                await bridgeLease.DisposeAsync().ConfigureAwait(false);
            if (carrier is not null)
                await carrier.DisposeAsync().ConfigureAwait(false);
            if (publisher is not null)
                await publisher.DisposeAsync().ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static TimeSpan CreateReconnectDelay(int failures) =>
        RdpDvcReconnectBackoff.CreateDelay(failures);
    private sealed class AttemptFactory(
        ProtectedFileRdpDvcLocalCarrier owner,
        RdpDvcRuntimeEvidenceTicket ticket) :
        IRdpDvcLocalCarrierAttemptFactory
    {
        public Task<IRdpDvcLocalCarrierAttempt> ConnectAsync(
            CancellationToken cancellationToken) =>
            owner.ConnectAttemptAsync(
                ticket,
                publishInitialEvidence: false,
                cancellationToken);
    }

    private sealed class LocalCarrierAttempt(
        IRdpDvcOpaqueControlBridgeLease bridgeLease,
        IAsyncDisposable carrier,
        AuthenticatedRdpDvcEvidencePublisher? publisher) :
        IRdpDvcLocalCarrierAttempt,
        IRdpDvcLocalCarrierLease
    {
        private int disposed;

        public Task Completion => bridgeLease.Completion;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;
            await bridgeLease.DisposeAsync().ConfigureAwait(false);
            await carrier.DisposeAsync().ConfigureAwait(false);
            if (publisher is not null)
                await publisher.DisposeAsync().ConfigureAwait(false);
        }
    }
}
public sealed record RdpDvcRuntimeEvidenceTicket(
    Guid TicketId,
    RdpDvcEvidenceTicketIdentity Identity)
{
    public override string ToString() =>
        $"RdpDvcRuntimeEvidenceTicket {{ TicketId = [REDACTED], " +
        $"Generation = {Identity.ConnectionGeneration} }}";
}

public sealed class ProductionRdCoreConnectionRuntime :
    IRdCoreConnectionRuntime,
    IAsyncDisposable
{
    private static readonly RdCorePresentationCapabilities
        VerifiedPresentation = new(
            false,
            true,
            RdCorePresentationCapabilities.VerifiedEvidenceCode);

    private readonly IRdCoreConnectionLeaseFactory leaseFactory;
    private readonly IRdpDvcRuntimeEvidenceSource evidenceSource;
    private readonly IRdpDvcLocalCarrier? localCarrier;
    private readonly IConnectionGenerationStore generationStore;
    private readonly TimeSpan evidenceTimeout;
    private readonly ConcurrentDictionary<string, OwnedConnection> leases =
        new(StringComparer.Ordinal);

    public ProductionRdCoreConnectionRuntime(
        IRdCoreConnectionLeaseFactory leaseFactory,
        IRdpDvcRuntimeEvidenceSource evidenceSource,
        TimeSpan? evidenceTimeout = null,
        IRdpDvcLocalCarrier? localCarrier = null,
        IConnectionGenerationStore? generationStore = null)
    {
        this.leaseFactory = leaseFactory;
        this.evidenceSource = evidenceSource;
        this.localCarrier = localCarrier;
        this.generationStore = generationStore ??
            new InMemoryConnectionGenerationStore();
        this.evidenceTimeout = evidenceTimeout ?? TimeSpan.FromSeconds(30);
        if (this.evidenceTimeout <= TimeSpan.Zero ||
            this.evidenceTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(
                nameof(evidenceTimeout));
    }

    public async Task<RdCoreConnectionRuntimeResult> ConnectAsync(
        RdCoreConnectionStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!evidenceSource.IsConfigured)
            throw new ConnectionHostOperationException(
                "CONNECTION_HOST_DVC_EVIDENCE_SOURCE_UNAVAILABLE",
                "Authenticated DVC evidence is not configured.");
        var generation = await generationStore.ReserveAsync(
                request.ConnectionId,
                cancellationToken)
            .ConfigureAwait(false);
        var runtimeId = Guid.NewGuid().ToString("N");
        if (string.IsNullOrWhiteSpace(request.DvcEvidenceReference))
            throw new ConnectionHostOperationException(
                "CONNECTION_HOST_DVC_EVIDENCE_REFERENCE_REQUIRED",
                "An opaque DVC evidence reference is required.");
        var ticket = await evidenceSource.RegisterExpectedAsync(
                request.DvcEvidenceReference,
                request.ConnectionId,
                runtimeId,
                generation,
                cancellationToken)
            .ConfigureAwait(false);
        IRdCoreConnectionLeaseHandle? lease = null;
        IRdpDvcLocalCarrierLease? carrier = null;
        try
        {
            lease = await leaseFactory.CreateAsync(
                    request,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await evidenceSource.CancelAsync(ticket).ConfigureAwait(false);
            throw;
        }
        if (lease is null)
        {
            await evidenceSource.CancelAsync(ticket).ConfigureAwait(false);
            throw new InvalidOperationException(
                "The RDCore lease factory returned no lease.");
        }
        var eventLease = lease;
        var ticketReleased = false;
        var runtimeEvents = new List<RdCoreDvcEvidenceEvent>(2);
        var connected = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var plugins = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        void OnConnected(object? sender, EventArgs args)
        {
            lock (runtimeEvents)
                runtimeEvents.Add(RdCoreDvcEvidenceEvent.RdCoreConnected);
            connected.TrySetResult();
        }
        void OnPlugins(object? sender, EventArgs args)
        {
            lock (runtimeEvents)
                runtimeEvents.Add(RdCoreDvcEvidenceEvent.WtsPluginsLoaded);
            plugins.TrySetResult();
        }

        lease.Connected += OnConnected;
        lease.WtsPluginsLoaded += OnPlugins;
        try
        {
            using var timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken);
            timeout.CancelAfter(evidenceTimeout);
            await lease.ConnectAsync(timeout.Token).ConfigureAwait(false);
            RdpDvcRuntimeEvidenceBatch external;
            if (lease is IExternallyProvenRdCoreConnectionLeaseHandle
                externallyProven)
            {
                var evidenceTask = evidenceSource.WaitForEvidenceAsync(
                        ticket,
                        timeout.Token);
                if (localCarrier is not null)
                    carrier = await localCarrier.ConnectAsync(
                            ticket,
                            timeout.Token)
                        .ConfigureAwait(false);
                var completed = await Task.WhenAny(
                        evidenceTask,
                        externallyProven.ConnectionFailure)
                    .ConfigureAwait(false);
                if (completed == externallyProven.ConnectionFailure)
                    await externallyProven.ConnectionFailure
                        .ConfigureAwait(false);
                external = await evidenceTask.ConfigureAwait(false);
            }
            else
            {
                await connected.Task.WaitAsync(timeout.Token)
                    .ConfigureAwait(false);
                await plugins.Task.WaitAsync(timeout.Token)
                    .ConfigureAwait(false);
                external = await evidenceSource.WaitForEvidenceAsync(
                        ticket,
                        timeout.Token)
                    .ConfigureAwait(false);
            }
            ValidateExternalEvidence(
                request.ConnectionId,
                runtimeId,
                generation,
                external,
                ticket.Identity.Route);
            var evidence = new List<RdCoreRuntimeEvidence>(7)
            {
                new(RdCoreDvcEvidenceEvent.RdCoreConnected),
                new(RdCoreDvcEvidenceEvent.WtsPluginsLoaded)
            };
            evidence.AddRange(external.Evidence);
            ValidateCompleteEvidence(request.Registration, generation, evidence);
            if (lease is IExternallyProvenRdCoreConnectionLeaseHandle
                externallyValidated)
                externallyValidated.ConfirmConnected();
            lock (runtimeEvents)
                ValidateRuntimeEvents(runtimeEvents);
            await evidenceSource.CancelAsync(ticket).ConfigureAwait(false);
            ticketReleased = true;
            var result = new RdCoreConnectionRuntimeResult(
                runtimeId,
                generation,
                evidence,
                lease is IRdCorePresentationLeaseHandle
                    ? VerifiedPresentation
                    : new(
                        false,
                        false,
                        "RDCORE_SAME_CONNECTION_PRESENTATION_UNPROVEN"));
            var ownedConnection = new OwnedConnection(
                lease,
                carrier,
                result);
            if (!leases.TryAdd(runtimeId, ownedConnection))
                throw new InvalidOperationException(
                    "The RDCore runtime connection ID collided.");
            if (carrier is not null)
                _ = RemoveOnCarrierCompletionAsync(
                    runtimeId,
                    generation,
                    carrier);
            carrier = null;
            if (lease is IExternallyProvenRdCoreConnectionLeaseHandle
                externallyProvenLease)
                _ = RemoveOnExternalFailureAsync(
                    runtimeId,
                    generation,
                    externallyProvenLease);
            lease = null;
            return result;
        }
        finally
        {
            eventLease.Connected -= OnConnected;
            eventLease.WtsPluginsLoaded -= OnPlugins;
            if (lease is not null)
            {
                try
                {
                    if (lease.State == RdCoreConnectionState.Connected)
                        await lease.DisconnectAsync(CancellationToken.None)
                            .ConfigureAwait(false);
                }
                finally
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                }
            }
            if (carrier is not null)
                await carrier.DisposeAsync().ConfigureAwait(false);
            if (!ticketReleased)
                await evidenceSource.CancelAsync(ticket).ConfigureAwait(false);
        }
    }

    public Task<RdCoreConnectionRuntimeResult?> ReconcileAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (leases.TryGetValue(runtimeConnectionId, out var owned) &&
            owned.Result.ConnectionGeneration == connectionGeneration &&
            owned.Lease.State == RdCoreConnectionState.Connected &&
            (owned.Lease is not
                IExternallyProvenRdCoreConnectionLeaseHandle external ||
             !external.ConnectionFailure.IsCompleted))
            return Task.FromResult<RdCoreConnectionRuntimeResult?>(
                owned.Result);
        return Task.FromResult<RdCoreConnectionRuntimeResult?>(null);
    }

    public Task<RdCorePresentationProof> ViewExistingAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken)
        => Task.FromException<RdCorePresentationProof>(
            new ConnectionHostOperationException(
                "CONNECTION_HOST_VIEW_ONLY_PRESENTATION_UNPROVEN",
                "A non-interactive same-connection view is not proven."));

    public async Task<RdCorePresentationProof> TakeControlAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken)
    {
        var owned = PresentationLease(
            runtimeConnectionId,
            connectionGeneration);
        await owned.ShowAsync(cancellationToken).ConfigureAwait(false);
        return new(
            runtimeConnectionId,
            connectionGeneration,
            RdCorePresentationCapabilities.VerifiedEvidenceCode);
    }

    public async Task ReleaseControlAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken)
    {
        var owned = PresentationLease(
            runtimeConnectionId,
            connectionGeneration);
        await owned.HideAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DisconnectAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken)
    {
        if (!leases.TryGetValue(runtimeConnectionId, out var owned) ||
            owned.Result.ConnectionGeneration != connectionGeneration)
            throw new InvalidOperationException(
                "The RDCore runtime connection generation is stale.");
        if (!leases.TryRemove(
                new KeyValuePair<string, OwnedConnection>(
                    runtimeConnectionId,
                    owned)))
            throw new InvalidOperationException(
                "The RDCore runtime connection changed.");
        try
        {
            await owned.Lease.DisconnectAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            if (owned.Carrier is not null)
                await owned.Carrier.DisposeAsync().ConfigureAwait(false);
            await owned.Lease.DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var pair in leases.ToArray())
        {
            if (!leases.TryRemove(pair))
                continue;
            try
            {
                if (pair.Value.Lease.State ==
                    RdCoreConnectionState.Connected)
                    await pair.Value.Lease.DisconnectAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false);
            }
            finally
            {
                if (pair.Value.Carrier is not null)
                    await pair.Value.Carrier.DisposeAsync()
                        .ConfigureAwait(false);
                await pair.Value.Lease.DisposeAsync().ConfigureAwait(false);
            }
        }
        if (evidenceSource is IAsyncDisposable asyncDisposable)
            await asyncDisposable.DisposeAsync().ConfigureAwait(false);
        else if (evidenceSource is IDisposable disposable)
            disposable.Dispose();
    }

    private static void ValidateExternalEvidence(
        string connectionId,
        string runtimeConnectionId,
        long generation,
        RdpDvcRuntimeEvidenceBatch evidence,
        RdpDvcEvidenceRoute preauthorizedRoute)
    {
        if (!string.Equals(
                evidence.ConnectionId,
                connectionId,
                StringComparison.Ordinal) ||
            !string.Equals(
                evidence.RuntimeConnectionId,
                runtimeConnectionId,
                StringComparison.Ordinal) ||
            evidence.ConnectionGeneration != generation ||
            evidence.Evidence.Count != 5 ||
            evidence.AuthenticatedRoute is not { WtsSessionId: > 0 }
                authenticatedRoute ||
            !preauthorizedRoute.MatchesAuthenticatedRoute(
                authenticatedRoute))
            throw new InvalidDataException(
                "DVC evidence did not match the RDCore connection.");
    }

    private static void ValidateCompleteEvidence(
        DvcPluginRegistrationStatus registration,
        long generation,
        IReadOnlyList<RdCoreRuntimeEvidence> evidence)
    {
        var sequence = new RdCoreDvcEvidenceSequence(generation);
        foreach (var item in evidence)
        {
            sequence.Record(
                item.Event,
                item.PluginAddInName,
                item.PluginClsid,
                item.ChannelName);
        }

        var result = RdCoreDvcContract.ValidateEvidence(
            new(true, true, registration),
            sequence);
        if (!result.Accepted ||
            !string.Equals(
                result.Code,
                RdCoreDvcContract.EvidenceVerifiedCode,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "The complete RDCore/DVC evidence chain was not verified.");
    }

    private static void ValidateRuntimeEvents(
        IReadOnlyList<RdCoreDvcEvidenceEvent> events)
    {
        if (!events.SequenceEqual(
                new[]
                {
                    RdCoreDvcEvidenceEvent.RdCoreConnected,
                    RdCoreDvcEvidenceEvent.WtsPluginsLoaded
                }))
            throw new InvalidDataException(
                "RDCore runtime evidence arrived out of order.");
    }

    private async Task RemoveOnCarrierCompletionAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        IRdpDvcLocalCarrierLease carrier)
    {
        try
        {
            await carrier.Completion.ConfigureAwait(false);
        }
        catch (Exception exception)
            when (IsExpectedConnectionTermination(exception))
        {
        }
        catch (Exception exception)
        {
            System.Diagnostics.Trace.TraceError(
                "DVC reconnect supervisor failed: {0}; 0x{1:X8}.",
                exception.GetType().Name,
                exception.HResult);
        }
        await RemoveOwnedConnectionAsync(
                runtimeConnectionId,
                connectionGeneration,
                expectedLease: null,
                carrier)
            .ConfigureAwait(false);
    }

    private async Task RemoveOnExternalFailureAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        IExternallyProvenRdCoreConnectionLeaseHandle lease)
    {
        try
        {
            await lease.ConnectionFailure.ConfigureAwait(false);
            return;
        }
        catch (Exception exception)
            when (IsExpectedConnectionTermination(exception))
        {
        }
        catch (Exception exception)
        {
            System.Diagnostics.Trace.TraceError(
                "External RDCore lease failed unexpectedly: {0}; 0x{1:X8}.",
                exception.GetType().Name,
                exception.HResult);
        }
        await RemoveOwnedConnectionAsync(
                runtimeConnectionId,
                connectionGeneration,
                lease,
                expectedCarrier: null)
            .ConfigureAwait(false);
    }

    private async Task RemoveOwnedConnectionAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        IRdCoreConnectionLeaseHandle? expectedLease,
        IRdpDvcLocalCarrierLease? expectedCarrier)
    {
        if (!leases.TryGetValue(runtimeConnectionId, out var owned) ||
            owned.Result.ConnectionGeneration != connectionGeneration ||
            expectedLease is not null &&
            !ReferenceEquals(owned.Lease, expectedLease) ||
            expectedCarrier is not null &&
            !ReferenceEquals(owned.Carrier, expectedCarrier) ||
            !leases.TryRemove(
                new KeyValuePair<string, OwnedConnection>(
                    runtimeConnectionId,
                    owned)))
            return;
        try
        {
            if (owned.Carrier is not null)
                await owned.Carrier.DisposeAsync().ConfigureAwait(false);
            if (owned.Lease.State == RdCoreConnectionState.Connected)
                await owned.Lease.DisconnectAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            await owned.Lease.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            System.Diagnostics.Trace.TraceError(
                "RDCore connection cleanup failed: {0}; 0x{1:X8}.",
                exception.GetType().Name,
                exception.HResult);
        }
    }

    private static bool IsExpectedConnectionTermination(
        Exception exception) =>
        exception is
            OperationCanceledException or
            EndOfStreamException or
            IOException or
            TimeoutException or
            InvalidDataException or
            InvalidOperationException or
            RdpDvcProtocolException or
            TransportProtocolException or
            CryptographicException or
            TransportDisconnectedException or
            TransientTransportException;
    private static ConnectionHostOperationException
        UnsupportedPresentationException() =>
        new(
            "CONNECTION_HOST_SAME_CONNECTION_PRESENTATION_UNPROVEN",
            "RDCore same-connection presentation is not proven.");

    private IRdCorePresentationLeaseHandle PresentationLease(
        string runtimeConnectionId,
        long connectionGeneration)
    {
        if (!leases.TryGetValue(runtimeConnectionId, out var owned) ||
            owned.Result.ConnectionGeneration != connectionGeneration ||
            owned.Lease.State != RdCoreConnectionState.Connected)
            throw new InvalidOperationException(
                "The RDCore runtime connection generation is stale.");
        return owned.Lease as IRdCorePresentationLeaseHandle
            ?? throw UnsupportedPresentationException();
    }

    private sealed record OwnedConnection(
        IRdCoreConnectionLeaseHandle Lease,
        IRdpDvcLocalCarrierLease? Carrier,
        RdCoreConnectionRuntimeResult Result);
}
