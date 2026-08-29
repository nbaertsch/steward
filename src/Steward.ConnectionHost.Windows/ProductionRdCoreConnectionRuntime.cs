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

public interface IRdpDvcLocalCarrier
{
    Task<IAsyncDisposable> ConnectAsync(
        RdpDvcRuntimeEvidenceTicket ticket,
        CancellationToken cancellationToken);
}

public sealed class ProtectedFileRdpDvcLocalCarrier(
    string dvcKeyFile,
    string controlSigningPrivateKeyFile,
    string nodeSigningPublicKeyFile,
    string controlIdentity,
    string nodeIdentity,
    string evidencePipeName,
    string evidenceKeyFile,
    Action<string>? diagnosticSink = null) :
    IRdpDvcLocalCarrier
{
    public async Task<IAsyncDisposable> ConnectAsync(
        RdpDvcRuntimeEvidenceTicket ticket,
        CancellationToken cancellationToken)
    {
        diagnosticSink?.Invoke("key-read");
        var key = await File.ReadAllBytesAsync(
                Path.GetFullPath(dvcKeyFile),
                cancellationToken)
            .ConfigureAwait(false);
        AuthenticatedRdpDvcEvidencePublisher? publisher = null;
        RdpDvcEvidencePublishingConnectionAcceptor? acceptor = null;
        try
        {
            var route = ticket.Identity.Route;
            var options = new RdpDvcAuthenticationOptions(
                new(
                    route.SessionId,
                    route.HostId,
                    route.NodeIncarnationId,
                    route.IsWtsWildcard ? null : route.WtsSessionId,
                    route.ConnectionNonce),
                key);
            var source = new RdpDvcNamedPipeWireChannelSource(
                options,
                connectTimeout: TimeSpan.FromMinutes(5));
            var controlKey = ECDsa.Create();
            controlKey.ImportFromPem(
                await File.ReadAllTextAsync(
                        Path.GetFullPath(controlSigningPrivateKeyFile),
                        cancellationToken)
                    .ConfigureAwait(false));
            using var nodeKey = ECDsa.Create();
            nodeKey.ImportFromPem(
                await File.ReadAllTextAsync(
                        Path.GetFullPath(nodeSigningPublicKeyFile),
                        cancellationToken)
                    .ConfigureAwait(false));
            publisher =
                AuthenticatedRdpDvcEvidencePublisher.FromProtectedFile(
                    evidencePipeName,
                    evidenceKeyFile);
            acceptor = new(
                source,
                options,
                new(
                    TransportEndpointRole.Control,
                    new EcdsaEndpointSigningKey(
                        controlIdentity,
                        controlKey),
                    new(
                        nodeIdentity,
                        nodeKey.ExportSubjectPublicKeyInfo()),
                    HandshakeTimeout: TimeSpan.FromMinutes(5),
                    OperationTimeout: TimeSpan.FromMinutes(5)),
                publisher,
                ticket.Identity);
            diagnosticSink?.Invoke("pipe-open-start");
            var connection = await acceptor.AcceptAsync(
                    CreateHello(route),
                    cancellationToken)
                .ConfigureAwait(false);
            diagnosticSink?.Invoke("secure-accept-complete");
            return new LocalCarrierLease(
                connection,
                acceptor,
                publisher);
        }
        catch
        {
            if (acceptor is not null)
                await acceptor.DisposeAsync().ConfigureAwait(false);
            if (publisher is not null)
                await publisher.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static SessionHello CreateHello(RdpDvcEvidenceRoute route) =>
        new(
            route.SessionId,
            new NodeIncarnationId(route.NodeIncarnationId),
            1,
            0,
            new HashSet<string>(StringComparer.Ordinal)
            {
                "rdp-dvc-secure",
                "orchestration-v1",
                "reconciliation-v1",
                "resume-cursors-v1"
            },
            new HashSet<string>(StringComparer.Ordinal),
            new Dictionary<StreamKind, long>(),
            new(64 * 1024, 8));

    private sealed class LocalCarrierLease(
        ITransportConnection connection,
        RdpDvcEvidencePublishingConnectionAcceptor acceptor,
        AuthenticatedRdpDvcEvidencePublisher publisher) :
        IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            await acceptor.DisposeAsync().ConfigureAwait(false);
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
    private readonly TimeSpan evidenceTimeout;
    private readonly ConcurrentDictionary<string, OwnedConnection> leases =
        new(StringComparer.Ordinal);
    private long nextGeneration = DateTimeOffset.UtcNow.UtcTicks;

    public ProductionRdCoreConnectionRuntime(
        IRdCoreConnectionLeaseFactory leaseFactory,
        IRdpDvcRuntimeEvidenceSource evidenceSource,
        TimeSpan? evidenceTimeout = null,
        IRdpDvcLocalCarrier? localCarrier = null)
    {
        this.leaseFactory = leaseFactory;
        this.evidenceSource = evidenceSource;
        this.localCarrier = localCarrier;
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
        var generation = Interlocked.Increment(ref nextGeneration);
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
        IAsyncDisposable? carrier = null;
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
                externallyProven.ConfirmConnected();
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
            lock (runtimeEvents)
                ValidateRuntimeEvents(runtimeEvents);
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
            if (!leases.TryAdd(runtimeId, new(lease, carrier, result)))
                throw new InvalidOperationException(
                    "The RDCore runtime connection ID collided.");
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
            !preauthorizedRoute.HasSamePreauthorizedBase(
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
        catch
        {
        }
        if (!leases.TryGetValue(runtimeConnectionId, out var owned) ||
            owned.Result.ConnectionGeneration != connectionGeneration ||
            !ReferenceEquals(owned.Lease, lease) ||
            !leases.TryRemove(
                new KeyValuePair<string, OwnedConnection>(
                    runtimeConnectionId,
                    owned)))
            return;
        try
        {
            if (owned.Carrier is not null)
                await owned.Carrier.DisposeAsync().ConfigureAwait(false);
            await lease.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            System.Diagnostics.Trace.TraceError(
                "External RDCore lease cleanup failed: {0}; 0x{1:X8}.",
                exception.GetType().Name,
                exception.HResult);
        }
    }

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
        IAsyncDisposable? Carrier,
        RdCoreConnectionRuntimeResult Result);
}
