using System.IO.Pipes;
using System.Security.Cryptography;
using System.Threading.Channels;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Stack.Local;
using Steward.Transport;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class ProtectedFileRdpDvcLocalCarrierTests : IDisposable
{
    private readonly string root = Path.Combine(AppContext.BaseDirectory,
        "protected-carrier-composition", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task ConnectAsync_installs_attempt_factory_and_reconnects_after_clean_eof()
    {
        Directory.CreateDirectory(root);
        using var controlKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var dvcKey = RandomNumberGenerator.GetBytes(32);
        var evidenceKey = RandomNumberGenerator.GetBytes(32);
        var dvcKeyFile = Path.Combine(root, "dvc.key");
        var evidenceKeyFile = Path.Combine(root, "evidence.key");
        await File.WriteAllBytesAsync(dvcKeyFile, dvcKey);
        CurrentUserProtectedDataFile.Write(evidenceKeyFile,
            AuthenticatedRdpDvcEvidencePublisher.KeyFilePurpose, evidenceKey);
        var route = new RdpDvcEvidenceRoute(Guid.NewGuid(), Guid.NewGuid(),
            Guid.NewGuid(), 0, Guid.NewGuid(), ProtocolVersion: 2);
        var ticket = new RdpDvcRuntimeEvidenceTicket(Guid.NewGuid(),
            new("carrier-composition-reference", "carrier-composition",
                "runtime-composition", 1, route));
        var connector = new AuthenticatedAttemptConnector(route, dvcKey);
        var evidencePipe = "Steward.Evidence.Carrier." +
            Guid.NewGuid().ToString("N");
        await using var evidence = new EvidenceCaptureServer(evidencePipe,
            evidenceKey, 2);
        var controlPipe = "Steward.Control.Carrier." +
            Guid.NewGuid().ToString("N");
        var routeStatePath = Path.Combine(root, "routes.db");
        var highWaterPath = Path.Combine(root, "high-water.db");
        var control = RunControlAsync(controlPipe, connector, controlKey,
            nodeKey, Path.Combine(root, "control.pk8.pem"), 2);
        var carrier = new ProtectedFileRdpDvcLocalCarrier(dvcKeyFile,
            "injected-connector", evidencePipe, evidenceKeyFile,
            new SqliteConnectionReconnectHighWaterStore(highWaterPath),
            new RdpDvcOpaqueControlPipeBridge(
                new(controlPipe, TimeSpan.FromSeconds(5), 4096),
                new SqliteConnectionMetadataStore(routeStatePath)), connector);

        await using var lease = await carrier.ConnectAsync(ticket,
            CancellationToken.None);
        var first = await connector.WaitForAttemptAsync(1);
        await first.CloseNodeAsync();
        await first.HostDisposed.WaitAsync(TimeSpan.FromSeconds(5));
        var second = await connector.WaitForAttemptAsync(2);
        var publications = await evidence.Completion.WaitAsync(
            TimeSpan.FromSeconds(5));
        await first.SessionReady.WaitAsync(TimeSpan.FromSeconds(5));
        await second.SessionReady.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.All(connector.Tickets,
            value => Assert.Equal(2, value.Route.ProtocolVersion));
        Assert.Equal([1L, 2L], connector.Identities
            .Select(value => value.ReconnectGeneration));
        Assert.All(connector.HostAuthentications,
            value => Assert.Equal(64, value.TranscriptHash.Length));
        Assert.All(connector.NodeSessions,
            value => Assert.True(value.Session.Security.IsSecure));
        Assert.Equal([
                RdpDvcEvidencePublicationEvent.DvcHmacAuthenticated,
                RdpDvcEvidencePublicationEvent.SecurePeerAuthenticated],
            publications.Select(value => value.Event));
        Assert.All(publications, value => Assert.Equal(
            ticket.Identity.ConnectionId, value.Ticket?.ConnectionId));
        Assert.Equal(2L, await ReadScalarAsync(highWaterPath,
            "SELECT MAX(generation) FROM reconnect_high_water"));
        Assert.Equal(1L, await ReadScalarAsync(routeStatePath,
            "SELECT COUNT(*) FROM connection_routes WHERE active=1"));

        await second.CloseNodeAsync();
        await second.HostDisposed.WaitAsync(TimeSpan.FromSeconds(5));
        await lease.DisposeAsync();
        await control.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0L, await ReadScalarAsync(routeStatePath,
            "SELECT COUNT(*) FROM connection_routes WHERE active=1"));
        Assert.Equal(2, connector.DisposedConnections);
        Assert.All(connector.NodeSessions,
            value => Assert.True(value.IsDisposed));
        CryptographicOperations.ZeroMemory(dvcKey);
        CryptographicOperations.ZeroMemory(evidenceKey);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(root)) Directory.Delete(root, true);
    }

    private static async Task RunControlAsync(string pipeName,
        AuthenticatedAttemptConnector connector, ECDsa controlKey,
        ECDsa nodeKey, string controlKeyFile, int expectedAttempts)
    {
        await File.WriteAllTextAsync(controlKeyFile,
            controlKey.ExportPkcs8PrivateKeyPem());
        var nodeKeyFile = controlKeyFile + ".node.spki.pem";
        await File.WriteAllTextAsync(nodeKeyFile,
            nodeKey.ExportSubjectPublicKeyInfoPem());
        for (var index = 0; index < expectedAttempts; index++)
        {
            await using var pipe = new NamedPipeServerStream(pipeName,
                PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                64 * 1024, 64 * 1024);
            await pipe.WaitForConnectionAsync();
            var attachment = Assert.IsType<ReconnectCarrierAttachment>(
                await RdpDvcControlCarrierAttachmentCodec.ReadAsync(pipe));
            var attempt = await connector.WaitForAttemptAsync(index + 1);
            Assert.Equal(attempt.Identity.AttemptId, attachment.AttemptId);
            await using var responses = new NamedPipeClientStream(".",
                ReconnectCarrierAttachmentCodec.AcknowledgementPipeName(
                    pipeName, attachment.AttemptId), PipeDirection.Out,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await responses.ConnectAsync();
            await ReconnectCarrierControlMessageCodec.WriteAsync(responses,
                ReconnectCarrierControlMessage.RelayReady(
                    attachment.AttemptId));
            var hello = Hello(attachment);
            var endpoint = new NodeEndpointRegistration(attachment.HostId,
                attachment.NodeIncarnationId, PoolId.New(),
                ExtensionMetadataDto.Create("direct-websocket", "1.0",
                    new { attachment.SessionId }), "node",
                nodeKeyFile,
                new ResourceRequirements(1), [], [], DateTimeOffset.UtcNow);
            var accepting = new ControlReconnectSessionTerminator("control",
                controlKeyFile, TimeSpan.FromSeconds(5)).AcceptAsync(pipe,
                    attachment, endpoint, hello, CancellationToken.None);
            var connecting = attempt.ConnectNodeAsync(nodeKey, controlKey,
                hello);
            var sessions = await Task.WhenAll(accepting, connecting)
                .WaitAsync(TimeSpan.FromSeconds(5));
            attempt.SetSessions(sessions[0], sessions[1]);
            await ReconnectCarrierControlMessageCodec.WriteAsync(responses,
                ReconnectCarrierControlMessage.SecureSessionAuthenticated(
                    attachment.AttemptId));
            await attempt.HostDisposed.WaitAsync(TimeSpan.FromSeconds(10));
            await sessions[0].DisposeAsync();
        }
    }

    private static SessionHello Hello(ReconnectCarrierAttachment value) =>
        new(value.SessionId, value.NodeIncarnationId, 1, 0,
            new HashSet<string>(["rdp-dvc-reconnect-v2"]),
            new HashSet<string>(["rdp-dvc-reconnect-v2"]),
            new Dictionary<StreamKind, long>(), new(64 * 1024, 8),
            value.Binding);

    private static async Task<long> ReadScalarAsync(string path, string sql)
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(
            $"Data Source={path}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    private sealed class AuthenticatedAttemptConnector(
        RdpDvcEvidenceRoute route, byte[] expectedSecret) :
        IRdpDvcLocalCarrierV2Connector
    {
        private readonly Channel<NodeAttempt> changed =
            Channel.CreateUnbounded<NodeAttempt>();
        private readonly List<NodeAttempt> attempts = [];
        private int generation;
        private int disposedConnections;

        public IReadOnlyList<RdpDvcEvidenceTicketIdentity> Tickets =>
            attempts.Select(value => value.Ticket).ToArray();
        public IReadOnlyList<RdpDvcCarrierAttemptIdentity> Identities =>
            attempts.Select(value => value.Identity).ToArray();
        public IReadOnlyList<RdpDvcCarrierAuthenticationV2>
            HostAuthentications => attempts.Select(value =>
                value.HostAuthentication).ToArray();
        public IReadOnlyList<TrackedTransportConnection> NodeSessions =>
            attempts.Select(value => value.NodeSession).ToArray();
        public int DisposedConnections => Volatile.Read(
            ref disposedConnections);

        public async Task<IRdpDvcLocalCarrierV2Connection> ConnectAsync(
            RdpDvcEvidenceTicketIdentity ticket,
            ReadOnlyMemory<byte> carrierSecret,
            CancellationToken cancellationToken)
        {
            Assert.Equal(expectedSecret, carrierSecret.ToArray());
            Assert.Equal(route, ticket.Route);
            var identity = new RdpDvcCarrierAttemptIdentity(route.SessionId,
                new HostId(route.HostId),
                new NodeIncarnationId(route.NodeIncarnationId),
                Interlocked.Increment(ref generation), Guid.NewGuid(), 42)
            { RouteId = route.HostId };
            var (nodeWire, hostWire) = CarrierWire.Create(42);
            var nodeTask = RdpDvcCarrierHandshakeV2.InitiateAsync(nodeWire,
                identity, carrierSecret, TimeSpan.FromSeconds(2),
                cancellationToken).AsTask();
            var hostTask = RdpDvcCarrierHandshakeV2.RespondAsync(hostWire,
                identity, carrierSecret, TimeSpan.FromSeconds(2),
                cancellationToken).AsTask();
            await Task.WhenAll(nodeTask, hostTask);
            var attempt = new NodeAttempt(ticket, identity, await nodeTask);
            attempts.Add(attempt);
            await changed.Writer.WriteAsync(attempt, cancellationToken);
            return new TestConnection(identity, await hostTask, attempt,
                () => Interlocked.Increment(ref disposedConnections));
        }

        public async Task<NodeAttempt> WaitForAttemptAsync(int count)
        {
            using var timeout = new CancellationTokenSource(
                TimeSpan.FromSeconds(5));
            while (attempts.Count < count)
                _ = await changed.Reader.ReadAsync(timeout.Token);
            return attempts[count - 1];
        }
    }

    private sealed class TestConnection(
        RdpDvcCarrierAttemptIdentity identity,
        RdpDvcConnectedStreamV2 carrier,
        NodeAttempt attempt,
        Action onDisposed) : IRdpDvcLocalCarrierV2Connection
    {
        private int disposed;
        public RdpDvcCarrierAttemptIdentity Identity { get; } = identity;
        public Stream Stream => carrier.Stream;
        public RdpDvcCarrierAuthenticationV2 Authentication =>
            carrier.Authentication;
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            await carrier.DisposeAsync();
            onDisposed();
            attempt.MarkHostDisposed();
        }
    }

    private sealed class NodeAttempt(
        RdpDvcEvidenceTicketIdentity ticket,
        RdpDvcCarrierAttemptIdentity identity,
        RdpDvcConnectedStreamV2 carrier)
    {
        private SecureStreamCarrier? secure;
        private TrackedTransportConnection? nodeSession;
        private readonly TaskCompletionSource hostDisposed = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource sessionReady = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public RdpDvcEvidenceTicketIdentity Ticket { get; } = ticket;
        public RdpDvcCarrierAttemptIdentity Identity { get; } = identity;
        public RdpDvcCarrierAuthenticationV2 HostAuthentication =>
            carrier.Authentication;
        public TrackedTransportConnection NodeSession => nodeSession ??
            throw new InvalidOperationException("Node session unavailable.");
        public Task HostDisposed => hostDisposed.Task;
        public Task SessionReady => sessionReady.Task;

        public async Task<ITransportConnection> ConnectNodeAsync(ECDsa nodeKey,
            ECDsa controlKey, SessionHello hello)
        {
            secure = new SecureStreamCarrier(new SingleStreamConnector(
                carrier.Stream), new(TransportEndpointRole.Node,
                    new EcdsaEndpointSigningKey("node",
                        ECDsa.Create(nodeKey.ExportParameters(true))),
                    new("control", controlKey.ExportSubjectPublicKeyInfo()),
                    HandshakeTimeout: TimeSpan.FromSeconds(2)));
            return await secure.ConnectAsync(hello);
        }

        public void SetSessions(ITransportConnection control,
            ITransportConnection node)
        {
            nodeSession = new TrackedTransportConnection(node);
            sessionReady.TrySetResult();
        }

        public async Task CloseNodeAsync()
        {
            if (nodeSession is not null) await nodeSession.DisposeAsync();
            if (secure is not null) await secure.DisposeAsync();
            await carrier.DisposeAsync();
        }

        public void MarkHostDisposed() => hostDisposed.TrySetResult();
    }

    private sealed class TrackedTransportConnection(
        ITransportConnection inner) : ITransportConnection
    {
        private int disposed;
        public NegotiatedSession Session => inner.Session;
        public bool IsDisposed => Volatile.Read(ref disposed) != 0;
        public ValueTask SendAsync(TransportFrame frame,
            CancellationToken cancellationToken = default) =>
            inner.SendAsync(frame, cancellationToken);
        public bool TrySend(TransportFrame frame) => inner.TrySend(frame);
        public IAsyncEnumerable<TransportFrame> ReceiveAsync(
            CancellationToken cancellationToken = default) =>
            inner.ReceiveAsync(cancellationToken);
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
                await inner.DisposeAsync();
        }
    }

    private sealed class EvidenceCaptureServer : IAsyncDisposable
    {
        private readonly CancellationTokenSource stop = new();
        private readonly Task<IReadOnlyList<RdpDvcEvidencePublication>> server;

        public EvidenceCaptureServer(string pipeName, byte[] key, int count) =>
            server = RunAsync(pipeName, key, count, stop.Token);
        public Task<IReadOnlyList<RdpDvcEvidencePublication>> Completion =>
            server;

        public async ValueTask DisposeAsync()
        {
            stop.Cancel();
            try { await server; }
            catch (OperationCanceledException) { }
            stop.Dispose();
        }

        private static async Task<IReadOnlyList<RdpDvcEvidencePublication>>
            RunAsync(string pipeName, byte[] key, int count,
                CancellationToken cancellationToken)
        {
            var result = new List<RdpDvcEvidencePublication>();
            while (result.Count < count)
            {
                await using var pipe = new NamedPipeServerStream(pipeName,
                    PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await pipe.WaitForConnectionAsync(cancellationToken);
                var frame = await RdpDvcEvidenceIpcProtocol.ReadFrameAsync(
                    pipe, cancellationToken);
                result.Add(RdpDvcEvidenceIpcProtocol.Decode(frame, key));
                await pipe.WriteAsync(new byte[] { 1 }, cancellationToken);
                await pipe.FlushAsync(cancellationToken);
            }
            return result;
        }
    }

    private sealed class SingleStreamConnector(Stream stream) :
        ITransportStreamConnector
    {
        private int used;
        public ValueTask<Stream> ConnectStreamAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref used, 1) != 0)
                throw new InvalidOperationException("The stream is single-use.");
            return ValueTask.FromResult(stream);
        }
    }

    private sealed class CarrierWire(Channel<byte[]> incoming,
        Channel<byte[]> outgoing) : IRdpDvcWireChannel
    {
        public static (RdpDvcWireConnection Node,
            RdpDvcWireConnection Host) Create(int sessionId)
        {
            var nodeToHost = Channel.CreateUnbounded<byte[]>();
            var hostToNode = Channel.CreateUnbounded<byte[]>();
            return (new(new CarrierWire(hostToNode, nodeToHost), sessionId),
                new(new CarrierWire(nodeToHost, hostToNode), null));
        }

        public ValueTask WritePduAsync(ReadOnlyMemory<byte> pdu,
            CancellationToken cancellationToken = default) =>
            outgoing.Writer.WriteAsync(pdu.ToArray(), cancellationToken);
        public ValueTask<byte[]> ReadPduAsync(
            CancellationToken cancellationToken = default) =>
            incoming.Reader.ReadAsync(cancellationToken);
        public ValueTask DisposeAsync()
        {
            outgoing.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }
}

