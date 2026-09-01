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

public sealed class RdpDvcOpaqueBridgeCompositionTests : IDisposable
{
    private readonly string root = Path.Combine(
        AppContext.BaseDirectory,
        "opaque-bridge-composition",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Production_supervisor_completes_two_authenticated_generations_and_cleans_state()
    {
        Directory.CreateDirectory(root);
        using var controlKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var endpoint = await CreateEndpointAsync(controlKey, nodeKey);
        var routeStatePath = Path.Combine(root, "bridge-state.db");
        var highWaterPath = Path.Combine(root, "high-water.db");
        var factory = new SignedLifecycleAttemptFactory(
            generation => StartSignedLifecycleAttemptAsync(
                endpoint,
                controlKey,
                nodeKey,
                generation,
                routeStatePath,
                highWaterPath));
        var first = await factory.ConnectConcreteAsync(CancellationToken.None);
        await using var supervisor = new RdpDvcLocalCarrierReconnectSupervisor(
            first,
            factory,
            _ => TimeSpan.FromMilliseconds(1),
            (delay, cancellationToken) => Task.Delay(delay, cancellationToken));

        await first.CloseNodeAsync();
        var second = await factory.WaitForAttemptAsync(2);

        Assert.Equal(
            [
                "1:carrier-hmac",
                "1:signed-ecdh",
                "2:carrier-hmac",
                "2:signed-ecdh"
            ],
            factory.Evidence);
        Assert.Equal(1, first.Binding.ReconnectGeneration);
        Assert.Equal(2, second.Binding.ReconnectGeneration);
        Assert.NotEqual(first.Binding.AttemptId, second.Binding.AttemptId);
        Assert.Equal(2L, await ReadHighWaterAsync(highWaterPath));
        Assert.Equal(1L, await CountActiveRoutesAsync(routeStatePath));
        Assert.Equal(1L, await CountAttachedControlsAsync(routeStatePath));

        await second.CloseNodeAsync();
        await second.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await supervisor.DisposeAsync();

        Assert.Equal(0L, await CountActiveRoutesAsync(routeStatePath));
        Assert.Equal(0L, await CountAttachedControlsAsync(routeStatePath));
        Assert.Equal(2, factory.CommittedGenerations);
    }
    [Fact]
    public async Task Invalid_local_attachment_is_rejected_before_relay()
    {
        Directory.CreateDirectory(root);
        using var controlKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var endpoint = await CreateEndpointAsync(controlKey, nodeKey);
        var identity = Attempt(endpoint) with { HostId = HostId.New() };
        var (nodeCarrier, hostCarrier) = await ConnectCarrierAsync(
            identity,
            RandomNumberGenerator.GetBytes(32));
        await using var nodeCarrierLease = nodeCarrier;
        var attachment = new ReconnectCarrierAttachment(
            identity.SessionId,
            hostCarrier.Authentication.ToTransportBinding());
        var pipeName = "Steward.Control.Invalid." +
            Guid.NewGuid().ToString("N");
        await using var controlPipe = Server(pipeName);
        var bridge = new RdpDvcOpaqueControlPipeBridge(
            new(pipeName, TimeSpan.FromSeconds(2), 4096));
        var attaching = bridge.AttachAsync(
            hostCarrier.Stream,
            attachment,
            new("composition", 1),
            CancellationToken.None);
        await controlPipe.WaitForConnectionAsync();
        var received = await ReconnectCarrierAttachmentCodec.ReadAsync(
            controlPipe);
        Assert.NotEqual(endpoint.Registration.HostId, received.Binding.HostId);
        await using var responses = await ConnectControlResponsesAsync(
            pipeName,
            received.Binding.AttemptId);

        await SendControlResponseAsync(
            responses,
            ReconnectCarrierControlMessage.Failed(
                received.Binding.AttemptId,
                ReconnectCarrierFailure.AttachmentRejected));
        var failure = await Assert.ThrowsAsync<
            ReconnectCarrierControlRejectedException>(() => attaching);
        Assert.Equal(
            ReconnectCarrierFailure.AttachmentRejected,
            failure.Failure);
    }
    [Fact]
    public async Task Remote_signed_handshake_failure_never_authenticates_route()
    {
        Directory.CreateDirectory(root);
        using var controlKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var enrolledNodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var endpoint = await CreateEndpointAsync(controlKey, enrolledNodeKey);
        var identity = Attempt(endpoint);
        var (nodeCarrier, hostCarrier) = await ConnectCarrierAsync(
            identity,
            RandomNumberGenerator.GetBytes(32));
        await using var nodeCarrierLease = nodeCarrier;
        var attachment = new ReconnectCarrierAttachment(
            identity.SessionId,
            hostCarrier.Authentication.ToTransportBinding());
        var pipeName = "Steward.Control.RemoteFailure." +
            Guid.NewGuid().ToString("N");
        await using var controlPipe = Server(pipeName);
        var statePath = Path.Combine(root, "bad-signature-state.db");
        var stateStore = new SqliteConnectionMetadataStore(statePath);
        var bridge = new RdpDvcOpaqueControlPipeBridge(
            new(pipeName, TimeSpan.FromSeconds(2), 4096),
            stateStore);
        var attaching = bridge.AttachAsync(
            hostCarrier.Stream,
            attachment,
            new("composition", 1),
            CancellationToken.None);
        await controlPipe.WaitForConnectionAsync();
        _ = await ReconnectCarrierAttachmentCodec.ReadAsync(controlPipe);
        await using var responses = await ConnectControlResponsesAsync(
            pipeName,
            attachment.Binding.AttemptId);
        await SendControlResponseAsync(
            responses,
            ReconnectCarrierControlMessage.RelayReady(
                attachment.Binding.AttemptId));
        Assert.False(attaching.IsCompleted);
        var hello = Hello(endpoint, attachment);
        var terminator = new ControlReconnectSessionTerminator(
            "control",
            endpoint.ControlPrivateKey,
            TimeSpan.FromSeconds(2));
        var accepting = terminator.AcceptAsync(
            controlPipe,
            attachment,
            endpoint.Registration,
            hello,
            CancellationToken.None);
        await using var attackerCarrier = NodeSecureCarrier(
            nodeCarrier.Stream,
            attackerKey,
            controlKey);
        var attacking = attackerCarrier.ConnectAsync(hello).AsTask();

        await Assert.ThrowsAnyAsync<CryptographicException>(
            () => accepting.WaitAsync(TimeSpan.FromSeconds(5)));
        await SendControlResponseAsync(
            responses,
            ReconnectCarrierControlMessage.Failed(
                attachment.Binding.AttemptId,
                ReconnectCarrierFailure.SessionAuthenticationFailed));
        var failure = await Assert.ThrowsAsync<
            ReconnectCarrierControlRejectedException>(() => attaching);
        Assert.Equal(
            ReconnectCarrierFailure.SessionAuthenticationFailed,
            failure.Failure);
        Assert.Equal(0L, await CountActiveRoutesAsync(statePath));
        Assert.Equal(0L, await CountAttachedControlsAsync(statePath));
        if (attacking.IsCompletedSuccessfully)
            await (await attacking).DisposeAsync();
    }
    [Fact]
    public async Task Sanitized_1_0_23_carrier_routes_opaquely_to_control_signed_ecdh()
    {
        Directory.CreateDirectory(root);
        using var controlKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var endpoint = await CreateEndpointAsync(controlKey, nodeKey);
        var nonce = Guid.NewGuid();
        var (nodeCarrier, hostCarrier) =
            await ConnectRetainedV1CarrierAsync(
                endpoint,
                nonce,
                RandomNumberGenerator.GetBytes(32));
        await using var nodeCarrierLease = nodeCarrier;
        var attachment = new RetainedV1CarrierAttachment(
            endpoint.SessionId,
            endpoint.Registration.HostId,
            endpoint.Registration.NodeIncarnationId,
            hostCarrier.Handshake.RdpSessionId,
            nonce,
            new(
                "1.0.23",
                FiniteNonceStateRetained: true));
        var pipeName = "Steward.Control.RetainedV1." +
            Guid.NewGuid().ToString("N");
        await using var controlPipe = Server(pipeName);
        var bridge = new RdpDvcOpaqueControlPipeBridge(
            new(pipeName, TimeSpan.FromSeconds(5), 4096));
        var attaching = bridge.AttachAsync(
            hostCarrier.Stream,
            attachment,
            new("retained-v1", 1),
            CancellationToken.None);
        await controlPipe.WaitForConnectionAsync();
        var received = await RdpDvcControlCarrierAttachmentCodec.ReadAsync(
            controlPipe);
        Assert.Equal(attachment, Assert.IsType<
            RetainedV1CarrierAttachment>(received));
        await using var responses = await ConnectControlResponsesAsync(
            pipeName,
            attachment.AttemptId);
        await SendControlResponseAsync(
            responses,
            ReconnectCarrierControlMessage.RelayReady(
                attachment.AttemptId));

        var hello = new SessionHello(
            endpoint.SessionId,
            endpoint.Registration.NodeIncarnationId,
            1,
            0,
            new HashSet<string>(["rdp-dvc-secure"]),
            new HashSet<string>(),
            new Dictionary<StreamKind, long>(),
            new(64 * 1024, 8));
        var terminator = new ControlReconnectSessionTerminator(
            "control",
            endpoint.ControlPrivateKey,
            TimeSpan.FromSeconds(5));
        var accepting = terminator.AcceptAsync(
            controlPipe,
            attachment,
            endpoint.Registration,
            hello,
            CancellationToken.None);
        await using var nodeSecureCarrier = NodeSecureCarrier(
            nodeCarrier.Stream,
            nodeKey,
            controlKey);
        var connecting = nodeSecureCarrier.ConnectAsync(hello).AsTask();
        var established = await Task.WhenAll(accepting, connecting)
            .WaitAsync(TimeSpan.FromSeconds(5));
        await using var control = established[0];
        await using var node = established[1];
        await SendControlResponseAsync(
            responses,
            ReconnectCarrierControlMessage
                .SecureSessionAuthenticated(attachment.AttemptId));
        await using var bridgeLease = await attaching.WaitAsync(
            TimeSpan.FromSeconds(2));

        Assert.True(control.Session.Security.IsSecure);
        Assert.Null(control.Session.ReconnectBinding);
        Assert.Equal("node", control.Session.Security.RemoteIdentity);
    }
    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private async Task<SignedLifecycleAttempt>
        StartSignedLifecycleAttemptAsync(
            TestEndpoint endpoint,
            ECDsa controlKey,
            ECDsa nodeKey,
            long reconnectGeneration,
            string routeStatePath,
            string highWaterPath)
    {
        var identity = Attempt(endpoint) with
        {
            ReconnectGeneration = reconnectGeneration,
            AttemptId = Guid.NewGuid()
        };
        var secret = RandomNumberGenerator.GetBytes(32);
        var (nodeCarrier, hostCarrier) = await ConnectCarrierAsync(
            identity,
            secret);
        CryptographicOperations.ZeroMemory(secret);
        var attachment = new ReconnectCarrierAttachment(
            identity.SessionId,
            hostCarrier.Authentication.ToTransportBinding());
        var pipeName = "Steward.Control.Supervisor." +
            Guid.NewGuid().ToString("N");
        var controlPipe = Server(pipeName);
        var stateStore = new SqliteConnectionMetadataStore(routeStatePath);
        var bridge = new RdpDvcOpaqueControlPipeBridge(
            new(pipeName, TimeSpan.FromSeconds(5), 4096),
            stateStore);
        var bridgeTask = bridge.AttachAsync(
            hostCarrier.Stream,
            attachment,
            new("composition", 1),
            CancellationToken.None);
        await controlPipe.WaitForConnectionAsync();
        var received = await ReconnectCarrierAttachmentCodec.ReadAsync(
            controlPipe);
        Assert.Equal(attachment, received);
        var responses = await ConnectControlResponsesAsync(
            pipeName,
            attachment.Binding.AttemptId);
        await SendControlResponseAsync(
            responses,
            ReconnectCarrierControlMessage.RelayReady(
                attachment.Binding.AttemptId));

        var hello = Hello(endpoint, attachment);
        var terminator = new ControlReconnectSessionTerminator(
            "control",
            endpoint.ControlPrivateKey,
            TimeSpan.FromSeconds(5));
        var accepting = terminator.AcceptAsync(
            controlPipe,
            attachment,
            endpoint.Registration,
            hello,
            CancellationToken.None);
        var nodeSecureCarrier = NodeSecureCarrier(
            nodeCarrier.Stream,
            nodeKey,
            controlKey);
        var connecting = nodeSecureCarrier.ConnectAsync(hello).AsTask();
        var established = await Task.WhenAll(accepting, connecting)
            .WaitAsync(TimeSpan.FromSeconds(5));
        var control = established[0];
        var node = established[1];
        await SendControlResponseAsync(
            responses,
            ReconnectCarrierControlMessage.SecureSessionAuthenticated(
                attachment.Binding.AttemptId));
        var bridgeLease = await bridgeTask.WaitAsync(
            TimeSpan.FromSeconds(2));
        await new SqliteConnectionReconnectHighWaterStore(highWaterPath)
            .ObserveAsync(
                "composition",
                identity,
                CancellationToken.None);
        return new(
            attachment.Binding,
            bridgeLease,
            nodeCarrier,
            nodeSecureCarrier,
            node,
            control,
            responses,
            controlPipe);
    }

    private async Task<TestEndpoint> CreateEndpointAsync(
        ECDsa controlKey,
        ECDsa nodeKey)
    {
        var controlPrivate = Path.Combine(root, "control.pk8.pem");
        var nodePublic = Path.Combine(root, "node.spki.pem");
        await File.WriteAllTextAsync(
            controlPrivate,
            controlKey.ExportPkcs8PrivateKeyPem());
        await File.WriteAllTextAsync(
            nodePublic,
            nodeKey.ExportSubjectPublicKeyInfoPem());
        var host = HostId.New();
        var incarnation = NodeIncarnationId.New();
        var sessionId = Guid.NewGuid();
        return new(
            sessionId,
            controlPrivate,
            new(
                host,
                incarnation,
                PoolId.New(),
                ExtensionMetadataDto.Create(
                    "direct-websocket",
                    "1.0",
                    new { sessionId }),
                "node",
                nodePublic,
                new ResourceRequirements(1),
                [],
                [],
                DateTimeOffset.UtcNow));
    }

    private static RdpDvcCarrierAttemptIdentity Attempt(
        TestEndpoint endpoint) =>
        new(
            endpoint.SessionId,
            endpoint.Registration.HostId,
            endpoint.Registration.NodeIncarnationId,
            1,
            Guid.NewGuid(),
            42)
        {
            RouteId = endpoint.Registration.HostId.Value
        };

    private static SessionHello Hello(
        TestEndpoint endpoint,
        ReconnectCarrierAttachment attachment) =>
        new(
            endpoint.SessionId,
            endpoint.Registration.NodeIncarnationId,
            1,
            0,
            new HashSet<string>(["rdp-dvc-reconnect-v2"]),
            new HashSet<string>(["rdp-dvc-reconnect-v2"]),
            new Dictionary<StreamKind, long>(),
            new(64 * 1024, 8),
            attachment.Binding);

    private static SecureStreamCarrier NodeSecureCarrier(
        Stream stream,
        ECDsa nodeKey,
        ECDsa controlKey) =>
        new(
            new SingleStreamConnector(stream),
            new(
                TransportEndpointRole.Node,
                new EcdsaEndpointSigningKey(
                    "node",
                    ECDsa.Create(nodeKey.ExportParameters(true))),
                new(
                    "control",
                    controlKey.ExportSubjectPublicKeyInfo()),
                HandshakeTimeout: TimeSpan.FromSeconds(2)));

    private static NamedPipeServerStream Server(string pipeName) =>
        new(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            64 * 1024,
            64 * 1024);

    private static async Task<NamedPipeClientStream>
        ConnectControlResponsesAsync(
            string pipeName,
            Guid attemptId)
    {
        var responses = new NamedPipeClientStream(
            ".",
            RdpDvcOpaqueControlPipeBridge.AcknowledgementPipeName(
                pipeName,
                attemptId),
            PipeDirection.Out,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await responses.ConnectAsync();
        return responses;
    }

    private static Task SendControlResponseAsync(
        Stream responses,
        ReconnectCarrierControlMessage message) =>
        ReconnectCarrierControlMessageCodec.WriteAsync(
            responses,
            message);

    private static async Task<long> ReadHighWaterAsync(
        string databasePath)
    {
        await using var connection =
            new Microsoft.Data.Sqlite.SqliteConnection(
                $"Data Source={databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT MAX(generation) FROM reconnect_high_water";
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    private static async Task<long> CountActiveRoutesAsync(
        string databasePath)
    {
        await using var connection =
            new Microsoft.Data.Sqlite.SqliteConnection(
                $"Data Source={databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(*) FROM connection_routes WHERE active=1";
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    private static async Task<long> CountAttachedControlsAsync(
        string databasePath)
    {
        await using var connection =
            new Microsoft.Data.Sqlite.SqliteConnection(
                $"Data Source={databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*) FROM control_attachments
            WHERE detached_at IS NULL
            """;
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }
    private static async Task<(
        RdpDvcConnectedStream Node,
        RdpDvcConnectedStream Host)> ConnectRetainedV1CarrierAsync(
            TestEndpoint endpoint,
            Guid nonce,
            byte[] secret)
    {
        var authentication = new RdpDvcAuthenticationOptions(
            new(
                endpoint.SessionId,
                endpoint.Registration.HostId.Value,
                endpoint.Registration.NodeIncarnationId.Value,
                RdpSessionId: null,
                ConnectionNonce: nonce),
            secret);
        var (nodeWire, hostWire) = CarrierWire.Create(42);
        var node = RdpDvcStreamHandshake.InitiateAsync(
                nodeWire,
                authentication)
            .AsTask();
        var host = RdpDvcStreamHandshake.RespondAsync(
                hostWire,
                authentication)
            .AsTask();
        await Task.WhenAll(node, host);
        return (await node, await host);
    }
    private static async Task<(
        RdpDvcConnectedStreamV2 Node,
        RdpDvcConnectedStreamV2 Host)> ConnectCarrierAsync(
        RdpDvcCarrierAttemptIdentity identity,
        byte[] secret)
    {
        var (nodeWire, hostWire) = CarrierWire.Create(identity.RdpSessionId);
        var node = RdpDvcCarrierHandshakeV2.InitiateAsync(
                nodeWire,
                identity,
                secret,
                TimeSpan.FromSeconds(2))
            .AsTask();
        var host = RdpDvcCarrierHandshakeV2.RespondAsync(
                hostWire,
                identity,
                secret,
                TimeSpan.FromSeconds(2))
            .AsTask();
        await Task.WhenAll(node, host);
        return (await node, await host);
    }

    private sealed class SignedLifecycleAttemptFactory(
        Func<long, Task<SignedLifecycleAttempt>> connect) :
        IRdpDvcLocalCarrierAttemptFactory
    {
        private readonly List<SignedLifecycleAttempt> attempts = [];
        private readonly SemaphoreSlim changed = new(0);
        private readonly object gate = new();
        private int connectCount;

        public IReadOnlyList<string> Evidence { get; private set; } = [];
        public int CommittedGenerations { get; private set; }

        public async Task<SignedLifecycleAttempt> ConnectConcreteAsync(
            CancellationToken cancellationToken)
        {
            var generation = Interlocked.Increment(ref connectCount);
            if (generation > 2)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new OperationCanceledException(cancellationToken);
            }
            var attempt = await connect(generation);
            lock (gate)
            {
                attempts.Add(attempt);
                Evidence = Evidence
                    .Append($"{generation}:carrier-hmac")
                    .Append($"{generation}:signed-ecdh")
                    .ToArray();
                CommittedGenerations++;
            }
            changed.Release();
            return attempt;
        }

        public async Task<IRdpDvcLocalCarrierAttempt> ConnectAsync(
            CancellationToken cancellationToken) =>
            await ConnectConcreteAsync(cancellationToken);

        public async Task<SignedLifecycleAttempt> WaitForAttemptAsync(
            int expectedCount)
        {
            using var timeout = new CancellationTokenSource(
                TimeSpan.FromSeconds(5));
            while (true)
            {
                lock (gate)
                {
                    if (attempts.Count >= expectedCount)
                        return attempts[expectedCount - 1];
                }
                await changed.WaitAsync(timeout.Token);
            }
        }
    }

    private sealed class SignedLifecycleAttempt(
        ReconnectTransportBinding binding,
        IRdpDvcOpaqueControlBridgeLease bridgeLease,
        RdpDvcConnectedStreamV2 nodeCarrier,
        SecureStreamCarrier nodeSecureCarrier,
        ITransportConnection node,
        ITransportConnection control,
        NamedPipeClientStream responses,
        NamedPipeServerStream controlPipe) :
        IRdpDvcLocalCarrierAttempt
    {
        private int disposed;

        public ReconnectTransportBinding Binding { get; } = binding;
        public Task Completion => bridgeLease.Completion;

        public async Task CloseNodeAsync()
        {
            await node.DisposeAsync();
            await nodeSecureCarrier.DisposeAsync();
            await nodeCarrier.DisposeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;
            await node.DisposeAsync();
            await control.DisposeAsync();
            await bridgeLease.DisposeAsync();
            await nodeSecureCarrier.DisposeAsync();
            await nodeCarrier.DisposeAsync();
            await responses.DisposeAsync();
            await controlPipe.DisposeAsync();
        }
    }

    private sealed record TestEndpoint(
        Guid SessionId,
        string ControlPrivateKey,
        NodeEndpointRegistration Registration);

    private sealed class SingleStreamConnector(Stream stream) :
        ITransportStreamConnector
    {
        private int used;

        public ValueTask<Stream> ConnectStreamAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref used, 1) != 0)
                throw new InvalidOperationException(
                    "The test stream is single-use.");
            return ValueTask.FromResult(stream);
        }
    }

    private sealed class CarrierWire(
        Channel<byte[]> incoming,
        Channel<byte[]> outgoing) : IRdpDvcWireChannel
    {
        public static (
            RdpDvcWireConnection Node,
            RdpDvcWireConnection Host) Create(int rdpSessionId)
        {
            var nodeToHost = Channel.CreateUnbounded<byte[]>();
            var hostToNode = Channel.CreateUnbounded<byte[]>();
            return (
                new(
                    new CarrierWire(hostToNode, nodeToHost),
                    rdpSessionId),
                new(
                    new CarrierWire(nodeToHost, hostToNode),
                    null));
        }

        public ValueTask WritePduAsync(
            ReadOnlyMemory<byte> pdu,
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
