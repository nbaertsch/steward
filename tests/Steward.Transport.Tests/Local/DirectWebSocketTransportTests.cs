using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using Steward.Domain;
using Steward.Transport.Local;

namespace Steward.Transport.Tests.Local;

public sealed class DirectWebSocketTransportTests
{
    [Theory]
    [InlineData(TransportEndpointRole.Control)]
    [InlineData(TransportEndpointRole.Node)]
    public async Task Either_role_can_dial_and_exchange_multiplexed_payloads(
        TransportEndpointRole dialingRole)
    {
        await using var pair = await ConnectedPair.CreateAsync(dialingRole);
        Assert.True(pair.Dialer.Session.Security.IsSecure);
        Assert.Equal("listener", pair.Dialer.Session.Security.RemoteIdentity);
        Assert.Equal("dialer", pair.Listener.Session.Security.RemoteIdentity);

        var control = pair.Frame(StreamKind.Control, 1, "control");
        var events = pair.Frame(StreamKind.Events, 1, "events");
        await pair.Dialer.SendAsync(control);
        await pair.Dialer.SendAsync(events);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var received = pair.Listener.ReceiveAsync(timeout.Token).GetAsyncEnumerator();
        Assert.True(await received.MoveNextAsync());
        Assert.Equal("control", Encoding.UTF8.GetString(received.Current.Payload.Span));
        Assert.True(await received.MoveNextAsync());
        Assert.Equal(StreamKind.Events, received.Current.Stream);
        Assert.Equal("events", Encoding.UTF8.GetString(received.Current.Payload.Span));
    }

    [Fact]
    public async Task Handshake_rejects_the_wrong_enrolled_identity()
    {
        using var dialerKey = EcdsaEndpointSigningKey.Create("dialer");
        using var listenerKey = EcdsaEndpointSigningKey.Create("listener");
        using var unrelatedKey = EcdsaEndpointSigningKey.Create("unrelated");
        var endpoint = LoopbackEndpoint();
        var hello = Hello();
        var listenerOptions = Options(
            endpoint,
            TransportEndpointRole.Node,
            listenerKey,
            new ExpectedPeerIdentity("dialer", dialerKey.ExportPublicKey()));
        await using var acceptor = new DirectWebSocketConnectionAcceptor(listenerOptions);
        var accepting = acceptor.AcceptAsync(hello).AsTask();
        var dialer = new DirectWebSocketCarrier(Options(
            endpoint,
            TransportEndpointRole.Control,
            dialerKey,
            new ExpectedPeerIdentity("listener", unrelatedKey.ExportPublicKey())));

        var error = await Assert.ThrowsAsync<SecureHandshakeException>(
            () => dialer.ConnectAsync(hello).AsTask());
        Assert.Equal(SecureHandshakeError.IdentityMismatch, error.Error);
        await using var accepted = await accepting.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Cancelled_accept_can_be_retried_without_losing_the_next_connection()
    {
        using var dialerKey = EcdsaEndpointSigningKey.Create("dialer");
        using var listenerKey = EcdsaEndpointSigningKey.Create("listener");
        var endpoint = LoopbackEndpoint();
        var hello = Hello();
        await using var acceptor = new DirectWebSocketConnectionAcceptor(Options(
            endpoint,
            TransportEndpointRole.Node,
            listenerKey,
            new ExpectedPeerIdentity("dialer", dialerKey.ExportPublicKey())));

        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => acceptor.AcceptAsync(hello, cancelled.Token).AsTask());
        }

        var accepting = acceptor.AcceptAsync(hello).AsTask();
        var carrier = new DirectWebSocketCarrier(Options(
            endpoint,
            TransportEndpointRole.Control,
            dialerKey,
            new ExpectedPeerIdentity("listener", listenerKey.ExportPublicKey())));
        await using var dialer = await carrier.ConnectAsync(hello);
        await using var listener = await accepting.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(dialer.Session.Security.IsSecure);
    }

    [Fact]
    public async Task Reconnect_resumes_each_stream_from_negotiated_cursors()
    {
        using var dialerKey = EcdsaEndpointSigningKey.Create("dialer");
        using var listenerKey = EcdsaEndpointSigningKey.Create("listener");
        var endpoint = LoopbackEndpoint();
        var dialerOptions = Options(
            endpoint,
            TransportEndpointRole.Control,
            dialerKey,
            new ExpectedPeerIdentity("listener", listenerKey.ExportPublicKey()));
        var listenerOptions = Options(
            endpoint,
            TransportEndpointRole.Node,
            listenerKey,
            new ExpectedPeerIdentity("dialer", dialerKey.ExportPublicKey()));
        await using var acceptor = new DirectWebSocketConnectionAcceptor(listenerOptions);

        var firstHello = Hello();
        var firstAccept = acceptor.AcceptAsync(firstHello).AsTask();
        var carrier = new DirectWebSocketCarrier(dialerOptions);
        await using (var dialer = await carrier.ConnectAsync(firstHello))
        await using (var listener = await firstAccept.WaitAsync(TimeSpan.FromSeconds(5)))
        {
            await dialer.SendAsync(Frame(firstHello, StreamKind.Logs, 1, "one"));
            Assert.Equal(1, (await ReadOneAsync(listener)).Sequence);
        }

        var cursors = new Dictionary<StreamKind, long> { [StreamKind.Logs] = 1 };
        var resumedHello = Hello(
            cursors,
            sessionId: firstHello.SessionId,
            incarnation: firstHello.NodeIncarnationId);
        var resumedAccept = acceptor.AcceptAsync(resumedHello).AsTask();
        await using var resumedDialer = await carrier.ConnectAsync(resumedHello);
        await using var resumedListener = await resumedAccept.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, resumedDialer.Session.RemoteResumeCursors[StreamKind.Logs]);
        await resumedDialer.SendAsync(Frame(resumedHello, StreamKind.Logs, 2, "two"));
        var resumed = await ReadOneAsync(resumedListener);
        Assert.Equal(2, resumed.Sequence);
        Assert.Equal("two", Encoding.UTF8.GetString(resumed.Payload.Span));
    }

    [Fact]
    public async Task Replayed_or_out_of_order_frame_is_rejected()
    {
        await using var pair = await ConnectedPair.CreateAsync(TransportEndpointRole.Control);
        var first = pair.Frame(StreamKind.Artifacts, 1, "first");
        await pair.Dialer.SendAsync(first);
        _ = await ReadOneAsync(pair.Listener);

        var replay = await Assert.ThrowsAsync<TransportProtocolException>(
            () => pair.Dialer.SendAsync(first).AsTask());
        Assert.Equal(TransportError.InvalidSequence, replay.Error);
        var skipped = await Assert.ThrowsAsync<TransportProtocolException>(
            () => pair.Dialer.SendAsync(pair.Frame(StreamKind.Artifacts, 3, "third")).AsTask());
        Assert.Equal(TransportError.InvalidSequence, skipped.Error);
    }

    [Fact]
    public async Task Replayed_encrypted_record_is_rejected()
    {
        using var dialerKey = EcdsaEndpointSigningKey.Create("dialer");
        using var listenerKey = EcdsaEndpointSigningKey.Create("listener");
        var endpoint = LoopbackEndpoint();
        var hello = Hello();
        await using var acceptor = new DirectWebSocketConnectionAcceptor(Options(
            endpoint,
            TransportEndpointRole.Node,
            listenerKey,
            new ExpectedPeerIdentity("dialer", dialerKey.ExportPublicKey())));
        var accepting = acceptor.AcceptAsync(hello).AsTask();
        using var socket = new ClientWebSocket();
        await socket.ConnectAsync(endpoint, CancellationToken.None);
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var localHandshake = SecureTransportProtocol.CreateHandshake(
            TransportEndpointRole.Control,
            dialerKey,
            hello,
            ephemeral);
        await socket.SendAsync(
            localHandshake,
            WebSocketMessageType.Binary,
            true,
            CancellationToken.None);
        var remoteRecord = await ReceiveRawAsync(socket);
        var remoteHandshake = SecureTransportProtocol.ParseAndVerifyHandshake(
            remoteRecord,
            TransportEndpointRole.Control,
            new ExpectedPeerIdentity("listener", listenerKey.ExportPublicKey()),
            hello);
        var keys = SecureTransportProtocol.DeriveKeys(
            ephemeral,
            remoteHandshake,
            localHandshake,
            remoteRecord,
            TransportEndpointRole.Control);
        await using var listener = await accepting.WaitAsync(TimeSpan.FromSeconds(5));
        var plaintext = SecureTransportProtocol.SerializeFrame(
            Frame(hello, StreamKind.Control, 1, "once"));
        var encrypted = SecureTransportProtocol.Encrypt(
            keys.Send,
            TransportEndpointRole.Control,
            hello.SessionId,
            1,
            plaintext);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var received = listener.ReceiveAsync(timeout.Token).GetAsyncEnumerator();
        await socket.SendAsync(encrypted, WebSocketMessageType.Binary, true, timeout.Token);
        Assert.True(await received.MoveNextAsync());
        await socket.SendAsync(encrypted, WebSocketMessageType.Binary, true, timeout.Token);
        var replay = await Assert.ThrowsAsync<TransportProtocolException>(
            () => received.MoveNextAsync().AsTask());
        Assert.Equal(TransportError.InvalidSequence, replay.Error);
        CryptographicOperations.ZeroMemory(keys.Send);
        CryptographicOperations.ZeroMemory(keys.Receive);
    }

    [Fact]
    public async Task Identity_stream_carries_ephemeral_request_response_payloads()
    {
        await using var pair = await ConnectedPair.CreateAsync(TransportEndpointRole.Node);
        await pair.Dialer.SendAsync(pair.Frame(StreamKind.Identity, 1, "request"));
        var request = await ReadOneAsync(pair.Listener);
        Assert.Equal(StreamKind.Identity, request.Stream);
        Assert.Equal("request", Encoding.UTF8.GetString(request.Payload.Span));

        await pair.Listener.SendAsync(new TransportFrame(
            request.SessionId,
            request.NodeIncarnationId,
            StreamKind.Identity,
            1,
            1,
            Encoding.UTF8.GetBytes("response")));
        var response = await ReadOneAsync(pair.Dialer);
        Assert.Equal(StreamKind.Identity, response.Stream);
        Assert.Equal("response", Encoding.UTF8.GetString(response.Payload.Span));
    }

    [Fact]
    public async Task Negotiated_payload_limit_is_enforced_before_wire_allocation()
    {
        var dialerHello = Hello(limits: new TransportLimits(32, 4));
        var listenerHello = Hello(
            limits: new TransportLimits(8, 2),
            sessionId: dialerHello.SessionId,
            incarnation: dialerHello.NodeIncarnationId);
        await using var pair = await ConnectedPair.CreateAsync(
            TransportEndpointRole.Control,
            dialerHello,
            listenerHello);
        Assert.Equal(8, pair.Dialer.Session.Limits.MaximumPayloadBytes);
        Assert.Equal(2, pair.Dialer.Session.Limits.MaximumBufferedFrames);

        var error = await Assert.ThrowsAsync<TransportProtocolException>(
            () => pair.Dialer.SendAsync(new TransportFrame(
                dialerHello.SessionId,
                dialerHello.NodeIncarnationId,
                StreamKind.Terminal,
                1,
                0,
                new byte[9])).AsTask());
        Assert.Equal(TransportError.PayloadTooLarge, error.Error);
    }

    [Fact]
    public void Plaintext_websockets_require_explicit_loopback_local_development()
    {
        using var local = EcdsaEndpointSigningKey.Create("local");
        using var peer = EcdsaEndpointSigningKey.Create("peer");
        var expected = new ExpectedPeerIdentity("peer", peer.ExportPublicKey());

        Assert.Throws<ArgumentException>(() => new DirectWebSocketConnectionAcceptor(
            new DirectWebSocketOptions(
                new Uri("ws://127.0.0.1:54321/direct/"),
                TransportEndpointRole.Control,
                local,
                expected)));
        Assert.Throws<ArgumentException>(() => new DirectWebSocketConnectionAcceptor(
            new DirectWebSocketOptions(
                new Uri("ws://192.0.2.1:54321/direct/"),
                TransportEndpointRole.Control,
                local,
                expected,
                AllowUnencryptedLoopback: true)));
    }

    private static async Task<TransportFrame> ReadOneAsync(ITransportConnection connection)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var enumerator = connection.ReceiveAsync(timeout.Token).GetAsyncEnumerator();
        Assert.True(await enumerator.MoveNextAsync());
        return enumerator.Current;
    }

    private static async Task<byte[]> ReceiveRawAsync(WebSocket socket)
    {
        using var record = new MemoryStream();
        var chunk = new byte[4096];
        WebSocketReceiveResult result;
        do
        {
            result = await socket.ReceiveAsync(chunk, CancellationToken.None);
            Assert.Equal(WebSocketMessageType.Binary, result.MessageType);
            record.Write(chunk, 0, result.Count);
        } while (!result.EndOfMessage);
        return record.ToArray();
    }

    private static DirectWebSocketOptions Options(
        Uri endpoint,
        TransportEndpointRole role,
        IEndpointSigningKey key,
        ExpectedPeerIdentity peer) =>
        new(
            endpoint,
            role,
            key,
            peer,
            AllowUnencryptedLoopback: true,
            ConnectTimeout: TimeSpan.FromSeconds(5),
            HandshakeTimeout: TimeSpan.FromSeconds(5),
            OperationTimeout: TimeSpan.FromSeconds(5));

    private static SessionHello Hello(
        IReadOnlyDictionary<StreamKind, long>? cursors = null,
        TransportLimits? limits = null,
        Guid? sessionId = null,
        NodeIncarnationId? incarnation = null) =>
        new(
            sessionId ?? Guid.NewGuid(),
            incarnation ?? NodeIncarnationId.New(),
            1,
            0,
            new HashSet<string>(StringComparer.Ordinal) { "direct" },
            new HashSet<string>(StringComparer.Ordinal),
            cursors ?? new Dictionary<StreamKind, long>(),
            limits ?? new TransportLimits(1024, 8));

    private static TransportFrame Frame(
        SessionHello hello,
        StreamKind stream,
        long sequence,
        string payload) =>
        new(
            hello.SessionId,
            hello.NodeIncarnationId,
            stream,
            sequence,
            sequence,
            Encoding.UTF8.GetBytes(payload));

    private static Uri LoopbackEndpoint()
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        var port = ((IPEndPoint)reservation.LocalEndpoint).Port;
        return new Uri($"ws://127.0.0.1:{port}/direct/");
    }

    private sealed class ConnectedPair : IAsyncDisposable
    {
        private readonly EcdsaEndpointSigningKey _dialerKey;
        private readonly EcdsaEndpointSigningKey _listenerKey;
        private readonly DirectWebSocketConnectionAcceptor _acceptor;
        private readonly SessionHello _hello;

        private ConnectedPair(
            EcdsaEndpointSigningKey dialerKey,
            EcdsaEndpointSigningKey listenerKey,
            DirectWebSocketConnectionAcceptor acceptor,
            SessionHello hello,
            ITransportConnection dialer,
            ITransportConnection listener)
        {
            _dialerKey = dialerKey;
            _listenerKey = listenerKey;
            _acceptor = acceptor;
            _hello = hello;
            Dialer = dialer;
            Listener = listener;
        }

        public ITransportConnection Dialer { get; }
        public ITransportConnection Listener { get; }

        public TransportFrame Frame(StreamKind stream, long sequence, string payload) =>
            DirectWebSocketTransportTests.Frame(_hello, stream, sequence, payload);

        public static async Task<ConnectedPair> CreateAsync(
            TransportEndpointRole dialerRole,
            SessionHello? dialerHello = null,
            SessionHello? listenerHello = null)
        {
            var dialerKey = EcdsaEndpointSigningKey.Create("dialer");
            var listenerKey = EcdsaEndpointSigningKey.Create("listener");
            try
            {
                dialerHello ??= Hello();
                listenerHello ??= new SessionHello(
                    dialerHello.SessionId,
                    dialerHello.NodeIncarnationId,
                    dialerHello.ProtocolMajor,
                    dialerHello.ProtocolMinor,
                    dialerHello.SupportedFeatures,
                    dialerHello.RequiredFeatures,
                    dialerHello.ResumeCursors,
                    dialerHello.Limits);
                var endpoint = LoopbackEndpoint();
                var listenerRole = dialerRole == TransportEndpointRole.Control
                    ? TransportEndpointRole.Node
                    : TransportEndpointRole.Control;
                var acceptor = new DirectWebSocketConnectionAcceptor(Options(
                    endpoint,
                    listenerRole,
                    listenerKey,
                    new ExpectedPeerIdentity("dialer", dialerKey.ExportPublicKey())));
                try
                {
                    var accepting = acceptor.AcceptAsync(listenerHello).AsTask();
                    var carrier = new DirectWebSocketCarrier(Options(
                        endpoint,
                        dialerRole,
                        dialerKey,
                        new ExpectedPeerIdentity("listener", listenerKey.ExportPublicKey())));
                    var dialer = await carrier.ConnectAsync(dialerHello);
                    try
                    {
                        var listener = await accepting.WaitAsync(TimeSpan.FromSeconds(5));
                        return new ConnectedPair(
                            dialerKey,
                            listenerKey,
                            acceptor,
                            dialerHello,
                            dialer,
                            listener);
                    }
                    catch
                    {
                        await dialer.DisposeAsync();
                        throw;
                    }
                }
                catch
                {
                    await acceptor.DisposeAsync();
                    throw;
                }
            }
            catch
            {
                dialerKey.Dispose();
                listenerKey.Dispose();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Dialer.DisposeAsync();
            await Listener.DisposeAsync();
            await _acceptor.DisposeAsync();
            _dialerKey.Dispose();
            _listenerKey.Dispose();
        }
    }
}
