using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Channels;
using Steward.Domain;
using Steward.Transport;
using Steward.Transport.Rdp.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

public sealed class RdpDvcProtocolTests
{
    private static readonly Guid SessionId =
        new("62A9C60C-942A-441A-93C5-246C676B5A11");
    private static readonly HostId HostId =
        new(new Guid("86B15D83-9B3B-4703-AD2E-490012318AC1"));
    private static readonly NodeIncarnationId IncarnationId =
        new(new Guid("C80584BC-C0C5-488D-B75E-7CD5616455FB"));

    [Fact]
    public void Codec_round_trips_authenticated_binding()
    {
        var key = Key();
        var message = Message(
            RdpDvcMessageKind.Ping,
            sequence: 1,
            payload: new byte[] { 1, 2, 3 });

        var encoded = RdpDvcMessageCodec.Encode(message, key);
        var decoded = RdpDvcMessageCodec.Decode(
            encoded,
            Options(key, 42));

        Assert.Equal(message.Kind, decoded.Kind);
        Assert.Equal(message.SessionId, decoded.SessionId);
        Assert.Equal(message.HostId, decoded.HostId);
        Assert.Equal(message.NodeIncarnationId, decoded.NodeIncarnationId);
        Assert.Equal(message.Nonce, decoded.Nonce);
        Assert.Equal(message.Sequence, decoded.Sequence);
        Assert.Equal(message.Payload.ToArray(), decoded.Payload.ToArray());
    }

    [Fact]
    public void Codec_rejects_corruption_binding_and_bounds()
    {
        var key = Key();
        var encoded = RdpDvcMessageCodec.Encode(
            Message(
                RdpDvcMessageKind.Data,
                2,
                new byte[] { 1, 2, 3 }),
            key);
        encoded[^1] ^= 0x40;
        var corruption = Assert.Throws<RdpDvcProtocolException>(
            () => RdpDvcMessageCodec.Decode(
                encoded,
                Options(key, 42)));
        Assert.Equal(
            RdpDvcProtocolError.AuthenticationFailed,
            corruption.Error);

        var valid = RdpDvcMessageCodec.Encode(
            Message(
                RdpDvcMessageKind.Data,
                2,
                new byte[] { 1, 2, 3 }),
            key);
        var wrongSession = Options(key, 41);
        var binding = Assert.Throws<RdpDvcProtocolException>(
            () => RdpDvcMessageCodec.Decode(valid, wrongSession));
        Assert.Equal(
            RdpDvcProtocolError.BindingMismatch,
            binding.Error);

        var wrongNonce = Options(key, 42) with
        {
            ExpectedPeer =
                Options(key, 42).ExpectedPeer with
                {
                    ConnectionNonce = Guid.NewGuid()
                }
        };
        var nonceBinding = Assert.Throws<RdpDvcProtocolException>(
            () => RdpDvcMessageCodec.Decode(valid, wrongNonce));
        Assert.Equal(
            RdpDvcProtocolError.BindingMismatch,
            nonceBinding.Error);

        var large = new byte[StewardRdpDvc.MaximumPingPayloadBytes + 1];
        var bounds = Assert.Throws<RdpDvcProtocolException>(
            () => RdpDvcMessageCodec.Encode(
                Message(RdpDvcMessageKind.Ping, 1, large),
                key));
        Assert.Equal(RdpDvcProtocolError.BoundsExceeded, bounds.Error);
    }

    [Fact]
    public void Fragment_reassembly_is_bounded_and_exact()
    {
        var encoded = RdpDvcMessageCodec.Encode(
            Message(
                RdpDvcMessageKind.Data,
                2,
                Enumerable.Range(0, 4096)
                    .Select(value => (byte)value)
                    .ToArray()),
            Key());
        var reassembler = new BoundedDvcMessageReassembler();

        Assert.Empty(reassembler.Push(encoded.AsSpan(0, 17)));
        Assert.Empty(reassembler.Push(encoded.AsSpan(17, 1000)));
        var completed = reassembler.Push(encoded.AsSpan(1017));

        Assert.Single(completed);
        Assert.Equal(encoded, completed[0]);

        var pduReassembler =
            new BoundedChannelPduReassembler(encoded.Length);
        Assert.Null(pduReassembler.Push(
            encoded.AsSpan(0, 1000),
            BoundedChannelPduReassembler.First));
        var pdu = pduReassembler.Push(
            encoded.AsSpan(1000),
            BoundedChannelPduReassembler.Last);
        Assert.Equal(encoded, pdu);

        var header = new byte[8 + encoded.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(
            header,
            checked((uint)encoded.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(
            header.AsSpan(4),
            BoundedChannelPduReassembler.First |
            BoundedChannelPduReassembler.Last);
        encoded.CopyTo(header.AsSpan(8));
        Assert.Equal(
            encoded,
            pduReassembler.PushReadBuffer(header));
    }

    [Fact]
    public async Task Ping_pong_maps_to_bounded_bidirectional_stream()
    {
        var pair = WirePair.Create();
        var key = Key();
        var initiate = RdpDvcStreamHandshake.InitiateAsync(
            new(pair.First, 42),
            Options(key, 42));
        var respond = RdpDvcStreamHandshake.RespondAsync(
            new(pair.Second, null),
            Options(key));
        var connected = await Task.WhenAll(
            initiate.AsTask(),
            respond.AsTask());
        await using var initiator = connected[0];
        await using var responder = connected[1];
        var payload = Enumerable.Range(0, 16_384)
            .Select(value => (byte)value)
            .ToArray();

        await initiator.Stream.WriteAsync(payload);
        var received = new byte[payload.Length];
        await ReadExactlyAsync(responder.Stream, received);

        Assert.Equal(payload, received);
        Assert.Equal(42, initiator.Handshake.RdpSessionId);
        Assert.Equal(1, initiator.Handshake.Sequence);
    }

    [Fact]
    public async Task Ping_pong_binds_a_prearranged_connection_nonce()
    {
        var pair = WirePair.Create();
        var key = Key();
        var nonce = Guid.NewGuid();
        var options = Options(key, 42) with
        {
            ExpectedPeer =
                Options(key, 42).ExpectedPeer with
                {
                    ConnectionNonce = nonce
                }
        };

        var connected = await Task.WhenAll(
            RdpDvcStreamHandshake.InitiateAsync(
                    new(pair.First, 42),
                    options)
                .AsTask(),
            RdpDvcStreamHandshake.RespondAsync(
                    new(pair.Second, null),
                    options)
                .AsTask());

        await using var initiator = connected[0];
        await using var responder = connected[1];
        Assert.Equal(nonce, initiator.Handshake.Nonce);
        Assert.Equal(nonce, responder.Handshake.Nonce);
    }

    [Fact]
    public async Task Stream_rejects_out_of_order_data()
    {
        var pair = WirePair.Create();
        var key = Key();
        var nonce = Guid.NewGuid();
        var handshake = Message(
            RdpDvcMessageKind.Ping,
            1,
            RandomNumberGenerator.GetBytes(32)) with
        {
            Nonce = nonce
        };
        var ping = RdpDvcMessageCodec.Encode(handshake, key);
        var pong = RdpDvcMessageCodec.Encode(
            handshake with
            {
                Kind = RdpDvcMessageKind.Pong
            },
            key);
        await pair.First.WritePduAsync(ping);
        _ = await pair.Second.ReadPduAsync();
        await pair.Second.WritePduAsync(pong);
        _ = await pair.First.ReadPduAsync();
        var options = Options(key, 42);
        await using var stream = new AuthenticatedRdpDvcStream(
            pair.First,
            options,
            handshake,
            2,
            2);
        var outOfOrder = RdpDvcMessageCodec.Encode(
            handshake with
            {
                Kind = RdpDvcMessageKind.Data,
                Sequence = 3,
                Payload = new byte[] { 1 }
            },
            key);
        await pair.Second.WritePduAsync(outOfOrder);

        var exception = await Assert.ThrowsAsync<
            RdpDvcProtocolException>(
            async () =>
            {
                var buffer = new byte[1];
                _ = await stream.ReadAsync(buffer);
            });
        Assert.Equal(
            RdpDvcProtocolError.InvalidSequence,
            exception.Error);
        await pair.Second.DisposeAsync();
    }

    [Fact]
    public async Task Ping_timeout_and_cancellation_are_distinct()
    {
        var pair = WirePair.Create();
        var timeoutOptions = Options(Key(), 42) with
        {
            HandshakeTimeout = TimeSpan.FromMilliseconds(50)
        };
        await Assert.ThrowsAsync<TimeoutException>(
            () => RdpDvcStreamHandshake.InitiateAsync(
                    new(pair.First, 42),
                    timeoutOptions)
                .AsTask());
        await pair.Second.DisposeAsync();

        var cancellationPair = WirePair.Create();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => RdpDvcStreamHandshake.RespondAsync(
                    new(cancellationPair.First, null),
                    Options(Key()),
                    cancelled.Token)
                .AsTask());
        await cancellationPair.Second.DisposeAsync();
    }

    [Fact]
    public void Ping_nonce_replay_and_stale_timestamp_are_rejected()
    {
        var now = DateTimeOffset.UtcNow;
        var nonce = Guid.NewGuid();

        Assert.True(RdpDvcReplayWindow.TryAccept(
            nonce,
            "first"u8,
            now.UtcTicks,
            now));
        Assert.False(RdpDvcReplayWindow.TryAccept(
            nonce,
            "first"u8,
            now.UtcTicks,
            now));
        Assert.False(RdpDvcReplayWindow.TryAccept(
            nonce,
            "second"u8,
            now.UtcTicks,
            now));
        Assert.False(RdpDvcReplayWindow.TryAccept(
            Guid.NewGuid(),
            "stale"u8,
            now.Subtract(TimeSpan.FromMinutes(6)).UtcTicks,
            now));
    }

    [Fact]
    public async Task Secure_transport_frames_map_over_dvc_stream()
    {
        var pair = WirePair.Create();
        var authenticationKey = Key();
        var dvcConnections = await Task.WhenAll(
            RdpDvcStreamHandshake.InitiateAsync(
                    new(pair.First, 42),
                    Options(authenticationKey, 42))
                .AsTask(),
            RdpDvcStreamHandshake.RespondAsync(
                    new(pair.Second, null),
                    Options(authenticationKey))
                .AsTask());
        using var controlKey =
            EcdsaEndpointSigningKey.Create("control");
        using var nodeKey =
            EcdsaEndpointSigningKey.Create("node");
        var controlExpected = new ExpectedPeerIdentity(
            "node",
            nodeKey.ExportPublicKey());
        var nodeExpected = new ExpectedPeerIdentity(
            "control",
            controlKey.ExportPublicKey());
        var controlCarrier = new SecureStreamCarrier(
            new OneStreamConnector(dvcConnections[1].Stream),
            new(
                TransportEndpointRole.Control,
                controlKey,
                controlExpected,
                OperationTimeout: TimeSpan.FromMilliseconds(50)));
        var nodeAcceptor = new SecureStreamConnectionAcceptor(
            new OneStreamAcceptor(dvcConnections[0].Stream),
            new(
                TransportEndpointRole.Node,
                nodeKey,
                nodeExpected,
                OperationTimeout: TimeSpan.FromMilliseconds(50)));
        var hello = Hello();
        var established = await Task.WhenAll(
            controlCarrier.ConnectAsync(hello).AsTask(),
            nodeAcceptor.AcceptAsync(hello).AsTask());
        await using var control = established[0];
        await using var node = established[1];
        var frame = new TransportFrame(
            SessionId,
            IncarnationId,
            StreamKind.Control,
            1,
            1,
            new byte[] { 4, 5, 6 });

        using var timeout = new CancellationTokenSource(
            TimeSpan.FromSeconds(2));
        await using var received = node
            .ReceiveAsync(timeout.Token)
            .GetAsyncEnumerator();
        var waiting = received.MoveNextAsync().AsTask();
        await Task.Delay(200, timeout.Token);

        await control.SendAsync(frame, timeout.Token);

        Assert.True(await waiting);
        Assert.Equal(
            frame.Payload.ToArray(),
            received.Current.Payload.ToArray());
    }

    private static SessionHello Hello() =>
        new(
            SessionId,
            IncarnationId,
            1,
            0,
            new HashSet<string>(StringComparer.Ordinal)
            {
                "dvc-test"
            },
            new HashSet<string>(StringComparer.Ordinal),
            new Dictionary<StreamKind, long>(),
            new(64 * 1024, 8));

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..]);
            Assert.NotEqual(0, read);
            offset += read;
        }
    }

    private static RdpDvcMessage Message(
        RdpDvcMessageKind kind,
        long sequence,
        ReadOnlyMemory<byte> payload) =>
        new(
            kind,
            StewardRdpDvc.ProtocolVersion,
            SessionId,
            HostId.Value,
            IncarnationId.Value,
            42,
            new Guid("9818CE49-A046-47A9-BCA6-E93A3EA492FC"),
            sequence,
            DateTimeOffset.UtcNow.UtcTicks,
            payload);

    private static RdpDvcAuthenticationOptions Options(
        byte[] key,
        int? rdpSessionId = null) =>
        new(
            new(
                SessionId,
                HostId.Value,
                IncarnationId.Value,
                rdpSessionId),
            key,
            64 * 1024,
            TimeSpan.FromSeconds(2),
            TimeSpan.FromSeconds(2));

    private static byte[] Key() =>
        Enumerable.Range(1, 32)
            .Select(value => (byte)value)
            .ToArray();

    private sealed class WirePair
    {
        private WirePair(
            IRdpDvcWireChannel first,
            IRdpDvcWireChannel second)
        {
            First = first;
            Second = second;
        }

        internal IRdpDvcWireChannel First { get; }
        internal IRdpDvcWireChannel Second { get; }

        internal static WirePair Create()
        {
            var firstToSecond =
                Channel.CreateBounded<byte[]>(8);
            var secondToFirst =
                Channel.CreateBounded<byte[]>(8);
            return new(
                new ChannelWire(
                    secondToFirst.Reader,
                    firstToSecond.Writer),
                new ChannelWire(
                    firstToSecond.Reader,
                    secondToFirst.Writer));
        }
    }

    private sealed class ChannelWire(
        ChannelReader<byte[]> reader,
        ChannelWriter<byte[]> writer) : IRdpDvcWireChannel
    {
        public async ValueTask WritePduAsync(
            ReadOnlyMemory<byte> pdu,
            CancellationToken cancellationToken = default) =>
            await writer.WriteAsync(
                pdu.ToArray(),
                cancellationToken);

        public async ValueTask<byte[]> ReadPduAsync(
            CancellationToken cancellationToken = default) =>
            await reader.ReadAsync(cancellationToken);

        public ValueTask DisposeAsync()
        {
            writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class OneStreamConnector(Stream stream) :
        ITransportStreamConnector
    {
        public ValueTask<Stream> ConnectStreamAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(stream);
        }
    }

    private sealed class OneStreamAcceptor(Stream stream) :
        ITransportStreamAcceptor
    {
        public ValueTask<Stream> AcceptStreamAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(stream);
        }
    }
}
