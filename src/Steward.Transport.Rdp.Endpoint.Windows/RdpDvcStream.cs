using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
#if !RDP_DVC_SERVER_EMBEDDED
using Steward.Transport;
#endif

namespace Steward.Transport.Rdp.Windows;

public interface IRdpDvcWireChannel : IAsyncDisposable
{
    ValueTask WritePduAsync(
        ReadOnlyMemory<byte> pdu,
        CancellationToken cancellationToken = default);

    ValueTask<byte[]> ReadPduAsync(
        CancellationToken cancellationToken = default);
}

public sealed record RdpDvcWireConnection(
    IRdpDvcWireChannel Channel,
    int? RdpSessionId);

public interface IRdpDvcWireChannelSource
{
    ValueTask<RdpDvcWireConnection> OpenChannelAsync(
        CancellationToken cancellationToken = default);
}

public sealed record RdpDvcHandshakeResult(
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    int RdpSessionId,
    Guid Nonce,
    long Sequence,
    TimeSpan RoundTripTime);

public sealed class RdpDvcConnectedStream(
    Stream stream,
    RdpDvcHandshakeResult handshake) : IAsyncDisposable
{
    public Stream Stream { get; } = stream;
    public RdpDvcHandshakeResult Handshake { get; } = handshake;

    public ValueTask DisposeAsync() => Stream.DisposeAsync();
}

public static class RdpDvcStreamHandshake
{
    public static async ValueTask<RdpDvcConnectedStream> InitiateAsync(
        RdpDvcWireConnection connection,
        RdpDvcAuthenticationOptions options,
        CancellationToken cancellationToken = default)
    {
        options.Validate();
        var sessionId = connection.RdpSessionId ??
            options.ExpectedPeer.RdpSessionId ??
            throw new InvalidOperationException(
                "The initiating DVC endpoint must know the exact RDP session ID.");
        if (options.ExpectedPeer.RdpSessionId is int expectedSession &&
            expectedSession > 0 &&
            sessionId != expectedSession)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BindingMismatch,
                "The opened RDP session differs from the configured session.");

        var nonce =
            options.ExpectedPeer.ConnectionNonce ??
            Guid.NewGuid();
        var challenge = RandomNumberGenerator.GetBytes(32);
        var pingPayload =
            options.ExpectedPeer.ConnectionNonce.HasValue
                ? RdpDvcBrokerRoutingProtocol.CreatePingPayload(
                    options,
                    sessionId,
                    nonce,
                    challenge)
                : challenge;
        var ping = CreateMessage(
            RdpDvcMessageKind.Ping,
            options.ExpectedPeer,
            sessionId,
            nonce,
            1,
            pingPayload);
        var encoded = RdpDvcMessageCodec.Encode(
            ping,
            options.AuthenticationKey.Span,
            options.MaximumPayloadBytes);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await RunWithTimeoutAsync(
                    token => connection.Channel.WritePduAsync(
                            encoded,
                            token)
                        .AsTask(),
                    options.PingTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            var response = await RunWithTimeoutAsync(
                    token => connection.Channel.ReadPduAsync(token).AsTask(),
                    options.PingTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            stopwatch.Stop();
            var pong = RdpDvcMessageCodec.Decode(response, options);
            if (pong.Kind != RdpDvcMessageKind.Pong ||
                pong.Sequence != 1 ||
                pong.Nonce != nonce ||
                !CryptographicOperations.FixedTimeEquals(
                    pong.Payload.Span,
                    pingPayload))
                throw new RdpDvcProtocolException(
                    RdpDvcProtocolError.UnexpectedMessage,
                    "The Steward DVC PONG does not match its PING.");
            return new(
                new AuthenticatedRdpDvcStream(
                    connection.Channel,
                    options,
                    pong,
                    2,
                    2),
                ToResult(pong, stopwatch.Elapsed));
        }
        catch
        {
            await connection.Channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    public static async ValueTask<RdpDvcConnectedStream> RespondAsync(
        RdpDvcWireConnection connection,
        RdpDvcAuthenticationOptions options,
        CancellationToken cancellationToken = default)
    {
        options.Validate();
        try
        {
            var request = await RunWithTimeoutAsync(
                    token => connection.Channel.ReadPduAsync(token).AsTask(),
                    options.PingTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            var ping = RdpDvcMessageCodec.Decode(request, options);
            if (ping.Kind != RdpDvcMessageKind.Ping ||
                ping.Sequence != 1 ||
                ping.Nonce == Guid.Empty)
                throw new RdpDvcProtocolException(
                    RdpDvcProtocolError.UnexpectedMessage,
                    "The first Steward DVC message must be PING sequence one.");
            if (!RdpDvcReplayWindow.TryAccept(
                    ping.Nonce,
                    ping.Payload.Span,
                    ping.SentAtUtcTicks,
                    DateTimeOffset.UtcNow))
                throw new RdpDvcProtocolException(
                    RdpDvcProtocolError.AuthenticationFailed,
                    "The Steward DVC PING is stale or replayed.");
            if (connection.RdpSessionId.HasValue &&
                ping.RdpSessionId != connection.RdpSessionId.Value)
                throw new RdpDvcProtocolException(
                    RdpDvcProtocolError.BindingMismatch,
                    "The authenticated PING names another RDP session.");
            var pong = ping with
            {
                Kind = RdpDvcMessageKind.Pong,
                SentAtUtcTicks = DateTimeOffset.UtcNow.UtcTicks
            };
            var encoded = RdpDvcMessageCodec.Encode(
                pong,
                options.AuthenticationKey.Span,
                options.MaximumPayloadBytes);
            await RunWithTimeoutAsync(
                    token => connection.Channel.WritePduAsync(
                            encoded,
                            token)
                        .AsTask(),
                    options.PingTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            var rtt = TimeSpan.FromTicks(Math.Max(
                0,
                DateTimeOffset.UtcNow.UtcTicks - ping.SentAtUtcTicks));
            return new(
                new AuthenticatedRdpDvcStream(
                    connection.Channel,
                    options,
                    ping,
                    2,
                    2),
                ToResult(ping, rtt));
        }
        catch
        {
            await connection.Channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static RdpDvcMessage CreateMessage(
        RdpDvcMessageKind kind,
        RdpDvcPeerIdentity identity,
        int rdpSessionId,
        Guid nonce,
        long sequence,
        ReadOnlyMemory<byte> payload) =>
        new(
            kind,
            StewardRdpDvc.ProtocolVersion,
            identity.SessionId,
            identity.HostId,
            identity.NodeIncarnationId,
            rdpSessionId,
            nonce,
            sequence,
            DateTimeOffset.UtcNow.UtcTicks,
            payload);

    private static RdpDvcHandshakeResult ToResult(
        RdpDvcMessage message,
        TimeSpan roundTripTime) =>
        new(
            message.SessionId,
            message.HostId,
            message.NodeIncarnationId,
            message.RdpSessionId,
            message.Nonce,
            message.Sequence,
            roundTripTime);

    private static async Task RunWithTimeoutAsync(
        Func<CancellationToken, Task> action,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await action(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The authenticated Steward DVC PING/PONG timed out.");
        }
    }

    private static async Task<T> RunWithTimeoutAsync<T>(
        Func<CancellationToken, Task<T>> action,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            return await action(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The authenticated Steward DVC PING/PONG timed out.");
        }
    }
}

internal static class RdpDvcReplayWindow
{
    private const int MaximumRememberedNonces = 4096;
    private static readonly TimeSpan MaximumAge =
        TimeSpan.FromMinutes(5);
    private static readonly ConcurrentDictionary<Guid, long> Seen =
        new();
    private static readonly object Gate = new();

    internal static bool TryAccept(
        Guid nonce,
        ReadOnlySpan<byte> payload,
        long sentAtUtcTicks,
        DateTimeOffset now)
    {
        _ = payload;
        DateTimeOffset sentAt;
        try
        {
            sentAt = new DateTimeOffset(
                sentAtUtcTicks,
                TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
        if ((now - sentAt).Duration() > MaximumAge)
            return false;
        lock (Gate)
        {
            var oldest = now.Subtract(MaximumAge).UtcTicks;
            foreach (var entry in Seen)
            {
                if (entry.Value < oldest)
                    Seen.TryRemove(entry.Key, out _);
            }
            if (Seen.Count >= MaximumRememberedNonces)
                return false;
            return Seen.TryAdd(nonce, now.UtcTicks);
        }
    }
}

internal sealed class AuthenticatedRdpDvcStream : Stream
{
    private readonly IRdpDvcWireChannel _channel;
    private readonly RdpDvcAuthenticationOptions _options;
    private readonly RdpDvcPeerIdentity _identity;
    private readonly Guid _nonce;
    private readonly int _rdpSessionId;
    private readonly byte[] _authenticationKey;
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private byte[]? _currentRead;
    private int _currentReadOffset;
    private long _sendSequence;
    private long _receiveSequence;
    private int _reading;
    private int _disposed;

    internal AuthenticatedRdpDvcStream(
        IRdpDvcWireChannel channel,
        RdpDvcAuthenticationOptions options,
        RdpDvcMessage handshake,
        long sendSequence,
        long receiveSequence)
    {
        _channel = channel;
        _options = options;
        _identity = options.ExpectedPeer;
        _nonce = handshake.Nonce;
        _rdpSessionId = handshake.RdpSessionId;
        _authenticationKey = options.AuthenticationKey.ToArray();
        _sendSequence = sendSequence;
        _receiveSequence = receiveSequence;
    }

    public override bool CanRead => Volatile.Read(ref _disposed) == 0;
    public override bool CanSeek => false;
    public override bool CanWrite => Volatile.Read(ref _disposed) == 0;
    public override long Length =>
        throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() { }

    public override Task FlushAsync(
        CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count))
            .AsTask()
            .GetAwaiter()
            .GetResult();

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        if (buffer.IsEmpty)
            return 0;
        if (Interlocked.Exchange(ref _reading, 1) != 0)
            throw new InvalidOperationException(
                "Only one Steward DVC stream reader is supported.");
        try
        {
            if (_currentRead is null ||
                _currentReadOffset == _currentRead.Length)
            {
                var encoded = await RunWireAsync(
                        token => _channel.ReadPduAsync(token).AsTask(),
                        cancellationToken)
                    .ConfigureAwait(false);
                var message = RdpDvcMessageCodec.Decode(
                    encoded,
                    _options with
                    {
                        AuthenticationKey = _authenticationKey
                    });
                if (message.Kind != RdpDvcMessageKind.Data)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.UnexpectedMessage,
                        "Only DATA is valid after Steward DVC PING/PONG.");
                if (message.Nonce != _nonce ||
                    message.RdpSessionId != _rdpSessionId ||
                    message.Sequence != _receiveSequence)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.InvalidSequence,
                        "Steward DVC DATA is out of order or rebound.");
                _receiveSequence = checked(_receiveSequence + 1);
                _currentRead = message.Payload.ToArray();
                _currentReadOffset = 0;
            }

            var available = _currentRead.Length - _currentReadOffset;
            var count = Math.Min(buffer.Length, available);
            _currentRead.AsMemory(_currentReadOffset, count).CopyTo(buffer);
            _currentReadOffset += count;
            return count;
        }
        finally
        {
            Volatile.Write(ref _reading, 0);
        }
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count))
            .AsTask()
            .GetAwaiter()
            .GetResult();

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        if (buffer.IsEmpty)
            return;
        await _writeGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var count = Math.Min(
                    _options.MaximumPayloadBytes,
                    buffer.Length - offset);
                var message = new RdpDvcMessage(
                    RdpDvcMessageKind.Data,
                    StewardRdpDvc.ProtocolVersion,
                    _identity.SessionId,
                    _identity.HostId,
                    _identity.NodeIncarnationId,
                    _rdpSessionId,
                    _nonce,
                    _sendSequence,
                    DateTimeOffset.UtcNow.UtcTicks,
                    buffer.Slice(offset, count));
                var encoded = RdpDvcMessageCodec.Encode(
                    message,
                    _authenticationKey,
                    _options.MaximumPayloadBytes);
                await RunWireAsync(
                        token => _channel.WritePduAsync(
                                encoded,
                                token)
                            .AsTask(),
                        cancellationToken)
                    .ConfigureAwait(false);
                _sendSequence = checked(_sendSequence + 1);
                offset += count;
            }
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async Task RunWireAsync(
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        using var timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(_options.WireOperationTimeout);
        try
        {
            await action(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The Steward DVC stream operation timed out.");
        }
    }

    private async Task<T> RunWireAsync<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        using var timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(_options.WireOperationTimeout);
        try
        {
            return await action(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The Steward DVC stream operation timed out.");
        }
    }

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        CryptographicOperations.ZeroMemory(_authenticationKey);
        _writeGate.Dispose();
        await _channel.DisposeAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }
}

#if !RDP_DVC_SERVER_EMBEDDED
public sealed class RdpDvcTransportStreamConnector(
    IRdpDvcWireChannelSource source,
    RdpDvcAuthenticationOptions options,
    Action<RdpDvcHandshakeResult>? onAuthenticated = null) :
    ITransportStreamConnector
{
    public async ValueTask<Stream> ConnectStreamAsync(
        CancellationToken cancellationToken = default)
    {
        var channel = await source.OpenChannelAsync(cancellationToken)
            .ConfigureAwait(false);
        var connected = await RdpDvcStreamHandshake.InitiateAsync(
                channel,
                options,
                cancellationToken)
            .ConfigureAwait(false);
        onAuthenticated?.Invoke(connected.Handshake);
        return connected.Stream;
    }
}

public sealed class RdpDvcTransportStreamAcceptor(
    IRdpDvcWireChannelSource source,
    RdpDvcAuthenticationOptions options,
    Action<RdpDvcHandshakeResult>? onAuthenticated = null) :
    ITransportStreamAcceptor
{
    public async ValueTask<Stream> AcceptStreamAsync(
        CancellationToken cancellationToken = default)
    {
        var channel = await source.OpenChannelAsync(cancellationToken)
            .ConfigureAwait(false);
        var connected = await RdpDvcStreamHandshake.RespondAsync(
                channel,
                options,
                cancellationToken)
            .ConfigureAwait(false);
        onAuthenticated?.Invoke(connected.Handshake);
        return connected.Stream;
    }
}

public sealed class RdpDvcNamedPipeWireChannelSource(
    RdpDvcAuthenticationOptions routingAuthentication,
    string? pipeName = null,
    TimeSpan? connectTimeout = null) : IRdpDvcWireChannelSource
{
    private readonly TimeSpan _connectTimeout =
        connectTimeout ?? TimeSpan.FromSeconds(15);

    public RdpDvcNamedPipeWireChannelSource(
        string? pipeName = null,
        TimeSpan? connectTimeout = null) :
        this(null!, pipeName, connectTimeout)
    {
    }

    public async ValueTask<RdpDvcWireConnection> OpenChannelAsync(
        CancellationToken cancellationToken = default)
    {
        if (routingAuthentication is null)
            throw new InvalidOperationException(
                "Authenticated broker routing options are required.");
        var route =
            RdpDvcBrokerRoutingProtocol.RequireExactRoute(
                routingAuthentication);
        var resolvedPipeName =
            pipeName ?? StewardRdpDvc.CurrentUserPipeName();
        if (string.IsNullOrWhiteSpace(resolvedPipeName) ||
            resolvedPipeName.Length > 128 ||
            resolvedPipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new ArgumentException(
                "The Steward DVC broker pipe name is invalid.",
                nameof(pipeName));
        if (_connectTimeout <= TimeSpan.Zero ||
            _connectTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(connectTimeout));

        var pipe = new NamedPipeClientStream(
            ".",
            resolvedPipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(_connectTimeout);
        try
        {
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            var request =
                RdpDvcBrokerRoutingProtocol.EncodeRequest(route);
            await pipe.WriteAsync(request, timeout.Token)
                .ConfigureAwait(false);
            await pipe.FlushAsync(timeout.Token)
                .ConfigureAwait(false);
            var candidate =
                await RdpDvcBrokerRoutingProtocol.ReadCandidateAsync(
                        pipe,
                        timeout.Token)
                    .ConfigureAwait(false);
            var selectedWtsSessionId = 0;
            try
            {
                var ping = RdpDvcMessageCodec.Decode(
                    candidate,
                    routingAuthentication);
                if (ping.Kind != RdpDvcMessageKind.Ping ||
                    ping.Sequence != 1 ||
                    ping.Nonce !=
                        route.Identity.ConnectionNonce ||
                    ping.RdpSessionId <= 0 ||
                    !route.Identity.IsWtsWildcard &&
                    ping.RdpSessionId !=
                    route.Identity.RdpSessionId ||
                    !RdpDvcBrokerRoutingProtocol
                        .HasExpectedAuthenticator(
                            ping.Payload.Span,
                            route))
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.UnexpectedMessage,
                        "The routed Steward DVC candidate is not the expected PING.");
                selectedWtsSessionId = ping.RdpSessionId;
                await pipe.WriteAsync(
                        new byte[]
                        {
                            RdpDvcBrokerRoutingProtocol.Accepted
                        },
                        timeout.Token)
                    .ConfigureAwait(false);
                await pipe.FlushAsync(timeout.Token)
                    .ConfigureAwait(false);
            }
            catch
            {
                try
                {
                    await pipe.WriteAsync(
                            new byte[]
                            {
                                RdpDvcBrokerRoutingProtocol.Rejected
                            },
                            timeout.Token)
                        .ConfigureAwait(false);
                    await pipe.FlushAsync(timeout.Token)
                        .ConfigureAwait(false);
                }
                catch
                {
                }
                throw;
            }
            return new(
                new PrefetchedRdpDvcWireChannel(
                    new LengthPrefixedDvcWireChannel(pipe),
                    candidate),
                selectedWtsSessionId);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            pipe.Dispose();
            throw new TimeoutException(
                "The Steward DVC COM broker did not activate in time.");
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }

    internal sealed class PrefetchedRdpDvcWireChannel(
        IRdpDvcWireChannel inner,
        byte[] firstPdu) : IRdpDvcWireChannel
    {
        private byte[]? _firstPdu = firstPdu;

        public ValueTask WritePduAsync(
            ReadOnlyMemory<byte> pdu,
            CancellationToken cancellationToken = default) =>
            inner.WritePduAsync(pdu, cancellationToken);

        public ValueTask<byte[]> ReadPduAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var first = Interlocked.Exchange(ref _firstPdu, null);
            return first is not null
                ? ValueTask.FromResult(first)
                : inner.ReadPduAsync(cancellationToken);
        }

        public ValueTask DisposeAsync() =>
            inner.DisposeAsync();
    }
}

public sealed class LengthPrefixedDvcWireChannel(
    Stream stream,
    int maximumPduBytes =
        RdpDvcMessageCodec.MinimumEncodedSize +
        StewardRdpDvc.MaximumPayloadBytes) : IRdpDvcWireChannel
{
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private int _reading;
    private int _disposed;

    public async ValueTask WritePduAsync(
        ReadOnlyMemory<byte> pdu,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        if (pdu.Length <
                RdpDvcMessageCodec.MinimumEncodedSize ||
            pdu.Length > maximumPduBytes)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The broker PDU length exceeds its bound.");
        await _writeGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var header = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(header, pdu.Length);
            await stream.WriteAsync(header, cancellationToken)
                .ConfigureAwait(false);
            await stream.WriteAsync(pdu, cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public async ValueTask<byte[]> ReadPduAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        if (Interlocked.Exchange(ref _reading, 1) != 0)
            throw new InvalidOperationException(
                "Only one broker PDU reader is supported.");
        try
        {
            var header = new byte[4];
            await ReadExactlyAsync(
                    stream,
                    header,
                    cancellationToken)
                .ConfigureAwait(false);
            var length = BinaryPrimitives.ReadInt32BigEndian(header);
            if (length <
                    RdpDvcMessageCodec.MinimumEncodedSize ||
                length > maximumPduBytes)
                throw new RdpDvcProtocolException(
                    RdpDvcProtocolError.BoundsExceeded,
                    "The broker PDU declaration exceeds its bound.");
            var pdu = new byte[length];
            await ReadExactlyAsync(
                    stream,
                    pdu,
                    cancellationToken)
                .ConfigureAwait(false);
            return pdu;
        }
        finally
        {
            Volatile.Write(ref _reading, 0);
        }
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(
                    destination[offset..],
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException(
                    "The Steward DVC broker pipe closed.");
            offset += read;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        _writeGate.Dispose();
        await stream.DisposeAsync().ConfigureAwait(false);
    }
}
#endif
