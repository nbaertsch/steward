using System.Collections.Concurrent;
using System.Net;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace Steward.Transport.Local;

public sealed record DirectWebSocketOptions(
    Uri Endpoint,
    TransportEndpointRole Role,
    IEndpointSigningKey SigningKey,
    ExpectedPeerIdentity ExpectedPeer,
    bool AllowUnencryptedLoopback = false,
    int MaximumWireFrameBytes = 1024 * 1024 + 4096,
    int MaximumBufferedFrames = 256,
    long RekeyAfterFrames = 1_000_000,
    TimeSpan? ConnectTimeout = null,
    TimeSpan? HandshakeTimeout = null,
    TimeSpan? OperationTimeout = null,
    TimeSpan? MaximumSessionLifetime = null)
{
    public TimeSpan ConnectionTimeout => ConnectTimeout ?? TimeSpan.FromSeconds(15);
    public TimeSpan SecureHandshakeTimeout => HandshakeTimeout ?? TimeSpan.FromSeconds(10);
    public TimeSpan WireOperationTimeout => OperationTimeout ?? TimeSpan.FromSeconds(30);
    public TimeSpan SessionLifetime => MaximumSessionLifetime ?? TimeSpan.FromHours(1);
    internal Uri NormalizedEndpoint
    {
        get
        {
            if (Endpoint.AbsolutePath.EndsWith('/'))
                return Endpoint;
            var builder = new UriBuilder(Endpoint) { Path = Endpoint.AbsolutePath + "/" };
            return builder.Uri;
        }
    }

    internal void Validate()
    {
        if (!Endpoint.IsAbsoluteUri ||
            Endpoint.Scheme is not ("ws" or "wss") ||
            !string.IsNullOrEmpty(Endpoint.UserInfo) ||
            !string.IsNullOrEmpty(Endpoint.Query) ||
            !string.IsNullOrEmpty(Endpoint.Fragment))
            throw new ArgumentException("The direct endpoint must be an absolute ws or wss URI without credentials, query, or fragment.");
        if (Endpoint.Scheme == "ws" && (!Endpoint.IsLoopback || !AllowUnencryptedLoopback))
            throw new ArgumentException("Direct endpoints require wss; ws must be explicitly enabled for loopback local development.");
        if (!Enum.IsDefined(Role))
            throw new ArgumentOutOfRangeException(nameof(Role));
        _ = ExpectedPeer.Validate();
        if (SigningKey is null || string.IsNullOrWhiteSpace(SigningKey.Identity))
            throw new ArgumentException("A local endpoint signing identity is required.");
        if (MaximumWireFrameBytes is < 128 or > 16 * 1024 * 1024 ||
            MaximumBufferedFrames is < 1 or > 65536 ||
            RekeyAfterFrames <= 0)
            throw new ArgumentOutOfRangeException(nameof(MaximumWireFrameBytes));
        ValidateTimeout(ConnectionTimeout, nameof(ConnectTimeout));
        ValidateTimeout(SecureHandshakeTimeout, nameof(HandshakeTimeout));
        ValidateTimeout(WireOperationTimeout, nameof(OperationTimeout));
        ValidateTimeout(SessionLifetime, nameof(MaximumSessionLifetime), TimeSpan.FromDays(1));
    }

    private static void ValidateTimeout(TimeSpan value, string name, TimeSpan? maximum = null)
    {
        if (value <= TimeSpan.Zero || value > (maximum ?? TimeSpan.FromMinutes(5)))
            throw new ArgumentOutOfRangeException(name);
    }
}

public sealed class DirectWebSocketCarrier(
    DirectWebSocketOptions options,
    Func<ClientWebSocket>? socketFactory = null) : ITransportCarrier, IAsyncDisposable
{
    private int _disposed;

    public async ValueTask<ITransportConnection> ConnectAsync(
        SessionHello hello,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        options.Validate();
        var socket = socketFactory?.Invoke() ?? new ClientWebSocket();
        try
        {
            await DirectWebSocketSession.RunWithTimeoutAsync(
                token => socket.ConnectAsync(options.NormalizedEndpoint, token),
                options.ConnectionTimeout,
                cancellationToken);
            return await DirectWebSocketSession.EstablishAsync(socket, hello, options, cancellationToken);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0 &&
            options.SigningKey is IDisposable disposable)
            disposable.Dispose();
        return ValueTask.CompletedTask;
    }
}

public sealed class DirectWebSocketConnectionAcceptor : ITransportConnectionAcceptor
{
    private readonly DirectWebSocketOptions _options;
    private readonly HttpListener _listener = new();
    private Task<HttpListenerContext>? _pendingContext;
    private int _accepting;
    private int _disposed;

    public DirectWebSocketConnectionAcceptor(DirectWebSocketOptions options)
    {
        options.Validate();
        _options = options;
        _listener.Prefixes.Add(ToListenerPrefix(options.Endpoint));
        _listener.Start();
    }

    public async ValueTask<ITransportConnection> AcceptAsync(
        SessionHello hello,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.Exchange(ref _accepting, 1) != 0)
            throw new InvalidOperationException("Only one concurrent direct connection accept is supported.");

        HttpListenerContext? context = null;
        WebSocket? socket = null;
        try
        {
            _pendingContext ??= _listener.GetContextAsync();
            context = await DirectWebSocketSession.RunWithTimeoutAsync(
                token => _pendingContext.WaitAsync(token),
                _options.ConnectionTimeout,
                cancellationToken);
            _pendingContext = null;
            if (!context.Request.IsWebSocketRequest)
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                context.Response.Close();
                throw new WebSocketException("The direct endpoint requires a WebSocket upgrade.");
            }

            var webSocketContext = await DirectWebSocketSession.RunWithTimeoutAsync(
                token => context.AcceptWebSocketAsync(null).WaitAsync(token),
                _options.SecureHandshakeTimeout,
                cancellationToken);
            socket = webSocketContext.WebSocket;
            return await DirectWebSocketSession.EstablishAsync(socket, hello, _options, cancellationToken);
        }
        catch
        {
            if (_pendingContext?.IsCompleted == true)
                _pendingContext = null;
            if (socket is null)
            {
                try { context?.Response.Abort(); }
                catch (ObjectDisposedException) { }
            }
            socket?.Dispose();
            throw;
        }
        finally
        {
            Volatile.Write(ref _accepting, 0);
        }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _listener.Close();
            if (_options.SigningKey is IDisposable disposable)
                disposable.Dispose();
        }
        return ValueTask.CompletedTask;
    }

    private static string ToListenerPrefix(Uri endpoint)
    {
        var builder = new UriBuilder(endpoint)
        {
            Scheme = endpoint.Scheme == "wss" ? Uri.UriSchemeHttps : Uri.UriSchemeHttp,
            Path = endpoint.AbsolutePath.EndsWith('/') ? endpoint.AbsolutePath : endpoint.AbsolutePath + "/"
        };
        return builder.Uri.AbsoluteUri;
    }
}

internal static class DirectWebSocketSession
{
    internal static async ValueTask<ITransportConnection> EstablishAsync(
        WebSocket socket,
        SessionHello hello,
        DirectWebSocketOptions options,
        CancellationToken cancellationToken)
    {
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var localHandshake = SecureTransportProtocol.CreateHandshake(
            options.Role, options.SigningKey, hello, ephemeral);
        var handshakeLimit = Math.Min(
            SecureTransportProtocol.MaximumHandshakeBytes,
            options.MaximumWireFrameBytes);
        if (localHandshake.Length > handshakeLimit)
            throw new SecureHandshakeException(
                SecureHandshakeError.BoundsExceeded,
                "The local handshake exceeds the direct carrier limit.");
        await RunWithTimeoutAsync(
            token => socket.SendAsync(localHandshake, WebSocketMessageType.Binary, true, token),
            options.SecureHandshakeTimeout,
            cancellationToken);
        var remoteRecord = await RunWithTimeoutAsync(
            token => ReceiveRecordAsync(socket, handshakeLimit, token),
            options.SecureHandshakeTimeout,
            cancellationToken);
        var remoteHandshake = SecureTransportProtocol.ParseAndVerifyHandshake(
            remoteRecord, options.Role, options.ExpectedPeer.Validate(), hello);
        var keys = SecureTransportProtocol.DeriveKeys(
            ephemeral, remoteHandshake, localHandshake, remoteRecord, options.Role);
        try
        {
            var remoteHello = SecureTransportProtocol.FromWire(remoteHandshake.Hello);
            var security = new VerifiedSessionSecurity(
                true, true, options.SigningKey.Identity, remoteHandshake.Identity, keys.Binding);
            var session = SessionNegotiator.Negotiate(hello, remoteHello, security);
            return new DirectWebSocketConnection(socket, session, options, keys.Send, keys.Receive);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(keys.Send);
            CryptographicOperations.ZeroMemory(keys.Receive);
            throw;
        }
    }

    internal static async Task<byte[]> ReceiveRecordAsync(
        WebSocket socket,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var record = new MemoryStream();
        var chunk = new byte[Math.Min(maximumBytes + 1, 16 * 1024)];
        WebSocketReceiveResult result;
        do
        {
            result = await socket.ReceiveAsync(chunk, cancellationToken);
            if (result.MessageType == WebSocketMessageType.Close)
                throw new WebSocketException("The peer closed the direct transport.");
            if (result.MessageType != WebSocketMessageType.Binary ||
                record.Length + result.Count > maximumBytes)
                throw new TransportProtocolException(
                    TransportError.PayloadTooLarge,
                    "The direct transport record is invalid or too large.");
            record.Write(chunk, 0, result.Count);
        } while (!result.EndOfMessage);
        return record.ToArray();
    }

    internal static async Task RunWithTimeoutAsync(
        Func<CancellationToken, Task> operation,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await operation(timeoutSource.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The direct transport operation timed out.");
        }
    }

    internal static async Task<T> RunWithTimeoutAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            return await operation(timeoutSource.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The direct transport operation timed out.");
        }
    }
}

internal sealed class DirectWebSocketConnection : ITransportConnection
{
    private sealed record PendingSend(TransportFrame Frame, TaskCompletionSource? Completion);

    private readonly WebSocket _socket;
    private readonly DirectWebSocketOptions _options;
    private readonly byte[] _sendKey;
    private readonly byte[] _receiveKey;
    private readonly ConcurrentDictionary<StreamKind, long> _sent;
    private readonly ConcurrentDictionary<StreamKind, long> _received;
    private readonly SemaphoreSlim _enqueueGate = new(1, 1);
    private readonly Channel<PendingSend> _outbound;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _sendPump;
    private readonly DateTimeOffset _expiresAt;
    private long _sendRecord;
    private long _receiveRecord;
    private int _receiving;
    private int _disposed;

    internal DirectWebSocketConnection(
        WebSocket socket,
        NegotiatedSession session,
        DirectWebSocketOptions options,
        byte[] sendKey,
        byte[] receiveKey)
    {
        _socket = socket;
        Session = session;
        _options = options;
        _sendKey = sendKey;
        _receiveKey = receiveKey;
        _sent = new(session.RemoteResumeCursors);
        _received = new(session.LocalResumeCursors);
        _expiresAt = DateTimeOffset.UtcNow + options.SessionLifetime;
        _outbound = Channel.CreateBounded<PendingSend>(new BoundedChannelOptions(
            Math.Min(session.Limits.MaximumBufferedFrames, options.MaximumBufferedFrames))
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
        _sendPump = PumpSendsAsync();
    }

    public NegotiatedSession Session { get; }

    public async ValueTask SendAsync(
        TransportFrame frame,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var completion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = new PendingSend(frame, completion);
        await _enqueueGate.WaitAsync(cancellationToken);
        try
        {
            ValidateFrame(frame, _sent);
            await _outbound.Writer.WriteAsync(pending, cancellationToken);
            _sent[frame.Stream] = frame.Sequence;
        }
        finally
        {
            _enqueueGate.Release();
        }
        await completion.Task.WaitAsync(cancellationToken);
    }

    public bool TrySend(TransportFrame frame)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (!_enqueueGate.Wait(0))
            return false;
        try
        {
            ValidateFrame(frame, _sent);
            var pending = new PendingSend(frame, null);
            if (!_outbound.Writer.TryWrite(pending))
                return false;
            _sent[frame.Stream] = frame.Sequence;
            return true;
        }
        finally
        {
            _enqueueGate.Release();
        }
    }

    public async IAsyncEnumerable<TransportFrame> ReceiveAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _receiving, 1) != 0)
            throw new InvalidOperationException("Only one direct transport receiver is supported.");
        try
        {
            while (_socket.State == WebSocketState.Open)
            {
                ThrowIfExpired();
                var record = await DirectWebSocketSession.ReceiveRecordAsync(
                    _socket,
                    _options.MaximumWireFrameBytes,
                    cancellationToken);
                var recordSequence = checked(++_receiveRecord);
                if (recordSequence > _options.RekeyAfterFrames)
                    throw new CryptographicException("The receive key usage limit was reached; reconnect to rekey.");
                var remoteRole = _options.Role == TransportEndpointRole.Control
                    ? TransportEndpointRole.Node
                    : TransportEndpointRole.Control;
                var plaintext = SecureTransportProtocol.Decrypt(
                    _receiveKey, remoteRole, Session.SessionId, recordSequence, record);
                TransportFrame frame;
                try
                {
                    frame = SecureTransportProtocol.DeserializeFrame(plaintext);
                    ValidateFrame(frame, _received);
                    _received[frame.Stream] = frame.Sequence;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }
                yield return frame;
            }
        }
        finally
        {
            Volatile.Write(ref _receiving, 0);
        }
    }

    private async Task PumpSendsAsync()
    {
        Exception? failure = null;
        try
        {
            await foreach (var pending in _outbound.Reader.ReadAllAsync(_lifetime.Token))
            {
                try
                {
                    ThrowIfExpired();
                    var sequence = checked(++_sendRecord);
                    if (sequence > _options.RekeyAfterFrames)
                        throw new CryptographicException("The send key usage limit was reached; reconnect to rekey.");
                    var plaintext = SecureTransportProtocol.SerializeFrame(pending.Frame);
                    byte[] encrypted;
                    try
                    {
                        if (plaintext.Length + 25 > _options.MaximumWireFrameBytes)
                            throw new TransportProtocolException(
                                TransportError.PayloadTooLarge,
                                "The encrypted frame exceeds the direct carrier limit.");
                        encrypted = SecureTransportProtocol.Encrypt(
                            _sendKey, _options.Role, Session.SessionId, sequence, plaintext);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                    }
                    await DirectWebSocketSession.RunWithTimeoutAsync(
                        token => _socket.SendAsync(
                            encrypted, WebSocketMessageType.Binary, true, token),
                        _options.WireOperationTimeout,
                        _lifetime.Token);
                    pending.Completion?.TrySetResult();
                }
                catch (Exception ex)
                {
                    pending.Completion?.TrySetException(ex);
                    throw;
                }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            failure = ex;
            _outbound.Writer.TryComplete(ex);
        }
        finally
        {
            while (_outbound.Reader.TryRead(out var pending))
            {
                if (failure is null)
                    pending.Completion?.TrySetCanceled(_lifetime.Token);
                else
                    pending.Completion?.TrySetException(failure);
            }
        }
    }

    private void ValidateFrame(
        TransportFrame frame,
        ConcurrentDictionary<StreamKind, long> cursors)
    {
        if (frame.SessionId != Session.SessionId ||
            frame.NodeIncarnationId != Session.NodeIncarnationId)
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "Frame binding differs from the secure session.");
        if (frame.Payload.Length > Session.Limits.MaximumPayloadBytes)
            throw new TransportProtocolException(
                TransportError.PayloadTooLarge,
                "Frame payload exceeds the negotiated limit.");
        if (frame.Payload.Length > _options.MaximumWireFrameBytes - 78)
            throw new TransportProtocolException(
                TransportError.PayloadTooLarge,
                "Frame payload exceeds the direct carrier limit.");
        if (frame.Cursor < 0 ||
            frame.Sequence != cursors.GetValueOrDefault(frame.Stream) + 1)
            throw new TransportProtocolException(
                TransportError.InvalidSequence,
                "Frame sequence is not contiguous.");
    }

    private void ThrowIfExpired()
    {
        if (DateTimeOffset.UtcNow >= _expiresAt)
            throw new CryptographicException("The secure session expired; reconnect to rekey.");
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        _outbound.Writer.TryComplete();
        _lifetime.Cancel();
        try
        {
            await _sendPump;
            if (_socket.State == WebSocketState.Open)
                await _socket.CloseOutputAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "closed",
                    CancellationToken.None);
        }
        catch (Exception ex) when (
            ex is WebSocketException or IOException or ObjectDisposedException or OperationCanceledException)
        { }
        _socket.Dispose();
        _enqueueGate.Dispose();
        _lifetime.Dispose();
        CryptographicOperations.ZeroMemory(_sendKey);
        CryptographicOperations.ZeroMemory(_receiveKey);
    }
}
