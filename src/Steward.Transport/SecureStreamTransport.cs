using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Steward.Transport;

public interface ITransportStreamConnector
{
    ValueTask<Stream> ConnectStreamAsync(
        CancellationToken cancellationToken = default);
}

public interface ITransportStreamAcceptor
{
    ValueTask<Stream> AcceptStreamAsync(
        CancellationToken cancellationToken = default);
}

public sealed record SecureStreamTransportOptions(
    TransportEndpointRole Role,
    IEndpointSigningKey SigningKey,
    ExpectedPeerIdentity ExpectedPeer,
    int MaximumWireRecordBytes = 1024 * 1024 + 4096,
    long RekeyAfterFrames = 1_000_000,
    TimeSpan? HandshakeTimeout = null,
    TimeSpan? OperationTimeout = null,
    TimeSpan? MaximumSessionLifetime = null)
{
    public TimeSpan SecureHandshakeTimeout =>
        HandshakeTimeout ?? TimeSpan.FromSeconds(10);

    public TimeSpan WireOperationTimeout =>
        OperationTimeout ?? TimeSpan.FromSeconds(30);

    public TimeSpan SessionLifetime =>
        MaximumSessionLifetime ?? TimeSpan.FromHours(1);

    internal void Validate()
    {
        if (!Enum.IsDefined(Role))
            throw new ArgumentOutOfRangeException(nameof(Role));
        if (SigningKey is null ||
            string.IsNullOrWhiteSpace(SigningKey.Identity))
            throw new ArgumentException(
                "A local endpoint signing identity is required.");
        _ = ExpectedPeer.Validate();
        if (MaximumWireRecordBytes is < 128 or > 16 * 1024 * 1024 ||
            RekeyAfterFrames <= 0)
            throw new ArgumentOutOfRangeException(nameof(MaximumWireRecordBytes));
        ValidateTimeout(
            SecureHandshakeTimeout,
            nameof(HandshakeTimeout),
            TimeSpan.FromMinutes(5));
        ValidateTimeout(
            WireOperationTimeout,
            nameof(OperationTimeout),
            TimeSpan.FromMinutes(5));
        ValidateTimeout(
            SessionLifetime,
            nameof(MaximumSessionLifetime),
            TimeSpan.FromDays(1));
    }

    private static void ValidateTimeout(
        TimeSpan value,
        string name,
        TimeSpan maximum)
    {
        if (value <= TimeSpan.Zero || value > maximum)
            throw new ArgumentOutOfRangeException(name);
    }
}

public sealed class SecureStreamCarrier(
    ITransportStreamConnector connector,
    SecureStreamTransportOptions options) :
    ITransportCarrier,
    IAsyncDisposable
{
    private int _disposed;

    public async ValueTask<ITransportConnection> ConnectAsync(
        SessionHello hello,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        options.Validate();
        var stream = await connector.ConnectStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return await SecureStreamSession.EstablishAsync(
                    stream,
                    hello,
                    options,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
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

public sealed class SecureStreamConnectionAcceptor(
    ITransportStreamAcceptor acceptor,
    SecureStreamTransportOptions options) :
    ITransportConnectionAcceptor
{
    private int _accepting;
    private int _disposed;

    public async ValueTask<ITransportConnection> AcceptAsync(
        SessionHello hello,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        if (Interlocked.Exchange(ref _accepting, 1) != 0)
            throw new InvalidOperationException(
                "Only one concurrent stream connection accept is supported.");

        Stream? stream = null;
        try
        {
            options.Validate();
            stream = await acceptor.AcceptStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            return await SecureStreamSession.EstablishAsync(
                    stream,
                    hello,
                    options,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            if (stream is not null)
                await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            Volatile.Write(ref _accepting, 0);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        if (acceptor is IAsyncDisposable asyncDisposable)
            await asyncDisposable.DisposeAsync().ConfigureAwait(false);
        else if (acceptor is IDisposable disposable)
            disposable.Dispose();
        if (options.SigningKey is IDisposable signingKey)
            signingKey.Dispose();
    }
}

internal static class SecureStreamSession
{
    internal static async ValueTask<ITransportConnection> EstablishAsync(
        Stream stream,
        SessionHello hello,
        SecureStreamTransportOptions options,
        CancellationToken cancellationToken)
    {
        if (!stream.CanRead || !stream.CanWrite)
            throw new ArgumentException(
                "The transport stream must be readable and writable.",
                nameof(stream));

        using var ephemeral =
            ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var localHandshake = SecureTransportProtocol.CreateHandshake(
            options.Role,
            options.SigningKey,
            hello,
            ephemeral);
        var handshakeLimit = Math.Min(
            SecureTransportProtocol.MaximumHandshakeBytes,
            options.MaximumWireRecordBytes);
        await RunWithTimeoutAsync(
                token => WriteRecordAsync(
                    stream,
                    localHandshake,
                    handshakeLimit,
                    token),
                options.SecureHandshakeTimeout,
                cancellationToken)
            .ConfigureAwait(false);
        var remoteRecord = await RunWithTimeoutAsync(
                token => ReadRecordAsync(stream, handshakeLimit, token),
                options.SecureHandshakeTimeout,
                cancellationToken)
            .ConfigureAwait(false);
        var remoteHandshake =
            SecureTransportProtocol.ParseAndVerifyHandshake(
                remoteRecord,
                options.Role,
                options.ExpectedPeer.Validate(),
                hello);
        var keys = SecureTransportProtocol.DeriveKeys(
            ephemeral,
            remoteHandshake,
            localHandshake,
            remoteRecord,
            options.Role);
        try
        {
            var remoteHello =
                SecureTransportProtocol.FromWire(remoteHandshake.Hello);
            var security = new VerifiedSessionSecurity(
                true,
                true,
                options.SigningKey.Identity,
                remoteHandshake.Identity,
                keys.Binding);
            var session = SessionNegotiator.Negotiate(
                hello,
                remoteHello,
                security);
            return new SecureStreamConnection(
                stream,
                session,
                options,
                keys.Send,
                keys.Receive);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(keys.Send);
            CryptographicOperations.ZeroMemory(keys.Receive);
            throw;
        }
    }

    internal static async Task WriteRecordAsync(
        Stream stream,
        ReadOnlyMemory<byte> record,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (record.Length <= 0 || record.Length > maximumBytes)
            throw new TransportProtocolException(
                TransportError.PayloadTooLarge,
                "The stream transport record exceeds its bound.");
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, record.Length);
        await stream.WriteAsync(header, cancellationToken)
            .ConfigureAwait(false);
        await stream.WriteAsync(record, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<byte[]> ReadRecordAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await ReadExactlyAsync(stream, header, cancellationToken)
            .ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length <= 0 || length > maximumBytes)
            throw new TransportProtocolException(
                TransportError.PayloadTooLarge,
                "The stream transport record length is invalid.");
        var record = new byte[length];
        await ReadExactlyAsync(stream, record, cancellationToken)
            .ConfigureAwait(false);
        return record;
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
                    "The stream transport closed during a record.");
            offset += read;
        }
    }

    internal static async Task RunWithTimeoutAsync(
        Func<CancellationToken, Task> operation,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await operation(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The secure stream transport operation timed out.");
        }
    }

    internal static async Task<T> RunWithTimeoutAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            return await operation(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The secure stream transport operation timed out.");
        }
    }
}

internal sealed class SecureStreamConnection : ITransportConnection
{
    private readonly Stream _stream;
    private readonly SecureStreamTransportOptions _options;
    private readonly byte[] _sendKey;
    private readonly byte[] _receiveKey;
    private readonly ConcurrentDictionary<StreamKind, long> _sent;
    private readonly ConcurrentDictionary<StreamKind, long> _received;
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly DateTimeOffset _expiresAt;
    private long _sendRecord;
    private long _receiveRecord;
    private int _receiving;
    private int _disposed;

    internal SecureStreamConnection(
        Stream stream,
        NegotiatedSession session,
        SecureStreamTransportOptions options,
        byte[] sendKey,
        byte[] receiveKey)
    {
        _stream = stream;
        Session = session;
        _options = options;
        _sendKey = sendKey;
        _receiveKey = receiveKey;
        _sent = new(session.RemoteResumeCursors);
        _received = new(session.LocalResumeCursors);
        _expiresAt = DateTimeOffset.UtcNow + options.SessionLifetime;
    }

    public NegotiatedSession Session { get; }

    public async ValueTask SendAsync(
        TransportFrame frame,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfExpired();
            ValidateFrame(frame, _sent);
            var sequence = checked(++_sendRecord);
            if (sequence > _options.RekeyAfterFrames)
                throw new CryptographicException(
                    "The send key usage limit was reached; reconnect to rekey.");
            var plaintext = SecureTransportProtocol.SerializeFrame(frame);
            byte[] encrypted;
            try
            {
                encrypted = SecureTransportProtocol.Encrypt(
                    _sendKey,
                    _options.Role,
                    Session.SessionId,
                    sequence,
                    plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
            await SecureStreamSession.RunWithTimeoutAsync(
                    token => SecureStreamSession.WriteRecordAsync(
                        _stream,
                        encrypted,
                        _options.MaximumWireRecordBytes,
                        token),
                    _options.WireOperationTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            _sent[frame.Stream] = frame.Sequence;
        }
        finally
        {
            _sendGate.Release();
        }
    }

    public bool TrySend(TransportFrame frame)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        ValidateFrame(frame, _sent);
        return false;
    }

    public async IAsyncEnumerable<TransportFrame> ReceiveAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        if (Interlocked.Exchange(ref _receiving, 1) != 0)
            throw new InvalidOperationException(
                "Only one secure stream receiver is supported.");
        try
        {
            while (true)
            {
                ThrowIfExpired();
                var record = await SecureStreamSession.ReadRecordAsync(
                        _stream,
                        _options.MaximumWireRecordBytes,
                        cancellationToken)
                    .ConfigureAwait(false);
                var sequence = checked(++_receiveRecord);
                if (sequence > _options.RekeyAfterFrames)
                    throw new CryptographicException(
                        "The receive key usage limit was reached; reconnect to rekey.");
                var remoteRole =
                    _options.Role == TransportEndpointRole.Control
                        ? TransportEndpointRole.Node
                        : TransportEndpointRole.Control;
                var plaintext = SecureTransportProtocol.Decrypt(
                    _receiveKey,
                    remoteRole,
                    Session.SessionId,
                    sequence,
                    record);
                TransportFrame frame;
                try
                {
                    frame =
                        SecureTransportProtocol.DeserializeFrame(plaintext);
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

    private void ValidateFrame(
        TransportFrame frame,
        ConcurrentDictionary<StreamKind, long> cursors)
    {
        if (frame.SessionId != Session.SessionId ||
            frame.NodeIncarnationId != Session.NodeIncarnationId)
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "Frame binding differs from the secure stream session.");
        if (frame.Payload.Length > Session.Limits.MaximumPayloadBytes)
            throw new TransportProtocolException(
                TransportError.PayloadTooLarge,
                "Frame payload exceeds the negotiated limit.");
        var prior = cursors.GetValueOrDefault(frame.Stream, 0);
        if (frame.Sequence != prior + 1 || frame.Cursor < 0)
            throw new TransportProtocolException(
                TransportError.InvalidSequence,
                "Frame sequence is not contiguous.");
    }

    private void ThrowIfExpired()
    {
        if (DateTimeOffset.UtcNow >= _expiresAt)
            throw new CryptographicException(
                "The secure stream session lifetime was reached; reconnect to rekey.");
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        CryptographicOperations.ZeroMemory(_sendKey);
        CryptographicOperations.ZeroMemory(_receiveKey);
        _sendGate.Dispose();
        await _stream.DisposeAsync().ConfigureAwait(false);
    }
}
