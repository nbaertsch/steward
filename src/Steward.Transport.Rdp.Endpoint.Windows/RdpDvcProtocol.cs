using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Steward.Transport.Rdp.Windows;

public enum RdpDvcMessageKind : byte
{
    Ping = 1,
    Pong = 2,
    Data = 3
}

public enum RdpDvcProtocolError
{
    Malformed,
    UnsupportedVersion,
    BoundsExceeded,
    AuthenticationFailed,
    BindingMismatch,
    InvalidSequence,
    UnexpectedMessage
}

public sealed class RdpDvcProtocolException(
    RdpDvcProtocolError error,
    string message) : IOException(message)
{
    public RdpDvcProtocolError Error { get; } = error;
}

public sealed record RdpDvcPeerIdentity(
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    int? RdpSessionId = null,
    Guid? ConnectionNonce = null)
{
    public RdpDvcPeerIdentity Validate()
    {
        if (SessionId == Guid.Empty ||
            HostId == Guid.Empty ||
            NodeIncarnationId == Guid.Empty ||
            RdpSessionId is < 0 ||
            ConnectionNonce == Guid.Empty)
            throw new ArgumentException(
                "The DVC peer identity binding is invalid.");
        return this;
    }
}

public sealed record RdpDvcMessage(
    RdpDvcMessageKind Kind,
    ushort Version,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    int RdpSessionId,
    Guid Nonce,
    long Sequence,
    long SentAtUtcTicks,
    ReadOnlyMemory<byte> Payload);

public sealed record RdpDvcAuthenticationOptions(
    RdpDvcPeerIdentity ExpectedPeer,
    ReadOnlyMemory<byte> AuthenticationKey,
    int MaximumPayloadBytes = StewardRdpDvc.MaximumPayloadBytes,
    TimeSpan? HandshakeTimeout = null,
    TimeSpan? OperationTimeout = null)
{
    public TimeSpan PingTimeout =>
        HandshakeTimeout ?? TimeSpan.FromSeconds(15);

    public TimeSpan WireOperationTimeout =>
        OperationTimeout ?? TimeSpan.FromSeconds(30);

    internal void Validate()
    {
        _ = ExpectedPeer.Validate();
        if (AuthenticationKey.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC authentication key must contain 32 through 64 bytes.");
        if (MaximumPayloadBytes is <= 0 or > StewardRdpDvc.MaximumPayloadBytes)
            throw new ArgumentOutOfRangeException(nameof(MaximumPayloadBytes));
        ValidateTimeout(PingTimeout, nameof(HandshakeTimeout));
        ValidateTimeout(WireOperationTimeout, nameof(OperationTimeout));
    }

    private static void ValidateTimeout(TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero || value > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(name);
    }
}

public static class RdpDvcMessageCodec
{
    internal const int HeaderSize = 96;
    internal const int AuthenticationTagSize = 32;
    internal const int MinimumEncodedSize =
        HeaderSize + AuthenticationTagSize;
    private static ReadOnlySpan<byte> Magic =>
        "SDVC"u8;

    public static byte[] Encode(
        RdpDvcMessage message,
        ReadOnlySpan<byte> authenticationKey,
        int maximumPayloadBytes = StewardRdpDvc.MaximumPayloadBytes)
    {
        ValidateLocal(message, authenticationKey, maximumPayloadBytes);
        var result = new byte[
            HeaderSize + message.Payload.Length + AuthenticationTagSize];
        Magic.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(
            result.AsSpan(4, 2),
            message.Version);
        result[6] = (byte)message.Kind;
        result[7] = 0;
        BinaryPrimitives.WriteInt32BigEndian(
            result.AsSpan(8, 4),
            message.Payload.Length);
        BinaryPrimitives.WriteInt64BigEndian(
            result.AsSpan(12, 8),
            message.Sequence);
        BinaryPrimitives.WriteInt64BigEndian(
            result.AsSpan(20, 8),
            message.SentAtUtcTicks);
        BinaryPrimitives.WriteInt32BigEndian(
            result.AsSpan(28, 4),
            message.RdpSessionId);
        message.SessionId.TryWriteBytes(result.AsSpan(32, 16));
        message.HostId.TryWriteBytes(result.AsSpan(48, 16));
        message.NodeIncarnationId.TryWriteBytes(
            result.AsSpan(64, 16));
        message.Nonce.TryWriteBytes(result.AsSpan(80, 16));
        message.Payload.Span.CopyTo(result.AsSpan(HeaderSize));
        var authenticatedLength = result.Length - AuthenticationTagSize;
        HMACSHA256.HashData(
            authenticationKey,
            result.AsSpan(0, authenticatedLength),
            result.AsSpan(authenticatedLength));
        return result;
    }

    public static RdpDvcMessage Decode(
        ReadOnlySpan<byte> encoded,
        RdpDvcAuthenticationOptions options)
    {
        options.Validate();
        if (encoded.Length < MinimumEncodedSize ||
            !encoded[..4].SequenceEqual(Magic) ||
            encoded[7] != 0)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.Malformed,
                "The Steward DVC message header is malformed.");

        var payloadLength =
            BinaryPrimitives.ReadInt32BigEndian(encoded.Slice(8, 4));
        if (payloadLength < 0 ||
            payloadLength > options.MaximumPayloadBytes ||
            encoded.Length !=
            HeaderSize + payloadLength + AuthenticationTagSize)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The Steward DVC message length exceeds its bound.");

        Span<byte> expectedTag = stackalloc byte[AuthenticationTagSize];
        HMACSHA256.HashData(
            options.AuthenticationKey.Span,
            encoded[..^AuthenticationTagSize],
            expectedTag);
        if (!CryptographicOperations.FixedTimeEquals(
                expectedTag,
                encoded[^AuthenticationTagSize..]))
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.AuthenticationFailed,
                "The Steward DVC message authentication tag is invalid.");

        var version =
            BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(4, 2));
        if (version != StewardRdpDvc.ProtocolVersion)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.UnsupportedVersion,
                "The Steward DVC protocol version is unsupported.");
        var kind = (RdpDvcMessageKind)encoded[6];
        if (!Enum.IsDefined(kind))
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.Malformed,
                "The Steward DVC message kind is undefined.");

        var message = new RdpDvcMessage(
            kind,
            version,
            new Guid(encoded.Slice(32, 16)),
            new Guid(encoded.Slice(48, 16)),
            new Guid(encoded.Slice(64, 16)),
            BinaryPrimitives.ReadInt32BigEndian(encoded.Slice(28, 4)),
            new Guid(encoded.Slice(80, 16)),
            BinaryPrimitives.ReadInt64BigEndian(encoded.Slice(12, 8)),
            BinaryPrimitives.ReadInt64BigEndian(encoded.Slice(20, 8)),
            encoded.Slice(HeaderSize, payloadLength).ToArray());
        ValidatePeer(message, options.ExpectedPeer);
        if (message.Kind is RdpDvcMessageKind.Ping or RdpDvcMessageKind.Pong &&
            message.Payload.Length > StewardRdpDvc.MaximumPingPayloadBytes)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The Steward DVC ping payload exceeds its bound.");
        return message;
    }

    internal static int GetEncodedLength(
        ReadOnlySpan<byte> header,
        int maximumPayloadBytes)
    {
        if (header.Length < HeaderSize ||
            !header[..4].SequenceEqual(Magic))
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.Malformed,
                "The Steward DVC fragment header is malformed.");
        var payloadLength =
            BinaryPrimitives.ReadInt32BigEndian(header.Slice(8, 4));
        if (payloadLength < 0 || payloadLength > maximumPayloadBytes)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The Steward DVC fragment length exceeds its bound.");
        return checked(HeaderSize + payloadLength + AuthenticationTagSize);
    }

    private static void ValidateLocal(
        RdpDvcMessage message,
        ReadOnlySpan<byte> authenticationKey,
        int maximumPayloadBytes)
    {
        if (message.Version != StewardRdpDvc.ProtocolVersion)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.UnsupportedVersion,
                "The local Steward DVC version is unsupported.");
        if (!Enum.IsDefined(message.Kind) ||
            message.SessionId == Guid.Empty ||
            message.HostId == Guid.Empty ||
            message.NodeIncarnationId == Guid.Empty ||
            message.RdpSessionId < 0 ||
            message.Nonce == Guid.Empty ||
            message.Sequence <= 0 ||
            message.SentAtUtcTicks <= 0)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.Malformed,
                "The local Steward DVC message is invalid.");
        if (authenticationKey.Length is < 32 or > 64 ||
            message.Payload.Length > maximumPayloadBytes ||
            maximumPayloadBytes is <= 0 or > StewardRdpDvc.MaximumPayloadBytes ||
            message.Kind is RdpDvcMessageKind.Ping or RdpDvcMessageKind.Pong &&
            message.Payload.Length > StewardRdpDvc.MaximumPingPayloadBytes)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The local Steward DVC message exceeds a protocol bound.");
    }

    private static void ValidatePeer(
        RdpDvcMessage message,
        RdpDvcPeerIdentity expected)
    {
        if (message.SessionId != expected.SessionId ||
            message.HostId != expected.HostId ||
            message.NodeIncarnationId != expected.NodeIncarnationId ||
            expected.RdpSessionId is > 0 &&
            message.RdpSessionId != expected.RdpSessionId.Value ||
            expected.ConnectionNonce.HasValue &&
            message.Nonce != expected.ConnectionNonce.Value ||
            message.RdpSessionId < 0)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BindingMismatch,
                "The Steward DVC message binding differs from the expected peer.");
    }
}
