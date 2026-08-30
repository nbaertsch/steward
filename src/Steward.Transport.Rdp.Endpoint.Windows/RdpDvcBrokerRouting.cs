using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Steward.Transport.Rdp.Windows;

public readonly record struct RdpDvcConnectionIdentity
{
    public RdpDvcConnectionIdentity(
        Guid sessionId,
        Guid hostId,
        Guid nodeIncarnationId,
        int rdpSessionId,
        Guid connectionNonce)
    {
        if (sessionId == Guid.Empty ||
            hostId == Guid.Empty ||
            nodeIncarnationId == Guid.Empty ||
            rdpSessionId < 0 ||
            connectionNonce == Guid.Empty)
            throw new ArgumentException(
                "The DVC connection identity is invalid.");
        SessionId = sessionId;
        HostId = hostId;
        NodeIncarnationId = nodeIncarnationId;
        RdpSessionId = rdpSessionId;
        ConnectionNonce = connectionNonce;
    }

    public Guid SessionId { get; }
    public Guid HostId { get; }
    public Guid NodeIncarnationId { get; }
    public int RdpSessionId { get; }
    public Guid ConnectionNonce { get; }
    public bool IsWtsWildcard => RdpSessionId == 0;

    public override string ToString() =>
        "RdpDvcConnectionIdentity { Redacted }";
}

internal static class RdpDvcBrokerRoutingProtocol
{
    internal const ushort Version = 2;
    internal const int AuthenticatorSize = 32;
    internal const int RoutingPingPayloadSize =
        AuthenticatorSize + 32;
    internal const int RequestSize = 108;
    internal const byte Accepted = 1;
    internal const byte Rejected = 0;
    private static ReadOnlySpan<byte> Magic =>
        "SDRB"u8;

    internal static RdpDvcBrokerRoute RequireExactRoute(
        RdpDvcAuthenticationOptions options)
    {
        options.Validate();
        var peer = options.ExpectedPeer;
        if (peer.ConnectionNonce is not { } nonce)
            throw new InvalidOperationException(
                "Broker routing requires an exact connection nonce.");
        var rdpSessionId = peer.RdpSessionId.GetValueOrDefault();
        var identity = new RdpDvcConnectionIdentity(
            peer.SessionId,
            peer.HostId,
            peer.NodeIncarnationId,
            rdpSessionId,
            nonce);
        return new(
            identity,
            ComputeAuthenticator(
                identity,
                options.AuthenticationKey.Span));
    }

    internal static byte[] EncodeRequest(
        RdpDvcBrokerRoute route)
    {
        var request = new byte[RequestSize];
        Magic.CopyTo(request);
        BinaryPrimitives.WriteUInt16BigEndian(
            request.AsSpan(4, 2),
            Version);
        route.Identity.SessionId.TryWriteBytes(
            request.AsSpan(8, 16));
        route.Identity.HostId.TryWriteBytes(
            request.AsSpan(24, 16));
        route.Identity.NodeIncarnationId.TryWriteBytes(
            request.AsSpan(40, 16));
        BinaryPrimitives.WriteInt32BigEndian(
            request.AsSpan(56, 4),
            route.Identity.RdpSessionId);
        route.Identity.ConnectionNonce.TryWriteBytes(
            request.AsSpan(60, 16));
        route.Authenticator.CopyTo(
            request.AsSpan(76, AuthenticatorSize));
        return request;
    }

    internal static RdpDvcBrokerRoute DecodeRequest(
        ReadOnlySpan<byte> request)
    {
        if (request.Length != RequestSize ||
            !request[..4].SequenceEqual(Magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(
                request.Slice(4, 2)) != Version ||
            request[6] != 0 ||
            request[7] != 0)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.Malformed,
                "The DVC broker routing request is malformed.");
        return new(
            new(
                new Guid(request.Slice(8, 16)),
                new Guid(request.Slice(24, 16)),
                new Guid(request.Slice(40, 16)),
                BinaryPrimitives.ReadInt32BigEndian(
                    request.Slice(56, 4)),
                new Guid(request.Slice(60, 16))),
            request.Slice(76, AuthenticatorSize));
    }

    internal static bool TryReadUntrustedCandidateRoute(
        ReadOnlySpan<byte> encoded,
        out RdpDvcBrokerRoute route)
    {
        route = default;
        if (encoded.Length < RdpDvcMessageCodec.MinimumEncodedSize ||
            !encoded[..4].SequenceEqual("SDVC"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(
                encoded.Slice(4, 2)) !=
                StewardRdpDvc.ProtocolVersion ||
            encoded[6] != (byte)RdpDvcMessageKind.Ping ||
            encoded[7] != 0 ||
            BinaryPrimitives.ReadInt64BigEndian(
                encoded.Slice(12, 8)) != 1)
            return false;
        var payloadLength =
            BinaryPrimitives.ReadInt32BigEndian(
                encoded.Slice(8, 4));
        if (payloadLength !=
                RoutingPingPayloadSize ||
            payloadLength >
                StewardRdpDvc.MaximumPingPayloadBytes ||
            encoded.Length !=
                RdpDvcMessageCodec.HeaderSize +
                payloadLength +
                RdpDvcMessageCodec.AuthenticationTagSize)
            return false;
        try
        {
            var rdpSessionId =
                BinaryPrimitives.ReadInt32BigEndian(
                    encoded.Slice(28, 4));
            if (rdpSessionId <= 0)
                return false;
            route = new(
                new(
                    new Guid(encoded.Slice(32, 16)),
                    new Guid(encoded.Slice(48, 16)),
                    new Guid(encoded.Slice(64, 16)),
                    rdpSessionId,
                    new Guid(encoded.Slice(80, 16))),
                encoded.Slice(
                    RdpDvcMessageCodec.HeaderSize,
                    AuthenticatorSize));
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    internal static byte[] CreatePingPayload(
        RdpDvcAuthenticationOptions options,
        int rdpSessionId,
        Guid connectionNonce,
        ReadOnlySpan<byte> challenge)
    {
        if (challenge.Length != 32)
            throw new ArgumentException(
                "The DVC routing challenge must contain 32 bytes.",
                nameof(challenge));
        var identity = new RdpDvcConnectionIdentity(
            options.ExpectedPeer.SessionId,
            options.ExpectedPeer.HostId,
            options.ExpectedPeer.NodeIncarnationId,
            rdpSessionId,
            connectionNonce);
        var authenticator = ComputeAuthenticator(
            identity,
            options.AuthenticationKey.Span);
        var payload = new byte[
            AuthenticatorSize + challenge.Length];
        authenticator.CopyTo(payload);
        challenge.CopyTo(payload.AsSpan(AuthenticatorSize));
        return payload;
    }

    internal static bool HasExpectedAuthenticator(
        ReadOnlySpan<byte> payload,
        RdpDvcBrokerRoute route) =>
        payload.Length == RoutingPingPayloadSize &&
        CryptographicOperations.FixedTimeEquals(
            payload[..AuthenticatorSize],
            route.Authenticator);

    private static byte[] ComputeAuthenticator(
        RdpDvcConnectionIdentity identity,
        ReadOnlySpan<byte> authenticationKey)
    {
        Span<byte> material = stackalloc byte[76];
        "SDRB-AUTH-v2"u8.CopyTo(material);
        identity.SessionId.TryWriteBytes(
            material.Slice(12, 16));
        identity.HostId.TryWriteBytes(
            material.Slice(28, 16));
        identity.NodeIncarnationId.TryWriteBytes(
            material.Slice(44, 16));
        identity.ConnectionNonce.TryWriteBytes(
            material.Slice(60, 16));
        return HMACSHA256.HashData(
            authenticationKey,
            material);
    }

    internal static async ValueTask WriteCandidateAsync(
        Stream stream,
        ReadOnlyMemory<byte> candidate,
        CancellationToken cancellationToken)
    {
        if (candidate.Length <
                RdpDvcMessageCodec.MinimumEncodedSize ||
            candidate.Length >
                RdpDvcMessageCodec.MinimumEncodedSize +
                StewardRdpDvc.MaximumPingPayloadBytes)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The DVC broker routing candidate exceeds its bound.");
        var length = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(
            length,
            candidate.Length);
        await stream.WriteAsync(length, cancellationToken)
            .ConfigureAwait(false);
        await stream.WriteAsync(candidate, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    internal static async ValueTask<byte[]> ReadCandidateAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var length = new byte[4];
        await ReadExactlyAsync(
                stream,
                length,
                cancellationToken)
            .ConfigureAwait(false);
        var count = BinaryPrimitives.ReadInt32BigEndian(length);
        if (count < RdpDvcMessageCodec.MinimumEncodedSize ||
            count >
                RdpDvcMessageCodec.MinimumEncodedSize +
                StewardRdpDvc.MaximumPingPayloadBytes)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The DVC broker routing candidate declaration exceeds its bound.");
        var candidate = new byte[count];
        await ReadExactlyAsync(
                stream,
                candidate,
                cancellationToken)
            .ConfigureAwait(false);
        return candidate;
    }

    internal static async ValueTask ReadExactlyAsync(
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
}

internal readonly struct RdpDvcBrokerRoute :
    IEquatable<RdpDvcBrokerRoute>
{
    private readonly byte[] _authenticator;

    internal RdpDvcBrokerRoute(
        RdpDvcConnectionIdentity identity,
        ReadOnlySpan<byte> authenticator)
    {
        if (authenticator.Length !=
            RdpDvcBrokerRoutingProtocol.AuthenticatorSize)
            throw new ArgumentException(
                "The DVC broker route authenticator is invalid.",
                nameof(authenticator));
        Identity = identity;
        _authenticator = authenticator.ToArray();
    }

    internal RdpDvcConnectionIdentity Identity { get; }
    internal ReadOnlySpan<byte> Authenticator =>
        _authenticator;

    internal bool MatchesRequest(RdpDvcBrokerRoute request) =>
        Identity.SessionId == request.Identity.SessionId &&
        Identity.HostId == request.Identity.HostId &&
        Identity.NodeIncarnationId ==
            request.Identity.NodeIncarnationId &&
        Identity.ConnectionNonce ==
            request.Identity.ConnectionNonce &&
        (request.Identity.IsWtsWildcard ||
         Identity.RdpSessionId ==
         request.Identity.RdpSessionId) &&
        _authenticator is not null &&
        request._authenticator is not null &&
        CryptographicOperations.FixedTimeEquals(
            _authenticator,
            request._authenticator);

    internal string DescribeMatch(RdpDvcBrokerRoute request) =>
        $"session={Identity.SessionId == request.Identity.SessionId};" +
        $"host={Identity.HostId == request.Identity.HostId};" +
        $"incarnation={Identity.NodeIncarnationId == request.Identity.NodeIncarnationId};" +
        $"nonce={Identity.ConnectionNonce == request.Identity.ConnectionNonce};" +
        $"wts={request.Identity.IsWtsWildcard || Identity.RdpSessionId == request.Identity.RdpSessionId};" +
        $"auth={_authenticator is not null && request._authenticator is not null && CryptographicOperations.FixedTimeEquals(_authenticator, request._authenticator)}";

    public bool Equals(RdpDvcBrokerRoute other) =>
        Identity == other.Identity &&
        _authenticator is not null &&
        other._authenticator is not null &&
        CryptographicOperations.FixedTimeEquals(
            _authenticator,
            other._authenticator);

    public override bool Equals(object? value) =>
        value is RdpDvcBrokerRoute other &&
        Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Identity);
        if (_authenticator is not null)
        {
            hash.Add(BinaryPrimitives.ReadInt32BigEndian(
                _authenticator.AsSpan(0, 4)));
            hash.Add(BinaryPrimitives.ReadInt32BigEndian(
                _authenticator.AsSpan(28, 4)));
        }
        return hash.ToHashCode();
    }

    public static bool operator ==(
        RdpDvcBrokerRoute left,
        RdpDvcBrokerRoute right) =>
        left.Equals(right);

    public static bool operator !=(
        RdpDvcBrokerRoute left,
        RdpDvcBrokerRoute right) =>
        !left.Equals(right);

    public override string ToString() =>
        "RdpDvcBrokerRoute { Redacted }";
}
