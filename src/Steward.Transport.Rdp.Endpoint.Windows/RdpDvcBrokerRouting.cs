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
        RouteId = hostId;
        NodeIncarnationId = nodeIncarnationId;
        RdpSessionId = rdpSessionId;
        ConnectionNonce = connectionNonce;
        ReconnectGeneration = 0;
        AttemptId = Guid.Empty;
        Version = 1;
    }

    public RdpDvcConnectionIdentity(
        Guid sessionId,
        Guid hostId,
        Guid nodeIncarnationId,
        int rdpSessionId,
        long reconnectGeneration,
        Guid attemptId)
    {
        if (sessionId == Guid.Empty ||
            hostId == Guid.Empty ||
            nodeIncarnationId == Guid.Empty ||
            rdpSessionId < 0 ||
            reconnectGeneration < 0 ||
            reconnectGeneration == 0 && attemptId != Guid.Empty ||
            reconnectGeneration > 0 && attemptId == Guid.Empty)
            throw new ArgumentException(
                "The DVC reconnect identity is invalid.");
        SessionId = sessionId;
        HostId = hostId;
        RouteId = hostId;
        NodeIncarnationId = nodeIncarnationId;
        RdpSessionId = rdpSessionId;
        ConnectionNonce = Guid.Empty;
        ReconnectGeneration = reconnectGeneration;
        AttemptId = attemptId;
        Version = 2;
    }

    public Guid SessionId { get; }
    public Guid HostId { get; }
    public Guid RouteId { get; init; }
    public Guid NodeIncarnationId { get; }
    public int RdpSessionId { get; }
    public Guid ConnectionNonce { get; }
    public long ReconnectGeneration { get; }
    public Guid AttemptId { get; }
    public int Version { get; }
    public bool IsWtsWildcard => RdpSessionId == 0;
    public bool IsReconnectV2 => Version == 2;

    public override string ToString() =>
        "RdpDvcConnectionIdentity { Redacted }";
}
internal static class RdpDvcBrokerRoutingProtocol
{
    internal const ushort Version = 2;
    internal const ushort ReconnectVersion = 3;
    internal const int AuthenticatorSize = 32;
    internal const int RoutingPingPayloadSize =
        AuthenticatorSize + 32;
    internal const int RequestSize = 108;
    internal const int ReconnectRequestSize = 132;
    internal const int ReconnectClientHelloSize = 222;
    internal const int ReconnectRouteAuthenticatorOffset = 126;
    internal const int ReconnectAttemptAuthenticatorOffset = 158;
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

    internal static RdpDvcBrokerRoute CreateReconnectRoute(
        RdpDvcConnectionIdentity identity,
        ReadOnlySpan<byte> authenticationKey)
    {
        if (!identity.IsReconnectV2 ||
            authenticationKey.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC reconnect route is invalid.");
        return new(
            identity,
            RequiresExactReconnectAuthenticator(identity)
                ? ComputeReconnectAuthenticator(
                    identity,
                    authenticationKey)
                : ComputeReconnectSelectorAuthenticator(
                    identity,
                    authenticationKey));
    }

    internal static bool RequiresExactReconnectAuthenticator(
        RdpDvcConnectionIdentity identity) =>
        identity.IsReconnectV2 &&
        identity.ReconnectGeneration > 0 &&
        identity.AttemptId != Guid.Empty &&
        identity.RdpSessionId > 0;
    internal static byte[] EncodeRequest(
        RdpDvcBrokerRoute route)
    {
        if (route.Identity.IsReconnectV2)
        {
            var reconnect = new byte[ReconnectRequestSize];
            Magic.CopyTo(reconnect);
            BinaryPrimitives.WriteUInt16BigEndian(
                reconnect.AsSpan(4, 2),
                ReconnectVersion);
            route.Identity.SessionId.TryWriteBytes(
                reconnect.AsSpan(8, 16));
            route.Identity.RouteId.TryWriteBytes(
                reconnect.AsSpan(24, 16));
            route.Identity.HostId.TryWriteBytes(
                reconnect.AsSpan(40, 16));
            route.Identity.NodeIncarnationId.TryWriteBytes(
                reconnect.AsSpan(56, 16));
            BinaryPrimitives.WriteInt64BigEndian(
                reconnect.AsSpan(72, 8),
                route.Identity.ReconnectGeneration);
            route.Identity.AttemptId.TryWriteBytes(
                reconnect.AsSpan(80, 16));
            BinaryPrimitives.WriteInt32BigEndian(
                reconnect.AsSpan(96, 4),
                route.Identity.RdpSessionId);
            route.Authenticator.CopyTo(
                reconnect.AsSpan(100, AuthenticatorSize));
            return reconnect;
        }

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
        if (request.Length < 8 ||
            !request[..4].SequenceEqual(Magic) ||
            request[6] != 0 ||
            request[7] != 0)
            throw MalformedRequest();
        var version = BinaryPrimitives.ReadUInt16BigEndian(
            request.Slice(4, 2));
        if (version == ReconnectVersion &&
            request.Length == ReconnectRequestSize)
            return new(
                new RdpDvcConnectionIdentity(
                    new Guid(request.Slice(8, 16)),
                    new Guid(request.Slice(40, 16)),
                    new Guid(request.Slice(56, 16)),
                    BinaryPrimitives.ReadInt32BigEndian(
                        request.Slice(96, 4)),
                    BinaryPrimitives.ReadInt64BigEndian(
                        request.Slice(72, 8)),
                    new Guid(request.Slice(80, 16)))
                {
                    RouteId = new Guid(request.Slice(24, 16))
                },
                request.Slice(100, AuthenticatorSize));
        if (version == Version && request.Length == RequestSize)
            return new(
                new(
                    new Guid(request.Slice(8, 16)),
                    new Guid(request.Slice(24, 16)),
                    new Guid(request.Slice(40, 16)),
                    BinaryPrimitives.ReadInt32BigEndian(
                        request.Slice(56, 4)),
                    new Guid(request.Slice(60, 16))),
                request.Slice(76, AuthenticatorSize));
        throw MalformedRequest();
    }

    internal static async ValueTask<RdpDvcBrokerRoute> ReadRequestAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var prefix = new byte[8];
        await ReadExactlyAsync(stream, prefix, cancellationToken)
            .ConfigureAwait(false);
        if (!prefix.AsSpan(0, 4).SequenceEqual(Magic))
            throw MalformedRequest();
        var version = BinaryPrimitives.ReadUInt16BigEndian(
            prefix.AsSpan(4, 2));
        var length = version switch
        {
            Version => RequestSize,
            ReconnectVersion => ReconnectRequestSize,
            _ => throw MalformedRequest()
        };
        var request = new byte[length];
        prefix.CopyTo(request, 0);
        await ReadExactlyAsync(
                stream,
                request.AsMemory(prefix.Length),
                cancellationToken)
            .ConfigureAwait(false);
        return DecodeRequest(request);
    }

    internal static bool TryReadUntrustedCandidateRoute(
        ReadOnlySpan<byte> encoded,
        out RdpDvcBrokerRoute route)
    {
        route = default;
        if (TryReadUntrustedReconnectCandidate(encoded, out route))
            return true;
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
        if (payloadLength != RoutingPingPayloadSize ||
            payloadLength > StewardRdpDvc.MaximumPingPayloadBytes ||
            encoded.Length != RdpDvcMessageCodec.HeaderSize +
                payloadLength +
                RdpDvcMessageCodec.AuthenticationTagSize)
            return false;
        try
        {
            var rdpSessionId = BinaryPrimitives.ReadInt32BigEndian(
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

    private static bool TryReadUntrustedReconnectCandidate(
        ReadOnlySpan<byte> encoded,
        out RdpDvcBrokerRoute route)
    {
        route = default;
        if (encoded.Length != RdpDvcMessageCodec.HeaderSize +
                ReconnectClientHelloSize +
                RdpDvcMessageCodec.AuthenticationTagSize ||
            !encoded[..4].SequenceEqual("SDVC"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(
                encoded.Slice(4, 2)) !=
                StewardRdpDvc.ProtocolVersion ||
            encoded[6] != (byte)RdpDvcMessageKind.Ping ||
            encoded[7] != 0 ||
            BinaryPrimitives.ReadInt32BigEndian(
                encoded.Slice(8, 4)) != ReconnectClientHelloSize ||
            BinaryPrimitives.ReadInt64BigEndian(
                encoded.Slice(12, 8)) != 1)
            return false;
        var payload = encoded.Slice(
            RdpDvcMessageCodec.HeaderSize,
            ReconnectClientHelloSize);
        if (payload[0] != 2 || payload[1] != 1)
            return false;
        try
        {
            var sessionId = new Guid(payload.Slice(2, 16));
            var routeId = new Guid(payload.Slice(18, 16));
            var hostId = new Guid(payload.Slice(34, 16));
            var incarnationId = new Guid(payload.Slice(50, 16));
            var attemptId = new Guid(payload.Slice(74, 16));
            var rdpSessionId = BinaryPrimitives.ReadInt32LittleEndian(
                payload.Slice(90, 4));
            if (sessionId != new Guid(encoded.Slice(32, 16)) ||
                hostId != new Guid(encoded.Slice(48, 16)) ||
                incarnationId != new Guid(encoded.Slice(64, 16)) ||
                attemptId != new Guid(encoded.Slice(80, 16)) ||
                rdpSessionId != BinaryPrimitives.ReadInt32BigEndian(
                    encoded.Slice(28, 4)))
                return false;
            var identity = new RdpDvcConnectionIdentity(
                sessionId,
                hostId,
                incarnationId,
                rdpSessionId,
                BinaryPrimitives.ReadInt64LittleEndian(
                    payload.Slice(66, 8)),
                attemptId)
            {
                RouteId = routeId
            };
            route = new(
                identity,
                payload.Slice(
                    ReconnectRouteAuthenticatorOffset,
                    AuthenticatorSize),
                payload.Slice(
                    ReconnectAttemptAuthenticatorOffset,
                    AuthenticatorSize));
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
    private static RdpDvcProtocolException MalformedRequest() =>
        new(
            RdpDvcProtocolError.Malformed,
            "The DVC broker routing request is malformed.");
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

    internal static byte[] ComputeReconnectSelectorAuthenticator(
        RdpDvcConnectionIdentity identity,
        ReadOnlySpan<byte> authenticationKey)
    {
        if (!identity.IsReconnectV2 ||
            identity.RouteId == Guid.Empty ||
            authenticationKey.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC reconnect route selector input is invalid.");
        Span<byte> material = stackalloc byte[84];
        material.Clear();
        "SDRB-SELECTOR-v1"u8.CopyTo(material);
        identity.SessionId.TryWriteBytes(material.Slice(20, 16));
        identity.RouteId.TryWriteBytes(material.Slice(36, 16));
        identity.HostId.TryWriteBytes(material.Slice(52, 16));
        identity.NodeIncarnationId.TryWriteBytes(
            material.Slice(68, 16));
        return HMACSHA256.HashData(authenticationKey, material);
    }
    internal static byte[] ComputeReconnectAuthenticator(
        RdpDvcConnectionIdentity identity,
        ReadOnlySpan<byte> authenticationKey)
    {
        if (!identity.IsReconnectV2 ||
            identity.RouteId == Guid.Empty ||
            identity.RdpSessionId < 0 ||
            authenticationKey.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC reconnect route authenticator input is invalid.");
        Span<byte> material = stackalloc byte[112];
        material.Clear();
        "SDRB-RECONNECT-v4"u8.CopyTo(material);
        identity.SessionId.TryWriteBytes(material.Slice(20, 16));
        identity.RouteId.TryWriteBytes(material.Slice(36, 16));
        identity.HostId.TryWriteBytes(material.Slice(52, 16));
        identity.NodeIncarnationId.TryWriteBytes(
            material.Slice(68, 16));
        BinaryPrimitives.WriteInt64BigEndian(
            material.Slice(84, 8),
            identity.ReconnectGeneration);
        identity.AttemptId.TryWriteBytes(material.Slice(92, 16));
        BinaryPrimitives.WriteInt32BigEndian(
            material.Slice(108, 4),
            identity.RdpSessionId);

        return HMACSHA256.HashData(authenticationKey, material);
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
    private readonly byte[]? _exactAuthenticator;

    internal RdpDvcBrokerRoute(
        RdpDvcConnectionIdentity identity,
        ReadOnlySpan<byte> authenticator)
    {
        ValidateAuthenticator(authenticator);
        Identity = identity;
        _authenticator = authenticator.ToArray();
        _exactAuthenticator =
            RdpDvcBrokerRoutingProtocol
                .RequiresExactReconnectAuthenticator(identity)
                ? authenticator.ToArray()
                : null;
    }

    internal RdpDvcBrokerRoute(
        RdpDvcConnectionIdentity identity,
        ReadOnlySpan<byte> selectorAuthenticator,
        ReadOnlySpan<byte> exactAuthenticator)
    {
        ValidateAuthenticator(selectorAuthenticator);
        ValidateAuthenticator(exactAuthenticator);
        if (!identity.IsReconnectV2)
            throw new ArgumentException(
                "Only reconnect candidates have two authenticators.",
                nameof(identity));
        Identity = identity;
        _authenticator = selectorAuthenticator.ToArray();
        _exactAuthenticator = exactAuthenticator.ToArray();
    }

    internal RdpDvcConnectionIdentity Identity { get; }
    internal ReadOnlySpan<byte> Authenticator =>
        _authenticator;

    internal bool MatchesRequest(RdpDvcBrokerRoute request) =>
        Identity.SessionId == request.Identity.SessionId &&
        Identity.RouteId == request.Identity.RouteId &&
        Identity.HostId == request.Identity.HostId &&
        Identity.NodeIncarnationId ==
            request.Identity.NodeIncarnationId &&
        HasSameVersionedAttempt(request.Identity) &&
        (request.Identity.IsWtsWildcard ||
         Identity.RdpSessionId ==
         request.Identity.RdpSessionId) &&
        HasExpectedAuthenticator(request);

    private bool HasSameVersionedAttempt(
        RdpDvcConnectionIdentity request) =>
        Identity.IsReconnectV2 == request.IsReconnectV2 &&
        (Identity.IsReconnectV2
            ? request.ReconnectGeneration == 0 ||
              Identity.ReconnectGeneration == request.ReconnectGeneration &&
              Identity.AttemptId == request.AttemptId
            : Identity.ConnectionNonce == request.ConnectionNonce);

    private bool HasExpectedAuthenticator(
        RdpDvcBrokerRoute request)
    {
        if (_authenticator is null || request._authenticator is null)
            return false;
        var candidate =
            RdpDvcBrokerRoutingProtocol
                .RequiresExactReconnectAuthenticator(request.Identity)
                ? _exactAuthenticator
                : _authenticator;
        return candidate is not null &&
            CryptographicOperations.FixedTimeEquals(
                candidate,
                request._authenticator);
    }

    internal string DescribeMatch(RdpDvcBrokerRoute request) =>
        $"session={Identity.SessionId == request.Identity.SessionId};" +
        $"route={Identity.RouteId == request.Identity.RouteId};" +
        $"host={Identity.HostId == request.Identity.HostId};" +
        $"incarnation={Identity.NodeIncarnationId == request.Identity.NodeIncarnationId};" +
        $"versionedAttempt={HasSameVersionedAttempt(request.Identity)};" +
        $"wts={request.Identity.IsWtsWildcard || Identity.RdpSessionId == request.Identity.RdpSessionId};" +
        $"auth={HasExpectedAuthenticator(request)}";

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

    private static void ValidateAuthenticator(
        ReadOnlySpan<byte> authenticator)
    {
        if (authenticator.Length !=
            RdpDvcBrokerRoutingProtocol.AuthenticatorSize)
            throw new ArgumentException(
                "The DVC broker route authenticator is invalid.",
                nameof(authenticator));
    }
}
