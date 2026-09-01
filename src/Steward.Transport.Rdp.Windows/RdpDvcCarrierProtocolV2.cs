using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using Steward.Domain;
using Steward.Transport;

namespace Steward.Transport.Rdp.Windows;

public static class RdpDvcReconnectBackoff
{
    public static TimeSpan CreateDelay(int failures)
    {
        if (failures < 0)
            throw new ArgumentOutOfRangeException(nameof(failures));
        var effectiveFailures = Math.Max(1, failures);
        var exponent = Math.Min(effectiveFailures - 1, 16);
        var maximumMilliseconds = Math.Min(
            30_000,
            250 * (1 << exponent));
        var minimumMilliseconds = maximumMilliseconds / 2;
        return TimeSpan.FromMilliseconds(
            RandomNumberGenerator.GetInt32(
                minimumMilliseconds,
                maximumMilliseconds + 1));
    }
}
public sealed record RdpDvcCarrierAttemptIdentity(
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    long ReconnectGeneration,
    Guid AttemptId,
    int RdpSessionId)
{
    public Guid RouteId { get; init; } = HostId.Value;

    public RdpDvcCarrierAttemptIdentity Validate()
    {
        if (SessionId == Guid.Empty ||
            RouteId == Guid.Empty ||
            HostId.Value == Guid.Empty ||
            NodeIncarnationId.Value == Guid.Empty ||
            ReconnectGeneration <= 0 ||
            AttemptId == Guid.Empty ||
            RdpSessionId <= 0)
            throw new InvalidDataException(
                "The DVC carrier attempt identity is invalid.");
        return this;
    }
}

public sealed record RdpDvcCarrierClientHelloV2(
    RdpDvcCarrierAttemptIdentity Identity,
    byte[] NodeChallenge);

public sealed record RdpDvcCarrierServerHelloV2(
    RdpDvcCarrierAttemptIdentity Identity,
    byte[] NodeChallenge,
    byte[] BrokerChallenge);

public sealed record RdpDvcCarrierFinishV2(
    RdpDvcCarrierAttemptIdentity Identity,
    byte[] TranscriptHash);

public static class RdpDvcCarrierProtocolV2
{
    public const byte ProtocolVersion = 2;
    public const int ChallengeBytes = 32;
    public const int AuthenticationTagBytes = 32;
    public const int ClientHelloBytes = 222;
    public const int ServerHelloBytes = 190;
    public const int FinishBytes = 158;
    private const byte ClientHelloKind = 1;
    private const byte ServerHelloKind = 2;
    private const byte FinishKind = 3;

    public static byte[] CreateClientHello(
        RdpDvcCarrierAttemptIdentity identity,
        ReadOnlySpan<byte> nodeChallenge,
        ReadOnlySpan<byte> carrierSecret)
    {
        identity.Validate();
        ValidateChallenge(nodeChallenge, nameof(nodeChallenge));
        ValidateSecret(carrierSecret);
        var frame = new byte[ClientHelloBytes];
        WriteHeader(
            frame,
            ClientHelloKind,
            identity);
        nodeChallenge.CopyTo(frame.AsSpan(94, ChallengeBytes));
        var routeIdentity = new RdpDvcConnectionIdentity(
            identity.SessionId,
            identity.HostId.Value,
            identity.NodeIncarnationId.Value,
            identity.RdpSessionId,
            identity.ReconnectGeneration,
            identity.AttemptId)
        {
            RouteId = identity.RouteId
        };
        var routeSelector =
            RdpDvcBrokerRoutingProtocol
                .ComputeReconnectSelectorAuthenticator(
                    routeIdentity,
                    carrierSecret);
        var attemptAuthenticator =
            RdpDvcBrokerRoutingProtocol
                .ComputeReconnectAuthenticator(
                    routeIdentity,
                    carrierSecret);
        try
        {
            routeSelector.CopyTo(
                frame.AsSpan(
                    RdpDvcBrokerRoutingProtocol
                        .ReconnectRouteAuthenticatorOffset,
                    AuthenticationTagBytes));
            attemptAuthenticator.CopyTo(
                frame.AsSpan(
                    RdpDvcBrokerRoutingProtocol
                        .ReconnectAttemptAuthenticatorOffset,
                    AuthenticationTagBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(routeSelector);
            CryptographicOperations.ZeroMemory(attemptAuthenticator);
        }
        Authenticate(
            frame,
            ClientHelloBytes - AuthenticationTagBytes,
            carrierSecret);
        return frame;
    }

    public static RdpDvcCarrierClientHelloV2 ParseClientHello(
        ReadOnlySpan<byte> frame,
        ReadOnlySpan<byte> carrierSecret)
    {
        if (frame.Length != ClientHelloBytes)
            throw Protocol("The DVC carrier client hello has an invalid length.");
        ValidateSecret(carrierSecret);
        VerifyAuthentication(frame, carrierSecret);
        var identity = ReadHeader(frame, ClientHelloKind);
        VerifyReconnectAuthenticators(
            frame,
            identity,
            carrierSecret);
        return new(
            identity,
            frame.Slice(94, ChallengeBytes).ToArray());
    }

    public static byte[] CreateServerHello(
        RdpDvcCarrierClientHelloV2 client,
        ReadOnlySpan<byte> brokerChallenge,
        ReadOnlySpan<byte> carrierSecret)
    {
        ArgumentNullException.ThrowIfNull(client);
        client.Identity.Validate();
        ValidateChallenge(client.NodeChallenge, nameof(client.NodeChallenge));
        ValidateChallenge(brokerChallenge, nameof(brokerChallenge));
        ValidateSecret(carrierSecret);
        var frame = new byte[ServerHelloBytes];
        WriteHeader(frame, ServerHelloKind, client.Identity);
        client.NodeChallenge.CopyTo(frame, 94);
        brokerChallenge.CopyTo(frame.AsSpan(126, ChallengeBytes));
        Authenticate(frame, ServerHelloBytes - AuthenticationTagBytes, carrierSecret);
        return frame;
    }

    public static RdpDvcCarrierServerHelloV2 ParseServerHello(
        ReadOnlySpan<byte> frame,
        RdpDvcCarrierClientHelloV2 expectedClient,
        ReadOnlySpan<byte> carrierSecret)
    {
        ArgumentNullException.ThrowIfNull(expectedClient);
        if (frame.Length != ServerHelloBytes)
            throw Protocol("The DVC carrier server hello has an invalid length.");
        ValidateSecret(carrierSecret);
        VerifyAuthentication(frame, carrierSecret);
        var identity = ReadHeader(frame, ServerHelloKind);
        if (identity != expectedClient.Identity ||
            !CryptographicOperations.FixedTimeEquals(
                frame.Slice(94, ChallengeBytes),
                expectedClient.NodeChallenge))
            throw Protocol(
                "The DVC carrier server hello does not match the client attempt.");
        return new(
            identity,
            frame.Slice(94, ChallengeBytes).ToArray(),
            frame.Slice(126, ChallengeBytes).ToArray());
    }

    public static byte[] CreateFinish(
            RdpDvcCarrierAttemptIdentity identity,
            ReadOnlySpan<byte> clientHello,
            ReadOnlySpan<byte> serverHello,
            ReadOnlySpan<byte> carrierSecret)
    {
        identity.Validate();
        var client = ParseClientHello(clientHello, carrierSecret);
        _ = ParseServerHello(serverHello, client, carrierSecret);
        if (client.Identity != identity)
            throw Protocol(
                "The DVC carrier finish identity does not match the transcript.");
        var frame = new byte[FinishBytes];
        WriteHeader(frame, FinishKind, identity);
        var transcript = SHA256.HashData(
            Concat(clientHello, serverHello));
        try
        {
            transcript.CopyTo(frame, 94);
            Authenticate(
                frame,
                FinishBytes - AuthenticationTagBytes,
                carrierSecret);
            return frame;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcript);
        }
    }

    public static RdpDvcCarrierFinishV2 ParseFinish(
            ReadOnlySpan<byte> frame,
            RdpDvcCarrierClientHelloV2 client,
            ReadOnlySpan<byte> clientHello,
            ReadOnlySpan<byte> serverHello,
            ReadOnlySpan<byte> carrierSecret)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (frame.Length != FinishBytes)
            throw Protocol("The DVC carrier finish has an invalid length.");
        VerifyAuthentication(frame, carrierSecret);
        var identity = ReadHeader(frame, FinishKind);
        var transcript = SHA256.HashData(
            Concat(clientHello, serverHello));
        try
        {
            if (identity != client.Identity ||
                !CryptographicOperations.FixedTimeEquals(
                    frame.Slice(94, ChallengeBytes),
                    transcript))
                throw Protocol(
                    "The DVC carrier finish does not match the authenticated transcript.");
            return new(identity, transcript.ToArray());
        }

        finally
        {
            CryptographicOperations.ZeroMemory(transcript);
        }
    }

    private static void VerifyReconnectAuthenticators(
        ReadOnlySpan<byte> frame,
        RdpDvcCarrierAttemptIdentity identity,
        ReadOnlySpan<byte> carrierSecret)
    {
        var routeIdentity = new RdpDvcConnectionIdentity(
            identity.SessionId,
            identity.HostId.Value,
            identity.NodeIncarnationId.Value,
            identity.RdpSessionId,
            identity.ReconnectGeneration,
            identity.AttemptId)
        {
            RouteId = identity.RouteId
        };
        var expectedSelector = RdpDvcBrokerRoutingProtocol
            .ComputeReconnectSelectorAuthenticator(
                routeIdentity,
                carrierSecret);
        var expectedAttempt = RdpDvcBrokerRoutingProtocol
            .ComputeReconnectAuthenticator(
                routeIdentity,
                carrierSecret);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    expectedSelector,
                    frame.Slice(
                        RdpDvcBrokerRoutingProtocol
                            .ReconnectRouteAuthenticatorOffset,
                        AuthenticationTagBytes)) ||
                !CryptographicOperations.FixedTimeEquals(
                    expectedAttempt,
                    frame.Slice(
                        RdpDvcBrokerRoutingProtocol
                            .ReconnectAttemptAuthenticatorOffset,
                        AuthenticationTagBytes)))
                throw Protocol(
                    "The DVC carrier route authenticator is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedSelector);
            CryptographicOperations.ZeroMemory(expectedAttempt);
        }
    }
    private static void WriteHeader(
        Span<byte> frame,
        byte kind,
        RdpDvcCarrierAttemptIdentity identity)
    {
        frame[0] = ProtocolVersion;
        frame[1] = kind;
        identity.SessionId.TryWriteBytes(frame[2..18]);
        identity.RouteId.TryWriteBytes(frame[18..34]);
        identity.HostId.Value.TryWriteBytes(frame[34..50]);
        identity.NodeIncarnationId.Value.TryWriteBytes(frame[50..66]);
        BinaryPrimitives.WriteInt64LittleEndian(
            frame[66..74],
            identity.ReconnectGeneration);
        identity.AttemptId.TryWriteBytes(frame[74..90]);
        BinaryPrimitives.WriteInt32LittleEndian(
            frame[90..94],
            identity.RdpSessionId);
    }

    private static RdpDvcCarrierAttemptIdentity ReadHeader(
        ReadOnlySpan<byte> frame,
        byte expectedKind)
    {
        if (frame[0] != ProtocolVersion || frame[1] != expectedKind)
            throw Protocol(
                "The DVC carrier protocol version or message kind is invalid.");
        return new RdpDvcCarrierAttemptIdentity(
            new(frame[2..18]),
            new(new Guid(frame[34..50])),
            new(new Guid(frame[50..66])),
            BinaryPrimitives.ReadInt64LittleEndian(frame[66..74]),
            new(frame[74..90]),
            BinaryPrimitives.ReadInt32LittleEndian(frame[90..94]))
        {
            RouteId = new Guid(frame[18..34])
        }.Validate();
    }
    private static void Authenticate(
        Span<byte> frame,
        int authenticatedLength,
        ReadOnlySpan<byte> secret)
    {
        using var hmac = new HMACSHA256(secret.ToArray());
        var tag = hmac.ComputeHash(frame[..authenticatedLength].ToArray());
        tag.CopyTo(frame[authenticatedLength..]);
        CryptographicOperations.ZeroMemory(tag);
    }

    private static void VerifyAuthentication(
        ReadOnlySpan<byte> frame,
        ReadOnlySpan<byte> secret)
    {
        var authenticatedLength = frame.Length - AuthenticationTagBytes;
        using var hmac = new HMACSHA256(secret.ToArray());
        var expected = hmac.ComputeHash(frame[..authenticatedLength].ToArray());
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    expected,
                    frame[authenticatedLength..]))
                throw Protocol("The DVC carrier authentication tag is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    private static byte[] Concat(
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second)
    {
        var value = new byte[first.Length + second.Length];
        first.CopyTo(value);
        second.CopyTo(value.AsSpan(first.Length));
        return value;
    }

    private static void ValidateChallenge(
        ReadOnlySpan<byte> challenge,
        string name)
    {
        if (challenge.Length != ChallengeBytes)
            throw new ArgumentException(
                "DVC carrier challenges must be 256 bits.",
                name);
    }

    private static void ValidateSecret(ReadOnlySpan<byte> secret)
    {
        if (secret.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC carrier root secret length is invalid.",
                nameof(secret));
    }

    private static RdpDvcProtocolException Protocol(string message) =>
        new(RdpDvcProtocolError.AuthenticationFailed, message);
}
public sealed record RdpDvcCarrierRouteIdentity(
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    long? ExpectedReconnectGeneration,
    Guid? ExpectedAttemptId,
    int? ExpectedRdpSessionId)
{
    public Guid RouteId { get; init; } = HostId.Value;

    public RdpDvcCarrierRouteIdentity Validate()
    {
        if (SessionId == Guid.Empty ||
            RouteId == Guid.Empty ||
            HostId.Value == Guid.Empty ||
            NodeIncarnationId.Value == Guid.Empty ||
            (ExpectedReconnectGeneration is null) !=
                (ExpectedAttemptId is null) ||
            ExpectedReconnectGeneration is <= 0 ||
            ExpectedAttemptId == Guid.Empty ||
            ExpectedRdpSessionId is <= 0)
            throw new ArgumentException(
                "The DVC carrier route identity is invalid.");
        return this;
    }
}

#if !RDP_DVC_SERVER_EMBEDDED
public sealed class RdpDvcCarrierV2NamedPipeWireChannelSource :
    IRdpDvcWireChannelSource
{
    private readonly RdpDvcCarrierRouteIdentity identity;
    private readonly string pipeName;
    private readonly TimeSpan connectTimeout;
    private readonly byte[] carrierSecret;
    private int used;

    public RdpDvcCarrierAttemptIdentity? SelectedIdentity { get; private set; }

    public RdpDvcCarrierV2NamedPipeWireChannelSource(
        RdpDvcCarrierRouteIdentity identity,
        ReadOnlySpan<byte> carrierSecret,
        string? pipeName = null,
        TimeSpan? connectTimeout = null)
    {
        this.identity = identity.Validate();
        if (carrierSecret.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC carrier root secret length is invalid.",
                nameof(carrierSecret));
        this.carrierSecret = carrierSecret.ToArray();
        this.pipeName = pipeName ?? StewardRdpDvc.CurrentUserPipeName();
        this.connectTimeout = connectTimeout ?? TimeSpan.FromSeconds(15);
        if (string.IsNullOrWhiteSpace(this.pipeName) ||
            this.pipeName.Length > 128 ||
            this.pipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new ArgumentException(
                "The Steward DVC broker pipe name is invalid.",
                nameof(pipeName));
        if (this.connectTimeout <= TimeSpan.Zero ||
            this.connectTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(
                nameof(connectTimeout));
    }

    public async ValueTask<RdpDvcWireConnection> OpenChannelAsync(
        CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref used, 1) != 0)
            throw new InvalidOperationException(
                "The DVC carrier route source is single-use.");
        var pipe = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(connectTimeout);
        try
        {
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            var routeIdentity = new RdpDvcConnectionIdentity(
                identity.SessionId,
                identity.HostId.Value,
                identity.NodeIncarnationId.Value,
                identity.ExpectedRdpSessionId.GetValueOrDefault(),
                identity.ExpectedReconnectGeneration.GetValueOrDefault(),
                identity.ExpectedAttemptId.GetValueOrDefault())
            {
                RouteId = identity.RouteId
            };
            var route =
                RdpDvcBrokerRoutingProtocol.CreateReconnectRoute(
                    routeIdentity,
                    carrierSecret);
            var request = RdpDvcBrokerRoutingProtocol.EncodeRequest(
                route);
            await pipe.WriteAsync(request, timeout.Token)
                .ConfigureAwait(false);
            await pipe.FlushAsync(timeout.Token).ConfigureAwait(false);
            var candidate =
                await RdpDvcBrokerRoutingProtocol.ReadCandidateAsync(
                        pipe,
                        timeout.Token)
                    .ConfigureAwait(false);
            var accepted = false;
            try
            {
                var routedMessage = RdpDvcMessageCodec.Decode(
                    candidate,
                    new RdpDvcAuthenticationOptions(
                        new(
                            identity.SessionId,
                            identity.HostId.Value,
                            identity.NodeIncarnationId.Value,
                            identity.ExpectedRdpSessionId,
                            identity.ExpectedAttemptId),
                        carrierSecret));
                if (routedMessage.Kind != RdpDvcMessageKind.Ping ||
                    routedMessage.Sequence != 1)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.UnexpectedMessage,
                        "The routed DVC reconnect candidate is not a client hello.");
                var client = RdpDvcCarrierProtocolV2.ParseClientHello(
                    routedMessage.Payload.Span,
                    carrierSecret);
                if (client.Identity.SessionId != identity.SessionId ||
                    client.Identity.RouteId != identity.RouteId ||
                    client.Identity.HostId != identity.HostId ||
                    client.Identity.NodeIncarnationId !=
                        identity.NodeIncarnationId ||
                    identity.ExpectedReconnectGeneration is
                    { } expectedGeneration &&
                    (client.Identity.ReconnectGeneration !=
                         expectedGeneration ||
                     client.Identity.AttemptId !=
                         identity.ExpectedAttemptId) ||
                    identity.ExpectedRdpSessionId is { } expectedWts &&
                    client.Identity.RdpSessionId != expectedWts)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.BindingMismatch,
                        "The routed DVC reconnect candidate does not match the expected attempt.");
                SelectedIdentity = client.Identity;
                await pipe.WriteAsync(
                        new[] { RdpDvcBrokerRoutingProtocol.Accepted },
                        timeout.Token)
                    .ConfigureAwait(false);
                await pipe.FlushAsync(timeout.Token).ConfigureAwait(false);
                accepted = true;
                return new(
                    new RdpDvcNamedPipeWireChannelSource
                        .PrefetchedRdpDvcWireChannel(
                            new LengthPrefixedDvcWireChannel(pipe),
                            candidate),
                    client.Identity.RdpSessionId);
            }
            finally
            {
                if (!accepted)
                {
                    try
                    {
                        await pipe.WriteAsync(
                                new[]
                                {
                                    RdpDvcBrokerRoutingProtocol.Rejected
                                },
                                timeout.Token)
                            .ConfigureAwait(false);
                        await pipe.FlushAsync(timeout.Token)
                            .ConfigureAwait(false);
                    }
                    catch (Exception exception)
                        when (exception is
                            IOException or OperationCanceledException)
                    {
                    }
                }
            }
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
        finally
        {
            CryptographicOperations.ZeroMemory(carrierSecret);
        }
    }
}
#endif

public sealed record RdpDvcCarrierAuthenticationV2(
    RdpDvcCarrierAttemptIdentity Identity,
    string TranscriptHash)
{
    public ReconnectTransportBinding ToTransportBinding() =>
        new ReconnectTransportBinding(
            ReconnectTransportBinding.CurrentVersion,
            Identity.HostId,
            Identity.NodeIncarnationId,
            Identity.ReconnectGeneration,
            Identity.AttemptId,
            Identity.RdpSessionId,
            TranscriptHash)
        {
            RouteId = Identity.RouteId
        }.Validate(Identity.NodeIncarnationId);
}

public sealed class RdpDvcConnectedStreamV2(
    Stream stream,
    RdpDvcCarrierAuthenticationV2 authentication) : IAsyncDisposable
{
    public Stream Stream { get; } = stream ??
        throw new ArgumentNullException(nameof(stream));

    public RdpDvcCarrierAuthenticationV2 Authentication { get; } =
        authentication ?? throw new ArgumentNullException(
            nameof(authentication));

    public ValueTask DisposeAsync() => Stream.DisposeAsync();
}

public static class RdpDvcCarrierHandshakeV2
{
    public static async ValueTask<RdpDvcConnectedStreamV2> InitiateAsync(
        RdpDvcWireConnection connection,
        RdpDvcCarrierAttemptIdentity identity,
        ReadOnlyMemory<byte> carrierSecret,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        identity.Validate();
        ValidateConnectionSession(connection, identity);
        ValidateTimeout(timeout);
        ValidateSecret(carrierSecret);
        var nodeChallenge = RandomNumberGenerator.GetBytes(
            RdpDvcCarrierProtocolV2.ChallengeBytes);
        try
        {
            var clientHello = RdpDvcCarrierProtocolV2.CreateClientHello(
                identity,
                nodeChallenge,
                carrierSecret.Span);
            try
            {
                var encodedClient = EncodeMessage(
                    RdpDvcMessageKind.Ping,
                    sequence: 1,
                    identity,
                    clientHello,
                    carrierSecret.Span);
                try
                {
                    await RunWithTimeoutAsync(
                            token => connection.Channel.WritePduAsync(
                                    encodedClient,
                                    token)
                                .AsTask(),
                            timeout,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(encodedClient);
                }
                var client = RdpDvcCarrierProtocolV2.ParseClientHello(
                    clientHello,
                    carrierSecret.Span);
                var encodedServer = await RunWithTimeoutAsync(
                        token => connection.Channel.ReadPduAsync(token)
                            .AsTask(),
                        timeout,
                        cancellationToken)
                    .ConfigureAwait(false);
                try
                {
                    var serverMessage = DecodeMessage(
                        encodedServer,
                        identity,
                        carrierSecret);
                    RequireMessage(
                        serverMessage,
                        RdpDvcMessageKind.Pong,
                        sequence: 1);
                    _ = RdpDvcCarrierProtocolV2.ParseServerHello(
                        serverMessage.Payload.Span,
                        client,
                        carrierSecret.Span);
                    var finish = RdpDvcCarrierProtocolV2.CreateFinish(
                        identity,
                        clientHello,
                        serverMessage.Payload.Span,
                        carrierSecret.Span);
                    try
                    {
                        var encodedFinish = EncodeMessage(
                            RdpDvcMessageKind.Data,
                            sequence: 2,
                            identity,
                            finish,
                            carrierSecret.Span);
                        try
                        {
                            await RunWithTimeoutAsync(
                                    token => connection.Channel.WritePduAsync(
                                            encodedFinish,
                                            token)
                                        .AsTask(),
                                    timeout,
                                    cancellationToken)
                                .ConfigureAwait(false);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(encodedFinish);
                        }
                        var authenticated =
                            RdpDvcCarrierProtocolV2.ParseFinish(
                                finish,
                                client,
                                clientHello,
                                serverMessage.Payload.Span,
                                carrierSecret.Span);
                        return CreateConnected(
                            connection.Channel,
                            identity,
                            authenticated.TranscriptHash,
                            carrierSecret,
                            sendSequence: 3,
                            receiveSequence: 2);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(finish);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(encodedServer);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clientHello);
            }
        }
        catch
        {
            await connection.Channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nodeChallenge);
        }
    }

    public static async ValueTask<RdpDvcConnectedStreamV2> RespondAsync(
        RdpDvcWireConnection connection,
        RdpDvcCarrierAttemptIdentity expectedIdentity,
        ReadOnlyMemory<byte> carrierSecret,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        expectedIdentity.Validate();
        ValidateConnectionSession(connection, expectedIdentity);
        ValidateTimeout(timeout);
        ValidateSecret(carrierSecret);
        var brokerChallenge = RandomNumberGenerator.GetBytes(
            RdpDvcCarrierProtocolV2.ChallengeBytes);
        try
        {
            var encodedClient = await RunWithTimeoutAsync(
                    token => connection.Channel.ReadPduAsync(token)
                        .AsTask(),
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                var clientMessage = DecodeMessage(
                    encodedClient,
                    expectedIdentity,
                    carrierSecret);
                RequireMessage(
                    clientMessage,
                    RdpDvcMessageKind.Ping,
                    sequence: 1);
                var client = RdpDvcCarrierProtocolV2.ParseClientHello(
                    clientMessage.Payload.Span,
                    carrierSecret.Span);
                if (client.Identity != expectedIdentity)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.BindingMismatch,
                        "The DVC reconnect attempt does not match the expected route.");
                var serverHello = RdpDvcCarrierProtocolV2.CreateServerHello(
                    client,
                    brokerChallenge,
                    carrierSecret.Span);
                try
                {
                    var encodedServer = EncodeMessage(
                        RdpDvcMessageKind.Pong,
                        sequence: 1,
                        expectedIdentity,
                        serverHello,
                        carrierSecret.Span);
                    try
                    {
                        await RunWithTimeoutAsync(
                                token => connection.Channel.WritePduAsync(
                                        encodedServer,
                                        token)
                                    .AsTask(),
                                timeout,
                                cancellationToken)
                            .ConfigureAwait(false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(encodedServer);
                    }
                    var encodedFinish = await RunWithTimeoutAsync(
                            token => connection.Channel.ReadPduAsync(token)
                                .AsTask(),
                            timeout,
                            cancellationToken)
                        .ConfigureAwait(false);
                    try
                    {
                        var finishMessage = DecodeMessage(
                            encodedFinish,
                            expectedIdentity,
                            carrierSecret);
                        RequireMessage(
                            finishMessage,
                            RdpDvcMessageKind.Data,
                            sequence: 2);
                        var authenticated =
                            RdpDvcCarrierProtocolV2.ParseFinish(
                                finishMessage.Payload.Span,
                                client,
                                clientMessage.Payload.Span,
                                serverHello,
                                carrierSecret.Span);
                        return CreateConnected(
                            connection.Channel,
                            expectedIdentity,
                            authenticated.TranscriptHash,
                            carrierSecret,
                            sendSequence: 2,
                            receiveSequence: 3);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(encodedFinish);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(serverHello);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encodedClient);
            }
        }
        catch
        {
            await connection.Channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(brokerChallenge);
        }
    }

    private static byte[] EncodeMessage(
        RdpDvcMessageKind kind,
        long sequence,
        RdpDvcCarrierAttemptIdentity identity,
        ReadOnlyMemory<byte> payload,
        ReadOnlySpan<byte> carrierSecret) =>
        RdpDvcMessageCodec.Encode(
            new(
                kind,
                StewardRdpDvc.ProtocolVersion,
                identity.SessionId,
                identity.HostId.Value,
                identity.NodeIncarnationId.Value,
                identity.RdpSessionId,
                identity.AttemptId,
                sequence,
                DateTimeOffset.UtcNow.UtcTicks,
                payload),
            carrierSecret);

    private static RdpDvcMessage DecodeMessage(
        ReadOnlySpan<byte> encoded,
        RdpDvcCarrierAttemptIdentity identity,
        ReadOnlyMemory<byte> carrierSecret) =>
        RdpDvcMessageCodec.Decode(
            encoded,
            new RdpDvcAuthenticationOptions(
                new(
                    identity.SessionId,
                    identity.HostId.Value,
                    identity.NodeIncarnationId.Value,
                    identity.RdpSessionId,
                    identity.AttemptId),
                carrierSecret));

    private static void RequireMessage(
        RdpDvcMessage message,
        RdpDvcMessageKind expectedKind,
        long sequence)
    {
        if (message.Kind != expectedKind ||
            message.Sequence != sequence)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.UnexpectedMessage,
                "The DVC carrier v2 message kind or sequence is invalid.");
    }

    private static RdpDvcConnectedStreamV2 CreateConnected(
        IRdpDvcWireChannel channel,
        RdpDvcCarrierAttemptIdentity identity,
        ReadOnlySpan<byte> transcriptHash,
        ReadOnlyMemory<byte> carrierSecret,
        long sendSequence,
        long receiveSequence)
    {
        var options = new RdpDvcAuthenticationOptions(
            new(
                identity.SessionId,
                identity.HostId.Value,
                identity.NodeIncarnationId.Value,
                identity.RdpSessionId,
                identity.AttemptId),
            carrierSecret);
        var handshake = new RdpDvcMessage(
            RdpDvcMessageKind.Ping,
            StewardRdpDvc.ProtocolVersion,
            identity.SessionId,
            identity.HostId.Value,
            identity.NodeIncarnationId.Value,
            identity.RdpSessionId,
            identity.AttemptId,
            0,
            DateTimeOffset.UtcNow.UtcTicks,
            ReadOnlyMemory<byte>.Empty);
        var stream = new AuthenticatedRdpDvcStream(
            channel,
            options,
            handshake,
            sendSequence,
            receiveSequence);
        return new(
            stream,
            new(identity, Convert.ToHexString(transcriptHash)));
    }

    private static void ValidateConnectionSession(
        RdpDvcWireConnection connection,
        RdpDvcCarrierAttemptIdentity identity)
    {
        if (connection.RdpSessionId is { } actual &&
            actual != identity.RdpSessionId)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BindingMismatch,
                "The opened RDP session differs from the reconnect attempt.");
    }

    private static void ValidateSecret(ReadOnlyMemory<byte> secret)
    {
        if (secret.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC carrier root secret length is invalid.",
                nameof(secret));
    }

    private static void ValidateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    private static async Task RunWithTimeoutAsync(
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
                "The DVC carrier v2 handshake timed out.");
        }
    }

    private static async Task<T> RunWithTimeoutAsync<T>(
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
            return await operation(timeoutSource.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The DVC carrier v2 handshake timed out.");
        }
    }
}
