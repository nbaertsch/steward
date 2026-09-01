using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Channels;
using Steward.Domain;
using Steward.Transport.Rdp.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

public sealed class RdpDvcCarrierProtocolV2Tests
{
    [Fact]
    public void Authenticated_hellos_roundtrip_and_bind_both_challenges()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var nodeChallenge = RandomNumberGenerator.GetBytes(32);
        var brokerChallenge = RandomNumberGenerator.GetBytes(32);
        var identity = Identity();
        var clientFrame = RdpDvcCarrierProtocolV2.CreateClientHello(
            identity,
            nodeChallenge,
            secret);
        var client = RdpDvcCarrierProtocolV2.ParseClientHello(
            clientFrame,
            secret);
        var serverFrame = RdpDvcCarrierProtocolV2.CreateServerHello(
            client,
            brokerChallenge,
            secret);
        var server = RdpDvcCarrierProtocolV2.ParseServerHello(
            serverFrame,
            client,
            secret);
        var finishFrame = RdpDvcCarrierProtocolV2.CreateFinish(
            identity,
            clientFrame,
            serverFrame,
            secret);
        var finish = RdpDvcCarrierProtocolV2.ParseFinish(
            finishFrame,
            client,
            clientFrame,
            serverFrame,
            secret);

        Assert.Equal(identity, client.Identity);
        Assert.Equal(identity, server.Identity);
        Assert.Equal(nodeChallenge, server.NodeChallenge);
        Assert.Equal(brokerChallenge, server.BrokerChallenge);
        Assert.Equal(identity, finish.Identity);
        Assert.Equal(32, finish.TranscriptHash.Length);
    }

    [Fact]
    public void Tampering_and_wrong_secret_are_rejected()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var frame = RdpDvcCarrierProtocolV2.CreateClientHello(
            Identity(),
            RandomNumberGenerator.GetBytes(32),
            secret);
        var tampered = frame.ToArray();
        tampered[20] ^= 0x40;

        Assert.Throws<RdpDvcProtocolException>(() =>
            RdpDvcCarrierProtocolV2.ParseClientHello(
                tampered,
                secret));
        Assert.Throws<RdpDvcProtocolException>(() =>
            RdpDvcCarrierProtocolV2.ParseClientHello(
                frame,
                RandomNumberGenerator.GetBytes(32)));
    }

    [Fact]
    public void Server_hello_cannot_be_transferred_to_another_attempt()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var firstFrame = RdpDvcCarrierProtocolV2.CreateClientHello(
            Identity(),
            RandomNumberGenerator.GetBytes(32),
            secret);
        var first = RdpDvcCarrierProtocolV2.ParseClientHello(
            firstFrame,
            secret);
        var serverFrame = RdpDvcCarrierProtocolV2.CreateServerHello(
            first,
            RandomNumberGenerator.GetBytes(32),
            secret);
        var secondFrame = RdpDvcCarrierProtocolV2.CreateClientHello(
            Identity(),
            RandomNumberGenerator.GetBytes(32),
            secret);
        var second = RdpDvcCarrierProtocolV2.ParseClientHello(
            secondFrame,
            secret);

        Assert.Throws<RdpDvcProtocolException>(() =>
            RdpDvcCarrierProtocolV2.ParseServerHello(
                serverFrame,
                second,
                secret));
    }

    [Fact]
    public void Finish_rejects_a_mutated_transcript()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var identity = Identity();
        var clientFrame = RdpDvcCarrierProtocolV2.CreateClientHello(
            identity,
            RandomNumberGenerator.GetBytes(32),
            secret);
        var client = RdpDvcCarrierProtocolV2.ParseClientHello(
            clientFrame,
            secret);
        var serverFrame = RdpDvcCarrierProtocolV2.CreateServerHello(
            client,
            RandomNumberGenerator.GetBytes(32),
            secret);
        var finish = RdpDvcCarrierProtocolV2.CreateFinish(
            identity,
            clientFrame,
            serverFrame,
            secret);
        var mutated = serverFrame.ToArray();
        mutated[100] ^= 0x01;

        Assert.Throws<RdpDvcProtocolException>(() =>
            RdpDvcCarrierProtocolV2.ParseFinish(
                finish,
                client,
                clientFrame,
                mutated,
                secret));
    }

    [Fact]
    public void New_evidence_routes_default_v2_and_reject_downgrade()
    {
        var expected = new RdpDvcEvidenceRoute(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            0,
            Guid.NewGuid());
        Assert.Equal(2, expected.ProtocolVersion);
        var authenticated = new RdpDvcEvidenceRoute(
            expected.SessionId,
            expected.HostId,
            expected.NodeIncarnationId,
            42,
            Guid.NewGuid(),
            ProtocolVersion: 2);

        Assert.True(expected.MatchesAuthenticatedRoute(authenticated));
        Assert.False(expected.MatchesAuthenticatedRoute(
            authenticated with { HostId = Guid.NewGuid() }));
        Assert.False(expected.MatchesAuthenticatedRoute(
            authenticated with { ProtocolVersion = 1 }));
    }
    [Fact]
    public async Task Full_two_sided_handshake_yields_authenticated_data_streams()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var identity = Identity();
        var (nodeWire, brokerWire) = WirePair.Create(
            identity.RdpSessionId);

        var nodeTask = RdpDvcCarrierHandshakeV2.InitiateAsync(
                nodeWire,
                identity,
                secret,
                TimeSpan.FromSeconds(5))
            .AsTask();
        var brokerTask = RdpDvcCarrierHandshakeV2.RespondAsync(
                brokerWire,
                identity,
                secret,
                TimeSpan.FromSeconds(5))
            .AsTask();
        await using var node = await nodeTask;
        await using var broker = await brokerTask;

        Assert.Equal(identity, node.Authentication.Identity);
        Assert.Equal(identity, broker.Authentication.Identity);
        Assert.Equal(
            node.Authentication.TranscriptHash,
            broker.Authentication.TranscriptHash);
        var payload = "authenticated-v2"u8.ToArray();
        await node.Stream.WriteAsync(payload);
        var received = new byte[payload.Length];
        await broker.Stream.ReadExactlyAsync(received);
        Assert.Equal(payload, received);
    }

    [Fact]
    public void Ten_thousand_reconnects_do_not_exhaust_or_repeat_transcripts()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var session = Guid.NewGuid();
        var host = HostId.New();
        var incarnation = NodeIncarnationId.New();
        var transcripts = new HashSet<string>(StringComparer.Ordinal);

        for (var generation = 1; generation <= 10_000; generation++)
        {
            var identity = new RdpDvcCarrierAttemptIdentity(
                session,
                host,
                incarnation,
                generation,
                Guid.NewGuid(),
                42);
            var clientFrame = RdpDvcCarrierProtocolV2.CreateClientHello(
                identity,
                RandomNumberGenerator.GetBytes(32),
                secret);
            var client = RdpDvcCarrierProtocolV2.ParseClientHello(
                clientFrame,
                secret);
            var serverFrame = RdpDvcCarrierProtocolV2.CreateServerHello(
                client,
                RandomNumberGenerator.GetBytes(32),
                secret);
            var finishFrame = RdpDvcCarrierProtocolV2.CreateFinish(
                identity,
                clientFrame,
                serverFrame,
                secret);
            var finish = RdpDvcCarrierProtocolV2.ParseFinish(
                finishFrame,
                client,
                clientFrame,
                serverFrame,
                secret);

            Assert.True(transcripts.Add(
                Convert.ToHexString(finish.TranscriptHash)));
        }
    }

    [Fact]
    public void Cross_route_node_host_incarnation_wts_and_generation_are_rejected()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var identity = Identity();
        var clientFrame = RdpDvcCarrierProtocolV2.CreateClientHello(
            identity,
            RandomNumberGenerator.GetBytes(32),
            secret);
        var client = RdpDvcCarrierProtocolV2.ParseClientHello(
            clientFrame,
            secret);
        var serverFrame = RdpDvcCarrierProtocolV2.CreateServerHello(
            client,
            RandomNumberGenerator.GetBytes(32),
            secret);
        var substitutions = new[]
        {
            identity with { SessionId = Guid.NewGuid() },
            identity with { RouteId = Guid.NewGuid() },
            identity with { HostId = HostId.New() },
            identity with { NodeIncarnationId = NodeIncarnationId.New() },
            identity with { ReconnectGeneration = identity.ReconnectGeneration + 1 },
            identity with { AttemptId = Guid.NewGuid() },
            identity with { RdpSessionId = identity.RdpSessionId + 1 }
        };

        foreach (var substitution in substitutions)
        {
            var expected = client with { Identity = substitution };
            Assert.Throws<RdpDvcProtocolException>(() =>
                RdpDvcCarrierProtocolV2.ParseServerHello(
                    serverFrame,
                    expected,
                    secret));
        }
    }
    [Fact]
    public void Route_authenticator_binds_every_exact_attempt_field()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var identity = Identity();
        var exact = ConnectionIdentity(identity);
        var captured = RdpDvcBrokerRoutingProtocol
            .ComputeReconnectAuthenticator(exact, secret);
        var substitutions = new[]
        {
            identity with { SessionId = Guid.NewGuid() },
            identity with { RouteId = Guid.NewGuid() },
            identity with { HostId = HostId.New() },
            identity with
            {
                NodeIncarnationId = NodeIncarnationId.New()
            },
            identity with
            {
                ReconnectGeneration = identity.ReconnectGeneration + 1
            },
            identity with { AttemptId = Guid.NewGuid() },
            identity with { RdpSessionId = identity.RdpSessionId + 1 }
        };

        foreach (var substitution in substitutions)
        {
            var changed = RdpDvcBrokerRoutingProtocol
                .ComputeReconnectAuthenticator(
                    ConnectionIdentity(substitution),
                    secret);
            Assert.False(
                CryptographicOperations.FixedTimeEquals(
                    captured,
                    changed));
        }
    }

    [Fact]
    public void Captured_route_authenticator_cannot_replay_across_attempts()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var firstAttempt = Identity();
        var first = ConnectionIdentity(firstAttempt);
        var captured = RdpDvcBrokerRoutingProtocol
            .ComputeReconnectAuthenticator(first, secret);
        var replayAttempts = new[]
        {
            firstAttempt with
            {
                ReconnectGeneration =
                    firstAttempt.ReconnectGeneration + 1
            },
            firstAttempt with { AttemptId = Guid.NewGuid() },
            firstAttempt with
            {
                RdpSessionId = firstAttempt.RdpSessionId + 1
            },
            firstAttempt with { RouteId = Guid.NewGuid() }
        };

        foreach (var replayAttempt in replayAttempts)
        {
            var replayIdentity = ConnectionIdentity(replayAttempt);
            var replay = new RdpDvcBrokerRoute(
                replayIdentity,
                captured);
            var expected = new RdpDvcBrokerRoute(
                replayIdentity,
                RdpDvcBrokerRoutingProtocol
                    .ComputeReconnectAuthenticator(
                        replayIdentity,
                        secret));
            Assert.False(replay.MatchesRequest(expected));
        }
    }
    [Fact]
    public void Concurrent_exact_routes_match_only_their_own_attempt()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var routes = Enumerable.Range(0, 64)
            .Select(_ => ConnectionIdentity(Identity() with
            {
                RouteId = Guid.NewGuid()
            }))
            .Select(identity => new RdpDvcBrokerRoute(
                identity,
                RdpDvcBrokerRoutingProtocol
                    .ComputeReconnectAuthenticator(identity, secret)))
            .ToArray();

        Parallel.For(
            0,
            routes.Length,
            index =>
            {
                Assert.True(routes[index].MatchesRequest(routes[index]));
                Assert.False(routes[index].MatchesRequest(
                    routes[(index + 1) % routes.Length]));
            });
    }

    [Fact]
    public void Broker_rejects_captured_selector_reframed_as_exact_attempt()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var first = Identity();
        var clientHello = RdpDvcCarrierProtocolV2.CreateClientHello(
            first,
            RandomNumberGenerator.GetBytes(32),
            secret);
        var encoded = RdpDvcMessageCodec.Encode(
            new(
                RdpDvcMessageKind.Ping,
                StewardRdpDvc.ProtocolVersion,
                first.SessionId,
                first.HostId.Value,
                first.NodeIncarnationId.Value,
                first.RdpSessionId,
                first.AttemptId,
                1,
                DateTimeOffset.UtcNow.UtcTicks,
                clientHello),
            secret);
        var replay = first with
        {
            ReconnectGeneration = first.ReconnectGeneration + 1,
            AttemptId = Guid.NewGuid(),
            RdpSessionId = first.RdpSessionId + 1
        };
        var forged = encoded.ToArray();
        var payloadOffset = RdpDvcMessageCodec.HeaderSize;
        BinaryPrimitives.WriteInt64LittleEndian(
            forged.AsSpan(payloadOffset + 66, 8),
            replay.ReconnectGeneration);
        replay.AttemptId.TryWriteBytes(
            forged.AsSpan(payloadOffset + 74, 16));
        BinaryPrimitives.WriteInt32LittleEndian(
            forged.AsSpan(payloadOffset + 90, 4),
            replay.RdpSessionId);
        BinaryPrimitives.WriteInt32BigEndian(
            forged.AsSpan(28, 4),
            replay.RdpSessionId);
        replay.AttemptId.TryWriteBytes(forged.AsSpan(80, 16));

        Assert.True(
            RdpDvcBrokerRoutingProtocol.TryReadUntrustedCandidateRoute(
                forged,
                out var candidate));
        var expected = RdpDvcBrokerRoutingProtocol.CreateReconnectRoute(
            ConnectionIdentity(replay),
            secret);
        Assert.False(candidate.MatchesRequest(expected));
    }
    private static RdpDvcConnectionIdentity ConnectionIdentity(
        RdpDvcCarrierAttemptIdentity identity) =>
        new(
            identity.SessionId,
            identity.HostId.Value,
            identity.NodeIncarnationId.Value,
            identity.RdpSessionId,
            identity.ReconnectGeneration,
            identity.AttemptId)
        {
            RouteId = identity.RouteId
        };
    private static RdpDvcCarrierAttemptIdentity Identity() =>
        new(
            Guid.NewGuid(),
            HostId.New(),
            NodeIncarnationId.New(),
            1,
            Guid.NewGuid(),
            42);

    private sealed class WirePair(
        Channel<byte[]> incoming,
        Channel<byte[]> outgoing) : IRdpDvcWireChannel
    {
        public static (RdpDvcWireConnection Node, RdpDvcWireConnection Broker)
            Create(int rdpSessionId)
        {
            var nodeToBroker = Channel.CreateUnbounded<byte[]>();
            var brokerToNode = Channel.CreateUnbounded<byte[]>();
            return (
                new(
                    new WirePair(brokerToNode, nodeToBroker),
                    rdpSessionId),
                new(
                    new WirePair(nodeToBroker, brokerToNode),
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
