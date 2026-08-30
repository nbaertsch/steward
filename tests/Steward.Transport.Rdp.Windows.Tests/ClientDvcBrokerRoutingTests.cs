using System.Collections.Concurrent;
using System.Security.Cryptography;
using Steward.Domain;
using Steward.RdpDvc.Client.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

public sealed class ClientDvcBrokerRoutingTests
{
    [Fact]
    public async Task Concurrent_channels_route_by_authenticated_identity_not_arrival()
    {
        var pipeName =
            $"Steward.Routing.{Guid.NewGuid():N}";
        await using var broker =
            new ClientDvcBroker(_ => { }, pipeName);
        var sessionId = Guid.NewGuid();
        var hostId = new HostId(Guid.NewGuid());
        var incarnation =
            new NodeIncarnationId(Guid.NewGuid());
        var key = RandomNumberGenerator.GetBytes(32);
        var first = Route.Create(
            41,
            sessionId,
            hostId,
            incarnation,
            key,
            preauthorizeWts: true);
        var second = Route.Create(
            42,
            sessionId,
            hostId,
            incarnation,
            key,
            preauthorizeWts: true);
        var firstChannel = new CapturingClientChannel();
        var secondChannel = new CapturingClientChannel();
        var firstAttachment =
            broker.TryAttach(firstChannel);
        var secondAttachment =
            broker.TryAttach(secondChannel);
        Assert.NotNull(firstAttachment);
        Assert.NotNull(secondAttachment);

        Assert.True(secondAttachment.ReceiveFragment(
            second.EncodedPing));
        Assert.True(firstAttachment.ReceiveFragment(
            first.EncodedPing));

        var firstSource =
            new RdpDvcNamedPipeWireChannelSource(
                first.Options,
                pipeName,
                TimeSpan.FromSeconds(5));
        var secondSource =
            new RdpDvcNamedPipeWireChannelSource(
                second.Options,
                pipeName,
                TimeSpan.FromSeconds(5));
        var opened = await Task.WhenAll(
            firstSource.OpenChannelAsync().AsTask(),
            secondSource.OpenChannelAsync().AsTask());
        var connected = await Task.WhenAll(
            RdpDvcStreamHandshake.RespondAsync(
                    opened[0],
                    first.Options)
                .AsTask(),
            RdpDvcStreamHandshake.RespondAsync(
                    opened[1],
                    second.Options)
                .AsTask());

        var firstPong = await firstChannel.ReadWriteAsync();
        var secondPong = await secondChannel.ReadWriteAsync();
        var decodedFirst = RdpDvcMessageCodec.Decode(
            firstPong,
            first.Options);
        var decodedSecond = RdpDvcMessageCodec.Decode(
            secondPong,
            second.Options);

        Assert.Equal(
            RdpDvcMessageKind.Pong,
            decodedFirst.Kind);
        Assert.Equal(first.Nonce, decodedFirst.Nonce);
        Assert.Equal(first.SessionId, decodedFirst.SessionId);
        Assert.Equal(41, decodedFirst.RdpSessionId);
        Assert.Equal(
            RdpDvcMessageKind.Pong,
            decodedSecond.Kind);
        Assert.Equal(second.Nonce, decodedSecond.Nonce);
        Assert.Equal(second.SessionId, decodedSecond.SessionId);
        Assert.Equal(42, decodedSecond.RdpSessionId);

        foreach (var connection in connected)
            await connection.DisposeAsync();
    }

    [Fact]
    public async Task Route_rejects_wrong_authentication_without_cross_wiring()
    {
        var pipeName =
            $"Steward.Routing.{Guid.NewGuid():N}";
        await using var broker =
            new ClientDvcBroker(_ => { }, pipeName);
        var route = Route.Create(51);
        var attachment =
            broker.TryAttach(new CapturingClientChannel());
        Assert.NotNull(attachment);
        Assert.True(attachment.ReceiveFragment(route.EncodedPing));
        var wrongKey = RandomNumberGenerator.GetBytes(32);
        var wrongOptions = route.Options with
        {
            AuthenticationKey = wrongKey
        };
        var wrongSource = new RdpDvcNamedPipeWireChannelSource(
            wrongOptions,
            pipeName,
            TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAsync<TimeoutException>(
            () => wrongSource.OpenChannelAsync().AsTask());

        var correctSource =
            new RdpDvcNamedPipeWireChannelSource(
                route.Options,
                pipeName,
                TimeSpan.FromSeconds(5));
        var opened = await correctSource.OpenChannelAsync();
        await using var connected =
            await RdpDvcStreamHandshake.RespondAsync(
                opened,
                route.Options);
    }

    [Fact]
    public void Routed_source_requires_exact_nonce_but_allows_wts_wildcard()
    {
        var route = Route.Create(61);
        var missingNonce = route.Options with
        {
            ExpectedPeer =
                route.Options.ExpectedPeer with
                {
                    ConnectionNonce = null
                }
        };
        var source = new RdpDvcNamedPipeWireChannelSource(
            missingNonce,
            $"Steward.Routing.{Guid.NewGuid():N}");

        var exception = Assert.Throws<InvalidOperationException>(
            () => source.OpenChannelAsync().AsTask()
                .GetAwaiter()
                .GetResult());

        Assert.DoesNotContain(
            Convert.ToHexString(
                route.Options.AuthenticationKey.Span),
            exception.ToString(),
            StringComparison.Ordinal);

        var wildcard = route.Options with
        {
            ExpectedPeer =
                route.Options.ExpectedPeer with
                {
                    RdpSessionId = null
                }
        };
        _ = new RdpDvcNamedPipeWireChannelSource(
            wildcard,
            $"Steward.Routing.{Guid.NewGuid():N}");
    }

    [Fact]
    public void Route_identity_allows_only_zero_or_positive_wts()
    {
        var wildcard = new RdpDvcConnectionIdentity(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            0,
            Guid.NewGuid());
        Assert.True(wildcard.IsWtsWildcard);
        Assert.Throws<ArgumentException>(() =>
            new RdpDvcConnectionIdentity(
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                -1,
                Guid.NewGuid()));
    }

    [Fact]
    public async Task Wildcard_route_rejects_ambiguous_same_nonce_candidates()
    {
        var pipeName =
            $"Steward.Routing.{Guid.NewGuid():N}";
        await using var broker =
            new ClientDvcBroker(_ => { }, pipeName);
        var sessionId = Guid.NewGuid();
        var hostId = new HostId(Guid.NewGuid());
        var incarnation =
            new NodeIncarnationId(Guid.NewGuid());
        var nonce = Guid.NewGuid();
        var key = RandomNumberGenerator.GetBytes(32);
        var first = Route.Create(
            81,
            sessionId,
            hostId,
            incarnation,
            key,
            nonce,
            preauthorizeWts: true);
        var second = Route.Create(
            82,
            sessionId,
            hostId,
            incarnation,
            key,
            nonce,
            preauthorizeWts: true);
        var firstAttachment =
            broker.TryAttach(new CapturingClientChannel());
        var secondAttachment =
            broker.TryAttach(new CapturingClientChannel());
        Assert.NotNull(firstAttachment);
        Assert.NotNull(secondAttachment);
        Assert.True(firstAttachment.ReceiveFragment(first.EncodedPing));
        Assert.True(secondAttachment.ReceiveFragment(second.EncodedPing));
        await Task.Delay(50);
        var source = new RdpDvcNamedPipeWireChannelSource(
            first.Options,
            pipeName,
            TimeSpan.FromSeconds(1));

        await Assert.ThrowsAnyAsync<IOException>(
            () => source.OpenChannelAsync().AsTask());
    }

    [Fact]
    public async Task Attachment_reports_backpressure_instead_of_dropping()
    {
        var route = Route.Create(71);
        await using var attachment = new ClientDvcAttachment(
            new CapturingClientChannel());

        for (var index = 0;
             index <= StewardRdpDvc.MaximumBufferedPdus;
             index++)
            Assert.True(attachment.ReceiveFragment(route.EncodedPing));

        Assert.False(attachment.ReceiveFragment(route.EncodedPing));
    }

    private sealed record Route(
        Guid SessionId,
        Guid Nonce,
        RdpDvcAuthenticationOptions Options,
        byte[] EncodedPing)
    {
        internal static Route Create(
            int rdpSessionId,
            Guid? sessionId = null,
            HostId? hostId = null,
            NodeIncarnationId? incarnation = null,
            byte[]? key = null,
            Guid? connectionNonce = null,
            bool preauthorizeWts = false)
        {
            var resolvedSessionId =
                sessionId ?? Guid.NewGuid();
            var resolvedHostId =
                hostId ?? new HostId(Guid.NewGuid());
            var resolvedIncarnation =
                incarnation ??
                new NodeIncarnationId(Guid.NewGuid());
            var nonce = connectionNonce ?? Guid.NewGuid();
            var resolvedKey =
                key ?? RandomNumberGenerator.GetBytes(32);
            var options = new RdpDvcAuthenticationOptions(
                new(
                    resolvedSessionId,
                    resolvedHostId.Value,
                    resolvedIncarnation.Value,
                    preauthorizeWts ? null : rdpSessionId,
                    nonce),
                resolvedKey,
                HandshakeTimeout: TimeSpan.FromSeconds(5),
                OperationTimeout: TimeSpan.FromSeconds(5));
            var ping = new RdpDvcMessage(
                RdpDvcMessageKind.Ping,
                StewardRdpDvc.ProtocolVersion,
                resolvedSessionId,
                resolvedHostId.Value,
                resolvedIncarnation.Value,
                rdpSessionId,
                nonce,
                1,
                DateTimeOffset.UtcNow.UtcTicks,
                RdpDvcBrokerRoutingProtocol.CreatePingPayload(
                    options,
                    rdpSessionId,
                    nonce,
                    RandomNumberGenerator.GetBytes(32)));
            return new(
                resolvedSessionId,
                nonce,
                options,
                RdpDvcMessageCodec.Encode(
                    ping,
                    resolvedKey));
        }
    }

    private sealed class CapturingClientChannel :
        IClientDvcChannel
    {
        private readonly ConcurrentQueue<byte[]> _writes = new();
        private readonly SemaphoreSlim _written = new(0);

        public int Write(ReadOnlySpan<byte> pdu)
        {
            _writes.Enqueue(pdu.ToArray());
            _written.Release();
            return HResults.Ok;
        }

        public int Close() => HResults.Ok;

        internal async Task<byte[]> ReadWriteAsync()
        {
            await _written.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(_writes.TryDequeue(out var value));
            return value;
        }
    }
}
