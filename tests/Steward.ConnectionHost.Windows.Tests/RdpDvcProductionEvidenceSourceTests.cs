using System.Security.Cryptography;
using System.Threading.Channels;
using Steward.Domain;
using Steward.Transport;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class RdpDvcProductionEvidenceSourceTests
{
    [Fact]
    public async Task Spoofed_hmac_is_rejected()
    {
        var key = Key();
        await using var source = Source(key, out _);
        var report = Lifecycle(
            Guid.NewGuid(),
            1,
            RdpDvcEvidencePublicationEvent
                .StewardComClassActivated);
        var frame = RdpDvcEvidenceIpcProtocol.Encode(
            report,
            Key());

        var result = source.AcceptFrame(
            frame,
            DateTimeOffset.UtcNow);

        Assert.False(result.Accepted);
        Assert.Equal(
            "DVC_EVIDENCE_AUTHENTICATION_FAILED",
            result.Code);
    }

    [Fact]
    public async Task Accepted_report_cannot_be_replayed()
    {
        var key = Key();
        await using var source = Source(key, out _);
        var frame = Encode(
            Lifecycle(
                Guid.NewGuid(),
                1,
                RdpDvcEvidencePublicationEvent
                    .StewardComClassActivated),
            key);

        var first = source.AcceptFrame(
            frame,
            DateTimeOffset.UtcNow);
        var replay = source.AcceptFrame(
            frame,
            DateTimeOffset.UtcNow);

        Assert.True(first.Accepted);
        Assert.False(replay.Accepted);
        Assert.Equal(
            "DVC_EVIDENCE_SEQUENCE_REJECTED",
            replay.Code);
    }

    [Fact]
    public async Task Wrong_route_and_generation_are_rejected()
    {
        var key = Key();
        var route = PreauthorizedRoute();
        var boundRoute = route.BindWtsSession(41);
        await using var source = Source(
            key,
            out var resolver,
            ("evidence-reference", route));
        var ticket = await source.RegisterExpectedAsync(
            "evidence-reference",
            "connection",
            "runtime",
            7,
            CancellationToken.None);
        PublishLifecycle(source, key, boundRoute);
        var wrongRoute = ticket.Identity with
        {
            Route = PreauthorizedRoute().BindWtsSession(42)
        };
        var wrongGeneration = ticket.Identity with
        {
            ConnectionGeneration = 8,
            Route = boundRoute
        };

        var routeResult = source.AcceptFrame(
            Encode(
                Transport(
                    Guid.NewGuid(),
                    1,
                    RdpDvcEvidencePublicationEvent
                        .DvcHmacAuthenticated,
                    wrongRoute),
                key),
            DateTimeOffset.UtcNow);
        var generationResult = source.AcceptFrame(
            Encode(
                Transport(
                    Guid.NewGuid(),
                    1,
                    RdpDvcEvidencePublicationEvent
                        .DvcHmacAuthenticated,
                    wrongGeneration),
                key),
            DateTimeOffset.UtcNow);

        Assert.False(routeResult.Accepted);
        Assert.Equal(
            "DVC_EVIDENCE_TICKET_REJECTED",
            routeResult.Code);
        Assert.False(generationResult.Accepted);
        Assert.Equal(
            "DVC_EVIDENCE_TICKET_REJECTED",
            generationResult.Code);
        Assert.Equal(route, resolver.Routes["evidence-reference"]);
    }

    [Fact]
    public async Task Evidence_must_arrive_in_required_order()
    {
        var key = Key();
        var route = PreauthorizedRoute();
        var boundRoute = route.BindWtsSession(51);
        await using var source = Source(
            key,
            out _,
            ("ordered-reference", route));
        var ticket = await source.RegisterExpectedAsync(
            "ordered-reference",
            "connection",
            "runtime",
            9,
            CancellationToken.None);

        PublishLifecycle(source, key, boundRoute);
        var earlySecure = source.AcceptFrame(
            Encode(
                Transport(
                    Guid.NewGuid(),
                    1,
                    RdpDvcEvidencePublicationEvent
                        .SecurePeerAuthenticated,
                    ticket.Identity with { Route = boundRoute }),
                key),
            DateTimeOffset.UtcNow);
        var reporter = Guid.NewGuid();
        var skippedActivation = source.AcceptFrame(
            Encode(
                Lifecycle(
                    reporter,
                    1,
                    RdpDvcEvidencePublicationEvent
                        .StewardPluginInitialized),
                key),
            DateTimeOffset.UtcNow);

        Assert.False(earlySecure.Accepted);
        Assert.Equal(
            "DVC_EVIDENCE_WTS_BINDING_REQUIRED",
            earlySecure.Code);
        Assert.False(skippedActivation.Accepted);
        Assert.Equal(
            "DVC_EVIDENCE_ORDER_REJECTED",
            skippedActivation.Code);
    }

    [Fact]
    public async Task Incomplete_ticket_times_out_without_completion()
    {
        var key = Key();
        var route = PreauthorizedRoute();
        await using var source = Source(
            key,
            out _,
            ("timeout-reference", route));
        var ticket = await source.RegisterExpectedAsync(
            "timeout-reference",
            "connection",
            "runtime",
            11,
            CancellationToken.None);
        using var timeout = new CancellationTokenSource(
            TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => source.WaitForEvidenceAsync(
                ticket,
                timeout.Token));

        await source.CancelAsync(ticket);
    }

    [Fact]
    public async Task Concurrent_connections_complete_only_their_exact_tickets()
    {
        var key = Key();
        var firstRoute = PreauthorizedRoute();
        var secondRoute = firstRoute with
        {
            ConnectionNonce = Guid.NewGuid()
        };
        var firstBound = firstRoute.BindWtsSession(71);
        var secondBound = secondRoute.BindWtsSession(72);
        await using var source = Source(
            key,
            out _,
            ("first-reference", firstRoute),
            ("second-reference", secondRoute));
        var first = await source.RegisterExpectedAsync(
            "first-reference",
            "first",
            "runtime-first",
            13,
            CancellationToken.None);
        var second = await source.RegisterExpectedAsync(
            "second-reference",
            "second",
            "runtime-second",
            14,
            CancellationToken.None);

        PublishLifecycle(source, key, secondBound);
        PublishLifecycle(source, key, firstBound);
        PublishTransport(
            source,
            key,
            first.Identity with { Route = firstBound });
        PublishTransport(
            source,
            key,
            second.Identity with { Route = secondBound });

        var completed = await Task.WhenAll(
            source.WaitForEvidenceAsync(
                first,
                CancellationToken.None),
            source.WaitForEvidenceAsync(
                second,
                CancellationToken.None));

        Assert.Equal("first", completed[0].ConnectionId);
        Assert.Equal(13, completed[0].ConnectionGeneration);
        Assert.Equal("second", completed[1].ConnectionId);
        Assert.Equal(14, completed[1].ConnectionGeneration);
        Assert.All(
            completed,
            batch => Assert.Equal(5, batch.Evidence.Count));
    }

    [Fact]
    public async Task Authenticated_dvc_and_secure_ecdh_publish_final_events()
    {
        var publicationKey = Key();
        var dvcKey = Key();
        var route = PreauthorizedRoute();
        var boundRoute = route.BindWtsSession(81);
        var pipeName =
            "Steward.Evidence.Transport." + Guid.NewGuid().ToString("N");
        var resolver = new FakeResolver(
            ("transport-reference", route));
        await using var source =
            new ProductionRdpDvcRuntimeEvidenceSource(
                resolver,
                pipeName,
                publicationKey);
        var ticket = await source.RegisterExpectedAsync(
            "transport-reference",
            "connection",
            "runtime",
            17,
            CancellationToken.None);
        PublishLifecycle(source, publicationKey, boundRoute);
        await using var publisher =
            new AuthenticatedRdpDvcEvidencePublisher(
                pipeName,
                publicationKey);
        var wires = WirePair.Create();
        var authentication = new RdpDvcAuthenticationOptions(
            new(
                route.SessionId,
                route.HostId,
                route.NodeIncarnationId,
                null,
                route.ConnectionNonce),
            dvcKey,
            HandshakeTimeout: TimeSpan.FromSeconds(2),
            OperationTimeout: TimeSpan.FromSeconds(2));
        var localKey =
            EcdsaEndpointSigningKey.Create("local");
        var remoteKey =
            EcdsaEndpointSigningKey.Create("remote");
        await using var local = new
            RdpDvcEvidencePublishingConnectionAcceptor(
                new OneWireSource(wires.Second, null),
                authentication,
                new(
                    TransportEndpointRole.Node,
                    localKey,
                    new(
                        "remote",
                        remoteKey.ExportPublicKey())),
                publisher,
                ticket.Identity);
        await using var remote = new SecureStreamCarrier(
            new RdpDvcTransportStreamConnector(
                new OneWireSource(
                    wires.First,
                    boundRoute.WtsSessionId),
                authentication),
            new(
                TransportEndpointRole.Control,
                remoteKey,
                new(
                    "local",
                    localKey.ExportPublicKey())));
        var hello = Hello(route);

        var connected = await Task.WhenAll(
            remote.ConnectAsync(hello).AsTask(),
            local.AcceptAsync(hello).AsTask());
        var batch = await source.WaitForEvidenceAsync(
            ticket,
            CancellationToken.None);

        Assert.Equal(5, batch.Evidence.Count);
        Assert.Equal(
            RdCoreDvcEvidenceEvent.DvcHmacAuthenticated,
            batch.Evidence[3].Event);
        Assert.Equal(
            RdCoreDvcEvidenceEvent.SecurePeerAuthenticated,
            batch.Evidence[4].Event);
        foreach (var connection in connected)
            await connection.DisposeAsync();
    }

    [Fact]
    public async Task Authenticated_wts_binding_is_immutable()
    {
        var key = Key();
        var route = PreauthorizedRoute();
        var bound = route.BindWtsSession(91);
        await using var source = Source(
            key,
            out _,
            ("immutable-reference", route));
        var ticket = await source.RegisterExpectedAsync(
            "immutable-reference",
            "connection",
            "runtime",
            21,
            CancellationToken.None);
        PublishLifecycle(source, key, bound);
        var reporter = Guid.NewGuid();
        Assert.True(Accept(
            source,
            key,
            Transport(
                reporter,
                1,
                RdpDvcEvidencePublicationEvent
                    .DvcHmacAuthenticated,
                ticket.Identity with { Route = bound })));

        var wrongWts = source.AcceptFrame(
            Encode(
                Transport(
                    reporter,
                    2,
                    RdpDvcEvidencePublicationEvent
                        .SecurePeerAuthenticated,
                    ticket.Identity with
                    {
                        Route = route.BindWtsSession(92)
                    }),
                key),
            DateTimeOffset.UtcNow);

        Assert.False(wrongWts.Accepted);
        Assert.Equal(
            "DVC_EVIDENCE_WTS_BINDING_REQUIRED",
            wrongWts.Code);
        Assert.True(Accept(
            source,
            key,
            Transport(
                reporter,
                2,
                RdpDvcEvidencePublicationEvent
                    .SecurePeerAuthenticated,
                ticket.Identity with { Route = bound })));
    }

    [Fact]
    public async Task Two_wts_candidates_for_same_nonce_are_ambiguous()
    {
        var key = Key();
        var route = PreauthorizedRoute();
        await using var source = Source(
            key,
            out _,
            ("ambiguous-reference", route));
        _ = await source.RegisterExpectedAsync(
            "ambiguous-reference",
            "connection",
            "runtime",
            23,
            CancellationToken.None);
        PublishLifecycle(
            source,
            key,
            route.BindWtsSession(101));
        var reporter = Guid.NewGuid();
        Assert.True(Accept(
            source,
            key,
            Lifecycle(
                reporter,
                1,
                RdpDvcEvidencePublicationEvent
                    .StewardComClassActivated)));
        Assert.True(Accept(
            source,
            key,
            Lifecycle(
                reporter,
                2,
                RdpDvcEvidencePublicationEvent
                    .StewardPluginInitialized)));

        var ambiguous = source.AcceptFrame(
            Encode(
                Lifecycle(
                    reporter,
                    3,
                    RdpDvcEvidencePublicationEvent
                        .StewardChannelOpened,
                    route.BindWtsSession(102)),
                key),
            DateTimeOffset.UtcNow);

        Assert.False(ambiguous.Accepted);
        Assert.Equal(
            "DVC_EVIDENCE_ROUTE_AMBIGUOUS",
            ambiguous.Code);
    }

    private static ProductionRdpDvcRuntimeEvidenceSource Source(
        byte[] key,
        out FakeResolver resolver,
        params (string Reference, RdpDvcEvidenceRoute Route)[] routes)
    {
        resolver = new(routes);
        return new(
            resolver,
            "Steward.Evidence.Tests." + Guid.NewGuid().ToString("N"),
            key);
    }

    private static void PublishLifecycle(
        ProductionRdpDvcRuntimeEvidenceSource source,
        byte[] key,
        RdpDvcEvidenceRoute route)
    {
        var reporter = Guid.NewGuid();
        Assert.True(Accept(
            source,
            key,
            Lifecycle(
                reporter,
                1,
                RdpDvcEvidencePublicationEvent
                    .StewardComClassActivated)));
        Assert.True(Accept(
            source,
            key,
            Lifecycle(
                reporter,
                2,
                RdpDvcEvidencePublicationEvent
                    .StewardPluginInitialized)));
        Assert.True(Accept(
            source,
            key,
            Lifecycle(
                reporter,
                3,
                RdpDvcEvidencePublicationEvent
                    .StewardChannelOpened,
                route)));
    }

    private static void PublishTransport(
        ProductionRdpDvcRuntimeEvidenceSource source,
        byte[] key,
        RdpDvcEvidenceTicketIdentity ticket)
    {
        var reporter = Guid.NewGuid();
        Assert.True(Accept(
            source,
            key,
            Transport(
                reporter,
                1,
                RdpDvcEvidencePublicationEvent
                    .DvcHmacAuthenticated,
                ticket)));
        Assert.True(Accept(
            source,
            key,
            Transport(
                reporter,
                2,
                RdpDvcEvidencePublicationEvent
                    .SecurePeerAuthenticated,
                ticket)));
    }

    private static bool Accept(
        ProductionRdpDvcRuntimeEvidenceSource source,
        byte[] key,
        RdpDvcEvidencePublication publication) =>
        source.AcceptFrame(
                Encode(publication, key),
                DateTimeOffset.UtcNow)
            .Accepted;

    private static byte[] Encode(
        RdpDvcEvidencePublication publication,
        byte[] key) =>
        RdpDvcEvidenceIpcProtocol.Encode(publication, key);

    private static RdpDvcEvidencePublication Lifecycle(
        Guid reporter,
        long sequence,
        RdpDvcEvidencePublicationEvent evidenceEvent,
        RdpDvcEvidenceRoute? route = null) =>
        new(
            reporter,
            sequence,
            DateTimeOffset.UtcNow.UtcTicks,
            evidenceEvent,
            CandidateRoute: route);

    private static RdpDvcEvidencePublication Transport(
        Guid reporter,
        long sequence,
        RdpDvcEvidencePublicationEvent evidenceEvent,
        RdpDvcEvidenceTicketIdentity ticket) =>
        new(
            reporter,
            sequence,
            DateTimeOffset.UtcNow.UtcTicks,
            evidenceEvent,
            ticket);

    private static RdpDvcEvidenceRoute PreauthorizedRoute() =>
        new(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            0,
            Guid.NewGuid());

    private static byte[] Key() =>
        RandomNumberGenerator.GetBytes(32);

    private static SessionHello Hello(RdpDvcEvidenceRoute route) =>
        new(
            route.SessionId,
            new NodeIncarnationId(route.NodeIncarnationId),
            1,
            0,
            new HashSet<string>(StringComparer.Ordinal)
            {
                "evidence-test"
            },
            new HashSet<string>(StringComparer.Ordinal),
            new Dictionary<StreamKind, long>(),
            new(64 * 1024, 8));

    private sealed class FakeResolver(
        params (string Reference, RdpDvcEvidenceRoute Route)[] routes) :
        IRdpDvcEvidenceTicketResolver
    {
        public IReadOnlyDictionary<string, RdpDvcEvidenceRoute> Routes
            { get; } = routes.ToDictionary(
                value => value.Reference,
                value => value.Route,
                StringComparer.Ordinal);

        public ValueTask<RdpDvcEvidenceRoute> ResolveAsync(
            string evidenceReference,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Routes[evidenceReference]);
        }
    }

    private sealed class OneWireSource(
        IRdpDvcWireChannel wire,
        int? sessionId) : IRdpDvcWireChannelSource
    {
        private IRdpDvcWireChannel? remaining = wire;

        public ValueTask<RdpDvcWireConnection> OpenChannelAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = Interlocked.Exchange(ref remaining, null) ??
                throw new InvalidOperationException(
                    "The test wire was already opened.");
            return ValueTask.FromResult(
                new RdpDvcWireConnection(value, sessionId));
        }
    }

    private sealed class WirePair
    {
        private WirePair(
            IRdpDvcWireChannel first,
            IRdpDvcWireChannel second)
        {
            First = first;
            Second = second;
        }

        public IRdpDvcWireChannel First { get; }
        public IRdpDvcWireChannel Second { get; }

        public static WirePair Create()
        {
            var firstToSecond = Channel.CreateBounded<byte[]>(8);
            var secondToFirst = Channel.CreateBounded<byte[]>(8);
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
}
