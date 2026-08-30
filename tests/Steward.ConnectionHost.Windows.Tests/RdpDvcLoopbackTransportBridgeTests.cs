using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Steward.ConnectionHost.Windows;
using Steward.Domain;
using Steward.Transport;
using Steward.Transport.Local;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class RdpDvcLoopbackTransportBridgeTests : IDisposable
{
    private readonly string root = Path.Combine(
        AppContext.BaseDirectory,
        "rdp-dvc-loopback-bridge",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Bridge_relays_frames_and_survives_control_reconnect()
    {
        Directory.CreateDirectory(root);
        using var bridgeSigning = ECDsa.Create(
            ECCurve.NamedCurves.nistP256);
        using var controlSigning = ECDsa.Create(
            ECCurve.NamedCurves.nistP256);
        var bridgePrivate = Path.Combine(root, "bridge-private.pem");
        var controlPublic = Path.Combine(root, "control-public.pem");
        await File.WriteAllTextAsync(
            bridgePrivate,
            bridgeSigning.ExportPkcs8PrivateKeyPem());
        await File.WriteAllTextAsync(
            controlPublic,
            controlSigning.ExportSubjectPublicKeyInfoPem());

        var sessionId = Guid.NewGuid();
        var incarnation = NodeIncarnationId.New();
        var nodeHello = Hello(sessionId, incarnation);
        var remoteHello = Hello(sessionId, incarnation);
        var (nodeCarrier, remoteCarrier) =
            InMemoryDuplexCarrier.CreatePair(
                new(
                    true,
                    true,
                    "node",
                    "control",
                    "inner"),
                new(
                    true,
                    true,
                    "control",
                    "node",
                    "inner"));
        var nodeConnecting = nodeCarrier.ConnectAsync(nodeHello).AsTask();
        var remoteConnecting = remoteCarrier.ConnectAsync(remoteHello).AsTask();
        await using var node = await nodeConnecting;
        await using var remote = await remoteConnecting;

        var endpoint = LoopbackEndpoint();
        await using var bridge = new RdpDvcLoopbackTransportBridge(
            new(
                endpoint,
                "connection-host-b1",
                bridgePrivate,
                "control",
                controlPublic));
        await using var bridgeLease = await bridge.AttachAsync(
            remote,
            CancellationToken.None);

        await using var first = await ConnectControlAsync(
            endpoint,
            bridgeSigning,
            controlSigning,
            Hello(sessionId, incarnation));
        await node.SendAsync(Frame(
            sessionId,
            incarnation,
            StreamKind.Events,
            1,
            "from-node"));
        Assert.Equal(
            "from-node",
            Encoding.UTF8.GetString(
                (await ReadOneAsync(first)).Payload.Span));

        await first.SendAsync(Frame(
            sessionId,
            incarnation,
            StreamKind.Control,
            1,
            "from-control"));
        Assert.Equal(
            "from-control",
            Encoding.UTF8.GetString(
                (await ReadOneAsync(node)).Payload.Span));
        await first.DisposeAsync();

        var resumed = Hello(
            sessionId,
            incarnation,
            new Dictionary<StreamKind, long>
            {
                [StreamKind.Events] = 1
            });
        await using var second = await ConnectControlAsync(
            endpoint,
            bridgeSigning,
            controlSigning,
            resumed);
        await node.SendAsync(Frame(
            sessionId,
            incarnation,
            StreamKind.Events,
            2,
            "after-reconnect"));
        Assert.Equal(
            "after-reconnect",
            Encoding.UTF8.GetString(
                (await ReadOneAsync(second)).Payload.Span));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private static async Task<ITransportConnection> ConnectControlAsync(
        Uri endpoint,
        ECDsa bridgeSigning,
        ECDsa controlSigning,
        SessionHello hello)
    {
        var carrier = new DirectWebSocketCarrier(
            new(
                endpoint,
                TransportEndpointRole.Control,
                new EcdsaEndpointSigningKey(
                    "control",
                    ECDsa.Create(controlSigning.ExportParameters(true))),
                new(
                    "connection-host-b1",
                    bridgeSigning.ExportSubjectPublicKeyInfo()),
                AllowUnencryptedLoopback: true));
        return await carrier.ConnectAsync(hello);
    }

    private static SessionHello Hello(
        Guid sessionId,
        NodeIncarnationId incarnation,
        IReadOnlyDictionary<StreamKind, long>? cursors = null) =>
        new(
            sessionId,
            incarnation,
            1,
            0,
            new HashSet<string>(StringComparer.Ordinal)
            {
                "orchestration-v1",
                "reconciliation-v1",
                "resume-cursors-v1"
            },
            new HashSet<string>(StringComparer.Ordinal)
            {
                "orchestration-v1"
            },
            cursors ?? new Dictionary<StreamKind, long>(),
            new(64 * 1024, 32));

    private static TransportFrame Frame(
        Guid sessionId,
        NodeIncarnationId incarnation,
        StreamKind stream,
        long sequence,
        string value) =>
        new(
            sessionId,
            incarnation,
            stream,
            sequence,
            sequence,
            Encoding.UTF8.GetBytes(value));

    private static async Task<TransportFrame> ReadOneAsync(
        ITransportConnection connection)
    {
        using var timeout =
            new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await foreach (var frame in connection.ReceiveAsync(
                           timeout.Token))
            return frame;
        throw new EndOfStreamException();
    }

    private static Uri LoopbackEndpoint()
    {
        using var reservation = new TcpListener(
            IPAddress.Loopback,
            0);
        reservation.Start();
        var port = ((IPEndPoint)reservation.LocalEndpoint).Port;
        return new($"ws://127.0.0.1:{port}/steward/");
    }
}
