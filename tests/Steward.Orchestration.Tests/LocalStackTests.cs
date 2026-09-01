using System.IO.Pipes;
using System.Security.Cryptography;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.PortableState;
using Steward.Stack.Local;
using Steward.Transport;

namespace Steward.Orchestration.Tests;

public sealed class LocalStackTests
{
    [Fact]
    public async Task Control_owns_signing_key_and_terminates_bound_reconnect_session()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "control-reconnect-terminator",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var controlKey = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            using var nodeKey = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            var controlPrivate = Path.Combine(root, "control.pem");
            var nodePublic = Path.Combine(root, "node.pem");
            await File.WriteAllTextAsync(
                controlPrivate,
                controlKey.ExportPkcs8PrivateKeyPem());
            await File.WriteAllTextAsync(
                nodePublic,
                nodeKey.ExportSubjectPublicKeyInfoPem());
            var host = HostId.New();
            var incarnation = NodeIncarnationId.New();
            var sessionId = Guid.NewGuid();
            var binding = new ReconnectTransportBinding(
                2,
                host,
                incarnation,
                11,
                Guid.NewGuid(),
                42,
                Convert.ToHexString(
                    RandomNumberGenerator.GetBytes(32)));
            var attachment = new ReconnectCarrierAttachment(
                sessionId,
                binding);
            var endpoint = new NodeEndpointRegistration(
                host,
                incarnation,
                PoolId.New(),
                ExtensionMetadataDto.Create(
                    "direct-websocket", "1.0", new { }),
                "node",
                nodePublic,
                new ResourceRequirements(1),
                [],
                [],
                DateTimeOffset.UtcNow);
            var hello = new SessionHello(
                sessionId,
                incarnation,
                1,
                0,
                new HashSet<string>(["rdp-dvc-reconnect-v2"]),
                new HashSet<string>(["rdp-dvc-reconnect-v2"]),
                new Dictionary<StreamKind, long>(),
                new(64 * 1024, 8),
                binding);
            var pipeName = "Steward.Terminator." +
                Guid.NewGuid().ToString("N");
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                64 * 1024,
                64 * 1024);
            await using var client = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            var waiting = server.WaitForConnectionAsync();
            await client.ConnectAsync(CancellationToken.None);
            await waiting;
            var terminator = new ControlReconnectSessionTerminator(
                "control",
                controlPrivate,
                TimeSpan.FromSeconds(5));
            var accepting = terminator.AcceptAsync(
                server,
                attachment,
                endpoint,
                hello,
                CancellationToken.None);
            var nodeCarrier = new SecureStreamCarrier(
                new TestStreamConnector(client),
                new(
                    TransportEndpointRole.Node,
                    new EcdsaEndpointSigningKey(
                        "node",
                        ECDsa.Create(nodeKey.ExportParameters(true))),
                    new(
                        "control",
                        controlKey.ExportSubjectPublicKeyInfo()),
                    HandshakeTimeout: TimeSpan.FromSeconds(5)));
            var nodeConnecting = nodeCarrier.ConnectAsync(hello).AsTask();

            var established = await Task.WhenAll(
                accepting,
                nodeConnecting);
            await using var control = established[0];
            await using var node = established[1];

            Assert.Equal("control", control.Session.Security.LocalIdentity);
            Assert.Equal("node", control.Session.Security.RemoteIdentity);
            Assert.Equal(binding, control.Session.ReconnectBinding);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
    [Fact]
    public async Task Direct_session_replicates_between_distinct_filesystem_roots()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "local-stack-replication",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var source = Store(Path.Combine(root, "source"));
            var destination = Store(Path.Combine(root, "destination"));
            var content = RandomNumberGenerator.GetBytes(180_000);
            var path = Path.Combine(root, "object.bin");
            await File.WriteAllBytesAsync(path, content);
            var hash = Convert.ToHexStringLower(SHA256.HashData(content));
            var descriptor = new PortableObjectDescriptor(
                PortableObjectDescriptor.ContentAddressedName("artifacts", hash),
                PortableObjectId.New().ToString(),
                "1.0",
                "application/octet-stream",
                hash,
                content.Length,
                new Dictionary<string, string>());
            _ = await new PortableObjectUploader(source).UploadAsync(
                path, descriptor);

            var securityA = new VerifiedSessionSecurity(
                true, true, "node", "control", "binding");
            var securityB = new VerifiedSessionSecurity(
                true, true, "control", "node", "binding");
            var carriers = InMemoryDuplexCarrier.CreatePair(
                securityA, securityB);
            var hello = new SessionHello(
                Guid.NewGuid(),
                NodeIncarnationId.New(),
                1,
                0,
                new HashSet<string>(),
                new HashSet<string>(),
                new Dictionary<StreamKind, long>
                {
                    [StreamKind.Artifacts] = 7
                },
                new TransportLimits(256 * 1024, 32));
            var nodeConnect = carriers.First.ConnectAsync(hello).AsTask();
            var controlConnect = carriers.Second.ConnectAsync(hello).AsTask();
            await using var node = await nodeConnect;
            await using var control = await controlConnect;

            var client = new LocalPortableTransferClient();
            using var attachment = client.Attach(node);
            var receiver = new LocalPortableReceiveHandler(destination);
            using var cancellation = new CancellationTokenSource(
                TimeSpan.FromSeconds(10));
            var controlPump = PumpAsync(
                control, receiver, cancellation.Token);
            var nodePump = PumpAsync(
                node, client, cancellation.Token);
            var receipt = await client.ReplicateAsync(
                source, descriptor, cancellation.Token);

            Assert.Equal(hash, receipt.Sha256);
            await using var replicated = await destination.OpenReadAsync(
                descriptor.ObjectName, cancellation.Token);
            Assert.Equal(
                hash,
                Convert.ToHexStringLower(
                    await SHA256.HashDataAsync(
                        replicated, cancellation.Token)));
            cancellation.Cancel();
            await IgnoreCancellationAsync(controlPump);
            await IgnoreCancellationAsync(nodePump);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); }
            catch (IOException) { }
        }
    }

    private static LocalStackContentAddressedObjectStore Store(string root) =>
        new(LocalStackOptions.PortableStateBinding(new { rootPath = root }));

    private static async Task PumpAsync(
        ITransportConnection connection,
        IAuxiliaryTransportStreamHandler handler,
        CancellationToken cancellationToken)
    {
        await foreach (var frame in connection.ReceiveAsync(cancellationToken))
        {
            Assert.Equal(handler.Stream, frame.Stream);
            await handler.HandleAsync(
                connection, frame, cancellationToken);
        }
    }

    private static async Task IgnoreCancellationAsync(Task task)
    {
        try { await task; }
        catch (OperationCanceledException) { }
    }

    private sealed class TestStreamConnector(Stream stream) :
        ITransportStreamConnector
    {
        public ValueTask<Stream> ConnectStreamAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(stream);
        }
    }
}
