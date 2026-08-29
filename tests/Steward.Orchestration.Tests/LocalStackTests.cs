using System.Security.Cryptography;
using Steward.Domain;
using Steward.PortableState;
using Steward.Stack.Local;
using Steward.Transport;

namespace Steward.Orchestration.Tests;

public sealed class LocalStackTests
{
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
}
