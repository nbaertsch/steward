using Microsoft.Extensions.Options;
using System.Text.Json;
using Steward.Domain;
using Steward.Orchestration;
using Steward.PortableState;
using Steward.Stack.Local;
using Steward.Transport;

namespace Steward.Node.Host;

public sealed class ProductionNodeWorker(
    IOptions<NodeHostOptions> configured,
    ValidatedLocalStackOptions localStack,
    ILocalTransportFactory transportFactory,
    IPortableObjectStore portableStore,
    LocalPortableTransferClient portableTransfer,
    ILogger<ProductionNodeWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "The Local Stack Node runtime requires Windows.");
        var options = configured.Value.Validate();
        await using var runtime = await ProductionNodeRuntime.CreateAsync(
            options,
            localStack.CredentialVaultRoot,
            portableStore,
            portableTransfer,
            taskReadinessDiagnostic: message =>
                logger.LogWarning("{TaskReadinessDiagnostic}", message),
            stoppingToken).ConfigureAwait(false);

        var endpoint = localStack.Nodes.SingleOrDefault(x =>
            x.HostId == options.HostId &&
            x.NodeIncarnationId == options.IncarnationId)
            ?? throw new InvalidOperationException(
                "The Node has no matching Local Stack transport endpoint.");
        var binding = endpoint.Transport.Data
            .Deserialize<LocalDirectTransportBinding>()
            ?.Validate()
            ?? throw new InvalidDataException(
                "The Node Local Stack transport binding is invalid.");

        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var hello = await runtime.CreateSessionHelloAsync(
                    DirectSessionId(options.HostId, options.IncarnationId),
                    new HashSet<string>(StringComparer.Ordinal)
                    {
                        "orchestration-v1", "reconciliation-v1", "resume-cursors-v1"
                    },
                    new HashSet<string>(StringComparer.Ordinal) { "orchestration-v1" },
                    new(
                        localStack.MaximumTransportPayloadBytes,
                        localStack.MaximumBufferedFrames),
                    stoppingToken).ConfigureAwait(false);

                ITransportConnection connection;
                IAsyncDisposable owner;
                if (binding.DialDirection == LocalDirectDialDirection.NodeDialsControl)
                {
                    var carrier = transportFactory.CreateDialer(
                        endpoint, TransportEndpointRole.Node);
                    owner = carrier as IAsyncDisposable
                        ?? new NoopAsyncDisposable();
                    connection = await carrier.ConnectAsync(hello, stoppingToken);
                }
                else
                {
                    var acceptor = transportFactory.CreateAcceptor(
                        endpoint, TransportEndpointRole.Node);
                    owner = acceptor;
                    connection = await acceptor.AcceptAsync(hello, stoppingToken);
                }
                await using (owner)
                await using (connection)
                {
                    failures = 0;
                    await runtime.RunSessionAsync(connection, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogWarning("Node session ended with {Code}; reconnecting.",
                    exception is TransportProtocolException protocol
                        ? protocol.Error.ToString()
                        : "session.failure");
            }
            failures = Math.Min(failures + 1, 10);
            await Task.Delay(
                TimeSpan.FromMilliseconds(Math.Min(30_000, 250 * Math.Pow(2, failures - 1))),
                stoppingToken);
        }
    }

    private static Guid DirectSessionId(
        HostId hostId,
        NodeIncarnationId incarnationId) =>
        new(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(
                $"steward-direct:{hostId}:{incarnationId}")).AsSpan(0, 16));

    private sealed class NoopAsyncDisposable : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
