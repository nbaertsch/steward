using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Transport;

namespace Steward.Stack.Local;

[SupportedOSPlatform("windows")]
public sealed class LocalControlSessionWorker(
    ValidatedLocalStackOptions options,
    ILocalTransportFactory transport,
    ControlNodeRegistrationStore registrations,
    ControlOrchestrator orchestrator,
    ControlTerminalRouter terminals,
    ControlTerminalRevocationStore terminalRevocations,
    DirectSessionControlIdentityHandler identity,
    IEnumerable<IAuxiliaryTransportStreamHandler> auxiliaryHandlers,
    ILogger<LocalControlSessionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "The Local Stack credential vault requires Windows.");
        if (!options.TransportEnabled)
        {
            logger.LogInformation("Local Stack direct transport is disabled.");
            return;
        }
        foreach (var node in options.Nodes)
            await registrations.RegisterAsync(node, stoppingToken);

        var running = new Dictionary<NodeIncarnationId, LocalNodeSession>();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var configured = (await registrations.ListAsync(stoppingToken))
                    .Where(x => x.Enabled &&
                        x.Transport.Kind == LocalStackOptions.TransportKind &&
                        x.Transport.Version == LocalStackOptions.TransportVersion)
                    .ToDictionary(x => x.NodeIncarnationId);
                foreach (var existing in running.ToArray())
                {
                    if (configured.TryGetValue(existing.Key, out var current) &&
                        existing.Value.Fingerprint == Fingerprint(current) &&
                        !existing.Value.Task.IsCompleted)
                        continue;
                    running.Remove(existing.Key);
                    await StopAsync(existing.Value);
                }
                foreach (var endpoint in configured.Values)
                {
                    if (running.ContainsKey(endpoint.NodeIncarnationId))
                        continue;
                    var linked = CancellationTokenSource.CreateLinkedTokenSource(
                        stoppingToken);
                    running.Add(endpoint.NodeIncarnationId, new(
                        Fingerprint(endpoint),
                        linked,
                        RunEndpointAsync(endpoint, linked.Token)));
                }
                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
            }
        }
        finally
        {
            foreach (var session in running.Values)
                session.Cancellation.Cancel();
            foreach (var session in running.Values)
                await StopAsync(session);
        }
    }

    private async Task RunEndpointAsync(
        NodeEndpointRegistration endpoint,
        CancellationToken cancellationToken)
    {
        var binding = endpoint.Transport.Data
            .Deserialize<LocalDirectTransportBinding>()
            ?.Validate()
            ?? throw new InvalidDataException(
                "Local Stack direct transport binding is invalid.");
        var handlers = auxiliaryHandlers
            .Append<IAuxiliaryTransportStreamHandler>(
                new DirectSessionControlIdentityStreamHandler(
                    endpoint.HostId,
                    identity))
            .ToArray();
        var pump = new ControlSessionPump(
            orchestrator,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            terminals,
            terminalRevocations,
            handlers);
        var failures = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var hello = await HelloAsync(endpoint, cancellationToken);
                if (binding.DialDirection ==
                    LocalDirectDialDirection.ControlDialsNode)
                {
                    var carrier = transport.CreateDialer(
                        endpoint, TransportEndpointRole.Control);
                    try
                    {
                        await using var connection = await carrier.ConnectAsync(
                            hello, cancellationToken);
                        failures = 0;
                        await pump.RunSessionAsync(connection, cancellationToken);
                    }
                    finally
                    {
                        if (carrier is IAsyncDisposable disposable)
                            await disposable.DisposeAsync();
                    }
                }
                else
                {
                    await using var acceptor = transport.CreateAcceptor(
                        endpoint, TransportEndpointRole.Control);
                    await using var connection = await acceptor.AcceptAsync(
                        hello, cancellationToken);
                    failures = 0;
                    await pump.RunSessionAsync(connection, cancellationToken);
                }
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogWarning(
                    "Local direct session for Node {NodeId} ended with {Code} " +
                    "({ExceptionType}, 0x{HResult:X8}): {Detail}",
                    endpoint.NodeIncarnationId,
                    exception is TransportProtocolException protocol
                        ? protocol.Error.ToString()
                        : "direct-session-failure",
                    exception.GetType().Name,
                    exception.HResult,
                    BoundedDetail(exception.Message));
            }
            failures = Math.Min(failures + 1, 10);
            await Task.Delay(
                TimeSpan.FromMilliseconds(
                    Math.Min(30_000, 250 * Math.Pow(2, failures - 1))),
                cancellationToken);
        }
    }

    private async Task<SessionHello> HelloAsync(
        NodeEndpointRegistration endpoint,
        CancellationToken cancellationToken)
    {
        var cursor = await orchestrator.GetNodeCursorAsync(
            endpoint.NodeIncarnationId, cancellationToken);
        return new(
            SessionId(endpoint),
            endpoint.NodeIncarnationId,
            1,
            0,
            new HashSet<string>
            {
                "orchestration-v1",
                "terminal-v1",
                "direct-identity-v1",
                "portable-transfer-v1"
            },
            new HashSet<string> { "orchestration-v1" },
            new Dictionary<StreamKind, long>
            {
                [StreamKind.Events] = cursor,
                [StreamKind.Terminal] =
                    terminals.GetReceivedCursor(endpoint.NodeIncarnationId)
            },
            new(
                options.MaximumTransportPayloadBytes,
                options.MaximumBufferedFrames));
    }

    private static Guid SessionId(NodeEndpointRegistration endpoint)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(
            $"steward-direct:{endpoint.HostId}:{endpoint.NodeIncarnationId}");
        return new Guid(SHA256.HashData(bytes).AsSpan(0, 16));
    }

    private static string Fingerprint(NodeEndpointRegistration endpoint) =>
        $"{endpoint.HostId}|{endpoint.NodeIncarnationId}|" +
        $"{endpoint.Transport.Kind}|{endpoint.Transport.Version}|" +
        $"{endpoint.Transport.Data.GetRawText()}|" +
        $"{endpoint.PeerIdentity}|{endpoint.PeerPublicKeyReference}";

    private static string BoundedDetail(string value)
    {
        var sanitized = value.Replace('\r', ' ').Replace('\n', ' ');
        return sanitized.Length <= 512 ? sanitized : sanitized[..512];
    }

    private static async Task StopAsync(LocalNodeSession session)
    {
        session.Cancellation.Cancel();
        try
        {
            await session.Task;
        }
        catch (OperationCanceledException)
            when (session.Cancellation.IsCancellationRequested)
        {
        }
        finally
        {
            session.Cancellation.Dispose();
        }
    }

    private sealed record LocalNodeSession(
        string Fingerprint,
        CancellationTokenSource Cancellation,
        Task Task);
}
