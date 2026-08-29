using Microsoft.Extensions.Options;
using Steward.Transport;

namespace Steward.Node;

public interface INodeClock
{
    DateTimeOffset UtcNow { get; }
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public interface IJitterSource
{
    double NextUnit();
}

public sealed record HostBootIdentity(Guid Id, bool Verified);

public interface IHostBootIdentityProvider
{
    HostBootIdentity GetCurrent();
}

// This fallback distinguishes service instances only. HostRuntime must replace it with a verified Host boot identity.
public sealed class UnverifiedProcessBootIdentityProvider : IHostBootIdentityProvider
{
    private static readonly Guid ProcessIdentity = Guid.NewGuid();
    public HostBootIdentity GetCurrent() => new(ProcessIdentity, false);
}

public sealed class SystemNodeClock : INodeClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) => Task.Delay(delay, cancellationToken);
}

public sealed class SystemJitterSource : IJitterSource
{
    public double NextUnit() => Random.Shared.NextDouble();
}

public sealed class NodeSessionOptions
{
    public string JournalPath { get; set; } = "steward-node.db";
    public TimeSpan MinimumReconnectDelay { get; set; } = TimeSpan.FromMilliseconds(100);
    public TimeSpan MaximumReconnectDelay { get; set; } = TimeSpan.FromSeconds(30);
    public int MaximumPayloadBytes { get; set; } = 1024 * 1024;
    public int MaximumBufferedFrames { get; set; } = 256;
    public HashSet<string> SupportedFeatures { get; set; } = new(StringComparer.Ordinal) { "reconciliation-v1", "resume-cursors-v1" };
    public HashSet<string> RequiredFeatures { get; set; } = new(StringComparer.Ordinal) { "reconciliation-v1" };
}

public sealed class Worker(
    NodeJournal journal,
    ITransportCarrier carrier,
    INodeClock clock,
    IJitterSource jitter,
    IHostBootIdentityProvider hostBootIdentityProvider,
    IOptions<NodeSessionOptions> options,
    ILogger<Worker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var hostBoot = hostBootIdentityProvider.GetCurrent();
        await journal.InitializeAsync(
            hostBootId: hostBoot.Id,
            hostBootIdentityVerified: hostBoot.Verified,
            cancellationToken: stoppingToken);
        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var sessionId = Guid.NewGuid();
                var cursors = await journal.GetStreamCursorsAsync(stoppingToken);
                var configured = options.Value;
                var hello = new SessionHello(
                    sessionId,
                    journal.Identity.IncarnationId,
                    1,
                    0,
                    configured.SupportedFeatures,
                    configured.RequiredFeatures,
                    cursors,
                    new TransportLimits(configured.MaximumPayloadBytes, configured.MaximumBufferedFrames));
                await using var connection = await carrier.ConnectAsync(hello, stoppingToken);
                await journal.BeginSessionAsync(connection.Session.SessionId, connection.Session.NodeIncarnationId, stoppingToken);
                failures = 0;
                await foreach (var frame in connection.ReceiveAsync(stoppingToken))
                    await journal.SetStreamCursorAsync(frame.Stream, frame.Cursor, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (TransportProtocolException ex) when (ex.Error == TransportError.UnsupportedRequiredFeature)
            {
                logger.LogWarning(ex, "Session refused because the peer does not support required features; journal remains available.");
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Node transport session ended; reconnecting.");
            }

            failures = Math.Min(failures + 1, 30);
            var delay = ComputeBackoff(failures, options.Value.MinimumReconnectDelay, options.Value.MaximumReconnectDelay, jitter.NextUnit());
            await clock.DelayAsync(delay, stoppingToken);
        }
    }

    public static TimeSpan ComputeBackoff(int failures, TimeSpan minimum, TimeSpan maximum, double jitterUnit)
    {
        if (minimum <= TimeSpan.Zero || maximum < minimum) throw new ArgumentOutOfRangeException(nameof(minimum));
        if (jitterUnit is < 0 or > 1) throw new ArgumentOutOfRangeException(nameof(jitterUnit));
        var exponent = Math.Min(Math.Max(failures - 1, 0), 20);
        var cappedTicks = Math.Min(maximum.Ticks, minimum.Ticks * Math.Pow(2, exponent));
        var half = cappedTicks / 2;
        return TimeSpan.FromTicks((long)Math.Min(maximum.Ticks, half + half * jitterUnit));
    }
}
