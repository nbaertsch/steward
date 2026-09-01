using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;

namespace Steward.HandleKeeper;

[SupportedOSPlatform("windows")]
public sealed class HandleKeeperWorker(HandleKeeperServer server) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => server.RunAsync(stoppingToken);
}
