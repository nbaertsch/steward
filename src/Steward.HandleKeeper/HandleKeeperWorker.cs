using Microsoft.Extensions.Hosting;
using System.Runtime.Versioning;

namespace Steward.HandleKeeper;

[SupportedOSPlatform("windows")]
public sealed class HandleKeeperWorker(HandleKeeperServer server) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => server.RunAsync(stoppingToken);
}
