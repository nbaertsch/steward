using Steward.HandleKeeper;

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("Steward.HandleKeeper is a Windows service.");

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "Steward Handle Keeper");
builder.Services.AddSingleton(new HandleKeeperOptions(
    GetOption(args, "--pipe") ?? Environment.GetEnvironmentVariable("STEWARD_KEEPER_PIPE") ?? "steward-handle-keeper-v1",
    GetOption(args, "--node-account") ?? Environment.GetEnvironmentVariable("STEWARD_NODE_ACCOUNT")
        ?? throw new InvalidOperationException("Expected Node account/SID must be configured."),
    MaximumMessageBytes: 16 * 1024,
    MaximumCachedRequests: GetIntOption(args, "--cache-capacity", 8192),
    RequestTimeout: TimeSpan.FromSeconds(5),
    IdempotencyTtl: TimeSpan.FromSeconds(GetIntOption(args, "--cache-ttl-seconds", 120)),
    MaximumRetainedLeases: GetIntOption(args, "--max-leases", 1024)));
builder.Services.AddSingleton<HandleKeeperServer>();
builder.Services.AddHostedService<HandleKeeperWorker>();
await builder.Build().RunAsync();

static string? GetOption(string[] arguments, string name)
{
    var index = Array.IndexOf(arguments, name);
    return index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}

static int GetIntOption(string[] arguments, string name, int fallback) =>
    int.TryParse(GetOption(arguments, name), out var value) ? value : fallback;
