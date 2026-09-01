using Steward.HandleKeeper;

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("Steward.HandleKeeper is a Windows service.");

var builder = Host.CreateApplicationBuilder(args);
if (args.Contains("--console", StringComparer.Ordinal))
{
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole();
}
else
{
    builder.Services.AddWindowsService(
        options => options.ServiceName = "Steward Handle Keeper");
}
var keeperOptions = new HandleKeeperOptions(
    GetOption(args, "--pipe") ??
        Environment.GetEnvironmentVariable("STEWARD_KEEPER_PIPE") ??
        "steward-handle-keeper-v1",
    GetOption(args, "--node-account") ??
        Environment.GetEnvironmentVariable("STEWARD_NODE_ACCOUNT")
        ?? throw new InvalidOperationException(
            "Expected Node account/SID must be configured."),
    MaximumMessageBytes: 16 * 1024,
    MaximumCachedRequests: GetIntOption(args, "--cache-capacity", 8192),
    RequestTimeout: TimeSpan.FromSeconds(5),
    IdempotencyTtl: TimeSpan.FromSeconds(
        GetIntOption(args, "--cache-ttl-seconds", 120)),
    MaximumRetainedLeases: GetIntOption(args, "--max-leases", 1024),
    TrustedMaintenanceImagePath: Path.GetFullPath(
        GetOption(args, "--maintenance-image") ??
        throw new InvalidOperationException(
            "Trusted maintenance image must be configured.")),
    TrustedProvisionerImagePath: Path.GetFullPath(
        GetOption(args, "--provisioner-image") ??
        throw new InvalidOperationException(
            "Trusted provisioner image must be configured.")));
var fenceStatePath = GetOption(args, "--fence-state-file") ??
    throw new InvalidOperationException(
        "Durable HandleKeeper fence state must be configured.");
var fenceKeyPath = GetOption(args, "--fence-key-file") ??
    throw new InvalidOperationException(
        "HandleKeeper fence authentication key must be configured.");
var fenceKey = File.ReadAllBytes(Path.GetFullPath(fenceKeyPath));
try
{
    var fenceState = new HandleKeeperDrainFenceState(
        new FileHandleKeeperFenceStore(
            Path.GetFullPath(fenceStatePath),
            fenceKey));
    builder.Services.AddSingleton(keeperOptions);
    builder.Services.AddSingleton(fenceState);
    builder.Services.AddSingleton(serviceProvider =>
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();
        return new HandleKeeperServer(
            serviceProvider.GetRequiredService<HandleKeeperOptions>(),
            serviceProvider.GetRequiredService<HandleKeeperDrainFenceState>());
    });
}
finally
{
    System.Security.Cryptography.CryptographicOperations.ZeroMemory(fenceKey);
}
builder.Services.AddHostedService<HandleKeeperWorker>();
await builder.Build().RunAsync();

static string? GetOption(string[] arguments, string name)
{
    var index = Array.IndexOf(arguments, name);
    return index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}

static int GetIntOption(string[] arguments, string name, int fallback) =>
    int.TryParse(GetOption(arguments, name), out var value) ? value : fallback;
