using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Steward.Maintenance.Windows;

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException(
        "Steward maintenance service requires Windows.");

var serviceArguments = MaintenanceServiceArguments.Parse(args);
MaintenanceStateSecurity.Protect(serviceArguments.StateRoot);
var configuration = MaintenanceServiceConfiguration.Load(
    serviceArguments.StateRoot);
var controlKeyPath = Path.Combine(
    serviceArguments.StateRoot,
    "control-signing.spki");
if (!File.Exists(controlKeyPath) ||
    File.GetAttributes(controlKeyPath).HasFlag(FileAttributes.ReparsePoint) ||
    new FileInfo(controlKeyPath).Length is < 64 or > 512)
    throw new InvalidDataException(
        "Maintenance Control trust key is unavailable.");
var controlKey = File.ReadAllBytes(controlKeyPath);
var machineSecret = MaintenanceMachineSecret.LoadOrCreate(
    Path.Combine(serviceArguments.StateRoot, "machine-secret.dpapi"));
var endpointSessionKeyPath = Path.Combine(
    configuration.EndpointStateRoot,
    "keys",
    "rdp-dvc.key");
if (!File.Exists(endpointSessionKeyPath) ||
    File.GetAttributes(endpointSessionKeyPath).HasFlag(
        FileAttributes.ReparsePoint) ||
    new FileInfo(endpointSessionKeyPath).Length != 32)
    throw new InvalidDataException(
        "Endpoint session authenticator is unavailable.");
var endpointSessionKey = File.ReadAllBytes(endpointSessionKeyPath);
try
{
    var handler = new SocketsHttpHandler
    {
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 3,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        MaxConnectionsPerServer = 2
    };
    var httpClient = new HttpClient(handler)
    {
        Timeout = TimeSpan.FromMinutes(10)
    };
    var authenticator = new MaintenanceRequestAuthenticator(
        controlKey,
        TimeProvider.System,
        TimeSpan.FromMinutes(5));
    var replay = new FileMaintenanceReplayStore(
        Path.Combine(serviceArguments.StateRoot, "replay.journal"),
        machineSecret,
        8192);
    var journal = new FileMaintenanceJournal(
        Path.Combine(serviceArguments.StateRoot, "operations.journal"),
        machineSecret);
    var coordinator = new MaintenanceCoordinator(
        authenticator,
        replay,
        journal,
        new WindowsMaintenanceOperationExecutor(
            serviceArguments.StateRoot,
            configuration,
            httpClient,
            machineSecret),
        new NamedPipeHandleKeeperDrainFence(
            configuration.KeeperPipeName,
            machineSecret));
    var pipeServer = new MaintenancePipeServer(
        new MaintenanceIpcOptions(
            configuration.PipeName,
            64 * 1024,
            4,
            TimeSpan.FromSeconds(30)),
        configuration.NodeUserSid,
        new MaintenanceSessionAuthenticator(
            endpointSessionKey,
            TimeProvider.System,
            TimeSpan.FromSeconds(15)),
        coordinator);

    var builder = Host.CreateApplicationBuilder(args);
    if (serviceArguments.Console)
    {
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
    }
    else
    {
        builder.Services.AddWindowsService(options =>
            options.ServiceName = "Steward Maintenance");
    }
    builder.Services.AddSingleton(httpClient);
    builder.Services.AddSingleton(coordinator);
    builder.Services.AddSingleton(pipeServer);
    builder.Services.AddHostedService<MaintenanceWorker>();
    await builder.Build().RunAsync().ConfigureAwait(false);
}
finally
{
    CryptographicOperations.ZeroMemory(controlKey);
    CryptographicOperations.ZeroMemory(machineSecret);
    CryptographicOperations.ZeroMemory(endpointSessionKey);
}

internal sealed record MaintenanceServiceArguments(
    string StateRoot,
    bool Console)
{
    internal static MaintenanceServiceArguments Parse(string[] arguments)
    {
        string? stateRoot = null;
        var console = false;
        for (var index = 0; index < arguments.Length; index++)
        {
            switch (arguments[index])
            {
                case "--console" when !console:
                    console = true;
                    break;
                case "--state-root" when stateRoot is null &&
                    index + 1 < arguments.Length:
                    stateRoot = arguments[++index];
                    break;
                default:
                    throw new ArgumentException(
                        "Usage: --state-root PATH [--console]");
            }
        }
        if (string.IsNullOrWhiteSpace(stateRoot))
            throw new ArgumentException(
                "Maintenance state root is required.");
        var full = Path.GetFullPath(stateRoot);
        MaintenanceStateSecurity.ValidatePath(full);
        return new MaintenanceServiceArguments(full, console);
    }
}

internal sealed class MaintenanceWorker(
    MaintenanceCoordinator coordinator,
    MaintenancePipeServer pipeServer,
    ILogger<MaintenanceWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        var recovery = await coordinator.RecoverAsync(stoppingToken)
            .ConfigureAwait(false);
        if (recovery.Failed > 0)
            logger.LogError(
                "{FailedCount} maintenance operations failed recovery.",
                recovery.Failed);
        if (recovery.Deferred > 0)
            logger.LogInformation(
                "{DeferredCount} maintenance operations await reboot.",
                recovery.Deferred);
        await pipeServer.RunAsync(stoppingToken).ConfigureAwait(false);
    }
}

