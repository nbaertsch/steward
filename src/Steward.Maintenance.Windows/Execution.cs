using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Runtime.Windows;

namespace Steward.Maintenance.Windows;

internal sealed class NamedPipeHandleKeeperDrainFence :
    IHandleKeeperDrainFence
{
    private static readonly byte[] CapabilityContext =
        "Steward.HandleKeeper.Fence.v1"u8.ToArray();
    private readonly string pipeName;
    private readonly byte[] machineAuthenticationKey;

    internal NamedPipeHandleKeeperDrainFence(
        string pipeName,
        ReadOnlySpan<byte> machineAuthenticationKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        if (machineAuthenticationKey.Length != 32)
            throw new ArgumentException(
                "HandleKeeper fence key must be 256 bits.",
                nameof(machineAuthenticationKey));
        this.pipeName = pipeName;
        this.machineAuthenticationKey = machineAuthenticationKey.ToArray();
    }

    public ValueTask<IAsyncDisposable> AcquireAsync(
        HandleKeeperDrainRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var capability = DeriveCapability(request.TransactionId);
        using var keeper = CreateClient();
        var status = keeper.FenceStatus();
        var acquisition = keeper.AcquireDrainFence(
            request.TransactionId,
            request.ScopeId,
            capability,
            status.Generation);
        if (!acquisition.Acquired)
        {
            _ = keeper.ReleaseDrainFence(acquisition.Lease);
            throw new MaintenanceProtocolException(
                "live_leases",
                "HandleKeeper has live leases; privileged cutover is refused.");
        }
        return ValueTask.FromResult<IAsyncDisposable>(
            new FenceScope(pipeName, acquisition.Lease));
    }

    private JobKeeperFenceCapability DeriveCapability(Guid transactionId) =>
        CreateCapability(machineAuthenticationKey, transactionId);

    internal static JobKeeperFenceCapability CreateCapability(
        ReadOnlySpan<byte> machineAuthenticationKey,
        Guid transactionId)
    {
        if (machineAuthenticationKey.Length != 32)
            throw new ArgumentException(
                "HandleKeeper fence key must be 256 bits.",
                nameof(machineAuthenticationKey));
        if (transactionId == Guid.Empty)
            throw new ArgumentException(
                "Fence transaction identity is required.",
                nameof(transactionId));
        var input = new byte[CapabilityContext.Length + 16];
        CapabilityContext.CopyTo(input, 0);
        transactionId.TryWriteBytes(input.AsSpan(CapabilityContext.Length));
        var capability = HMACSHA256.HashData(
            machineAuthenticationKey,
            input);
        try
        {
            return new JobKeeperFenceCapability(
                Convert.ToBase64String(capability));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(capability);
        }
    }

    private NamedPipeJobHandleKeeper CreateClient() => new(new(
        pipeName,
        TimeSpan.FromSeconds(3),
        ConnectAttempts: 2));

    private sealed class FenceScope(
        string pipeName,
        JobKeeperFenceLease lease) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            using var keeper = new NamedPipeJobHandleKeeper(new(
                pipeName,
                TimeSpan.FromSeconds(3),
                ConnectAttempts: 2));
            var status = keeper.FenceStatus();
            if (status.Phase == JobKeeperFencePhase.Unfenced)
                return ValueTask.CompletedTask;
            _ = keeper.ReleaseDrainFence(lease with
            {
                Generation = status.Generation,
                Depth = status.Depth,
                Phase = status.Phase
            });
            return ValueTask.CompletedTask;
        }
    }
}
internal sealed record ProcessResult(int ExitCode, string Output);

internal sealed partial class WindowsMaintenanceOperationExecutor(
    string stateRoot,
    MaintenanceServiceConfiguration configuration,
    HttpClient httpClient,
    byte[] machineAuthenticationKey) :
    IMaintenanceOperationExecutor,
    IEndpointUpdatePlatform
{
    private const int MaximumToolOutputCharacters = 8192;
    private const string StewardConfigProperty = "STEWARD_CONFIG";
    private const string StewardAttestationProperty = "STEWARD_ATTESTATION";
    private readonly string stateRoot = Path.GetFullPath(stateRoot);
    private readonly byte[] machineAuthenticationKey =
        machineAuthenticationKey.Length == 32
            ? machineAuthenticationKey.ToArray()
            : throw new ArgumentException(
                "Maintenance machine authentication key must be 256 bits.",
                nameof(machineAuthenticationKey));

    public async Task<MaintenanceExecutionResult> ExecuteAsync(
        MaintenanceOperation operation,
        MaintenanceExecutionContext context,
        CancellationToken cancellationToken) => operation switch
        {
            ActivateEndpointUpdateOperation update =>
                await ActivateUpdateAsync(update, context, cancellationToken)
                    .ConfigureAwait(false),
            ConfigureWslOperation wsl =>
                await ConfigureWslAsync(wsl, context, cancellationToken)
                    .ConfigureAwait(false),
            ImportWslDistributionOperation distribution =>
                await ImportDistributionAsync(distribution, cancellationToken)
                    .ConfigureAwait(false),
            ConfigureDockerOperation docker =>
                await ConfigureDockerAsync(docker, cancellationToken)
                    .ConfigureAwait(false),
            RepairEndpointOperation repair =>
                await RepairAsync(repair, cancellationToken)
                    .ConfigureAwait(false),
            CollectDiagnosticsOperation diagnostics =>
                await CollectDiagnosticsAsync(diagnostics, cancellationToken)
                    .ConfigureAwait(false),
            ContinueAfterRebootOperation reboot =>
                await RebootAsync(reboot, context, cancellationToken)
                    .ConfigureAwait(false),
            _ => throw new MaintenanceProtocolException(
                "unknown_operation",
                "Maintenance operation is unsupported.")
        };

    private async Task<MaintenanceExecutionResult> ActivateUpdateAsync(
        ActivateEndpointUpdateOperation operation,
        MaintenanceExecutionContext context,
        CancellationToken cancellationToken)
    {
        var store = new FileEndpointUpdateTransactionStore(
            Path.Combine(stateRoot, "endpoint-update.journal"),
            machineAuthenticationKey,
            configuration.InstalledProductVersion);
        var coordinator = new EndpointUpdateCoordinator(
            store,
            this,
            maximumHealthObservations: 24,
            transactionId: context.OperationId);
        try
        {
            _ = await coordinator.ExecuteAsync(operation, cancellationToken)
                .ConfigureAwait(false);
            return MaintenanceExecutionResult.Succeeded();
        }
        catch (EndpointUpdateException exception)
        {
            throw new MaintenanceProtocolException(
                exception.Code,
                exception.Message);
        }
    }
    private async Task<UpdateProvisioningPaths> WriteUpdateProvisioningAsync(
        ActivateEndpointUpdateOperation operation,
        MsiMetadata metadata,
        CancellationToken cancellationToken)
    {
        var bootstrapPath = Path.Combine(
            stateRoot,
            "bootstrap-envelope.spki");
        var controlPath = Path.Combine(
            stateRoot,
            "control-signing.spki");
        if (!File.Exists(bootstrapPath) || !File.Exists(controlPath))
            throw new InvalidDataException(
                "Maintenance update trust files are unavailable.");
        var staging = Path.Combine(stateRoot, "staging");
        Directory.CreateDirectory(staging);
        var updateBootstrapPath = Path.Combine(
            staging,
            "bootstrap-envelope.spki");
        var updateControlPath = Path.Combine(
            staging,
            "control-signing.spki");
        File.Copy(bootstrapPath, updateBootstrapPath, overwrite: true);
        File.Copy(controlPath, updateControlPath, overwrite: true);
        var provisioningConfigPath = Path.Combine(
            staging,
            "update-provisioning.json");
        var provisioningConfig = new UpdateProvisioningConfiguration(
            1,
            operation.ProductVersion,
            Path.GetFileName(updateBootstrapPath),
            Path.GetFileName(updateControlPath),
            configuration.ControlIdentity,
            configuration.NodeUserAccount,
            configuration.NodeUserSid);
        await WriteAtomicAsync(
                provisioningConfigPath,
                JsonSerializer.SerializeToUtf8Bytes(provisioningConfig),
                cancellationToken)
            .ConfigureAwait(false);
        var attestationPath = Path.Combine(
            staging,
            "update-artifact-attestation.json");
        var attestation = new UpdateArtifactAttestation(
            1,
            operation.ProductVersion,
            operation.Package.Sha256,
            operation.Provenance.SourceRepository,
            operation.Provenance.SourceCommit,
            operation.Provenance.SourceRef,
            operation.Provenance.SignerWorkflow,
            operation.Provenance.SourceRunId,
            metadata.ProductCode,
            FileSha256(provisioningConfigPath),
            FileSha256(updateBootstrapPath),
            FileSha256(updateControlPath),
            configuration.ControlIdentity);
        await WriteAtomicAsync(
                attestationPath,
                JsonSerializer.SerializeToUtf8Bytes(attestation),
                cancellationToken)
            .ConfigureAwait(false);
        return new UpdateProvisioningPaths(
            provisioningConfigPath,
            attestationPath);
    }

    private async Task<MaintenanceExecutionResult> ConfigureWslAsync(
        ConfigureWslOperation operation,
        MaintenanceExecutionContext context,
        CancellationToken cancellationToken)
    {
        if (context.IsRecovery &&
            context.Continuation is { Length: > 0 } priorBoot)
        {
            if (!RebootObserved(priorBoot, BootIdentity()))
                throw new MaintenanceProtocolException(
                    "reboot_not_observed",
                    "Required WSL reboot has not occurred.");
            await EnsureWslVersionAsync(cancellationToken)
                .ConfigureAwait(false);
            return MaintenanceExecutionResult.Succeeded();
        }
        var wsl = await RunAsync(
                MaintenanceTool.Dism,
                [
                    "/Online", "/Enable-Feature",
                    "/FeatureName:Microsoft-Windows-Subsystem-Linux",
                    "/All", "/NoRestart"
                ],
                cancellationToken)
            .ConfigureAwait(false);
        RequireDismSuccess(wsl);
        var virtualMachine = await RunAsync(
                MaintenanceTool.Dism,
                [
                    "/Online", "/Enable-Feature",
                    "/FeatureName:VirtualMachinePlatform",
                    "/All", "/NoRestart"
                ],
                cancellationToken)
            .ConfigureAwait(false);
        RequireDismSuccess(virtualMachine);
        var package = await DownloadAsync(
                operation.Package,
                "wsl.2.7.12.0.x64.msi",
                cancellationToken)
            .ConfigureAwait(false);
        var install = await RunAsync(
                MaintenanceTool.WindowsInstaller,
                ["/i", package, "/qn", "/norestart"],
                cancellationToken)
            .ConfigureAwait(false);
        if (install.ExitCode is not (0 or 1641 or 3010))
            throw new MaintenanceProtocolException(
                "wsl_configuration_failed",
                "Approved WSL 2.7.12 package installation failed.");
        var rebootRequired = wsl.ExitCode == 3010 ||
            virtualMachine.ExitCode == 3010 ||
            install.ExitCode is 1641 or 3010;
        if (rebootRequired)
            return MaintenanceExecutionResult.AwaitingReboot(BootIdentity());
        await EnsureWslVersionAsync(cancellationToken).ConfigureAwait(false);
        return MaintenanceExecutionResult.Succeeded();
    }

    private async Task<MaintenanceExecutionResult> ImportDistributionAsync(
        ImportWslDistributionOperation operation,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(operation.User.Sid, configuration.NodeUserSid,
                StringComparison.Ordinal) ||
            !string.Equals(operation.User.Account,
                configuration.NodeUserAccount,
                StringComparison.OrdinalIgnoreCase))
            throw new MaintenanceProtocolException(
                "assigned_user_mismatch",
                "WSL distribution operation targets another user.");
        var package = await DownloadAsync(
                operation.Package,
                "ubuntu-24.04-rootfs.tar.gz",
                cancellationToken)
            .ConfigureAwait(false);
        var userRuntime = Path.Combine(
            Path.GetDirectoryName(stateRoot) ??
                throw new InvalidDataException(
                    "Maintenance state root has no parent."),
            "UserRuntime",
            operation.User.Sid);
        var distributionRoot = Path.Combine(
            userRuntime,
            "wsl",
            "Ubuntu-24.04");
        PrepareAssignedUserDirectory(userRuntime, operation.User.Sid);
        Directory.CreateDirectory(Path.GetDirectoryName(distributionRoot)!);
        PrepareAssignedUserDirectory(
            Path.GetDirectoryName(distributionRoot)!,
            operation.User.Sid);
        var wslExecutable = Path.Combine(
            Environment.SystemDirectory,
            "wsl.exe");
        var import = await AssignedUserProcessRunner.RunAsync(
                operation.User,
                wslExecutable,
                [
                    "--import", "Ubuntu-24.04", distributionRoot,
                    package, "--version", "2"
                ],
                cancellationToken)
            .ConfigureAwait(false);
        if (import.ExitCode != 0)
            throw new MaintenanceProtocolException(
                "wsl_distribution_failed",
                "Assigned-user WSL distribution import failed.");
        var configure = await AssignedUserProcessRunner.RunAsync(
                operation.User,
                wslExecutable,
                [
                    "--manage", "Ubuntu-24.04",
                    "--set-default-user", "ubuntu"
                ],
                cancellationToken)
            .ConfigureAwait(false);
        RequireSuccess(configure, "wsl_distribution_failed");
        return MaintenanceExecutionResult.Succeeded();
    }

    private async Task<MaintenanceExecutionResult> ConfigureDockerAsync(
        ConfigureDockerOperation operation,
        CancellationToken cancellationToken)
    {
        var engine = await DownloadAsync(
                operation.EnginePackage,
                "docker-28.3.1.zip",
                cancellationToken)
            .ConfigureAwait(false);
        var compose = await DownloadAsync(
                operation.ComposePackage,
                "docker-compose-windows-x86_64.exe",
                cancellationToken)
            .ConfigureAwait(false);
        var runtime = Path.Combine(stateRoot, "docker", "runtime");
        Directory.CreateDirectory(runtime);
        ExtractApprovedDockerArchive(engine, runtime);
        var plugins = Path.Combine(runtime, "cli-plugins");
        Directory.CreateDirectory(plugins);
        PrepareForOverwrite(
            Path.Combine(plugins, "docker-compose.exe"));
        File.Copy(
            compose,
            Path.Combine(plugins, "docker-compose.exe"),
            overwrite: true);
        PrepareForOverwrite(
            Path.Combine(runtime, "docker-compose.exe"));
        File.Copy(
            compose,
            Path.Combine(runtime, "docker-compose.exe"),
            overwrite: true);
        var daemonConfig = Path.Combine(stateRoot, "docker", "daemon.json");
        var daemonBytes = JsonSerializer.SerializeToUtf8Bytes(
            new DockerDaemonFile(
                operation.Configuration.Experimental,
                operation.Configuration.ShutdownTimeoutSeconds,
                operation.Configuration.MaximumConcurrentDownloads,
                "StewardDockerTasks"));
        await WriteAtomicAsync(daemonConfig, daemonBytes, cancellationToken)
            .ConfigureAwait(false);
        var dockerd = Path.Combine(runtime, "dockerd.exe");
        var docker = Path.Combine(runtime, "docker.exe");
        RequireSha256(
            dockerd,
            MaintenanceArtifactCatalog.DockerDaemonSha256);
        RequireSha256(
            docker,
            MaintenanceArtifactCatalog.DockerClientSha256);
        await ConfigureDockerTaskCapabilityAsync(
                operation.TaskIdentities,
                docker,
                Path.Combine(plugins, "docker-compose.exe"),
                cancellationToken)
            .ConfigureAwait(false);
        var registration = await RunApprovedDockerDaemonAsync(
                dockerd,
                ["--register-service", "--config-file", daemonConfig],
                cancellationToken)
            .ConfigureAwait(false);
        if (registration.ExitCode != 0 &&
            !registration.Output.Contains(
                "already exists",
                StringComparison.OrdinalIgnoreCase))
            throw new MaintenanceProtocolException(
                "docker_configuration_failed",
                "Approved Docker service registration failed.");
        var start = await RunAsync(
                MaintenanceTool.ServiceControl,
                ["start", "docker"],
                cancellationToken)
            .ConfigureAwait(false);
        if (start.ExitCode != 0 &&
            !start.Output.Contains("already",
                StringComparison.OrdinalIgnoreCase))
            throw new MaintenanceProtocolException(
                "docker_configuration_failed",
                "Approved Docker service start failed.");
        var engineVersion = await RunProcessAsync(
                docker,
                ["version", "--format", "{{.Server.Version}}"],
                cancellationToken)
            .ConfigureAwait(false);
        var composeVersion = await RunProcessAsync(
                Path.Combine(runtime, "docker-compose.exe"),
                ["version", "--short"],
                cancellationToken)
            .ConfigureAwait(false);
        if (engineVersion.ExitCode != 0 ||
            !engineVersion.Output.Contains(
                MaintenanceArtifactCatalog.DockerEngineVersion,
                StringComparison.Ordinal) ||
            composeVersion.ExitCode != 0 ||
            !composeVersion.Output.Contains(
                MaintenanceArtifactCatalog.DockerComposeVersion,
                StringComparison.Ordinal))
            throw new MaintenanceProtocolException(
                "docker_smoke_failed",
                "Docker native smoke capability proof failed.");
        var proof = new DockerCapabilityProof(
            1,
            MaintenanceArtifactCatalog.DockerEngineVersion,
            MaintenanceArtifactCatalog.DockerComposeVersion,
            FileSha256(docker),
            FileSha256(Path.Combine(runtime, "docker-compose.exe")),
            "npipe:////./pipe/docker_engine",
            operation.TaskIdentities,
            true,
            DateTimeOffset.UtcNow);
        await WriteAtomicAsync(
                Path.Combine(stateRoot, "docker", "capability.json"),
                JsonSerializer.SerializeToUtf8Bytes(proof),
                cancellationToken)
            .ConfigureAwait(false);
        return MaintenanceExecutionResult.Succeeded();
    }

    private async Task<MaintenanceExecutionResult> RepairAsync(
        RepairEndpointOperation operation,
        CancellationToken cancellationToken)
    {
        ProcessResult result;
        switch (operation.Target)
        {
            case RepairTarget.MaintenanceService:
                result = await RunAsync(
                        MaintenanceTool.ServiceControl,
                        ["config", "StewardMaintenance", "start=", "auto"],
                        cancellationToken)
                    .ConfigureAwait(false);
                RequireSuccess(result, "repair_failed");
                result = await RunAsync(
                        MaintenanceTool.ServiceControl,
                        ["start", "StewardMaintenance"],
                        cancellationToken)
                    .ConfigureAwait(false);
                break;
            case RepairTarget.HandleKeeperTask:
                result = await RunAsync(
                        MaintenanceTool.TaskScheduler,
                        [
                            "/Run", "/TN",
                            $@"\Steward\HandleKeeper-{configuration.HostId:N}"
                        ],
                        cancellationToken)
                    .ConfigureAwait(false);
                break;
            case RepairTarget.RdpDvcEndpointTask:
                result = await RunAsync(
                        MaintenanceTool.TaskScheduler,
                        [
                            "/Run", "/TN",
                            $@"\Steward\RdpDvcEndpoint-{configuration.HostId:N}"
                        ],
                        cancellationToken)
                    .ConfigureAwait(false);
                break;
            default:
                throw new MaintenanceProtocolException(
                    "repair_target_unknown",
                    "Repair target is unsupported.");
        }
        RequireSuccess(result, "repair_failed");
        return MaintenanceExecutionResult.Succeeded();
    }

    private async Task<MaintenanceExecutionResult> CollectDiagnosticsAsync(
        CollectDiagnosticsOperation operation,
        CancellationToken cancellationToken)
    {
        var service = await RunAsync(
                MaintenanceTool.ServiceControl,
                ["query", "StewardMaintenance"],
                cancellationToken)
            .ConfigureAwait(false);
        var keeper = await RunAsync(
                MaintenanceTool.TaskScheduler,
                [
                    "/Query", "/TN",
                    $@"\Steward\HandleKeeper-{configuration.HostId:N}",
                    "/FO", "LIST"
                ],
                cancellationToken)
            .ConfigureAwait(false);
        var endpoint = await RunAsync(
                MaintenanceTool.TaskScheduler,
                [
                    "/Query", "/TN",
                    $@"\Steward\RdpDvcEndpoint-{configuration.HostId:N}",
                    "/FO", "LIST"
                ],
                cancellationToken)
            .ConfigureAwait(false);
        var snapshot = new MaintenanceDiagnosticSnapshot(
            1,
            DateTimeOffset.UtcNow,
            service.ExitCode,
            Bound(service.Output, 1024),
            keeper.ExitCode,
            Bound(keeper.Output, 1024),
            endpoint.ExitCode,
            Bound(endpoint.Output, 1024));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot);
        if (bytes.Length > operation.MaximumBytes)
            throw new MaintenanceProtocolException(
                "diagnostics_bound",
                "Maintenance diagnostics exceed the requested bound.");
        var directory = Path.Combine(stateRoot, "diagnostics");
        Directory.CreateDirectory(directory);
        await WriteAtomicAsync(
                Path.Combine(directory, "latest.json"),
                bytes,
                cancellationToken)
            .ConfigureAwait(false);
        return MaintenanceExecutionResult.Succeeded();
    }

    private async Task<MaintenanceExecutionResult> RebootAsync(
        ContinueAfterRebootOperation operation,
        MaintenanceExecutionContext context,
        CancellationToken cancellationToken)
    {
        if (context.IsRecovery)
        {
            if (context.Continuation is null ||
                !RebootObserved(context.Continuation, BootIdentity()))
                throw new MaintenanceProtocolException(
                    "reboot_not_observed",
                    "Required reboot has not occurred.");
            return MaintenanceExecutionResult.Succeeded();
        }
        var identity = BootIdentity();
        var result = await RunAsync(
                MaintenanceTool.Shutdown,
                ["/r", "/t", "5", "/d", "p:4:1"],
                cancellationToken)
            .ConfigureAwait(false);
        RequireSuccess(result, "reboot_failed");
        return MaintenanceExecutionResult.AwaitingReboot(identity);
    }

    private async Task<string> DownloadAsync(
        ApprovedArtifact artifact,
        string name,
        CancellationToken cancellationToken)
    {
        MaintenanceContract.ValidateArtifact(artifact);
        var directory = Path.Combine(stateRoot, "staging");
        Directory.CreateDirectory(directory);
        var destination = Path.Combine(directory, name);
        if (File.Exists(destination) && ArtifactMatches(destination, artifact))
            return destination;
        var pending = destination + ".new";
        using var request = new HttpRequestMessage(HttpMethod.Get, artifact.Uri);
        using var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode ||
            !ApprovedDownloadDestination(
                artifact.Uri,
                response.RequestMessage?.RequestUri) ||
            response.Content.Headers.ContentLength is long contentLength &&
            contentLength != artifact.Length)
            throw new MaintenanceProtocolException(
                "artifact_download_failed",
                "Approved maintenance artifact download failed.");
        try
        {
            await using var input = await response.Content.ReadAsStreamAsync(
                    cancellationToken)
                .ConfigureAwait(false);
            await using var output = new FileStream(
                pending,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            var buffer = new byte[64 * 1024];
            long total = 0;
            while (true)
            {
                var read = await input.ReadAsync(buffer, cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                    break;
                total += read;
                if (total > artifact.Length)
                    throw new MaintenanceProtocolException(
                        "artifact_size_mismatch",
                        "Approved maintenance artifact size mismatched.");
                await output.WriteAsync(
                        buffer.AsMemory(0, read),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
            if (total != artifact.Length)
                throw new MaintenanceProtocolException(
                    "artifact_size_mismatch",
                    "Approved maintenance artifact size mismatched.");
            File.Move(pending, destination, overwrite: true);
            if (!ArtifactMatches(destination, artifact))
                throw new MaintenanceProtocolException(
                    "hash_mismatch",
                    "Approved maintenance artifact hash mismatched.");
            return destination;
        }
        finally
        {
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }

    private static bool ApprovedDownloadDestination(
        Uri requested,
        Uri? actual)
    {
        if (actual is null ||
            !actual.IsAbsoluteUri ||
            !string.Equals(actual.Scheme, Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(actual.UserInfo) ||
            !string.IsNullOrEmpty(actual.Fragment))
            return false;
        if (actual == requested)
            return true;
        return string.Equals(
                requested.Host,
                "github.com",
                StringComparison.OrdinalIgnoreCase) &&
            string.Equals(
                actual.Host,
                "release-assets.githubusercontent.com",
                StringComparison.OrdinalIgnoreCase);
    }
    private static bool ArtifactMatches(
        string path,
        ApprovedArtifact artifact)
    {
        if (new FileInfo(path).Length != artifact.Length ||
            File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            return false;
        var expected = Convert.FromHexString(artifact.Sha256);
        var actual = SHA256.HashData(File.ReadAllBytes(path));
        try
        {
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static async Task EnsureWslVersionAsync(
        CancellationToken cancellationToken)
    {
        var version = await RunAsync(
                MaintenanceTool.Wsl,
                ["--version"],
                cancellationToken)
            .ConfigureAwait(false);
        if (version.ExitCode != 0 ||
            !version.Output.Contains(
                MaintenanceArtifactCatalog.WslVersion,
                StringComparison.Ordinal))
            throw new MaintenanceProtocolException(
                "wsl_version_mismatch",
                "Installed WSL runtime is not the approved version 2.7.12.");
    }

    private static void PrepareAssignedUserDirectory(
        string path,
        string userSid)
    {
        Directory.CreateDirectory(path);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        var system = new SecurityIdentifier(
            WellKnownSidType.LocalSystemSid,
            null);
        var administrators = new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);
        var assigned = new SecurityIdentifier(userSid);
        security.SetOwner(system);
        foreach (var sid in new[] { system, administrators, assigned })
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit |
                InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private async Task ConfigureDockerTaskCapabilityAsync(
        IReadOnlyList<DockerTaskIdentity> identities,
        string docker,
        string compose,
        CancellationToken cancellationToken)
    {
        var group = await RunAsync(
                MaintenanceTool.LocalGroup,
                ["localgroup", "StewardDockerTasks", "/add"],
                cancellationToken)
            .ConfigureAwait(false);
        if (group.ExitCode != 0 &&
            !group.Output.Contains("already exists",
                StringComparison.OrdinalIgnoreCase))
            throw new MaintenanceProtocolException(
                "docker_capability_failed",
                "The narrow Docker transport group could not be created.");
        foreach (var identity in identities.DistinctBy(value => value.Sid))
        {
            var member = await RunAsync(
                    MaintenanceTool.LocalGroup,
                    [
                        "localgroup", "StewardDockerTasks",
                        "*" + identity.Sid, "/add"
                    ],
                    cancellationToken)
                .ConfigureAwait(false);
            if (member.ExitCode != 0 &&
                !member.Output.Contains("already",
                    StringComparison.OrdinalIgnoreCase))
                throw new MaintenanceProtocolException(
                    "docker_capability_failed",
                    "A declared Docker task identity could not receive transport capability.");
        }
        var clientRoot = Path.Combine(
            Path.GetDirectoryName(stateRoot) ??
                throw new InvalidDataException(
                    "Maintenance state root has no parent."),
            "DockerClient");
        var pluginRoot = Path.Combine(clientRoot, "cli-plugins");
        Directory.CreateDirectory(pluginRoot);
        var client = Path.Combine(clientRoot, "docker.exe");
        var clientCompose = Path.Combine(pluginRoot, "docker-compose.exe");
        PrepareForOverwrite(client);
        PrepareForOverwrite(clientCompose);
        File.Copy(docker, client, overwrite: true);
        File.Copy(compose, clientCompose, overwrite: true);
        File.SetAttributes(client, FileAttributes.ReadOnly);
        File.SetAttributes(clientCompose, FileAttributes.ReadOnly);
        ProtectDockerClientCapability(clientRoot, identities);
    }

    internal static void ProtectDockerClientCapability(
        string root,
        IReadOnlyList<DockerTaskIdentity> identities,
        SecurityIdentifier? ownerOverride = null)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        var system = new SecurityIdentifier(
            WellKnownSidType.LocalSystemSid,
            null);
        var administrators = new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);
        var owner = ownerOverride ?? system;
        if (ownerOverride is null)
            security.SetOwner(owner);
        foreach (var sid in new[] { system, administrators })
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit |
                InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        foreach (var identity in identities.DistinctBy(value => value.Sid))
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(identity.Sid),
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit |
                InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        new DirectoryInfo(root).SetAccessControl(security);
        foreach (var directory in Directory.EnumerateDirectories(
                     root,
                     "*",
                     SearchOption.AllDirectories))
            new DirectoryInfo(directory).SetAccessControl(security);
        foreach (var file in Directory.EnumerateFiles(
                     root,
                     "*",
                     SearchOption.AllDirectories))
        {
            var fileSecurity = new FileSecurity();
            fileSecurity.SetAccessRuleProtection(true, false);
            if (ownerOverride is null)
                fileSecurity.SetOwner(owner);
            fileSecurity.AddAccessRule(new FileSystemAccessRule(
                system, FileSystemRights.FullControl,
                AccessControlType.Allow));
            fileSecurity.AddAccessRule(new FileSystemAccessRule(
                administrators, FileSystemRights.FullControl,
                AccessControlType.Allow));
            foreach (var identity in identities.DistinctBy(value => value.Sid))
                fileSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(identity.Sid),
                    FileSystemRights.ReadAndExecute,
                    AccessControlType.Allow));
            new FileInfo(file).SetAccessControl(fileSecurity);
        }
    }

    private static void ExtractApprovedDockerArchive(
        string archive,
        string destination)
    {
        using var zip = ZipFile.OpenRead(archive);
        if (zip.Entries.Count is < 1 or > 64)
            throw new InvalidDataException(
                "Approved Docker archive has an invalid shape.");
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "docker.exe",
            "dockerd.exe",
            "docker/docker.exe",
            "docker/dockerd.exe"
        };
        var extracted = false;
        foreach (var entry in zip.Entries)
        {
            var normalized = entry.FullName.Replace('\\', '/');
            if (!allowed.Contains(normalized) || entry.Length is <= 0 or > 512L * 1024 * 1024)
                continue;
            var name = Path.GetFileName(normalized);
            var target = Path.Combine(destination, name);
            PrepareForOverwrite(target);
            using var input = entry.Open();
            using var output = new FileStream(
                target,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None);
            input.CopyTo(output);
            output.Flush(flushToDisk: true);
            extracted = true;
        }
        if (!extracted ||
            !File.Exists(Path.Combine(destination, "dockerd.exe")) ||
            !File.Exists(Path.Combine(destination, "docker.exe")))
            throw new InvalidDataException(
                "Approved Docker archive contains no allowlisted binary.");
    }

    private static void PrepareForOverwrite(string path)
    {
        if (File.Exists(path))
            File.SetAttributes(
                path,
                File.GetAttributes(path) & ~FileAttributes.ReadOnly);
    }

    private static void RequireSha256(string path, string expected)
    {
        if (!string.Equals(
                FileSha256(path),
                expected,
                StringComparison.Ordinal))
            throw new MaintenanceProtocolException(
                "hash_mismatch",
                "Approved Docker binary hash mismatched.");
    }

    private static Task WriteAtomicAsync(
        string path,
        byte[] content,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = WindowsDurableFile.WriteAtomic(path, content);
        return Task.CompletedTask;
    }

    private static async Task<ProcessResult> RunApprovedDockerDaemonAsync(
        string dockerd,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken) =>
        await RunProcessAsync(dockerd, arguments, cancellationToken)
            .ConfigureAwait(false);

    private static Task<ProcessResult> RunAsync(
        MaintenanceTool tool,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var executable = tool switch
        {
            MaintenanceTool.GitHubCli => "gh.exe",
            MaintenanceTool.WindowsInstaller => Path.Combine(
                Environment.SystemDirectory, "msiexec.exe"),
            MaintenanceTool.Dism => Path.Combine(
                Environment.SystemDirectory, "dism.exe"),
            MaintenanceTool.Wsl => Path.Combine(
                Environment.SystemDirectory, "wsl.exe"),
            MaintenanceTool.ServiceControl => Path.Combine(
                Environment.SystemDirectory, "sc.exe"),
            MaintenanceTool.TaskScheduler => Path.Combine(
                Environment.SystemDirectory, "schtasks.exe"),
            MaintenanceTool.Shutdown => Path.Combine(
                Environment.SystemDirectory, "shutdown.exe"),
            MaintenanceTool.LocalGroup => Path.Combine(
                Environment.SystemDirectory, "net.exe"),
            MaintenanceTool.PowerShellSignatureVerifier => Path.Combine(
                Environment.SystemDirectory,
                "WindowsPowerShell", "v1.0", "powershell.exe"),
            _ => throw new InvalidOperationException(
                "Maintenance tool is unsupported.")
        };
        IReadOnlyList<string> effectiveArguments = tool ==
            MaintenanceTool.PowerShellSignatureVerifier
            ? [
                "-NoProfile", "-NonInteractive", "-Command",
                "if((Get-AuthenticodeSignature -LiteralPath $args[0]).Status -ne 'Valid'){exit 5}",
                "--", arguments.Single()
            ]
            : arguments;
        return RunProcessAsync(
            executable,
            effectiveArguments,
            cancellationToken,
            terminateOnCancellation: tool !=
                MaintenanceTool.WindowsInstaller);
    }

    private static async Task<ProcessResult> RunProcessAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken,
        bool terminateOnCancellation = true)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ??
            throw new InvalidOperationException(
                "Approved maintenance tool could not start.");
        try
        {
            var outputTask = process.StandardOutput.ReadToEndAsync(
                cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(
                cancellationToken);
            await process.WaitForExitAsync(cancellationToken)
                .ConfigureAwait(false);
            var output = Bound(
                await outputTask.ConfigureAwait(false) + "\n" +
                await errorTask.ConfigureAwait(false),
                MaximumToolOutputCharacters);
            return new ProcessResult(process.ExitCode, output);
        }
        catch (OperationCanceledException)
        {
            if (terminateOnCancellation && !process.HasExited)
                process.Kill(entireProcessTree: true);
            throw;
        }
    }

    private static void RequireDismSuccess(ProcessResult result)
    {
        if (result.ExitCode is not (0 or 3010))
            throw new MaintenanceProtocolException(
                "wsl_configuration_failed",
                "Approved WSL configuration failed.");
    }

    private static void RequireSuccess(
        ProcessResult result,
        string code)
    {
        if (result.ExitCode != 0)
            throw new MaintenanceProtocolException(
                code,
                "Approved maintenance tool failed.");
    }

    private static string Bound(string value, int maximum) =>
        value.Length <= maximum ? value : value[..maximum];

    private static string BootIdentity() =>
        JsonSerializer.Serialize(WindowsBootIdentity.Capture());

    internal static bool RebootObserved(
        string prior,
        string current)
    {
        WindowsBootIdentityEvidence? priorEvidence;
        WindowsBootIdentityEvidence? currentEvidence;
        try
        {
            priorEvidence = JsonSerializer.Deserialize<
                WindowsBootIdentityEvidence>(prior);
            currentEvidence = JsonSerializer.Deserialize<
                WindowsBootIdentityEvidence>(current);
        }
        catch (JsonException)
        {
            throw new MaintenanceProtocolException(
                "reboot_identity_unverified",
                "Windows boot identity evidence is unavailable.");
        }
        if (priorEvidence is null || currentEvidence is null ||
            !priorEvidence.Verified || !currentEvidence.Verified)
            throw new MaintenanceProtocolException(
                "reboot_identity_unverified",
                "Windows boot identity evidence is unavailable.");
        return !string.Equals(
            priorEvidence.Identity,
            currentEvidence.Identity,
            StringComparison.Ordinal);
    }

    private static string FileSha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private sealed record UpdateProvisioningPaths(
        string Configuration,
        string Attestation);

    private sealed record UpdateProvisioningConfiguration(
        int Version,
        string ProductVersion,
        string BootstrapEncryptionPublicKey,
        string ControlSigningPublicKey,
        string ControlIdentity,
        string ProvisionedUserAccount,
        string ProvisionedUserSid);

    private sealed record UpdateArtifactAttestation(
        int Version,
        string ProductVersion,
        string MsiSha256,
        string SourceRepository,
        string SourceCommit,
        string SourceRef,
        string SignerWorkflow,
        string SourceRunId,
        string ProductCode,
        string ConfigSha256,
        string BootstrapEncryptionPublicKeySha256,
        string ControlSigningPublicKeySha256,
        string ControlIdentity);

    private sealed record MsiMetadata(
        string ProductVersion,
        string ProductCode,
        string UpgradeCode)
    {
        internal static MsiMetadata Read(string package)
        {
            var result = NativeMethods.MsiOpenDatabase(
                package,
                IntPtr.Zero,
                out var database);
            if (result != 0)
                throw new InvalidDataException(
                    "Verified endpoint package is not a readable MSI.");
            try
            {
                return new MsiMetadata(
                    ReadProperty(database, "ProductVersion"),
                    ReadProperty(database, "ProductCode"),
                    ReadProperty(database, "UpgradeCode"));
            }
            finally
            {
                NativeMethods.MsiCloseHandle(database);
            }
        }

        private static string ReadProperty(uint database, string name)
        {
            var query =
                $"SELECT `Value` FROM `Property` WHERE `Property`='{name}'";
            if (NativeMethods.MsiDatabaseOpenView(
                    database,
                    query,
                    out var view) != 0)
                throw new InvalidDataException(
                    "Verified endpoint MSI metadata is unavailable.");
            try
            {
                if (NativeMethods.MsiViewExecute(view, 0) != 0 ||
                    NativeMethods.MsiViewFetch(view, out var record) != 0)
                    throw new InvalidDataException(
                        "Verified endpoint MSI property is unavailable.");
                try
                {
                    var capacity = 512u;
                    var value = new StringBuilder(checked((int)capacity));
                    if (NativeMethods.MsiRecordGetString(
                            record,
                            1,
                            value,
                            ref capacity) != 0)
                        throw new InvalidDataException(
                            "Verified endpoint MSI property is invalid.");
                    var result = value.ToString();
                    if (string.IsNullOrWhiteSpace(result))
                        throw new InvalidDataException(
                            "Verified endpoint MSI property is empty.");
                    return result;
                }
                finally
                {
                    NativeMethods.MsiCloseHandle(record);
                }
            }
            finally
            {
                NativeMethods.MsiCloseHandle(view);
            }
        }

        private static class NativeMethods
        {
            [DllImport(
                "msi.dll",
                EntryPoint = "MsiOpenDatabaseW",
                CharSet = CharSet.Unicode)]
            internal static extern uint MsiOpenDatabase(
                string databasePath,
                IntPtr persist,
                out uint database);

            [DllImport(
                "msi.dll",
                EntryPoint = "MsiDatabaseOpenViewW",
                CharSet = CharSet.Unicode)]
            internal static extern uint MsiDatabaseOpenView(
                uint database,
                string query,
                out uint view);

            [DllImport("msi.dll")]
            internal static extern uint MsiViewExecute(
                uint view,
                uint record);

            [DllImport("msi.dll")]
            internal static extern uint MsiViewFetch(
                uint view,
                out uint record);

            [DllImport(
                "msi.dll",
                EntryPoint = "MsiRecordGetStringW",
                CharSet = CharSet.Unicode)]
            internal static extern uint MsiRecordGetString(
                uint record,
                uint field,
                StringBuilder value,
                ref uint valueCharacters);

            [DllImport("msi.dll")]
            internal static extern uint MsiCloseHandle(uint handle);
        }
    }

    private sealed record DockerDaemonFile(
        [property: JsonPropertyName("experimental")] bool Experimental,
        [property: JsonPropertyName("shutdown-timeout")] int ShutdownTimeout,
        [property: JsonPropertyName("max-concurrent-downloads")] int MaxConcurrentDownloads,
        [property: JsonPropertyName("group")] string Group);

    private sealed record DockerCapabilityProof(
        int Version,
        string EngineVersion,
        string ComposeVersion,
        string DockerClientSha256,
        string DockerComposeSha256,
        string Transport,
        IReadOnlyList<DockerTaskIdentity> TaskIdentities,
        bool NativeSmokeVerified,
        DateTimeOffset VerifiedAtUtc);

    private sealed record MaintenanceDiagnosticSnapshot(
        int Version,
        DateTimeOffset CollectedAtUtc,
        int MaintenanceServiceExitCode,
        string MaintenanceService,
        int HandleKeeperExitCode,
        string HandleKeeper,
        int RdpDvcEndpointExitCode,
        string RdpDvcEndpoint);

    private enum MaintenanceTool
    {
        GitHubCli,
        WindowsInstaller,
        Dism,
        Wsl,
        ServiceControl,
        TaskScheduler,
        Shutdown,
        LocalGroup,
        PowerShellSignatureVerifier
    }
}







