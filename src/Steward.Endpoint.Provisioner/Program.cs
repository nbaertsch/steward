using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Contracts;
using Steward.Transport;
using Steward.Runtime.Windows;

namespace Steward.Endpoint.Provisioner;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            if (args.Contains(
                    "--execute-update-handoff",
                    StringComparer.Ordinal))
            {
                var handoffOptions =
                    EndpointInstallerHandoffExecutionOptions.Parse(args);
                var handoff = new EndpointInstallerHandoffExecutor(
                    new PhysicalProvisionerFileSystem(),
                    new WindowsEndpointInstallerRuntime(),
                    new NamedPipeEndpointInstallerFenceCompletion());
                var handoffReceipt = handoff.Execute(handoffOptions);
                Console.WriteLine(
                    $"Steward endpoint installer handoff " +
                    $"{handoffReceipt.Outcome}; " +
                    $"transaction={handoffReceipt.TransactionId:D}");
                return 0;
            }
            var options = ProvisionerOptions.Parse(args);
            var provisioner = new EndpointProvisioner(
                new PhysicalProvisionerFileSystem(),
                new PowerShellTaskRegistrar(),
                new IcaclsEndpointSecurity(),
                new AuthenticatedEndpointReadyHealthVerifier());
            string receipt;
            string action;
            switch (options.TransactionAction)
            {
                case MsiTransactionAction.Commit:
                    provisioner.CommitMsiTransaction(options);
                    receipt = options.TransactionJournalPath;
                    action = "MSI transaction committed";
                    break;
                case MsiTransactionAction.Rollback:
                    provisioner.RollbackMsiTransaction(
                        options,
                        "msi_rollback");
                    receipt = options.TransactionJournalPath;
                    action = "MSI transaction rolled back";
                    break;
                default:
                    receipt = options.VerifyOnly
                        ? provisioner.Verify(options)
                        : provisioner.Provision(options);
                    action = options.VerifyOnly
                        ? "verified"
                        : "provisioned";
                    break;
            }
            Console.WriteLine(
                $"Steward endpoint {action}; receipt={receipt}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Steward endpoint provisioning failed: " +
                $"{exception.GetType().Name}: {exception.Message}");
            return 1;
        }
    }
}

internal enum EndpointInstallerHandoffAction
{
    InstallEndpoint
}

internal enum EndpointInstallerReceiptOutcome
{
    Committed,
    RolledBack
}

internal sealed record EndpointOwnerCapability
{
    public EndpointOwnerCapability(string encoded)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encoded);
        byte[] value;
        try
        {
            value = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "Endpoint owner capability is invalid.",
                nameof(encoded),
                exception);
        }
        try
        {
            if (value.Length != 32)
                throw new ArgumentException(
                    "Endpoint owner capability must be 256 bits.",
                    nameof(encoded));
            Encoded = encoded;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    public string Encoded { get; }

    internal string Sha256()
    {
        var value = Convert.FromBase64String(Encoded);
        try
        {
            return Convert.ToHexString(SHA256.HashData(value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    public override string ToString() => "[endpoint-owner-capability]";
}

internal sealed record EndpointInstallerHandoffIntent(
    int Version,
    Guid TransactionId,
    ulong UpdateSequence,
    EndpointOwnerCapability OwnerCapability,
    string ProductVersion,
    string MsiSha256,
    long MsiLength,
    Guid ProductCode,
    Guid UpgradeCode,
    string ReleaseDirectoryName,
    string ProvisionerSha256,
    EndpointInstallerHandoffAction Action);

internal sealed record EndpointInstallerHandoffReceipt(
    int Version,
    Guid TransactionId,
    ulong UpdateSequence,
    string OwnerCapabilitySha256,
    string ProductVersion,
    string MsiSha256,
    Guid ProductCode,
    Guid UpgradeCode,
    EndpointInstallerHandoffAction Action,
    EndpointInstallerReceiptOutcome Outcome,
    int InstallerExitCode);

internal sealed record EndpointInstallerServiceConfiguration(
    int Version,
    string PipeName,
    string NodeUserSid,
    string NodeUserAccount,
    string ControlIdentity,
    string KeeperPipeName,
    Guid HostId,
    string InstalledProductVersion,
    string ApprovedSourceRepository,
    string ApprovedSignerWorkflow,
    string EndpointStateRoot,
    string InstallRoot,
    string VersionedRoot,
    string EndpointUpgradeCode);

internal sealed record EndpointInstallerIdentity(
    Guid ProductCode,
    Guid UpgradeCode,
    string ProductVersion,
    string MsiSha256);

internal sealed record EndpointInstallerExecutionState(
    int Version,
    Guid TransactionId,
    ulong UpdateSequence,
    string OwnerCapabilitySha256,
    EndpointInstallerIdentity Identity)
{
    internal static EndpointInstallerExecutionState Create(
        EndpointInstallerHandoffIntent intent) => new(
        1,
        intent.TransactionId,
        intent.UpdateSequence,
        intent.OwnerCapability.Sha256(),
        new EndpointInstallerIdentity(
            intent.ProductCode,
            intent.UpgradeCode,
            intent.ProductVersion,
            intent.MsiSha256));
}

internal sealed record EndpointInstallerHandoffExecutionOptions(
    string MaintenanceStateRoot,
    string ProvisionerPath)
{
    internal string ExecutionStatePath => Path.Combine(
        MaintenanceStateRoot,
        "installer-handoff",
        "execution.json");

    internal static EndpointInstallerHandoffExecutionOptions Parse(
        string[] arguments)
    {
        if (arguments.Length != 3 ||
            arguments[0] != "--execute-update-handoff" ||
            arguments[1] != "--maintenance-state-root" ||
            string.IsNullOrWhiteSpace(arguments[2]))
            throw new ArgumentException(
                "Usage: --execute-update-handoff " +
                "--maintenance-state-root PATH");
        var processPath = Environment.ProcessPath ??
            throw new InvalidOperationException(
                "Provisioner process identity is unavailable.");
        return new EndpointInstallerHandoffExecutionOptions(
            Path.GetFullPath(arguments[2]),
            Path.GetFullPath(processPath));
    }
}

internal sealed record VerifiedEndpointInstallerPackage(
    EndpointInstallerIdentity Identity,
    string PackagePath,
    string ConfigurationPath,
    string AttestationPath);

internal sealed record EndpointInstallerRuntimeResult(
    EndpointInstallerReceiptOutcome Outcome,
    int ExitCode)
{
    internal static EndpointInstallerRuntimeResult Committed(int exitCode) =>
        new(EndpointInstallerReceiptOutcome.Committed, exitCode);

    internal static EndpointInstallerRuntimeResult RolledBack(int exitCode) =>
        new(EndpointInstallerReceiptOutcome.RolledBack, exitCode);
}

internal interface IEndpointInstallerRuntime
{
    EndpointInstallerRuntimeResult Install(
        VerifiedEndpointInstallerPackage package);

    EndpointInstallerRuntimeResult Recover(
        EndpointInstallerIdentity identity);
}

internal sealed class WindowsEndpointInstallerRuntime :
    IEndpointInstallerRuntime
{
    public EndpointInstallerRuntimeResult Install(
        VerifiedEndpointInstallerPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.SystemDirectory,
                "msiexec.exe"),
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in new[]
                 {
                     "/i",
                     package.PackagePath,
                     "/qn",
                     "/norestart",
                     "STEWARD_CONFIG=" + package.ConfigurationPath,
                     "STEWARD_ATTESTATION=" + package.AttestationPath
                 })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ??
            throw new InvalidOperationException(
                "Windows Installer handoff could not be started.");
        process.WaitForExit();
        return process.ExitCode is 0 or 1641 or 3010
            ? EndpointInstallerRuntimeResult.Committed(process.ExitCode)
            : EndpointInstallerRuntimeResult.RolledBack(process.ExitCode);
    }

    public EndpointInstallerRuntimeResult Recover(
        EndpointInstallerIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var productCode = identity.ProductCode.ToString("B").ToUpperInvariant();
        var state = NativeMethods.MsiQueryProductState(productCode);
        if (state is NativeMethods.InstallState.Default or
            NativeMethods.InstallState.Local or
            NativeMethods.InstallState.Source)
        {
            var version = new StringBuilder(64);
            var length = version.Capacity;
            var result = NativeMethods.MsiGetProductInfo(
                productCode,
                "VersionString",
                version,
                ref length);
            if (result != 0 ||
                !string.Equals(
                    version.ToString(),
                    identity.ProductVersion,
                    StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Recovered Windows Installer product identity mismatched.");
            return EndpointInstallerRuntimeResult.Committed(0);
        }
        if (state is NativeMethods.InstallState.Absent or
            NativeMethods.InstallState.Unknown)
            return EndpointInstallerRuntimeResult.RolledBack(1603);
        throw new InvalidOperationException(
            "Windows Installer transaction outcome is not terminal.");
    }

    private static class NativeMethods
    {
        internal enum InstallState
        {
            Unknown = -1,
            Absent = 2,
            Local = 3,
            Source = 4,
            Default = 5
        }

#pragma warning disable SYSLIB1054
        [DllImport(
            "msi.dll",
            EntryPoint = "MsiQueryProductStateW",
            CharSet = CharSet.Unicode)]
        internal static extern InstallState MsiQueryProductState(
            string productCode);

        [DllImport(
            "msi.dll",
            EntryPoint = "MsiGetProductInfoW",
            CharSet = CharSet.Unicode)]
        internal static extern uint MsiGetProductInfo(
            string productCode,
            string property,
            StringBuilder value,
            ref int valueLength);
#pragma warning restore SYSLIB1054
    }
}

internal interface IEndpointInstallerFenceCompletion
{
    void Complete(
        EndpointInstallerServiceConfiguration configuration,
        EndpointInstallerHandoffIntent intent);
}

internal sealed class NullEndpointInstallerFenceCompletion :
    IEndpointInstallerFenceCompletion
{
    internal static NullEndpointInstallerFenceCompletion Instance { get; } =
        new();

    private NullEndpointInstallerFenceCompletion()
    {
    }

    public void Complete(
        EndpointInstallerServiceConfiguration configuration,
        EndpointInstallerHandoffIntent intent)
    {
    }
}

internal sealed class NamedPipeEndpointInstallerFenceCompletion :
    IEndpointInstallerFenceCompletion
{
    public void Complete(
        EndpointInstallerServiceConfiguration configuration,
        EndpointInstallerHandoffIntent intent)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(intent);
        var task = new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.SystemDirectory,
                "schtasks.exe"),
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in new[]
                 {
                     "/Run",
                     "/TN",
                     $@"\Steward\HandleKeeper-{configuration.HostId:N}"
                 })
            task.ArgumentList.Add(argument);
        using (var process = Process.Start(task) ??
               throw new InvalidOperationException(
                   "HandleKeeper task could not be started for fence completion."))
        {
            process.WaitForExit();
            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    "HandleKeeper task start failed during fence completion.");
        }
        var capability = new JobKeeperFenceCapability(
            intent.OwnerCapability.Encoded);
        Exception? lastError = null;
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                using var keeper = new NamedPipeJobHandleKeeper(new(
                    configuration.KeeperPipeName,
                    TimeSpan.FromSeconds(2),
                    ConnectAttempts: 1));
                var status = keeper.FenceStatus();
                if (status.Phase == JobKeeperFencePhase.Unfenced)
                    return;
                var released = keeper.ReleaseTransferredDrainFence(
                    intent.TransactionId,
                    intent.TransactionId,
                    capability,
                    status.Generation);
                if (released.Phase != JobKeeperFencePhase.Unfenced)
                    throw new InvalidDataException(
                        "HandleKeeper fence remained active after installer completion.");
                return;
            }
            catch (Exception exception) when (exception is
                IOException or TimeoutException or UnauthorizedAccessException)
            {
                lastError = exception;
                Thread.Sleep(250);
            }
        }
        throw new IOException(
            "HandleKeeper did not accept installer fence completion.",
            lastError);
    }
}
internal sealed class EndpointInstallerHandoffExecutor(
    IProvisionerFileSystem files,
    IEndpointInstallerRuntime runtime,
    IEndpointInstallerFenceCompletion? fenceCompletion = null)
{
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };

    internal EndpointInstallerHandoffReceipt Execute(
        EndpointInstallerHandoffExecutionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var configuration = Read<EndpointInstallerServiceConfiguration>(
            Path.Combine(options.MaintenanceStateRoot, "service-config.json"));
        if (configuration.Version != 1 ||
            configuration.HostId == Guid.Empty ||
            !Guid.TryParse(
                configuration.EndpointUpgradeCode,
                out var configuredUpgradeCode) ||
            configuredUpgradeCode == Guid.Empty)
            throw new InvalidDataException(
                "Installer handoff service configuration is invalid.");
        var handoffRoot = Path.Combine(
            options.MaintenanceStateRoot,
            "installer-handoff",
            configuration.HostId.ToString("N"));
        var intent = Read<EndpointInstallerHandoffIntent>(
            Path.Combine(handoffRoot, "intent.json"));
        ValidateIntent(intent, configuration, configuredUpgradeCode);
        var receiptPath = Path.Combine(handoffRoot, "receipt.json");
        if (files.FileExists(receiptPath))
        {
            var existing = Read<EndpointInstallerHandoffReceipt>(receiptPath);
            ValidateReceipt(intent, existing);
            return existing;
        }
        var packagePath = ConfinedPackagePath(
            configuration.VersionedRoot,
            intent.ReleaseDirectoryName);
        var provisioningPath = Path.Combine(
            options.MaintenanceStateRoot,
            "staging",
            "update-provisioning.json");
        var attestationPath = Path.Combine(
            options.MaintenanceStateRoot,
            "staging",
            "update-artifact-attestation.json");
        ValidateFile(packagePath, intent.MsiLength, intent.MsiSha256);
        ValidateFile(
            options.ProvisionerPath,
            new FileInfo(options.ProvisionerPath).Length,
            intent.ProvisionerSha256);
        ValidateRegularFile(provisioningPath);
        ValidateRegularFile(attestationPath);
        var expectedExecution = EndpointInstallerExecutionState.Create(intent);
        EndpointInstallerRuntimeResult result;
        if (files.FileExists(options.ExecutionStatePath))
        {
            var execution = Read<EndpointInstallerExecutionState>(
                options.ExecutionStatePath);
            if (execution != expectedExecution)
                throw new InvalidDataException(
                    "Installer handoff execution state mismatched.");
            result = runtime.Recover(execution.Identity);
        }
        else
        {
            files.CreateDirectory(
                Path.GetDirectoryName(options.ExecutionStatePath) ??
                throw new InvalidDataException(
                    "Installer execution state has no parent."));
            files.WriteAtomic(
                options.ExecutionStatePath,
                JsonSerializer.SerializeToUtf8Bytes(expectedExecution, Json));
            result = runtime.Install(new VerifiedEndpointInstallerPackage(
                expectedExecution.Identity,
                packagePath,
                provisioningPath,
                attestationPath));
        }
        (fenceCompletion ?? NullEndpointInstallerFenceCompletion.Instance)
            .Complete(configuration, intent);
        var receipt = new EndpointInstallerHandoffReceipt(
            1,
            intent.TransactionId,
            intent.UpdateSequence,
            intent.OwnerCapability.Sha256(),
            intent.ProductVersion,
            intent.MsiSha256,
            intent.ProductCode,
            intent.UpgradeCode,
            intent.Action,
            result.Outcome,
            result.ExitCode);
        ValidateReceipt(intent, receipt);
        files.WriteAtomic(
            receiptPath,
            JsonSerializer.SerializeToUtf8Bytes(receipt, Json));
        return receipt;
    }

    private T Read<T>(string path)
    {
        ValidateRegularFile(path);
        return JsonSerializer.Deserialize<T>(files.ReadAllBytes(path), Json) ??
            throw new InvalidDataException(
                "Installer handoff document is empty.");
    }

    private static string ConfinedPackagePath(
        string versionedRoot,
        string releaseDirectoryName)
    {
        if (releaseDirectoryName != Path.GetFileName(releaseDirectoryName))
            throw new InvalidDataException(
                "Installer release directory identity is invalid.");
        var root = Path.GetFullPath(versionedRoot).TrimEnd(
            Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var package = Path.GetFullPath(Path.Combine(
            root,
            releaseDirectoryName,
            "Steward.Endpoint.Msi.msi"));
        if (!package.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Installer package escaped the versioned root.");
        return package;
    }

    private static void ValidateIntent(
        EndpointInstallerHandoffIntent intent,
        EndpointInstallerServiceConfiguration configuration,
        Guid configuredUpgradeCode)
    {
        var releasePrefix = "release-" + intent.ProductVersion + "-";
        if (intent.Version != 1 || intent.TransactionId == Guid.Empty ||
            intent.UpdateSequence == 0 ||
            !Version.TryParse(intent.ProductVersion, out var version) ||
            version.Build < 0 || version.Revision >= 0 ||
            !ValidHash(intent.MsiSha256) || intent.MsiLength <= 0 ||
            intent.ProductCode == Guid.Empty ||
            intent.UpgradeCode != configuredUpgradeCode ||
            intent.ReleaseDirectoryName.Length != releasePrefix.Length + 16 ||
            !intent.ReleaseDirectoryName.StartsWith(
                releasePrefix,
                StringComparison.Ordinal) ||
            intent.ReleaseDirectoryName[releasePrefix.Length..].Any(
                character => !char.IsAsciiHexDigit(character)) ||
            !ValidHash(intent.ProvisionerSha256) ||
            intent.Action != EndpointInstallerHandoffAction.InstallEndpoint)
            throw new InvalidDataException(
                "Installer handoff intent is invalid.");
    }

    private static void ValidateReceipt(
        EndpointInstallerHandoffIntent intent,
        EndpointInstallerHandoffReceipt receipt)
    {
        if (receipt.Version != 1 ||
            receipt.TransactionId != intent.TransactionId ||
            receipt.UpdateSequence != intent.UpdateSequence ||
            !HashEquals(
                receipt.OwnerCapabilitySha256,
                intent.OwnerCapability.Sha256()) ||
            receipt.ProductVersion != intent.ProductVersion ||
            !HashEquals(receipt.MsiSha256, intent.MsiSha256) ||
            receipt.ProductCode != intent.ProductCode ||
            receipt.UpgradeCode != intent.UpgradeCode ||
            receipt.Action != intent.Action ||
            !Enum.IsDefined(receipt.Outcome) ||
            receipt.Outcome == EndpointInstallerReceiptOutcome.Committed &&
            receipt.InstallerExitCode is not (0 or 1641 or 3010))
            throw new InvalidDataException(
                "Installer handoff receipt is invalid.");
    }

    private static void ValidateRegularFile(string path)
    {
        if (!File.Exists(path) ||
            File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "Installer handoff input is not a regular file.");
    }

    private static void ValidateFile(
        string path,
        long expectedLength,
        string expectedSha256)
    {
        ValidateRegularFile(path);
        if (new FileInfo(path).Length != expectedLength ||
            !HashEquals(
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
                expectedSha256))
            throw new InvalidDataException(
                "Installer handoff file identity mismatched.");
    }

    private static bool ValidHash(string value) =>
        value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static bool HashEquals(string first, string second)
    {
        if (!ValidHash(first) || !ValidHash(second))
            return false;
        var left = Convert.FromHexString(first);
        var right = Convert.FromHexString(second);
        try
        {
            return CryptographicOperations.FixedTimeEquals(left, right);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(left);
            CryptographicOperations.ZeroMemory(right);
        }
    }
}
internal enum MsiTransactionAction
{
    Prepare,
    Commit,
    Rollback
}

internal sealed record ProvisionerOptions(
    string InstallRoot,
    string ConfigPath,
    string StateRoot,
    string ArtifactAttestationPath,
    bool VerifyOnly = false,
    string? MaintenanceStateRoot = null,
    Guid? MsiTransactionId = null,
    MsiTransactionAction TransactionAction = MsiTransactionAction.Prepare)
{
    internal string EffectiveMaintenanceStateRoot =>
        MaintenanceStateRoot ??
        Path.Combine(
            Path.GetDirectoryName(StateRoot) ??
                throw new InvalidDataException(
                    "Endpoint state root has no parent."),
            "Maintenance");

    internal string TransactionJournalPath => Path.Combine(
        Path.GetDirectoryName(EffectiveMaintenanceStateRoot) ??
            throw new InvalidDataException(
                "Maintenance state root has no parent."),
        "InstallerTransactions",
        (MsiTransactionId ?? throw new InvalidOperationException(
            "MSI transaction identity is unavailable.")).ToString("N") +
        ".json");

    internal static ProvisionerOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var verifyOnly = false;
        Guid? transactionId = null;
        var transactionAction = MsiTransactionAction.Prepare;
        for (var index = 0; index < args.Length;)
        {
            if (args[index] == "--verify-only")
            {
                if (verifyOnly)
                    throw new ArgumentException(
                        "Option '--verify-only' was specified more than once.");
                verifyOnly = true;
                index++;
                continue;
            }
            if (args[index] is
                "--prepare-msi-transaction" or
                "--commit-msi-transaction" or
                "--rollback-msi-transaction")
            {
                if (transactionId is not null || index + 1 >= args.Length ||
                    !Guid.TryParse(args[index + 1], out var parsed) ||
                    parsed == Guid.Empty)
                    throw new ArgumentException(
                        "MSI transaction identity is invalid or duplicated.");
                transactionId = parsed;
                transactionAction = args[index] switch
                {
                    "--commit-msi-transaction" =>
                        MsiTransactionAction.Commit,
                    "--rollback-msi-transaction" =>
                        MsiTransactionAction.Rollback,
                    _ => MsiTransactionAction.Prepare
                };
                index += 2;
                continue;
            }
            if (index + 1 >= args.Length ||
                args[index] is not (
                    "--install-root" or "--config" or "--state-root" or
                    "--artifact-attestation" or "--maintenance-state-root") ||
                !values.TryAdd(args[index], args[index + 1]))
                throw new ArgumentException(
                    "Usage: --install-root PATH --config PATH --state-root PATH");
            index += 2;
        }
        return new(
            FullDirectory(Required(values, "--install-root")),
            FullFile(Required(values, "--config")),
            Path.GetFullPath(Required(values, "--state-root")),
            FullFile(Required(values, "--artifact-attestation")),
            verifyOnly,
            Path.GetFullPath(Required(
                values,
                "--maintenance-state-root")),
            transactionId,
            transactionAction);
    }

    private static string Required(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var value) &&
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"Required option '{name}' is missing.");

    private static string FullDirectory(string path)
    {
        var full = Path.GetFullPath(path);
        if (!Directory.Exists(full) ||
            File.GetAttributes(full).HasFlag(FileAttributes.ReparsePoint))
            throw new ArgumentException("Install root is not a regular directory.");
        return full;
    }

    private static string FullFile(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full) ||
            File.GetAttributes(full).HasFlag(FileAttributes.ReparsePoint))
            throw new ArgumentException("Provisioning config is not a regular file.");
        return full;
    }
}

internal sealed record EndpointProvisioningConfig(
    int Version,
    string ProductVersion,
    string BootstrapEncryptionPublicKey,
    string ControlSigningPublicKey,
    string ControlIdentity,
    string? ProvisionedUserAccount = null,
    string? ProvisionedUserSid = null);

internal sealed record EndpointMaintenanceConfiguration(
    int Version,
    string PipeName,
    string NodeUserSid,
    string NodeUserAccount,
    string ControlIdentity,
    string KeeperPipeName,
    Guid HostId,
    string InstalledProductVersion,
    string ApprovedSourceRepository,
    string ApprovedSignerWorkflow,
    string EndpointStateRoot,
    string InstallRoot,
    string VersionedRoot,
    string EndpointUpgradeCode);

internal sealed record MaintenanceStateSnapshot(
    bool Existed,
    byte[]? Configuration,
    byte[]? ControlSigningPublicKey,
    byte[]? BootstrapEncryptionPublicKey);

internal enum EndpointProvisionerTransactionState
{
    Prepared,
    CommitIntent,
    RollbackIntent,
    StateRestored,
    TasksRestored,
    Committed
}

internal sealed record EndpointProvisionerTransaction(
    int Version,
    Guid TransactionId,
    EndpointProvisionerTransactionState State,
    string StateRoot,
    string BackupRoot,
    bool PriorStateExisted,
    EndpointTaskSnapshot TaskSnapshot,
    EndpointMachineIdentity TaskSnapshotIdentity,
    MaintenanceStateSnapshot MaintenanceSnapshot,
    string UserSid,
    string ReceiptPath);

internal sealed record EndpointArtifactAttestation(
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

internal sealed record EndpointMachineIdentity(
    int Version,
    string ProductVersion,
    Guid BootstrapOperationId,
    Guid SessionId,
    Guid HostId,
    Guid IncarnationId,
    string NodeIdentity,
    string ControlIdentity,
    DateTimeOffset CreatedAtUtc);

internal sealed record EndpointReconnectLedgerReceipt(
    int Version,
    string LedgerFile,
    string HealthFile);

internal sealed record EndpointV1MigrationReceipt(
    int Version,
    string RetainedEndpointVersion,
    int NonceCount,
    int NextIndex,
    string InventorySha256,
    string AuthorizationFile,
    string AuthorizationSha256);

internal sealed record EndpointProvisioningReceiptBody(
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
    string ControlIdentity,
    Guid BootstrapOperationId,
    Guid SessionId,
    Guid HostId,
    Guid IncarnationId,
    string NodeIdentity,
    string Ciphertext,
    string NodeSigningPublicKey,
    [property: JsonPropertyName("connectionNonces")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<Guid>? LegacyConnectionNonces,
    DateTimeOffset ProvisionedAtUtc,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    EndpointReconnectLedgerReceipt? ReconnectLedger,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    EndpointV1MigrationReceipt? V1Migration = null);

internal sealed record EndpointNonceState(
    int Version,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    IReadOnlyList<Guid> Nonces,
    int NextIndex);

internal sealed record EndpointProvisioningReceipt(
    EndpointProvisioningReceiptBody Body,
    string Signature);

internal sealed record EndpointPayloadManifest(
    int Version,
    string ProductVersion,
    IReadOnlyList<EndpointPayloadFile> Files);

internal sealed record EndpointPayloadFile(
    string RelativePath,
    long Length,
    string Sha256);

internal interface IProvisionerFileSystem
{
    bool FileExists(string path);
    byte[] ReadAllBytes(string path);
    string ReadAllText(string path);
    bool DirectoryExists(string path);
    IReadOnlyList<string> GetFiles(string path);
    void CreateDirectory(string path);
    void CopyDirectory(string source, string destination);
    void MoveDirectory(string source, string destination);
    void DeleteDirectory(string path);
    void WriteNew(string path, ReadOnlySpan<byte> content);
    void WriteAtomic(string path, ReadOnlySpan<byte> content);
}

internal enum ProvisionerDurableCommitResult
{
    FileAndParentDirectoryCommitted,
    FileCommittedParentDirectoryFlushUnsupported
}
internal sealed class PhysicalProvisionerFileSystem : IProvisionerFileSystem
{
    public bool FileExists(string path) => File.Exists(path);
    public byte[] ReadAllBytes(string path) => File.ReadAllBytes(path);
    public string ReadAllText(string path) => File.ReadAllText(path);
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public IReadOnlyList<string> GetFiles(string path) =>
        Directory.GetFiles(path, "*", SearchOption.AllDirectories);
    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
    public void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        var start = new ProcessStartInfo
        {
            FileName = "robocopy.exe",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in new[]
                 {
                     source,
                     destination,
                     "/E",
                     "/COPY:DAT",
                     "/DCOPY:DAT",
                     "/R:0",
                     "/W:0",
                     "/XJ",
                     "/SL",
                     "/NFL",
                     "/NDL",
                     "/NJH",
                     "/NJS",
                     "/NP"
                 })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ??
            throw new InvalidOperationException(
                "Could not start the endpoint state copy.");
        process.WaitForExit();
        if (process.ExitCode >= 8)
            throw new IOException(
                $"Endpoint state copy failed with exit code {process.ExitCode}.");
    }
    public void MoveDirectory(string source, string destination) =>
        Directory.Move(source, destination);
    public void DeleteDirectory(string path)
    {
        if (Directory.Exists(path))
            Directory.Delete(path, recursive: true);
    }

    public void WriteNew(string path, ReadOnlySpan<byte> content)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough);
        stream.Write(content);
        stream.Flush(flushToDisk: true);
    }

    public void WriteAtomic(string path, ReadOnlySpan<byte> content) =>
        _ = WriteAtomicDurable(path, content);

    internal ProvisionerDurableCommitResult WriteAtomicDurable(
        string path,
        ReadOnlySpan<byte> content)
    {
        var full = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(full) ??
            throw new InvalidDataException(
                "Atomic provisioner file has no parent directory.");
        Directory.CreateDirectory(directory);
        var pending = full + ".new";
        try
        {
            using (var stream = new FileStream(
                       pending,
                       FileMode.Create,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }
            File.Move(pending, full, overwrite: true);
            return FlushParentDirectory(directory);
        }
        finally
        {
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }

    private static ProvisionerDurableCommitResult FlushParentDirectory(
        string directory)
    {
        if (!OperatingSystem.IsWindows())
            return ProvisionerDurableCommitResult.
                FileCommittedParentDirectoryFlushUnsupported;
        using var handle = DurableNative.CreateFile(
            directory,
            0x80000000,
            0x00000001 | 0x00000002 | 0x00000004,
            IntPtr.Zero,
            3,
            0x02000000 | 0x80000000,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            if (UnsupportedDirectoryFlush(error))
                return ProvisionerDurableCommitResult.
                    FileCommittedParentDirectoryFlushUnsupported;
            throw new System.ComponentModel.Win32Exception(
                error,
                "Provisioner parent directory open failed.");
        }
        if (DurableNative.FlushFileBuffers(handle))
            return ProvisionerDurableCommitResult.
                FileAndParentDirectoryCommitted;
        var flushError = Marshal.GetLastWin32Error();
        if (UnsupportedDirectoryFlush(flushError))
            return ProvisionerDurableCommitResult.
                FileCommittedParentDirectoryFlushUnsupported;
        throw new System.ComponentModel.Win32Exception(
            flushError,
            "Provisioner parent directory flush failed.");
    }

    private static bool UnsupportedDirectoryFlush(int error) =>
        error is 1 or 5 or 6 or 50;

    private static class DurableNative
    {
#pragma warning disable SYSLIB1054
        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateFileW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        internal static extern Microsoft.Win32.SafeHandles.SafeFileHandle
            CreateFile(
                string fileName,
                uint desiredAccess,
                uint shareMode,
                IntPtr securityAttributes,
                uint creationDisposition,
                uint flagsAndAttributes,
                IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FlushFileBuffers(
            Microsoft.Win32.SafeHandles.SafeFileHandle file);
#pragma warning restore SYSLIB1054
    }
}

internal interface IEndpointTaskRegistrar
{
    ProvisionedUser ResolveUser();
    EndpointTaskSnapshot Capture(EndpointMachineIdentity identity);
    void Quiesce(EndpointMachineIdentity identity);
    void Restore(
        EndpointTaskSnapshot snapshot,
        EndpointMachineIdentity identity);
    void Register(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string userAccount,
        string userSid,
        string controlIdentity);
    bool IsHealthy(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string controlIdentity,
        string userAccount,
        string userSid);
}

internal interface IEndpointSecurity
{
    void PrepareStateRoot(
        string stateRoot,
        string? sid,
        bool repairExistingChildren);
    void GrantUserReadExecute(string installRoot, string sid);
}

internal enum EndpointAclAuthority
{
    Privileged,
    AssignedUserRoot,
    AssignedUserMutable,
    AssignedUserReadOnly
}

internal sealed record EndpointAclPathPlan(
    string Path,
    EndpointAclAuthority Authority,
    bool IsDirectory);

internal sealed record EndpointAclPlan(
    string Root,
    SecurityIdentifier? AssignedUser,
    IReadOnlyList<EndpointAclPathPlan> Paths)
{
    internal static EndpointAclPlan Create(
        string stateRoot,
        string? assignedUserSid,
        bool includeChildren)
    {
        var root = Path.GetFullPath(stateRoot);
        var assignedUser = assignedUserSid is null
            ? null
            : new SecurityIdentifier(assignedUserSid);
        var paths = new List<EndpointAclPathPlan>
        {
            new(
                root,
                assignedUser is null
                    ? EndpointAclAuthority.Privileged
                    : EndpointAclAuthority.AssignedUserRoot,
                true)
        };
        if (!includeChildren)
            return new EndpointAclPlan(root, assignedUser, paths);
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories)
                 .OrderBy(value => value.Count(character =>
                     character == Path.DirectorySeparatorChar))
                 .ThenBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            var attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "Endpoint state cannot contain reparse points.");
            var isDirectory = attributes.HasFlag(FileAttributes.Directory);
            paths.Add(new EndpointAclPathPlan(
                path,
                Classify(root, path, assignedUser, isDirectory),
                isDirectory));
        }
        return new EndpointAclPlan(root, assignedUser, paths);
    }

    private static EndpointAclAuthority Classify(
        string root,
        string path,
        SecurityIdentifier? assignedUser,
        bool isDirectory)
    {
        if (assignedUser is null)
            return EndpointAclAuthority.Privileged;
        var relative = Path.GetRelativePath(root, path);
        var first = relative.Split(
            Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries)[0];
        if (string.Equals(first, "keys", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(first, "receipts", StringComparison.OrdinalIgnoreCase))
            return EndpointAclAuthority.AssignedUserReadOnly;
        if (!isDirectory && IsReadOnlyAuthorityFile(relative))
            return EndpointAclAuthority.AssignedUserReadOnly;
        return EndpointAclAuthority.AssignedUserMutable;
    }

    private static bool IsReadOnlyAuthorityFile(string relative) =>
        relative is
            "identity.json" or
            "node-host.json" or
            "bootstrap-receipt.json" or
            "retained-v1-migration.json";
}

internal static class EndpointAclEffectivePolicy
{
    internal static bool AllowsRestrictedToken(
        FileSystemSecurity security,
        SecurityIdentifier principal,
        SecurityIdentifier restrictedAuthority,
        FileSystemRights requestedRights)
    {
        ArgumentNullException.ThrowIfNull(security);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(restrictedAuthority);
        if (requestedRights == 0)
            throw new ArgumentOutOfRangeException(nameof(requestedRights));
        return Allows(security, principal, requestedRights) &&
            Allows(security, restrictedAuthority, requestedRights);
    }

    private static bool Allows(
        FileSystemSecurity security,
        SecurityIdentifier sid,
        FileSystemRights requestedRights)
    {
        var allowed = (FileSystemRights)0;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     typeof(SecurityIdentifier)))
        {
            if (!rule.IdentityReference.Equals(sid))
                continue;
            if (rule.AccessControlType == AccessControlType.Deny &&
                (rule.FileSystemRights & requestedRights) != 0)
                return false;
            if (rule.AccessControlType == AccessControlType.Allow)
                allowed |= rule.FileSystemRights;
        }
        return (allowed & requestedRights) == requestedRights;
    }
}
internal sealed class IcaclsEndpointSecurity : IEndpointSecurity
{
    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public void PrepareStateRoot(
        string stateRoot,
        string? sid,
        bool repairExistingChildren)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Endpoint ACLs require Windows.");
        var root = Path.GetFullPath(stateRoot);
        var rootAttributes = File.GetAttributes(root);
        if (!rootAttributes.HasFlag(FileAttributes.Directory) ||
            rootAttributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "Endpoint state root must be a plain directory.");
        ValidateNoReparsePoints(root);
        var plan = EndpointAclPlan.Create(
            root,
            sid,
            repairExistingChildren);
        foreach (var item in plan.Paths)
            Apply(item, plan.AssignedUser);
        ValidateNoReparsePoints(root);
    }

    public void GrantUserReadExecute(string installRoot, string sid) =>
        EndpointProvisioner.Run(
            "icacls.exe",
            installRoot,
            "/grant",
            $"*{sid}:(OI)(CI)RX",
            "/T",
            "/C");

    private static void Apply(
        EndpointAclPathPlan item,
        SecurityIdentifier? assignedUser)
    {
        if (item.IsDirectory)
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(
                isProtected: true,
                preserveInheritance: false);
            AddDirectoryAuthority(
                security,
                SystemSid,
                FileSystemRights.FullControl);
            AddDirectoryAuthority(
                security,
                AdministratorsSid,
                FileSystemRights.FullControl);
            AddAssignedUserDirectoryRules(
                security,
                assignedUser,
                item.Authority);
            new DirectoryInfo(item.Path).SetAccessControl(security);
            return;
        }
        var fileSecurity = new FileSecurity();
        fileSecurity.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        AddFileAuthority(
            fileSecurity,
            SystemSid,
            FileSystemRights.FullControl);
        AddFileAuthority(
            fileSecurity,
            AdministratorsSid,
            FileSystemRights.FullControl);
        if (assignedUser is not null)
            AddFileAuthority(
                fileSecurity,
                assignedUser,
                item.Authority == EndpointAclAuthority.AssignedUserReadOnly
                    ? FileSystemRights.ReadAndExecute
                    : FileSystemRights.Modify);
        new FileInfo(item.Path).SetAccessControl(fileSecurity);
    }

    private static void AddAssignedUserDirectoryRules(
        DirectorySecurity security,
        SecurityIdentifier? assignedUser,
        EndpointAclAuthority authority)
    {
        if (assignedUser is null || authority == EndpointAclAuthority.Privileged)
            return;
        if (authority == EndpointAclAuthority.AssignedUserRoot)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                assignedUser,
                FileSystemRights.ReadAndExecute | FileSystemRights.Write,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                assignedUser,
                FileSystemRights.Modify,
                InheritanceFlags.ObjectInherit |
                InheritanceFlags.ContainerInherit,
                PropagationFlags.InheritOnly,
                AccessControlType.Allow));
            return;
        }
        AddDirectoryAuthority(
            security,
            assignedUser,
            authority == EndpointAclAuthority.AssignedUserReadOnly
                ? FileSystemRights.ReadAndExecute
                : FileSystemRights.Modify);
    }

    private static void AddDirectoryAuthority(
        DirectorySecurity security,
        SecurityIdentifier sid,
        FileSystemRights rights) =>
        security.AddAccessRule(new FileSystemAccessRule(
            sid,
            rights,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

    private static void AddFileAuthority(
        FileSecurity security,
        SecurityIdentifier sid,
        FileSystemRights rights) =>
        security.AddAccessRule(new FileSystemAccessRule(
            sid,
            rights,
            AccessControlType.Allow));

    private static void ValidateNoReparsePoints(string root)
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories))
            if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "Endpoint state cannot contain reparse points.");
    }
}
internal interface IEndpointReadyHealthVerifier
{
    bool IsKnownGood(
        ProvisionerOptions options,
        EndpointMachineIdentity identity);
}

internal sealed class AuthenticatedEndpointReadyHealthVerifier :
    IEndpointReadyHealthVerifier
{
    private static readonly JsonSerializerOptions Json = CreateJson();

    public bool IsKnownGood(
        ProvisionerOptions options,
        EndpointMachineIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(identity);
        var healthPath = Path.Combine(
            options.StateRoot,
            EndpointStateFiles.V2Health);
        var keyPath = Path.Combine(
            options.StateRoot,
            "keys",
            "rdp-dvc.key");
        if (!RegularFile(healthPath) || !RegularFile(keyPath) ||
            new FileInfo(healthPath).Length is <= 0 or > 64 * 1024 ||
            new FileInfo(keyPath).Length != 32)
            return false;
        var key = File.ReadAllBytes(keyPath);
        try
        {
            var authenticated = JsonSerializer.Deserialize<
                AuthenticatedEndpointV2Health>(
                File.ReadAllBytes(healthPath),
                Json);
            if (authenticated is null)
                return false;
            var health = EndpointV2HealthAuthenticator.Verify(
                authenticated,
                key);
            if (health.SessionId != identity.SessionId ||
                health.HostId != identity.HostId ||
                health.NodeIncarnationId != identity.IncarnationId ||
                health.NodeIdentity != identity.NodeIdentity ||
                health.ControlIdentity != identity.ControlIdentity ||
                health.State != EndpointV2HealthState.Authenticated ||
                health.ReconnectGeneration <= 0 ||
                health.UpdatedAtUtc <
                    DateTimeOffset.UtcNow - TimeSpan.FromSeconds(30) ||
                health.UpdatedAtUtc >
                    DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5) ||
                health.ProcessId <= 0)
                return false;
            using var process = Process.GetProcessById(health.ProcessId);
            return !process.HasExited &&
                process.Id == health.ProcessId &&
                process.SessionId == health.WtsSessionId &&
                process.StartTime.ToUniversalTime() ==
                    health.ProcessStartedAtUtc;
        }
        catch (Exception exception) when (exception is
            JsonException or InvalidDataException or ArgumentException or
            InvalidOperationException or
            System.ComponentModel.Win32Exception)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static bool RegularFile(string path) =>
        File.Exists(path) &&
        !File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint);

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.CamelCase,
            allowIntegerValues: false));
        return options;
    }
}
internal sealed record ProvisionedUser(
    string Account,
    string Sid);

internal sealed record EndpointTaskSnapshot(
    string? KeeperXml,
    bool KeeperWasRunning,
    string? ServerXml,
    bool ServerWasRunning);

internal sealed class EndpointProvisioner(
    IProvisionerFileSystem files,
    IEndpointTaskRegistrar tasks,
    IEndpointSecurity security,
    IEndpointReadyHealthVerifier? readyHealth = null)
{
    private IEndpointReadyHealthVerifier EndpointReadyHealth { get; } =
        readyHealth ?? new AuthenticatedEndpointReadyHealthVerifier();
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    internal string Provision(ProvisionerOptions options)
    {
        var config = JsonSerializer.Deserialize<EndpointProvisioningConfig>(
                         files.ReadAllText(options.ConfigPath),
                         Json)
                     ?? throw new InvalidDataException(
                         "Provisioning config is empty.");
        var artifact = JsonSerializer.Deserialize<EndpointArtifactAttestation>(
                           files.ReadAllText(options.ArtifactAttestationPath),
                           Json)
                       ?? throw new InvalidDataException(
                           "Artifact attestation is empty.");
        ValidateArtifact(artifact);
        ValidateConfig(config, artifact, options);
        ValidatePayload(options.InstallRoot, artifact.ProductVersion);
        if (options.TransactionAction != MsiTransactionAction.Prepare)
            throw new InvalidOperationException(
                "MSI transaction control cannot provision endpoint state.");
        if (options.MsiTransactionId is not null &&
            TryLoadMsiTransaction(options) is { } pending)
        {
            if (!files.FileExists(pending.ReceiptPath))
                throw new InvalidDataException(
                    "Prepared MSI transaction receipt is unavailable.");
            if (pending.State is
                EndpointProvisionerTransactionState.Prepared or
                EndpointProvisionerTransactionState.CommitIntent)
                return pending.ReceiptPath;
            if (pending.State == EndpointProvisionerTransactionState.Committed)
            {
                if (EndpointReadyHealth
                    .IsKnownGood(options, pending.TaskSnapshotIdentity))
                {
                    files.DeleteDirectory(pending.BackupRoot);
                    DeleteMsiTransaction(options);
                    return pending.ReceiptPath;
                }
                DeleteMsiTransaction(options);
            }
            else
            {
                throw new InvalidOperationException(
                    "MSI transaction is already rolling back.");
            }
        }
        var user = ResolveUser(config);
        var backupRoot = options.StateRoot + ".previous";
        if (!files.DirectoryExists(options.StateRoot) &&
            files.DirectoryExists(backupRoot))
            files.MoveDirectory(backupRoot, options.StateRoot);
        if (files.DirectoryExists(options.StateRoot))
            security.PrepareStateRoot(
                options.StateRoot,
                user.Sid,
                repairExistingChildren: true);
        if (files.DirectoryExists(options.StateRoot) &&
            files.DirectoryExists(backupRoot))
        {
            var currentIsCommitted = false;
            try
            {
                var currentIdentity = LoadIdentity(
                    Path.Combine(options.StateRoot, "identity.json"));
                var currentReceipt = LoadValidatedReceipt(
                    Path.Combine(
                        options.StateRoot,
                        "bootstrap-receipt.json"),
                    options.StateRoot,
                    currentIdentity);
                currentIsCommitted =
                    currentReceipt.ProductVersion ==
                        currentIdentity.ProductVersion &&
                    currentReceipt.ControlIdentity ==
                        currentIdentity.ControlIdentity &&
                    tasks.IsHealthy(
                        options.InstallRoot,
                        options.StateRoot,
                        currentIdentity,
                        config.ControlIdentity,
                        user.Account,
                        user.Sid) &&
                    EndpointReadyHealth
                        .IsKnownGood(options, currentIdentity);
            }

            catch (JsonException)
            {
            }
            catch (InvalidDataException)
            {
            }
            catch (FormatException)
            {
            }
            catch (CryptographicException)
            {
            }
            catch (IOException)
            {
            }
            if (currentIsCommitted)
                files.DeleteDirectory(backupRoot);
            else
            {
                files.DeleteDirectory(options.StateRoot);
                files.MoveDirectory(backupRoot, options.StateRoot);
                security.PrepareStateRoot(
                    options.StateRoot,
                    user.Sid,
                    repairExistingChildren: true);
            }
        }
        var existing = files.DirectoryExists(options.StateRoot);
        if (existing &&
            TryLoadHealthyExisting(
                options,
                config,
                artifact,
                out var receipt))
            return receipt;
        var previousIdentity = existing
            ? LoadIdentity(Path.Combine(options.StateRoot, "identity.json"))
            : null;
        var workingRoot =
            options.StateRoot + $".new-{Guid.NewGuid():N}";
        var backupCreated = false;
        var newStateInstalled = false;
        EndpointTaskSnapshot? taskSnapshot = null;
        EndpointMachineIdentity? taskSnapshotIdentity = null;
        var restoreTasks = false;
        MaintenanceStateSnapshot? maintenanceSnapshot = null;
        try
        {
            if (existing)
            {
                taskSnapshot = tasks.Capture(previousIdentity!);
                taskSnapshotIdentity = previousIdentity;
                restoreTasks = true;
                tasks.Quiesce(previousIdentity!);
                files.CreateDirectory(workingRoot);
                security.PrepareStateRoot(
                    workingRoot,
                    null,
                    repairExistingChildren: false);
                files.CopyDirectory(options.StateRoot, workingRoot);
            }
            else
            {
                files.CreateDirectory(workingRoot);
                security.PrepareStateRoot(
                    workingRoot,
                    null,
                    repairExistingChildren: false);
            }
            DeleteRuntimeReadiness(workingRoot);
            var retainedV1 = previousIdentity is null
                ? null
                : ValidateRetainedV1Migration(
                    workingRoot,
                    previousIdentity);
            if (previousIdentity is not null)
                ArchiveBootstrapReceipt(
                    workingRoot,
                    previousIdentity.ProductVersion);
            var identityPath = Path.Combine(workingRoot, "identity.json");
            var identity = LoadOrCreateIdentity(
                identityPath,
                artifact.ProductVersion,
                config.ControlIdentity);
            var keys = Path.Combine(workingRoot, "keys");
            files.CreateDirectory(keys);
            var authenticationPath = Path.Combine(keys, "rdp-dvc.key");
            var nodePrivatePath = Path.Combine(keys, "node-signing.pk8");
            var controlPublicPath =
                Path.Combine(keys, "control-signing.spki");
            var authentication = LoadOrCreateSecret(authenticationPath, 32);
            using var node = LoadOrCreateNodeKey(nodePrivatePath);
            var nodePublic = node.ExportSubjectPublicKeyInfo();
            try
            {
                var controlPublic = ResolveConfigFile(
                    options.ConfigPath,
                    config.ControlSigningPublicKey);
                var controlBytes = files.ReadAllBytes(controlPublic);
                ValidateControlPublicKey(controlBytes);
                if (files.FileExists(controlPublicPath))
                {
                    var enrolled = files.ReadAllBytes(controlPublicPath);
                    try
                    {
                        if (!CryptographicOperations.FixedTimeEquals(
                                enrolled,
                                controlBytes))
                            throw new InvalidOperationException(
                                "Endpoint upgrade cannot replace enrolled Control signing key.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(enrolled);
                    }
                }
                else
                {
                    files.WriteAtomic(controlPublicPath, controlBytes);
                }
                CryptographicOperations.ZeroMemory(controlBytes);
                maintenanceSnapshot = CaptureMaintenanceState(options);
                PrepareMaintenanceState(
                    options,
                    config,
                    artifact,
                    identity,
                    user);
                var migrationReceipt = retainedV1 is null
                    ? null
                    : WriteRetainedV1MigrationAuthorization(
                        workingRoot,
                        identity,
                        node,
                        retainedV1);
                WriteNodeConfig(
                    Path.Combine(workingRoot, "node-host.json"),
                    options.StateRoot,
                    identity);
                WriteReceipt(
                    Path.Combine(
                        workingRoot,
                        "bootstrap-receipt.json"),
                    options,
                    config,
                    artifact,
                    identity,
                    authentication,
                    node,
                    nodePublic,
                    migrationReceipt);
                security.PrepareStateRoot(
                    workingRoot,
                    user.Sid,
                    repairExistingChildren: true);
                security.GrantUserReadExecute(options.InstallRoot, user.Sid);
                taskSnapshot ??= tasks.Capture(identity);
                taskSnapshotIdentity ??= identity;
                if (existing)
                {
                    files.MoveDirectory(options.StateRoot, backupRoot);
                    backupCreated = true;
                }
                files.MoveDirectory(workingRoot, options.StateRoot);
                newStateInstalled = true;
                try
                {
                    restoreTasks = true;
                    tasks.Register(
                        options.InstallRoot,
                        options.StateRoot,
                        identity,
                        user.Account,
                        user.Sid,
                        config.ControlIdentity);
                    restoreTasks = false;
                }
                catch
                {
                    files.DeleteDirectory(options.StateRoot);
                    newStateInstalled = false;
                    if (existing)
                    {
                        files.MoveDirectory(backupRoot, options.StateRoot);
                        backupCreated = false;
                    }
                    tasks.Restore(taskSnapshot, identity);
                    restoreTasks = false;
                    throw;
                }
                var receiptPath = Path.Combine(
                    options.StateRoot,
                    "bootstrap-receipt.json");
                if (options.MsiTransactionId is { } msiTransactionId)
                {
                    var transaction = new EndpointProvisionerTransaction(
                        1,
                        msiTransactionId,
                        EndpointProvisionerTransactionState.Prepared,
                        options.StateRoot,
                        backupRoot,
                        existing,
                        taskSnapshot,
                        taskSnapshotIdentity,
                        maintenanceSnapshot ?? throw new InvalidOperationException(
                            "Maintenance state snapshot is unavailable."),
                        user.Sid,
                        receiptPath);
                    SaveMsiTransaction(options, transaction);
                    maintenanceSnapshot = null;
                    return receiptPath;
                }
                try
                {
                    files.DeleteDirectory(backupRoot);
                    backupCreated = false;
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
                maintenanceSnapshot = null;
                return receiptPath;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(authentication);
                CryptographicOperations.ZeroMemory(nodePublic);
            }
        }
        catch
        {
            try
            {
                files.DeleteDirectory(workingRoot);
                if (newStateInstalled)
                {
                    files.DeleteDirectory(options.StateRoot);
                    newStateInstalled = false;
                }
                if (backupCreated &&
                    !files.DirectoryExists(options.StateRoot))
                {
                    files.MoveDirectory(backupRoot, options.StateRoot);
                    backupCreated = false;
                }
                if (!existing)
                    files.DeleteDirectory(options.StateRoot);
                if (!backupCreated)
                    files.DeleteDirectory(backupRoot);
                if (maintenanceSnapshot is not null)
                    RestoreMaintenanceState(
                        options,
                        maintenanceSnapshot);
            }
            finally
            {
                if (restoreTasks && taskSnapshot is not null)
                    tasks.Restore(
                        taskSnapshot,
                        taskSnapshotIdentity ??
                        throw new InvalidOperationException(
                            "Endpoint task snapshot identity is unavailable."));
            }
            throw;
        }
    }

    internal void CommitMsiTransaction(ProvisionerOptions options)
    {
        var transaction = LoadMsiTransaction(options);
        if (transaction.State is
            EndpointProvisionerTransactionState.RollbackIntent or
            EndpointProvisionerTransactionState.StateRestored or
            EndpointProvisionerTransactionState.TasksRestored)
            throw new InvalidOperationException(
                "A rolling-back MSI transaction cannot be committed.");
        if (transaction.State == EndpointProvisionerTransactionState.Prepared)
            transaction = TransitionMsiTransaction(
                options,
                transaction,
                EndpointProvisionerTransactionState.CommitIntent);
        if (transaction.State == EndpointProvisionerTransactionState.CommitIntent)
            transaction = TransitionMsiTransaction(
                options,
                transaction,
                EndpointProvisionerTransactionState.Committed);
        if (!EndpointReadyHealth
            .IsKnownGood(options, transaction.TaskSnapshotIdentity))
            return;
        files.DeleteDirectory(transaction.BackupRoot);
        DeleteMsiTransaction(options);
    }

    internal void RollbackMsiTransaction(
        ProvisionerOptions options,
        string failureCode)
    {
        if (string.IsNullOrWhiteSpace(failureCode) || failureCode.Length > 64)
            throw new ArgumentException(
                "MSI rollback failure code is invalid.",
                nameof(failureCode));
        var transaction = LoadMsiTransaction(options);
        if (transaction.State == EndpointProvisionerTransactionState.Committed)
            throw new InvalidOperationException(
                "A committed MSI transaction cannot be rolled back.");
        if (transaction.State < EndpointProvisionerTransactionState.RollbackIntent)
            transaction = TransitionMsiTransaction(
                options,
                transaction,
                EndpointProvisionerTransactionState.RollbackIntent);
        if (transaction.State == EndpointProvisionerTransactionState.RollbackIntent)
        {
            if (transaction.PriorStateExisted)
            {
                if (files.DirectoryExists(transaction.BackupRoot))
                {
                    files.DeleteDirectory(transaction.StateRoot);
                    files.MoveDirectory(
                        transaction.BackupRoot,
                        transaction.StateRoot);
                }
                else
                {
                    var restored = LoadIdentity(Path.Combine(
                        transaction.StateRoot,
                        "identity.json"));
                    if (restored != transaction.TaskSnapshotIdentity)
                        throw new InvalidDataException(
                            "MSI rollback lost the prior endpoint state.");
                }
            }
            else
            {
                files.DeleteDirectory(transaction.StateRoot);
                files.DeleteDirectory(transaction.BackupRoot);
            }
            RestoreMaintenanceState(
                options,
                transaction.MaintenanceSnapshot);
            transaction = TransitionMsiTransaction(
                options,
                transaction,
                EndpointProvisionerTransactionState.StateRestored);
        }
        if (transaction.State == EndpointProvisionerTransactionState.StateRestored)
        {
            tasks.Restore(
                transaction.TaskSnapshot,
                transaction.TaskSnapshotIdentity);
            transaction = TransitionMsiTransaction(
                options,
                transaction,
                EndpointProvisionerTransactionState.TasksRestored);
        }
        files.DeleteDirectory(transaction.BackupRoot);
        DeleteMsiTransaction(options);
        _ = failureCode;
    }

    private EndpointProvisionerTransaction? TryLoadMsiTransaction(
        ProvisionerOptions options)
    {
        if (options.MsiTransactionId is null ||
            !files.FileExists(options.TransactionJournalPath))
            return null;
        var transaction = JsonSerializer.Deserialize<
            EndpointProvisionerTransaction>(
            files.ReadAllText(options.TransactionJournalPath),
            Json) ?? throw new InvalidDataException(
                "MSI transaction journal is empty.");
        ValidateMsiTransaction(options, transaction);
        return transaction;
    }

    private EndpointProvisionerTransaction LoadMsiTransaction(
        ProvisionerOptions options) =>
        TryLoadMsiTransaction(options) ??
        throw new InvalidDataException(
            "MSI transaction journal is unavailable.");

    private void SaveMsiTransaction(
        ProvisionerOptions options,
        EndpointProvisionerTransaction transaction)
    {
        ValidateMsiTransaction(options, transaction);
        var root = Path.GetDirectoryName(options.TransactionJournalPath) ??
            throw new InvalidDataException(
                "MSI transaction journal has no parent.");
        if (!files.DirectoryExists(root))
            files.CreateDirectory(root);
        security.PrepareStateRoot(root, null, repairExistingChildren: true);
        files.WriteAtomic(
            options.TransactionJournalPath,
            JsonSerializer.SerializeToUtf8Bytes(transaction, Json));
        security.PrepareStateRoot(root, null, repairExistingChildren: true);
    }

    private EndpointProvisionerTransaction TransitionMsiTransaction(
        ProvisionerOptions options,
        EndpointProvisionerTransaction transaction,
        EndpointProvisionerTransactionState state)
    {
        var updated = transaction with { State = state };
        SaveMsiTransaction(options, updated);
        return updated;
    }

    private static void ValidateMsiTransaction(
        ProvisionerOptions options,
        EndpointProvisionerTransaction transaction)
    {
        if (transaction.Version != 1 ||
            options.MsiTransactionId is null ||
            transaction.TransactionId != options.MsiTransactionId ||
            transaction.TransactionId == Guid.Empty ||
            transaction.StateRoot != options.StateRoot ||
            transaction.BackupRoot != options.StateRoot + ".previous" ||
            transaction.TaskSnapshotIdentity.HostId == Guid.Empty ||
            transaction.TaskSnapshotIdentity.IncarnationId == Guid.Empty ||
            string.IsNullOrWhiteSpace(transaction.UserSid) ||
            transaction.ReceiptPath != Path.Combine(
                options.StateRoot,
                "bootstrap-receipt.json") ||
            !Enum.IsDefined(transaction.State))
            throw new InvalidDataException(
                "MSI transaction journal is invalid.");
    }

    private static void DeleteMsiTransaction(ProvisionerOptions options)
    {
        if (File.Exists(options.TransactionJournalPath))
            File.Delete(options.TransactionJournalPath);
    }

    internal string Verify(ProvisionerOptions options)
    {
        var config = JsonSerializer.Deserialize<EndpointProvisioningConfig>(
                         files.ReadAllText(options.ConfigPath),
                         Json)
                     ?? throw new InvalidDataException(
                         "Provisioning config is empty.");
        var artifact = JsonSerializer.Deserialize<EndpointArtifactAttestation>(
                           files.ReadAllText(options.ArtifactAttestationPath),
                           Json)
                       ?? throw new InvalidDataException(
                           "Artifact attestation is empty.");
        ValidateArtifact(artifact);
        ValidateConfig(config, artifact, options);
        ValidatePayload(options.InstallRoot, artifact.ProductVersion);
        if (!files.DirectoryExists(options.StateRoot) ||
            !TryLoadHealthyExisting(
                options,
                config,
                artifact,
                out var receipt))
            throw new InvalidDataException(
                "Endpoint provisioning commit is not healthy.");
        return receipt;
    }

    private static void DeleteRuntimeReadiness(string stateRoot)
    {
        foreach (var name in new[]
                 {
                     EndpointStateFiles.V2Health,
                     EndpointStateFiles.V2Health + ".failure",
                     EndpointStateFiles.V2Health + ".new",
                     EndpointStateFiles.RetainedV1Health,
                     EndpointStateFiles.RetainedV1Health + ".failure",
                     EndpointStateFiles.RetainedV1Health + ".new"
                 })
        {
            var path = Path.Combine(stateRoot, name);
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    private void ArchiveBootstrapReceipt(
        string workingRoot,
        string productVersion)
    {
        var source = Path.Combine(workingRoot, "bootstrap-receipt.json");
        if (!files.FileExists(source))
            return;
        if (!Version.TryParse(productVersion, out var version) ||
            version.Build < 0 || version.Revision >= 0)
            throw new InvalidDataException(
                "Existing endpoint receipt version is invalid.");
        var content = files.ReadAllBytes(source);
        try
        {
            var digest = Convert.ToHexString(SHA256.HashData(content));
            var receiptRoot = Path.Combine(workingRoot, "receipts");
            files.CreateDirectory(receiptRoot);
            var destination = Path.Combine(
                receiptRoot,
                $"bootstrap-{version.ToString(3)}-{digest}.json");
            if (files.FileExists(destination))
            {
                var existing = files.ReadAllBytes(destination);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(
                            existing,
                            content))
                        throw new InvalidDataException(
                            "Archived endpoint receipt hash collided.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(existing);
                }
                return;
            }
            files.WriteNew(destination, content);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }
    private EndpointMachineIdentity LoadOrCreateIdentity(
        string path,
        string productVersion,
        string controlIdentity)
    {
        if (files.FileExists(path))
        {
            var existing = JsonSerializer.Deserialize<EndpointMachineIdentity>(
                               files.ReadAllText(path),
                               Json)
                           ?? throw new InvalidDataException(
                               "Existing endpoint identity is invalid.");
            if (existing.Version != 1 ||
                existing.BootstrapOperationId == Guid.Empty ||
                existing.SessionId == Guid.Empty ||
                existing.HostId == Guid.Empty ||
                existing.IncarnationId == Guid.Empty ||
                string.IsNullOrWhiteSpace(existing.NodeIdentity))
                throw new InvalidDataException(
                    "Existing endpoint identity is invalid.");
            if (!Version.TryParse(existing.ProductVersion, out var oldVersion) ||
                !Version.TryParse(productVersion, out var newVersion) ||
                newVersion < oldVersion)
                throw new InvalidOperationException(
                    "Endpoint provisioning cannot downgrade machine state.");
            var updated = existing with
            {
                ProductVersion = productVersion
            };
            if (!string.Equals(
                    existing.ControlIdentity,
                    controlIdentity,
                    StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "Endpoint upgrade cannot replace enrolled Control identity.");
            files.WriteAtomic(
                path,
                JsonSerializer.SerializeToUtf8Bytes(updated, Json));
            return updated;
        }

        var host = Guid.NewGuid();
        var identity = new EndpointMachineIdentity(
            1,
            productVersion,
            Guid.NewGuid(),
            Guid.NewGuid(),
            host,
            Guid.NewGuid(),
            $"node/{host:N}",
            controlIdentity,
            DateTimeOffset.UtcNow);
        files.WriteNew(
            path,
            JsonSerializer.SerializeToUtf8Bytes(identity, Json));
        return identity;
    }

    private ProvisionedUser ResolveUser(EndpointProvisioningConfig config)
    {
        if (config.ProvisionedUserAccount is not { Length: > 0 } account ||
            config.ProvisionedUserSid is not { Length: > 0 } sid)
            return tasks.ResolveUser();
        account = new System.Security.Principal.SecurityIdentifier(sid)
            .Translate(typeof(System.Security.Principal.NTAccount))
            .Value;
        return new(account, sid);
    }

    private EndpointMachineIdentity LoadIdentity(string path)
    {
        if (!files.FileExists(path))
            throw new InvalidDataException(
                "Existing endpoint identity is unavailable.");
        var identity = JsonSerializer.Deserialize<EndpointMachineIdentity>(
                           files.ReadAllText(path),
                           Json)
                       ?? throw new InvalidDataException(
                           "Existing endpoint identity is invalid.");
        if (identity.Version != 1 ||
            identity.BootstrapOperationId == Guid.Empty ||
            identity.SessionId == Guid.Empty ||
            identity.HostId == Guid.Empty ||
            identity.IncarnationId == Guid.Empty ||
            string.IsNullOrWhiteSpace(identity.NodeIdentity) ||
            string.IsNullOrWhiteSpace(identity.ControlIdentity))
            throw new InvalidDataException(
                "Existing endpoint identity is invalid.");
        return identity;
    }

    private byte[] LoadOrCreateSecret(string path, int length)
    {
        if (files.FileExists(path))
        {
            var existing = files.ReadAllBytes(path);
            if (existing.Length != length)
                throw new InvalidDataException(
                    "Existing endpoint secret has an invalid length.");
            return existing;
        }
        var value = RandomNumberGenerator.GetBytes(length);
        files.WriteNew(path, value);
        return value;
    }

    private ECDsa LoadOrCreateNodeKey(string path)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (files.FileExists(path))
        {
            var bytes = files.ReadAllBytes(path);
            try
            {
                key.ImportPkcs8PrivateKey(bytes, out var read);
                if (read != bytes.Length)
                    throw new CryptographicException(
                        "Existing node key contains trailing data.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
            return key;
        }
        var privateKey = key.ExportPkcs8PrivateKey();
        try
        {
            files.WriteNew(path, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
        return key;
    }

    private void WriteReceipt(
        string path,
        ProvisionerOptions options,
        EndpointProvisioningConfig config,
        EndpointArtifactAttestation artifact,
        EndpointMachineIdentity identity,
        byte[] authentication,
        ECDsa node,
        byte[] nodePublic,
        EndpointV1MigrationReceipt? migrationReceipt)
    {
        using var rsa = RSA.Create();
        var envelopePath = ResolveConfigFile(
            options.ConfigPath,
            config.BootstrapEncryptionPublicKey);
        var publicKey = files.ReadAllBytes(envelopePath);
        try
        {
            rsa.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length)
                throw new CryptographicException(
                    "Bootstrap encryption key contains trailing data.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
        var ciphertext = RdpDvcBootstrapEnvelope.Encrypt(
            rsa,
            new(
                identity.BootstrapOperationId,
                identity.SessionId,
                identity.HostId,
                identity.IncarnationId,
                authentication,
                nodePublic));
        try
        {
            var body = new EndpointProvisioningReceiptBody(
                2,
                artifact.ProductVersion,
                artifact.MsiSha256,
                artifact.SourceRepository,
                artifact.SourceCommit,
                artifact.SourceRef,
                artifact.SignerWorkflow,
                artifact.SourceRunId,
                artifact.ProductCode,
                artifact.ConfigSha256,
                artifact.BootstrapEncryptionPublicKeySha256,
                artifact.ControlSigningPublicKeySha256,
                artifact.ControlIdentity,
                identity.BootstrapOperationId,
                identity.SessionId,
                identity.HostId,
                identity.IncarnationId,
                identity.NodeIdentity,
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(nodePublic),
                LegacyConnectionNonces: null,
                DateTimeOffset.UtcNow,
                new(
                    2,
                    EndpointStateFiles.ReconnectLedgerV2,
                    EndpointStateFiles.V2Health),
                migrationReceipt);
            var canonical = JsonSerializer.SerializeToUtf8Bytes(body);
            var signature = node.SignData(
                canonical,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            var receipt = new EndpointProvisioningReceipt(
                body,
                Convert.ToBase64String(signature));
            files.WriteAtomic(
                path,
                JsonSerializer.SerializeToUtf8Bytes(receipt, Json));
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(canonical);
            CryptographicOperations.ZeroMemory(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private sealed record LegacyNonceInventory(
        EndpointNonceState State,
        string InventorySha256);

    private sealed record ValidatedRetainedV1Migration(
        LegacyNonceInventory Inventory,
        string RetainedEndpointVersion);

    private ValidatedRetainedV1Migration? ValidateRetainedV1Migration(
        string stateRoot,
        EndpointMachineIdentity identity)
    {
        var noncePath = Path.Combine(stateRoot, "nonce-sequence.json");
        var inventory = ReadLegacyNonceInventory(noncePath, identity);
        if (inventory is null)
            return null;
        var receipt = LoadValidatedReceipt(
            Path.Combine(stateRoot, "bootstrap-receipt.json"),
            stateRoot,
            identity);
        if (string.Equals(
                identity.ProductVersion,
                RetainedV1MigrationAuthorizationBody
                    .SupportedEndpointVersion,
                StringComparison.Ordinal) &&
            string.Equals(
                receipt.ProductVersion,
                RetainedV1MigrationAuthorizationBody
                    .SupportedEndpointVersion,
                StringComparison.Ordinal) &&
            receipt.LegacyConnectionNonces is not null &&
            receipt.ReconnectLedger is null &&
            receipt.V1Migration is null)
            return new(
                inventory,
                RetainedV1MigrationAuthorizationBody
                    .SupportedEndpointVersion);
        if (receipt.V1Migration is { } migration &&
            string.Equals(
                migration.RetainedEndpointVersion,
                RetainedV1MigrationAuthorizationBody
                    .SupportedEndpointVersion,
                StringComparison.Ordinal))
            return new(inventory, migration.RetainedEndpointVersion);
        throw new InvalidDataException(
            "The retained nonce inventory is not durably proven as exact 1.0.23 state.");
    }

    private EndpointV1MigrationReceipt
        WriteRetainedV1MigrationAuthorization(
            string stateRoot,
            EndpointMachineIdentity identity,
            ECDsa node,
            ValidatedRetainedV1Migration migration)
    {
        const string fileName = "retained-v1-migration.json";
        var authorization = RetainedV1MigrationAuthorizationCodec.Create(
            new(
                1,
                migration.RetainedEndpointVersion,
                identity.SessionId,
                identity.HostId,
                identity.IncarnationId,
                migration.Inventory.State.Nonces.Count,
                migration.Inventory.State.NextIndex,
                migration.Inventory.InventorySha256),
            node);
        var encoded = RetainedV1MigrationAuthorizationCodec.Encode(
            authorization);
        try
        {
            files.WriteAtomic(Path.Combine(stateRoot, fileName), encoded);
            return new(
                1,
                migration.RetainedEndpointVersion,
                migration.Inventory.State.Nonces.Count,
                migration.Inventory.State.NextIndex,
                migration.Inventory.InventorySha256,
                fileName,
                Convert.ToHexString(SHA256.HashData(encoded)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private LegacyNonceInventory? ReadLegacyNonceInventory(
        string path,
        EndpointMachineIdentity identity)
    {
        if (!files.FileExists(path))
            return null;
        var bytes = files.ReadAllBytes(path);
        try
        {
            var existing = JsonSerializer.Deserialize<EndpointNonceState>(
                               bytes,
                               Json)
                           ?? throw new InvalidDataException(
                               "Existing endpoint nonce state is invalid.");
            ValidateLegacyNonceState(existing, identity);
            return new(
                existing,
                Convert.ToHexString(SHA256.HashData(bytes)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ValidateLegacyNonceState(
        EndpointNonceState state,
        EndpointMachineIdentity identity)
    {
        if (state.Version != 1 ||
            state.SessionId != identity.SessionId ||
            state.HostId != identity.HostId ||
            state.NodeIncarnationId != identity.IncarnationId ||
            state.Nonces.Count is < 2 or > 256 ||
            state.Nonces.Any(value => value == Guid.Empty) ||
            state.Nonces.Distinct().Count() != state.Nonces.Count ||
            state.NextIndex < 0 ||
            state.NextIndex > state.Nonces.Count)
            throw new InvalidDataException(
                "Existing endpoint nonce state is invalid.");
    }
    private MaintenanceStateSnapshot CaptureMaintenanceState(
        ProvisionerOptions options)
    {
        var maintenanceStateRoot = options.EffectiveMaintenanceStateRoot;
        if (!files.DirectoryExists(maintenanceStateRoot))
            return new MaintenanceStateSnapshot(false, null, null, null);
        var configurationPath = Path.Combine(
            maintenanceStateRoot,
            "service-config.json");
        var controlPath = Path.Combine(
            maintenanceStateRoot,
            "control-signing.spki");
        var bootstrapPath = Path.Combine(
            maintenanceStateRoot,
            "bootstrap-envelope.spki");
        return new MaintenanceStateSnapshot(
            true,
            files.FileExists(configurationPath)
                ? files.ReadAllBytes(configurationPath)
                : null,
            files.FileExists(controlPath)
                ? files.ReadAllBytes(controlPath)
                : null,
            files.FileExists(bootstrapPath)
                ? files.ReadAllBytes(bootstrapPath)
                : null);
    }

    private void PrepareMaintenanceState(
        ProvisionerOptions options,
        EndpointProvisioningConfig config,
        EndpointArtifactAttestation artifact,
        EndpointMachineIdentity identity,
        ProvisionedUser user)
    {
        var maintenanceStateRoot = options.EffectiveMaintenanceStateRoot;
        if (!files.DirectoryExists(maintenanceStateRoot))
            files.CreateDirectory(maintenanceStateRoot);
        security.PrepareStateRoot(
            maintenanceStateRoot, null,
            repairExistingChildren: true);
        PreserveMaintenanceTrustFile(
            ResolveConfigFile(
                options.ConfigPath,
                config.ControlSigningPublicKey),
            Path.Combine(
                maintenanceStateRoot,
                "control-signing.spki"),
            ValidateControlPublicKey,
            "Maintenance Control trust cannot change during repair.");
        PreserveMaintenanceTrustFile(
            ResolveConfigFile(
                options.ConfigPath,
                config.BootstrapEncryptionPublicKey),
            Path.Combine(
                maintenanceStateRoot,
                "bootstrap-envelope.spki"),
            static _ => { },
            "Maintenance bootstrap trust cannot change during repair.");
        var serviceConfiguration = new EndpointMaintenanceConfiguration(
            1,
            "Steward.Maintenance.v1",
            user.Sid,
            user.Account,
            identity.ControlIdentity,
            $"Steward.Node.{identity.IncarnationId:N}",
            identity.HostId,
            artifact.ProductVersion,
            artifact.SourceRepository,
            artifact.SignerWorkflow,
            options.StateRoot,
            options.InstallRoot,
            Path.Combine(
                Path.GetDirectoryName(maintenanceStateRoot) ??
                    throw new InvalidDataException(
                        "Maintenance state root has no parent."),
                "Versions"),
            "{37C34E0A-E245-48A4-B07C-78E2955A7E65}");
        var versionedRoot = serviceConfiguration.VersionedRoot;
        if (!files.DirectoryExists(versionedRoot))
            files.CreateDirectory(versionedRoot);
        security.PrepareStateRoot(
            versionedRoot,
            null,
            repairExistingChildren: true); files.WriteAtomic(
            Path.Combine(maintenanceStateRoot, "service-config.json"),
            JsonSerializer.SerializeToUtf8Bytes(
                serviceConfiguration,
                Json));
        security.PrepareStateRoot(
            maintenanceStateRoot, null,
            repairExistingChildren: true);
    }

    private void PreserveMaintenanceTrustFile(
        string source,
        string destination,
        Action<byte[]> validate,
        string mismatchMessage)
    {
        var value = files.ReadAllBytes(source);
        try
        {
            validate(value);
            if (files.FileExists(destination))
            {
                var existing = files.ReadAllBytes(destination);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(
                            existing,
                            value))
                        throw new InvalidOperationException(mismatchMessage);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(existing);
                }
            }
            else
            {
                files.WriteAtomic(destination, value);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
    private void RestoreMaintenanceState(
        ProvisionerOptions options,
        MaintenanceStateSnapshot snapshot)
    {
        var maintenanceStateRoot = options.EffectiveMaintenanceStateRoot;
        if (!snapshot.Existed)
        {
            files.DeleteDirectory(maintenanceStateRoot);
            return;
        }
        if (!files.DirectoryExists(maintenanceStateRoot))
            files.CreateDirectory(maintenanceStateRoot);
        RestoreMaintenanceFile(
            Path.Combine(maintenanceStateRoot, "service-config.json"),
            snapshot.Configuration);
        RestoreMaintenanceFile(
            Path.Combine(maintenanceStateRoot, "control-signing.spki"),
            snapshot.ControlSigningPublicKey);
        RestoreMaintenanceFile(
            Path.Combine(maintenanceStateRoot, "bootstrap-envelope.spki"),
            snapshot.BootstrapEncryptionPublicKey);
        security.PrepareStateRoot(
            maintenanceStateRoot, null,
            repairExistingChildren: true);
    }

    private void RestoreMaintenanceFile(
        string path,
        byte[]? priorContent)
    {
        if (priorContent is null)
        {
            if (File.Exists(path))
                File.Delete(path);
            return;
        }
        try
        {
            files.WriteAtomic(path, priorContent);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priorContent);
        }
    }

    private bool MaintenanceStateIsHealthy(
        ProvisionerOptions options,
        EndpointArtifactAttestation artifact,
        EndpointMachineIdentity identity,
        ProvisionedUser user)
    {
        var root = options.EffectiveMaintenanceStateRoot;
        var configurationPath = Path.Combine(root, "service-config.json");
        var controlPath = Path.Combine(root, "control-signing.spki");
        var bootstrapPath = Path.Combine(root, "bootstrap-envelope.spki");
        if (!files.DirectoryExists(root) ||
            !files.FileExists(configurationPath) ||
            !files.FileExists(controlPath) ||
            !files.FileExists(bootstrapPath))
            return false;
        try
        {
            var actual = JsonSerializer.Deserialize<
                EndpointMaintenanceConfiguration>(
                files.ReadAllText(configurationPath),
                Json);
            var expected = new EndpointMaintenanceConfiguration(
                1,
                "Steward.Maintenance.v1",
                user.Sid,
                user.Account,
                identity.ControlIdentity,
                $"Steward.Node.{identity.IncarnationId:N}",
                identity.HostId,
                artifact.ProductVersion,
                artifact.SourceRepository,
                artifact.SignerWorkflow,
                options.StateRoot,
                options.InstallRoot,
                Path.Combine(
                    Path.GetDirectoryName(root) ??
                        throw new InvalidDataException(
                            "Maintenance state root has no parent."),
                    "Versions"),
                "{37C34E0A-E245-48A4-B07C-78E2955A7E65}");
            var endpointControl = files.ReadAllBytes(Path.Combine(
                options.StateRoot,
                "keys",
                "control-signing.spki"));
            var maintenanceControl = files.ReadAllBytes(controlPath);
            var configuredBootstrap = files.ReadAllBytes(ResolveConfigFile(
                options.ConfigPath,
                JsonSerializer.Deserialize<EndpointProvisioningConfig>(
                    files.ReadAllText(options.ConfigPath),
                    Json)?.BootstrapEncryptionPublicKey ??
                throw new InvalidDataException(
                    "Provisioning config is invalid.")));
            var maintenanceBootstrap = files.ReadAllBytes(bootstrapPath);
            try
            {
                return actual == expected &&
                    CryptographicOperations.FixedTimeEquals(
                        endpointControl,
                        maintenanceControl) &&
                    CryptographicOperations.FixedTimeEquals(
                        configuredBootstrap,
                        maintenanceBootstrap);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(endpointControl);
                CryptographicOperations.ZeroMemory(maintenanceControl);
                CryptographicOperations.ZeroMemory(configuredBootstrap);
                CryptographicOperations.ZeroMemory(maintenanceBootstrap);
            }
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }
    private void WriteNodeConfig(
        string path,
        string stateRoot,
        EndpointMachineIdentity identity)
    {
        files.WriteAtomic(
            path,
            JsonSerializer.SerializeToUtf8Bytes(
                new
                {
                    journalPath = Path.Combine(stateRoot, "node.db"),
                    executionJournalPath =
                        Path.Combine(stateRoot, "execution.db"),
                    evaluationDatabasePath =
                        Path.Combine(stateRoot, "evaluation.db"),
                    workspaceRoot = Path.Combine(stateRoot, "workspaces"),
                    spoolRoot = Path.Combine(stateRoot, "spool"),
                    spoolHighLimitBytes = 4L * 1024 * 1024 * 1024,
                    spoolHardLimitBytes = 8L * 1024 * 1024 * 1024,
                    spoolOsReserveBytes = 2L * 1024 * 1024 * 1024,
                    keeperPipeName =
                        $"Steward.Node.{identity.IncarnationId:N}",
                    nodeIncarnationId = identity.IncarnationId,
                    hostId = identity.HostId,
                    terminalJournalPath =
                        Path.Combine(stateRoot, "terminal.db"),
                    maximumTerminalSessions = 32,
                    agentsEnabled = false,
                    agentExecutable = "",
                    agentRuntimeProfile = "process-jsonl/1.0"
                },
                Json));
    }

    private void ValidateConfig(
        EndpointProvisioningConfig config,
        EndpointArtifactAttestation artifact,
        ProvisionerOptions options)
    {
        if (config.Version != 1 ||
            string.IsNullOrWhiteSpace(config.ProductVersion) ||
            config.ProductVersion != artifact.ProductVersion ||
            string.IsNullOrWhiteSpace(config.BootstrapEncryptionPublicKey) ||
            string.IsNullOrWhiteSpace(config.ControlSigningPublicKey) ||
            string.IsNullOrWhiteSpace(config.ControlIdentity) ||
            (string.IsNullOrWhiteSpace(config.ProvisionedUserAccount) !=
             string.IsNullOrWhiteSpace(config.ProvisionedUserSid)) ||
            (config.ProvisionedUserAccount is { Length: > 0 } account &&
             (account.Length > 256 || account.Any(char.IsControl))) ||
            (config.ProvisionedUserSid is { Length: > 0 } sid &&
             (!sid.StartsWith("S-1-", StringComparison.Ordinal) ||
              sid.Length > 184)) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.RdpDvc.Server.Windows.dll")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.HandleKeeper.dll")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.RdpDvc.Server.Windows.deps.json")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.RdpDvc.Server.Windows.runtimeconfig.json")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.Maintenance.Windows.exe")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.Maintenance.Windows.dll")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.Maintenance.Windows.deps.json")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.Maintenance.Windows.runtimeconfig.json")) ||
            !File.Exists(Path.Combine(options.InstallRoot, "e_sqlite3.dll")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "endpoint-payload.hashes.json")))
            throw new InvalidDataException(
                "Endpoint provisioning inputs are invalid.");
        var bootstrap = ResolveConfigFile(
            options.ConfigPath,
            config.BootstrapEncryptionPublicKey);
        var control = ResolveConfigFile(
            options.ConfigPath,
            config.ControlSigningPublicKey);
        if (!string.Equals(
                config.ControlIdentity,
                artifact.ControlIdentity,
                StringComparison.Ordinal) ||
            !HashMatches(options.ConfigPath, artifact.ConfigSha256) ||
            !HashMatches(
                bootstrap,
                artifact.BootstrapEncryptionPublicKeySha256) ||
            !HashMatches(
                control,
                artifact.ControlSigningPublicKeySha256))
            throw new InvalidDataException(
                "Provisioning trust inputs do not match artifact attestation.");
    }

    private static void ValidateArtifact(
        EndpointArtifactAttestation artifact)
    {
        if (artifact.Version != 1 ||
            !Version.TryParse(artifact.ProductVersion, out _) ||
            artifact.MsiSha256.Length != 64 ||
            artifact.MsiSha256.Any(character =>
                !char.IsAsciiHexDigit(character)) ||
            string.IsNullOrWhiteSpace(artifact.SourceRepository) ||
            artifact.SourceCommit.Length != 40 ||
            artifact.SourceCommit.Any(character =>
                !char.IsAsciiHexDigit(character)) ||
            !artifact.SourceRef.StartsWith("refs/", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(artifact.SignerWorkflow) ||
            string.IsNullOrWhiteSpace(artifact.SourceRunId) ||
            !Guid.TryParse(artifact.ProductCode, out var productCode) ||
            productCode == Guid.Empty ||
            !ValidSha256(artifact.ConfigSha256) ||
            !ValidSha256(artifact.BootstrapEncryptionPublicKeySha256) ||
            !ValidSha256(artifact.ControlSigningPublicKeySha256) ||
            string.IsNullOrWhiteSpace(artifact.ControlIdentity))
            throw new InvalidDataException(
                "Artifact attestation is invalid.");
    }

    private bool HashMatches(string path, string expected) =>
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(expected),
            SHA256.HashData(files.ReadAllBytes(path)));

    private static bool ValidSha256(string value) =>
        value.Length == 64 &&
        value.All(char.IsAsciiHexDigit);

    private void ValidatePayload(
        string installRoot,
        string productVersion)
    {
        var manifestPath = Path.Combine(
            installRoot,
            "endpoint-payload.hashes.json");
        var manifest = JsonSerializer.Deserialize<EndpointPayloadManifest>(
                           File.ReadAllText(manifestPath),
                           Json)
                       ?? throw new InvalidDataException(
                           "Endpoint payload manifest is empty.");
        if (manifest.Version != 1 ||
            manifest.ProductVersion != productVersion ||
            manifest.Files.Count is 0 or > 512)
            throw new InvalidDataException(
                "Endpoint payload manifest is invalid.");
        var root = Path.GetFullPath(installRoot) +
            Path.DirectorySeparatorChar;
        var expected = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var file in manifest.Files)
        {
            if (string.IsNullOrWhiteSpace(file.RelativePath) ||
                Path.IsPathFullyQualified(file.RelativePath) ||
                file.RelativePath.Contains("..", StringComparison.Ordinal) ||
                file.Sha256.Length != 64 ||
                file.Sha256.Any(character =>
                    !char.IsAsciiHexDigit(character)))
                throw new InvalidDataException(
                    "Endpoint payload manifest entry is invalid.");
            var normalized = file.RelativePath.Replace(
                '/',
                Path.DirectorySeparatorChar);
            if (!expected.Add(normalized))
                throw new InvalidDataException(
                    "Endpoint payload manifest contains duplicate entries.");
            var path = Path.GetFullPath(
                Path.Combine(installRoot, normalized));
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(path) ||
                new FileInfo(path).Length != file.Length ||
                !CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(file.Sha256),
                    SHA256.HashData(File.ReadAllBytes(path))))
                throw new InvalidDataException(
                    "Endpoint payload validation failed.");
        }
        var actual = files.GetFiles(installRoot)
            .Select(path => Path.GetRelativePath(installRoot, path))
            .Where(path => !string.Equals(
                path,
                "endpoint-payload.hashes.json",
                StringComparison.OrdinalIgnoreCase))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!actual.SetEquals(expected))
            throw new InvalidDataException(
                "Endpoint payload does not exactly match its manifest.");
    }

    private static void ValidateControlPublicKey(byte[] value)
    {
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(value, out var read);
        if (read != value.Length)
            throw new CryptographicException(
                "Control signing key contains trailing data.");
    }

    private static string ResolveConfigFile(
        string configPath,
        string relative)
    {
        if (Path.IsPathFullyQualified(relative) ||
            relative.Contains("..", StringComparison.Ordinal))
            throw new InvalidDataException(
                "Provisioning config path is invalid.");
        var root = Path.GetDirectoryName(configPath)
            ?? throw new InvalidDataException(
                "Provisioning config has no directory.");
        var path = Path.GetFullPath(Path.Combine(root, relative));
        if (!path.StartsWith(
                Path.GetFullPath(root) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path))
            throw new InvalidDataException(
                "Provisioning config file is unavailable.");
        return path;
    }

    private bool TryLoadHealthyExisting(
        ProvisionerOptions options,
        EndpointProvisioningConfig config,
        EndpointArtifactAttestation artifact,
        out string receiptPath)
    {
        receiptPath = Path.Combine(
            options.StateRoot,
            "bootstrap-receipt.json");
        var identityPath = Path.Combine(options.StateRoot, "identity.json");
        if (!files.FileExists(identityPath) ||
            !files.FileExists(receiptPath))
            return false;
        var identity = LoadIdentity(identityPath);
        if (!string.Equals(
                identity.ProductVersion,
                artifact.ProductVersion,
                StringComparison.Ordinal) ||
            !RequiredStateFiles(options.StateRoot).All(files.FileExists))
            return false;
        var user = ResolveUser(config);
        if (!MaintenanceStateIsHealthy(
                options,
                artifact,
                identity,
                user))
            return false;
        if (!tasks.IsHealthy(
            options.InstallRoot,
            options.StateRoot,
            identity,
            config.ControlIdentity,
            user.Account,
            user.Sid))
            return false;
        try
        {
            ValidateReceipt(
                receiptPath,
                options.StateRoot,
                identity,
                artifact);
            return EndpointReadyHealth
                .IsKnownGood(options, identity);
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private void ValidateReceipt(
        string path,
        string stateRoot,
        EndpointMachineIdentity identity,
        EndpointArtifactAttestation artifact)
    {
        var body = LoadValidatedReceipt(path, stateRoot, identity);
        if (body.ProductVersion != artifact.ProductVersion ||
            !string.Equals(
                body.MsiSha256,
                artifact.MsiSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.SourceRepository,
                artifact.SourceRepository,
                StringComparison.Ordinal) ||
            !string.Equals(
                body.SourceCommit,
                artifact.SourceCommit,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.SourceRef,
                artifact.SourceRef,
                StringComparison.Ordinal) ||
            !string.Equals(
                body.SignerWorkflow,
                artifact.SignerWorkflow,
                StringComparison.Ordinal) ||
            !string.Equals(
                body.SourceRunId,
                artifact.SourceRunId,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.ProductCode,
                artifact.ProductCode,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.ConfigSha256,
                artifact.ConfigSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.BootstrapEncryptionPublicKeySha256,
                artifact.BootstrapEncryptionPublicKeySha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.ControlSigningPublicKeySha256,
                artifact.ControlSigningPublicKeySha256,
                StringComparison.OrdinalIgnoreCase) ||
            body.ControlIdentity != artifact.ControlIdentity)
            throw new InvalidDataException(
                "Existing endpoint receipt does not match current artifact.");
    }

    private EndpointProvisioningReceiptBody LoadValidatedReceipt(
        string path,
        string stateRoot,
        EndpointMachineIdentity identity)
    {
        var receipt = JsonSerializer.Deserialize<EndpointProvisioningReceipt>(
                          files.ReadAllText(path),
                          Json)
                      ?? throw new InvalidDataException(
                          "Existing endpoint receipt is invalid.");
        if (receipt.Body is null ||
            string.IsNullOrWhiteSpace(receipt.Signature))
            throw new InvalidDataException(
                "Existing endpoint receipt is incomplete.");
        var body = receipt.Body;
        if (body.Version != 2 ||
            string.IsNullOrWhiteSpace(body.ProductVersion) ||
            body.ControlIdentity != identity.ControlIdentity ||
            body.BootstrapOperationId != identity.BootstrapOperationId ||
            body.SessionId != identity.SessionId ||
            body.HostId != identity.HostId ||
            body.IncarnationId != identity.IncarnationId ||
            body.NodeIdentity != identity.NodeIdentity ||
            body.ReconnectLedger is not null &&
            (body.ReconnectLedger.Version != 2 ||
             body.ReconnectLedger.LedgerFile !=
                EndpointStateFiles.ReconnectLedgerV2 ||
             body.ReconnectLedger.HealthFile != EndpointStateFiles.V2Health) ||
            body.ReconnectLedger is null &&
            body.LegacyConnectionNonces is null)
            throw new InvalidDataException(
                "Existing endpoint receipt does not match current state.");
        var noncePath = Path.Combine(stateRoot, "nonce-sequence.json");
        if (body.LegacyConnectionNonces is not null)
        {
            var legacy = ReadLegacyNonceInventory(noncePath, identity)
                ?? throw new InvalidDataException(
                    "Existing v1 receipt has no nonce inventory.");
            if (!legacy.State.Nonces.SequenceEqual(
                    body.LegacyConnectionNonces))
                throw new InvalidDataException(
                    "Existing endpoint nonce state does not match the v1 receipt.");
        }
        if (body.V1Migration is not null)
        {
            var legacy = ReadLegacyNonceInventory(noncePath, identity)
                ?? throw new InvalidDataException(
                    "The v1 migration receipt has no nonce inventory.");
            var authorizationPath = Path.Combine(
                stateRoot,
                body.V1Migration.AuthorizationFile);
            if (body.V1Migration.Version != 1 ||
                !string.Equals(
                    body.V1Migration.RetainedEndpointVersion,
                    RetainedV1MigrationAuthorizationBody
                        .SupportedEndpointVersion,
                    StringComparison.Ordinal) ||
                body.V1Migration.AuthorizationFile !=
                    "retained-v1-migration.json" ||
                body.V1Migration.NonceCount != legacy.State.Nonces.Count ||
                body.V1Migration.NextIndex != legacy.State.NextIndex ||
                !string.Equals(
                    body.V1Migration.InventorySha256,
                    legacy.InventorySha256,
                    StringComparison.Ordinal) ||
                !files.FileExists(authorizationPath))
                throw new InvalidDataException(
                    "The v1 migration receipt does not match the retained inventory.");
            var authorizationBytes = files.ReadAllBytes(authorizationPath);
            try
            {
                if (!string.Equals(
                        body.V1Migration.AuthorizationSha256,
                        Convert.ToHexString(SHA256.HashData(
                            authorizationBytes)),
                        StringComparison.Ordinal))
                    throw new InvalidDataException(
                        "The v1 migration authorization digest is invalid.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(authorizationBytes);
            }
        }
        else if (body.LegacyConnectionNonces is null &&
                 files.FileExists(noncePath))
        {
            throw new InvalidDataException(
                "A retained v1 nonce inventory requires an explicit migration receipt.");
        }
        var privateBytes = files.ReadAllBytes(
            Path.Combine(stateRoot, "keys", "node-signing.pk8"));
        try
        {
            using var node = ECDsa.Create();
            node.ImportPkcs8PrivateKey(privateBytes, out var read);
            if (body.V1Migration is { } migration)
            {
                var nonceBytes = files.ReadAllBytes(Path.Combine(
                    stateRoot,
                    "nonce-sequence.json"));
                var authorizationBytes = files.ReadAllBytes(Path.Combine(
                    stateRoot,
                    migration.AuthorizationFile));
                try
                {
                    _ = RetainedV1MigrationAuthorizationCodec.Validate(
                        RetainedV1MigrationAuthorizationCodec.Decode(
                            authorizationBytes),
                        node,
                        nonceBytes,
                        identity.SessionId,
                        identity.HostId,
                        identity.IncarnationId,
                        migration.NonceCount,
                        migration.NextIndex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nonceBytes);
                    CryptographicOperations.ZeroMemory(authorizationBytes);
                }
            }
            if (read != privateBytes.Length ||
                !CryptographicOperations.FixedTimeEquals(
                    node.ExportSubjectPublicKeyInfo(),
                    Convert.FromBase64String(body.NodeSigningPublicKey)) ||
                !node.VerifyData(
                    JsonSerializer.SerializeToUtf8Bytes(body),
                    Convert.FromBase64String(receipt.Signature),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence))
                throw new InvalidDataException(
                    "Existing endpoint receipt signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateBytes);
        }
        return body;
    }

    private static IEnumerable<string> RequiredStateFiles(string root)
    {
        yield return Path.Combine(root, "keys", "rdp-dvc.key");
        yield return Path.Combine(root, "keys", "node-signing.pk8");
        yield return Path.Combine(root, "keys", "control-signing.spki");
        yield return Path.Combine(root, "node-host.json");
    }

    internal static void Run(string executable, params string[] arguments)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException(
                $"Unable to start {executable}.");
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"{executable} failed with exit code {process.ExitCode}.");
    }
}

internal sealed class PowerShellTaskRegistrar : IEndpointTaskRegistrar
{
    public ProvisionedUser ResolveUser()
    {
        var script =
            "$p=@(Get-CimInstance Win32_UserProfile|?{!$_.Special-and$_.Loaded-and($_.SID-like'S-1-12-1-*'-or$_.SID-like'S-1-5-21-*')});" +
            "if($p.Count-ne1){exit 2};$sid=$p[0].SID;" +
            "$a=(New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value;" +
            "[pscustomobject]@{account=$a;sid=$sid}|ConvertTo-Json -Compress";
        var output = RunPowerShell(script);
        return JsonSerializer.Deserialize<ProvisionedUser>(
                   output,
                   new JsonSerializerOptions(JsonSerializerDefaults.Web))
               ?? throw new InvalidDataException(
                   "Interactive user resolution failed.");
    }

    public EndpointTaskSnapshot Capture(EndpointMachineIdentity identity)
    {
        var script = $$"""
            $a=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'HandleKeeper-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            $b=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'RdpDvcEndpoint-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            [pscustomobject]@{
              keeperXml=if($null-ne$a){Export-ScheduledTask -TaskPath '\Steward\' -TaskName $a.TaskName}else{$null}
              keeperWasRunning=$null-ne$a-and$a.State-eq'Running'
              serverXml=if($null-ne$b){Export-ScheduledTask -TaskPath '\Steward\' -TaskName $b.TaskName}else{$null}
              serverWasRunning=$null-ne$b-and$b.State-eq'Running'
            }|ConvertTo-Json -Compress
            """;
        return JsonSerializer.Deserialize<EndpointTaskSnapshot>(
                   RunPowerShell(script),
                   new JsonSerializerOptions(JsonSerializerDefaults.Web))
               ?? throw new InvalidDataException(
                   "Endpoint task snapshot failed.");
    }

    public void Quiesce(EndpointMachineIdentity identity)
    {
        var script = $$"""
            $ErrorActionPreference='Stop'
            $keeperName='HandleKeeper-{{identity.HostId:N}}'
            $serverName='RdpDvcEndpoint-{{identity.HostId:N}}'
            $names=@($keeperName,$serverName)
            foreach($name in $names){
              $task=Get-ScheduledTask -TaskName $name -TaskPath '\Steward\' -ErrorAction SilentlyContinue
              if($null-ne$task){Disable-ScheduledTask -InputObject $task|Out-Null}
            }

            Stop-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            Stop-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            do {
              $running=@($names|Where-Object{
                (Get-ScheduledTask -TaskName $_ -TaskPath '\Steward\' -ErrorAction SilentlyContinue).State-eq'Running'
              }).Count
              if($running-gt0){Start-Sleep -Milliseconds 250}
            } until($running-eq0-or[DateTime]::UtcNow-ge$deadline)
            if($running-ne0){throw 'Endpoint tasks did not quiesce.'}
            """;
        RunPowerShell(script);
    }

    public void Restore(
        EndpointTaskSnapshot snapshot,
        EndpointMachineIdentity identity)
    {
        var keeperXml = snapshot.KeeperXml is null
            ? "$null"
            : "'" + Convert.ToBase64String(
                Encoding.UTF8.GetBytes(snapshot.KeeperXml)) + "'";
        var serverXml = snapshot.ServerXml is null
            ? "$null"
            : "'" + Convert.ToBase64String(
                Encoding.UTF8.GetBytes(snapshot.ServerXml)) + "'";
        var script = $$"""
            $ErrorActionPreference='Stop'
            $keeperName='HandleKeeper-{{identity.HostId:N}}'
            $serverName='RdpDvcEndpoint-{{identity.HostId:N}}'

            Stop-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            Stop-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
            $keeperData={{keeperXml}}
            $serverData={{serverXml}}
            if($null-ne$keeperData){
              $xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($keeperData))
              Register-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Xml $xml -Force|Out-Null
              if(${{snapshot.KeeperWasRunning.ToString().ToLowerInvariant()}}){Start-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\'}
            }
            if($null-ne$serverData){
              $xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($serverData))
              Register-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Xml $xml -Force|Out-Null
              if(${{snapshot.ServerWasRunning.ToString().ToLowerInvariant()}}){Start-ScheduledTask -TaskName $serverName -TaskPath '\Steward\'}
            }
            """;
        RunPowerShell(script);
    }

    public void Register(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string userAccount,
        string userSid,
        string controlIdentity)
    {
        var actions = BuildActions(
            installRoot,
            stateRoot,
            identity,
            userAccount,
            controlIdentity);
        var keeper = Path.Combine(installRoot, "Steward.HandleKeeper.exe");
        var server = Path.Combine(
            installRoot,
            "Steward.RdpDvc.Server.Windows.exe");
        var provisioner = Path.Combine(
            installRoot,
            "Steward.Endpoint.Provisioner.exe");
        var maintenanceRoot = Path.Combine(
            Path.GetDirectoryName(stateRoot) ??
                throw new InvalidDataException(
                    "Endpoint state root has no parent."),
            "Maintenance");
        if (!File.Exists(keeper) || !File.Exists(server) ||
            !File.Exists(provisioner))
            throw new FileNotFoundException(
                "Self-contained endpoint executables are unavailable.");
        var scriptPath = Path.Combine(
            installRoot,
            $".register-endpoint-{Guid.NewGuid():N}.ps1");
        var script = $$"""
            $ErrorActionPreference='Stop'
            $keeperName='HandleKeeper-{{identity.HostId:N}}'
            $serverName='RdpDvcEndpoint-{{identity.HostId:N}}'
            $handoffName='EndpointInstallerHandoff-{{identity.HostId:N}}'
            $keeperPrior=Get-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            $serverPrior=Get-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            $handoffPrior=Get-ScheduledTask -TaskName $handoffName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            $keeperXml=if($null-ne$keeperPrior){Export-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\'}else{$null}
            $serverXml=if($null-ne$serverPrior){Export-ScheduledTask -TaskName $serverName -TaskPath '\Steward\'}else{$null}
            $handoffXml=if($null-ne$handoffPrior){Export-ScheduledTask -TaskName $handoffName -TaskPath '\Steward\'}else{$null}
            Stop-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            Stop-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            $trigger=New-ScheduledTaskTrigger -AtLogOn -User '{{Escape(userAccount)}}'
            $principal=New-ScheduledTaskPrincipal -UserId '{{Escape(userAccount)}}' -LogonType Interactive -RunLevel Limited
            $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            $keeper=New-ScheduledTaskAction -Execute '{{Escape(actions.KeeperExecutable)}}' -Argument '{{Escape(actions.KeeperArguments)}}' -WorkingDirectory '{{Escape(installRoot)}}'
            $server=New-ScheduledTaskAction -Execute '{{Escape(actions.ServerExecutable)}}' -Argument '{{Escape(actions.ServerArguments)}}' -WorkingDirectory '{{Escape(installRoot)}}'
            $handoff=New-ScheduledTaskAction -Execute '{{Escape(provisioner)}}' -Argument '--execute-update-handoff --maintenance-state-root "{{Escape(maintenanceRoot)}}"' -WorkingDirectory '{{Escape(installRoot)}}'
            $handoffPrincipal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $handoffSettings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            function Add-RemoteConnectTrigger([string]$taskName) {
              [xml]$xml=Export-ScheduledTask -TaskName $taskName -TaskPath '\Steward\'
              $namespace=$xml.Task.NamespaceURI
              $reconnect=$xml.CreateElement('SessionStateChangeTrigger',$namespace)
              foreach($entry in @(
                @('Enabled','true'),
                @('StateChange','RemoteConnect'),
                @('UserId','{{Escape(userAccount)}}'))) {
                $element=$xml.CreateElement($entry[0],$namespace)
                $element.InnerText=$entry[1]
                [void]$reconnect.AppendChild($element)
              }
              [void]$xml.Task.Triggers.AppendChild($reconnect)
              Register-ScheduledTask -TaskName $taskName -TaskPath '\Steward\' -Xml $xml.OuterXml -Force|Out-Null
            }
            try {
              Register-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Action $keeper -Trigger $trigger -Principal $principal -Settings $settings -Force|Out-Null
              Add-RemoteConnectTrigger $keeperName
              Register-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Action $server -Trigger $trigger -Principal $principal -Settings $settings -Force|Out-Null
              Add-RemoteConnectTrigger $serverName
              Register-ScheduledTask -TaskName $handoffName -TaskPath '\Steward\' -Action $handoff -Principal $handoffPrincipal -Settings $handoffSettings -Force|Out-Null
            } catch {
              Unregister-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
              Unregister-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
              Unregister-ScheduledTask -TaskName $handoffName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
              if($null-ne$keeperXml){Register-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Xml $keeperXml -Force|Out-Null}
              if($null-ne$serverXml){Register-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Xml $serverXml -Force|Out-Null}
              if($null-ne$handoffXml){Register-ScheduledTask -TaskName $handoffName -TaskPath '\Steward\' -Xml $handoffXml -Force|Out-Null}
              throw
            }
            """;
        File.WriteAllText(
            scriptPath,
            script,
            new UTF8Encoding(false));
        try
        {
            RunPowerShellFile(scriptPath);
            if (HasActiveRemoteSession(userSid))
            {
                RunPowerShell(
                    $$"""
                    $ErrorActionPreference='Stop'
                    Start-ScheduledTask -TaskName 'HandleKeeper-{{identity.HostId:N}}' -TaskPath '\Steward\'
                    Start-Sleep -Milliseconds 500
                    Start-ScheduledTask -TaskName 'RdpDvcEndpoint-{{identity.HostId:N}}' -TaskPath '\Steward\'
                    """);
            }
        }
        finally
        {
            File.Delete(scriptPath);
        }
    }

    public bool IsHealthy(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string controlIdentity,
        string userAccount,
        string userSid)
    {
        var expected = BuildActions(
            installRoot,
            stateRoot,
            identity,
            userAccount,
            controlIdentity);
        var handoffProvisioner = Path.Combine(
            installRoot,
            "Steward.Endpoint.Provisioner.exe");
        var maintenanceRoot = Path.Combine(
            Path.GetDirectoryName(stateRoot) ??
                throw new InvalidDataException(
                    "Endpoint state root has no parent."),
            "Maintenance");
        var handoffArguments =
            "--execute-update-handoff --maintenance-state-root \"" +
            maintenanceRoot + "\"";
        var script = $$"""
            $a=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'HandleKeeper-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            $b=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'RdpDvcEndpoint-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            $h=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'EndpointInstallerHandoff-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            $m=Get-CimInstance Win32_Service -Filter "Name='StewardMaintenance'" -ErrorAction SilentlyContinue
            $aUserSid=if($null-ne$a-and![string]::IsNullOrWhiteSpace($a.Principal.UserId)){
              try{([Security.Principal.NTAccount]$a.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value}catch{$null}
            }else{$null}
            $bUserSid=if($null-ne$b-and![string]::IsNullOrWhiteSpace($b.Principal.UserId)){
              try{([Security.Principal.NTAccount]$b.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value}catch{$null}
            }else{$null}
            $canonical=@($a,$b).Where({
              if($null-eq$_-or$_.Triggers.Count-ne2-or
                $null-eq$_.Settings-or
                $null-eq$_.Settings.IdleSettings-or
                $null-eq$_.Settings.NetworkSettings){return $false}
              $settings=$_.Settings
              $settings.AllowDemandStart-and
              $settings.AllowHardTerminate-and
              $settings.Compatibility-eq'Win7'-and
              [string]::IsNullOrEmpty($settings.DeleteExpiredTaskAfter)-and
              $settings.Priority-eq7-and
              $settings.RestartCount-eq999-and
              $settings.RestartInterval-eq'PT1M'-and
              !$settings.RunOnlyIfIdle-and
              !$settings.RunOnlyIfNetworkAvailable-and
              !$settings.WakeToRun-and
              !$settings.DisallowStartOnRemoteAppSession-and
              $settings.UseUnifiedSchedulingEngine-and
              !$settings.Volatile-and
              $settings.IdleSettings.IdleDuration-eq'PT10M'-and
              !$settings.IdleSettings.RestartOnIdle-and
              $settings.IdleSettings.StopOnIdleEnd-and
              $settings.IdleSettings.WaitTimeout-eq'PT1H'-and
              [string]::IsNullOrEmpty($settings.NetworkSettings.Id)-and
              [string]::IsNullOrEmpty($settings.NetworkSettings.Name)-and
              $null-eq$settings.MaintenanceSettings
            }).Count-eq2
            $aTriggers=if($null-ne$a){@($a.Triggers)}else{@()}
            $bTriggers=if($null-ne$b){@($b.Triggers)}else{@()}
            $aLogon=@($aTriggers.Where({
              $_.CimClass.CimClassName-eq'MSFT_TaskLogonTrigger'
            }))
            $bLogon=@($bTriggers.Where({
              $_.CimClass.CimClassName-eq'MSFT_TaskLogonTrigger'
            }))
            $aReconnect=@($aTriggers.Where({
              $_.CimClass.CimClassName-eq'MSFT_TaskSessionStateChangeTrigger'
            }))
            $bReconnect=@($bTriggers.Where({
              $_.CimClass.CimClassName-eq'MSFT_TaskSessionStateChangeTrigger'
            }))
            $triggerDefaults=@(
              $aLogon+$bLogon+$aReconnect+$bReconnect
            ).Where({
              [string]::IsNullOrEmpty($_.Delay)-and
              [string]::IsNullOrEmpty($_.EndBoundary)-and
              [string]::IsNullOrEmpty($_.ExecutionTimeLimit)-and
              [string]::IsNullOrEmpty($_.Id)-and
              [string]::IsNullOrEmpty($_.StartBoundary)-and
              ($null-eq$_.Repetition-or(
                [string]::IsNullOrEmpty($_.Repetition.Duration)-and
                [string]::IsNullOrEmpty($_.Repetition.Interval)-and
                !$_.Repetition.StopAtDurationEnd))
            }).Count-eq4
                        $ok=$null-ne$a-and$null-ne$b-and$null-ne$h-and$null-ne$m-and
              $h.Actions.Count-eq1-and
              $h.Actions[0].Execute-eq'{{Escape(handoffProvisioner)}}'-and
              $h.Actions[0].Arguments-eq'{{Escape(handoffArguments)}}'-and
              $h.Actions[0].WorkingDirectory-eq'{{Escape(installRoot)}}'-and
              $h.Principal.UserId-eq'SYSTEM'-and
              $h.Principal.LogonType-eq'ServiceAccount'-and
              $h.Principal.RunLevel-eq'Highest'-and
              $h.Triggers.Count-eq0-and
              $m.StartName-eq'LocalSystem'-and
              $m.StartMode-eq'Auto'-and
              $m.State-eq'Running'-and
              $canonical-and$triggerDefaults-and
              $a.Actions.Count-eq1-and$b.Actions.Count-eq1-and
              $a.Actions[0].Execute-eq'{{Escape(expected.KeeperExecutable)}}'-and
              $a.Actions[0].Arguments-eq'{{Escape(expected.KeeperArguments)}}'-and
              $a.Actions[0].WorkingDirectory-eq'{{Escape(installRoot)}}'-and
              $b.Actions[0].Execute-eq'{{Escape(expected.ServerExecutable)}}'-and
              $b.Actions[0].Arguments-eq'{{Escape(expected.ServerArguments)}}'-and
              $b.Actions[0].WorkingDirectory-eq'{{Escape(installRoot)}}'-and
              $aUserSid-eq'{{Escape(userSid)}}'-and
              $bUserSid-eq'{{Escape(userSid)}}'-and
              $a.Principal.LogonType-eq'Interactive'-and
              $b.Principal.LogonType-eq'Interactive'-and
              $a.Principal.RunLevel-eq'Limited'-and
              $b.Principal.RunLevel-eq'Limited'-and
              $a.Principal.ProcessTokenSidType-eq'Default'-and
              $b.Principal.ProcessTokenSidType-eq'Default'-and
              [string]::IsNullOrEmpty(($a.Principal.RequiredPrivilege-join''))-and
              [string]::IsNullOrEmpty(($b.Principal.RequiredPrivilege-join''))-and
              [string]::IsNullOrEmpty($a.Principal.DisplayName)-and
              [string]::IsNullOrEmpty($b.Principal.DisplayName)-and
              $a.Principal.Id-eq'Author'-and
              $b.Principal.Id-eq'Author'-and
              $aLogon.Count-eq1-and$bLogon.Count-eq1-and
              $aReconnect.Count-eq1-and$bReconnect.Count-eq1-and
              $aLogon[0].UserId-eq'{{Escape(userAccount)}}'-and
              $bLogon[0].UserId-eq'{{Escape(userAccount)}}'-and
              $aLogon[0].Enabled-and$bLogon[0].Enabled-and
              $aReconnect[0].UserId-eq'{{Escape(userAccount)}}'-and
              $bReconnect[0].UserId-eq'{{Escape(userAccount)}}'-and
              $aReconnect[0].StateChange-eq3-and
              $bReconnect[0].StateChange-eq3-and
              $aReconnect[0].Enabled-and$bReconnect[0].Enabled-and
              $a.Settings.Enabled-and$b.Settings.Enabled-and
              $a.Settings.Hidden-and$b.Settings.Hidden-and
              $a.Settings.StartWhenAvailable-and
              $b.Settings.StartWhenAvailable-and
              !$a.Settings.DisallowStartIfOnBatteries-and
              !$b.Settings.DisallowStartIfOnBatteries-and
              !$a.Settings.StopIfGoingOnBatteries-and
              !$b.Settings.StopIfGoingOnBatteries-and
              $a.Settings.ExecutionTimeLimit-eq'PT0S'-and
              $b.Settings.ExecutionTimeLimit-eq'PT0S'-and
              $a.Settings.MultipleInstances-eq'IgnoreNew'-and
              $b.Settings.MultipleInstances-eq'IgnoreNew'
            $ok=$ok-and$a.State-in@('Ready','Running')-and
              $b.State-in@('Ready','Running')
            if($ok){'true'}else{'false'}
            """;
        return bool.TryParse(RunPowerShell(script), out var healthy) &&
            healthy;
    }

    private static EndpointActions BuildActions(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string userAccount,
        string controlIdentity)
    {
        var keys = Path.Combine(stateRoot, "keys");
        return new(
            Path.Combine(installRoot, "Steward.HandleKeeper.exe"),
            $"--console --pipe \"Steward.Node.{identity.IncarnationId:N}\" " +
            $"--node-account \"{userAccount}\" " +
            $"--fence-state-file \"{Path.Combine(stateRoot, "handlekeeper-fence.journal")}\" " +
            $"--fence-key-file \"{Path.Combine(keys, "rdp-dvc.key")}\" " +
            $"--maintenance-image \"{Path.Combine(installRoot, "Steward.Maintenance.Windows.exe")}\" " +
            $"--provisioner-image \"{Path.Combine(installRoot, "Steward.Endpoint.Provisioner.exe")}\"",
            Path.Combine(
                installRoot,
                "Steward.RdpDvc.Server.Windows.exe"),
            $"--session-id {identity.SessionId:D} " +
            $"--host-id {identity.HostId:D} --incarnation-id {identity.IncarnationId:D} " +
            $"--auth-key-file \"{Path.Combine(keys, "rdp-dvc.key")}\" " +
            $"--reconnect-ledger-file \"{Path.Combine(stateRoot, EndpointStateFiles.ReconnectLedgerV2)}\" " +
            $"--readiness-receipt-file \"{Path.Combine(stateRoot, EndpointStateFiles.V2Health)}\" " +
            $"--node-host-config \"{Path.Combine(stateRoot, "node-host.json")}\" " +
            $"--portable-state-root \"{Path.Combine(stateRoot, "portable")}\" " +
            $"--credential-vault-root \"{Path.Combine(stateRoot, "credentials")}\" " +
            $"--node-signing-key-file \"{Path.Combine(keys, "node-signing.pk8")}\" " +
            $"--node-identity \"{identity.NodeIdentity}\" " +
            $"--control-signing-key-file \"{Path.Combine(keys, "control-signing.spki")}\" " +
            $"--control-identity \"{controlIdentity}\"");
    }

    private static bool HasActiveRemoteSession(string userSid)
    {
        if (!Native.WTSEnumerateSessions(
                IntPtr.Zero,
                0,
                1,
                out var sessions,
                out var count))
            throw new InvalidOperationException(
                "Active RDP session enumeration failed.");
        try
        {
            var size = Marshal.SizeOf<Native.WtsSessionInfo>();
            for (var index = 0; index < count; index++)
            {
                var session = Marshal.PtrToStructure<Native.WtsSessionInfo>(
                    IntPtr.Add(sessions, index * size));
                if (session.SessionId == 0 ||
                    session.State != Native.WtsConnectState.Active ||
                    QueryProtocol(session.SessionId) != 2 ||
                    !Native.WTSQueryUserToken(
                        (uint)session.SessionId,
                        out var token))
                    continue;
                try
                {
                    using var identity = new WindowsIdentity(token);
                    if (string.Equals(
                            identity.User?.Value,
                            userSid,
                            StringComparison.Ordinal))
                        return true;
                }
                finally
                {
                    Native.CloseHandle(token);
                }
            }
            return false;
        }
        finally
        {
            Native.WTSFreeMemory(sessions);
        }
    }

    private static ushort QueryProtocol(int sessionId)
    {
        if (!Native.WTSQuerySessionInformation(
                IntPtr.Zero,
                (uint)sessionId,
                Native.WtsInfoClass.ClientProtocolType,
                out var buffer,
                out var bytes))
            throw new InvalidOperationException(
                "Active RDP session protocol query failed.");
        try
        {
            if (bytes < sizeof(ushort))
                throw new InvalidDataException(
                    "Active RDP session protocol is invalid.");
            return unchecked((ushort)Marshal.ReadInt16(buffer));
        }
        finally
        {
            Native.WTSFreeMemory(buffer);
        }
    }

    private static class Native
    {
        internal enum WtsConnectState
        {
            Active = 0
        }

        internal enum WtsInfoClass
        {
            ClientProtocolType = 16
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WtsSessionInfo
        {
            internal int SessionId;
            internal nint StationName;
            internal WtsConnectState State;
        }

        [DllImport(
            "Wtsapi32.dll",
            EntryPoint = "WTSEnumerateSessionsW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSEnumerateSessions(
            nint server,
            int reserved,
            int version,
            out nint sessionInfo,
            out int count);

        [DllImport(
            "Wtsapi32.dll",
            EntryPoint = "WTSQuerySessionInformationW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSQuerySessionInformation(
            nint server,
            uint sessionId,
            WtsInfoClass infoClass,
            out nint buffer,
            out uint bytesReturned);

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSQueryUserToken(
            uint sessionId,
            out nint token);

        [DllImport("Wtsapi32.dll")]
        internal static extern void WTSFreeMemory(nint memory);

        [DllImport("Kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(nint handle);
    }

    private static string Escape(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static string RunPowerShell(string script)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"steward-provision-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(path, script, new UTF8Encoding(false));
        try
        {
            return RunPowerShellFile(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    internal sealed record EndpointActions(
        string KeeperExecutable,
        string KeeperArguments,
        string ServerExecutable,
        string ServerArguments);

    private static string RunPowerShellFile(string path)
    {
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.SystemDirectory,
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in new[]
                 {
                     "-NoProfile",
                     "-NonInteractive",
                     "-ExecutionPolicy",
                     "Bypass",
                     "-File",
                     path
                 })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException(
                "Unable to start Windows PowerShell.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                "Endpoint task registration failed: " +
                error.Trim()[..Math.Min(error.Trim().Length, 2_000)]);
        return output.Trim();
    }
}







