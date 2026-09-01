using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Runtime.Windows;

namespace Steward.Maintenance.Windows;

internal sealed record EndpointProcessEvidence(
    int ProcessId,
    int WtsSessionId,
    DateTimeOffset StartedAtUtc,
    bool IsRunning);

internal interface IEndpointProcessEvidenceSource
{
    EndpointProcessEvidence Observe(int processId);
}

internal sealed class WindowsEndpointProcessEvidenceSource :
    IEndpointProcessEvidenceSource
{
    public EndpointProcessEvidence Observe(int processId)
    {
        if (processId <= 0)
            throw new ArgumentOutOfRangeException(nameof(processId));
        using var process = Process.GetProcessById(processId);
        var running = !process.HasExited;
        return new EndpointProcessEvidence(
            processId,
            process.SessionId,
            process.StartTime.ToUniversalTime(),
            running);
    }
}

internal static class EndpointUpdateHealthGate
{
    internal static EndpointHealthObservation Evaluate(
        AuthenticatedEndpointV2Health authenticated,
        ReadOnlySpan<byte> authenticationKey,
        Guid expectedSessionId,
        Guid expectedHostId,
        Guid expectedNodeIncarnationId,
        string expectedNodeIdentity,
        string expectedControlIdentity,
        ulong generationHighWater,
        DateTimeOffset nowUtc,
        TimeSpan maximumAge,
        IEndpointProcessEvidenceSource processEvidence)
    {
        if (maximumAge < TimeSpan.FromSeconds(5) ||
            maximumAge > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(maximumAge));
        ArgumentNullException.ThrowIfNull(processEvidence);
        EndpointV2Health health;
        try
        {
            health = EndpointV2HealthAuthenticator.Verify(
                authenticated,
                authenticationKey);
        }
        catch (Exception exception) when (exception is
            InvalidDataException or ArgumentException)
        {
            return new EndpointHealthObservation(
                EndpointHealthStatus.Unhealthy,
                "v2-health-authentication-invalid");
        }
        if (health.SessionId != expectedSessionId ||
            health.HostId != expectedHostId ||
            health.NodeIncarnationId != expectedNodeIncarnationId ||
            !string.Equals(health.NodeIdentity, expectedNodeIdentity,
                StringComparison.Ordinal) ||
            !string.Equals(health.ControlIdentity, expectedControlIdentity,
                StringComparison.Ordinal))
            return new EndpointHealthObservation(
                EndpointHealthStatus.IdentityMismatch,
                "v2-health-identity-mismatch");
        if (health.UpdatedAtUtc < nowUtc - maximumAge ||
            health.UpdatedAtUtc > nowUtc + TimeSpan.FromSeconds(5) ||
            health.State != EndpointV2HealthState.Authenticated ||
            health.ReconnectGeneration <= 0 ||
            checked((ulong)health.ReconnectGeneration) <=
                generationHighWater)
            return new EndpointHealthObservation(
                EndpointHealthStatus.ControlUnavailable,
                "fresh-v2-authentication-pending");
        EndpointProcessEvidence process;
        try
        {
            process = processEvidence.Observe(health.ProcessId);
        }
        catch (Exception exception) when (exception is
            ArgumentException or InvalidOperationException or
            System.ComponentModel.Win32Exception)
        {
            return new EndpointHealthObservation(
                EndpointHealthStatus.Unhealthy,
                "v2-health-process-unavailable");
        }
        if (!process.IsRunning ||
            process.ProcessId != health.ProcessId ||
            process.WtsSessionId != health.WtsSessionId ||
            process.StartedAtUtc != health.ProcessStartedAtUtc)
            return new EndpointHealthObservation(
                EndpointHealthStatus.Unhealthy,
                "v2-health-process-session-mismatch");
        return new EndpointHealthObservation(
            EndpointHealthStatus.Healthy,
            "fresh-v2-control-authenticated");
    }
}
internal sealed partial class WindowsMaintenanceOperationExecutor
{
    Task<EndpointPreservationSnapshot>
        IEndpointUpdatePlatform.CapturePreservedStateAsync(
            Guid transactionId,
            ActivateEndpointUpdateOperation operation,
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = operation;
        if (transactionId == Guid.Empty)
            throw new ArgumentException(
                "Endpoint update transaction identity is required.",
                nameof(transactionId));
        var identity = ReadEndpointIdentity();
        EndpointUpdateFileValidator.EnsureRegularFile(Path.Combine(
            configuration.EndpointStateRoot,
            EndpointStateFiles.ReconnectLedgerV2));
        EndpointUpdateFileValidator.EnsureRegularFile(Path.Combine(
            configuration.EndpointStateRoot,
            EndpointStateFiles.V2Health));
        var backupRoot = Path.Combine(
            stateRoot,
            "preservation",
            transactionId.ToString("N"));
        if (Directory.Exists(backupRoot))
        {
            MaintenanceStateSecurity.ValidatePath(backupRoot);
            Directory.Delete(backupRoot, recursive: true);
        }
        Directory.CreateDirectory(backupRoot);
        MaintenanceStateSecurity.Protect(backupRoot);
        var databases = new List<EndpointSqliteSnapshot>();
        foreach (var name in new[]
                 {
                     "node.db",
                     "execution.db",
                     "terminal.db",
                     "evaluation.db"
                 })
        {
            var source = Path.Combine(
                configuration.EndpointStateRoot,
                name);
            if (File.Exists(source))
                databases.Add(EndpointSqlitePreservation.Capture(
                    source,
                    Path.Combine(backupRoot, name)));
        }
        string DatabaseHash(string name) =>
            databases.SingleOrDefault(value =>
                string.Equals(
                    Path.GetFileName(value.BackupPath),
                    name,
                    StringComparison.Ordinal))?.Tables.Count > 0
                ? HashDatabase(databases.Single(value =>
                    string.Equals(
                        Path.GetFileName(value.BackupPath),
                        name,
                        StringComparison.Ordinal)))
                : new string('0', 64);
        var snapshot = new EndpointPreservationSnapshot(
            identity.HostId,
            identity.IncarnationId,
            HashRequired(Path.Combine(
                configuration.EndpointStateRoot,
                "keys",
                "node-signing.pk8")),
            HashRequired(Path.Combine(
                configuration.EndpointStateRoot,
                "keys",
                "control-signing.spki")),
            HashRequired(Path.Combine(stateRoot, "control-signing.spki")),
            DatabaseHash("node.db"),
            DatabaseHash("execution.db"),
            EndpointPreservationInspector.HashTree(Path.Combine(
                configuration.EndpointStateRoot,
                "workspaces")),
            EndpointPreservationInspector.HashTree(Path.Combine(
                configuration.EndpointStateRoot,
                "spool")),
            HashRequired(Path.Combine(
                configuration.EndpointStateRoot,
                "bootstrap-receipt.json")),
            DatabaseHash("terminal.db"),
            DatabaseHash("evaluation.db"),
            ReadReconnectGeneration(),
            ReadCommittedUpdateSequence(),
            ReadApplicationCursor(),
            ScheduledTaskSemantics())
        {
            SessionId = identity.SessionId,
            NodeIdentity = identity.NodeIdentity,
            ControlIdentity = identity.ControlIdentity,
            PortableTreeSha256 = EndpointPreservationInspector.HashTree(
                Path.Combine(
                    configuration.EndpointStateRoot,
                    "portable")),
            BackupRoot = backupRoot,
            SqliteDatabases = databases
        };
        return Task.FromResult(snapshot);
    }

    async Task<VerifiedEndpointRelease>
        IEndpointUpdatePlatform.VerifyReleaseAsync(
            ActivateEndpointUpdateOperation operation,
            CancellationToken cancellationToken)
    {
        if (!string.Equals(operation.Provenance.SourceRepository,
                configuration.ApprovedSourceRepository, StringComparison.Ordinal) ||
            !string.Equals(operation.Provenance.SignerWorkflow,
                configuration.ApprovedSignerWorkflow, StringComparison.Ordinal) ||
            operation.Release.UpgradeCode != Guid.Parse(configuration.EndpointUpgradeCode))
            throw new EndpointUpdateException(
                "provenance_mismatch",
                "Endpoint update provenance does not match machine policy.");

        var package = await DownloadAsync(operation.Package,
                $"endpoint-{operation.Release.MsiSha256}.msi", cancellationToken)
            .ConfigureAwait(false);
        var manifest = await DownloadAsync(operation.ReleaseManifest,
                $"endpoint-{operation.ReleaseManifest.Sha256}.release.psd1", cancellationToken)
            .ConfigureAwait(false);
        var bundle = await DownloadAsync(operation.AttestationBundle,
                $"endpoint-{operation.AttestationBundle.Sha256}.sigstore.json", cancellationToken)
            .ConfigureAwait(false);
        await VerifyGitHubAttestationAsync(package, bundle, operation.Provenance, cancellationToken)
            .ConfigureAwait(false);
        await VerifyGitHubAttestationAsync(manifest, bundle, operation.Provenance, cancellationToken)
            .ConfigureAwait(false);
        var signedManifest = EndpointReleaseManifestParser.Parse(manifest);
        EndpointReleaseManifestParser.ValidateBinding(signedManifest, operation);
        var metadata = MsiMetadata.Read(package);
        if (!string.Equals(metadata.ProductVersion, operation.ProductVersion, StringComparison.Ordinal) ||
            !Guid.TryParse(metadata.ProductCode, out var productCode) ||
            productCode != operation.Release.ProductCode ||
            !Guid.TryParse(metadata.UpgradeCode, out var upgradeCode) ||
            upgradeCode != operation.Release.UpgradeCode)
            throw new EndpointUpdateException(
                "corrupt_msi",
                "Verified endpoint MSI identity does not match its release.");
        return new VerifiedEndpointRelease(operation.Release, manifest, package, bundle);
    }

    async Task<StagedEndpointRelease>
        IEndpointUpdatePlatform.StageImmutableAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var verified = transaction.VerifiedRelease ??
            throw new InvalidOperationException("Verified endpoint release is unavailable.");
        MaintenanceStateSecurity.Protect(configuration.VersionedRoot);
        var releaseRoot = Path.Combine(configuration.VersionedRoot,
            "release-" + transaction.Operation.ProductVersion + "-" +
            transaction.Operation.Release.MsiSha256[..16].ToLowerInvariant());
        Directory.CreateDirectory(releaseRoot);
        MaintenanceStateSecurity.Protect(releaseRoot);
        var package = await CopyImmutableAsync(verified.PackagePath,
                Path.Combine(releaseRoot, "Steward.Endpoint.Msi.msi"),
                transaction.Operation.Package, cancellationToken).ConfigureAwait(false);
        var manifest = await CopyImmutableAsync(verified.ManifestPath,
                Path.Combine(releaseRoot, "steward-endpoint.release.psd1"),
                transaction.Operation.ReleaseManifest, cancellationToken).ConfigureAwait(false);
        var bundle = await CopyImmutableAsync(verified.AttestationPath,
                Path.Combine(releaseRoot, "Steward.Endpoint.Msi.sigstore.json"),
                transaction.Operation.AttestationBundle, cancellationToken).ConfigureAwait(false);
        CachePriorKnownGood(transaction.PriorVersion);
        EndpointUpdateFileValidator.ValidateTree(releaseRoot, requireTrustedAcl: true);
        var treeHash = HashStagedFiles(releaseRoot, package, manifest, bundle);
        return new StagedEndpointRelease(transaction.Operation.Release, releaseRoot,
            package, manifest, bundle, treeHash);
    }

    async Task IEndpointUpdatePlatform.ExpandCompatibilityAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var marker = new EndpointMigrationWindow(1, transaction.TransactionId,
            transaction.UpdateSequence, transaction.PriorVersion,
            transaction.Operation.ProductVersion, EndpointMigrationWindowState.Expanded);
        await WriteAtomicAsync(Path.Combine(stateRoot, "migration-window.json"),
            JsonSerializer.SerializeToUtf8Bytes(marker), cancellationToken).ConfigureAwait(false);
    }

    async Task IEndpointUpdatePlatform.PersistInstallerHandoffAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var staged = RequireImmutableStage(transaction);
        var metadata = MsiMetadata.Read(staged.PackagePath);
        _ = await WriteUpdateProvisioningAsync(
                transaction.Operation,
                metadata,
                cancellationToken)
            .ConfigureAwait(false);
        var provisioner = Path.Combine(
            configuration.InstallRoot,
            "Steward.Endpoint.Provisioner.exe");
        EndpointUpdateFileValidator.EnsureRegularFile(provisioner);
        var handoff = new EndpointInstallerHandoffIntent(
            1,
            transaction.TransactionId,
            transaction.UpdateSequence,
            EndpointOwnerCapability.Derive(
                machineAuthenticationKey,
                transaction.TransactionId),
            transaction.Operation.ProductVersion,
            transaction.Operation.Release.MsiSha256,
            transaction.Operation.Release.MsiLength,
            transaction.Operation.Release.ProductCode,
            transaction.Operation.Release.UpgradeCode,
            Path.GetFileName(staged.VersionRoot),
            FileSha256(provisioner),
            EndpointInstallerHandoffAction.InstallEndpoint);
        var store = InstallerHandoffStore();
        var handoffRoot = InstallerHandoffRoot();
        if (store.Current is { } prior && prior.Intent != handoff &&
            prior.Phase is EndpointInstallerHandoffPhase.Committed or
                EndpointInstallerHandoffPhase.RolledBack)
        {
            foreach (var completedFile in new[]
                     {
                         Path.Combine(handoffRoot, "receipt.json"),
                         Path.Combine(
                             stateRoot,
                             "installer-handoff",
                             "execution.json")
                     })
                if (File.Exists(completedFile))
                    File.Delete(completedFile);
        }
        var prepared = store.Prepare(handoff);
        Directory.CreateDirectory(handoffRoot);
        MaintenanceStateSecurity.Protect(handoffRoot);
        await WriteAtomicAsync(
                Path.Combine(handoffRoot, "intent.json"),
                JsonSerializer.SerializeToUtf8Bytes(prepared.Intent),
                cancellationToken)
            .ConfigureAwait(false);
    }

    async Task IEndpointUpdatePlatform.TriggerInstallerHandoffAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var store = InstallerHandoffStore();
        var current = store.Current ?? throw new InvalidDataException(
            "Installer handoff intent is unavailable.");
        if (current.Intent.TransactionId != transaction.TransactionId)
            throw new EndpointUpdateException(
                "installer_handoff_owner",
                "Installer handoff belongs to another update transaction.");
        if (current.Phase == EndpointInstallerHandoffPhase.IntentCommitted)
        {
            var receiptPath = Path.Combine(
                InstallerHandoffRoot(),
                "receipt.json");
            if (File.Exists(receiptPath))
            {
                _ = store.MarkTriggered(
                    transaction.TransactionId,
                    current.Intent.OwnerCapability,
                    current.Generation);
                return;
            }
            using (var keeper = new NamedPipeJobHandleKeeper(new(
                       configuration.KeeperPipeName,
                       TimeSpan.FromSeconds(3),
                       ConnectAttempts: 2)))
            {
                var fence = keeper.FenceStatus();
                if (fence.Phase == JobKeeperFencePhase.Unfenced)
                    throw new EndpointUpdateException(
                        "installer_handoff_fence_missing",
                        "Installer handoff requires durable HandleKeeper ownership.");
                var maintenanceCapability =
                    NamedPipeHandleKeeperDrainFence.CreateCapability(
                        machineAuthenticationKey,
                        transaction.TransactionId);
                var lease = new JobKeeperFenceLease(
                    transaction.TransactionId,
                    transaction.TransactionId,
                    maintenanceCapability,
                    fence.Generation,
                    fence.Depth,
                    fence.Phase);
                _ = keeper.TransferDrainFence(
                    lease,
                    new JobKeeperFenceCapability(
                        current.Intent.OwnerCapability.Encoded),
                    current.Intent.ProvisionerSha256);
            }
            var trigger = await RunAsync(
                    MaintenanceTool.TaskScheduler,
                    [
                        "/Run",
                        "/TN",
                        $@"\Steward\EndpointInstallerHandoff-" +
                        $"{configuration.HostId:N}"
                    ],
                    cancellationToken)
                .ConfigureAwait(false);
            RequireSuccess(trigger, "installer_handoff_trigger_failed");
            _ = store.MarkTriggered(
                transaction.TransactionId,
                current.Intent.OwnerCapability,
                current.Generation);
        }
    }

    async Task<EndpointInstallerReceiptOutcome>
        IEndpointUpdatePlatform.ObserveInstallerReceiptAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
    {
        var receiptPath = Path.Combine(
            InstallerHandoffRoot(),
            "receipt.json");
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var store = InstallerHandoffStore();
            var current = store.Current ?? throw new InvalidDataException(
                "Installer handoff state is unavailable.");
            if (current.Intent.TransactionId != transaction.TransactionId)
                throw new EndpointUpdateException(
                    "installer_handoff_owner",
                    "Installer handoff belongs to another update transaction.");
            if (current.Receipt is { } terminal)
                return terminal.Outcome;
            if (File.Exists(receiptPath))
            {
                EndpointUpdateFileValidator.EnsureRegularFile(receiptPath);
                var receipt = JsonSerializer.Deserialize<
                    EndpointInstallerHandoffReceipt>(
                    await File.ReadAllBytesAsync(
                            receiptPath,
                            cancellationToken)
                        .ConfigureAwait(false),
                    CreateEndpointHealthJson()) ??
                    throw new InvalidDataException(
                        "Installer handoff receipt is empty.");
                return store.RecordReceipt(
                    receipt,
                    current.Generation).Receipt!.Outcome;
            }
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private FileEndpointInstallerHandoffStore InstallerHandoffStore() => new(
        Path.Combine(stateRoot, "installer-handoff.journal"),
        machineAuthenticationKey);

    private string InstallerHandoffRoot() => Path.Combine(
        stateRoot,
        "installer-handoff",
        configuration.HostId.ToString("N"));
    async Task<EndpointHealthObservation>
        IEndpointUpdatePlatform.ObserveHealthAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
    {
        RequireImmutableStage(transaction);
        if (File.Exists(Path.Combine(
                configuration.EndpointStateRoot,
                EndpointStateFiles.V2Health + ".failure")))
            return new EndpointHealthObservation(
                EndpointHealthStatus.CrashLoop, "endpoint-restart-failure");
        var identity = ReadEndpointIdentity();
        if (identity.HostId != transaction.PreservedState.HostId ||
            identity.IncarnationId != transaction.PreservedState.NodeIncarnationId ||
            !string.Equals(identity.ProductVersion,
                transaction.Operation.ProductVersion, StringComparison.Ordinal))
            return new EndpointHealthObservation(
                EndpointHealthStatus.IdentityMismatch, "endpoint-identity-mismatch");
        var readinessPath = Path.Combine(
            configuration.EndpointStateRoot,
            EndpointStateFiles.V2Health);
        if (!File.Exists(readinessPath))
        {
            await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken)
                .ConfigureAwait(false);
            return new EndpointHealthObservation(
                EndpointHealthStatus.ControlUnavailable,
                "authenticated-v2-health-missing");
        }
        AuthenticatedEndpointV2Health readiness;
        try
        {
            EndpointUpdateFileValidator.EnsureRegularFile(readinessPath);
            if (new FileInfo(readinessPath).Length is <= 0 or > 64 * 1024)
                throw new InvalidDataException(
                    "Endpoint v2 health cache size is invalid.");
            readiness = JsonSerializer.Deserialize<AuthenticatedEndpointV2Health>(
                await File.ReadAllBytesAsync(
                        readinessPath,
                        cancellationToken)
                    .ConfigureAwait(false),
                CreateEndpointHealthJson()) ?? throw new JsonException(
                    "Endpoint v2 health is empty.");
        }
        catch (Exception exception) when (exception is
            JsonException or InvalidDataException)
        {
            return new EndpointHealthObservation(
                EndpointHealthStatus.Unhealthy,
                "v2-health-corrupt");
        }
        var authenticationPath = Path.Combine(
            configuration.EndpointStateRoot,
            "keys",
            "rdp-dvc.key");
        EndpointUpdateFileValidator.EnsureRegularFile(authenticationPath);
        if (new FileInfo(authenticationPath).Length != 32)
            return new EndpointHealthObservation(
                EndpointHealthStatus.Unhealthy,
                "v2-health-authenticator-invalid");
        var authenticationKey = await File.ReadAllBytesAsync(
                authenticationPath,
                cancellationToken)
            .ConfigureAwait(false);
        EndpointHealthObservation healthObservation;
        try
        {
            healthObservation = EndpointUpdateHealthGate.Evaluate(
                readiness,
                authenticationKey,
                identity.SessionId,
                transaction.PreservedState.HostId,
                transaction.PreservedState.NodeIncarnationId,
                identity.NodeIdentity,
                identity.ControlIdentity,
                transaction.PreservedState.ReconnectGeneration,
                DateTimeOffset.UtcNow,
                TimeSpan.FromSeconds(30),
                new WindowsEndpointProcessEvidenceSource());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authenticationKey);
        }
        if (healthObservation.Status != EndpointHealthStatus.Healthy)
        {
            if (healthObservation.Status ==
                EndpointHealthStatus.ControlUnavailable)
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken)
                    .ConfigureAwait(false);
            return healthObservation;
        }
        var provisioner = Path.Combine(
            configuration.InstallRoot,
            "Steward.Endpoint.Provisioner.exe");
        var provisioning = Path.Combine(
            stateRoot,
            "staging",
            "update-provisioning.json");
        var attestation = Path.Combine(
            stateRoot,
            "staging",
            "update-artifact-attestation.json");
        if (!File.Exists(provisioner) ||
            !File.Exists(provisioning) ||
            !File.Exists(attestation))
            return new EndpointHealthObservation(
                EndpointHealthStatus.Unhealthy,
                "provisioning-health-input-missing");
        var verification = await RunProcessAsync(
            provisioner,
            [
                "--verify-only",
                "--install-root", configuration.InstallRoot,
                "--config", provisioning,
                "--state-root", configuration.EndpointStateRoot,
                "--maintenance-state-root", stateRoot,
                "--artifact-attestation", attestation
            ],
            cancellationToken).ConfigureAwait(false);
        if (verification.ExitCode != 0)
            return new EndpointHealthObservation(
                EndpointHealthStatus.Unhealthy,
                "provisioning-health-failed");
        return new EndpointHealthObservation(
            EndpointHealthStatus.Healthy, "control-authenticated");
    }

    async Task IEndpointUpdatePlatform.CommitKnownGoodAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var staged = RequireImmutableStage(transaction);
        var knownGood = Path.Combine(configuration.VersionedRoot,
            "known-good", transaction.Operation.ProductVersion);
        Directory.CreateDirectory(knownGood);
        MaintenanceStateSecurity.Protect(knownGood);
        var package = await CopyImmutableAsync(staged.PackagePath,
                Path.Combine(knownGood, "endpoint.msi"),
                transaction.Operation.Package, cancellationToken).ConfigureAwait(false);
        var active = new EndpointActiveVersion(1,
            transaction.Operation.ProductVersion,
            transaction.Operation.Release.MsiSha256,
            transaction.UpdateSequence, package);
        await WriteAtomicAsync(Path.Combine(stateRoot, "active-version.json"),
            JsonSerializer.SerializeToUtf8Bytes(active), cancellationToken).ConfigureAwait(false);
        var provisioner = Path.Combine(
            configuration.InstallRoot,
            "Steward.Endpoint.Provisioner.exe");
        var commit = await RunProcessAsync(
                provisioner,
                [
                    "--commit-msi-transaction",
                    transaction.Operation.Release.ProductCode.ToString("D"),
                    "--install-root",
                    configuration.InstallRoot,
                    "--config",
                    Path.Combine(
                        stateRoot,
                        "staging",
                        "update-provisioning.json"),
                    "--state-root",
                    configuration.EndpointStateRoot,
                    "--maintenance-state-root",
                    stateRoot,
                    "--artifact-attestation",
                    Path.Combine(
                        stateRoot,
                        "staging",
                        "update-artifact-attestation.json")
                ],
                cancellationToken)
            .ConfigureAwait(false);
        if (commit.ExitCode != 0)
            return;
    }

    async Task IEndpointUpdatePlatform.ContractCompatibilityAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var marker = new EndpointMigrationWindow(1, transaction.TransactionId,
            transaction.UpdateSequence, transaction.PriorVersion,
            transaction.Operation.ProductVersion, EndpointMigrationWindowState.Contracted);
        await WriteAtomicAsync(Path.Combine(stateRoot, "migration-window.json"),
            JsonSerializer.SerializeToUtf8Bytes(marker), cancellationToken).ConfigureAwait(false);
    }

    async Task IEndpointUpdatePlatform.RollbackAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var priorRoot = Path.Combine(configuration.VersionedRoot,
            "known-good", transaction.PriorVersion);
        var provisioner = Path.Combine(priorRoot, "payload",
            "Steward.Endpoint.Provisioner.exe");
        var rollbackConfig = Path.Combine(priorRoot, "rollback-config.json");
        var rollbackAttestation = Path.Combine(priorRoot, "rollback-attestation.json");
        if (!File.Exists(provisioner) || !File.Exists(rollbackConfig) ||
            !File.Exists(rollbackAttestation))
            throw new EndpointUpdateException(
                "rollback_package_missing",
                "Known-good endpoint rollback payload is unavailable.");
        RestorePriorIdentityVersion(
            transaction.PriorVersion,
            transaction.TransactionId);
        var rollback = await RunProcessAsync(provisioner,
            [
                "--install-root", Path.GetDirectoryName(provisioner)!,
                "--config", rollbackConfig,
                "--state-root", configuration.EndpointStateRoot,
                "--maintenance-state-root", stateRoot,
                "--artifact-attestation", rollbackAttestation
            ], cancellationToken).ConfigureAwait(false);
        if (rollback.ExitCode != 0)
            throw new EndpointUpdateException(
                "rollback_failed", "Known-good endpoint rollback failed.");
        var priorReceipt = ReadProvisioningReceipt();
        var active = new EndpointActiveVersion(
            1,
            transaction.PriorVersion,
            priorReceipt.Body.MsiSha256,
            transaction.UpdateSequence,
            Path.GetDirectoryName(provisioner)!);
        await WriteAtomicAsync(
            Path.Combine(stateRoot, "active-version.json"),
            JsonSerializer.SerializeToUtf8Bytes(active),
            cancellationToken).ConfigureAwait(false);
    }

    Task IEndpointUpdatePlatform.CleanupPreservationAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (transaction.PreservedState.BackupRoot is { Length: > 0 } root &&
            Directory.Exists(root))
        {
            MaintenanceStateSecurity.ValidatePath(root);
            Directory.Delete(root, recursive: true);
        }
        return Task.CompletedTask;
    }

    Task IEndpointUpdatePlatform.AssertPreservedAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var preserved = transaction.PreservedState;
        var identity = ReadEndpointIdentity();
        var identityMismatch =
            identity.HostId != preserved.HostId ||
            identity.IncarnationId != preserved.NodeIncarnationId ||
            preserved.SessionId != Guid.Empty &&
            identity.SessionId != preserved.SessionId ||
            preserved.NodeIdentity.Length > 0 &&
            !string.Equals(identity.NodeIdentity, preserved.NodeIdentity,
                StringComparison.Ordinal) ||
            preserved.ControlIdentity.Length > 0 &&
            !string.Equals(identity.ControlIdentity, preserved.ControlIdentity,
                StringComparison.Ordinal);
        var updateSequence = ReadCommittedUpdateSequence();
        var requiresCommittedSequence = transaction.State is
            EndpointUpdateTransactionState.KnownGoodCommitted or
            EndpointUpdateTransactionState.MigrationContracted or
            EndpointUpdateTransactionState.Succeeded;
        if (identityMismatch ||
            !FixedHashEquals(HashRequired(Path.Combine(
                configuration.EndpointStateRoot,
                "keys",
                "node-signing.pk8")),
                preserved.NodePrivateKeySha256) ||
            !FixedHashEquals(HashRequired(Path.Combine(
                configuration.EndpointStateRoot,
                "keys",
                "control-signing.spki")),
                preserved.ControlTrustSha256) ||
            !FixedHashEquals(HashRequired(Path.Combine(
                stateRoot,
                "control-signing.spki")),
                preserved.MaintenanceTrustSha256) ||
            !FixedHashEquals(
                EndpointPreservationInspector.HashTree(Path.Combine(
                    configuration.EndpointStateRoot,
                    "workspaces")),
                preserved.WorkspaceTreeSha256) ||
            !FixedHashEquals(
                EndpointPreservationInspector.HashTree(Path.Combine(
                    configuration.EndpointStateRoot,
                    "spool")),
                preserved.SpoolTreeSha256) ||
            preserved.PortableTreeSha256 != new string('0', 64) &&
            !FixedHashEquals(
                EndpointPreservationInspector.HashTree(Path.Combine(
                    configuration.EndpointStateRoot,
                    "portable")),
                preserved.PortableTreeSha256) ||
            !ReceiptPreserved(preserved.ReceiptTreeSha256) ||
            ReadReconnectGeneration() < preserved.ReconnectGeneration ||
            ReadApplicationCursor() < preserved.ApplicationCursor ||
            updateSequence < preserved.UpdateVersion ||
            requiresCommittedSequence &&
            updateSequence < transaction.UpdateSequence ||
            !string.Equals(
                ScheduledTaskSemantics(),
                preserved.ScheduledTaskSemantics,
                StringComparison.Ordinal))
            throw PreservationFailure();

        if (preserved.SqliteDatabases.Count > 0)
        {
            foreach (var database in preserved.SqliteDatabases)
                EndpointSqlitePreservation.AssertNondecreasing(
                    database,
                    Path.Combine(
                        configuration.EndpointStateRoot,
                        Path.GetFileName(database.BackupPath)));
        }
        else if (!OptionalFilePreserved(
                     preserved.NodeJournalSha256,
                     Path.Combine(configuration.EndpointStateRoot, "node.db")) ||
                 !OptionalFilePreserved(
                     preserved.ExecutionJournalSha256,
                     Path.Combine(configuration.EndpointStateRoot, "execution.db")) ||
                 !OptionalFilePreserved(
                     preserved.TerminalJournalSha256,
                     Path.Combine(configuration.EndpointStateRoot, "terminal.db")) ||
                 !OptionalFilePreserved(
                     preserved.EvaluationJournalSha256,
                     Path.Combine(configuration.EndpointStateRoot, "evaluation.db")))
            throw PreservationFailure();
        return Task.CompletedTask;
    }

    private static JsonSerializerOptions CreateEndpointHealthJson()
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
    private static EndpointUpdateException PreservationFailure() => new(
        "preservation_failed",
        "Endpoint update changed immutable authority or moved durable state backwards.");

    private async Task VerifyGitHubAttestationAsync(
        string subject,
        string bundle,
        ArtifactProvenance provenance,
        CancellationToken cancellationToken)
    {
        var verification = await RunAsync(MaintenanceTool.GitHubCli,
            [
                "attestation", "verify", subject,
                "--bundle", bundle,
                "--repo", provenance.SourceRepository,
                "--signer-workflow", provenance.SignerWorkflow,
                "--signer-digest", provenance.SourceCommit,
                "--source-digest", provenance.SourceCommit,
                "--source-ref", provenance.SourceRef,
                "--deny-self-hosted-runners"
            ], cancellationToken).ConfigureAwait(false);
        if (verification.ExitCode != 0)
            throw new EndpointUpdateException(
                "signature_mismatch",
                "Endpoint release signature or attestation is invalid.");
    }

    private async Task<string> CopyImmutableAsync(
        string source,
        string destination,
        ApprovedArtifact artifact,
        CancellationToken cancellationToken)
    {
        if (File.Exists(destination))
        {
            if (!ArtifactMatches(destination, artifact))
                throw new EndpointUpdateException(
                    "staging_mutated",
                    "Existing endpoint version staging does not match its release.");
            return destination;
        }
        var pending = destination + ".new";
        try
        {
            await using var input = new FileStream(source, FileMode.Open,
                FileAccess.Read, FileShare.Read);
            await using var output = new FileStream(pending, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
            File.Move(pending, destination);
            if (!ArtifactMatches(destination, artifact))
                throw new EndpointUpdateException(
                    "staging_mutated", "Endpoint version staging changed during copy.");
            File.SetAttributes(destination,
                File.GetAttributes(destination) | FileAttributes.ReadOnly);
            return destination;
        }
        finally
        {
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }

    private StagedEndpointRelease RequireImmutableStage(
        EndpointUpdateTransaction transaction)
    {
        var staged = transaction.StagedRelease ??
            throw new InvalidOperationException("Staged endpoint release is unavailable.");
        EndpointUpdateFileValidator.ValidateTree(staged.VersionRoot, requireTrustedAcl: true);
        var actual = HashStagedFiles(staged.VersionRoot, staged.PackagePath,
            staged.ManifestPath, staged.AttestationPath);
        if (!FixedHashEquals(actual, staged.TreeSha256))
            throw new EndpointUpdateException(
                "staging_mutated",
                "Endpoint version staging changed after verification.");
        return staged;
    }
    private string HashStagedFiles(string root, params string[] paths)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in paths.Order(StringComparer.Ordinal))
        {
            var identity = EndpointUpdateFileValidator.Capture(
                root, path, requireTrustedAcl: true);
            hash.AppendData(Encoding.UTF8.GetBytes(
                $"{Path.GetFileName(path)}\n{identity.Length}\n" +
                $"{identity.Sha256}\n{identity.VolumeSerialNumber}\n{identity.FileIndex}\n"));
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private void CachePriorKnownGood(string priorVersion)
    {
        var destination = Path.Combine(configuration.VersionedRoot,
            "known-good", priorVersion);
        var payload = Path.Combine(destination, "payload");
        var required = new[]
        {
            Path.Combine(payload, "Steward.Endpoint.Provisioner.exe"),
            Path.Combine(destination, "rollback-config.json"),
            Path.Combine(destination, "rollback-attestation.json"),
            Path.Combine(destination, "bootstrap-envelope.spki"),
            Path.Combine(destination, "control-signing.spki")
        };
        if (required.All(File.Exists))
        {
            EndpointUpdateFileValidator.ValidateTree(
                destination,
                requireTrustedAcl: true);
            return;
        }
        if (Directory.Exists(destination))
        {
            EndpointUpdateFileValidator.ValidateTree(
                destination,
                requireTrustedAcl: true);
            Directory.Delete(destination, recursive: true);
        }
        Directory.CreateDirectory(payload);
        MaintenanceStateSecurity.Protect(destination);
        CopyPayloadTree(configuration.InstallRoot, payload);
        var receipt = ReadProvisioningReceipt();
        var config = new RollbackProvisioningConfig(1,
            receipt.Body.ProductVersion, "bootstrap-envelope.spki",
            "control-signing.spki", receipt.Body.ControlIdentity,
            configuration.NodeUserAccount, configuration.NodeUserSid);
        File.Copy(Path.Combine(stateRoot, "bootstrap-envelope.spki"),
            Path.Combine(destination, "bootstrap-envelope.spki"), overwrite: false);
        File.Copy(Path.Combine(stateRoot, "control-signing.spki"),
            Path.Combine(destination, "control-signing.spki"), overwrite: false);
        var configBytes = JsonSerializer.SerializeToUtf8Bytes(config);
        File.WriteAllBytes(
            Path.Combine(destination, "rollback-config.json"),
            configBytes);
        var rollbackAttestation = receipt.Body.ToArtifactAttestation() with
        {
            ConfigSha256 = Convert.ToHexString(SHA256.HashData(configBytes))
        };
        File.WriteAllBytes(
            Path.Combine(destination, "rollback-attestation.json"),
            JsonSerializer.SerializeToUtf8Bytes(rollbackAttestation));
        CryptographicOperations.ZeroMemory(configBytes);
        MaintenanceStateSecurity.Protect(destination);
        EndpointUpdateFileValidator.ValidateTree(destination, requireTrustedAcl: true);
    }

    private static void CopyPayloadTree(string source, string destination)
    {
        var sourceRoot = Path.GetFullPath(source).TrimEnd(
            Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var pending = new Stack<string>();
        pending.Push(sourceRoot.TrimEnd(Path.DirectorySeparatorChar));
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new EndpointUpdateException(
                        "staging_reparse",
                        "Known-good payload contains a reparse point.");
                var relative = Path.GetRelativePath(sourceRoot, entry);
                var target = Path.Combine(destination, relative);
                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    Directory.CreateDirectory(target);
                    pending.Push(entry);
                }
                else
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    File.Copy(entry, target, overwrite: false);
                }
            }
        }
    }

    private EndpointIdentityFile ReadEndpointIdentity()
    {
        var path = Path.Combine(configuration.EndpointStateRoot, "identity.json");
        EndpointUpdateFileValidator.EnsureRegularFile(path);
        var identity = JsonSerializer.Deserialize<EndpointIdentityFile>(
            File.ReadAllBytes(path),
            new JsonSerializerOptions(JsonSerializerDefaults.Web)) ??
            throw new InvalidDataException("Endpoint identity is empty.");
        if (identity.Version != 1 ||
            identity.BootstrapOperationId == Guid.Empty ||
            identity.SessionId == Guid.Empty ||
            identity.HostId == Guid.Empty ||
            identity.IncarnationId == Guid.Empty ||
            string.IsNullOrWhiteSpace(identity.NodeIdentity) ||
            string.IsNullOrWhiteSpace(identity.ControlIdentity) ||
            !Version.TryParse(identity.ProductVersion, out _))
            throw new InvalidDataException("Endpoint identity is invalid.");
        return identity;
    }

    private void RestorePriorIdentityVersion(
        string priorVersion,
        Guid transactionId)
    {
        var path = Path.Combine(configuration.EndpointStateRoot, "identity.json");
        var identity = ReadEndpointIdentity() with { ProductVersion = priorVersion };
        var pending = path + $".rollback-{transactionId:N}";
        if (File.Exists(pending))
        {
            EndpointUpdateFileValidator.EnsureRegularFile(pending);
            var recovered = JsonSerializer.Deserialize<EndpointIdentityFile>(
                File.ReadAllBytes(pending));
            if (recovered != identity)
                throw new EndpointUpdateException(
                    "rollback_staging_mutated",
                    "Endpoint rollback identity staging was mutated.");
        }
        else
        {
            using var stream = new FileStream(
                pending,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            JsonSerializer.Serialize(stream, identity);
            stream.Flush(flushToDisk: true);
        }
        File.Move(pending, path, overwrite: true);
        _ = WindowsDurableFile.FlushParentDirectory(
            Path.GetDirectoryName(path) ??
            throw new InvalidDataException(
                "Rollback identity has no parent directory."));
    }

    private ProvisioningReceipt ReadProvisioningReceipt()
    {
        var path = Path.Combine(configuration.EndpointStateRoot, "bootstrap-receipt.json");
        EndpointUpdateFileValidator.EnsureRegularFile(path);
        return JsonSerializer.Deserialize<ProvisioningReceipt>(
            File.ReadAllBytes(path),
            new JsonSerializerOptions(JsonSerializerDefaults.Web)) ??
            throw new InvalidDataException("Endpoint provisioning receipt is empty.");
    }

    private ulong ReadReconnectGeneration()
    {
        var ledger = Path.Combine(
            configuration.EndpointStateRoot,
            EndpointStateFiles.ReconnectLedgerV2);
        var generation = File.Exists(ledger)
            ? ReadSqliteMaximum(
                ledger,
                "SELECT COALESCE(MAX(generation),0) FROM reconnect_state")
            : 0;
        var legacy = Path.Combine(
            configuration.EndpointStateRoot,
            "nonce-sequence.json");
        if (!File.Exists(legacy))
            return generation;
        var nonce = JsonSerializer.Deserialize<LegacyNonceCursor>(
            File.ReadAllBytes(legacy),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var legacyGeneration = nonce?.NextIndex is >= 0
            ? checked((ulong)nonce.NextIndex)
            : 0;
        return Math.Max(generation, legacyGeneration);
    }

    private ulong ReadApplicationCursor()
    {
        var journal = Path.Combine(
            configuration.EndpointStateRoot,
            "node.db");
        if (!File.Exists(journal))
            return 0;
        var stream = ReadSqliteMaximum(
            journal,
            "SELECT COALESCE(MAX(cursor),0) FROM stream_cursors");
        var output = ReadSqliteMaximum(
            journal,
            "SELECT COALESCE(MAX(output_cursor),0) FROM attempt_contexts");
        var acknowledgement = ReadSqliteMaximum(
            journal,
            "SELECT COALESCE(MAX(CAST(value AS INTEGER)),0) " +
            "FROM metadata WHERE key='ack_cursor'");
        return Math.Max(stream, Math.Max(output, acknowledgement));
    }

    private static ulong ReadSqliteMaximum(
        string path,
        string query)
    {
        EndpointUpdateFileValidator.EnsureRegularFile(path);
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 5
        }.ToString();
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = query;
        var value = Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
        if (value < 0)
            throw new InvalidDataException(
                "Endpoint monotonic cursor cannot be negative.");
        return checked((ulong)value);
    }
    private ulong ReadCommittedUpdateSequence()
    {
        var path = Path.Combine(stateRoot, "active-version.json");
        if (!File.Exists(path))
            return 0;
        try
        {
            return JsonSerializer.Deserialize<EndpointActiveVersion>(
                File.ReadAllBytes(path))?.UpdateSequence ?? 0;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Endpoint active version history is corrupt.", exception);
        }
    }

    private static string HashDatabase(EndpointSqliteSnapshot snapshot)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot.Tables);
        try
        {
            return Convert.ToHexString(SHA256.HashData(bytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string HashRequired(string path)
    {
        EndpointUpdateFileValidator.EnsureRegularFile(path);
        return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    }

    private static string HashOptional(string path) =>
        File.Exists(path) ? HashRequired(path) : new string('0', 64);

    private bool ReceiptPreserved(string expectedHash)
    {
        var current = Path.Combine(
            configuration.EndpointStateRoot,
            "bootstrap-receipt.json");
        if (File.Exists(current) &&
            FixedHashEquals(HashRequired(current), expectedHash))
            return true;
        var history = Path.Combine(
            configuration.EndpointStateRoot,
            "receipts");
        return Directory.Exists(history) &&
            Directory.EnumerateFiles(
                    history,
                    "bootstrap-*.json",
                    SearchOption.TopDirectoryOnly)
                .Any(path => FixedHashEquals(
                    HashRequired(path),
                    expectedHash));
    }

    private static bool OptionalFilePreserved(
        string priorHash,
        string path)
    {
        if (priorHash == new string('0', 64))
            return true;
        try
        {
            EndpointUpdateFileValidator.EnsureRegularFile(path);
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or InvalidDataException or
            UnauthorizedAccessException or EndpointUpdateException)
        {
            return false;
        }
    }

    private string ScheduledTaskSemantics() =>
        $"exact-user-at-logon-remote-connect/{configuration.HostId:N}";
    private static bool FixedHashEquals(string first, string second)
    {
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

    private enum EndpointMigrationWindowState { Expanded, Contracted }

    private sealed record EndpointMigrationWindow(
        int Version, Guid TransactionId, ulong UpdateSequence,
        string PriorVersion, string TargetVersion,
        EndpointMigrationWindowState State);

    private sealed record EndpointActiveVersion(
        int Version, string ProductVersion, string ReleaseSha256,
        ulong UpdateSequence, string PackagePath);

    private sealed record EndpointIdentityFile(
        int Version,
        string ProductVersion,
        Guid BootstrapOperationId,
        Guid SessionId,
        Guid HostId,
        Guid IncarnationId,
        string NodeIdentity,
        string ControlIdentity,
        DateTimeOffset CreatedAtUtc);

    private sealed record LegacyNonceCursor(int NextIndex);

    private sealed record RollbackProvisioningConfig(
        int Version, string ProductVersion,
        string BootstrapEncryptionPublicKey, string ControlSigningPublicKey,
        string ControlIdentity, string ProvisionedUserAccount,
        string ProvisionedUserSid);

    private sealed record ProvisioningReceipt(
        ProvisioningReceiptBody Body, string Signature);

    private sealed record ProvisioningReceiptBody(
        int Version, string ProductVersion, string MsiSha256,
        string SourceRepository, string SourceCommit, string SourceRef,
        string SignerWorkflow, string SourceRunId, string ProductCode,
        string ConfigSha256, string BootstrapEncryptionPublicKeySha256,
        string ControlSigningPublicKeySha256, string ControlIdentity)
    {
        internal RollbackArtifactAttestation ToArtifactAttestation() => new(
            1, ProductVersion, MsiSha256, SourceRepository, SourceCommit,
            SourceRef, SignerWorkflow, SourceRunId, ProductCode, ConfigSha256,
            BootstrapEncryptionPublicKeySha256,
            ControlSigningPublicKeySha256, ControlIdentity);
    }

    private sealed record RollbackArtifactAttestation(
        int Version, string ProductVersion, string MsiSha256,
        string SourceRepository, string SourceCommit, string SourceRef,
        string SignerWorkflow, string SourceRunId, string ProductCode,
        string ConfigSha256, string BootstrapEncryptionPublicKeySha256,
        string ControlSigningPublicKeySha256, string ControlIdentity);
}


