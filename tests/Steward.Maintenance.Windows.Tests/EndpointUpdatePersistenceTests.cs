using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class EndpointUpdatePersistenceTests
{
    [Fact]
    public void Sqlite_preservation_uses_a_consistent_backup_and_monotonic_checks()
    {
        var root = TestRoot();
        Directory.CreateDirectory(root);
        try
        {
            var database = Path.Combine(root, "journal.db");
            using (var connection = new SqliteConnection(
                       $"Data Source={database}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText =
                    "CREATE TABLE journal(sequence INTEGER NOT NULL);" +
                    "INSERT INTO journal(sequence) VALUES(1),(2);";
                command.ExecuteNonQuery();
            }
            var backup = Path.Combine(root, "backup", "journal.db");
            var snapshot = EndpointSqlitePreservation.Capture(
                database,
                backup);

            Assert.True(File.Exists(backup));
            Assert.True(snapshot.IntegrityVerified);
            Assert.Equal(2, snapshot.Tables.Single().RowCount);
            Assert.Equal(2, snapshot.Tables.Single()
                .Counters.Single().Maximum);

            using (var connection = new SqliteConnection(
                       $"Data Source={database}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "DELETE FROM journal WHERE sequence=2";
                command.ExecuteNonQuery();
            }
            Assert.Throws<EndpointUpdateException>(() =>
                EndpointSqlitePreservation.AssertNondecreasing(
                    snapshot,
                    database));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Preservation_tree_hash_binds_file_contents_and_metadata()
    {
        var root = TestRoot();
        Directory.CreateDirectory(root);
        try
        {
            var file = Path.Combine(root, "object.bin");
            File.WriteAllText(file, "first");
            var first = EndpointPreservationInspector.HashTree(root);

            File.WriteAllText(file, "other");
            var contentChanged = EndpointPreservationInspector.HashTree(root);
            File.SetLastWriteTimeUtc(file,
                File.GetLastWriteTimeUtc(file).AddMinutes(1));
            var metadataChanged = EndpointPreservationInspector.HashTree(root);

            Assert.NotEqual(first, contentChanged);
            Assert.NotEqual(contentChanged, metadataChanged);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Authenticated_transaction_continues_after_store_restart()
    {
        var root = TestRoot();
        Directory.CreateDirectory(root);
        try
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var path = Path.Combine(root, "endpoint-update.journal");
            var operation = Operation("1.1.0");
            var platform = new PersistentFakePlatform(Snapshot());
            var crash = new CrashAfterActivationIntent();
            var firstStore = new FileEndpointUpdateTransactionStore(
                path,
                key,
                "1.0.23");
            var first = new EndpointUpdateCoordinator(
                firstStore,
                platform,
                crash,
                maximumHealthObservations: 2);

            await Assert.ThrowsAsync<EndpointUpdateInterruptedException>(() =>
                first.ExecuteAsync(operation, default));

            var restartedStore = new FileEndpointUpdateTransactionStore(
                path,
                key,
                "9.9.9");
            var restarted = new EndpointUpdateCoordinator(
                restartedStore,
                platform,
                maximumHealthObservations: 2);
            var result = await restarted.ExecuteAsync(operation, default);

            Assert.Equal(EndpointUpdateDisposition.Activated, result.Disposition);
            Assert.Equal((ulong)1, restartedStore.History.LastUpdateSequence);
            Assert.Equal("1.1.0", restartedStore.History.ActiveVersion);
            Assert.Equal(1, platform.HandoffTriggerEffects);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Distinct_durable_operation_starts_next_monotonic_transaction()
    {
        var root = TestRoot();
        Directory.CreateDirectory(root);
        try
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var path = Path.Combine(root, "endpoint-update.journal");
            var platform = new PersistentFakePlatform(Snapshot());
            var firstId = Guid.NewGuid();
            var firstStore = new FileEndpointUpdateTransactionStore(path, key, "1.0.23");
            var first = new EndpointUpdateCoordinator(
                firstStore, platform, transactionId: firstId);
            await first.ExecuteAsync(Operation("1.1.0"), default);

            var secondId = Guid.NewGuid();
            var secondStore = new FileEndpointUpdateTransactionStore(path, key, "9.9.9");
            var second = new EndpointUpdateCoordinator(
                secondStore, platform, transactionId: secondId);
            var result = await second.ExecuteAsync(Operation("1.2.0"), default);

            Assert.Equal(EndpointUpdateDisposition.Activated, result.Disposition);
            Assert.Equal((ulong)2, secondStore.History.LastUpdateSequence);
            Assert.Equal("1.2.0", secondStore.History.ActiveVersion);
            Assert.Equal(secondId, secondStore.Current?.TransactionId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
    [Fact]
    public void Tampered_transaction_journal_fails_closed()
    {
        var root = TestRoot();
        Directory.CreateDirectory(root);
        try
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var path = Path.Combine(root, "endpoint-update.journal");
            var store = new FileEndpointUpdateTransactionStore(
                path,
                key,
                "1.0.23");
            _ = store.Begin(Operation("1.1.0"), Snapshot());
            var bytes = File.ReadAllBytes(path);
            bytes[^2] ^= 0x4A;
            File.WriteAllBytes(path, bytes);

            Assert.Throws<InvalidDataException>(() =>
                new FileEndpointUpdateTransactionStore(
                    path,
                    key,
                    "1.0.23"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Immutable_stage_validation_rejects_reparse_hardlink_and_mutation()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var root = TestRoot();
        Directory.CreateDirectory(root);
        try
        {
            var package = Path.Combine(root, "endpoint.msi");
            File.WriteAllText(package, "signed-package");
            var identity = EndpointUpdateFileValidator.Capture(
                root,
                package,
                requireTrustedAcl: false);
            File.AppendAllText(package, "mutation");
            var mutation = Assert.Throws<EndpointUpdateException>(() =>
                EndpointUpdateFileValidator.Revalidate(
                    root,
                    package,
                    identity,
                    requireTrustedAcl: false));
            Assert.Equal("staging_mutated", mutation.Code);

            File.WriteAllText(package, "signed-package");
            var hardlink = Path.Combine(root, "duplicate.msi");
            Assert.True(CreateHardLink(hardlink, package, IntPtr.Zero));
            var hardLinkError = Assert.Throws<EndpointUpdateException>(() =>
                EndpointUpdateFileValidator.Capture(
                    root,
                    package,
                    requireTrustedAcl: false));
            Assert.Equal("staging_hardlink", hardLinkError.Code);
            File.Delete(hardlink);

            var outside = Path.Combine(root, "outside");
            Directory.CreateDirectory(outside);
            var link = Path.Combine(root, "link");
            try
            {
                Directory.CreateSymbolicLink(link, outside);
            }
            catch (IOException)
            {
                return;
            }
            var reparse = Assert.Throws<EndpointUpdateException>(() =>
                EndpointUpdateFileValidator.ValidateTree(
                    root,
                    requireTrustedAcl: false));
            Assert.Equal("staging_reparse", reparse.Code);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static ActivateEndpointUpdateOperation Operation(string version) =>
        new(
            1,
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointMsi),
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointAttestation),
            MaintenanceContractTests.Release(version),
            MaintenanceContractTests.Provenance());

    private static EndpointPreservationSnapshot Snapshot() => new(
        Guid.Parse("11111111-1111-1111-1111-111111111111"),
        Guid.Parse("22222222-2222-2222-2222-222222222222"),
        Hash('1'), Hash('2'), Hash('3'), Hash('4'), Hash('5'), Hash('6'),
        Hash('7'), Hash('8'), Hash('9'), Hash('A'),
        9, 8, 7, "task-semantics");

    private static string Hash(char value) => new(value, 64);

    private static string TestRoot() => Path.Combine(
        Path.GetTempPath(),
        "steward-update-persistence-tests",
        Guid.NewGuid().ToString("N"));

#pragma warning disable SYSLIB1054
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);
#pragma warning restore SYSLIB1054
    private sealed class CrashAfterActivationIntent :
        IEndpointUpdateBoundaryObserver
    {
        public void Reached(EndpointUpdateBoundary boundary)
        {
            if (boundary == EndpointUpdateBoundary.InstallerHandoffIntentCommitted)
                throw new EndpointUpdateInterruptedException(boundary);
        }
    }

    private sealed class PersistentFakePlatform(
        EndpointPreservationSnapshot snapshot) : IEndpointUpdatePlatform
    {
        private bool handoffTriggered;
        internal int HandoffTriggerEffects { get; private set; }

        public Task<EndpointPreservationSnapshot> CapturePreservedStateAsync(
            Guid transactionId,
            ActivateEndpointUpdateOperation operation,
            CancellationToken cancellationToken) => Task.FromResult(snapshot);

        public Task<VerifiedEndpointRelease> VerifyReleaseAsync(
            ActivateEndpointUpdateOperation operation,
            CancellationToken cancellationToken) => Task.FromResult(new VerifiedEndpointRelease(
                operation.Release,
                "manifest",
                "package",
                "attestation"));

        public Task<StagedEndpointRelease> StageImmutableAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.FromResult(new StagedEndpointRelease(
                transaction.Operation.Release,
                "root",
                "package",
                "manifest",
                "attestation",
                Hash('B')));

        public Task ExpandCompatibilityAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task PersistInstallerHandoffAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task TriggerInstallerHandoffAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            if (!handoffTriggered)
            {
                handoffTriggered = true;
                HandoffTriggerEffects++;
            }
            return Task.CompletedTask;
        }

        public Task<EndpointInstallerReceiptOutcome>
            ObserveInstallerReceiptAsync(
                EndpointUpdateTransaction transaction,
                CancellationToken cancellationToken) => Task.FromResult(
                EndpointInstallerReceiptOutcome.Committed);

        public Task<EndpointHealthObservation> ObserveHealthAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.FromResult(
                new EndpointHealthObservation(
                    EndpointHealthStatus.Healthy,
                    "control-authenticated"));

        public Task CommitKnownGoodAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task ContractCompatibilityAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RollbackAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task CleanupPreservationAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task AssertPreservedAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            Assert.Equal(snapshot, transaction.PreservedState);
            return Task.CompletedTask;
        }
    }
}

