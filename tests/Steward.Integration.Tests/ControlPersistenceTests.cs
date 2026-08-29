using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Control;
using Steward.Domain;
using Steward.Persistence.Sqlite;

namespace Steward.Integration.Tests;

public sealed class ControlPersistenceTests
{
    [Fact]
    public async Task MigrationsAreIdempotentAndEnableDurablePragmas()
    {
        using var test = await TestStore.CreateAsync();
        await test.Store.InitializeAsync();
        Assert.Equal(SchemaMigrator.CurrentVersion, await test.Store.GetSchemaVersionAsync());
        await using var connection = await test.Store.OpenConnectionAsync();
        Assert.Equal("wal", await ScalarAsync(connection, "PRAGMA journal_mode;"));
        Assert.Equal("1", await ScalarAsync(connection, "PRAGMA foreign_keys;"));
        Assert.Equal("2", await ScalarAsync(connection, "PRAGMA synchronous;"));
    }

    [Fact]
    public async Task VersionOneNotificationsMigrateWithBackfilledPayloadHashes()
    {
        using var test = TestStore.CreateUninitialized();
        var notificationId = NotificationId.New();
        var payloadJson = JsonSerializer.Serialize(new { value = 1 }, StewardJson.Options);
        await using (var connection = new SqliteConnection($"Data Source={test.Store.DatabasePath}"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE schema_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    migrated_at TEXT NOT NULL
                );
                INSERT INTO schema_metadata VALUES(1, 1, $now);
                CREATE TABLE notification_outbox (
                    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_id TEXT NOT NULL UNIQUE,
                    stream TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    acknowledged_at TEXT
                );
                INSERT INTO notification_outbox(notification_id,stream,payload_json,created_at)
                VALUES($id,'agent:1',$json,$now);
                """;
            command.Parameters.AddWithValue("$id", notificationId.ToString());
            command.Parameters.AddWithValue("$json", payloadJson);
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync();
        }

        await test.Store.InitializeAsync();
        Assert.Equal(SchemaMigrator.CurrentVersion, await test.Store.GetSchemaVersionAsync());
        Assert.Equal(1, await test.Store.AppendNotificationAsync(
            notificationId, "agent:1", new { value = 1 }));
        await test.Store.InitializeAsync();
    }

    [Fact]
    public async Task VersionTwoMigratesWorkloadRequestsToVersionThree()
    {
        using var test = TestStore.CreateUninitialized();
        await using (var connection = new SqliteConnection($"Data Source={test.Store.DatabasePath}"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE schema_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    migrated_at TEXT NOT NULL
                );
                INSERT INTO schema_metadata VALUES(1, 2, $now);
                """;
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync();
        }

        await test.Store.InitializeAsync();
        Assert.Equal(3, await test.Store.GetSchemaVersionAsync());
        await using var migrated = await test.Store.OpenConnectionAsync();
        Assert.Equal("1", await ScalarAsync(migrated,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='workload_requests';"));
        await test.Store.InitializeAsync();
    }

    [Fact]
    public async Task FailedOutboxWriteRollsBackAggregate()
    {
        using var test = await TestStore.CreateAsync();
        var snapshot = WorkloadSnapshot(revision: 0);
        var duplicate = new OutboxMessage("same-message", "test", """{"value":1}""");
        var exception = await Assert.ThrowsAsync<PersistenceException>(() =>
            test.Store.SaveWorkloadAsync(snapshot, null, [duplicate, duplicate]));
        Assert.Equal(PersistenceErrorCode.IdempotencyConflict, exception.Code);
        Assert.Null(await test.Store.GetWorkloadAsync(snapshot.Payload.WorkloadId));
        Assert.Empty(await test.Store.ReadOutboxAsync());
    }

    [Fact]
    public async Task RevisionRaceHasExactlyOneWinner()
    {
        using var test = await TestStore.CreateAsync();
        var initial = WorkloadSnapshot(revision: 0);
        await test.Store.SaveWorkloadAsync(initial, null);
        var first = initial with { Revision = 1, Payload = initial.Payload with { WorkloadType = "first" } };
        var second = initial with { Revision = 1, Payload = initial.Payload with { WorkloadType = "second" } };

        var results = await Task.WhenAll(TrySave(first), TrySave(second));
        Assert.Equal(1, results.Count(x => x));
        Assert.Equal(1, (await test.Store.GetWorkloadAsync(initial.Payload.WorkloadId))!.Revision);

        async Task<bool> TrySave(ContractEnvelope<WorkloadDto> value)
        {
            try
            {
                await test.Store.SaveWorkloadAsync(value, 0);
                return true;
            }
            catch (PersistenceException exception) when (exception.Code == PersistenceErrorCode.RevisionConflict)
            {
                return false;
            }
        }
    }

    [Fact]
    public async Task CommandIdempotencyRejectsDifferentPayload()
    {
        using var test = await TestStore.CreateAsync();
        var command = Command("stable-key", "one");
        var first = await test.Store.EnqueueCommandAsync(command);
        Assert.Equal(first, await test.Store.EnqueueCommandAsync(command));
        var conflict = await Assert.ThrowsAsync<PersistenceException>(() =>
            test.Store.EnqueueCommandAsync(Command("stable-key", "two")));
        Assert.Equal(PersistenceErrorCode.IdempotencyConflict, conflict.Code);
        Assert.Single(await test.Store.DequeueCommandsAsync());
    }

    [Fact]
    public async Task AggregateAndOutboxCommitAtomically()
    {
        using var test = await TestStore.CreateAsync();
        var snapshot = WorkloadSnapshot(revision: 0);
        await test.Store.SaveWorkloadAsync(snapshot, null,
            [new("workload-created", "workload.created", """{"created":true}""", "create-key")]);
        Assert.NotNull(await test.Store.GetWorkloadAsync(snapshot.Payload.WorkloadId));
        var outbox = Assert.Single(await test.Store.ReadOutboxAsync());
        Assert.Equal("workload-created", outbox.MessageId);
    }

    [Fact]
    public async Task IdempotentWorkloadAndRequestRollBackWithOutboxFailure()
    {
        using var test = await TestStore.CreateAsync();
        var snapshot = WorkloadSnapshot(0);
        var duplicate = new OutboxMessage("duplicate", "workload.created", """{"value":1}""");
        await Assert.ThrowsAsync<PersistenceException>(() =>
            test.Store.CreateWorkloadIdempotentAsync(
                snapshot, "request-key", "request-hash", [duplicate, duplicate]));

        Assert.Null(await test.Store.GetWorkloadAsync(snapshot.Payload.WorkloadId));
        await using var connection = await test.Store.OpenConnectionAsync();
        Assert.Equal("0", await ScalarAsync(connection, "SELECT COUNT(*) FROM workload_requests;"));
        Assert.Empty(await test.Store.ReadOutboxAsync());
    }

    [Fact]
    public async Task ConcurrentSameWorkloadRequestReturnsOnePersistedSnapshot()
    {
        using var test = await TestStore.CreateAsync();
        var candidates = Enumerable.Range(0, 8).Select(_ => WorkloadSnapshot(0)).ToArray();
        var results = await Task.WhenAll(candidates.Select(snapshot =>
            test.Store.CreateWorkloadIdempotentAsync(
                snapshot, "same-request", "normalized-request-hash")));

        var persistedId = results[0].Payload.WorkloadId;
        Assert.All(results, result => Assert.Equal(persistedId, result.Payload.WorkloadId));
        await using var connection = await test.Store.OpenConnectionAsync();
        Assert.Equal("1", await ScalarAsync(connection, "SELECT COUNT(*) FROM workload_requests;"));
        Assert.Equal("1", await ScalarAsync(connection, "SELECT COUNT(*) FROM workloads;"));
    }

    [Fact]
    public async Task WorkloadRequestChangedHashConflictsWithoutCreatingCandidate()
    {
        using var test = await TestStore.CreateAsync();
        var persisted = WorkloadSnapshot(0);
        await test.Store.CreateWorkloadIdempotentAsync(
            persisted, "stable-request", "first-hash");
        var candidate = WorkloadSnapshot(0);

        var conflict = await Assert.ThrowsAsync<PersistenceException>(() =>
            test.Store.CreateWorkloadIdempotentAsync(
                candidate, "stable-request", "changed-hash"));
        Assert.Equal(PersistenceErrorCode.IdempotencyConflict, conflict.Code);
        Assert.Null(await test.Store.GetWorkloadAsync(candidate.Payload.WorkloadId));
        Assert.NotNull(await test.Store.GetWorkloadAsync(persisted.Payload.WorkloadId));
    }

    [Fact]
    public async Task NotificationsReplayByCursorAndAcknowledgeMonotonically()
    {
        using var test = await TestStore.CreateAsync();
        var first = await test.Store.AppendNotificationAsync(NotificationId.New(), "agent:1", new { value = 1 });
        var second = await test.Store.AppendNotificationAsync(NotificationId.New(), "agent:1", new { value = 2 });
        Assert.Equal([first, second], (await test.Store.ReadNotificationsAsync("agent:1", 0)).Select(x => x.Cursor));
        Assert.Equal([second], (await test.Store.ReadNotificationsAsync("agent:1", first)).Select(x => x.Cursor));

        await test.Store.AcknowledgeNotificationsAsync("agent:1", first);
        await test.Store.AcknowledgeNotificationsAsync("agent:1", first);
        Assert.Equal(first, await test.Store.GetAcknowledgedNotificationCursorAsync("agent:1"));
        Assert.Equal([first, second], (await test.Store.ReadNotificationsAsync("agent:1", 0)).Select(x => x.Cursor));
    }

    [Fact]
    public async Task NotificationIdentityRequiresExactStreamAndPayload()
    {
        using var test = await TestStore.CreateAsync();
        var id = NotificationId.New();
        var cursor = await test.Store.AppendNotificationAsync(id, "agent:1", new { value = 1 });
        Assert.Equal(cursor, await test.Store.AppendNotificationAsync(id, "agent:1", new { value = 1 }));

        var payloadConflict = await Assert.ThrowsAsync<PersistenceException>(() =>
            test.Store.AppendNotificationAsync(id, "agent:1", new { value = 2 }));
        Assert.Equal(PersistenceErrorCode.IdempotencyConflict, payloadConflict.Code);
        var streamConflict = await Assert.ThrowsAsync<PersistenceException>(() =>
            test.Store.AppendNotificationAsync(id, "agent:2", new { value = 1 }));
        Assert.Equal(PersistenceErrorCode.IdempotencyConflict, streamConflict.Code);
        Assert.Single(await test.Store.ReadNotificationsAsync("agent:1", 0));
        Assert.Empty(await test.Store.ReadNotificationsAsync("agent:2", 0));
    }

    [Fact]
    public async Task ConcurrentIdenticalDelegationsSucceedAndDifferentPayloadConflicts()
    {
        using var test = await TestStore.CreateAsync();
        var delegation = Delegation();
        await Task.WhenAll(Enumerable.Range(0, 8)
            .Select(_ => test.Store.RecordDelegationAsync(delegation, "delegation-key")));

        var conflict = await Assert.ThrowsAsync<PersistenceException>(() =>
            test.Store.RecordDelegationAsync(
                delegation with { SpoolQuotaBytes = delegation.SpoolQuotaBytes + 1 },
                "delegation-key"));
        Assert.Equal(PersistenceErrorCode.IdempotencyConflict, conflict.Code);

        await using var connection = await test.Store.OpenConnectionAsync();
        Assert.Equal("1", await ScalarAsync(connection, "SELECT COUNT(*) FROM delegations;"));
    }

    [Fact]
    public async Task BackupValidatesHashAndRestoreNeverOverwrites()
    {
        using var test = await TestStore.CreateAsync();
        var snapshot = WorkloadSnapshot(revision: 0);
        await test.Store.SaveWorkloadAsync(snapshot, null);
        var export = await new SqliteBackupService(test.Store).ExportAsync(test.Directory);
        var manifest = await SqliteBackupService.ValidateAsync(export.DatabasePath, export.ManifestPath);
        Assert.Equal(SchemaMigrator.CurrentVersion, manifest.SchemaVersion);

        var restored = Path.Combine(test.Directory, "restored.db");
        await SqliteBackupService.RestoreAsync(export.DatabasePath, export.ManifestPath, restored);
        await Assert.ThrowsAsync<IOException>(() =>
            SqliteBackupService.RestoreAsync(export.DatabasePath, export.ManifestPath, restored));

        await File.AppendAllTextAsync(export.DatabasePath, "tamper");
        var invalid = await Assert.ThrowsAsync<PersistenceException>(() =>
            SqliteBackupService.ValidateAsync(export.DatabasePath, export.ManifestPath));
        Assert.Equal(PersistenceErrorCode.InvalidBackup, invalid.Code);
    }

    [Fact]
    public async Task BackupIncludesCompletedWorkloadRequestTable()
    {
        using var test = await TestStore.CreateAsync();
        var snapshot = WorkloadSnapshot(0);
        await test.Store.CreateWorkloadIdempotentAsync(
            snapshot, "backup-request", "backup-hash");
        var export = await new SqliteBackupService(test.Store).ExportAsync(test.Directory);

        await using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = export.DatabasePath,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false
            }.ToString());
        await connection.OpenAsync();
        Assert.Equal("1", await ScalarAsync(connection,
            "SELECT COUNT(*) FROM workload_requests WHERE idempotency_key='backup-request' AND status='completed';"));
    }

    [Fact]
    public async Task NewControlCompositionReadsPersistedStateAfterRestart()
    {
        using var test = await TestStore.CreateAsync();
        var planner = JsonDocument.Parse("""{"name":"planner"}""").RootElement.Clone();
        var firstService = new WorkloadApplicationService(test.Store);
        var created = await firstService.CreateAsync(new("test", "planner", "1.0.0", planner));

        var restartedStore = new SqliteControlStore(test.Store.DatabasePath);
        await restartedStore.InitializeAsync();
        var restartedService = new WorkloadApplicationService(restartedStore);
        var restored = await restartedService.GetAsync(created.Payload.WorkloadId);
        Assert.NotNull(restored);
        Assert.Equal(JsonSerializer.Serialize(created, StewardJson.Options),
            JsonSerializer.Serialize(restored, StewardJson.Options));
    }

    [Fact]
    public async Task TaskAndAttemptSnapshotsRetainAuthoritativeColumns()
    {
        using var test = await TestStore.CreateAsync();
        var workload = WorkloadSnapshot(0);
        await test.Store.SaveWorkloadAsync(workload, null);
        var taskId = TaskId.New();
        var extension = Extension("task");
        var task = new ContractEnvelope<TaskDto>("steward.task", "1.0.0", [], [], DateTimeOffset.UtcNow, 0,
            new(taskId, workload.Payload.WorkloadId, workload.Payload.PlanRevisionId, "process", "1.0.0",
                TaskDesiredState.Ready, TaskObservedState.Blocked, 1, InterruptionClass.Restartable,
                TaskCapabilities.Execute, new(1, 1024, 0, 0, 1, 0, 0, 1), [], extension));
        await test.Store.SaveTaskAsync(task, null);
        var attemptId = TaskAttemptId.New();
        var attempt = new ContractEnvelope<TaskAttemptDto>("steward.task-attempt", "1.0.0", [], [], DateTimeOffset.UtcNow, 0,
            new(attemptId, taskId, 1, HostId.New(), NodeIncarnationId.New(), TaskAttemptState.Reserved,
                RecoveryCertainty.Certain, DelegationId.New(), CommandId.New(), DateTimeOffset.UtcNow.AddHours(1), extension));
        await test.Store.SaveTaskAttemptAsync(attempt, null);
        Assert.Equal(JsonSerializer.Serialize(task, StewardJson.Options),
            JsonSerializer.Serialize(await test.Store.GetTaskAsync(taskId), StewardJson.Options));
        Assert.Equal(JsonSerializer.Serialize(attempt, StewardJson.Options),
            JsonSerializer.Serialize(await test.Store.GetTaskAttemptAsync(attemptId), StewardJson.Options));
    }

    private static ContractEnvelope<WorkloadDto> WorkloadSnapshot(long revision)
    {
        var payload = new WorkloadDto(WorkloadId.New(), PlanRevisionId.New(), "test",
            WorkloadDesiredState.Active, WorkloadObservedState.Planning, [], [], Extension("planner"));
        return new("steward.workload", "1.0.0", [], [], DateTimeOffset.UtcNow, revision, payload);
    }

    private static CommandDto Command(string key, string value) =>
        new(CommandId.New(), key, 0, null, null, DateTimeOffset.UtcNow.AddMinutes(5), "test", "execute",
            new("test", "1.0.0", JsonDocument.Parse($$"""{"value":"{{value}}"}""").RootElement.Clone()));

    private static DelegationDto Delegation()
    {
        var now = DateTimeOffset.UtcNow;
        return new(
            DelegationId.New(),
            HostId.New(),
            NodeIncarnationId.New(),
            PlanRevisionId.New(),
            [new(TaskId.New(), 1, 2)],
            new(4, 1024, 2048, 0, 4, 0, 0, 4),
            2,
            4096,
            [new("inference", 100, now.AddHours(1))],
            [],
            now,
            now.AddMinutes(30),
            now.AddMinutes(45),
            now.AddHours(1),
            0);
    }

    private static ExtensionMetadataDto Extension(string kind) =>
        new(kind, "1.0.0", JsonDocument.Parse("{}").RootElement.Clone());

    private static async Task<string> ScalarAsync(SqliteConnection connection, string sql)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToString(await command.ExecuteScalarAsync())!;
    }

    private sealed class TestStore : IDisposable
    {
        public string Directory { get; }
        public SqliteControlStore Store { get; }

        private TestStore(string directory)
        {
            Directory = directory;
            Store = new(Path.Combine(directory, "control.db"));
        }

        public static async Task<TestStore> CreateAsync()
        {
            var result = CreateUninitialized();
            await result.Store.InitializeAsync();
            return result;
        }

        public static TestStore CreateUninitialized()
        {
            var directory = Path.Combine(AppContext.BaseDirectory, "workstream3-tests", Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(directory);
            return new TestStore(directory);
        }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, true);
        }
    }
}
