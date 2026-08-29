using Microsoft.Data.Sqlite;

namespace Steward.Persistence.Sqlite;

public static class SchemaMigrator
{
    public const int CurrentVersion = 3;

    private const string VersionOne = """
        CREATE TABLE IF NOT EXISTS schema_metadata (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL,
            migrated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workloads (
            workload_id TEXT PRIMARY KEY,
            revision INTEGER NOT NULL CHECK (revision >= 0),
            plan_revision_id TEXT,
            desired_state TEXT,
            observed_state TEXT,
            snapshot_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_workloads_state ON workloads(desired_state, observed_state);
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            workload_id TEXT NOT NULL REFERENCES workloads(workload_id) ON DELETE CASCADE,
            plan_revision_id TEXT,
            revision INTEGER NOT NULL CHECK (revision >= 0),
            accepted_generation INTEGER NOT NULL DEFAULT 0,
            desired_state TEXT,
            observed_state TEXT,
            snapshot_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_tasks_workload_state ON tasks(workload_id, observed_state);
        CREATE TABLE IF NOT EXISTS task_attempts (
            attempt_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            generation INTEGER NOT NULL CHECK (generation > 0),
            revision INTEGER NOT NULL CHECK (revision >= 0),
            state TEXT,
            snapshot_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(task_id, generation)
        );
        CREATE INDEX IF NOT EXISTS ix_attempts_task_state ON task_attempts(task_id, state);
        CREATE TABLE IF NOT EXISTS delegations (
            delegation_id TEXT PRIMARY KEY,
            idempotency_key TEXT NOT NULL UNIQUE,
            payload_hash TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            accepted_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS commands (
            command_id TEXT PRIMARY KEY,
            idempotency_key TEXT NOT NULL UNIQUE,
            payload_hash TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            outcome_json TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS aggregate_outbox (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            idempotency_key TEXT UNIQUE,
            payload_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            available_at TEXT NOT NULL,
            acknowledged_at TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_aggregate_outbox_ready ON aggregate_outbox(acknowledged_at, available_at, sequence);
        CREATE TABLE IF NOT EXISTS command_outbox (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id TEXT NOT NULL UNIQUE,
            idempotency_key TEXT NOT NULL UNIQUE,
            payload_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            available_at TEXT NOT NULL,
            acknowledged_at TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_command_outbox_ready ON command_outbox(acknowledged_at, available_at, sequence);
        CREATE TABLE IF NOT EXISTS notification_outbox (
            cursor INTEGER PRIMARY KEY AUTOINCREMENT,
            notification_id TEXT NOT NULL UNIQUE,
            stream TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            acknowledged_at TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_notifications_stream_cursor ON notification_outbox(stream, cursor);
        CREATE TABLE IF NOT EXISTS notification_cursors (
            stream TEXT PRIMARY KEY,
            acknowledged_cursor INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_cursor >= 0),
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS portable_objects (
            portable_object_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
            complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
            store_receipt TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_portable_objects_hash ON portable_objects(content_hash);
        """;

    public static async Task MigrateAsync(SqliteConnection connection, CancellationToken cancellationToken = default)
    {
        await using var transaction = connection.BeginTransaction(deferred: false);
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = VersionOne;
        await command.ExecuteNonQueryAsync(cancellationToken);

        command.CommandText = "SELECT schema_version FROM schema_metadata WHERE singleton = 1;";
        var storedVersion = await command.ExecuteScalarAsync(cancellationToken);
        var version = storedVersion is null ? 0 : Convert.ToInt32(storedVersion);
        if (version > CurrentVersion)
            throw new PersistenceException(PersistenceErrorCode.SchemaVersionMismatch,
                $"Store schema version {version} is newer than supported version {CurrentVersion}.");

        if (version == 0)
        {
            command.CommandText = """
                INSERT INTO schema_metadata(singleton, schema_version, migrated_at)
                VALUES(1, 1, $now);
                """;
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
            command.Parameters.Clear();
            version = 1;
        }

        if (version == 1)
        {
            command.CommandText = "ALTER TABLE notification_outbox ADD COLUMN payload_hash TEXT NOT NULL DEFAULT '';";
            await command.ExecuteNonQueryAsync(cancellationToken);

            command.CommandText = "SELECT cursor, payload_json FROM notification_outbox;";
            var existing = new List<(long Cursor, string Payload)>();
            await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                    existing.Add((reader.GetInt64(0), reader.GetString(1)));
            }

            command.CommandText = "UPDATE notification_outbox SET payload_hash=$hash WHERE cursor=$cursor;";
            var hashParameter = command.Parameters.Add("$hash", SqliteType.Text);
            var cursorParameter = command.Parameters.Add("$cursor", SqliteType.Integer);
            foreach (var row in existing)
            {
                hashParameter.Value = SqliteControlStore.Hash(row.Payload);
                cursorParameter.Value = row.Cursor;
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            command.Parameters.Clear();
            command.CommandText = """
                UPDATE schema_metadata SET schema_version=2, migrated_at=$now WHERE singleton=1;
                """;
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
            version = 2;
        }

        if (version == 2)
        {
            command.Parameters.Clear();
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS workload_requests (
                    idempotency_key TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    workload_id TEXT NOT NULL UNIQUE
                        REFERENCES workloads(workload_id) ON DELETE RESTRICT,
                    status TEXT NOT NULL CHECK (status IN ('completed')),
                    created_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_workload_requests_status
                    ON workload_requests(status, completed_at);
                UPDATE schema_metadata SET schema_version=3, migrated_at=$now WHERE singleton=1;
                """;
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
            version = 3;
        }

        if (version != CurrentVersion)
            throw new PersistenceException(PersistenceErrorCode.SchemaVersionMismatch,
                $"Store schema version {version} could not be migrated to {CurrentVersion}.");
        await transaction.CommitAsync(cancellationToken);
    }
}
