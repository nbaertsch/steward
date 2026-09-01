using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;

namespace Steward.Persistence.Sqlite;

public sealed class SqliteControlStore
{
    private readonly string _connectionString;

    public string DatabasePath { get; }

    public SqliteControlStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        DatabasePath = Path.GetFullPath(databasePath);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await ExecutePragmaScalarAsync(connection, "PRAGMA journal_mode=WAL;", "wal", cancellationToken);
        await SchemaMigrator.MigrateAsync(connection, cancellationToken);
    }

    public async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        try
        {
            await ExecuteAsync(connection, null, """
                PRAGMA foreign_keys=ON;
                PRAGMA busy_timeout=30000;
                PRAGMA synchronous=FULL;
                """, cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    public async Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = "SELECT schema_version FROM schema_metadata WHERE singleton = 1;";
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null ? 0 : Convert.ToInt32(result);
    }

    public Task SaveWorkloadAsync(
        ContractEnvelope<WorkloadDto> snapshot,
        long? expectedRevision,
        IEnumerable<OutboxMessage>? outbox = null,
        CancellationToken cancellationToken = default) =>
        SaveAggregateAsync(
            new AggregateSnapshot(AggregateKind.Workload, snapshot.Payload.WorkloadId.ToString(), snapshot.Revision,
                JsonSerializer.Serialize(snapshot, StewardJson.Options), null, null, snapshot.Payload.ObservedState.ToString()),
            expectedRevision, outbox, cancellationToken);

    public async Task<ContractEnvelope<WorkloadDto>> CreateWorkloadIdempotentAsync(
        ContractEnvelope<WorkloadDto> snapshot,
        string key,
        string normalizedHash,
        IEnumerable<OutboxMessage>? outbox = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedHash);
        var messages = outbox?.ToArray() ?? [];
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        try
        {
            var existing = await ReadWorkloadRequestAsync(connection, transaction, key, cancellationToken);
            if (existing is not null)
            {
                if (!FixedTimeTextEquals(existing.Value.RequestHash, normalizedHash))
                    throw new PersistenceException(PersistenceErrorCode.IdempotencyConflict,
                        $"Workload idempotency key '{key}' was already used with a different request.");
                var persisted = await ReadWorkloadSnapshotAsync(
                    connection, transaction, existing.Value.WorkloadId, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return persisted;
            }

            var aggregate = new AggregateSnapshot(
                AggregateKind.Workload,
                snapshot.Payload.WorkloadId.ToString(),
                snapshot.Revision,
                JsonSerializer.Serialize(snapshot, StewardJson.Options),
                null,
                null,
                snapshot.Payload.ObservedState.ToString());
            var revision = await ReadRevisionAsync(
                connection, transaction, "workloads", "workload_id", aggregate.Id, cancellationToken);
            if (revision is not null || aggregate.Revision < 0)
                throw RevisionConflict(aggregate, null, revision);

            await UpsertAggregateAsync(connection, transaction, aggregate, cancellationToken);
            foreach (var message in messages)
                await InsertOutboxAsync(connection, transaction, message, cancellationToken);

            var now = DateTimeOffset.UtcNow.ToString("O");
            var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO workload_requests(
                    idempotency_key, request_hash, workload_id, status, created_at, completed_at)
                VALUES($key, $hash, $workload, 'completed', $now, $now);
                """;
            insert.Parameters.AddWithValue("$key", key);
            insert.Parameters.AddWithValue("$hash", normalizedHash);
            insert.Parameters.AddWithValue("$workload", snapshot.Payload.WorkloadId.ToString());
            insert.Parameters.AddWithValue("$now", now);
            try
            {
                await insert.ExecuteNonQueryAsync(cancellationToken);
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
            {
                throw new PersistenceException(PersistenceErrorCode.IdempotencyConflict,
                    $"Workload idempotency key '{key}' or workload '{snapshot.Payload.WorkloadId}' is already recorded.",
                    exception);
            }

            await transaction.CommitAsync(cancellationToken);
            return snapshot;
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public Task SaveTaskAsync(
        ContractEnvelope<TaskDto> snapshot,
        long? expectedRevision,
        IEnumerable<OutboxMessage>? outbox = null,
        CancellationToken cancellationToken = default) =>
        SaveAggregateAsync(
            new AggregateSnapshot(AggregateKind.Task, snapshot.Payload.TaskId.ToString(), snapshot.Revision,
                JsonSerializer.Serialize(snapshot, StewardJson.Options), snapshot.Payload.WorkloadId.ToString(),
                snapshot.Payload.AcceptedGeneration, snapshot.Payload.ObservedState.ToString()),
            expectedRevision, outbox, cancellationToken);

    public Task SaveTaskAttemptAsync(
        ContractEnvelope<TaskAttemptDto> snapshot,
        long? expectedRevision,
        IEnumerable<OutboxMessage>? outbox = null,
        CancellationToken cancellationToken = default) =>
        SaveAggregateAsync(
            new AggregateSnapshot(AggregateKind.TaskAttempt, snapshot.Payload.TaskAttemptId.ToString(), snapshot.Revision,
                JsonSerializer.Serialize(snapshot, StewardJson.Options), snapshot.Payload.TaskId.ToString(),
                snapshot.Payload.Generation, snapshot.Payload.State.ToString()),
            expectedRevision, outbox, cancellationToken);

    public async Task<ContractEnvelope<WorkloadDto>?> GetWorkloadAsync(
        WorkloadId id, CancellationToken cancellationToken = default) =>
        await ReadSnapshotAsync<WorkloadDto>("workloads", "workload_id", id.ToString(), cancellationToken);

    public async Task<ContractEnvelope<TaskDto>?> GetTaskAsync(
        TaskId id, CancellationToken cancellationToken = default) =>
        await ReadSnapshotAsync<TaskDto>("tasks", "task_id", id.ToString(), cancellationToken);

    public async Task<ContractEnvelope<TaskAttemptDto>?> GetTaskAttemptAsync(
        TaskAttemptId id, CancellationToken cancellationToken = default) =>
        await ReadSnapshotAsync<TaskAttemptDto>("task_attempts", "attempt_id", id.ToString(), cancellationToken);

    public async Task<ContractEnvelope<TaskAttemptDto>?> GetTaskAttemptByTaskGenerationAsync(
        TaskId taskId,
        int generation,
        CancellationToken cancellationToken = default)
    {
        if (generation <= 0) throw new ArgumentOutOfRangeException(nameof(generation));
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT snapshot_json FROM task_attempts
            WHERE task_id=$task AND generation=$generation
            """;
        command.Parameters.AddWithValue("$task", taskId.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return json is null ? null :
            JsonSerializer.Deserialize<ContractEnvelope<TaskAttemptDto>>(json, StewardJson.Options)
            ?? throw new InvalidDataException("Stored TaskAttempt snapshot is invalid.");
    }

    public async Task<ContractEnvelope<TaskAttemptDto>?> GetLatestTaskAttemptByTaskAsync(
        TaskId taskId, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT snapshot_json FROM task_attempts
            WHERE task_id=$task
            ORDER BY generation DESC LIMIT 1
            """;
        command.Parameters.AddWithValue("$task", taskId.ToString());
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return json is null ? null :
            JsonSerializer.Deserialize<ContractEnvelope<TaskAttemptDto>>(json, StewardJson.Options)
            ?? throw new InvalidDataException("Stored TaskAttempt snapshot is invalid.");
    }

    public Task<IReadOnlyList<ContractEnvelope<WorkloadDto>>> ListWorkloadsAsync(
        int limit = 1000,
        CancellationToken cancellationToken = default) =>
        ReadSnapshotsAsync<WorkloadDto>(
            "SELECT snapshot_json FROM workloads ORDER BY updated_at DESC,workload_id LIMIT $limit",
            limit,
            cancellationToken);

    public Task<IReadOnlyList<ContractEnvelope<TaskDto>>> ListTasksAsync(
        int limit = 1000,
        CancellationToken cancellationToken = default) =>
        ReadSnapshotsAsync<TaskDto>(
            "SELECT snapshot_json FROM tasks ORDER BY updated_at DESC,task_id LIMIT $limit",
            limit,
            cancellationToken);

    public Task<IReadOnlyList<ContractEnvelope<TaskAttemptDto>>> ListTaskAttemptsAsync(
        int limit = 1000,
        CancellationToken cancellationToken = default) =>
        ReadSnapshotsAsync<TaskAttemptDto>(
            "SELECT snapshot_json FROM task_attempts ORDER BY updated_at DESC,attempt_id LIMIT $limit",
            limit,
            cancellationToken);

    public async Task<IReadOnlyList<PortableObjectReceipt>> ListPortableObjectsAsync(
        int limit = 1000,
        CancellationToken cancellationToken = default)
    {
        if (limit is <= 0 or > 5000)
            throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT portable_object_id,kind,content_hash,size_bytes,complete,
                   store_receipt,metadata_json,created_at
            FROM portable_objects ORDER BY created_at DESC,portable_object_id
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$limit", limit);
        var values = new List<PortableObjectReceipt>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            values.Add(new(
                PortableObjectId.Parse(reader.GetString(0)),
                Enum.Parse<PortableObjectKind>(reader.GetString(1)),
                reader.GetString(2),
                reader.GetInt64(3),
                reader.GetBoolean(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.GetString(6),
                DateTimeOffset.Parse(reader.GetString(7))));
        return values;
    }

    public async Task SaveAggregateAsync(
        AggregateSnapshot snapshot,
        long? expectedRevision,
        IEnumerable<OutboxMessage>? outbox = null,
        CancellationToken cancellationToken = default)
    {
        var messages = outbox?.ToArray() ?? [];
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        try
        {
            var (table, idColumn) = TableFor(snapshot.Kind);
            var existing = await ReadRevisionAsync(connection, transaction, table, idColumn, snapshot.Id, cancellationToken);
            if (expectedRevision is null ? existing is not null : existing != expectedRevision)
                throw RevisionConflict(snapshot, expectedRevision, existing);
            if (snapshot.Revision < 0 || (existing is not null && snapshot.Revision <= existing))
                throw RevisionConflict(snapshot, expectedRevision, existing);

            await UpsertAggregateAsync(connection, transaction, snapshot, cancellationToken);
            foreach (var message in messages)
                await InsertOutboxAsync(connection, transaction, message, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    private async Task<IReadOnlyList<ContractEnvelope<T>>> ReadSnapshotsAsync<T>(
        string sql,
        int limit,
        CancellationToken cancellationToken)
    {
        if (limit is <= 0 or > 5000)
            throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$limit", limit);
        var values = new List<ContractEnvelope<T>>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            values.Add(JsonSerializer.Deserialize<ContractEnvelope<T>>(
                reader.GetString(0),
                StewardJson.Options)
                ?? throw new InvalidDataException(
                    $"Stored {typeof(T).Name} snapshot is invalid."));
        return values;
    }

    public async Task<long> EnqueueCommandAsync(
        CommandDto command,
        DateTimeOffset? availableAt = null,
        CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(command, StewardJson.Options);
        var hash = Hash(json);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            var existing = await ReadIdempotentAsync(connection, transaction, "command_outbox", command.IdempotencyKey, cancellationToken);
            if (existing is { } found)
            {
                if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(found.Hash), Convert.FromHexString(hash)))
                    throw new PersistenceException(PersistenceErrorCode.IdempotencyConflict,
                        $"Idempotency key '{command.IdempotencyKey}' was already used with a different payload.");
                await transaction.CommitAsync(cancellationToken);
                return found.Sequence;
            }

            var dbCommand = connection.CreateCommand();
            dbCommand.Transaction = transaction;
            dbCommand.CommandText = """
                INSERT INTO command_outbox(command_id, idempotency_key, payload_hash, payload_json, created_at, available_at)
                VALUES($id, $key, $hash, $json, $now, $available);
                SELECT last_insert_rowid();
                """;
            dbCommand.Parameters.AddWithValue("$id", command.CommandId.ToString());
            dbCommand.Parameters.AddWithValue("$key", command.IdempotencyKey);
            dbCommand.Parameters.AddWithValue("$hash", hash);
            dbCommand.Parameters.AddWithValue("$json", json);
            dbCommand.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            dbCommand.Parameters.AddWithValue("$available", (availableAt ?? DateTimeOffset.UtcNow).ToString("O"));
            var sequence = Convert.ToInt64(await dbCommand.ExecuteScalarAsync(cancellationToken));
            await transaction.CommitAsync(cancellationToken);
            return sequence;
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public async Task<IReadOnlyList<CommandOutboxItem>> DequeueCommandsAsync(
        int limit = 100, DateTimeOffset? now = null, CancellationToken cancellationToken = default)
    {
        if (limit is <= 0 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT sequence, command_id, idempotency_key, payload_json, created_at, available_at, acknowledged_at
            FROM command_outbox
            WHERE acknowledged_at IS NULL AND available_at <= $now
            ORDER BY sequence LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$now", (now ?? DateTimeOffset.UtcNow).ToString("O"));
        command.Parameters.AddWithValue("$limit", limit);
        var result = new List<CommandOutboxItem>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(new(reader.GetInt64(0), CommandId.Parse(reader.GetString(1)), reader.GetString(2), reader.GetString(3),
                DateTimeOffset.Parse(reader.GetString(4)), DateTimeOffset.Parse(reader.GetString(5)),
                reader.IsDBNull(6) ? null : DateTimeOffset.Parse(reader.GetString(6))));
        return result;
    }

    public Task AcknowledgeCommandAsync(long sequence, CancellationToken cancellationToken = default) =>
        AcknowledgeBySequenceAsync("command_outbox", "sequence", sequence, cancellationToken);

    public async Task EnqueueOutboxAsync(
        OutboxMessage message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        await using var connection = await OpenConnectionAsync(
                cancellationToken)
            .ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(
            deferred: false);
        try
        {
            await InsertOutboxAsync(
                    connection,
                    transaction,
                    message,
                    cancellationToken)
                .ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken)
                .ConfigureAwait(false);
            throw;
        }
    }

    public async Task<IReadOnlyList<AggregateOutboxItem>> ReadOutboxAsync(
        int limit = 100, DateTimeOffset? now = null, CancellationToken cancellationToken = default)
    {
        if (limit is <= 0 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT sequence,message_id,kind,payload_json,created_at,available_at,acknowledged_at
            FROM aggregate_outbox
            WHERE acknowledged_at IS NULL AND available_at <= $now
            ORDER BY sequence LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$now", (now ?? DateTimeOffset.UtcNow).ToString("O"));
        command.Parameters.AddWithValue("$limit", limit);
        var result = new List<AggregateOutboxItem>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(new(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                DateTimeOffset.Parse(reader.GetString(4)), DateTimeOffset.Parse(reader.GetString(5)),
                reader.IsDBNull(6) ? null : DateTimeOffset.Parse(reader.GetString(6))));
        return result;
    }

    public Task AcknowledgeOutboxAsync(long sequence, CancellationToken cancellationToken = default) =>
        AcknowledgeBySequenceAsync("aggregate_outbox", "sequence", sequence, cancellationToken);

    public async Task RecordDelegationAsync(
        DelegationDto delegation,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(idempotencyKey);
        var json = JsonSerializer.Serialize(delegation, StewardJson.Options);
        await RecordIdempotentDocumentAsync(
            "delegations", "delegation_id", delegation.DelegationId.ToString(), idempotencyKey,
            json, delegation.AcceptedAt, cancellationToken);
    }

    public async Task<long> AppendNotificationAsync<TPayload>(
        NotificationId notificationId,
        string stream,
        TPayload payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stream);
        var json = JsonSerializer.Serialize(payload, StewardJson.Options);
        var hash = Hash(json);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        try
        {
            var existing = await ReadNotificationIdentityAsync(
                connection, transaction, notificationId, cancellationToken);
            if (existing is not null)
            {
                EnsureNotificationIdentityMatches(notificationId, stream, hash, json, existing.Value);
                await transaction.CommitAsync(cancellationToken);
                return existing.Value.Cursor;
            }

            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO notification_outbox(notification_id, stream, payload_hash, payload_json, created_at)
                VALUES($id, $stream, $hash, $json, $now)
                RETURNING cursor;
                """;
            command.Parameters.AddWithValue("$id", notificationId.ToString());
            command.Parameters.AddWithValue("$stream", stream);
            command.Parameters.AddWithValue("$hash", hash);
            command.Parameters.AddWithValue("$json", json);
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            var cursor = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
            await transaction.CommitAsync(cancellationToken);
            return cursor;
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public async Task<IReadOnlyList<NotificationOutboxItem>> ReadNotificationsAsync(
        string stream, long afterCursor, int limit = 100, CancellationToken cancellationToken = default)
    {
        if (afterCursor < 0) throw new ArgumentOutOfRangeException(nameof(afterCursor));
        if (limit is <= 0 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT cursor, notification_id, stream, payload_json, created_at, acknowledged_at
            FROM notification_outbox WHERE stream = $stream AND cursor > $cursor
            ORDER BY cursor LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$stream", stream);
        command.Parameters.AddWithValue("$cursor", afterCursor);
        command.Parameters.AddWithValue("$limit", limit);
        var result = new List<NotificationOutboxItem>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(new(reader.GetInt64(0), NotificationId.Parse(reader.GetString(1)), reader.GetString(2), reader.GetString(3),
                DateTimeOffset.Parse(reader.GetString(4)), reader.IsDBNull(5) ? null : DateTimeOffset.Parse(reader.GetString(5))));
        return result;
    }

    public async Task AcknowledgeNotificationsAsync(
        string stream, long throughCursor, CancellationToken cancellationToken = default)
    {
        if (throughCursor < 0) throw new ArgumentOutOfRangeException(nameof(throughCursor));
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO notification_cursors(stream, acknowledged_cursor, updated_at)
            VALUES($stream, $cursor, $now)
            ON CONFLICT(stream) DO UPDATE SET
              acknowledged_cursor = CASE WHEN acknowledged_cursor < excluded.acknowledged_cursor THEN excluded.acknowledged_cursor ELSE acknowledged_cursor END,
              updated_at = excluded.updated_at;
            UPDATE notification_outbox SET acknowledged_at = COALESCE(acknowledged_at, $now)
            WHERE stream = $stream AND cursor <= $cursor;
            """;
        command.Parameters.AddWithValue("$stream", stream);
        command.Parameters.AddWithValue("$cursor", throughCursor);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<long> GetAcknowledgedNotificationCursorAsync(
        string stream, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = "SELECT acknowledged_cursor FROM notification_cursors WHERE stream = $stream;";
        command.Parameters.AddWithValue("$stream", stream);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null ? 0 : Convert.ToInt64(result);
    }

    public async Task CatalogPortableObjectAsync(
        PortableObjectDto value, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(value, StewardJson.Options);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO portable_objects(portable_object_id, kind, content_hash, size_bytes, complete, store_receipt, metadata_json, created_at)
            VALUES($id, $kind, $hash, $size, $complete, $receipt, $json, $created)
            ON CONFLICT(portable_object_id) DO UPDATE SET
              kind=excluded.kind, content_hash=excluded.content_hash, size_bytes=excluded.size_bytes,
              complete=excluded.complete, store_receipt=excluded.store_receipt, metadata_json=excluded.metadata_json
            WHERE portable_objects.content_hash=excluded.content_hash AND portable_objects.size_bytes=excluded.size_bytes;
            """;
        command.Parameters.AddWithValue("$id", value.PortableObjectId.ToString());
        command.Parameters.AddWithValue("$kind", value.Kind.ToString());
        command.Parameters.AddWithValue("$hash", value.ContentHash);
        command.Parameters.AddWithValue("$size", value.SizeBytes);
        command.Parameters.AddWithValue("$complete", value.Complete);
        command.Parameters.AddWithValue("$receipt", (object?)value.StoreReceipt ?? DBNull.Value);
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue("$created", value.CreatedAt.ToString("O"));
        var changed = await command.ExecuteNonQueryAsync(cancellationToken);
        if (changed == 0)
            throw new PersistenceException(PersistenceErrorCode.IdempotencyConflict,
                $"Portable object '{value.PortableObjectId}' already has different content metadata.");
    }

    public async Task<PortableObjectReceipt?> GetPortableObjectAsync(
        PortableObjectId id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT kind, content_hash, size_bytes, complete, store_receipt, metadata_json, created_at
            FROM portable_objects WHERE portable_object_id=$id;
            """;
        command.Parameters.AddWithValue("$id", id.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new(id, Enum.Parse<PortableObjectKind>(reader.GetString(0)), reader.GetString(1), reader.GetInt64(2),
            reader.GetBoolean(3), reader.IsDBNull(4) ? null : reader.GetString(4), reader.GetString(5),
            DateTimeOffset.Parse(reader.GetString(6)));
    }

    private async Task<ContractEnvelope<T>?> ReadSnapshotAsync<T>(
        string table, string idColumn, string id, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = $"SELECT snapshot_json FROM {table} WHERE {idColumn} = $id;";
        command.Parameters.AddWithValue("$id", id);
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return json is null ? null : JsonSerializer.Deserialize<ContractEnvelope<T>>(json, StewardJson.Options)
            ?? throw new JsonException($"Stored {typeof(T).Name} snapshot was null.");
    }

    private static async Task<(string RequestHash, string WorkloadId)?> ReadWorkloadRequestAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string key,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT request_hash, workload_id
            FROM workload_requests
            WHERE idempotency_key=$key AND status='completed';
            """;
        command.Parameters.AddWithValue("$key", key);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? (reader.GetString(0), reader.GetString(1))
            : null;
    }

    private static async Task<ContractEnvelope<WorkloadDto>> ReadWorkloadSnapshotAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string workloadId,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT snapshot_json FROM workloads WHERE workload_id=$id;";
        command.Parameters.AddWithValue("$id", workloadId);
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        if (json is null)
            throw new PersistenceException(PersistenceErrorCode.NotFound,
                $"Completed workload request references missing workload '{workloadId}'.");
        return JsonSerializer.Deserialize<ContractEnvelope<WorkloadDto>>(json, StewardJson.Options)
            ?? throw new JsonException("Stored Workload snapshot was null.");
    }

    private static async Task UpsertAggregateAsync(
        SqliteConnection connection, SqliteTransaction transaction, AggregateSnapshot snapshot, CancellationToken token)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        var now = DateTimeOffset.UtcNow.ToString("O");
        switch (snapshot.Kind)
        {
            case AggregateKind.Workload:
                var workload = JsonSerializer.Deserialize<ContractEnvelope<WorkloadDto>>(snapshot.SnapshotJson, StewardJson.Options)
                    ?? throw new JsonException("Invalid workload snapshot.");
                command.CommandText = """
                    INSERT INTO workloads(workload_id, revision, plan_revision_id, desired_state, observed_state, snapshot_json, updated_at)
                    VALUES($id,$revision,$plan,$desired,$state,$json,$now)
                    ON CONFLICT(workload_id) DO UPDATE SET revision=excluded.revision,plan_revision_id=excluded.plan_revision_id,
                    desired_state=excluded.desired_state,observed_state=excluded.observed_state,snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at;
                    """;
                command.Parameters.AddWithValue("$plan", workload.Payload.PlanRevisionId.ToString());
                command.Parameters.AddWithValue("$desired", workload.Payload.DesiredState.ToString());
                break;
            case AggregateKind.Task:
                var task = JsonSerializer.Deserialize<ContractEnvelope<TaskDto>>(snapshot.SnapshotJson, StewardJson.Options)
                    ?? throw new JsonException("Invalid task snapshot.");
                command.CommandText = """
                    INSERT INTO tasks(task_id, workload_id, plan_revision_id, revision, accepted_generation, desired_state, observed_state, snapshot_json, updated_at)
                    VALUES($id,$parent,$plan,$revision,$generation,$desired,$state,$json,$now)
                    ON CONFLICT(task_id) DO UPDATE SET workload_id=excluded.workload_id,plan_revision_id=excluded.plan_revision_id,
                    revision=excluded.revision,accepted_generation=excluded.accepted_generation,desired_state=excluded.desired_state,
                    observed_state=excluded.observed_state,snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at;
                    """;
                command.Parameters.AddWithValue("$parent", snapshot.ParentId!);
                command.Parameters.AddWithValue("$plan", task.Payload.PlanRevisionId.ToString());
                command.Parameters.AddWithValue("$generation", snapshot.Generation ?? 0);
                command.Parameters.AddWithValue("$desired", task.Payload.DesiredState.ToString());
                break;
            case AggregateKind.TaskAttempt:
                command.CommandText = """
                    INSERT INTO task_attempts(attempt_id, task_id, generation, revision, state, snapshot_json, updated_at)
                    VALUES($id,$parent,$generation,$revision,$state,$json,$now)
                    ON CONFLICT(attempt_id) DO UPDATE SET task_id=excluded.task_id,generation=excluded.generation,
                    revision=excluded.revision,state=excluded.state,snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at;
                    """;
                command.Parameters.AddWithValue("$parent", snapshot.ParentId!);
                command.Parameters.AddWithValue("$generation", snapshot.Generation!.Value);
                break;
            default: throw new ArgumentOutOfRangeException(nameof(snapshot));
        }
        command.Parameters.AddWithValue("$id", snapshot.Id);
        command.Parameters.AddWithValue("$revision", snapshot.Revision);
        command.Parameters.AddWithValue("$state", (object?)snapshot.State ?? DBNull.Value);
        command.Parameters.AddWithValue("$json", snapshot.SnapshotJson);
        command.Parameters.AddWithValue("$now", now);
        await command.ExecuteNonQueryAsync(token);
    }

    private static async Task InsertOutboxAsync(
        SqliteConnection connection, SqliteTransaction transaction, OutboxMessage message, CancellationToken token)
    {
        var hash = Hash(message.PayloadJson);
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO aggregate_outbox(message_id,kind,idempotency_key,payload_hash,payload_json,created_at,available_at)
            VALUES($id,$kind,$key,$hash,$json,$now,$available);
            """;
        command.Parameters.AddWithValue("$id", message.MessageId);
        command.Parameters.AddWithValue("$kind", message.Kind);
        command.Parameters.AddWithValue("$key", (object?)message.IdempotencyKey ?? DBNull.Value);
        command.Parameters.AddWithValue("$hash", hash);
        command.Parameters.AddWithValue("$json", message.PayloadJson);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$available", (message.AvailableAt ?? DateTimeOffset.UtcNow).ToString("O"));
        try
        {
            await command.ExecuteNonQueryAsync(token);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
        {
            throw new PersistenceException(PersistenceErrorCode.IdempotencyConflict,
                $"Outbox message or idempotency key '{message.IdempotencyKey ?? message.MessageId}' already exists.", exception);
        }
    }

    private async Task AcknowledgeBySequenceAsync(
        string table, string column, long sequence, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = $"UPDATE {table} SET acknowledged_at=COALESCE(acknowledged_at,$now) WHERE {column}=$sequence;";
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$sequence", sequence);
        if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            throw new PersistenceException(PersistenceErrorCode.NotFound, $"Outbox sequence {sequence} was not found.");
    }

    private async Task RecordIdempotentDocumentAsync(
        string table, string idColumn, string id, string key, string json, DateTimeOffset acceptedAt,
        CancellationToken cancellationToken)
    {
        var hash = Hash(json);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        try
        {
            var existing = await ReadIdempotentDocumentAsync(
                connection, transaction, table, key, cancellationToken);
            if (existing is not null)
            {
                EnsureIdempotentDocumentMatches(key, hash, json, existing.Value);
                await transaction.CommitAsync(cancellationToken);
                return;
            }

            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"""
                INSERT INTO {table}({idColumn},idempotency_key,payload_hash,snapshot_json,accepted_at,created_at)
                VALUES($id,$key,$hash,$json,$accepted,$now);
                """;
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$key", key);
            command.Parameters.AddWithValue("$hash", hash);
            command.Parameters.AddWithValue("$json", json);
            command.Parameters.AddWithValue("$accepted", acceptedAt.ToString("O"));
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            try
            {
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
            {
                existing = await ReadIdempotentDocumentAsync(
                    connection, transaction, table, key, cancellationToken);
                if (existing is null)
                    throw new PersistenceException(PersistenceErrorCode.IdempotencyConflict,
                        $"Document identity or idempotency key '{key}' already exists.", exception);
                EnsureIdempotentDocumentMatches(key, hash, json, existing.Value);
            }
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    private static async Task<(string Hash, string Json)?> ReadIdempotentDocumentAsync(
        SqliteConnection connection, SqliteTransaction transaction, string table, string key, CancellationToken token)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT payload_hash,snapshot_json FROM {table} WHERE idempotency_key=$key;";
        command.Parameters.AddWithValue("$key", key);
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token) ? (reader.GetString(0), reader.GetString(1)) : null;
    }

    private static void EnsureIdempotentDocumentMatches(
        string key, string hash, string json, (string Hash, string Json) existing)
    {
        if (!FixedTimeHashEquals(existing.Hash, hash) ||
            !string.Equals(existing.Json, json, StringComparison.Ordinal))
            throw new PersistenceException(PersistenceErrorCode.IdempotencyConflict,
                $"Idempotency key '{key}' was already used with a different payload.");
    }

    private static async Task<(long Cursor, string Stream, string Hash, string Json)?> ReadNotificationIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        NotificationId notificationId,
        CancellationToken token)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT cursor,stream,payload_hash,payload_json
            FROM notification_outbox WHERE notification_id=$id;
            """;
        command.Parameters.AddWithValue("$id", notificationId.ToString());
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token)
            ? (reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3))
            : null;
    }

    private static void EnsureNotificationIdentityMatches(
        NotificationId notificationId,
        string stream,
        string hash,
        string json,
        (long Cursor, string Stream, string Hash, string Json) existing)
    {
        if (!string.Equals(existing.Stream, stream, StringComparison.Ordinal) ||
            !FixedTimeHashEquals(existing.Hash, hash) ||
            !string.Equals(existing.Json, json, StringComparison.Ordinal))
            throw new PersistenceException(PersistenceErrorCode.IdempotencyConflict,
                $"Notification ID '{notificationId}' was already used with a different stream or payload.");
    }

    private static bool FixedTimeHashEquals(string left, string right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));

    private static bool FixedTimeTextEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length &&
            CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static async Task<(long Sequence, string Hash)?> ReadIdempotentAsync(
        SqliteConnection connection, SqliteTransaction transaction, string table, string key, CancellationToken token)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT sequence,payload_hash FROM {table} WHERE idempotency_key=$key;";
        command.Parameters.AddWithValue("$key", key);
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token) ? (reader.GetInt64(0), reader.GetString(1)) : null;
    }

    private static async Task<long?> ReadRevisionAsync(
        SqliteConnection connection, SqliteTransaction transaction, string table, string idColumn, string id, CancellationToken token)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT revision FROM {table} WHERE {idColumn}=$id;";
        command.Parameters.AddWithValue("$id", id);
        var result = await command.ExecuteScalarAsync(token);
        return result is null ? null : Convert.ToInt64(result);
    }

    private static (string Table, string IdColumn) TableFor(AggregateKind kind) => kind switch
    {
        AggregateKind.Workload => ("workloads", "workload_id"),
        AggregateKind.Task => ("tasks", "task_id"),
        AggregateKind.TaskAttempt => ("task_attempts", "attempt_id"),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    private static PersistenceException RevisionConflict(AggregateSnapshot snapshot, long? expected, long? actual) =>
        new(PersistenceErrorCode.RevisionConflict,
            $"{snapshot.Kind} '{snapshot.Id}' expected revision {expected?.ToString() ?? "<new>"} but found {actual?.ToString() ?? "<missing>"}.");

    internal static string Hash(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    private static async Task ExecutePragmaScalarAsync(
        SqliteConnection connection, string sql, string expected, CancellationToken token)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        var actual = Convert.ToString(await command.ExecuteScalarAsync(token));
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"SQLite pragma returned '{actual}', expected '{expected}'.");
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken token)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(token);
    }
}
