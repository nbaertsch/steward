using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Steward.Domain;

namespace Steward.Agents;

public interface IAgentStore : IParentNotificationOutbox, IAsyncDisposable
{
    Task<IReadOnlyList<AgentDescriptor>> ListAsync(
        CancellationToken cancellationToken = default);

    Task<AgentDescriptor> CreateAsync(
        StewardAgentId agentId, AgentRuntimeDescriptor runtime, string? parentRoute = null,
        CancellationToken cancellationToken = default);
    Task<AgentDescriptor?> GetAsync(StewardAgentId agentId, CancellationToken cancellationToken = default);
    Task<AgentTurnRecord> SubmitTurnAsync(
        StewardAgentId agentId, AgentTurnRequest request, CancellationToken cancellationToken = default);
    Task<AgentTurnRecord?> GetTurnAsync(
        StewardAgentId agentId, AgentTurnId turnId, CancellationToken cancellationToken = default);
    Task<AgentTurnRecord?> TryClaimNextAsync(
        StewardAgentId agentId, Guid ownerId, DateTimeOffset now, bool permitsParallel,
        CancellationToken cancellationToken = default);
    Task<bool> TryAcquireRuntimeOwnershipAsync(
        StewardAgentId agentId, Guid ownerId, DateTimeOffset now, TimeSpan leaseDuration,
        CancellationToken cancellationToken = default);
    Task<bool> TryRenewRuntimeOwnershipAsync(
        StewardAgentId agentId, Guid ownerId, DateTimeOffset now, TimeSpan leaseDuration,
        CancellationToken cancellationToken = default);
    Task<int> RecoverAbandonedTurnsAsync(
        StewardAgentId agentId, Guid recoveringOwnerId, DateTimeOffset now,
        CancellationToken cancellationToken = default);
    Task SetExecutionAsync(
        StewardAgentId agentId, AgentTurnId turnId, ManagedAgentExecution execution,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AgentTurnRecord>> ReadRecoveringTurnsAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default);
    Task ResolveRecoveryAsync(
        StewardAgentId agentId, AgentTurnId turnId, ManagedExecutionStatus status,
        CancellationToken cancellationToken = default);
    Task AppendActivityAsync(
        StewardAgentId agentId, AgentTurnId turnId, AgentActivity activity,
        CancellationToken cancellationToken = default);
    Task CompleteAsync(
        StewardAgentId agentId, AgentTurnId turnId, string response,
        CancellationToken cancellationToken = default);
    Task SavePendingResultAsync(
        StewardAgentId agentId, AgentTurnId turnId, ManagedAgentExecution execution, string response,
        CancellationToken cancellationToken = default);
    Task<PendingAgentResult?> GetPendingResultAsync(
        StewardAgentId agentId, AgentTurnId turnId, CancellationToken cancellationToken = default);
    Task MarkPendingResultReportedAsync(
        StewardAgentId agentId, AgentTurnId turnId, Guid executionLeaseId,
        CancellationToken cancellationToken = default);
    Task FinalizePendingResultAsync(
        StewardAgentId agentId, AgentTurnId turnId, Guid executionLeaseId,
        CancellationToken cancellationToken = default);
    Task FailAsync(
        StewardAgentId agentId, AgentTurnId turnId, string errorCode, string? safeDetail,
        CancellationToken cancellationToken = default);
    Task<bool> CancelAsync(
        StewardAgentId agentId, AgentTurnId turnId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ContextRecord>> ReadContextAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default);
    Task AppendContextAsync(
        StewardAgentId agentId, string text, TextProvenance provenance,
        CancellationToken cancellationToken = default);
    Task CompactContextAsync(
        StewardAgentId agentId, ContextBudget budget, IContextCompactor compactor,
        CancellationToken cancellationToken = default);
    Task<bool> TrySetFrozenAsync(
        StewardAgentId agentId, bool frozen, long expectedRevision, CancellationToken cancellationToken = default);
    Task<AgentMigrationState?> BeginMigrationAsync(
        StewardAgentId agentId, HostId destinationHostId, long expectedRevision,
        CancellationToken cancellationToken = default);
    Task FinishMigrationAsync(
        Guid migrationId, StewardAgentId agentId, string state, bool unfreeze,
        CancellationToken cancellationToken = default);
    Task<AgentMigrationState?> GetMigrationAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AgentTurnRecord>> ReadPendingTurnsAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default);
    Task ImportCheckpointAsync(
        StewardAgentId agentId,
        IReadOnlyList<ContextRecord> context,
        IReadOnlyList<AgentTurnRecord> pendingTurns,
        CancellationToken cancellationToken = default);
    Task StageCheckpointAsync(
        Guid stageId, StewardAgentId agentId, byte[] contextJson, byte[] pendingTurnsJson,
        CancellationToken cancellationToken = default);
    Task<(byte[] ContextJson, byte[] PendingTurnsJson)?> ReadCheckpointStageAsync(
        Guid stageId, StewardAgentId agentId, CancellationToken cancellationToken = default);
    Task RemoveCheckpointStageAsync(
        Guid stageId, StewardAgentId agentId, CancellationToken cancellationToken = default);
}

public sealed class SqliteAgentStore : IAgentStore
{
    public const int CurrentSchemaVersion = 6;
    private readonly string _connectionString;

    public async Task<bool> HasActiveExecutionOnHostAsync(
        HostId hostId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*) FROM turns
            WHERE host_id=$host
              AND status IN ($dispatching,$running,$recovering)
            """;
        command.Parameters.AddWithValue("$host", hostId.ToString());
        command.Parameters.AddWithValue("$dispatching", (int)AgentTurnStatus.Dispatching);
        command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) > 0;
    }

    public async Task<IReadOnlyList<StewardAgentId>> ListAgentIdsAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT agent_id FROM agents ORDER BY agent_id";
        var values = new List<StewardAgentId>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            values.Add(StewardAgentId.Parse(reader.GetString(0)));
        return values;
    }

    public async Task<IReadOnlyList<AgentDescriptor>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        var values = new List<AgentDescriptor>();
        foreach (var id in await ListAgentIdsAsync(cancellationToken))
            values.Add(await GetAsync(id, cancellationToken)
                ?? throw new AgentStoreException(
                    "An Agent disappeared while reading the operations snapshot."));
        return values;
    }

    public SqliteAgentStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString();
        Initialize();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=30000;";
            command.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private void Initialize()
    {
        try
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS agent_schema(version INTEGER NOT NULL);
                INSERT INTO agent_schema(version) SELECT 0 WHERE NOT EXISTS(SELECT 1 FROM agent_schema);
                """;
            command.ExecuteNonQuery();
            command.CommandText = "SELECT version FROM agent_schema LIMIT 1";
            var version = Convert.ToInt32(command.ExecuteScalar());
            if (version is < 0 or > CurrentSchemaVersion)
                throw new AgentStoreException($"Agent schema version {version} is unsupported; expected {CurrentSchemaVersion}.");
            if (version == 0)
            {
                using var transaction = connection.BeginTransaction();
                command.Transaction = transaction;
                command.CommandText = """
                    CREATE TABLE agents(
                      agent_id TEXT PRIMARY KEY, runtime_name TEXT NOT NULL, runtime_version TEXT NOT NULL,
                      parallel_turns INTEGER NOT NULL, parent_route TEXT NULL, revision INTEGER NOT NULL,
                      response_cursor INTEGER NOT NULL, notification_cursor INTEGER NOT NULL,
                      placement_generation INTEGER NOT NULL, frozen INTEGER NOT NULL);
                    CREATE TABLE turns(
                      agent_id TEXT NOT NULL, turn_id TEXT NOT NULL, body_hash TEXT NOT NULL, text TEXT NOT NULL,
                      provenance INTEGER NOT NULL, client_request_id TEXT NULL,owner_id TEXT NULL,
                      status INTEGER NOT NULL, queue_sequence INTEGER NOT NULL,
                      response_sequence INTEGER NULL, response TEXT NULL, error TEXT NULL,
                      workload_id TEXT NULL, task_id TEXT NULL,
                      error_code TEXT NULL, safe_error_detail TEXT NULL,
                      lease_id TEXT NULL, attempt_id TEXT NULL, attempt_generation INTEGER NULL,
                      host_id TEXT NULL, node_incarnation_id TEXT NULL, accepted_at TEXT NULL,
                      PRIMARY KEY(agent_id,turn_id), UNIQUE(agent_id,queue_sequence),
                      FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE context_records(
                      agent_id TEXT NOT NULL, sequence INTEGER NOT NULL, text TEXT NOT NULL,
                      provenance INTEGER NOT NULL, token_estimate INTEGER NOT NULL,
                      checkpoint_id TEXT NULL, parent_checkpoint_id TEXT NULL, summary_sha256 TEXT NULL,
                      PRIMARY KEY(agent_id,sequence), FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE activities(
                      agent_id TEXT NOT NULL, turn_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                      text TEXT NOT NULL, provenance INTEGER NOT NULL,
                      PRIMARY KEY(agent_id,turn_id,sequence));
                    CREATE TABLE notifications(
                      agent_id TEXT NOT NULL, sequence INTEGER NOT NULL, turn_id TEXT NOT NULL,
                      kind TEXT NOT NULL, payload TEXT NOT NULL, provenance INTEGER NOT NULL,
                      PRIMARY KEY(agent_id,sequence), FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE INDEX turns_ready ON turns(agent_id,status,queue_sequence);
                    CREATE TABLE checkpoint_stages(
                      stage_id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,context_json BLOB NOT NULL,
                      pending_turns_json BLOB NOT NULL,created_at TEXT NOT NULL,
                      FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE agent_migrations(
                      agent_id TEXT PRIMARY KEY,migration_id TEXT NOT NULL,destination_host_id TEXT NOT NULL,
                      state TEXT NOT NULL,started_at TEXT NOT NULL,
                      FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE pending_agent_results(
                      agent_id TEXT NOT NULL,turn_id TEXT NOT NULL,lease_id TEXT NOT NULL,
                      response TEXT NOT NULL,terminal_reported INTEGER NOT NULL,
                      PRIMARY KEY(agent_id,turn_id),FOREIGN KEY(agent_id,turn_id) REFERENCES turns(agent_id,turn_id));
                    CREATE TABLE agent_runtime_owners(
                      agent_id TEXT NOT NULL,owner_id TEXT NOT NULL,acquired_at TEXT NOT NULL,
                      renewed_at TEXT NOT NULL,expires_at TEXT NOT NULL,
                      PRIMARY KEY(agent_id,owner_id),FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    UPDATE agent_schema SET version=6;
                    """;
                command.ExecuteNonQuery();
                transaction.Commit();
            }
            else if (version == 1)
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                command.Transaction = transaction;
                command.CommandText = """
                    ALTER TABLE turns ADD COLUMN error_code TEXT NULL;
                    ALTER TABLE turns ADD COLUMN safe_error_detail TEXT NULL;
                    ALTER TABLE turns ADD COLUMN lease_id TEXT NULL;
                    ALTER TABLE turns ADD COLUMN attempt_id TEXT NULL;
                    ALTER TABLE turns ADD COLUMN attempt_generation INTEGER NULL;
                    ALTER TABLE turns ADD COLUMN host_id TEXT NULL;
                    ALTER TABLE turns ADD COLUMN node_incarnation_id TEXT NULL;
                    ALTER TABLE turns ADD COLUMN accepted_at TEXT NULL;
                    ALTER TABLE turns ADD COLUMN client_request_id TEXT NULL;
                    UPDATE turns SET status=CASE status
                      WHEN 1 THEN 3
                      WHEN 2 THEN 4
                      WHEN 3 THEN 5
                      WHEN 4 THEN 6
                      ELSE status END;
                    CREATE TABLE checkpoint_stages(
                      stage_id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,context_json BLOB NOT NULL,
                      pending_turns_json BLOB NOT NULL,created_at TEXT NOT NULL,
                      FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE agent_migrations(
                      agent_id TEXT PRIMARY KEY,migration_id TEXT NOT NULL,destination_host_id TEXT NOT NULL,
                      state TEXT NOT NULL,started_at TEXT NOT NULL,
                      FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE pending_agent_results(
                      agent_id TEXT NOT NULL,turn_id TEXT NOT NULL,lease_id TEXT NOT NULL,
                      response TEXT NOT NULL,terminal_reported INTEGER NOT NULL,
                      PRIMARY KEY(agent_id,turn_id),FOREIGN KEY(agent_id,turn_id) REFERENCES turns(agent_id,turn_id));
                    UPDATE agent_schema SET version=5;
                    """;
                command.ExecuteNonQuery();
                transaction.Commit();
            }
            else if (version == 2)
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                command.Transaction = transaction;
                command.CommandText = """
                    CREATE TABLE checkpoint_stages(
                      stage_id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,context_json BLOB NOT NULL,
                      pending_turns_json BLOB NOT NULL,created_at TEXT NOT NULL,
                      FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE agent_migrations(
                      agent_id TEXT PRIMARY KEY,migration_id TEXT NOT NULL,destination_host_id TEXT NOT NULL,
                      state TEXT NOT NULL,started_at TEXT NOT NULL,
                      FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE pending_agent_results(
                      agent_id TEXT NOT NULL,turn_id TEXT NOT NULL,lease_id TEXT NOT NULL,
                      response TEXT NOT NULL,terminal_reported INTEGER NOT NULL,
                      PRIMARY KEY(agent_id,turn_id),FOREIGN KEY(agent_id,turn_id) REFERENCES turns(agent_id,turn_id));
                    UPDATE agent_schema SET version=5;
                    """;
                command.ExecuteNonQuery();
                transaction.Commit();
            }
            else if (version == 3)
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                command.Transaction = transaction;
                command.CommandText = """
                    CREATE TABLE agent_migrations(
                      agent_id TEXT PRIMARY KEY,migration_id TEXT NOT NULL,destination_host_id TEXT NOT NULL,
                      state TEXT NOT NULL,started_at TEXT NOT NULL,
                      FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    CREATE TABLE pending_agent_results(
                      agent_id TEXT NOT NULL,turn_id TEXT NOT NULL,lease_id TEXT NOT NULL,
                      response TEXT NOT NULL,terminal_reported INTEGER NOT NULL,
                      PRIMARY KEY(agent_id,turn_id),FOREIGN KEY(agent_id,turn_id) REFERENCES turns(agent_id,turn_id));
                    UPDATE agent_schema SET version=5;
                    """;
                command.ExecuteNonQuery();
                transaction.Commit();
            }
            else if (version == 4)
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                command.Transaction = transaction;
                command.CommandText = """
                    CREATE TABLE pending_agent_results(
                      agent_id TEXT NOT NULL,turn_id TEXT NOT NULL,lease_id TEXT NOT NULL,
                      response TEXT NOT NULL,terminal_reported INTEGER NOT NULL,
                      PRIMARY KEY(agent_id,turn_id),FOREIGN KEY(agent_id,turn_id) REFERENCES turns(agent_id,turn_id));
                    UPDATE agent_schema SET version=5;
                    """;
                command.ExecuteNonQuery();
                transaction.Commit();
            }
            if (version is >= 1 and <= 5)
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                command.Transaction = transaction;
                command.CommandText = """
                    ALTER TABLE turns ADD COLUMN owner_id TEXT NULL;
                    CREATE TABLE agent_runtime_owners(
                      agent_id TEXT NOT NULL,owner_id TEXT NOT NULL,acquired_at TEXT NOT NULL,
                      renewed_at TEXT NOT NULL,expires_at TEXT NOT NULL,
                      PRIMARY KEY(agent_id,owner_id),FOREIGN KEY(agent_id) REFERENCES agents(agent_id));
                    UPDATE turns SET status=3 WHERE status IN (1,2);
                    UPDATE agent_schema SET version=6;
                    """;
                command.ExecuteNonQuery();
                transaction.Commit();
            }

            command.Transaction = null;
            command.Parameters.Clear();
        }
        catch (AgentStoreException) { throw; }
        catch (SqliteException exception)
        {
            SqliteConnection.ClearAllPools();
            throw new AgentStoreException("Agent database state is corrupt or unreadable.", exception);
        }
    }

    public async Task<AgentDescriptor> CreateAsync(
        StewardAgentId agentId, AgentRuntimeDescriptor runtime, string? parentRoute = null,
        CancellationToken cancellationToken = default)
    {
        AgentLimits.Text(runtime.Name, 128, nameof(runtime.Name));
        AgentLimits.Text(runtime.Version, 64, nameof(runtime.Version));
        if (parentRoute is not null) AgentLimits.Text(parentRoute, 2048, nameof(parentRoute));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT OR IGNORE INTO agents VALUES($id,$name,$version,$parallel,$route,0,0,0,0,0)
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$name", runtime.Name);
        command.Parameters.AddWithValue("$version", runtime.Version);
        command.Parameters.AddWithValue("$parallel", runtime.SupportsParallelTurns ? 1 : 0);
        command.Parameters.AddWithValue("$route", (object?)parentRoute ?? DBNull.Value);
        var changed = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        var descriptor = await GetAsync(agentId, cancellationToken).ConfigureAwait(false)
            ?? throw new AgentStoreException("Agent creation did not persist.");
        if (changed == 0 &&
            (descriptor.RuntimeName != runtime.Name ||
             descriptor.RuntimeVersion != runtime.Version ||
             descriptor.SupportsParallelTurns != runtime.SupportsParallelTurns ||
             !string.Equals(descriptor.ParentRoute, parentRoute, StringComparison.Ordinal)))
            throw new AgentConflictException("Agent ID already exists with a different immutable descriptor.");
        return descriptor;
    }

    public async Task<AgentDescriptor?> GetAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT runtime_name,runtime_version,parallel_turns,parent_route,revision,response_cursor,
                   notification_cursor,placement_generation,frozen
            FROM agents WHERE agent_id=$id
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        var revision = reader.GetInt64(4);
        var responseCursor = reader.GetInt64(5);
        var notificationCursor = reader.GetInt64(6);
        var generation = reader.GetInt64(7);
        if (revision < 0 || responseCursor < 0 || notificationCursor < 0 ||
            notificationCursor > responseCursor || generation < 0)
            throw new AgentStoreException("Stored agent counters are invalid.");
        var runtimeName = reader.GetString(0);
        var runtimeVersion = reader.GetString(1);
        var parallel = reader.GetInt64(2);
        var parentRoute = reader.IsDBNull(3) ? null : reader.GetString(3);
        if (Encoding.UTF8.GetByteCount(runtimeName) > 128 ||
            Encoding.UTF8.GetByteCount(runtimeVersion) > 64 ||
            (parentRoute is not null && Encoding.UTF8.GetByteCount(parentRoute) > 2048))
            throw new AgentStoreException("Stored agent descriptor exceeds bounds.");
        if (parallel is not (0 or 1)) throw new AgentStoreException("Stored parallel-turn capability is invalid.");
        return new(agentId, runtimeName, runtimeVersion, parallel != 0,
            parentRoute, revision, responseCursor,
            notificationCursor, generation, reader.GetInt64(8) != 0);
    }

    public async Task<AgentTurnRecord> SubmitTurnAsync(
        StewardAgentId agentId, AgentTurnRequest request, CancellationToken cancellationToken = default)
    {
        AgentLimits.Text(request.Text, AgentLimits.MaximumTurnBytes, nameof(request.Text));
        if (request.ClientRequestId is not null)
            AgentLimits.Text(request.ClientRequestId, 256, nameof(request.ClientRequestId));
        if (!Enum.IsDefined(request.Provenance))
            throw new ArgumentOutOfRangeException(nameof(request.Provenance));
        var hash = RequestHash(request);
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = "SELECT body_hash FROM turns WHERE agent_id=$id AND turn_id=$turn";
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$turn", request.TurnId.ToString());
        var existingHash = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (existingHash is string existing)
        {
            if (!string.Equals(existing, hash, StringComparison.Ordinal))
                throw new AgentConflictException("Turn ID was already submitted with different request fields.");
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return (await GetTurnAsync(agentId, request.TurnId, cancellationToken).ConfigureAwait(false))!;
        }
        command.CommandText = """
            SELECT frozen,(SELECT COUNT(*) FROM turns WHERE agent_id=$id
              AND status IN ($queued,$dispatching,$running,$recovering))
            FROM agents WHERE agent_id=$id
            """;
        command.Parameters.AddWithValue("$queued", (int)AgentTurnStatus.Queued);
        command.Parameters.AddWithValue("$dispatching", (int)AgentTurnStatus.Dispatching);
        command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                throw new KeyNotFoundException("Agent does not exist.");
            if (reader.GetInt64(0) != 0) throw new AgentConflictException("Agent is frozen for migration.");
            if (reader.GetInt64(1) >= AgentLimits.MaximumPendingTurns)
                throw new AgentConflictException("Agent pending-turn limit reached.");
        }
        command.CommandText = """
            INSERT OR IGNORE INTO turns(agent_id,turn_id,body_hash,text,provenance,client_request_id,status,queue_sequence,workload_id,task_id)
            VALUES($id,$turn,$hash,$text,$provenance,$client,$status,
              COALESCE((SELECT MAX(queue_sequence)+1 FROM turns WHERE agent_id=$id),1),$workload,$task)
            """;
        command.Parameters.AddWithValue("$hash", hash);
        command.Parameters.AddWithValue("$text", request.Text);
        command.Parameters.AddWithValue("$provenance", (int)request.Provenance);
        command.Parameters.AddWithValue("$client", (object?)request.ClientRequestId ?? DBNull.Value);
        command.Parameters.AddWithValue("$status", (int)AgentTurnStatus.Queued);
        command.Parameters.AddWithValue("$workload", WorkloadId.New().ToString());
        command.Parameters.AddWithValue("$task", TaskId.New().ToString());
        var inserted = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        if (inserted == 0) throw new AgentConflictException("Concurrent turn submission conflicted.");
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return (await GetTurnAsync(agentId, request.TurnId, cancellationToken).ConfigureAwait(false))!;
    }

    public async Task<AgentTurnRecord?> GetTurnAsync(
        StewardAgentId agentId, AgentTurnId turnId, CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT text,provenance,client_request_id,status,queue_sequence,response_sequence,response,
              error_code,safe_error_detail,workload_id,task_id,lease_id,attempt_id,
              attempt_generation,host_id,node_incarnation_id,accepted_at
            FROM turns WHERE agent_id=$id AND turn_id=$turn
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$turn", turnId.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? ReadTurn(agentId, turnId, reader) : null;
    }

    public async Task<AgentTurnRecord?> TryClaimNextAsync(
        StewardAgentId agentId,
        Guid ownerId,
        DateTimeOffset now,
        bool permitsParallel,
        CancellationToken cancellationToken = default)
    {
        if (ownerId == Guid.Empty) throw new ArgumentException("Runtime owner ID cannot be empty.", nameof(ownerId));
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = """
            SELECT a.frozen FROM agents a
            WHERE a.agent_id=$id AND EXISTS(
              SELECT 1 FROM agent_runtime_owners o
              WHERE o.agent_id=a.agent_id AND o.owner_id=$owner AND o.expires_at>$now)
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$owner", ownerId.ToString("D"));
        command.Parameters.AddWithValue("$now", SqlTimestamp(now));
        var frozen = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (frozen is null or DBNull || Convert.ToInt64(frozen) != 0) return null;
        command.CommandText = """
            UPDATE turns SET status=$dispatching,owner_id=$owner
            WHERE agent_id=$id AND turn_id=(
              SELECT turn_id FROM turns WHERE agent_id=$id AND status=$queued ORDER BY queue_sequence LIMIT 1)
            AND ($parallel=1 OR NOT EXISTS(
              SELECT 1 FROM turns active WHERE active.agent_id=$id
              AND active.status IN ($dispatching,$running,$recovering)))
            RETURNING turn_id,text,provenance,client_request_id,status,queue_sequence,response_sequence,response,
              error_code,safe_error_detail,workload_id,task_id,lease_id,attempt_id,
              attempt_generation,host_id,node_incarnation_id,accepted_at
            """;
        command.Parameters.AddWithValue("$queued", (int)AgentTurnStatus.Queued);
        command.Parameters.AddWithValue("$dispatching", (int)AgentTurnStatus.Dispatching);
        command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        command.Parameters.AddWithValue("$parallel", permitsParallel ? 1 : 0);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        AgentTurnRecord? turn = null;
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            turn = ReadTurn(agentId, AgentTurnId.Parse(reader.GetString(0)), reader, 1);
        await reader.DisposeAsync().ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return turn;
    }

    public async Task<bool> TryAcquireRuntimeOwnershipAsync(
        StewardAgentId agentId,
        Guid ownerId,
        DateTimeOffset now,
        TimeSpan leaseDuration,
        CancellationToken cancellationToken = default)
    {
        ValidateOwnership(ownerId, leaseDuration);
        var expires = now + leaseDuration;
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO agent_runtime_owners(agent_id,owner_id,acquired_at,renewed_at,expires_at)
            SELECT $agent,$owner,$now,$now,$expires
            WHERE EXISTS(SELECT 1 FROM agents WHERE agent_id=$agent)
              AND NOT EXISTS(SELECT 1 FROM agent_runtime_owners
                WHERE agent_id=$agent AND owner_id<>$owner AND expires_at>$now)
            ON CONFLICT(agent_id,owner_id) DO UPDATE SET renewed_at=$now,expires_at=$expires
            WHERE NOT EXISTS(SELECT 1 FROM agent_runtime_owners other
                WHERE other.agent_id=$agent AND other.owner_id<>$owner AND other.expires_at>$now)
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$owner", ownerId.ToString("D"));
        command.Parameters.AddWithValue("$now", SqlTimestamp(now));
        command.Parameters.AddWithValue("$expires", SqlTimestamp(expires));
        var changed = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        else await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
        return changed;
    }

    public async Task<bool> TryRenewRuntimeOwnershipAsync(
        StewardAgentId agentId,
        Guid ownerId,
        DateTimeOffset now,
        TimeSpan leaseDuration,
        CancellationToken cancellationToken = default)
    {
        ValidateOwnership(ownerId, leaseDuration);
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE agent_runtime_owners SET renewed_at=$now,expires_at=$expires
            WHERE agent_id=$agent AND owner_id=$owner AND expires_at>$now
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$owner", ownerId.ToString("D"));
        command.Parameters.AddWithValue("$now", SqlTimestamp(now));
        command.Parameters.AddWithValue("$expires", SqlTimestamp(now + leaseDuration));
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1;
    }

    public async Task<int> RecoverAbandonedTurnsAsync(
        StewardAgentId agentId,
        Guid recoveringOwnerId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        if (recoveringOwnerId == Guid.Empty)
            throw new ArgumentException("Runtime owner ID cannot be empty.", nameof(recoveringOwnerId));
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE turns SET status=$recovering
            WHERE agent_id=$agent AND status IN ($dispatching,$running)
              AND owner_id<>$owner
              AND EXISTS(SELECT 1 FROM agent_runtime_owners current
                WHERE current.agent_id=$agent AND current.owner_id=$owner AND current.expires_at>$now)
              AND EXISTS(SELECT 1 FROM agent_runtime_owners abandoned
                WHERE abandoned.agent_id=$agent AND abandoned.owner_id=turns.owner_id
                  AND abandoned.expires_at<=$now)
            """;
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        command.Parameters.AddWithValue("$dispatching", (int)AgentTurnStatus.Dispatching);
        command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$owner", recoveringOwnerId.ToString("D"));
        command.Parameters.AddWithValue("$now", SqlTimestamp(now));
        var changed = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return changed;
    }

    public async Task SetExecutionAsync(
        StewardAgentId agentId, AgentTurnId turnId, ManagedAgentExecution execution,
        CancellationToken cancellationToken = default)
    {
        execution.Validate();
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE turns SET status=CASE WHEN status=$recovering THEN $recovering ELSE $running END,
              lease_id=$lease,attempt_id=$attempt,
              attempt_generation=$generation,host_id=$host,node_incarnation_id=$node,accepted_at=$accepted
            WHERE agent_id=$id AND turn_id=$turn AND status IN ($dispatching,$recovering)
              AND workload_id=$workload AND task_id=$task
            """;
        command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
        command.Parameters.AddWithValue("$dispatching", (int)AgentTurnStatus.Dispatching);
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        AddExecutionParameters(command, execution);
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$turn", turnId.ToString());
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            throw new AgentConflictException("Managed execution does not match the claimed turn.");
    }

    public async Task<IReadOnlyList<AgentTurnRecord>> ReadRecoveringTurnsAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default)
    {
        var result = new List<AgentTurnRecord>();
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT turn_id,text,provenance,client_request_id,status,queue_sequence,response_sequence,response,
              error_code,safe_error_detail,workload_id,task_id,lease_id,attempt_id,
              attempt_generation,host_id,node_incarnation_id,accepted_at
            FROM turns WHERE agent_id=$id AND status=$recovering ORDER BY queue_sequence
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            result.Add(ReadTurn(agentId, AgentTurnId.Parse(reader.GetString(0)), reader, 1));
        return result;
    }

    public async Task ResolveRecoveryAsync(
        StewardAgentId agentId, AgentTurnId turnId, ManagedExecutionStatus status,
        CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(status.Fact)) throw new ArgumentOutOfRangeException(nameof(status));
        if (status.Fact == ManagedExecutionFact.Absent)
        {
            await using var connection = Open();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                UPDATE turns SET status=$queued,lease_id=NULL,attempt_id=NULL,attempt_generation=NULL,
                  host_id=NULL,node_incarnation_id=NULL,accepted_at=NULL
                WHERE agent_id=$id AND turn_id=$turn AND status=$recovering
                  AND NOT EXISTS(SELECT 1 FROM pending_agent_results
                    WHERE agent_id=$id AND turn_id=$turn)
                """;
            command.Parameters.AddWithValue("$queued", (int)AgentTurnStatus.Queued);
            command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
            command.Parameters.AddWithValue("$id", agentId.ToString());
            command.Parameters.AddWithValue("$turn", turnId.ToString());
            if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                command.CommandText = """
                    SELECT COUNT(*) FROM pending_agent_results WHERE agent_id=$id AND turn_id=$turn
                    """;
                if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)) == 1)
                    return;
                throw new AgentConflictException("Turn is no longer recovery-blocked.");
            }
            return;
        }
        if (status.Fact == ManagedExecutionFact.Present)
        {
            return; // A present execution remains recovery-blocked; it must not be rerun.
        }
        if (status.Fact == ManagedExecutionFact.Succeeded)
            await CompleteTerminalAsync(agentId, turnId, AgentTurnStatus.Responded, "response",
                status.Response ?? string.Empty, null, null, AgentTurnStatus.Recovering, cancellationToken).ConfigureAwait(false);
        else if (status.Fact == ManagedExecutionFact.Failed)
            await CompleteTerminalAsync(agentId, turnId, AgentTurnStatus.Failed, "failure", string.Empty,
                status.ErrorCode ?? "managed-task-failed", null, AgentTurnStatus.Recovering, cancellationToken).ConfigureAwait(false);
        else
            await CompleteTerminalAsync(agentId, turnId, AgentTurnStatus.Cancelled, "cancelled", string.Empty,
                "cancelled", null, AgentTurnStatus.Recovering, cancellationToken).ConfigureAwait(false);
    }

    public async Task AppendActivityAsync(
        StewardAgentId agentId, AgentTurnId turnId, AgentActivity activity,
        CancellationToken cancellationToken = default)
    {
        AgentLimits.Text(activity.Text, AgentLimits.MaximumActivityBytes, nameof(activity.Text));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO activities VALUES($id,$turn,
              COALESCE((SELECT MAX(sequence)+1 FROM activities WHERE agent_id=$id AND turn_id=$turn),1),
              $text,$provenance)
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$turn", turnId.ToString());
        command.Parameters.AddWithValue("$text", activity.Text);
        command.Parameters.AddWithValue("$provenance", (int)activity.Provenance);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task CompleteAsync(
        StewardAgentId agentId, AgentTurnId turnId, string response,
        CancellationToken cancellationToken = default)
    {
        AgentLimits.Text(response, AgentLimits.MaximumResponseBytes, nameof(response));
        await CompleteTerminalAsync(agentId, turnId, AgentTurnStatus.Responded, "response",
            response, null, null, AgentTurnStatus.Running, cancellationToken).ConfigureAwait(false);
    }

    public async Task SavePendingResultAsync(
        StewardAgentId agentId,
        AgentTurnId turnId,
        ManagedAgentExecution execution,
        string response,
        CancellationToken cancellationToken = default)
    {
        execution.Validate();
        AgentLimits.Text(response, AgentLimits.MaximumResponseBytes, nameof(response));
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO pending_agent_results(agent_id,turn_id,lease_id,response,terminal_reported)
            SELECT $agent,$turn,$lease,$response,0 FROM turns
            WHERE agent_id=$agent AND turn_id=$turn AND lease_id=$lease
              AND status IN ($running,$recovering)
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$turn", turnId.ToString());
        command.Parameters.AddWithValue("$lease", execution.LeaseId.ToString("D"));
        command.Parameters.AddWithValue("$response", response);
        command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 0)
        {
            command.CommandText = """
                SELECT COUNT(*) FROM pending_agent_results
                WHERE agent_id=$agent AND turn_id=$turn AND lease_id=$lease AND response=$response
                """;
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)) != 1)
                throw new AgentConflictException("Pending result differs from the managed execution.");
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<PendingAgentResult?> GetPendingResultAsync(
        StewardAgentId agentId,
        AgentTurnId turnId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT lease_id,response,terminal_reported FROM pending_agent_results
            WHERE agent_id=$agent AND turn_id=$turn
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$turn", turnId.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        try
        {
            var leaseId = Guid.Parse(reader.GetString(0));
            var response = reader.GetString(1);
            if (leaseId == Guid.Empty || Encoding.UTF8.GetByteCount(response) > AgentLimits.MaximumResponseBytes)
                throw new AgentStoreException("Stored pending result is invalid.");
            return new(agentId, turnId, leaseId, response, reader.GetInt64(2) != 0);
        }
        catch (FormatException exception)
        {
            throw new AgentStoreException("Stored pending result identity is invalid.", exception);
        }
    }

    public async Task MarkPendingResultReportedAsync(
        StewardAgentId agentId,
        AgentTurnId turnId,
        Guid executionLeaseId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE pending_agent_results SET terminal_reported=1
            WHERE agent_id=$agent AND turn_id=$turn AND lease_id=$lease
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$turn", turnId.ToString());
        command.Parameters.AddWithValue("$lease", executionLeaseId.ToString("D"));
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            throw new AgentConflictException("Pending result lease no longer matches.");
    }

    public async Task FinalizePendingResultAsync(
        StewardAgentId agentId,
        AgentTurnId turnId,
        Guid executionLeaseId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT t.text,t.provenance,t.status,p.response,p.terminal_reported
            FROM turns t JOIN pending_agent_results p
              ON p.agent_id=t.agent_id AND p.turn_id=t.turn_id
            WHERE t.agent_id=$agent AND t.turn_id=$turn AND t.lease_id=$lease AND p.lease_id=$lease
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$turn", turnId.ToString());
        command.Parameters.AddWithValue("$lease", executionLeaseId.ToString("D"));
        string input;
        string response;
        TextProvenance provenance;
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                throw new AgentConflictException("Pending result lease no longer matches.");
            input = reader.GetString(0);
            provenance = (TextProvenance)reader.GetInt32(1);
            var status = ReadStatus(reader.GetInt32(2));
            response = reader.GetString(3);
            if (reader.GetInt64(4) == 0)
                throw new AgentConflictException("Managed terminal result has not been reported.");
            if (status is not (AgentTurnStatus.Running or AgentTurnStatus.Recovering))
                throw new AgentConflictException("Turn cannot finalize its pending result.");
        }
        if (!Enum.IsDefined(provenance) ||
            Encoding.UTF8.GetByteCount(input) > AgentLimits.MaximumTurnBytes ||
            Encoding.UTF8.GetByteCount(response) > AgentLimits.MaximumResponseBytes)
            throw new AgentStoreException("Pending result source state is invalid.");
        command.CommandText = """
            INSERT INTO context_records(agent_id,sequence,text,provenance,token_estimate)
            VALUES($agent,COALESCE((SELECT MAX(sequence)+1 FROM context_records WHERE agent_id=$agent),1),
                   $input,$input_provenance,$input_tokens);
            INSERT INTO context_records(agent_id,sequence,text,provenance,token_estimate)
            VALUES($agent,(SELECT MAX(sequence)+1 FROM context_records WHERE agent_id=$agent),
                   $response,$response_provenance,$response_tokens);
            UPDATE agents SET response_cursor=response_cursor+1,revision=revision+1 WHERE agent_id=$agent;
            UPDATE turns SET status=$responded,response=$response,
              response_sequence=(SELECT response_cursor FROM agents WHERE agent_id=$agent)
            WHERE agent_id=$agent AND turn_id=$turn;
            INSERT INTO notifications(agent_id,sequence,turn_id,kind,payload,provenance)
            SELECT $agent,response_sequence,$turn,'response',$response,$response_provenance FROM turns
            WHERE agent_id=$agent AND turn_id=$turn;
            DELETE FROM pending_agent_results WHERE agent_id=$agent AND turn_id=$turn AND lease_id=$lease;
            """;
        command.Parameters.AddWithValue("$input", input);
        command.Parameters.AddWithValue("$input_provenance", (int)provenance);
        command.Parameters.AddWithValue("$input_tokens", EstimateTokens(input));
        command.Parameters.AddWithValue("$response", response);
        command.Parameters.AddWithValue("$response_provenance", (int)TextProvenance.Runtime);
        command.Parameters.AddWithValue("$response_tokens", EstimateTokens(response));
        command.Parameters.AddWithValue("$responded", (int)AgentTurnStatus.Responded);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task FailAsync(
        StewardAgentId agentId, AgentTurnId turnId, string errorCode, string? safeDetail,
        CancellationToken cancellationToken = default) =>
        CompleteTerminalAsync(agentId, turnId, AgentTurnStatus.Failed, "failure", string.Empty,
            ValidateErrorCode(errorCode), BoundSafeDetail(safeDetail), null, cancellationToken);

    public async Task<bool> CancelAsync(
        StewardAgentId agentId, AgentTurnId turnId, CancellationToken cancellationToken = default)
    {
        return await CompleteTerminalAsync(agentId, turnId, AgentTurnStatus.Cancelled, "cancelled",
            string.Empty, "cancelled", null, null, cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> CompleteTerminalAsync(
        StewardAgentId agentId,
        AgentTurnId turnId,
        AgentTurnStatus terminalStatus,
        string notificationKind,
        string response,
        string? errorCode,
        string? safeDetail,
        AgentTurnStatus? expectedStatus,
        CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT status,response,error_code FROM turns WHERE agent_id=$id AND turn_id=$turn";
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$turn", turnId.ToString());
        var alreadyApplied = false;
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                throw new KeyNotFoundException("Turn does not exist.");
            var current = ReadStatus(reader.GetInt32(0));
            if (IsTerminal(current))
            {
                var exact = current == terminalStatus && (terminalStatus switch
                {
                    AgentTurnStatus.Responded =>
                        string.Equals(NullableString(reader, 1), response, StringComparison.Ordinal),
                    AgentTurnStatus.Failed =>
                        string.Equals(NullableString(reader, 2), errorCode, StringComparison.Ordinal),
                    AgentTurnStatus.Cancelled => true,
                    _ => false
                });
                if (exact)
                {
                    alreadyApplied = true;
                }
                else throw new AgentConflictException("Turn already has a different terminal outcome.");
            }
            if (!alreadyApplied && expectedStatus.HasValue && current != expectedStatus)
                throw new AgentConflictException("Turn is not in the expected execution state.");
        }
        if (alreadyApplied)
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }
        var payload = terminalStatus switch
        {
            AgentTurnStatus.Responded => response,
            AgentTurnStatus.Failed => $"code:{errorCode}",
            _ => "cancelled"
        };
        AgentLimits.Text(payload, AgentLimits.MaximumResponseBytes, nameof(payload));
        command.CommandText = """
            UPDATE agents SET response_cursor=response_cursor+1,revision=revision+1 WHERE agent_id=$id;
            UPDATE turns SET status=$terminal,response=$response,error_code=$error,safe_error_detail=$detail,
              response_sequence=(SELECT response_cursor FROM agents WHERE agent_id=$id)
            WHERE agent_id=$id AND turn_id=$turn;
            INSERT INTO notifications(agent_id,sequence,turn_id,kind,payload,provenance)
            SELECT $id,response_sequence,$turn,$kind,$payload,$provenance FROM turns
            WHERE agent_id=$id AND turn_id=$turn;
            DELETE FROM pending_agent_results WHERE agent_id=$id AND turn_id=$turn;
            """;
        command.Parameters.AddWithValue("$terminal", (int)terminalStatus);
        command.Parameters.AddWithValue("$response", terminalStatus == AgentTurnStatus.Responded ? response : DBNull.Value);
        command.Parameters.AddWithValue("$error", (object?)errorCode ?? DBNull.Value);
        command.Parameters.AddWithValue("$detail", (object?)safeDetail ?? DBNull.Value);
        command.Parameters.AddWithValue("$kind", notificationKind);
        command.Parameters.AddWithValue("$payload", payload);
        command.Parameters.AddWithValue("$provenance", (int)TextProvenance.Steward);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    public async Task<IReadOnlyList<ContextRecord>> ReadContextAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default)
    {
        var result = new List<ContextRecord>();
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT sequence,text,provenance,token_estimate,checkpoint_id,parent_checkpoint_id,summary_sha256
            FROM context_records WHERE agent_id=$id ORDER BY sequence
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var record = new ContextRecord(reader.GetInt64(0), reader.GetString(1),
                (TextProvenance)reader.GetInt32(2), reader.GetInt32(3), NullableString(reader, 4),
                NullableString(reader, 5), NullableString(reader, 6));
            ValidateContext(record);
            result.Add(record);
        }
        return result;
    }

    public async Task AppendContextAsync(
        StewardAgentId agentId, string text, TextProvenance provenance,
        CancellationToken cancellationToken = default)
    {
        AgentLimits.Text(text, AgentLimits.MaximumContextBytes, nameof(text));
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO context_records(agent_id,sequence,text,provenance,token_estimate)
            VALUES($id,COALESCE((SELECT MAX(sequence)+1 FROM context_records WHERE agent_id=$id),1),
                   $text,$provenance,$tokens)
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$text", text);
        command.Parameters.AddWithValue("$provenance", (int)provenance);
        command.Parameters.AddWithValue("$tokens", EstimateTokens(text));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task CompactContextAsync(
        StewardAgentId agentId, ContextBudget budget, IContextCompactor compactor,
        CancellationToken cancellationToken = default)
    {
        budget.Validate();
        var records = await ReadContextAsync(agentId, cancellationToken).ConfigureAwait(false);
        if (records.Sum(x => Encoding.UTF8.GetByteCount(x.Text)) <= budget.MaximumBytes &&
            records.Sum(x => x.TokenEstimate) <= budget.MaximumTokens) return;
        var compacted = await compactor.CompactAsync(records, budget, cancellationToken).ConfigureAwait(false);
        AgentLimits.Text(compacted.Summary, budget.MaximumBytes, nameof(compacted.Summary));
        var checkpoint = Guid.NewGuid().ToString("D");
        var parent = records.LastOrDefault(x => x.CheckpointId is not null)?.CheckpointId;
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = """
            DELETE FROM context_records WHERE agent_id=$id;
            INSERT INTO context_records(agent_id,sequence,text,provenance,token_estimate,
              checkpoint_id,parent_checkpoint_id,summary_sha256)
            VALUES($id,1,$text,$provenance,$tokens,$checkpoint,$parent,$hash)
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$text", compacted.Summary);
        command.Parameters.AddWithValue("$provenance", (int)TextProvenance.Steward);
        command.Parameters.AddWithValue("$tokens", EstimateTokens(compacted.Summary));
        command.Parameters.AddWithValue("$checkpoint", checkpoint);
        command.Parameters.AddWithValue("$parent", (object?)parent ?? DBNull.Value);
        command.Parameters.AddWithValue("$hash", compacted.SourceSha256);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        var sequence = 2L;
        foreach (var retained in compacted.RetainedRecent)
        {
            await using var retainedCommand = connection.CreateCommand();
            retainedCommand.Transaction = transaction;
            retainedCommand.CommandText = """
                INSERT INTO context_records(agent_id,sequence,text,provenance,token_estimate)
                VALUES($id,$sequence,$text,$provenance,$tokens)
                """;
            retainedCommand.Parameters.AddWithValue("$id", agentId.ToString());
            retainedCommand.Parameters.AddWithValue("$sequence", sequence++);
            retainedCommand.Parameters.AddWithValue("$text", retained.Text);
            retainedCommand.Parameters.AddWithValue("$provenance", (int)retained.Provenance);
            retainedCommand.Parameters.AddWithValue("$tokens", retained.TokenEstimate);
            await retainedCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<AgentNotification>> ReadAsync(
        StewardAgentId agentId, long afterSequence, int maximumCount,
        CancellationToken cancellationToken = default)
    {
        if (afterSequence < 0) throw new ArgumentOutOfRangeException(nameof(afterSequence));
        if (maximumCount is <= 0 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximumCount));
        var result = new List<AgentNotification>();
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT sequence,turn_id,kind,payload,provenance FROM notifications
            WHERE agent_id=$id AND sequence>$after ORDER BY sequence LIMIT $limit
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$after", afterSequence);
        command.Parameters.AddWithValue("$limit", maximumCount);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var sequence = reader.GetInt64(0);
            var provenance = (TextProvenance)reader.GetInt32(4);
            var kind = reader.GetString(2);
            var payload = reader.GetString(3);
            if (sequence <= afterSequence || !Enum.IsDefined(provenance))
                throw new AgentStoreException("Stored notification state is invalid.");
            if (kind is not ("response" or "failure" or "cancelled") ||
                Encoding.UTF8.GetByteCount(payload) > AgentLimits.MaximumResponseBytes)
                throw new AgentStoreException("Stored notification payload is invalid.");
            try
            {
                result.Add(new(agentId, sequence, AgentTurnId.Parse(reader.GetString(1)),
                    kind, payload, provenance));
            }
            catch (FormatException exception)
            {
                throw new AgentStoreException("Stored notification identity is invalid.", exception);
            }
        }
        return result;
    }

    public async Task AcknowledgeAsync(
        StewardAgentId agentId, long contiguousSequence, CancellationToken cancellationToken = default)
    {
        if (contiguousSequence < 0) throw new ArgumentOutOfRangeException(nameof(contiguousSequence));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE agents SET notification_cursor=$cursor,revision=revision+1
            WHERE agent_id=$id AND notification_cursor<=$cursor AND response_cursor>=$cursor
            """;
        command.Parameters.AddWithValue("$cursor", contiguousSequence);
        command.Parameters.AddWithValue("$id", agentId.ToString());
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            throw new AgentConflictException("Notification acknowledgement is non-monotonic or beyond the response cursor.");
    }

    public async Task<bool> TrySetFrozenAsync(
        StewardAgentId agentId, bool frozen, long expectedRevision,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE agents SET frozen=$frozen,revision=revision+1
            WHERE agent_id=$id AND revision=$expected
            """;
        command.Parameters.AddWithValue("$frozen", frozen ? 1 : 0);
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$expected", expectedRevision);
        var changed = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        else await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
        return changed;
    }

    public async Task<AgentMigrationState?> BeginMigrationAsync(
        StewardAgentId agentId,
        HostId destinationHostId,
        long expectedRevision,
        CancellationToken cancellationToken = default)
    {
        var migrationId = Guid.NewGuid();
        var started = DateTimeOffset.UtcNow;
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE agents SET frozen=1,revision=revision+1
            WHERE agent_id=$agent AND revision=$expected AND frozen=0
              AND NOT EXISTS(
                SELECT 1 FROM turns
                WHERE agent_id=$agent AND status IN ($dispatching,$running,$recovering));
            INSERT INTO agent_migrations(agent_id,migration_id,destination_host_id,state,started_at)
            SELECT $agent,$migration,$destination,'preparing',$started WHERE changes()=1;
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$expected", expectedRevision);
        command.Parameters.AddWithValue("$migration", migrationId.ToString("D"));
        command.Parameters.AddWithValue("$destination", destinationHostId.ToString());
        command.Parameters.AddWithValue("$started", started.ToString("O"));
        command.Parameters.AddWithValue("$dispatching", (int)AgentTurnStatus.Dispatching);
        command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        var changed = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        if (changed == 0)
        {
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return null;
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new(migrationId, agentId, destinationHostId, "preparing", started);
    }

    public async Task FinishMigrationAsync(
        Guid migrationId,
        StewardAgentId agentId,
        string state,
        bool unfreeze,
        CancellationToken cancellationToken = default)
    {
        if (state is not ("placement-committed" or "destination-active" or "completed" or "aborted" or "lost"))
            throw new ArgumentException("Migration state is invalid.", nameof(state));
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE agent_migrations SET state=$state
            WHERE agent_id=$agent AND migration_id=$migration
              AND state NOT IN ('completed','aborted','lost');
            """;
        command.Parameters.AddWithValue("$state", state);
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$migration", migrationId.ToString("D"));
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            throw new AgentConflictException("Migration state no longer matches.");
        if (unfreeze)
        {
            command.CommandText = "UPDATE agents SET frozen=0,revision=revision+1 WHERE agent_id=$agent AND frozen=1";
            if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
                throw new AgentConflictException("Frozen migration source no longer matches.");
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<AgentMigrationState?> GetMigrationAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT migration_id,destination_host_id,state,started_at
            FROM agent_migrations WHERE agent_id=$agent
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        try
        {
            return new(Guid.Parse(reader.GetString(0)), agentId, HostId.Parse(reader.GetString(1)),
                reader.GetString(2), DateTimeOffset.Parse(
                    reader.GetString(3), System.Globalization.CultureInfo.InvariantCulture));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new AgentStoreException("Stored migration state is invalid.", exception);
        }
    }

    public async Task<IReadOnlyList<AgentTurnRecord>> ReadPendingTurnsAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default)
    {
        var result = new List<AgentTurnRecord>();
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT turn_id,text,provenance,client_request_id,status,queue_sequence,response_sequence,response,
              error_code,safe_error_detail,workload_id,task_id,lease_id,attempt_id,
              attempt_generation,host_id,node_incarnation_id,accepted_at
            FROM turns WHERE agent_id=$id
              AND status IN ($queued,$dispatching,$running,$recovering) ORDER BY queue_sequence
            """;
        command.Parameters.AddWithValue("$id", agentId.ToString());
        command.Parameters.AddWithValue("$queued", (int)AgentTurnStatus.Queued);
        command.Parameters.AddWithValue("$dispatching", (int)AgentTurnStatus.Dispatching);
        command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
        command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            result.Add(ReadTurn(agentId, AgentTurnId.Parse(reader.GetString(0)), reader, 1));
        return result;
    }

    public async Task ImportCheckpointAsync(
        StewardAgentId agentId,
        IReadOnlyList<ContextRecord> context,
        IReadOnlyList<AgentTurnRecord> pendingTurns,
        CancellationToken cancellationToken = default)
    {
        if (context.Count > AgentLimits.MaximumPendingTurns || pendingTurns.Count > AgentLimits.MaximumPendingTurns)
            throw new AgentStoreException("Checkpoint exceeds record limits.");
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        foreach (var record in context.OrderBy(x => x.Sequence))
        {
            AgentLimits.Text(record.Text, AgentLimits.MaximumContextBytes, nameof(context));
            ValidateContext(record);
            await using var command = connection.CreateCommand();
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = """
                INSERT OR IGNORE INTO context_records VALUES(
                  $id,$sequence,$text,$provenance,$tokens,$checkpoint,$parent,$hash)
                """;
            command.Parameters.AddWithValue("$id", agentId.ToString());
            command.Parameters.AddWithValue("$sequence", record.Sequence);
            command.Parameters.AddWithValue("$text", record.Text);
            command.Parameters.AddWithValue("$provenance", (int)record.Provenance);
            command.Parameters.AddWithValue("$tokens", record.TokenEstimate);
            command.Parameters.AddWithValue("$checkpoint", (object?)record.CheckpointId ?? DBNull.Value);
            command.Parameters.AddWithValue("$parent", (object?)record.ParentCheckpointId ?? DBNull.Value);
            command.Parameters.AddWithValue("$hash", (object?)record.SummarySha256 ?? DBNull.Value);
            var inserted = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            if (inserted == 0)
            {
                command.CommandText = """
                    SELECT COUNT(*) FROM context_records WHERE agent_id=$id AND sequence=$sequence
                      AND text=$text AND provenance=$provenance AND token_estimate=$tokens
                      AND checkpoint_id IS $checkpoint AND parent_checkpoint_id IS $parent
                      AND summary_sha256 IS $hash
                    """;
                if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)) != 1)
                    throw new AgentConflictException("Existing context record differs from checkpoint.");
            }
        }
        foreach (var turn in pendingTurns.OrderBy(x => x.QueueSequence))
        {
            if (turn.Status is not (AgentTurnStatus.Queued or AgentTurnStatus.Dispatching or
                AgentTurnStatus.Running or AgentTurnStatus.Recovering))
                throw new AgentStoreException("Checkpoint contains an invalid pending turn.");
            AgentLimits.Text(turn.Text, AgentLimits.MaximumTurnBytes, nameof(pendingTurns));
            await using var command = connection.CreateCommand();
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = """
                INSERT OR IGNORE INTO turns(agent_id,turn_id,body_hash,text,provenance,client_request_id,status,
                  queue_sequence,workload_id,task_id)
                VALUES($id,$turn,$hash,$text,$provenance,$client,$queued,$sequence,$workload,$task)
                """;
            command.Parameters.AddWithValue("$id", agentId.ToString());
            command.Parameters.AddWithValue("$turn", turn.TurnId.ToString());
            command.Parameters.AddWithValue("$hash", RequestHash(new(
                turn.TurnId, turn.Text, turn.Provenance, turn.ClientRequestId)));
            command.Parameters.AddWithValue("$text", turn.Text);
            command.Parameters.AddWithValue("$provenance", (int)turn.Provenance);
            command.Parameters.AddWithValue("$client", (object?)turn.ClientRequestId ?? DBNull.Value);
            command.Parameters.AddWithValue("$queued", (int)AgentTurnStatus.Queued);
            command.Parameters.AddWithValue("$sequence", turn.QueueSequence);
            command.Parameters.AddWithValue("$workload", turn.WorkloadId!.Value.ToString());
            command.Parameters.AddWithValue("$task", turn.TaskId!.Value.ToString());
            if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 0)
            {
                command.CommandText = """
                    SELECT COUNT(*) FROM turns WHERE agent_id=$id AND turn_id=$turn AND body_hash=$hash
                      AND text=$text AND provenance=$provenance AND client_request_id IS $client
                      AND queue_sequence=$sequence AND workload_id=$workload AND task_id=$task
                    """;
                if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)) != 1)
                    throw new AgentConflictException("Existing pending turn differs from checkpoint.");
            }
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task StageCheckpointAsync(
        Guid stageId,
        StewardAgentId agentId,
        byte[] contextJson,
        byte[] pendingTurnsJson,
        CancellationToken cancellationToken = default)
    {
        if (stageId == Guid.Empty) throw new ArgumentException("Stage ID cannot be empty.", nameof(stageId));
        ArgumentNullException.ThrowIfNull(contextJson);
        ArgumentNullException.ThrowIfNull(pendingTurnsJson);
        if (contextJson.LongLength > AgentLimits.MaximumContextBytes ||
            pendingTurnsJson.LongLength > AgentLimits.MaximumContextBytes)
            throw new AgentStoreException("Staged checkpoint exceeds storage bounds.");
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO checkpoint_stages VALUES($stage,$agent,$context,$turns,$created)
            """;
        command.Parameters.AddWithValue("$stage", stageId.ToString("D"));
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        command.Parameters.AddWithValue("$context", contextJson);
        command.Parameters.AddWithValue("$turns", pendingTurnsJson);
        command.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 0)
        {
            command.CommandText = """
                SELECT COUNT(*) FROM checkpoint_stages WHERE stage_id=$stage AND agent_id=$agent
                  AND context_json=$context AND pending_turns_json=$turns
                """;
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)) != 1)
                throw new AgentConflictException("Checkpoint stage ID already has different content.");
        }
        else
        {
            command.CommandText = """
                UPDATE agents SET frozen=1,revision=revision+1 WHERE agent_id=$agent AND frozen=0
                  AND NOT EXISTS(SELECT 1 FROM turns WHERE agent_id=$agent
                    AND status IN ($dispatching,$running,$recovering))
                """;
            command.Parameters.AddWithValue("$dispatching", (int)AgentTurnStatus.Dispatching);
            command.Parameters.AddWithValue("$running", (int)AgentTurnStatus.Running);
            command.Parameters.AddWithValue("$recovering", (int)AgentTurnStatus.Recovering);
            if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
                throw new AgentConflictException("Destination agent cannot enter staged, non-executable state.");
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<(byte[] ContextJson, byte[] PendingTurnsJson)?> ReadCheckpointStageAsync(
        Guid stageId,
        StewardAgentId agentId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT context_json,pending_turns_json FROM checkpoint_stages
            WHERE stage_id=$stage AND agent_id=$agent
            """;
        command.Parameters.AddWithValue("$stage", stageId.ToString("D"));
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        return ((byte[])reader[0], (byte[])reader[1]);
    }

    public async Task RemoveCheckpointStageAsync(
        Guid stageId,
        StewardAgentId agentId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM checkpoint_stages WHERE stage_id=$stage AND agent_id=$agent";
        command.Parameters.AddWithValue("$stage", stageId.ToString("D"));
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static AgentTurnRecord ReadTurn(
        StewardAgentId agentId, AgentTurnId turnId, SqliteDataReader reader, int offset = 0)
    {
        try
        {
            var provenance = (TextProvenance)reader.GetInt32(offset + 1);
            if (!Enum.IsDefined(provenance)) throw new AgentStoreException("Stored turn provenance is invalid.");
            var status = ReadStatus(reader.GetInt32(offset + 3));
            var queue = reader.GetInt64(offset + 4);
            long? responseSequence = reader.IsDBNull(offset + 5) ? null : reader.GetInt64(offset + 5);
            if (queue <= 0 || responseSequence <= 0)
                throw new AgentStoreException("Stored turn counters are invalid.");
            WorkloadId? workload = reader.IsDBNull(offset + 9) ? null : WorkloadId.Parse(reader.GetString(offset + 9));
            TaskId? task = reader.IsDBNull(offset + 10) ? null : TaskId.Parse(reader.GetString(offset + 10));
            if (workload is null || task is null)
                throw new AgentStoreException("Stored turn managed Task identity is missing.");
            var hasLease = !reader.IsDBNull(offset + 11);
            var executionFields = Enumerable.Range(offset + 11, 6).Count(i => !reader.IsDBNull(i));
            if (executionFields is not (0 or 6))
                throw new AgentStoreException("Stored managed execution lease is incomplete.");
            ManagedAgentExecution? execution = null;
            if (hasLease)
            {
                execution = new(Guid.Parse(reader.GetString(offset + 11)), workload.Value, task.Value,
                    TaskAttemptId.Parse(reader.GetString(offset + 12)), reader.GetInt32(offset + 13),
                    HostId.Parse(reader.GetString(offset + 14)), NodeIncarnationId.Parse(reader.GetString(offset + 15)),
                    DateTimeOffset.Parse(reader.GetString(offset + 16), System.Globalization.CultureInfo.InvariantCulture));
                execution.Validate();
            }
            if (status == AgentTurnStatus.Running && execution is null)
                throw new AgentStoreException("Running turn has no accepted managed execution lease.");
            if (IsTerminal(status) && responseSequence is null)
                throw new AgentStoreException("Terminal turn has no notification sequence.");
            var text = reader.GetString(offset);
            var client = NullableString(reader, offset + 2);
            var response = NullableString(reader, offset + 6);
            var safeDetail = NullableString(reader, offset + 8);
            if (Encoding.UTF8.GetByteCount(text) > AgentLimits.MaximumTurnBytes ||
                (client is not null && Encoding.UTF8.GetByteCount(client) > 256) ||
                (response is not null && Encoding.UTF8.GetByteCount(response) > AgentLimits.MaximumResponseBytes) ||
                (safeDetail is not null && Encoding.UTF8.GetByteCount(safeDetail) > AgentLimits.MaximumActivityBytes))
                throw new AgentStoreException("Stored turn text exceeds bounds.");
            return new(agentId, turnId, text, provenance, client,
                status, queue, responseSequence, NullableString(reader, offset + 6),
                NullableString(reader, offset + 7), NullableString(reader, offset + 8),
                workload, task, execution);
        }
        catch (AgentStoreException) { throw; }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or ArgumentException)
        {
            throw new AgentStoreException("Stored turn state is invalid.", exception);
        }
    }

    private static string? NullableString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    private static AgentTurnStatus ReadStatus(int value)
    {
        var status = (AgentTurnStatus)value;
        if (!Enum.IsDefined(status)) throw new AgentStoreException("Stored turn status is invalid.");
        return status;
    }
    private static bool IsTerminal(AgentTurnStatus status) =>
        status is AgentTurnStatus.Responded or AgentTurnStatus.Failed or AgentTurnStatus.Cancelled;
    private static void ValidateContext(ContextRecord record)
    {
        if (record.Sequence <= 0 || record.TokenEstimate <= 0 || !Enum.IsDefined(record.Provenance))
            throw new AgentStoreException("Stored context record counters or provenance are invalid.");
        AgentLimits.Text(record.Text, AgentLimits.MaximumContextBytes, nameof(record.Text));
        if (record.SummarySha256 is not null &&
            (record.SummarySha256.Length != 64 || !record.SummarySha256.All(Uri.IsHexDigit)))
            throw new AgentStoreException("Stored context summary hash is invalid.");
    }
    private static void AddExecutionParameters(SqliteCommand command, ManagedAgentExecution execution)
    {
        command.Parameters.AddWithValue("$lease", execution.LeaseId.ToString("D"));
        command.Parameters.AddWithValue("$workload", execution.WorkloadId.ToString());
        command.Parameters.AddWithValue("$task", execution.TaskId.ToString());
        command.Parameters.AddWithValue("$attempt", execution.AttemptId.ToString());
        command.Parameters.AddWithValue("$generation", execution.AttemptGeneration);
        command.Parameters.AddWithValue("$host", execution.HostId.ToString());
        command.Parameters.AddWithValue("$node", execution.NodeIncarnationId.ToString());
        command.Parameters.AddWithValue("$accepted", execution.AcceptedAt.ToString("O"));
    }
    private static void ValidateOwnership(Guid ownerId, TimeSpan leaseDuration)
    {
        if (ownerId == Guid.Empty) throw new ArgumentException("Runtime owner ID cannot be empty.", nameof(ownerId));
        if (leaseDuration < TimeSpan.FromSeconds(5) || leaseDuration > TimeSpan.FromMinutes(10))
            throw new ArgumentOutOfRangeException(nameof(leaseDuration));
    }
    private static string SqlTimestamp(DateTimeOffset value) => value.UtcDateTime.ToString("O");
    private static string ValidateErrorCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 64 || value.Any(x => !(char.IsAsciiLetterOrDigit(x) || x == '-')))
            throw new ArgumentException("Error code must be bounded ASCII letters, digits, or hyphens.", nameof(value));
        return value;
    }
    private static string? BoundSafeDetail(string? value)
    {
        if (value is null) return null;
        var redacted = Steward.PortableState.SecretRedactor.Redact(value);
        AgentLimits.Text(redacted, AgentLimits.MaximumActivityBytes, nameof(value));
        return redacted;
    }
    private static int EstimateTokens(string text) => Math.Max(1, (Encoding.UTF8.GetByteCount(text) + 3) / 4);
    private static string RequestHash(AgentTurnRequest request)
    {
        var canonical = $"{request.TurnId}\n{(int)request.Provenance}\n" +
            $"{request.ClientRequestId?.Length ?? -1}:{request.ClientRequestId}\n" +
            $"{Encoding.UTF8.GetByteCount(request.Text)}:{request.Text}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
    public ValueTask DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        return ValueTask.CompletedTask;
    }
}
