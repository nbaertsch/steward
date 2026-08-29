using Microsoft.Data.Sqlite;
using Steward.Domain;

namespace Steward.PortableState;

public sealed class SqliteAgentPlacementStore : IAgentPlacementStore
{
    private const int SchemaVersion = 2;
    private readonly string _connectionString;

    public SqliteAgentPlacementStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = false,
            DefaultTimeout = 30
        }.ToString();
        Initialize();
    }

    public async Task<long> GetGenerationAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT generation FROM agent_placements WHERE agent_id = $agent;";
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return value is null or DBNull ? 0 : Convert.ToInt64(value);
    }

    public async Task<bool> TryCommitHandoffAsync(
        MigrationHandoffRecord handoff,
        long expectedGeneration,
        CancellationToken cancellationToken = default)
    {
        if (handoff.ExpectedPlacementGeneration != expectedGeneration ||
            handoff.CommittedPlacementGeneration != checked(expectedGeneration + 1))
            throw new PortableStateException("Handoff generations do not form a valid CAS transition.");
        if (handoff.ActivationReceipt is not null || handoff.SourceReleased)
            throw new PortableStateException("A new handoff must begin before destination activation.");
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.Serializable,
            cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(
            connection,
            transaction,
            """
            INSERT INTO agent_placements(agent_id, generation)
            VALUES($agent, 0)
            ON CONFLICT(agent_id) DO NOTHING;
            """,
            cancellationToken,
            ("$agent", handoff.AgentId.ToString())).ConfigureAwait(false);
        var changed = await ExecuteAsync(
            connection,
            transaction,
            """
            UPDATE agent_placements
            SET generation = $next
            WHERE agent_id = $agent AND generation = $expected;
            """,
            cancellationToken,
            ("$next", handoff.CommittedPlacementGeneration),
            ("$agent", handoff.AgentId.ToString()),
            ("$expected", expectedGeneration)).ConfigureAwait(false);
        if (changed != 1)
        {
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }

        await ExecuteAsync(
            connection,
            transaction,
            """
            INSERT INTO migration_handoffs(
                agent_id, source_host_id, destination_host_id, expected_generation,
                committed_generation, source_name, source_sha256, source_length,
                source_etag, source_committed_at, bundle_sha256, hashes_verified,
                readiness_passed, restored_at, activation_receipt_id,
                activation_credentials_rebrokered, activation_at, source_released, committed_at)
            VALUES(
                $agent, $source, $destination, $expected, $committed, $name, $sha,
                $length, $etag, $source_at, $bundle, $verified, $ready, $restored,
                NULL, NULL, NULL, 0, $committed_at)
            ON CONFLICT(agent_id) DO UPDATE SET
                source_host_id=excluded.source_host_id,
                destination_host_id=excluded.destination_host_id,
                expected_generation=excluded.expected_generation,
                committed_generation=excluded.committed_generation,
                source_name=excluded.source_name,
                source_sha256=excluded.source_sha256,
                source_length=excluded.source_length,
                source_etag=excluded.source_etag,
                source_committed_at=excluded.source_committed_at,
                bundle_sha256=excluded.bundle_sha256,
                hashes_verified=excluded.hashes_verified,
                readiness_passed=excluded.readiness_passed,
                restored_at=excluded.restored_at,
                activation_receipt_id=NULL,
                activation_credentials_rebrokered=NULL,
                activation_at=NULL,
                source_released=0,
                committed_at=excluded.committed_at;
            """,
            cancellationToken,
            ("$agent", handoff.AgentId.ToString()),
            ("$source", handoff.SourceHostId.ToString()),
            ("$destination", handoff.DestinationHostId.ToString()),
            ("$expected", handoff.ExpectedPlacementGeneration),
            ("$committed", handoff.CommittedPlacementGeneration),
            ("$name", handoff.SourceReceipt.ObjectName),
            ("$sha", handoff.SourceReceipt.Sha256),
            ("$length", handoff.SourceReceipt.Length),
            ("$etag", handoff.SourceReceipt.ETag),
            ("$source_at", handoff.SourceReceipt.CommittedAt.ToString("O")),
            ("$bundle", handoff.DestinationReceipt.BundleSha256),
            ("$verified", handoff.DestinationReceipt.HashesVerified ? 1 : 0),
            ("$ready", handoff.DestinationReceipt.ReadinessPassed ? 1 : 0),
            ("$restored", handoff.DestinationReceipt.RestoredAt.ToString("O")),
            ("$committed_at", handoff.CommittedAt.ToString("O"))).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    public async Task<bool> TryRecordDestinationActiveAsync(
        DestinationActivationReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        if (receipt.PlacementGeneration <= 0 ||
            string.IsNullOrWhiteSpace(receipt.ActivationReceiptId) ||
            !receipt.CredentialsRebrokered)
            throw new PortableStateException("Destination-active receipt is invalid.");
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var changed = await ExecuteAsync(
            connection,
            null,
            """
            UPDATE migration_handoffs
            SET activation_receipt_id = $receipt,
                activation_credentials_rebrokered = $credentials,
                activation_at = $activated
            WHERE agent_id = $agent
              AND destination_host_id = $destination
              AND committed_generation = $generation
              AND activation_receipt_id IS NULL;
            """,
            cancellationToken,
            ("$receipt", receipt.ActivationReceiptId),
            ("$credentials", receipt.CredentialsRebrokered ? 1 : 0),
            ("$activated", receipt.ActivatedAt.ToString("O")),
            ("$agent", receipt.AgentId.ToString()),
            ("$destination", receipt.DestinationHostId.ToString()),
            ("$generation", receipt.PlacementGeneration)).ConfigureAwait(false);
        if (changed == 1)
            return true;
        var existing = await GetHandoffAsync(receipt.AgentId, cancellationToken).ConfigureAwait(false);
        return existing?.ActivationReceipt == receipt;
    }

    public async Task MarkSourceReleasedAsync(
        StewardAgentId agentId,
        long committedGeneration,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var changed = await ExecuteAsync(
            connection,
            null,
            """
            UPDATE migration_handoffs SET source_released = 1
            WHERE agent_id = $agent
              AND committed_generation = $generation
              AND activation_receipt_id IS NOT NULL;
            """,
            cancellationToken,
            ("$agent", agentId.ToString()),
            ("$generation", committedGeneration)).ConfigureAwait(false);
        if (changed != 1)
            throw new PortableStateException("Source release does not match the winning durable handoff.");
    }

    public async Task<MigrationHandoffRecord?> GetHandoffAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT source_host_id, destination_host_id, expected_generation,
                   committed_generation, source_name, source_sha256, source_length,
                   source_etag, source_committed_at, bundle_sha256, hashes_verified,
                   readiness_passed, restored_at, activation_receipt_id,
                   activation_credentials_rebrokered, activation_at,
                   source_released, committed_at
            FROM migration_handoffs WHERE agent_id = $agent;
            """;
        command.Parameters.AddWithValue("$agent", agentId.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;
        var source = HostId.Parse(reader.GetString(0));
        var destination = HostId.Parse(reader.GetString(1));
        var receipt = new PortableObjectReceipt(
            reader.GetString(4),
            reader.GetString(5),
            reader.GetInt64(6),
            reader.GetString(7),
            DateTimeOffset.Parse(reader.GetString(8), null, System.Globalization.DateTimeStyles.RoundtripKind));
        var restore = new DestinationRestoreReceipt(
            agentId,
            destination,
            reader.GetString(9),
            reader.GetBoolean(10),
            reader.GetBoolean(11),
            DateTimeOffset.Parse(reader.GetString(12), null, System.Globalization.DateTimeStyles.RoundtripKind));
        DestinationActivationReceipt? activation = reader.IsDBNull(13)
            ? null
            : new(
                agentId,
                destination,
                reader.GetInt64(3),
                reader.GetString(13),
                reader.GetBoolean(14),
                DateTimeOffset.Parse(reader.GetString(15), null, System.Globalization.DateTimeStyles.RoundtripKind));
        return new(
            agentId,
            source,
            destination,
            reader.GetInt64(2),
            reader.GetInt64(3),
            receipt,
            restore,
            activation,
            reader.GetBoolean(16),
            DateTimeOffset.Parse(reader.GetString(17), null, System.Globalization.DateTimeStyles.RoundtripKind));
    }

    private void Initialize()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS portable_state_schema(
                id INTEGER PRIMARY KEY CHECK(id = 1),
                version INTEGER NOT NULL
            );
            INSERT INTO portable_state_schema(id, version)
            VALUES(1, {SchemaVersion})
            ON CONFLICT(id) DO NOTHING;
            CREATE TABLE IF NOT EXISTS agent_placements(
                agent_id TEXT PRIMARY KEY,
                generation INTEGER NOT NULL CHECK(generation >= 0)
            );
            CREATE TABLE IF NOT EXISTS migration_handoffs(
                agent_id TEXT PRIMARY KEY,
                source_host_id TEXT NOT NULL,
                destination_host_id TEXT NOT NULL,
                expected_generation INTEGER NOT NULL,
                committed_generation INTEGER NOT NULL,
                source_name TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                source_length INTEGER NOT NULL,
                source_etag TEXT NOT NULL,
                source_committed_at TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                hashes_verified INTEGER NOT NULL,
                readiness_passed INTEGER NOT NULL,
                restored_at TEXT NOT NULL,
                activation_receipt_id TEXT NULL,
                activation_credentials_rebrokered INTEGER NULL,
                activation_at TEXT NULL,
                source_released INTEGER NOT NULL
                    CHECK(source_released = 0 OR activation_receipt_id IS NOT NULL),
                committed_at TEXT NOT NULL,
                FOREIGN KEY(agent_id) REFERENCES agent_placements(agent_id)
            );
            """;
        command.ExecuteNonQuery();
        command.CommandText = "SELECT version FROM portable_state_schema WHERE id = 1;";
        var version = Convert.ToInt32(command.ExecuteScalar());
        if (version == 1)
        {
            command.CommandText =
                """
                ALTER TABLE migration_handoffs ADD COLUMN activation_receipt_id TEXT NULL;
                ALTER TABLE migration_handoffs ADD COLUMN activation_credentials_rebrokered INTEGER NULL;
                ALTER TABLE migration_handoffs ADD COLUMN activation_at TEXT NULL;
                UPDATE portable_state_schema SET version = 2 WHERE id = 1;
                """;
            command.ExecuteNonQuery();
            version = 2;
        }
        if (version != SchemaVersion)
            throw new PortableStateException("Unsupported portable-state SQLite schema version.");
        command.CommandText =
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_migration_activation_receipt
            ON migration_handoffs(activation_receipt_id)
            WHERE activation_receipt_id IS NOT NULL;
            """;
        command.ExecuteNonQuery();
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }

    private static async Task<int> ExecuteAsync(
        SqliteConnection connection,
        System.Data.Common.DbTransaction? transaction,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction?)transaction;
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
