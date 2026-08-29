using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Providers.Abstractions;

namespace Steward.Orchestration;

public sealed class SqlitePoolStateStore : IPoolStateStore
{
    private readonly string connectionString;

    public SqlitePoolStateStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var full = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = full,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true
        }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS orchestration_pool_schema(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                version INTEGER NOT NULL
            );
            INSERT INTO orchestration_pool_schema(singleton,version)
            SELECT 1,1 WHERE NOT EXISTS(SELECT 1 FROM orchestration_pool_schema);
            CREATE TABLE IF NOT EXISTS orchestration_pool_states(
                pool_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                state_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """;
        command.ExecuteNonQuery();
        command.CommandText = "SELECT version FROM orchestration_pool_schema WHERE singleton=1";
        if (Convert.ToInt32(command.ExecuteScalar()) != 1)
            throw new InvalidDataException("Pool store schema is newer than this Control supports.");
    }

    public async Task<PoolState> LoadAsync(
        PoolId poolId, CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT state_json FROM orchestration_pool_states WHERE pool_id=$id";
        command.Parameters.AddWithValue("$id", poolId.ToString());
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return json is null
            ? PoolState.Empty(poolId)
            : JsonSerializer.Deserialize<PoolState>(json, StewardJson.Options)
                ?? throw new InvalidDataException("Durable Pool state is invalid.");
    }

    public async Task<bool> TrySaveAsync(
        PoolState state,
        long expectedRevision,
        CancellationToken cancellationToken = default)
    {
        if (state.Revision != expectedRevision + 1)
            throw new ArgumentException("Pool revision must increase by one.", nameof(state));
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.Parameters.AddWithValue("$id", state.PoolId.ToString());
        command.Parameters.AddWithValue("$revision", state.Revision);
        command.Parameters.AddWithValue("$expected", expectedRevision);
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(state, StewardJson.Options));
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        command.CommandText = """
            INSERT INTO orchestration_pool_states(pool_id,revision,state_json,updated_at)
            VALUES($id,$revision,$json,$now)
            ON CONFLICT(pool_id) DO UPDATE SET
              revision=excluded.revision,state_json=excluded.state_json,updated_at=excluded.updated_at
            WHERE orchestration_pool_states.revision=$expected
            """;
        var changed = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken);
        else await transaction.RollbackAsync(cancellationToken);
        return changed;
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA busy_timeout=30000;
            """;
        command.ExecuteNonQuery();
        return connection;
    }
}
