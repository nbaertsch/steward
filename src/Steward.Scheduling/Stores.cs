using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;

namespace Steward.Scheduling;

public sealed class InMemorySchedulerStateStore : ISchedulerStateStore
{
    private readonly ConcurrentDictionary<WorkloadId, SchedulerState> _states = [];

    public Task<SchedulerState?> LoadAsync(WorkloadId workloadId, CancellationToken cancellationToken = default)
    {
        if (!_states.TryGetValue(workloadId, out var state)) return Task.FromResult<SchedulerState?>(null);
        SchedulerStateValidator.Validate(state, expectedWorkloadId: workloadId);
        return Task.FromResult<SchedulerState?>(Snapshot(state));
    }

    public Task<bool> TrySaveAsync(SchedulerState state, long expectedRevision, CancellationToken cancellationToken = default)
    {
        SchedulerStateValidator.Validate(state);
        if (state.Revision != expectedRevision + 1) throw new ArgumentException("Revision must increment by one.", nameof(state));
        while (true)
        {
            if (!_states.TryGetValue(state.WorkloadId, out var current))
            {
                if (expectedRevision != -1) return Task.FromResult(false);
                if (_states.TryAdd(state.WorkloadId, Snapshot(state))) return Task.FromResult(true);
                continue;
            }
            if (current.Revision != expectedRevision) return Task.FromResult(false);
            if (_states.TryUpdate(state.WorkloadId, Snapshot(state), current)) return Task.FromResult(true);
        }
    }

    private static SchedulerState Snapshot(SchedulerState state) => state with
    {
        Tasks = state.Tasks.ToArray(),
        Hosts = state.Hosts.ToArray(),
        RateSlices = state.RateSlices.ToArray(),
        Results = state.Results.ToArray()
    };

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public sealed class SqliteSchedulerStateStore : ISchedulerStateStore
{
    public const int CurrentSchemaVersion = 1;
    private readonly string _connectionString;

    public SqliteSchedulerStateStore(string databasePath)
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

    private void Initialize()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS scheduling_schema(version INTEGER NOT NULL);
            INSERT INTO scheduling_schema(version)
              SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM scheduling_schema);
            """;
        command.ExecuteNonQuery();
        command.CommandText = "SELECT version FROM scheduling_schema LIMIT 1";
        var version = Convert.ToInt32(command.ExecuteScalar());
        if (version > CurrentSchemaVersion || version < 0)
            throw new SchedulerSchemaException($"Scheduling schema version {version} is unsupported; expected {CurrentSchemaVersion}.");
        if (version == 0)
        {
            using var transaction = connection.BeginTransaction();
            command.Transaction = transaction;
            command.CommandText = """
                CREATE TABLE scheduler_states(
                  workload_id TEXT PRIMARY KEY NOT NULL,
                  plan_revision_id TEXT NOT NULL,
                  plan_hash TEXT NOT NULL,
                  revision INTEGER NOT NULL,
                  state_json TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
                UPDATE scheduling_schema SET version=1;
                """;
            command.ExecuteNonQuery();
            transaction.Commit();
        }
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=30000;";
        command.ExecuteNonQuery();
        return connection;
    }

    public async Task<SchedulerState?> LoadAsync(WorkloadId workloadId, CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT state_json FROM scheduler_states WHERE workload_id=$id";
        command.Parameters.AddWithValue("$id", workloadId.ToString());
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (value is not string json) return null;
        SchedulerState state;
        try
        {
            state = JsonSerializer.Deserialize<SchedulerState>(json, StewardJson.Options)
                ?? throw new InvalidDataException("Stored scheduler state is invalid.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Stored scheduler state is invalid.", exception);
        }
        SchedulerStateValidator.Validate(state, expectedWorkloadId: workloadId);
        return state;
    }

    public async Task<bool> TrySaveAsync(SchedulerState state, long expectedRevision, CancellationToken cancellationToken = default)
    {
        SchedulerStateValidator.Validate(state);
        if (state.Revision != expectedRevision + 1) throw new ArgumentException("Revision must increment by one.", nameof(state));
        await using var connection = Open();
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.Parameters.AddWithValue("$id", state.WorkloadId.ToString());
        command.Parameters.AddWithValue("$plan", state.PlanRevisionId.ToString());
        command.Parameters.AddWithValue("$hash", state.PlanHash);
        command.Parameters.AddWithValue("$revision", state.Revision);
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(state, StewardJson.Options));
        command.Parameters.AddWithValue("$updated", DateTimeOffset.UtcNow.ToString("O"));
        if (expectedRevision == -1)
        {
            command.CommandText = """
                INSERT OR IGNORE INTO scheduler_states(workload_id,plan_revision_id,plan_hash,revision,state_json,updated_at)
                VALUES($id,$plan,$hash,$revision,$json,$updated)
                """;
        }
        else
        {
            command.Parameters.AddWithValue("$expected", expectedRevision);
            command.CommandText = """
                UPDATE scheduler_states SET plan_revision_id=$plan,plan_hash=$hash,revision=$revision,state_json=$json,updated_at=$updated
                WHERE workload_id=$id AND revision=$expected
                """;
        }
        var changed = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        else await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
        return changed;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
