using System.Collections.Concurrent;
using Microsoft.Data.Sqlite;
using Steward.Domain;

namespace Steward.Scheduling;

public sealed record GlobalRateLease(
    string LeaseId,
    string Scope,
    WorkloadId WorkloadId,
    TaskId TaskId,
    int Generation,
    HostId HostId,
    decimal Amount,
    decimal Consumed,
    decimal PostExpiryConsumed,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    ExpiredRateBehavior ExpiredBehavior,
    decimal ConservativeFloor)
{
    public decimal Remaining => Amount - Consumed;
}

public sealed record GlobalRateState(
    string Scope,
    long Revision,
    decimal Capacity,
    decimal RefillPerSecond,
    decimal Available,
    DateTimeOffset RefilledAt,
    DateTimeOffset? DelayedUntil,
    decimal ConservativeFloor,
    IReadOnlyList<GlobalRateLease> Leases);

public interface IGlobalRateStateStore : IAsyncDisposable
{
    Task<GlobalRateState?> LoadAsync(string scope, CancellationToken cancellationToken = default);
    Task<bool> TrySaveAsync(GlobalRateState state, long expectedRevision, CancellationToken cancellationToken = default);
}

public sealed class InMemoryGlobalRateStateStore : IGlobalRateStateStore
{
    private readonly ConcurrentDictionary<string, GlobalRateState> _states = new(StringComparer.Ordinal);

    public Task<GlobalRateState?> LoadAsync(string scope, CancellationToken cancellationToken = default) =>
        Task.FromResult(_states.TryGetValue(scope, out var state) ? Snapshot(state) : null);

    public Task<bool> TrySaveAsync(GlobalRateState state, long expectedRevision, CancellationToken cancellationToken = default)
    {
        GlobalRateStateValidator.Validate(state);
        if (state.Revision != expectedRevision + 1) throw new ArgumentException("Revision must increment by one.", nameof(state));
        while (true)
        {
            if (!_states.TryGetValue(state.Scope, out var current))
            {
                if (expectedRevision != -1) return Task.FromResult(false);
                if (_states.TryAdd(state.Scope, Snapshot(state))) return Task.FromResult(true);
                continue;
            }
            if (current.Revision != expectedRevision) return Task.FromResult(false);
            if (_states.TryUpdate(state.Scope, Snapshot(state), current)) return Task.FromResult(true);
        }
    }

    private static GlobalRateState Snapshot(GlobalRateState state) => state with { Leases = state.Leases.ToArray() };
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public sealed class SqliteGlobalRateStateStore : IGlobalRateStateStore
{
    public const int CurrentSchemaVersion = 2;
    private readonly string _connectionString;

    public SqliteGlobalRateStateStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath, Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared, Pooling = true, DefaultTimeout = 30
        }.ToString();
        Initialize();
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

    private void Initialize()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS global_rate_schema(version INTEGER NOT NULL);
            INSERT INTO global_rate_schema(version) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM global_rate_schema);
            """;
        command.ExecuteNonQuery();
        command.CommandText = "SELECT version FROM global_rate_schema LIMIT 1";
        var version = Convert.ToInt32(command.ExecuteScalar());
        if (version is < 0 or > CurrentSchemaVersion)
            throw new SchedulerSchemaException($"Global-rate schema version {version} is unsupported; expected {CurrentSchemaVersion}.");
        if (version == 0)
        {
            using var transaction = connection.BeginTransaction();
            command.Transaction = transaction;
            command.CommandText = """
                CREATE TABLE global_rate_states(
                  scope TEXT PRIMARY KEY NOT NULL,
                  revision INTEGER NOT NULL,
                  capacity TEXT NOT NULL,
                  refill_per_second TEXT NOT NULL,
                  available TEXT NOT NULL,
                  refilled_at TEXT NOT NULL,
                  delayed_until TEXT NULL,
                  conservative_floor TEXT NOT NULL
                );
                CREATE TABLE global_rate_leases(
                  lease_id TEXT PRIMARY KEY NOT NULL,
                  scope TEXT NOT NULL REFERENCES global_rate_states(scope) ON DELETE CASCADE,
                  workload_id TEXT NOT NULL,
                  task_id TEXT NOT NULL,
                  generation INTEGER NOT NULL,
                  host_id TEXT NOT NULL,
                  amount TEXT NOT NULL,
                  consumed TEXT NOT NULL,
                  post_expiry_consumed TEXT NOT NULL,
                  issued_at TEXT NOT NULL,
                  expires_at TEXT NOT NULL,
                  expired_behavior INTEGER NOT NULL,
                  conservative_floor TEXT NOT NULL
                );
                CREATE INDEX global_rate_leases_scope ON global_rate_leases(scope);
                UPDATE global_rate_schema SET version=2;
                """;
            command.ExecuteNonQuery();
            transaction.Commit();
        }
        else if (version == 1)
        {
            using var transaction = connection.BeginTransaction();
            command.Transaction = transaction;
            command.CommandText = """
                ALTER TABLE global_rate_leases ADD COLUMN post_expiry_consumed TEXT NOT NULL DEFAULT '0';
                UPDATE global_rate_schema SET version=2;
                """;
            command.ExecuteNonQuery();
            transaction.Commit();
        }
    }

    public async Task<GlobalRateState?> LoadAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT revision,capacity,refill_per_second,available,refilled_at,delayed_until,conservative_floor
            FROM global_rate_states WHERE scope=$scope
            """;
        command.Parameters.AddWithValue("$scope", scope);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        var state = new GlobalRateState(scope, reader.GetInt64(0), Parse(reader.GetString(1)), Parse(reader.GetString(2)),
            Parse(reader.GetString(3)), DateTimeOffset.Parse(reader.GetString(4), null, System.Globalization.DateTimeStyles.RoundtripKind),
            reader.IsDBNull(5) ? null : DateTimeOffset.Parse(reader.GetString(5), null, System.Globalization.DateTimeStyles.RoundtripKind),
            Parse(reader.GetString(6)), []);
        await reader.DisposeAsync().ConfigureAwait(false);
        command.Parameters.Clear();
        command.Parameters.AddWithValue("$scope", scope);
        command.CommandText = """
            SELECT lease_id,workload_id,task_id,generation,host_id,amount,consumed,post_expiry_consumed,issued_at,expires_at,expired_behavior,conservative_floor
            FROM global_rate_leases WHERE scope=$scope ORDER BY lease_id
            """;
        var leases = new List<GlobalRateLease>();
        await using var leaseReader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await leaseReader.ReadAsync(cancellationToken).ConfigureAwait(false))
            leases.Add(new(leaseReader.GetString(0), scope, WorkloadId.Parse(leaseReader.GetString(1)),
                TaskId.Parse(leaseReader.GetString(2)), leaseReader.GetInt32(3), HostId.Parse(leaseReader.GetString(4)),
                Parse(leaseReader.GetString(5)), Parse(leaseReader.GetString(6)), Parse(leaseReader.GetString(7)),
                DateTimeOffset.Parse(leaseReader.GetString(8), null, System.Globalization.DateTimeStyles.RoundtripKind),
                DateTimeOffset.Parse(leaseReader.GetString(9), null, System.Globalization.DateTimeStyles.RoundtripKind),
                (ExpiredRateBehavior)leaseReader.GetInt32(10), Parse(leaseReader.GetString(11))));
        state = state with { Leases = leases };
        GlobalRateStateValidator.Validate(state);
        return state;
    }

    public async Task<bool> TrySaveAsync(GlobalRateState state, long expectedRevision, CancellationToken cancellationToken = default)
    {
        GlobalRateStateValidator.Validate(state);
        if (state.Revision != expectedRevision + 1) throw new ArgumentException("Revision must increment by one.", nameof(state));
        await using var connection = Open();
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        AddStateParameters(command, state);
        if (expectedRevision == -1)
            command.CommandText = """
                INSERT OR IGNORE INTO global_rate_states(scope,revision,capacity,refill_per_second,available,refilled_at,delayed_until,conservative_floor)
                VALUES($scope,$revision,$capacity,$refill,$available,$refilled,$delayed,$floor)
                """;
        else
        {
            command.Parameters.AddWithValue("$expected", expectedRevision);
            command.CommandText = """
                UPDATE global_rate_states SET revision=$revision,capacity=$capacity,refill_per_second=$refill,
                  available=$available,refilled_at=$refilled,delayed_until=$delayed,conservative_floor=$floor
                WHERE scope=$scope AND revision=$expected
                """;
        }
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }
        command.Parameters.Clear();
        command.Parameters.AddWithValue("$scope", state.Scope);
        command.CommandText = "DELETE FROM global_rate_leases WHERE scope=$scope";
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        foreach (var lease in state.Leases)
        {
            command.Parameters.Clear();
            command.CommandText = """
                INSERT INTO global_rate_leases(lease_id,scope,workload_id,task_id,generation,host_id,amount,consumed,post_expiry_consumed,issued_at,expires_at,expired_behavior,conservative_floor)
                VALUES($id,$scope,$workload,$task,$generation,$host,$amount,$consumed,$postExpiryConsumed,$issued,$expires,$behavior,$floor)
                """;
            command.Parameters.AddWithValue("$id", lease.LeaseId);
            command.Parameters.AddWithValue("$scope", state.Scope);
            command.Parameters.AddWithValue("$workload", lease.WorkloadId.ToString());
            command.Parameters.AddWithValue("$task", lease.TaskId.ToString());
            command.Parameters.AddWithValue("$generation", lease.Generation);
            command.Parameters.AddWithValue("$host", lease.HostId.ToString());
            command.Parameters.AddWithValue("$amount", Format(lease.Amount));
            command.Parameters.AddWithValue("$consumed", Format(lease.Consumed));
            command.Parameters.AddWithValue("$postExpiryConsumed", Format(lease.PostExpiryConsumed));
            command.Parameters.AddWithValue("$issued", lease.IssuedAt.ToString("O"));
            command.Parameters.AddWithValue("$expires", lease.ExpiresAt.ToString("O"));
            command.Parameters.AddWithValue("$behavior", (int)lease.ExpiredBehavior);
            command.Parameters.AddWithValue("$floor", Format(lease.ConservativeFloor));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    private static void AddStateParameters(SqliteCommand command, GlobalRateState state)
    {
        command.Parameters.AddWithValue("$scope", state.Scope);
        command.Parameters.AddWithValue("$revision", state.Revision);
        command.Parameters.AddWithValue("$capacity", Format(state.Capacity));
        command.Parameters.AddWithValue("$refill", Format(state.RefillPerSecond));
        command.Parameters.AddWithValue("$available", Format(state.Available));
        command.Parameters.AddWithValue("$refilled", state.RefilledAt.ToString("O"));
        command.Parameters.AddWithValue("$delayed", (object?)state.DelayedUntil?.ToString("O") ?? DBNull.Value);
        command.Parameters.AddWithValue("$floor", Format(state.ConservativeFloor));
    }

    private static string Format(decimal value) => value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    private static decimal Parse(string value) => decimal.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal static class GlobalRateStateValidator
{
    public static void Validate(GlobalRateState state)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(state.Scope);
        if (state.Revision < 0 || state.Capacity <= 0 || state.RefillPerSecond < 0 ||
            state.Available < 0 || state.Available > state.Capacity ||
            state.ConservativeFloor < 0 || state.ConservativeFloor > state.Capacity)
            throw new InvalidDataException("Global-rate state has invalid bounds.");
        if (state.Leases.Select(x => x.LeaseId).Distinct(StringComparer.Ordinal).Count() != state.Leases.Count)
            throw new InvalidDataException("Global-rate lease IDs must be unique.");
        foreach (var lease in state.Leases)
            if (string.IsNullOrWhiteSpace(lease.LeaseId) || lease.Scope != state.Scope ||
                lease.Generation <= 0 || lease.Amount <= 0 ||
                lease.Consumed < 0 || lease.Consumed > lease.Amount ||
                lease.PostExpiryConsumed < 0 || lease.PostExpiryConsumed > lease.Consumed ||
                lease.PostExpiryConsumed > lease.ConservativeFloor || lease.ExpiresAt <= lease.IssuedAt ||
                lease.ConservativeFloor < 0 || lease.ConservativeFloor > lease.Amount)
                throw new InvalidDataException("Global-rate lease is invalid.");
        if (state.Available + state.Leases.Sum(x => GlobalRateAllocator.AvailableAt(x, state.RefilledAt)) > state.Capacity)
            throw new InvalidDataException("Global-rate spendable authority exceeds bucket capacity.");
    }
}
