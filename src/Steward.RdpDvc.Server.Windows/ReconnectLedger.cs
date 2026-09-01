using Microsoft.Data.Sqlite;

namespace Steward.RdpDvc.Server.Windows;

public enum ReconnectAttemptState
{
    Reserved = 0,
    CarrierAuthenticated = 1,
    SecureAuthenticated = 2,
    Online = 3,
    Closed = 4,
    Abandoned = 5
}

public sealed record ReconnectAttempt(
    long Generation,
    Guid AttemptId,
    ReconnectAttemptState State,
    DateTimeOffset UpdatedAtUtc);

public sealed class ReconnectLedger
{
    private const int CurrentSchemaVersion = 1;
    private readonly string connectionString;

    public ReconnectLedger(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath) ||
            !Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException(
                "Reconnect ledger path must be absolute.",
                nameof(databasePath));
        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(
            Path.GetDirectoryName(fullPath)!);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString();
        Initialize();
    }

    public async Task<ReconnectAttempt> ReserveAsync(
        Guid sessionId,
        Guid hostId,
        Guid incarnationId,
        Guid attemptId,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken = default)
    {
        ValidateIdentity(sessionId, hostId, incarnationId);
        if (attemptId == Guid.Empty)
            throw new ArgumentException(
                "Reconnect attempt ID must be nonempty.",
                nameof(attemptId));
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(
            deferred: false);
        await EnsureIdentityAsync(
            connection,
            transaction,
            sessionId,
            hostId,
            incarnationId,
            cancellationToken).ConfigureAwait(false);
        await using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText =
            "SELECT generation FROM reconnect_state WHERE singleton=1";
        var current = Convert.ToInt64(
            await read.ExecuteScalarAsync(cancellationToken)
                .ConfigureAwait(false));
        if (current == long.MaxValue)
            throw new OverflowException(
                "Reconnect generation is exhausted.");
        var generation = checked(current + 1);
        var updated = observedAt.ToUniversalTime();
        await using var supersede = connection.CreateCommand();
        supersede.Transaction = transaction;
        supersede.CommandText = """
            UPDATE reconnect_attempts
            SET state=$abandoned,updated_at=$updated
            WHERE generation < $generation
              AND state IN ($reserved,$carrier,$secure,$online)
            """;
        supersede.Parameters.AddWithValue(
            "$abandoned",
            (int)ReconnectAttemptState.Abandoned);
        supersede.Parameters.AddWithValue("$updated", updated.ToString("O"));
        supersede.Parameters.AddWithValue("$generation", generation);
        supersede.Parameters.AddWithValue(
            "$reserved",
            (int)ReconnectAttemptState.Reserved);
        supersede.Parameters.AddWithValue(
            "$carrier",
            (int)ReconnectAttemptState.CarrierAuthenticated);
        supersede.Parameters.AddWithValue(
            "$secure",
            (int)ReconnectAttemptState.SecureAuthenticated);
        supersede.Parameters.AddWithValue(
            "$online",
            (int)ReconnectAttemptState.Online);
        await supersede.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE reconnect_state
            SET generation=$generation, updated_at=$updated
            WHERE singleton=1 AND generation=$current
            """;
        update.Parameters.AddWithValue("$generation", generation);
        update.Parameters.AddWithValue("$updated", updated.ToString("O"));
        update.Parameters.AddWithValue("$current", current);
        if (await update.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new InvalidOperationException(
                "Reconnect generation reservation lost concurrency.");
        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO reconnect_attempts(
                generation,attempt_id,state,updated_at)
            VALUES($generation,$attempt,$state,$updated)
            """;
        insert.Parameters.AddWithValue("$generation", generation);
        insert.Parameters.AddWithValue("$attempt", attemptId.ToString("D"));
        insert.Parameters.AddWithValue(
            "$state",
            (int)ReconnectAttemptState.Reserved);
        insert.Parameters.AddWithValue("$updated", updated.ToString("O"));
        await insert.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken)
            .ConfigureAwait(false);
        return new(
            generation,
            attemptId,
            ReconnectAttemptState.Reserved,
            updated);
    }

    public async Task<ReconnectAttempt> TransitionAsync(
        Guid sessionId,
        Guid hostId,
        Guid incarnationId,
        long generation,
        Guid attemptId,
        ReconnectAttemptState expected,
        ReconnectAttemptState next,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken = default)
    {
        ValidateIdentity(sessionId, hostId, incarnationId);
        if (generation <= 0 || attemptId == Guid.Empty ||
            !ValidTransition(expected, next))
            throw new ArgumentException(
                "Reconnect attempt transition is invalid.");
        var updated = observedAt.ToUniversalTime();
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE reconnect_attempts
            SET state=$next,updated_at=$updated
            WHERE generation=$generation
              AND attempt_id=$attempt
              AND state=$expected
              AND EXISTS(
                SELECT 1 FROM reconnect_state
                WHERE singleton=1
                  AND session_id=$session
                  AND host_id=$host
                  AND incarnation_id=$incarnation
                  AND generation=$generation)
            """;
        command.Parameters.AddWithValue(
            "$session",
            sessionId.ToString("D"));
        command.Parameters.AddWithValue("$host", hostId.ToString("D"));
        command.Parameters.AddWithValue(
            "$incarnation",
            incarnationId.ToString("D"));
        command.Parameters.AddWithValue("$next", (int)next);
        command.Parameters.AddWithValue("$updated", updated.ToString("O"));
        command.Parameters.AddWithValue("$generation", generation);
        command.Parameters.AddWithValue("$attempt", attemptId.ToString("D"));
        command.Parameters.AddWithValue("$expected", (int)expected);
        if (await command.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new InvalidOperationException(
                "Reconnect attempt transition does not match durable state.");
        return new(generation, attemptId, next, updated);
    }

    public async Task<ReconnectAttempt?> LoadAsync(
        long generation,
        CancellationToken cancellationToken = default)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT attempt_id,state,updated_at
            FROM reconnect_attempts
            WHERE generation=$generation
            """;
        command.Parameters.AddWithValue("$generation", generation);
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? new(
                generation,
                Guid.Parse(reader.GetString(0)),
                (ReconnectAttemptState)reader.GetInt32(1),
                DateTimeOffset.Parse(reader.GetString(2)))
            : null;
    }

    private void Initialize()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(
            deferred: false);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS reconnect_schema(
                version INTEGER NOT NULL);
            INSERT INTO reconnect_schema(version)
            SELECT 1 WHERE NOT EXISTS(
                SELECT 1 FROM reconnect_schema);
            CREATE TABLE IF NOT EXISTS reconnect_state(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                session_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                incarnation_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reconnect_attempts(
                generation INTEGER PRIMARY KEY NOT NULL,
                attempt_id TEXT NOT NULL UNIQUE,
                state INTEGER NOT NULL,
                updated_at TEXT NOT NULL);
            """;
        command.ExecuteNonQuery();
        command.CommandText =
            "SELECT version FROM reconnect_schema LIMIT 1";
        var version = Convert.ToInt32(command.ExecuteScalar());
        if (version is < 0 or > CurrentSchemaVersion)
            throw new InvalidDataException(
                $"Reconnect ledger schema {version} is unsupported.");
        if (version == 0)
        {
            command.CommandText =
                "UPDATE reconnect_schema SET version=1";
            command.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    private static async Task EnsureIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid sessionId,
        Guid hostId,
        Guid incarnationId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT session_id,host_id,incarnation_id
            FROM reconnect_state WHERE singleton=1
            """;
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (reader.GetString(0) != sessionId.ToString("D") ||
                reader.GetString(1) != hostId.ToString("D") ||
                reader.GetString(2) != incarnationId.ToString("D"))
                throw new InvalidOperationException(
                    "Reconnect ledger belongs to a different endpoint identity.");
            return;
        }
        await reader.DisposeAsync();
        command.CommandText = """
            INSERT INTO reconnect_state(
                singleton,session_id,host_id,incarnation_id,
                generation,updated_at)
            VALUES(1,$session,$host,$incarnation,0,$updated)
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString("D"));
        command.Parameters.AddWithValue("$host", hostId.ToString("D"));
        command.Parameters.AddWithValue(
            "$incarnation",
            incarnationId.ToString("D"));
        command.Parameters.AddWithValue(
            "$updated",
            DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=30000;
            """;
        command.ExecuteNonQuery();
        return connection;
    }

    private static void ValidateIdentity(
        Guid sessionId,
        Guid hostId,
        Guid incarnationId)
    {
        if (sessionId == Guid.Empty ||
            hostId == Guid.Empty ||
            incarnationId == Guid.Empty)
            throw new ArgumentException(
                "Reconnect endpoint identity must be nonempty.");
    }

    private static bool ValidTransition(
        ReconnectAttemptState expected,
        ReconnectAttemptState next) =>
        (expected, next) is
            (ReconnectAttemptState.Reserved,
                ReconnectAttemptState.CarrierAuthenticated) or
            (ReconnectAttemptState.CarrierAuthenticated,
                ReconnectAttemptState.SecureAuthenticated) or
            (ReconnectAttemptState.SecureAuthenticated,
                ReconnectAttemptState.Online) or
            (ReconnectAttemptState.Reserved,
                ReconnectAttemptState.Abandoned) or
            (ReconnectAttemptState.CarrierAuthenticated,
                ReconnectAttemptState.Abandoned) or
            (ReconnectAttemptState.SecureAuthenticated,
                ReconnectAttemptState.Abandoned) or
            (ReconnectAttemptState.Online,
                ReconnectAttemptState.Closed);
}
