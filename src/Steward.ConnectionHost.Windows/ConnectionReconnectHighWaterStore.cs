using Microsoft.Data.Sqlite;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public interface IConnectionGenerationStore
{
    Task<long> ReserveAsync(
        string connectionId,
        CancellationToken cancellationToken);
}

public sealed class SqliteConnectionGenerationStore :
    IConnectionGenerationStore
{
    private readonly string connectionString;

    public SqliteConnectionGenerationStore(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath) ||
            !Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException(
                "The connection generation database path must be absolute.",
                nameof(databasePath));
        var path = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(
            Path.GetDirectoryName(path) ??
            throw new ArgumentException(
                "The connection generation path has no directory.",
                nameof(databasePath)));
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS connection_generations(
                connection_id TEXT PRIMARY KEY NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                updated_at TEXT NOT NULL);
            """;
        command.ExecuteNonQuery();
    }

    public async Task<long> ReserveAsync(
        string connectionId,
        CancellationToken cancellationToken)
    {
        ValidateConnectionId(connectionId);
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(
            deferred: false);
        await using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText = """
            SELECT generation FROM connection_generations
            WHERE connection_id=$connection
            """;
        read.Parameters.AddWithValue("$connection", connectionId);
        await using var reader = await read.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        var prior = await reader.ReadAsync(cancellationToken)
                .ConfigureAwait(false)
            ? reader.GetInt64(0)
            : 0;
        await reader.DisposeAsync().ConfigureAwait(false);
        if (prior == long.MaxValue)
            throw new OverflowException(
                "The connection generation is exhausted.");
        var generation = checked(prior + 1);
        await using var write = connection.CreateCommand();
        write.Transaction = transaction;
        write.CommandText = prior == 0
            ? """
                INSERT INTO connection_generations(
                    connection_id,generation,updated_at)
                VALUES($connection,$generation,$updated)
                """
            : """
                UPDATE connection_generations
                SET generation=$generation,updated_at=$updated
                WHERE connection_id=$connection
                  AND generation=$prior
                """;
        write.Parameters.AddWithValue("$connection", connectionId);
        write.Parameters.AddWithValue("$generation", generation);
        write.Parameters.AddWithValue(
            "$updated",
            DateTimeOffset.UtcNow.ToString("O"));
        if (prior != 0)
            write.Parameters.AddWithValue("$prior", prior);
        if (await write.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new InvalidOperationException(
                "The connection generation compare-and-swap failed.");
        await transaction.CommitAsync(cancellationToken)
            .ConfigureAwait(false);
        return generation;
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

    internal static void ValidateConnectionId(string connectionId)
    {
        if (string.IsNullOrWhiteSpace(connectionId) ||
            connectionId.Length >
                ConnectionHostProtocol.MaximumConnectionIdCharacters ||
            connectionId.Any(char.IsControl))
            throw new ArgumentException(
                "The connection ID is invalid.",
                nameof(connectionId));
    }
}

internal sealed class InMemoryConnectionGenerationStore :
    IConnectionGenerationStore
{
    private readonly Dictionary<string, long> generations =
        new(StringComparer.Ordinal);
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<long> ReserveAsync(
        string connectionId,
        CancellationToken cancellationToken)
    {
        SqliteConnectionGenerationStore.ValidateConnectionId(connectionId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var generation = checked(
                generations.GetValueOrDefault(connectionId) + 1);
            generations[connectionId] = generation;
            return generation;
        }
        finally
        {
            gate.Release();
        }
    }
}
public interface IConnectionReconnectHighWaterStore
{
    Task ObserveAsync(
        string connectionId,
        RdpDvcCarrierAttemptIdentity identity,
        CancellationToken cancellationToken);
}

public sealed class SqliteConnectionReconnectHighWaterStore :
    IConnectionReconnectHighWaterStore
{
    private readonly string connectionString;

    public SqliteConnectionReconnectHighWaterStore(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath) ||
            !Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException(
                "The reconnect high-water database path must be absolute.",
                nameof(databasePath));
        var path = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(
            Path.GetDirectoryName(path) ??
            throw new ArgumentException(
                "The reconnect high-water database path has no directory.",
                nameof(databasePath)));
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString();
        Initialize();
    }

    public async Task ObserveAsync(
        string connectionId,
        RdpDvcCarrierAttemptIdentity identity,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connectionId) ||
            connectionId.Length >
                ConnectionHostProtocol.MaximumConnectionIdCharacters ||
            connectionId.Any(char.IsControl))
            throw new ArgumentException(
                "The reconnect ConnectionId is invalid.",
                nameof(connectionId));
        identity.Validate();
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(
            deferred: false);
        await using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText = """
            SELECT session_id,route_id,host_id,node_incarnation_id,generation
            FROM reconnect_high_water
            WHERE connection_id=$connection
            """;
        read.Parameters.AddWithValue("$connection", connectionId);
        await using var reader = await read.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var session = reader.GetString(0);
            var route = reader.GetString(1);
            var host = reader.GetString(2);
            var incarnation = reader.GetString(3);
            var generation = reader.GetInt64(4);
            await reader.DisposeAsync().ConfigureAwait(false);
            if (!string.Equals(
                    session,
                    identity.SessionId.ToString("D"),
                    StringComparison.Ordinal) ||
                !string.Equals(
                    route,
                    identity.RouteId.ToString("D"),
                    StringComparison.Ordinal) ||
                !string.Equals(
                    host,
                    identity.HostId.Value.ToString("D"),
                    StringComparison.Ordinal) ||
                !string.Equals(
                    incarnation,
                    identity.NodeIncarnationId.Value.ToString("D"),
                    StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "The reconnect ConnectionId belongs to another endpoint identity.");
            if (identity.ReconnectGeneration <= generation)
                throw new InvalidOperationException(
                    "The reconnect generation was replayed or moved backward.");
            await using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE reconnect_high_water
                SET generation=$generation,
                    attempt_id=$attempt,
                    wts_session_id=$wts,
                    updated_at=$updated
                WHERE connection_id=$connection
                  AND generation=$previous
                """;
            BindObservation(
                update,
                connectionId,
                identity,
                DateTimeOffset.UtcNow);
            update.Parameters.AddWithValue("$previous", generation);
            if (await update.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false) != 1)
                throw new InvalidOperationException(
                    "The reconnect high-water compare-and-swap failed.");
        }
        else
        {
            await reader.DisposeAsync().ConfigureAwait(false);
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO reconnect_high_water(
                    connection_id,session_id,route_id,host_id,
                    node_incarnation_id,
                    generation,attempt_id,wts_session_id,updated_at)
                VALUES(
                    $connection,$session,$route,$host,$incarnation,
                    $generation,$attempt,$wts,$updated)
                """;
            BindObservation(
                insert,
                connectionId,
                identity,
                DateTimeOffset.UtcNow);
            await insert.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private void Initialize()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS reconnect_high_water(
                connection_id TEXT PRIMARY KEY NOT NULL,
                session_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                node_incarnation_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                attempt_id TEXT NOT NULL,
                wts_session_id INTEGER NOT NULL CHECK(wts_session_id > 0),
                updated_at TEXT NOT NULL);
            """;
        command.ExecuteNonQuery();
        if (!HasRouteIdColumn(connection))
        {
            command.CommandText = """
                ALTER TABLE reconnect_high_water
                ADD COLUMN route_id TEXT NOT NULL DEFAULT '';
                UPDATE reconnect_high_water
                SET route_id=host_id
                WHERE route_id='';
                """;
            command.ExecuteNonQuery();
        }
    }

    private static bool HasRouteIdColumn(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(reconnect_high_water)";
        using var reader = command.ExecuteReader();
        while (reader.Read())
            if (string.Equals(
                    reader.GetString(1),
                    "route_id",
                    StringComparison.Ordinal))
                return true;
        return false;
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

    private static void BindObservation(
        SqliteCommand command,
        string connectionId,
        RdpDvcCarrierAttemptIdentity identity,
        DateTimeOffset observedAt)
    {
        command.Parameters.AddWithValue("$connection", connectionId);
        command.Parameters.AddWithValue(
            "$session",
            identity.SessionId.ToString("D"));
        command.Parameters.AddWithValue(
            "$route",
            identity.RouteId.ToString("D"));
        command.Parameters.AddWithValue(
            "$host",
            identity.HostId.Value.ToString("D"));
        command.Parameters.AddWithValue(
            "$incarnation",
            identity.NodeIncarnationId.Value.ToString("D"));
        command.Parameters.AddWithValue(
            "$generation",
            identity.ReconnectGeneration);
        command.Parameters.AddWithValue(
            "$attempt",
            identity.AttemptId.ToString("D"));
        command.Parameters.AddWithValue("$wts", identity.RdpSessionId);
        command.Parameters.AddWithValue(
            "$updated",
            observedAt.ToUniversalTime().ToString("O"));
    }
}
