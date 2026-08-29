using Steward.Domain;
using Steward.Persistence.Sqlite;
using Steward.Terminal.Abstractions;

namespace Steward.Orchestration;

public sealed class ControlTerminalRevocationStore(SqliteControlStore store)
{
    public async Task EnqueueAsync(
        HostId hostId, NodeIncarnationId nodeId, TerminalSessionId sessionId,
        long revision, CancellationToken cancellationToken)
    {
        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        await using (var initialize = connection.CreateCommand())
        {
            initialize.CommandText = """
              CREATE TABLE IF NOT EXISTS terminal_revocation_outbox(
                host_id TEXT NOT NULL,node_incarnation_id TEXT NOT NULL,session_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,delivered INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL);
              """;
            await initialize.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var command = connection.CreateCommand();
        command.CommandText = """
          CREATE TABLE IF NOT EXISTS terminal_revocation_outbox(
            host_id TEXT NOT NULL,node_incarnation_id TEXT NOT NULL,session_id TEXT PRIMARY KEY,
            revision INTEGER NOT NULL,delivered INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL);
          INSERT INTO terminal_revocation_outbox(
            host_id,node_incarnation_id,session_id,revision,delivered,updated_at)
          VALUES($host,$node,$session,$revision,0,$now)
          ON CONFLICT(session_id) DO UPDATE SET
            revision=MAX(revision,excluded.revision),delivered=0,updated_at=excluded.updated_at;
          """;
        command.Parameters.AddWithValue("$host", hostId.ToString());
        command.Parameters.AddWithValue("$node", nodeId.ToString());
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$revision", revision);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<TerminalRevocationCommand>> ReadAsync(
        HostId hostId, NodeIncarnationId nodeId, CancellationToken cancellationToken)
    {
        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        await using (var initialize = connection.CreateCommand())
        {
            initialize.CommandText = """
              CREATE TABLE IF NOT EXISTS terminal_revocation_outbox(
                host_id TEXT NOT NULL,node_incarnation_id TEXT NOT NULL,session_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,delivered INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL);
              """;
            await initialize.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var command = connection.CreateCommand();
        command.CommandText = """
          SELECT session_id,revision FROM terminal_revocation_outbox
          WHERE host_id=$host AND node_incarnation_id=$node AND delivered=0 ORDER BY updated_at;
          """;
        command.Parameters.AddWithValue("$host", hostId.ToString());
        command.Parameters.AddWithValue("$node", nodeId.ToString());
        var values = new List<TerminalRevocationCommand>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            values.Add(new(TerminalSessionId.Parse(reader.GetString(0)), reader.GetInt64(1)));
        return values;
    }

    public async Task MarkDeliveredAsync(
        TerminalSessionId id, long revision, CancellationToken cancellationToken)
    {
        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
          UPDATE terminal_revocation_outbox SET delivered=1
          WHERE session_id=$id AND revision=$revision;
          """;
        command.Parameters.AddWithValue("$id", id.ToString());
        command.Parameters.AddWithValue("$revision", revision);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
