using Microsoft.Data.Sqlite;
using Steward.Orchestration;
using Steward.Terminal.Abstractions;

namespace Steward.Node.Host;

public sealed class DurableTerminalRevocationStore : ITerminalRevocationSink
{
    private readonly string connectionString;
    private long current;

    public DurableTerminalRevocationStore(string path)
    {
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(path),
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
          CREATE TABLE IF NOT EXISTS terminal_revocations(
            session_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,updated_at TEXT NOT NULL);
          SELECT COALESCE(MAX(revision),0) FROM terminal_revocations;
          """;
        current = Convert.ToInt64(command.ExecuteScalar());
    }

    public long CurrentRevision => Interlocked.Read(ref current);

    public async ValueTask AdvanceAsync(
        TerminalSessionId sessionId, long revision, CancellationToken cancellationToken)
    {
        if (revision <= 0) throw new ArgumentOutOfRangeException(nameof(revision));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
          INSERT INTO terminal_revocations(session_id,revision,updated_at)
          VALUES($id,$revision,$now)
          ON CONFLICT(session_id) DO UPDATE SET revision=MAX(revision,excluded.revision),
            updated_at=excluded.updated_at;
          """;
        command.Parameters.AddWithValue("$id", sessionId.ToString());
        command.Parameters.AddWithValue("$revision", revision);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken);
        Interlocked.Exchange(ref current, Math.Max(CurrentRevision, revision));
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;";
        command.ExecuteNonQuery();
        return connection;
    }
}
