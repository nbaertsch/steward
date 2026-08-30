using Microsoft.Data.Sqlite;
using Steward.Domain;

namespace Steward.Runtime.Windows;

public enum LaunchPhase { Planned, ProcessCreatedSuspended, AssignedToJob, Resumed, Exited }

public sealed record ExecutionJournalEntry(
    TaskAttemptId AttemptId,
    int Generation,
    int? ProcessId,
    long? ProcessCreationTimeUtcTicks,
    string JobName,
    string BootId,
    LaunchPhase Phase,
    string State,
    string StdoutPath,
    string StderrPath,
    long StdoutOffset,
    long StderrOffset,
    bool OutputTruncated,
    long OutputLimit,
    int? ThreadId = null,
    string? FailureDetail = null);

public sealed class ExecutionJournalSchemaException(string message) : InvalidOperationException(message);
public sealed class ExecutionIdentityConflictException(string message) : InvalidOperationException(message);

public sealed class ExecutionJournal
{
    public const int SchemaVersion = 2;
    private readonly string connectionString;

    public ExecutionJournal(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        connectionString = new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate }.ToString();
        using var connection = OpenRaw();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;";
        command.ExecuteNonQuery();
        command.CommandText = "PRAGMA user_version;";
        var version = Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='executions';";
        var hasExecutions = Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) != 0;
        if (version == 0 && hasExecutions)
            throw new ExecutionJournalSchemaException("An unversioned execution journal cannot be adopted.");
        if (version != 0 && version != SchemaVersion)
            throw new ExecutionJournalSchemaException($"Execution journal schema {version} is unsupported; expected {SchemaVersion}.");

        command.CommandText = $"""
            CREATE TABLE IF NOT EXISTS executions (
              attempt_id TEXT NOT NULL,
              generation INTEGER NOT NULL,
              pid INTEGER NULL,
              creation_ticks INTEGER NULL,
              job_name TEXT NOT NULL,
              boot_id TEXT NOT NULL,
              phase INTEGER NOT NULL,
              state TEXT NOT NULL,
              stdout_path TEXT NOT NULL,
              stderr_path TEXT NOT NULL,
              stdout_offset INTEGER NOT NULL DEFAULT 0,
              stderr_offset INTEGER NOT NULL DEFAULT 0,
              output_truncated INTEGER NOT NULL DEFAULT 0,
              output_limit INTEGER NOT NULL,
              thread_id INTEGER NULL,
              failure_detail TEXT NULL,
              PRIMARY KEY(attempt_id, generation)
            );
            CREATE TABLE IF NOT EXISTS journal_metadata (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO journal_metadata(key,value) VALUES ('schema_version','{SchemaVersion}');
            PRAGMA user_version={SchemaVersion};
            """;
        command.ExecuteNonQuery();
        command.CommandText = "SELECT value FROM journal_metadata WHERE key='schema_version';";
        if (!StringComparer.Ordinal.Equals(command.ExecuteScalar()?.ToString(), SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)))
            throw new ExecutionJournalSchemaException("Execution journal metadata does not match the supported schema.");
    }

    public void InsertPlanned(ExecutionJournalEntry entry)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        ValidatePlanned(entry);
        command.CommandText = """
            INSERT INTO executions
            (attempt_id,generation,pid,creation_ticks,job_name,boot_id,phase,state,stdout_path,stderr_path,stdout_offset,stderr_offset,output_truncated,output_limit,thread_id,failure_detail)
            VALUES ($attempt,$generation,NULL,NULL,$job,$boot,$phase,$state,$stdout,$stderr,0,0,0,$limit,NULL,NULL);
            """;
        BindIdentity(command, entry);
        command.Parameters.AddWithValue("$job", entry.JobName);
        command.Parameters.AddWithValue("$boot", entry.BootId);
        command.Parameters.AddWithValue("$phase", (int)entry.Phase);
        command.Parameters.AddWithValue("$state", entry.State);
        command.Parameters.AddWithValue("$stdout", entry.StdoutPath);
        command.Parameters.AddWithValue("$stderr", entry.StderrPath);
        command.Parameters.AddWithValue("$limit", entry.OutputLimit);
        try { command.ExecuteNonQuery(); }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
        {
            throw new Steward.Tasks.Abstractions.ExecutionRecoveryException(
                $"Attempt {entry.AttemptId}/{entry.Generation} already has launch evidence and must be recovered.", true);
        }
    }

    public void SetProcess(TaskAttemptId attemptId, int generation, int pid, long creationTicks, int threadId, LaunchPhase phase)
    {
        if (pid <= 0 || creationTicks <= 0 || threadId <= 0 || phase != LaunchPhase.AssignedToJob)
            throw new ExecutionIdentityConflictException("A durable process identity requires positive PID, creation time, thread ID, and AssignedToJob phase.");
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE executions SET pid=$pid,creation_ticks=$ticks,thread_id=$thread,phase=$phase,state='launching'
            WHERE attempt_id=$attempt AND generation=$generation AND phase=$planned
              AND pid IS NULL AND creation_ticks IS NULL AND thread_id IS NULL
            """;
        BindIdentity(command, attemptId, generation);
        command.Parameters.AddWithValue("$pid", pid);
        command.Parameters.AddWithValue("$ticks", creationTicks);
        command.Parameters.AddWithValue("$thread", threadId);
        command.Parameters.AddWithValue("$phase", (int)phase);
        command.Parameters.AddWithValue("$planned", (int)LaunchPhase.Planned);
        if (command.ExecuteNonQuery() != 1)
            throw new ExecutionIdentityConflictException("Process identity is immutable or the launch is not in Planned phase.");
    }

    public void SetPhase(TaskAttemptId attemptId, int generation, LaunchPhase phase, string state)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE executions SET phase=$phase,state=$state WHERE attempt_id=$attempt AND generation=$generation AND phase<=$phase";
        BindIdentity(command, attemptId, generation);
        command.Parameters.AddWithValue("$phase", (int)phase);
        command.Parameters.AddWithValue("$state", state);
        RequireOne(command.ExecuteNonQuery());
    }

    public void SetCursor(TaskAttemptId attemptId, int generation, string stream, long offset)
    {
        var column = stream switch { "stdout" => "stdout_offset", "stderr" => "stderr_offset", _ => throw new ArgumentOutOfRangeException(nameof(stream)) };
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"UPDATE executions SET {column}=$offset WHERE attempt_id=$attempt AND generation=$generation";
        BindIdentity(command, attemptId, generation);
        command.Parameters.AddWithValue("$offset", offset);
        RequireOne(command.ExecuteNonQuery());
    }

    public void MarkTruncated(TaskAttemptId attemptId, int generation)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE executions SET output_truncated=1,state='interrupted' WHERE attempt_id=$attempt AND generation=$generation";
        BindIdentity(command, attemptId, generation);
        RequireOne(command.ExecuteNonQuery());
    }

    public void MarkMonitorFailure(TaskAttemptId attemptId, int generation, string detail)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE executions SET state='recovering',failure_detail=$detail WHERE attempt_id=$attempt AND generation=$generation";
        BindIdentity(command, attemptId, generation);
        command.Parameters.AddWithValue("$detail", detail);
        RequireOne(command.ExecuteNonQuery());
    }

    public ExecutionJournalEntry? Get(TaskAttemptId attemptId, int generation)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT pid,creation_ticks,job_name,boot_id,phase,state,stdout_path,stderr_path,stdout_offset,stderr_offset,output_truncated,output_limit,thread_id,failure_detail FROM executions WHERE attempt_id=$attempt AND generation=$generation";
        BindIdentity(command, attemptId, generation);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var entry = new ExecutionJournalEntry(
            attemptId, generation,
            reader.IsDBNull(0) ? null : reader.GetInt32(0),
            reader.IsDBNull(1) ? null : reader.GetInt64(1),
            reader.GetString(2), reader.GetString(3), (LaunchPhase)reader.GetInt32(4), reader.GetString(5),
            reader.GetString(6), reader.GetString(7), reader.GetInt64(8), reader.GetInt64(9),
            reader.GetBoolean(10), reader.GetInt64(11),
            reader.IsDBNull(12) ? null : reader.GetInt32(12),
            reader.IsDBNull(13) ? null : reader.GetString(13));
        ValidatePersisted(entry);
        return entry;
    }

    private SqliteConnection Open()
    {
        var connection = OpenRaw();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;";
        command.ExecuteNonQuery();
        return connection;
    }

    private SqliteConnection OpenRaw()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    private static void ValidatePlanned(ExecutionJournalEntry entry)
    {
        var expectedJob = $@"Local\Steward.{entry.AttemptId.Value:N}.{entry.Generation}";
        if (entry.Generation <= 0 || entry.Phase != LaunchPhase.Planned ||
            !StringComparer.Ordinal.Equals(entry.JobName, expectedJob) ||
            string.IsNullOrWhiteSpace(entry.BootId) || entry.OutputLimit <= 0 ||
            !Path.IsPathFullyQualified(entry.StdoutPath) || !Path.IsPathFullyQualified(entry.StderrPath))
            throw new ExecutionIdentityConflictException("Planned execution identity or immutable storage metadata is invalid.");
    }

    private static void ValidatePersisted(ExecutionJournalEntry entry)
    {
        var expectedJob = $@"Local\Steward.{entry.AttemptId.Value:N}.{entry.Generation}";
        var processIdentityComplete = entry.ProcessId > 0 && entry.ProcessCreationTimeUtcTicks > 0 && entry.ThreadId > 0;
        if (entry.Generation <= 0 || !Enum.IsDefined(entry.Phase) ||
            !StringComparer.Ordinal.Equals(entry.JobName, expectedJob) ||
            string.IsNullOrWhiteSpace(entry.BootId) || entry.OutputLimit <= 0 ||
            !Path.IsPathFullyQualified(entry.StdoutPath) || !Path.IsPathFullyQualified(entry.StderrPath) ||
            (entry.Phase == LaunchPhase.Planned && (entry.ProcessId is not null || entry.ProcessCreationTimeUtcTicks is not null || entry.ThreadId is not null)) ||
            (entry.Phase != LaunchPhase.Planned && !processIdentityComplete))
            throw new ExecutionIdentityConflictException("Persisted execution identity is invalid or inconsistent.");
    }

    private static void BindIdentity(SqliteCommand command, ExecutionJournalEntry entry) => BindIdentity(command, entry.AttemptId, entry.Generation);
    private static void BindIdentity(SqliteCommand command, TaskAttemptId attemptId, int generation)
    {
        command.Parameters.AddWithValue("$attempt", attemptId.ToString());
        command.Parameters.AddWithValue("$generation", generation);
    }

    private static void RequireOne(int count)
    {
        if (count != 1) throw new InvalidOperationException("Execution journal identity was not found.");
    }
}
