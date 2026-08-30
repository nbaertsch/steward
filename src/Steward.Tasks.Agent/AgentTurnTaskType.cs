using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Tasks.Abstractions;

namespace Steward.Tasks.Agent;

public sealed record AgentTurnTaskInput(
    StewardAgentId AgentId,
    AgentTurnId TurnId,
    string Text,
    string Provenance,
    IReadOnlyList<string> Context,
    IReadOnlyList<string> Tools,
    IReadOnlyDictionary<string, string> Environment,
    string RuntimeProfile,
    string Executable,
    IReadOnlyList<string> Arguments,
    int MaximumOutputBytes);

public sealed record DurableAgentEvent(long Sequence, string Kind, string Text, string? Receipt);

public sealed class AgentTurnStateStore
{
    private readonly string connectionString;
    public AgentTurnStateStore(string path)
    {
        connectionString = new SqliteConnectionStringBuilder { DataSource = Path.GetFullPath(path) }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        var version = Convert.ToInt32(command.ExecuteScalar());
        if (version is not (0 or 1))
            throw new InvalidDataException($"Agent turn state schema {version} is unsupported.");
        command.CommandText = """
          CREATE TABLE IF NOT EXISTS agent_turn_events(
            attempt_id TEXT NOT NULL,generation INTEGER NOT NULL,sequence INTEGER NOT NULL,
            kind TEXT NOT NULL,text TEXT NOT NULL,receipt TEXT,
            PRIMARY KEY(attempt_id,generation,sequence));
          PRAGMA user_version=1;
          """;
        command.ExecuteNonQuery();
    }
    public void Append(TaskAttemptId attempt, int generation, DurableAgentEvent value)
    {
        if (generation <= 0 || value.Sequence <= 0 ||
            value.Kind is not ("activity" or "final") ||
            Encoding.UTF8.GetByteCount(value.Text) > 1024 * 1024 ||
            value.Receipt?.Length > 128)
            throw new InvalidDataException("Durable Agent event exceeds persisted bounds.");
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
          INSERT OR IGNORE INTO agent_turn_events(
            attempt_id,generation,sequence,kind,text,receipt)
          VALUES($attempt,$generation,$sequence,$kind,$text,$receipt);
          """;
        command.Parameters.AddWithValue("$attempt", attempt.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        command.Parameters.AddWithValue("$sequence", value.Sequence);
        command.Parameters.AddWithValue("$kind", value.Kind);
        command.Parameters.AddWithValue("$text", value.Text);
        command.Parameters.AddWithValue("$receipt", (object?)value.Receipt ?? DBNull.Value);
        var inserted = command.ExecuteNonQuery();
        if (inserted == 0)
        {
            command.CommandText = """
              SELECT kind,text,receipt FROM agent_turn_events
              WHERE attempt_id=$attempt AND generation=$generation AND sequence=$sequence;
              """;
            using var reader = command.ExecuteReader();
            if (!reader.Read() ||
                reader.GetString(0) != value.Kind ||
                reader.GetString(1) != value.Text ||
                (reader.IsDBNull(2) ? null : reader.GetString(2)) != value.Receipt)
                throw new InvalidDataException(
                    "Durable Agent event sequence conflicts with persisted content.");
        }
    }
    public IReadOnlyList<DurableAgentEvent> Read(TaskAttemptId attempt, int generation, long after)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
          SELECT sequence,kind,text,receipt FROM agent_turn_events
          WHERE attempt_id=$attempt AND generation=$generation AND sequence>$after
          ORDER BY sequence;
          """;
        command.Parameters.AddWithValue("$attempt", attempt.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        command.Parameters.AddWithValue("$after", after);
        using var reader = command.ExecuteReader();
        var values = new List<DurableAgentEvent>();
        while (reader.Read())
        {
            var value = new DurableAgentEvent(
                reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3));
            if (value.Sequence <= 0 || value.Kind is not ("activity" or "final") ||
                Encoding.UTF8.GetByteCount(value.Text) > 1024 * 1024 ||
                value.Receipt?.Length > 128)
                throw new InvalidDataException("Persisted Agent event is corrupt.");
            values.Add(value);
        }
        return values;
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

public sealed class AgentTurnTaskType(
    IProcessExecutor executor,
    AgentTurnStateStore store,
    string allowedExecutable,
    string runtimeProfile) : TaskTypeBase, ITaskOutputSource, IRecoverableTaskType
{
    public override TaskTypeVersion Type => new("steward-agent-turn", new Version(1, 0));
    public override TaskCapabilities Capabilities =>
        TaskCapabilities.Execute | TaskCapabilities.Observe | TaskCapabilities.Cancel;
    public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;

    public override ValidationResult Validate(JsonElement input)
    {
        try
        {
            var value = input.Deserialize<AgentTurnTaskInput>(StewardJson.Options)!;
            if (value.Executable != allowedExecutable || value.RuntimeProfile != runtimeProfile ||
                Encoding.UTF8.GetByteCount(value.Text) > 256 * 1024 ||
                value.Context.Sum(x => Encoding.UTF8.GetByteCount(x)) > 4 * 1024 * 1024 ||
                value.Tools.Count > 256 || value.Environment.Count > 256 ||
                value.MaximumOutputBytes is <= 0 or > 16 * 1024 * 1024)
                return ValidationResult.Invalid("Agent turn input is outside configured bounds.");
            return ValidationResult.Valid;
        }
        catch (JsonException) { return ValidationResult.Invalid("Agent turn input is invalid."); }
    }

    public override async ValueTask<IExecutionHandle> StartAsync(
        TaskExecutionContext context, CancellationToken cancellationToken)
    {
        var value = context.Input.Deserialize<AgentTurnTaskInput>(StewardJson.Options)!;
        var inputPath = Path.Combine(context.Workspace, ".steward", "agent-input.jsonl");
        Directory.CreateDirectory(Path.GetDirectoryName(inputPath)!);
        var request = JsonSerializer.Serialize(new
        {
            schema = "steward.agent-turn/1.0",
            agentId = value.AgentId.ToString(),
            turnId = value.TurnId.ToString(),
            value.Text, value.Provenance, value.Context, value.Tools, value.Environment
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        await File.WriteAllTextAsync(inputPath, request + Environment.NewLine, cancellationToken);
        return await executor.StartAsync(new(
            context.AttemptId, context.Generation, value.Executable, value.Arguments,
            context.Workspace, Path.Combine(context.Workspace, ".steward", "spool"),
            value.MaximumOutputBytes, 256 * 1024 * 1024, StandardInputPath: inputPath), cancellationToken);
    }

    public override async ValueTask<ExecutionObservation> ObserveAsync(
        IExecutionHandle execution, CancellationToken cancellationToken)
    {
        var observation = await executor.ObserveAsync(execution, cancellationToken);
        if (observation.State == ExecutionState.Exited)
            await DrainAsync(execution, cancellationToken);
        return observation;
    }

    private async Task DrainAsync(IExecutionHandle execution, CancellationToken token)
    {
        const int maximumLineBytes = 1024 * 1024;
        var pending = new List<byte>();
        long offset = 0;
        long sequence = 0;
        var final = false;
        while (true)
        {
            var read = await executor.ReadOutputAsync(
                execution, "stdout", offset, 64 * 1024, token);
            offset = read.Cursor.Offset;
            foreach (var value in read.Data.Span)
            {
                if (value == (byte)'\n')
                {
                    if (pending.Count > 0)
                    {
                        ParseLine(pending, execution, ref sequence, ref final);
                        pending.Clear();
                    }
                }
                else
                {
                    pending.Add(value);
                    if (pending.Count > maximumLineBytes)
                        throw new InvalidDataException("Agent runtime JSONL line exceeds its bound.");
                }
            }
            if (read.Data.IsEmpty || offset >= read.Cursor.Length) break;
        }
        if (pending.Count > 0)
            ParseLine(pending, execution, ref sequence, ref final);
        if (!final) throw new InvalidDataException("Agent runtime emitted no final response.");
    }

    private void ParseLine(
        IReadOnlyCollection<byte> bytes,
        IExecutionHandle execution,
        ref long sequence,
        ref bool final)
    {
        string line;
        try { line = new UTF8Encoding(false, true).GetString(bytes.ToArray()).TrimEnd('\r'); }
        catch (DecoderFallbackException)
        {
            throw new InvalidDataException("Agent runtime emitted invalid UTF-8 JSONL.");
        }
        JsonDocument document;
        try { document = JsonDocument.Parse(line); }
        catch (JsonException)
        {
            throw new InvalidDataException("Agent runtime emitted malformed JSONL.");
        }
        using (document)
        {
            var kind = document.RootElement.GetProperty("type").GetString();
            var text = document.RootElement.GetProperty("text").GetString() ?? string.Empty;
            if (kind == "final")
            {
                if (final) throw new InvalidDataException("Agent runtime emitted duplicate final response.");
                final = true;
                var receipt = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
                store.Append(execution.AttemptId, execution.Generation,
                    new(++sequence, "final", text, receipt));
            }
            else if (kind == "activity")
                store.Append(execution.AttemptId, execution.Generation,
                    new(++sequence, "activity", text, null));
            else throw new InvalidDataException("Agent runtime emitted unknown JSONL event.");
        }
    }

    public ValueTask<TaskOutputBatch> ReadOutputsAsync(
        IExecutionHandle execution, long afterCursor, int maximumCount, CancellationToken cancellationToken)
    {
        var values = store.Read(execution.AttemptId, execution.Generation, afterCursor)
            .Take(maximumCount).ToArray();
        IReadOnlyList<TaskRuntimeOutput> outputs = values.Select(x => x.Kind == "final"
            ? (TaskRuntimeOutput)new TaskRuntimeAgentFinal(x.Text, x.Receipt!)
            : new TaskRuntimeAgentActivity(x.Text)).ToArray();
        return ValueTask.FromResult(new TaskOutputBatch(
            values.LastOrDefault()?.Sequence ?? afterCursor, outputs));
    }

    public override ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken token) =>
        executor.CancelAsync(execution, gracePeriod, token);

    public async ValueTask<TaskExecutionRecoveryResult> RecoverExecutionAsync(
        TaskExecutionContext context, string currentBootIdentity, CancellationToken cancellationToken)
    {
        try
        {
            var execution = await executor.RecoverAsync(
                context.AttemptId, context.Generation, currentBootIdentity, cancellationToken);
            return new(TaskExecutionRecoveryStatus.Present, execution, "agent.present");
        }
        catch (ExecutionRecoveryException exception)
        {
            return new(exception.IsAmbiguous ? TaskExecutionRecoveryStatus.Ambiguous :
                TaskExecutionRecoveryStatus.Absent, Code: "agent.recovery");
        }
    }
}
