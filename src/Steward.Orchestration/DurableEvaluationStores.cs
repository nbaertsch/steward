using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Workloads.Evals;

namespace Steward.Orchestration;

public sealed class SqliteEvaluationStore :
    IRunnerStateStore,
    IEvaluationResultStore,
    IEvaluationRateFeedbackSink,
    IEvaluationTaskResultWriter,
    INodeRateFeedbackSource
{
    private readonly string connectionString;

    public SqliteEvaluationStore(string databasePath)
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
            CREATE TABLE IF NOT EXISTS evaluation_schema(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                version INTEGER NOT NULL
            );
            INSERT INTO evaluation_schema(singleton,version)
            SELECT 1,1 WHERE NOT EXISTS(SELECT 1 FROM evaluation_schema);
            CREATE TABLE IF NOT EXISTS evaluation_runner_states(
                attempt_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                state_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(attempt_id,generation)
            );
            CREATE TABLE IF NOT EXISTS evaluation_task_results(
                task_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                attempt_generation INTEGER NOT NULL,
                result_json TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(task_id,case_id,attempt_generation)
            );
            CREATE TABLE IF NOT EXISTS evaluation_manifests(
                location TEXT NOT NULL,
                manifest_key TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(location,manifest_key)
            );
            CREATE TABLE IF NOT EXISTS evaluation_rate_feedback(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                retry_after TEXT NOT NULL,
                created_at TEXT NOT NULL,
                processed_at TEXT
            );
            """;
        command.ExecuteNonQuery();
        command.CommandText = "PRAGMA table_info(evaluation_rate_feedback);";
        var hasProcessed = false;
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                hasProcessed |= reader.GetString(1) == "processed_at";
        if (!hasProcessed)
        {
            command.CommandText =
                "ALTER TABLE evaluation_rate_feedback ADD COLUMN processed_at TEXT;";
            command.ExecuteNonQuery();
        }
        command.CommandText = "SELECT version FROM evaluation_schema WHERE singleton=1";
        if (Convert.ToInt32(command.ExecuteScalar()) != 1)
            throw new InvalidDataException("Evaluation store schema is newer than this Node supports.");
    }

    public async ValueTask<EvaluationRunnerState?> LoadAsync(
        TaskAttemptId attemptId, int generation, CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT state_json FROM evaluation_runner_states
            WHERE attempt_id=$attempt AND generation=$generation
            """;
        command.Parameters.AddWithValue("$attempt", attemptId.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return json is null ? null :
            JsonSerializer.Deserialize<EvaluationRunnerState>(json, StewardJson.Options)
            ?? throw new InvalidDataException("Durable evaluation runner state is invalid.");
    }

    public async ValueTask SaveAsync(
        EvaluationRunnerState state, CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO evaluation_runner_states(attempt_id,generation,state_json,updated_at)
            VALUES($attempt,$generation,$json,$now)
            ON CONFLICT(attempt_id,generation) DO UPDATE SET
              state_json=excluded.state_json,updated_at=excluded.updated_at
            """;
        command.Parameters.AddWithValue("$attempt", state.AttemptId.ToString());
        command.Parameters.AddWithValue("$generation", state.Generation);
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(state, StewardJson.Options));
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async ValueTask DeleteAsync(
        TaskAttemptId attemptId, int generation, CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            DELETE FROM evaluation_runner_states
            WHERE attempt_id=$attempt AND generation=$generation
            """;
        command.Parameters.AddWithValue("$attempt", attemptId.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async ValueTask<IReadOnlyList<EvaluationCaseResult>> ReadTaskResultsAsync(
        TaskId taskId, CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT result_json FROM evaluation_task_results
            WHERE task_id=$task ORDER BY case_id,attempt_generation
            """;
        command.Parameters.AddWithValue("$task", taskId.ToString());
        var result = new List<EvaluationCaseResult>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(JsonSerializer.Deserialize<EvaluationCaseResult>(
                reader.GetString(0), StewardJson.Options)
                ?? throw new InvalidDataException("Durable evaluation result is invalid."));
        return result;
    }

    public async ValueTask RecordTaskResultAsync(
        TaskId taskId,
        EvaluationCaseResult result,
        CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(result, StewardJson.Options);
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO evaluation_task_results(
                task_id,case_id,attempt_generation,result_json,receipt_hash,created_at)
            VALUES($task,$case,$generation,$json,$hash,$now)
            ON CONFLICT(task_id,case_id,attempt_generation) DO UPDATE SET
              result_json=excluded.result_json
            WHERE evaluation_task_results.receipt_hash=excluded.receipt_hash
            """;
        command.Parameters.AddWithValue("$task", taskId.ToString());
        command.Parameters.AddWithValue("$case", result.CaseId);
        command.Parameters.AddWithValue("$generation", result.AttemptGeneration);
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue("$hash", result.ReceiptHash);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException("Evaluation result identity conflicts with durable content.");
    }

    public async ValueTask<EvaluationCaseResult> ReadPortableResultAsync(
        string reference, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reference);
        if (!Uri.TryCreate(reference, UriKind.Absolute, out var uri) ||
            uri.Scheme != "steward-result" ||
            !TaskId.TryParse(uri.Host, out var taskId))
            throw new InvalidDataException("Portable evaluation result reference is invalid.");
        var caseId = Uri.UnescapeDataString(uri.AbsolutePath.Trim('/'));
        var results = await ReadTaskResultsAsync(taskId, cancellationToken);
        return results.Single(x => x.CaseId == caseId);
    }

    public async ValueTask<EvaluationManifestReceipt?> ReadManifestAsync(
        string location, string manifestKey, CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT receipt_json FROM evaluation_manifests
            WHERE location=$location AND manifest_key=$key
            """;
        command.Parameters.AddWithValue("$location", location);
        command.Parameters.AddWithValue("$key", manifestKey);
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return json is null ? null :
            JsonSerializer.Deserialize<EvaluationManifestReceipt>(json, StewardJson.Options)
            ?? throw new InvalidDataException("Durable evaluation manifest receipt is invalid.");
    }

    public async ValueTask<EvaluationManifestReceipt> WriteManifestAsync(
        string location,
        string manifestKey,
        EvaluationExportManifest manifest,
        CancellationToken cancellationToken)
    {
        var receipt = new EvaluationManifestReceipt(
            $"{location.TrimEnd('/')}/{manifestKey}.json", manifest.ManifestHash, manifest);
        var json = JsonSerializer.Serialize(receipt, StewardJson.Options);
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO evaluation_manifests(
                location,manifest_key,receipt_json,manifest_hash,created_at)
            VALUES($location,$key,$json,$hash,$now)
            ON CONFLICT(location,manifest_key) DO NOTHING
            """;
        command.Parameters.AddWithValue("$location", location);
        command.Parameters.AddWithValue("$key", manifestKey);
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue("$hash", manifest.ManifestHash);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        var inserted = await command.ExecuteNonQueryAsync(cancellationToken);
        if (inserted == 0)
        {
            command.CommandText = """
                SELECT receipt_json,manifest_hash FROM evaluation_manifests
                WHERE location=$location AND manifest_key=$key
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken) ||
                reader.GetString(1) != manifest.ManifestHash ||
                reader.GetString(0) != json)
                throw new InvalidOperationException("Evaluation manifest key conflicts with durable content.");
        }
        await transaction.CommitAsync(cancellationToken);
        return receipt;
    }

    public async ValueTask ReportThrottleAsync(
        string scope, DateTimeOffset retryAfter, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO evaluation_rate_feedback(scope,retry_after,created_at)
            VALUES($scope,$retry,$now)
            """;
        command.Parameters.AddWithValue("$scope", scope);
        command.Parameters.AddWithValue("$retry", retryAfter.ToString("O"));
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async ValueTask<IReadOnlyList<RateFeedbackFact>> ReadPendingAsync(
        int maximumCount, CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT sequence,scope,retry_after FROM evaluation_rate_feedback
            WHERE processed_at IS NULL ORDER BY sequence LIMIT $limit
            """;
        command.Parameters.AddWithValue("$limit", maximumCount);
        var values = new List<RateFeedbackFact>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            values.Add(new(reader.GetInt64(0), reader.GetString(1),
                DateTimeOffset.Parse(reader.GetString(2))));
        return values;
    }

    public async ValueTask MarkProcessedAsync(
        long feedbackSequence, CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE evaluation_rate_feedback SET processed_at=$now
            WHERE sequence=$sequence
            """;
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$sequence", feedbackSequence);
        await command.ExecuteNonQueryAsync(cancellationToken);
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
