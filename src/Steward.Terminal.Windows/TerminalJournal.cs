using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Domain;
using Steward.Terminal.Abstractions;

namespace Steward.Terminal.Windows;

public sealed record TerminalJournalOptions(int MaximumSessions = 4_096, int MaximumTranscriptRowsPerSession = 100_000);

public sealed class TerminalJournalSchemaException(string message) : InvalidOperationException(message);

public sealed record TerminalTranscriptRecord(
    long Sequence,
    string Direction,
    long Offset,
    int Length,
    string Sha256,
    DateTimeOffset RecordedAt,
    byte[]? Content);

public sealed record TerminalOperationStart(
    bool IsNew,
    TerminalOperationStatus Status,
    TerminalSessionSnapshot Snapshot);

public sealed class TerminalJournal
{
    public const int SchemaVersion = 2;
    private const string EmptyHash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    private readonly string connectionString;
    private readonly TerminalJournalOptions options;

    public TerminalJournal(string databasePath, TerminalJournalOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        this.options = options ?? new();
        if (this.options.MaximumSessions <= 0 || this.options.MaximumTranscriptRowsPerSession <= 0)
            throw new ArgumentOutOfRangeException(nameof(options));
        var path = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
            DefaultTimeout = 30
        }.ToString();
        Initialize();
    }

    public TerminalSessionSnapshot CreateRequested(
        TerminalOpenRequest request,
        string requestFingerprint,
        string bootId,
        DateTimeOffset now)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);

        using (var existingRequest = connection.CreateCommand())
        {
            existingRequest.Transaction = transaction;
            existingRequest.CommandText = "SELECT fingerprint, session_id FROM terminal_requests WHERE request_id=$request;";
            existingRequest.Parameters.AddWithValue("$request", request.RequestId);
            using var reader = existingRequest.ExecuteReader();
            if (reader.Read())
            {
                var fingerprint = reader.GetString(0);
                var sessionId = TerminalSessionId.Parse(reader.GetString(1));
                if (!StringComparer.Ordinal.Equals(fingerprint, requestFingerprint) || sessionId != request.Authority.SessionId)
                    throw Problem(TerminalProblemCode.IdempotencyConflict, "Request ID was already used with different terminal intent.",
                        TerminalProblemDisposition.RequiresNewUserIntent, false);
                reader.Close();
                transaction.Commit();
                return GetRequired(connection, sessionId);
            }
        }

        using (var admission = connection.CreateCommand())
        {
            admission.Transaction = transaction;
            admission.CommandText = "SELECT COUNT(*) FROM terminal_sessions;";
            if (Convert.ToInt32(admission.ExecuteScalar(), CultureInfo.InvariantCulture) >= options.MaximumSessions)
                throw Problem(TerminalProblemCode.SessionLimitExceeded, "Terminal journal session limit reached.",
                    TerminalProblemDisposition.RequiresReconciliation, false);
        }

        var authority = request.Authority;
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO terminal_sessions(
                    session_id, request_id, request_fingerprint, host_id, node_incarnation_id, actor,
                    workspace_root, task_attempt_id, task_generation, issued_at, not_before, expires_at,
                    maximum_duration_ticks, maximum_input_bytes, maximum_output_bytes, transcript_mode,
                    maximum_transcript_bytes, file_transfer_capabilities, elevation_requested,
                    elevation_granted, revocation_revision, shell_kind, shell_executable, working_directory,
                    operational_replay_ticks, maximum_operational_spool_bytes,
                    boot_id, state, revision, input_bytes, output_bytes, input_sequence, output_sequence,
                    input_hash, output_hash, transcript_bytes, transcript_truncated,
                    unmanaged_mutation_suspected, output_eos, execution_identity, created_at, updated_at)
                VALUES(
                    $session, $request, $fingerprint, $host, $incarnation, $actor, $workspace, $attempt,
                    $generation, $issued, $not_before, $expires, $duration, $max_input, $max_output,
                    $transcript_mode, $max_transcript, $transfer, $elevation_requested, $elevation_granted,
                    $revocation, $shell_kind, $shell, $working, $replay_ticks, $spool_bytes,
                    $boot, $state, 0, 0, 0, 0, 0, $empty_hash, $empty_hash, 0, 0, 0, 0, '', $now, $now);
                """;
            command.Parameters.AddWithValue("$session", authority.SessionId.ToString());
            command.Parameters.AddWithValue("$request", request.RequestId);
            command.Parameters.AddWithValue("$fingerprint", requestFingerprint);
            command.Parameters.AddWithValue("$host", authority.HostId.ToString());
            command.Parameters.AddWithValue("$incarnation", authority.NodeIncarnationId.ToString());
            command.Parameters.AddWithValue("$actor", authority.Actor);
            command.Parameters.AddWithValue("$workspace", authority.WorkspaceRoot);
            command.Parameters.AddWithValue("$attempt", (object?)authority.Task?.TaskAttemptId.ToString() ?? DBNull.Value);
            command.Parameters.AddWithValue("$generation", (object?)authority.Task?.Generation ?? DBNull.Value);
            command.Parameters.AddWithValue("$issued", Format(authority.IssuedAt));
            command.Parameters.AddWithValue("$not_before", Format(authority.NotBefore));
            command.Parameters.AddWithValue("$expires", Format(authority.ExpiresAt));
            command.Parameters.AddWithValue("$duration", authority.MaximumDuration.Ticks);
            command.Parameters.AddWithValue("$max_input", authority.MaximumInputBytes);
            command.Parameters.AddWithValue("$max_output", authority.MaximumOutputBytes);
            command.Parameters.AddWithValue("$transcript_mode", (int)authority.TranscriptMode);
            command.Parameters.AddWithValue("$max_transcript", authority.MaximumTranscriptBytes);
            command.Parameters.AddWithValue("$transfer", (int)authority.FileTransferCapabilities);
            command.Parameters.AddWithValue("$elevation_requested", authority.ElevationRequested);
            command.Parameters.AddWithValue("$elevation_granted", authority.ElevationGranted);
            command.Parameters.AddWithValue("$revocation", authority.RevocationRevision);
            command.Parameters.AddWithValue("$shell_kind", (int)request.ShellKind);
            command.Parameters.AddWithValue("$shell", request.ShellExecutable);
            command.Parameters.AddWithValue("$working", request.WorkingDirectory);
            command.Parameters.AddWithValue("$replay_ticks", authority.OperationalReplayDuration.Ticks);
            command.Parameters.AddWithValue("$spool_bytes", authority.MaximumOperationalSpoolBytes);
            command.Parameters.AddWithValue("$boot", bootId);
            command.Parameters.AddWithValue("$state", (int)TerminalSessionState.Requested);
            command.Parameters.AddWithValue("$empty_hash", EmptyHash);
            command.Parameters.AddWithValue("$now", Format(now));
            try
            {
                command.ExecuteNonQuery();
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
            {
                throw Problem(TerminalProblemCode.IdempotencyConflict,
                    "Terminal session identity already has durable intent.",
                    TerminalProblemDisposition.RequiresReconciliation, false);
            }
        }

        using (var requestCommand = connection.CreateCommand())
        {
            requestCommand.Transaction = transaction;
            requestCommand.CommandText =
                "INSERT INTO terminal_requests(request_id,fingerprint,session_id,created_at) VALUES($request,$fingerprint,$session,$now);";
            requestCommand.Parameters.AddWithValue("$request", request.RequestId);
            requestCommand.Parameters.AddWithValue("$fingerprint", requestFingerprint);
            requestCommand.Parameters.AddWithValue("$session", authority.SessionId.ToString());
            requestCommand.Parameters.AddWithValue("$now", Format(now));
            requestCommand.ExecuteNonQuery();
        }

        transaction.Commit();
        return GetRequired(connection, authority.SessionId);
    }

    public TerminalSessionSnapshot Get(TerminalSessionId sessionId)
    {
        using var connection = Open();
        return GetRequired(connection, sessionId);
    }

    public TerminalSessionSnapshot? Find(TerminalSessionId sessionId)
    {
        using var connection = Open();
        return Find(connection, sessionId);
    }

    public TerminalOperationStart BeginOperation(
        string requestId,
        TerminalSessionId sessionId,
        string operationType,
        string fingerprint,
        DateTimeOffset now)
    {
        TerminalContractLimits.ValidateRequestId(requestId);
        if (operationType is not ("input" or "resize" or "close") ||
            string.IsNullOrWhiteSpace(fingerprint) || fingerprint.Length != 64)
            throw Problem(TerminalProblemCode.InvalidRequest, "Terminal operation identity is invalid.",
                TerminalProblemDisposition.Terminal, false);
        using var connection = Open();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);
        _ = GetRequired(connection, sessionId, transaction);
        using (var existing = connection.CreateCommand())
        {
            existing.Transaction = transaction;
            existing.CommandText =
                """
                SELECT session_id,operation_type,fingerprint,status,outcome_json
                FROM terminal_operations WHERE request_id=$request;
                """;
            existing.Parameters.AddWithValue("$request", requestId);
            using var reader = existing.ExecuteReader();
            if (reader.Read())
            {
                if (!StringComparer.Ordinal.Equals(reader.GetString(0), sessionId.ToString()) ||
                    !StringComparer.Ordinal.Equals(reader.GetString(1), operationType) ||
                    !StringComparer.Ordinal.Equals(reader.GetString(2), fingerprint))
                    throw Problem(TerminalProblemCode.IdempotencyConflict,
                        "Request ID was already used with different terminal operation intent.",
                        TerminalProblemDisposition.RequiresNewUserIntent, false);
                var status = (TerminalOperationStatus)reader.GetInt32(3);
                var outcome = reader.IsDBNull(4) ? null : reader.GetString(4);
                reader.Close();
                var replayCurrent = GetRequired(connection, sessionId, transaction);
                var snapshot = outcome is null
                    ? replayCurrent
                    : (JsonSerializer.Deserialize<TerminalSessionSnapshot>(outcome)
                       ?? throw new TerminalJournalSchemaException("Terminal operation outcome is malformed."))
                    with
                    {
                        SessionId = replayCurrent.SessionId,
                        HostId = replayCurrent.HostId,
                        NodeIncarnationId = replayCurrent.NodeIncarnationId,
                        Task = replayCurrent.Task
                    };
                transaction.Commit();
                return new(false, status, snapshot);
            }
        }

        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            """
            INSERT INTO terminal_operations(
                request_id,session_id,operation_type,fingerprint,status,outcome_json,created_at,updated_at)
            VALUES($request,$session,$type,$fingerprint,$status,NULL,$now,$now);
            """;
        insert.Parameters.AddWithValue("$request", requestId);
        insert.Parameters.AddWithValue("$session", sessionId.ToString());
        insert.Parameters.AddWithValue("$type", operationType);
        insert.Parameters.AddWithValue("$fingerprint", fingerprint);
        insert.Parameters.AddWithValue("$status", (int)TerminalOperationStatus.Accepted);
        insert.Parameters.AddWithValue("$now", Format(now));
        insert.ExecuteNonQuery();
        var current = GetRequired(connection, sessionId, transaction);
        transaction.Commit();
        return new(true, TerminalOperationStatus.Accepted, current);
    }

    public TerminalSessionSnapshot MarkOperationApplied(
        string requestId,
        TerminalSessionId sessionId,
        DateTimeOffset now)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);
        var snapshot = GetRequired(connection, sessionId, transaction);
        using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText =
            """
            UPDATE terminal_operations SET status=$applied,outcome_json=$outcome,updated_at=$now
            WHERE request_id=$request AND session_id=$session AND status=$accepted;
            """;
        update.Parameters.AddWithValue("$applied", (int)TerminalOperationStatus.Applied);
        update.Parameters.AddWithValue("$outcome", JsonSerializer.Serialize(snapshot));
        update.Parameters.AddWithValue("$now", Format(now));
        update.Parameters.AddWithValue("$request", requestId);
        update.Parameters.AddWithValue("$session", sessionId.ToString());
        update.Parameters.AddWithValue("$accepted", (int)TerminalOperationStatus.Accepted);
        if (update.ExecuteNonQuery() != 1)
            throw Problem(TerminalProblemCode.RevisionConflict, "Terminal operation outcome could not be committed.",
                TerminalProblemDisposition.RequiresReconciliation, true);
        transaction.Commit();
        return snapshot;
    }

    public void MarkOperationUncertain(
        string requestId,
        TerminalSessionId sessionId,
        DateTimeOffset now)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE terminal_operations SET status=$uncertain,updated_at=$now
            WHERE request_id=$request AND session_id=$session AND status=$accepted;
            """;
        command.Parameters.AddWithValue("$uncertain", (int)TerminalOperationStatus.SideEffectUncertain);
        command.Parameters.AddWithValue("$now", Format(now));
        command.Parameters.AddWithValue("$request", requestId);
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$accepted", (int)TerminalOperationStatus.Accepted);
        _ = command.ExecuteNonQuery();
    }

    public void AbandonAcceptedOperation(string requestId, TerminalSessionId sessionId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            DELETE FROM terminal_operations
            WHERE request_id=$request AND session_id=$session AND status=$accepted;
            """;
        command.Parameters.AddWithValue("$request", requestId);
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$accepted", (int)TerminalOperationStatus.Accepted);
        _ = command.ExecuteNonQuery();
    }

    public TerminalSessionSnapshot SetOpening(TerminalSessionId sessionId, long expectedRevision, DateTimeOffset now) =>
        Transition(sessionId, expectedRevision, [TerminalSessionState.Requested], TerminalSessionState.Opening, now);

    public TerminalSessionSnapshot SetOpen(
        TerminalSessionId sessionId,
        long expectedRevision,
        int processId,
        long processCreationTimeUtcTicks,
        string executionIdentity,
        DateTimeOffset now)
    {
        if (processId <= 0 || processCreationTimeUtcTicks <= 0 || string.IsNullOrWhiteSpace(executionIdentity) ||
            executionIdentity.Length > 256)
            throw Problem(TerminalProblemCode.InvalidRequest, "Terminal process identity is invalid.",
                TerminalProblemDisposition.Terminal, true);
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE terminal_sessions
            SET state=$open, revision=revision+1, process_id=$pid, process_creation_ticks=$ticks,
                execution_identity=$identity, updated_at=$now
            WHERE session_id=$session AND revision=$revision AND state=$opening
              AND process_id IS NULL AND process_creation_ticks IS NULL;
            """;
        command.Parameters.AddWithValue("$open", (int)TerminalSessionState.Open);
        command.Parameters.AddWithValue("$pid", processId);
        command.Parameters.AddWithValue("$ticks", processCreationTimeUtcTicks);
        command.Parameters.AddWithValue("$identity", executionIdentity);
        command.Parameters.AddWithValue("$now", Format(now));
        command.Parameters.AddWithValue("$opening", (int)TerminalSessionState.Opening);
        BindIdentity(command, sessionId, expectedRevision);
        RequireCas(command.ExecuteNonQuery(), sessionId);
        return GetRequired(connection, sessionId);
    }

    public TerminalSessionSnapshot AccountInput(
        TerminalSessionId sessionId,
        long expectedRevision,
        ReadOnlySpan<byte> content,
        string cumulativeHash,
        DateTimeOffset now,
        bool markMutation)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);
        var current = GetRequired(connection, sessionId, transaction);
        if (current.Revision != expectedRevision)
            throw RevisionConflict();
        if (current.State != TerminalSessionState.Open)
            throw InvalidState("Terminal input requires an open session.");
        var authority = GetAuthority(connection, sessionId, transaction);
        var nextBytes = checked(current.InputBytes + content.Length);
        if (nextBytes > authority.MaximumInputBytes)
            throw Problem(TerminalProblemCode.InputLimitExceeded, "Terminal input byte limit reached.",
                TerminalProblemDisposition.Terminal, false);
        var nextSequence = checked(current.InputSequence + 1);

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE terminal_sessions SET
                    input_bytes=$bytes, input_sequence=$sequence, input_hash=$hash,
                    revision=revision+1,
                    unmanaged_mutation_suspected=CASE WHEN $mutation=1 THEN 1 ELSE unmanaged_mutation_suspected END,
                    mutation_evidence=CASE WHEN $mutation=1 THEN 'terminal-input-conservative-policy' ELSE mutation_evidence END,
                    updated_at=$now
                WHERE session_id=$session AND revision=$revision AND state=$open;
                """;
            command.Parameters.AddWithValue("$bytes", nextBytes);
            command.Parameters.AddWithValue("$sequence", nextSequence);
            command.Parameters.AddWithValue("$hash", cumulativeHash);
            command.Parameters.AddWithValue("$mutation", markMutation);
            command.Parameters.AddWithValue("$now", Format(now));
            command.Parameters.AddWithValue("$open", (int)TerminalSessionState.Open);
            BindIdentity(command, sessionId, expectedRevision);
            RequireCas(command.ExecuteNonQuery(), sessionId);
        }

        AppendTranscript(connection, transaction, sessionId, authority, nextSequence, "input",
            current.InputBytes, content, cumulativeHash, now);
        transaction.Commit();
        return GetRequired(connection, sessionId);
    }

    public void AppendOutput(
        TerminalSessionId sessionId,
        long sequence,
        long offset,
        ReadOnlySpan<byte> content,
        string cumulativeHash,
        DateTimeOffset now)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);
        var current = GetRequired(connection, sessionId, transaction);
        if (sequence != checked(current.OutputSequence + 1) || offset != current.OutputBytes)
            throw Problem(TerminalProblemCode.RevisionConflict, "Terminal output cursor does not match durable state.",
                TerminalProblemDisposition.RequiresReconciliation, true);
        var authority = GetAuthority(connection, sessionId, transaction);
        var nextBytes = checked(offset + content.Length);
        if (nextBytes > authority.MaximumOutputBytes)
            throw Problem(TerminalProblemCode.OutputLimitExceeded, "Terminal output byte limit reached.",
                TerminalProblemDisposition.Terminal, true);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE terminal_sessions SET output_bytes=$bytes, output_sequence=$sequence,
                    output_hash=$hash, updated_at=$now
                WHERE session_id=$session AND output_sequence=$previous AND output_bytes=$offset
                  AND state IN ($opening,$open,$closing);
                """;
            command.Parameters.AddWithValue("$bytes", nextBytes);
            command.Parameters.AddWithValue("$sequence", sequence);
            command.Parameters.AddWithValue("$hash", cumulativeHash);
            command.Parameters.AddWithValue("$now", Format(now));
            command.Parameters.AddWithValue("$session", sessionId.ToString());
            command.Parameters.AddWithValue("$previous", sequence - 1);
            command.Parameters.AddWithValue("$offset", offset);
            command.Parameters.AddWithValue("$opening", (int)TerminalSessionState.Opening);
            command.Parameters.AddWithValue("$open", (int)TerminalSessionState.Open);
            command.Parameters.AddWithValue("$closing", (int)TerminalSessionState.Closing);
            if (command.ExecuteNonQuery() != 1)
                throw Problem(TerminalProblemCode.RevisionConflict, "Terminal output cursor update was rejected.",
                    TerminalProblemDisposition.RequiresReconciliation, true);
        }
        AppendTranscript(connection, transaction, sessionId, authority, sequence, "output",
            offset, content, cumulativeHash, now);
        AppendOperationalSpool(connection, transaction, sessionId, authority, sequence, offset,
            content, cumulativeHash, false, now);
        transaction.Commit();
    }

    public TerminalOutput AppendEndOfStream(TerminalSessionId sessionId, DateTimeOffset now)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);
        var current = GetRequired(connection, sessionId, transaction);
        using (var existing = connection.CreateCommand())
        {
            existing.Transaction = transaction;
            existing.CommandText = "SELECT output_eos FROM terminal_sessions WHERE session_id=$session;";
            existing.Parameters.AddWithValue("$session", sessionId.ToString());
            if (Convert.ToBoolean(existing.ExecuteScalar(), CultureInfo.InvariantCulture))
            {
                transaction.Commit();
                return new(sessionId, current.OutputSequence, current.OutputBytes, 0, ReadOnlyMemory<byte>.Empty,
                    current.OutputHash, true, true, false, TerminalOutputContentAvailability.MetadataOnly);
            }
        }

        var sequence = checked(current.OutputSequence + 1);
        using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText =
                """
                UPDATE terminal_sessions SET output_sequence=$sequence,output_eos=1,updated_at=$now
                WHERE session_id=$session AND output_sequence=$previous AND output_eos=0;
                """;
            update.Parameters.AddWithValue("$sequence", sequence);
            update.Parameters.AddWithValue("$now", Format(now));
            update.Parameters.AddWithValue("$session", sessionId.ToString());
            update.Parameters.AddWithValue("$previous", current.OutputSequence);
            if (update.ExecuteNonQuery() != 1)
                throw RevisionConflict();
        }
        var authority = GetAuthority(connection, sessionId, transaction);
        AppendTranscript(connection, transaction, sessionId, authority, sequence, "output",
            current.OutputBytes, ReadOnlySpan<byte>.Empty, current.OutputHash, now);
        AppendOperationalSpool(connection, transaction, sessionId, authority, sequence, current.OutputBytes,
            ReadOnlySpan<byte>.Empty, current.OutputHash, true, now);
        transaction.Commit();
        return new(sessionId, sequence, current.OutputBytes, 0, ReadOnlyMemory<byte>.Empty,
            current.OutputHash, true, false, false, TerminalOutputContentAvailability.Available);
    }

    public TerminalSessionSnapshot RecordResize(
        TerminalSessionId sessionId,
        long expectedRevision,
        int columns,
        int rows,
        DateTimeOffset now)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE terminal_sessions SET revision=revision+1, columns=$columns, rows=$rows, updated_at=$now
            WHERE session_id=$session AND revision=$revision AND state=$open;
            """;
        command.Parameters.AddWithValue("$columns", columns);
        command.Parameters.AddWithValue("$rows", rows);
        command.Parameters.AddWithValue("$now", Format(now));
        command.Parameters.AddWithValue("$open", (int)TerminalSessionState.Open);
        BindIdentity(command, sessionId, expectedRevision);
        RequireCas(command.ExecuteNonQuery(), sessionId);
        return GetRequired(connection, sessionId);
    }

    public TerminalSessionSnapshot SetClosing(TerminalSessionId sessionId, long expectedRevision, DateTimeOffset now) =>
        Transition(sessionId, expectedRevision, [TerminalSessionState.Open, TerminalSessionState.Opening],
            TerminalSessionState.Closing, now);

    public TerminalSessionSnapshot SetClosed(TerminalSessionId sessionId, string? reason, DateTimeOffset now)
    {
        var current = Get(sessionId);
        if (current.State is TerminalSessionState.Closed or TerminalSessionState.Interrupted)
            return current;
        return SystemTransition(sessionId, [TerminalSessionState.Requested, TerminalSessionState.Opening,
            TerminalSessionState.Open, TerminalSessionState.Closing], TerminalSessionState.Closed, reason, now);
    }

    public TerminalSessionSnapshot SetInterrupted(TerminalSessionId sessionId, string reason, DateTimeOffset now) =>
        SystemTransition(sessionId, [TerminalSessionState.Requested, TerminalSessionState.Opening,
            TerminalSessionState.Open, TerminalSessionState.Closing, TerminalSessionState.Recovering,
            TerminalSessionState.Closed],
            TerminalSessionState.Interrupted, reason, now);

    public IReadOnlyList<TerminalSessionSnapshot> ReconcileAfterRestart(
        NodeIncarnationId currentIncarnationId,
        string currentBootId,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentBootId);
        using var connection = Open();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using var select = connection.CreateCommand();
        select.Transaction = transaction;
        select.CommandText =
            """
            SELECT session_id,node_incarnation_id,boot_id,state FROM terminal_sessions
            WHERE state IN ($requested,$opening,$open,$closing,$recovering);
            """;
        select.Parameters.AddWithValue("$requested", (int)TerminalSessionState.Requested);
        select.Parameters.AddWithValue("$opening", (int)TerminalSessionState.Opening);
        select.Parameters.AddWithValue("$open", (int)TerminalSessionState.Open);
        select.Parameters.AddWithValue("$closing", (int)TerminalSessionState.Closing);
        select.Parameters.AddWithValue("$recovering", (int)TerminalSessionState.Recovering);
        var candidates = new List<(TerminalSessionId Id, bool IncarnationChanged, bool BootChanged, TerminalSessionState State)>();
        using (var reader = select.ExecuteReader())
        {
            while (reader.Read())
                candidates.Add((
                    TerminalSessionId.Parse(reader.GetString(0)),
                    NodeIncarnationId.Parse(reader.GetString(1)) != currentIncarnationId,
                    !StringComparer.Ordinal.Equals(reader.GetString(2), currentBootId),
                    (TerminalSessionState)reader.GetInt32(3)));
        }

        foreach (var candidate in candidates)
        {
            var target = candidate.IncarnationChanged || candidate.BootChanged ||
                         candidate.State is TerminalSessionState.Open or TerminalSessionState.Closing
                ? TerminalSessionState.Interrupted
                : TerminalSessionState.Recovering;
            var reason = candidate.IncarnationChanged ? "node-incarnation-changed" :
                candidate.BootChanged ? "host-rebooted" :
                candidate.State is TerminalSessionState.Requested or TerminalSessionState.Opening
                    ? "opening-outcome-ambiguous" : "runtime-handle-lost";
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText =
                """
                UPDATE terminal_sessions SET state=$state, revision=revision+1,
                    interruption_reason=$reason, updated_at=$now WHERE session_id=$session;
                """;
            update.Parameters.AddWithValue("$state", (int)target);
            update.Parameters.AddWithValue("$reason", reason);
            update.Parameters.AddWithValue("$now", Format(now));
            update.Parameters.AddWithValue("$session", candidate.Id.ToString());
            update.ExecuteNonQuery();
        }
        transaction.Commit();
        return candidates.Select(candidate => Get(candidate.Id)).ToArray();
    }

    public IReadOnlyList<TerminalTranscriptRecord> ReadTranscript(TerminalSessionId sessionId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT sequence,direction,offset,length,sha256,recorded_at,content
            FROM terminal_transcript WHERE session_id=$session ORDER BY id;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        using var reader = command.ExecuteReader();
        var records = new List<TerminalTranscriptRecord>();
        while (reader.Read())
            records.Add(new(reader.GetInt64(0), reader.GetString(1), reader.GetInt64(2), reader.GetInt32(3),
                reader.GetString(4), ParseTime(reader.GetString(5)), reader.IsDBNull(6) ? null : (byte[])reader[6]));
        return records;
    }

    public IReadOnlyList<TerminalOutput> ReadOutput(
        TerminalOutputReadRequest request,
        DateTimeOffset now)
    {
        TerminalContractLimits.ValidateOutputRead(request);
        using var connection = Open();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using (var cleanup = connection.CreateCommand())
        {
            cleanup.Transaction = transaction;
            cleanup.CommandText =
                "DELETE FROM terminal_output_spool WHERE session_id=$session AND retained_until<=$now;";
            cleanup.Parameters.AddWithValue("$session", request.SessionId.ToString());
            cleanup.Parameters.AddWithValue("$now", Format(now));
            cleanup.ExecuteNonQuery();
        }
        var snapshot = GetRequired(connection, request.SessionId, transaction);
        if (request.AfterSequence > snapshot.OutputSequence ||
            request.AfterOffset > snapshot.OutputBytes ||
            (request.AfterSequence == snapshot.OutputSequence && request.AfterOffset != snapshot.OutputBytes))
            throw Problem(TerminalProblemCode.InvalidRequest, "Terminal output cursor is invalid.",
                TerminalProblemDisposition.RequiresNewUserIntent, false);

        var candidates = new SortedDictionary<long, (long Offset, int Length, string Hash, bool Eos, byte[]? Content,
            TerminalOutputContentAvailability Availability)>();
        using (var transcript = connection.CreateCommand())
        {
            transcript.Transaction = transaction;
            transcript.CommandText =
                """
                SELECT sequence,offset,length,sha256,content FROM terminal_transcript
                WHERE session_id=$session AND direction='output' AND sequence>$sequence
                ORDER BY sequence LIMIT $limit;
                """;
            transcript.Parameters.AddWithValue("$session", request.SessionId.ToString());
            transcript.Parameters.AddWithValue("$sequence", request.AfterSequence);
            transcript.Parameters.AddWithValue("$limit", request.MaximumItems);
            using var reader = transcript.ExecuteReader();
            while (reader.Read())
            {
                var content = reader.IsDBNull(4) ? null : (byte[])reader[4];
                candidates[reader.GetInt64(0)] = (reader.GetInt64(1), reader.GetInt32(2), reader.GetString(3),
                    reader.GetInt32(2) == 0 && reader.GetInt64(0) == snapshot.OutputSequence,
                    content, content is null ? TerminalOutputContentAvailability.MetadataOnly :
                    TerminalOutputContentAvailability.Available);
            }
        }
        using (var spool = connection.CreateCommand())
        {
            spool.Transaction = transaction;
            spool.CommandText =
                """
                SELECT sequence,offset,length,sha256,end_of_stream,content
                FROM terminal_output_spool
                WHERE session_id=$session AND sequence>$sequence AND retained_until>$now
                ORDER BY sequence LIMIT $limit;
                """;
            spool.Parameters.AddWithValue("$session", request.SessionId.ToString());
            spool.Parameters.AddWithValue("$sequence", request.AfterSequence);
            spool.Parameters.AddWithValue("$now", Format(now));
            spool.Parameters.AddWithValue("$limit", request.MaximumItems);
            using var reader = spool.ExecuteReader();
            while (reader.Read())
                candidates[reader.GetInt64(0)] = (reader.GetInt64(1), reader.GetInt32(2), reader.GetString(3),
                    reader.GetBoolean(4), (byte[])reader[5], TerminalOutputContentAvailability.Available);
        }

        var output = new List<TerminalOutput>();
        var previousSequence = request.AfterSequence;
        var previousOffset = request.AfterOffset;
        long returnedBytes = 0;
        foreach (var (sequence, candidate) in candidates)
        {
            if (output.Count >= request.MaximumItems)
                break;
            var content = candidate.Content ?? [];
            var availability = candidate.Availability;
            if (returnedBytes + content.Length > request.MaximumBytes)
            {
                if (output.Count != 0)
                    break;
                content = [];
                availability = TerminalOutputContentAvailability.OmittedByReadLimit;
            }
            var gap = sequence != previousSequence + 1 || candidate.Offset != previousOffset;
            output.Add(new(request.SessionId, sequence, candidate.Offset, candidate.Length, content,
                candidate.Hash, candidate.Eos, true, gap, availability));
            returnedBytes += content.Length;
            previousSequence = sequence;
            previousOffset = checked(candidate.Offset + candidate.Length);
        }

        if (output.Count == 0 && snapshot.OutputSequence > request.AfterSequence)
        {
            using var eos = connection.CreateCommand();
            eos.Transaction = transaction;
            eos.CommandText = "SELECT output_eos FROM terminal_sessions WHERE session_id=$session;";
            eos.Parameters.AddWithValue("$session", request.SessionId.ToString());
            var endOfStream = Convert.ToBoolean(eos.ExecuteScalar(), CultureInfo.InvariantCulture);
            output.Add(new(request.SessionId, snapshot.OutputSequence, request.AfterOffset,
                checked((int)Math.Min(int.MaxValue, snapshot.OutputBytes - request.AfterOffset)),
                ReadOnlyMemory<byte>.Empty, snapshot.OutputHash, endOfStream, true, true,
                TerminalOutputContentAvailability.NotRetained));
        }
        transaction.Commit();
        return output;
    }

    internal TerminalAuthority GetAuthority(TerminalSessionId sessionId)
    {
        using var connection = Open();
        return GetAuthority(connection, sessionId, null);
    }

    private void Initialize()
    {
        using var connection = OpenRaw();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;";
        command.ExecuteNonQuery();
        command.CommandText = "PRAGMA user_version;";
        var version = Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='terminal_sessions';";
        var hasTables = Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 0;
        if (version == 0 && hasTables)
            throw new TerminalJournalSchemaException("An unversioned terminal journal cannot be adopted.");
        if (version is not 0 and not SchemaVersion)
            throw new TerminalJournalSchemaException($"Terminal journal schema {version} is unsupported.");
        command.CommandText =
            $"""
            CREATE TABLE IF NOT EXISTS terminal_sessions(
                session_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL UNIQUE,
                request_fingerprint TEXT NOT NULL,
                host_id TEXT NOT NULL,
                node_incarnation_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                workspace_root TEXT NOT NULL,
                task_attempt_id TEXT NULL,
                task_generation INTEGER NULL,
                issued_at TEXT NOT NULL,
                not_before TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                maximum_duration_ticks INTEGER NOT NULL,
                maximum_input_bytes INTEGER NOT NULL,
                maximum_output_bytes INTEGER NOT NULL,
                transcript_mode INTEGER NOT NULL,
                maximum_transcript_bytes INTEGER NOT NULL,
                file_transfer_capabilities INTEGER NOT NULL,
                elevation_requested INTEGER NOT NULL,
                elevation_granted INTEGER NOT NULL,
                revocation_revision INTEGER NOT NULL,
                shell_kind INTEGER NOT NULL,
                shell_executable TEXT NOT NULL,
                working_directory TEXT NOT NULL,
                operational_replay_ticks INTEGER NOT NULL,
                maximum_operational_spool_bytes INTEGER NOT NULL,
                boot_id TEXT NOT NULL,
                state INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                process_id INTEGER NULL,
                process_creation_ticks INTEGER NULL,
                input_bytes INTEGER NOT NULL,
                output_bytes INTEGER NOT NULL,
                input_sequence INTEGER NOT NULL,
                output_sequence INTEGER NOT NULL,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                transcript_bytes INTEGER NOT NULL,
                transcript_truncated INTEGER NOT NULL,
                unmanaged_mutation_suspected INTEGER NOT NULL,
                mutation_evidence TEXT NULL,
                output_eos INTEGER NOT NULL,
                columns INTEGER NULL,
                rows INTEGER NULL,
                execution_identity TEXT NOT NULL,
                interruption_reason TEXT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS terminal_requests(
                request_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                session_id TEXT NOT NULL UNIQUE REFERENCES terminal_sessions(session_id),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS terminal_transcript(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES terminal_sessions(session_id),
                sequence INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK(direction IN ('input','output')),
                offset INTEGER NOT NULL,
                length INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                content BLOB NULL,
                UNIQUE(session_id,direction,sequence)
            );
            CREATE INDEX IF NOT EXISTS ix_terminal_transcript_session ON terminal_transcript(session_id,id);
            CREATE TABLE IF NOT EXISTS terminal_output_spool(
                session_id TEXT NOT NULL REFERENCES terminal_sessions(session_id),
                sequence INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                length INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                end_of_stream INTEGER NOT NULL,
                retained_until TEXT NOT NULL,
                content BLOB NOT NULL,
                PRIMARY KEY(session_id,sequence)
            );
            CREATE INDEX IF NOT EXISTS ix_terminal_output_spool_expiry
                ON terminal_output_spool(session_id,retained_until,sequence);
            CREATE TABLE IF NOT EXISTS terminal_operations(
                request_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES terminal_sessions(session_id),
                operation_type TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                status INTEGER NOT NULL,
                outcome_json TEXT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_terminal_operations_session
                ON terminal_operations(session_id,created_at);
            PRAGMA user_version={SchemaVersion};
            """;
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = OpenRaw();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=30000;";
        command.ExecuteNonQuery();
        return connection;
    }

    private SqliteConnection OpenRaw()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    private TerminalSessionSnapshot Transition(
        TerminalSessionId sessionId,
        long expectedRevision,
        TerminalSessionState[] allowed,
        TerminalSessionState next,
        DateTimeOffset now)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        var states = string.Join(",", allowed.Select((_, index) => $"$s{index}"));
        command.CommandText =
            $"UPDATE terminal_sessions SET state=$next,revision=revision+1,updated_at=$now " +
            $"WHERE session_id=$session AND revision=$revision AND state IN ({states});";
        command.Parameters.AddWithValue("$next", (int)next);
        command.Parameters.AddWithValue("$now", Format(now));
        for (var index = 0; index < allowed.Length; index++)
            command.Parameters.AddWithValue($"$s{index}", (int)allowed[index]);
        BindIdentity(command, sessionId, expectedRevision);
        RequireCas(command.ExecuteNonQuery(), sessionId);
        return GetRequired(connection, sessionId);
    }

    private TerminalSessionSnapshot SystemTransition(
        TerminalSessionId sessionId,
        TerminalSessionState[] allowed,
        TerminalSessionState next,
        string? reason,
        DateTimeOffset now)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        var states = string.Join(",", allowed.Select((_, index) => $"$s{index}"));
        command.CommandText =
            $"UPDATE terminal_sessions SET state=$next,revision=revision+1,interruption_reason=$reason,updated_at=$now " +
            $"WHERE session_id=$session AND state IN ({states});";
        command.Parameters.AddWithValue("$next", (int)next);
        command.Parameters.AddWithValue("$reason", (object?)reason ?? DBNull.Value);
        command.Parameters.AddWithValue("$now", Format(now));
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        for (var index = 0; index < allowed.Length; index++)
            command.Parameters.AddWithValue($"$s{index}", (int)allowed[index]);
        if (command.ExecuteNonQuery() == 0)
        {
            var current = Find(connection, sessionId) ?? throw NotFound();
            if (current.State != next &&
                !(next == TerminalSessionState.Closed && current.State == TerminalSessionState.Interrupted))
                throw InvalidState("Terminal state transition was rejected.");
        }
        return GetRequired(connection, sessionId);
    }

    private void AppendTranscript(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TerminalSessionId sessionId,
        TerminalAuthority authority,
        long sequence,
        string direction,
        long offset,
        ReadOnlySpan<byte> content,
        string cumulativeHash,
        DateTimeOffset now)
    {
        if (authority.TranscriptMode == TerminalTranscriptMode.None)
            return;
        using var count = connection.CreateCommand();
        count.Transaction = transaction;
        count.CommandText = "SELECT COUNT(*) FROM terminal_transcript WHERE session_id=$session;";
        count.Parameters.AddWithValue("$session", sessionId.ToString());
        if (Convert.ToInt32(count.ExecuteScalar(), CultureInfo.InvariantCulture) >= options.MaximumTranscriptRowsPerSession)
        {
            MarkTranscriptTruncated(connection, transaction, sessionId);
            return;
        }

        var current = GetRequired(connection, sessionId, transaction);
        byte[]? retained = null;
        if (authority.TranscriptMode == TerminalTranscriptMode.Full &&
            content.Length <= authority.MaximumTranscriptBytes - current.TranscriptBytes)
            retained = content.ToArray();
        else if (authority.TranscriptMode == TerminalTranscriptMode.Full && content.Length > 0)
            MarkTranscriptTruncated(connection, transaction, sessionId);

        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            """
            INSERT INTO terminal_transcript(session_id,sequence,direction,offset,length,sha256,recorded_at,content)
            VALUES($session,$sequence,$direction,$offset,$length,$hash,$now,$content);
            """;
        insert.Parameters.AddWithValue("$session", sessionId.ToString());
        insert.Parameters.AddWithValue("$sequence", sequence);
        insert.Parameters.AddWithValue("$direction", direction);
        insert.Parameters.AddWithValue("$offset", offset);
        insert.Parameters.AddWithValue("$length", content.Length);
        insert.Parameters.AddWithValue("$hash", cumulativeHash);
        insert.Parameters.AddWithValue("$now", Format(now));
        insert.Parameters.AddWithValue("$content", (object?)retained ?? DBNull.Value);
        insert.ExecuteNonQuery();
        if (retained is not null)
        {
            using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = "UPDATE terminal_sessions SET transcript_bytes=transcript_bytes+$length WHERE session_id=$session;";
            update.Parameters.AddWithValue("$length", retained.Length);
            update.Parameters.AddWithValue("$session", sessionId.ToString());
            update.ExecuteNonQuery();
        }
    }

    private static void AppendOperationalSpool(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TerminalSessionId sessionId,
        TerminalAuthority authority,
        long sequence,
        long offset,
        ReadOnlySpan<byte> content,
        string cumulativeHash,
        bool endOfStream,
        DateTimeOffset now)
    {
        if (authority.MaximumOperationalSpoolBytes == 0 ||
            authority.OperationalReplayDuration == TimeSpan.Zero)
            return;
        using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT INTO terminal_output_spool(
                    session_id,sequence,offset,length,sha256,end_of_stream,retained_until,content)
                VALUES($session,$sequence,$offset,$length,$hash,$eos,$until,$content);
                """;
            insert.Parameters.AddWithValue("$session", sessionId.ToString());
            insert.Parameters.AddWithValue("$sequence", sequence);
            insert.Parameters.AddWithValue("$offset", offset);
            insert.Parameters.AddWithValue("$length", content.Length);
            insert.Parameters.AddWithValue("$hash", cumulativeHash);
            insert.Parameters.AddWithValue("$eos", endOfStream);
            insert.Parameters.AddWithValue("$until", Format(now + authority.OperationalReplayDuration));
            insert.Parameters.AddWithValue("$content", content.ToArray());
            insert.ExecuteNonQuery();
        }
        using var trim = connection.CreateCommand();
        trim.Transaction = transaction;
        trim.CommandText =
            """
            WITH ranked AS (
                SELECT sequence, SUM(length) OVER (ORDER BY sequence DESC) AS newest_bytes
                FROM terminal_output_spool WHERE session_id=$session
            )
            DELETE FROM terminal_output_spool
            WHERE session_id=$session
              AND sequence IN (SELECT sequence FROM ranked WHERE newest_bytes>$quota);
            """;
        trim.Parameters.AddWithValue("$session", sessionId.ToString());
        trim.Parameters.AddWithValue("$quota", authority.MaximumOperationalSpoolBytes);
        trim.ExecuteNonQuery();
    }

    private static void MarkTranscriptTruncated(SqliteConnection connection, SqliteTransaction transaction, TerminalSessionId sessionId)
    {
        using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = "UPDATE terminal_sessions SET transcript_truncated=1 WHERE session_id=$session;";
        update.Parameters.AddWithValue("$session", sessionId.ToString());
        update.ExecuteNonQuery();
    }

    private static TerminalAuthority GetAuthority(
        SqliteConnection connection,
        TerminalSessionId sessionId,
        SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT host_id,node_incarnation_id,actor,workspace_root,task_attempt_id,task_generation,
                   issued_at,not_before,expires_at,maximum_duration_ticks,maximum_input_bytes,
                   maximum_output_bytes,transcript_mode,maximum_transcript_bytes,
                   file_transfer_capabilities,elevation_requested,elevation_granted,revocation_revision,
                   operational_replay_ticks,maximum_operational_spool_bytes
            FROM terminal_sessions WHERE session_id=$session;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw NotFound();
        TerminalTaskBinding? task = reader.IsDBNull(4)
            ? null
            : new(TaskAttemptId.Parse(reader.GetString(4)), reader.GetInt32(5));
        return new(TerminalContractLimits.SchemaVersion, sessionId, HostId.Parse(reader.GetString(0)),
            NodeIncarnationId.Parse(reader.GetString(1)), reader.GetString(2), reader.GetString(3), task,
            ParseTime(reader.GetString(6)), ParseTime(reader.GetString(7)), ParseTime(reader.GetString(8)),
            TimeSpan.FromTicks(reader.GetInt64(9)), reader.GetInt64(10), reader.GetInt64(11),
            (TerminalTranscriptMode)reader.GetInt32(12), reader.GetInt64(13),
            (TerminalFileTransferCapabilities)reader.GetInt32(14), reader.GetBoolean(15), reader.GetBoolean(16),
            reader.GetInt64(17), TimeSpan.FromTicks(reader.GetInt64(18)), reader.GetInt64(19));
    }

    private static TerminalSessionSnapshot GetRequired(SqliteConnection connection, TerminalSessionId sessionId) =>
        Find(connection, sessionId) ?? throw NotFound();

    private static TerminalSessionSnapshot GetRequired(
        SqliteConnection connection,
        TerminalSessionId sessionId,
        SqliteTransaction transaction) =>
        Find(connection, sessionId, transaction) ?? throw NotFound();

    private static TerminalSessionSnapshot? Find(
        SqliteConnection connection,
        TerminalSessionId sessionId,
        SqliteTransaction? transaction = null)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT state,revision,host_id,node_incarnation_id,actor,workspace_root,task_attempt_id,
                   task_generation,expires_at,input_bytes,output_bytes,input_sequence,output_sequence,
                   input_hash,output_hash,transcript_mode,transcript_bytes,transcript_truncated,
                   unmanaged_mutation_suspected,mutation_evidence,process_id,process_creation_ticks,
                   elevation_granted,execution_identity,interruption_reason
            FROM terminal_sessions WHERE session_id=$session;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return null;
        TerminalTaskBinding? task = reader.IsDBNull(6)
            ? null
            : new(TaskAttemptId.Parse(reader.GetString(6)), reader.GetInt32(7));
        return new(sessionId, (TerminalSessionState)reader.GetInt32(0), reader.GetInt64(1),
            HostId.Parse(reader.GetString(2)), NodeIncarnationId.Parse(reader.GetString(3)),
            reader.GetString(4), reader.GetString(5), task, ParseTime(reader.GetString(8)),
            reader.GetInt64(9), reader.GetInt64(10), reader.GetInt64(11), reader.GetInt64(12),
            reader.GetString(13), reader.GetString(14), (TerminalTranscriptMode)reader.GetInt32(15),
            reader.GetInt64(16), reader.GetBoolean(17), reader.GetBoolean(18),
            reader.IsDBNull(19) ? null : reader.GetString(19),
            reader.IsDBNull(20) ? null : reader.GetInt32(20),
            reader.IsDBNull(21) ? null : reader.GetInt64(21), reader.GetBoolean(22), reader.GetString(23),
            reader.IsDBNull(24) ? null : reader.GetString(24));
    }

    private static void BindIdentity(SqliteCommand command, TerminalSessionId sessionId, long expectedRevision)
    {
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$revision", expectedRevision);
    }

    private static string Format(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static DateTimeOffset ParseTime(string value) =>
        DateTimeOffset.ParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private void RequireCas(int changed, TerminalSessionId sessionId)
    {
        if (changed == 1)
            return;
        using var connection = Open();
        if (Find(connection, sessionId) is null)
            throw NotFound();
        throw RevisionConflict();
    }

    private static TerminalException NotFound() =>
        Problem(TerminalProblemCode.SessionNotFound, "Terminal session was not found.",
            TerminalProblemDisposition.Terminal, false);

    private static TerminalException RevisionConflict() =>
        Problem(TerminalProblemCode.RevisionConflict, "Terminal session revision does not match.",
            TerminalProblemDisposition.RequiresReconciliation, false);

    private static TerminalException InvalidState(string detail) =>
        Problem(TerminalProblemCode.InvalidState, detail, TerminalProblemDisposition.RequiresReconciliation, false);

    private static TerminalException Problem(
        TerminalProblemCode code,
        string detail,
        TerminalProblemDisposition disposition,
        bool sideEffectMayHaveOccurred) =>
        new(new(code, detail, disposition, sideEffectMayHaveOccurred));
}
