using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Transport;

namespace Steward.Node;

public sealed record NodeIdentity(
    NodeIncarnationId IncarnationId,
    Guid CurrentHostBootId,
    Guid? PreviousHostBootId,
    bool RebootDetected,
    bool HostBootIdentityVerified)
{
    public Guid BootId => CurrentHostBootId;
}
public sealed record JournaledFact(long Sequence, string FactType, string PayloadJson, DateTimeOffset ObservedAt);
public sealed record CommandOutcome(string Status, string PayloadJson);
public sealed record CommandReservation(bool IsNew, CommandOutcome Outcome);
public sealed record JournaledAttemptContext(
    TaskAttemptId AttemptId,
    int Generation,
    CommandId CommandId,
    string ContextJson,
    TaskAttemptDto? Attempt,
    long OutputCursor);
public sealed record StartAuthorityReservation(
    Guid ReservationId,
    TaskAttemptId AttemptId,
    DelegationId DelegationId,
    TaskId TaskId,
    int Generation,
    ResourceRequirements Resources,
    IReadOnlyDictionary<string, decimal> ConsumedRates,
    IReadOnlyList<IdentityGrantId> IdentityGrantIds);

public sealed class IdempotencyConflictException(string message) : InvalidOperationException(message);
public sealed class CommandExecutionUncertainException(CommandId commandId)
    : InvalidOperationException($"Command '{commandId}' was durably accepted but has no terminal outcome; execution must be reconciled.")
{
    public CommandId CommandId { get; } = commandId;
}
public sealed class StaleAcknowledgementException(string message) : InvalidOperationException(message);
public sealed class AttemptIdentityConflictException(string message) : InvalidOperationException(message);
public sealed class UnsupportedJournalSchemaException(int found, int supported)
    : InvalidOperationException($"Node journal schema {found} is newer than supported schema {supported}.")
{
    public int FoundVersion { get; } = found;
    public int SupportedVersion { get; } = supported;
}

public sealed class NodeJournal : IAsyncDisposable
{
    public const int CurrentSchemaVersion = 3;
    private static readonly Guid UnverifiedProcessHostBootId = Guid.NewGuid();
    private readonly string _connectionString;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private NodeIdentity? _identity;

    public NodeJournal(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        }.ToString();
    }

    public NodeIdentity Identity => _identity ?? throw new InvalidOperationException("Journal has not been initialized.");

    public async Task<NodeIdentity> InitializeAsync(
        NodeIncarnationId? initialIncarnation = null,
        Guid? hostBootId = null,
        bool hostBootIdentityVerified = true,
        CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await ExecuteAsync(connection, """
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                """, cancellationToken);
            var schemaText = await ReadMetadataAsync(connection, "schema_version", cancellationToken);
            var schemaVersion = schemaText is null ? 0 : int.Parse(schemaText);
            if (schemaVersion > CurrentSchemaVersion)
                throw new UnsupportedJournalSchemaException(schemaVersion, CurrentSchemaVersion);

            await ExecuteAsync(connection, """
                CREATE TABLE IF NOT EXISTS delegations(id TEXT PRIMARY KEY, payload TEXT NOT NULL, hash TEXT NOT NULL, accepted_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS commands(
                    id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, request_hash TEXT NOT NULL,
                    request_payload TEXT NOT NULL, outcome_status TEXT NOT NULL, outcome_payload TEXT NOT NULL, completed_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS facts(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, fact_type TEXT NOT NULL, payload TEXT NOT NULL, observed_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts(
                    attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, generation INTEGER NOT NULL, state TEXT NOT NULL,
                    payload TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS stream_cursors(stream TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS delegation_authority_state(
                    delegation_id TEXT PRIMARY KEY, accepted_revision INTEGER NOT NULL, current_revision INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS task_rate_bindings(
                    delegation_id TEXT NOT NULL, task_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    scope TEXT NOT NULL, amount TEXT NOT NULL, expires_at TEXT NOT NULL,
                    PRIMARY KEY(delegation_id,task_id,generation,scope));
                CREATE TABLE IF NOT EXISTS task_identity_bindings(
                    delegation_id TEXT NOT NULL, task_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    grant_id TEXT NOT NULL, PRIMARY KEY(delegation_id,task_id,generation,grant_id));
                CREATE TABLE IF NOT EXISTS rate_authority_ledger(
                    delegation_id TEXT NOT NULL, scope TEXT NOT NULL, allocated TEXT NOT NULL, consumed TEXT NOT NULL,
                    PRIMARY KEY(delegation_id,scope));
                CREATE TABLE IF NOT EXISTS start_reservations(
                    reservation_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE, delegation_id TEXT NOT NULL,
                    task_id TEXT NOT NULL, generation INTEGER NOT NULL, resources TEXT NOT NULL,
                    state TEXT NOT NULL, reserved_at TEXT NOT NULL, completed_at TEXT, completion_sequence INTEGER,
                    UNIQUE(delegation_id,task_id,generation));
                CREATE TABLE IF NOT EXISTS reservation_rates(
                    reservation_id TEXT NOT NULL, scope TEXT NOT NULL, amount TEXT NOT NULL,
                    PRIMARY KEY(reservation_id,scope));
                CREATE TABLE IF NOT EXISTS reservation_identities(
                    reservation_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                    PRIMARY KEY(reservation_id,grant_id));
                CREATE TABLE IF NOT EXISTS attempt_contexts(
                    attempt_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    command_id TEXT NOT NULL UNIQUE,
                    context_hash TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    output_cursor INTEGER NOT NULL DEFAULT 0 CHECK(output_cursor >= 0),
                    created_at TEXT NOT NULL
                );
                """, cancellationToken);
            if (schemaVersion < CurrentSchemaVersion)
                await WriteMetadataAsync(connection, "schema_version", CurrentSchemaVersion.ToString(), cancellationToken);

            var incarnationValue = await ReadMetadataAsync(connection, "incarnation", cancellationToken);
            NodeIncarnationId incarnation;
            if (incarnationValue is null)
            {
                incarnation = initialIncarnation ?? NodeIncarnationId.New();
                await WriteMetadataAsync(connection, "incarnation", incarnation.ToString(), cancellationToken);
                await WriteMetadataAsync(connection, "ack_cursor", "0", cancellationToken);
            }
            else
            {
                incarnation = NodeIncarnationId.Parse(incarnationValue);
                if (initialIncarnation is not null && initialIncarnation != incarnation)
                    throw new InvalidOperationException("Database belongs to a different Node incarnation.");
            }

            var currentBootId = hostBootId ?? UnverifiedProcessHostBootId;
            if (currentBootId == Guid.Empty)
                throw new ArgumentException("Host boot identity cannot be empty.", nameof(hostBootId));
            var previousBootText = await ReadMetadataAsync(connection, "host_boot_id", cancellationToken);
            Guid? previousBootId = previousBootText is null ? null : Guid.Parse(previousBootText);
            var rebootDetected = previousBootId.HasValue && previousBootId.Value != currentBootId;
            await WriteMetadataAsync(connection, "previous_host_boot_id", previousBootText ?? string.Empty, cancellationToken);
            await WriteMetadataAsync(connection, "host_boot_id", currentBootId.ToString("D"), cancellationToken);
            _identity = new NodeIdentity(incarnation, currentBootId, previousBootId, rebootDetected, hostBootIdentityVerified && hostBootId.HasValue);
            return _identity;
        }
        finally { _mutex.Release(); }
    }

    public async Task AcceptDelegationAsync(DelegationDto delegation, CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        if (delegation.NodeIncarnationId != Identity.IncarnationId)
            throw new InvalidOperationException("Delegation targets a stale Node incarnation.");
        ValidateAuthorityBindings(delegation);
        var json = JsonSerializer.Serialize(delegation, StewardJson.Options);
        var hash = Hash(json);
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO delegations(id,payload,hash,accepted_at) VALUES($id,$payload,$hash,$at) ON CONFLICT(id) DO NOTHING";
            command.Parameters.AddWithValue("$id", delegation.DelegationId.ToString());
            command.Parameters.AddWithValue("$payload", json);
            command.Parameters.AddWithValue("$hash", hash);
            command.Parameters.AddWithValue("$at", delegation.AcceptedAt.ToString("O"));
            var inserted = await command.ExecuteNonQueryAsync(cancellationToken);
            if (inserted == 0)
            {
                command.CommandText = "SELECT hash FROM delegations WHERE id=$id";
                command.Parameters.Clear();
                command.Parameters.AddWithValue("$id", delegation.DelegationId.ToString());
                if (!string.Equals((string?)await command.ExecuteScalarAsync(cancellationToken), hash, StringComparison.Ordinal))
                    throw new IdempotencyConflictException("Delegation ID was reused with a different payload.");
            }
            else
            {
                await MaterializeAuthorityAsync(connection, transaction, delegation, cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    private static void ValidateAuthorityBindings(DelegationDto delegation)
    {
        var bindings = delegation.TaskAuthorityBindings ?? [];
        if (bindings.Select(x => (x.TaskId, x.Generation)).Distinct().Count() != bindings.Count)
            throw new ArgumentException("Task authority bindings must be unique by Task and generation.");
        foreach (var binding in bindings)
        {
            var range = delegation.AllowedGenerations.SingleOrDefault(x => x.TaskId == binding.TaskId);
            if (range is null || binding.Generation < range.Minimum || binding.Generation > range.Maximum)
                throw new ArgumentException("Task authority binding is outside the delegated generation range.");
            if (binding.RateLimits.Select(x => x.Scope).Distinct(StringComparer.Ordinal).Count() != binding.RateLimits.Count ||
                binding.RateLimits.Any(x => x.MaximumAmount < 0))
                throw new ArgumentException("Task rate bindings must have unique scopes and nonnegative amounts.");
            if (binding.IdentityGrantIds.Distinct().Count() != binding.IdentityGrantIds.Count ||
                binding.IdentityGrantIds.Any(x => !delegation.IdentityGrantIds.Contains(x)))
                throw new ArgumentException("Task identity bindings must reference unique delegated grants.");
        }
    }

    private static async Task MaterializeAuthorityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DelegationDto delegation,
        CancellationToken cancellationToken)
    {
        await ExecuteAsync(connection, transaction,
            "INSERT INTO delegation_authority_state(delegation_id,accepted_revision,current_revision) VALUES($id,$revision,$revision)",
            cancellationToken, P("$id", delegation.DelegationId.ToString()), P("$revision", delegation.RevocationRevision));
        foreach (var binding in delegation.TaskAuthorityBindings ?? [])
        {
            foreach (var rate in binding.RateLimits)
            {
                await ExecuteAsync(connection, transaction, """
                    INSERT INTO task_rate_bindings(delegation_id,task_id,generation,scope,amount,expires_at)
                    VALUES($delegation,$task,$generation,$scope,$amount,$expires)
                    """, cancellationToken,
                    P("$delegation", delegation.DelegationId.ToString()), P("$task", binding.TaskId.ToString()),
                    P("$generation", binding.Generation), P("$scope", rate.Scope),
                    P("$amount", DecimalText(rate.MaximumAmount)), P("$expires", rate.ExpiresAt.ToString("O")));
            }
            foreach (var grant in binding.IdentityGrantIds)
                await ExecuteAsync(connection, transaction, """
                    INSERT INTO task_identity_bindings(delegation_id,task_id,generation,grant_id)
                    VALUES($delegation,$task,$generation,$grant)
                    """, cancellationToken,
                    P("$delegation", delegation.DelegationId.ToString()), P("$task", binding.TaskId.ToString()),
                    P("$generation", binding.Generation), P("$grant", grant.ToString()));
        }

        foreach (var allocation in delegation.RateLimits)
            await ExecuteAsync(connection, transaction, """
                INSERT INTO rate_authority_ledger(delegation_id,scope,allocated,consumed)
                VALUES($delegation,$scope,$allocated,'0')
                """, cancellationToken,
                P("$delegation", delegation.DelegationId.ToString()), P("$scope", allocation.Scope),
                P("$allocated", DecimalText(allocation.MaximumAmount)));
    }

    public async Task<DelegationDto?> GetDelegationAsync(DelegationId id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT payload FROM delegations WHERE id=$id";
        command.Parameters.AddWithValue("$id", id.ToString());
        var value = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return value is null ? null : JsonSerializer.Deserialize<DelegationDto>(value, StewardJson.Options);
    }

    public async Task<StartAuthorityReservation> ReserveStartAuthorityAsync(
        TaskAttemptId attemptId,
        DelegationId delegationId,
        TaskId taskId,
        int generation,
        ResourceRequirements resources,
        IReadOnlyDictionary<string, decimal>? requestedRates,
        IEnumerable<IdentityGrantId>? requestedIdentities,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        var rates = requestedRates ?? new Dictionary<string, decimal>();
        var identities = (requestedIdentities ?? []).Distinct().ToArray();
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var existing = await ReadReservationByAttemptAsync(connection, transaction, attemptId, cancellationToken);
            if (existing is not null)
            {
                if (existing.DelegationId != delegationId || existing.TaskId != taskId || existing.Generation != generation)
                    throw new AttemptIdentityConflictException("TaskAttemptId already owns another authority reservation.");
                await transaction.CommitAsync(cancellationToken);
                return existing;
            }

            var delegation = await ReadDelegationAsync(connection, transaction, delegationId, cancellationToken)
                ?? throw new InvalidOperationException("Delegation is not accepted by this Node.");
            if (delegation.NodeIncarnationId != Identity.IncarnationId)
                throw Limit(DomainErrorCode.DelegationExpired, "Delegation belongs to another Node incarnation.");
            if (now < delegation.AcceptedAt || now >= delegation.NoNewStartsAfter ||
                now >= delegation.DrainAt || now >= delegation.AuthorityExpiresAt)
                throw Limit(DomainErrorCode.DelegationExpired, "Delegation does not permit new starts at this time.");

            var revisions = await ReadAuthorityRevisionsAsync(connection, transaction, delegationId, cancellationToken);
            if (revisions.Current > revisions.Accepted)
                throw Limit(DomainErrorCode.DelegationExpired, "Delegated authority has been revoked.");
            var range = delegation.AllowedGenerations.SingleOrDefault(x => x.TaskId == taskId);
            if (range is null || generation < range.Minimum || generation > range.Maximum)
                throw Limit(DomainErrorCode.DelegationLimitExceeded, "Task or generation is outside delegated authority.");
            if (!resources.FitsWithin(ToDomain(delegation.ResourceLimit)))
                throw Limit(DomainErrorCode.DelegationLimitExceeded, "Requested resources exceed the delegation envelope.");

            var active = await ReadActiveReservationsAsync(connection, transaction, delegationId, cancellationToken);
            if (active.Count >= delegation.ConcurrencyLimit)
                throw Limit(DomainErrorCode.DelegationLimitExceeded, "Delegation concurrency limit is exhausted.");
            var aggregate = SumResources(active.Select(x => x.Resources).Append(resources));
            if (!aggregate.FitsWithin(ToDomain(delegation.ResourceLimit)))
                throw Limit(DomainErrorCode.DelegationLimitExceeded, "Active reservations exceed the delegation resource envelope.");

            var boundRates = await ReadRateBindingsAsync(
                connection, transaction, delegationId, taskId, generation, cancellationToken);
            var boundIdentities = await ReadIdentityBindingsAsync(
                connection, transaction, delegationId, taskId, generation, cancellationToken);
            if (rates.Count != boundRates.Count ||
                rates.Any(x => !boundRates.TryGetValue(x.Key, out var bound) || x.Value != bound.Amount))
                throw Limit(DomainErrorCode.DelegationLimitExceeded,
                    "Declared rate requirements must exactly match the Task-generation authority binding.");
            if (!identities.ToHashSet().SetEquals(boundIdentities))
                throw Limit(DomainErrorCode.DelegationLimitExceeded,
                    "Declared identity requirements must exactly match the Task-generation authority binding.");

            foreach (var bound in boundRates)
            {
                if (now >= bound.Value.ExpiresAt)
                    throw Limit(DomainErrorCode.DelegationLimitExceeded, $"Rate '{bound.Key}' binding has expired.");
                var ledger = await ReadRateLedgerAsync(connection, transaction, delegationId, bound.Key, cancellationToken);
                if (ledger is null || ledger.Value.Consumed + bound.Value.Amount > ledger.Value.Allocated)
                    throw Limit(DomainErrorCode.DelegationLimitExceeded, $"Rate '{bound.Key}' allocation is exhausted.");
            }

            var reservation = new StartAuthorityReservation(
                Guid.NewGuid(), attemptId, delegationId, taskId, generation, resources,
                boundRates.ToDictionary(x => x.Key, x => x.Value.Amount, StringComparer.Ordinal),
                boundIdentities.ToArray());
            await ExecuteAsync(connection, transaction, """
                INSERT INTO start_reservations(
                    reservation_id,attempt_id,delegation_id,task_id,generation,resources,state,reserved_at)
                VALUES($reservation,$attempt,$delegation,$task,$generation,$resources,'active',$at)
                """, cancellationToken,
                P("$reservation", reservation.ReservationId.ToString("D")), P("$attempt", attemptId.ToString()),
                P("$delegation", delegationId.ToString()), P("$task", taskId.ToString()), P("$generation", generation),
                P("$resources", JsonSerializer.Serialize(ToDto(resources), StewardJson.Options)), P("$at", now.ToString("O")));
            foreach (var rate in reservation.ConsumedRates)
            {
                await ExecuteAsync(connection, transaction,
                    "INSERT INTO reservation_rates(reservation_id,scope,amount) VALUES($id,$scope,$amount)",
                    cancellationToken, P("$id", reservation.ReservationId.ToString("D")),
                    P("$scope", rate.Key), P("$amount", DecimalText(rate.Value)));
                await ExecuteAsync(connection, transaction, """
                    UPDATE rate_authority_ledger SET consumed=$consumed
                    WHERE delegation_id=$delegation AND scope=$scope
                    """, cancellationToken,
                    P("$consumed", DecimalText((await ReadRateLedgerAsync(connection, transaction, delegationId, rate.Key, cancellationToken))!.Value.Consumed + rate.Value)),
                    P("$delegation", delegationId.ToString()), P("$scope", rate.Key));
            }
            foreach (var grant in reservation.IdentityGrantIds)
                await ExecuteAsync(connection, transaction,
                    "INSERT INTO reservation_identities(reservation_id,grant_id) VALUES($id,$grant)",
                    cancellationToken, P("$id", reservation.ReservationId.ToString("D")), P("$grant", grant.ToString()));
            await transaction.CommitAsync(cancellationToken);
            return reservation;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            throw new DomainRuleViolationException(DomainErrorCode.DelegationLimitExceeded, "Task generation already has a start reservation.");
        }
        finally { _mutex.Release(); }
    }

    public async Task<long> CompleteStartReservationAsync(
        Guid reservationId,
        string factType,
        object payload,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await using var lookup = connection.CreateCommand();
            lookup.Transaction = transaction;
            lookup.CommandText = "SELECT state,completion_sequence FROM start_reservations WHERE reservation_id=$id";
            lookup.Parameters.AddWithValue("$id", reservationId.ToString("D"));
            await using var reader = await lookup.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
                throw new InvalidOperationException("Start reservation does not exist.");
            if (reader.GetString(0) == "completed")
            {
                var existingSequence = reader.GetInt64(1);
                await transaction.CommitAsync(cancellationToken);
                return existingSequence;
            }
            await reader.DisposeAsync();

            var sequence = await InsertFactAsync(connection, transaction, factType, payload, observedAt, cancellationToken);
            await ExecuteAsync(connection, transaction, """
                UPDATE start_reservations
                SET state='completed',completed_at=$at,completion_sequence=$sequence
                WHERE reservation_id=$id
                """, cancellationToken, P("$at", observedAt.ToString("O")),
                P("$sequence", sequence), P("$id", reservationId.ToString("D")));
            await transaction.CommitAsync(cancellationToken);
            return sequence;
        }
        finally { _mutex.Release(); }
    }

    public async Task AdvanceDelegationRevocationAsync(
        DelegationId delegationId,
        long revision,
        CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var current = await ReadAuthorityRevisionsAsync(connection, transaction, delegationId, cancellationToken);
            if (revision < current.Current)
                throw new InvalidOperationException("Revocation revision cannot move backwards.");
            await ExecuteAsync(connection, transaction,
                "UPDATE delegation_authority_state SET current_revision=$revision WHERE delegation_id=$id",
                cancellationToken, P("$revision", revision), P("$id", delegationId.ToString()));
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    public async Task ReconcileUnusedRateAsync(
        DelegationId delegationId,
        string scope,
        decimal amount,
        long controlRevision,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken = default)
    {
        if (amount <= 0) throw new ArgumentOutOfRangeException(nameof(amount));
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var revisions = await ReadAuthorityRevisionsAsync(connection, transaction, delegationId, cancellationToken);
            if (controlRevision < revisions.Current)
                throw new InvalidOperationException("Control reconciliation revision is stale.");
            var ledger = await ReadRateLedgerAsync(connection, transaction, delegationId, scope, cancellationToken)
                ?? throw new InvalidOperationException("Rate scope does not exist.");
            if (amount > ledger.Consumed)
                throw new InvalidOperationException("Cannot reconcile more rate than has been consumed.");
            await ExecuteAsync(connection, transaction, """
                UPDATE rate_authority_ledger SET consumed=$consumed
                WHERE delegation_id=$delegation AND scope=$scope
                """, cancellationToken, P("$consumed", DecimalText(ledger.Consumed - amount)),
                P("$delegation", delegationId.ToString()), P("$scope", scope));
            await InsertFactAsync(connection, transaction, "externalRateReconciledUnused",
                new { delegationId, scope, amount, controlRevision }, observedAt, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    public async Task<CommandReservation> ReserveOrchestrationCommandAsync(
        CommandDto command,
        CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        var request = JsonSerializer.Serialize(command, StewardJson.Options);
        var hash = Hash(request);
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            var existing = await FindCommandAsync(connection, command.IdempotencyKey, transaction, cancellationToken);
            if (existing is not null)
            {
                if (existing.Value.Id != command.CommandId.ToString() || existing.Value.Hash != hash)
                    throw new IdempotencyConflictException(
                        "Idempotency identity was reused with a different command payload.");
                await transaction.CommitAsync(cancellationToken);
                return new(false, existing.Value.Outcome);
            }
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO commands(id,idempotency_key,request_hash,request_payload,outcome_status,outcome_payload,completed_at)
                VALUES($id,$key,$hash,$request,'reserved','{}',$at)
                """;
            insert.Parameters.AddWithValue("$id", command.CommandId.ToString());
            insert.Parameters.AddWithValue("$key", command.IdempotencyKey);
            insert.Parameters.AddWithValue("$hash", hash);
            insert.Parameters.AddWithValue("$request", request);
            insert.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(true, new("reserved", "{}"));
        }
        finally { _mutex.Release(); }
    }

    public Task SetOrchestrationCommandOutcomeAsync(
        CommandId commandId,
        CommandOutcome outcome,
        CancellationToken cancellationToken = default)
    {
        if (outcome.Status is "reserved" or "accepted")
            throw new ArgumentException("Use a stable started or terminal orchestration command outcome.", nameof(outcome));
        return PersistCommandOutcomeAsync(commandId, outcome, cancellationToken);
    }

    public async Task RecordAttemptContextAsync(
        TaskAttemptId attemptId,
        int generation,
        CommandId commandId,
        string contextJson,
        CancellationToken cancellationToken = default)
    {
        if (generation <= 0) throw new ArgumentOutOfRangeException(nameof(generation));
        ArgumentException.ThrowIfNullOrWhiteSpace(contextJson);
        if (Encoding.UTF8.GetByteCount(contextJson) > 256 * 1024)
            throw new ArgumentException("Attempt context exceeds its durable bound.", nameof(contextJson));
        var hash = Hash(contextJson);
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO attempt_contexts(
                    attempt_id,generation,command_id,context_hash,context_json,created_at)
                VALUES($attempt,$generation,$command,$hash,$json,$at)
                ON CONFLICT(attempt_id) DO NOTHING
                """;
            command.Parameters.AddWithValue("$attempt", attemptId.ToString());
            command.Parameters.AddWithValue("$generation", generation);
            command.Parameters.AddWithValue("$command", commandId.ToString());
            command.Parameters.AddWithValue("$hash", hash);
            command.Parameters.AddWithValue("$json", contextJson);
            command.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
            var inserted = await command.ExecuteNonQueryAsync(cancellationToken);
            if (inserted == 0)
            {
                command.CommandText = """
                    SELECT generation,command_id,context_hash,context_json
                    FROM attempt_contexts WHERE attempt_id=$attempt
                    """;
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                if (!await reader.ReadAsync(cancellationToken) ||
                    reader.GetInt32(0) != generation ||
                    reader.GetString(1) != commandId.ToString() ||
                    reader.GetString(2) != hash ||
                    reader.GetString(3) != contextJson)
                    throw new AttemptIdentityConflictException(
                        "TaskAttempt context identity was reused with different immutable content.");
            }
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    public async Task<IReadOnlyList<JournaledAttemptContext>> ReadNonterminalAttemptContextsAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT c.attempt_id,c.generation,c.command_id,c.context_json,c.output_cursor,a.payload,a.state
            FROM attempt_contexts c
            LEFT JOIN attempts a ON a.attempt_id=c.attempt_id
            WHERE a.attempt_id IS NULL OR a.state IN (
                'Reserved','Dispatched','Accepted','Preparing','Launching','Running','Recovering')
            ORDER BY c.created_at,c.attempt_id
            """;
        var result = new List<JournaledAttemptContext>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            TaskAttemptDto? attempt = reader.IsDBNull(5)
                ? null
                : JsonSerializer.Deserialize<TaskAttemptDto>(reader.GetString(5), StewardJson.Options)
                    ?? throw new InvalidDataException("Durable Node attempt payload is invalid.");
            result.Add(new(
                TaskAttemptId.Parse(reader.GetString(0)),
                reader.GetInt32(1),
                CommandId.Parse(reader.GetString(2)),
                reader.GetString(3),
                attempt,
                reader.GetInt64(4)));
        }
        return result;
    }

    public async Task SetAttemptOutputCursorAsync(
        TaskAttemptId attemptId,
        long cursor,
        CancellationToken cancellationToken = default)
    {
        if (cursor < 0) throw new ArgumentOutOfRangeException(nameof(cursor));
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE attempt_contexts SET output_cursor=MAX(output_cursor,$cursor)
            WHERE attempt_id=$attempt
            """;
        command.Parameters.AddWithValue("$cursor", cursor);
        command.Parameters.AddWithValue("$attempt", attemptId.ToString());
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException("TaskAttempt context does not exist.");
    }

    public async Task<CommandOutcome> ExecuteCommandAsync(
        CommandDto command,
        Func<CancellationToken, Task<CommandOutcome>> execute,
        CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        var request = JsonSerializer.Serialize(command, StewardJson.Options);
        var hash = Hash(request);

        CommandOutcome? terminalReplay = null;
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
            var existing = await FindCommandAsync(connection, command.IdempotencyKey, transaction, cancellationToken);
            if (existing is not null)
            {
                if (existing.Value.Id != command.CommandId.ToString() || existing.Value.Hash != hash)
                    throw new IdempotencyConflictException("Idempotency identity was reused with a different command payload.");
                if (existing.Value.Outcome.Status == "accepted")
                    throw new CommandExecutionUncertainException(command.CommandId);
                terminalReplay = existing.Value.Outcome;
            }
            else
            {
                await using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                INSERT INTO commands(id,idempotency_key,request_hash,request_payload,outcome_status,outcome_payload,completed_at)
                VALUES($id,$key,$hash,$request,$status,$outcome,$at)
                """;
                insert.Parameters.AddWithValue("$id", command.CommandId.ToString());
                insert.Parameters.AddWithValue("$key", command.IdempotencyKey);
                insert.Parameters.AddWithValue("$hash", hash);
                insert.Parameters.AddWithValue("$request", request);
                insert.Parameters.AddWithValue("$status", "accepted");
                insert.Parameters.AddWithValue("$outcome", "{}");
                insert.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
                await insert.ExecuteNonQueryAsync(cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _mutex.Release(); }

        if (terminalReplay is not null)
            return terminalReplay;

        CommandOutcome outcome;
        try
        {
            outcome = await execute(cancellationToken);
            if (string.Equals(outcome.Status, "accepted", StringComparison.Ordinal))
                throw new InvalidOperationException("'accepted' is reserved for nonterminal command reservations.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            outcome = new CommandOutcome("failed", JsonSerializer.Serialize(new { error = ex.Message }, StewardJson.Options));
            await PersistCommandOutcomeAsync(command.CommandId, outcome, CancellationToken.None);
            throw;
        }

        await PersistCommandOutcomeAsync(command.CommandId, outcome, CancellationToken.None);
        return outcome;
    }

    public async Task<long> AppendFactAsync(string factType, object payload, DateTimeOffset observedAt, CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        var json = JsonSerializer.Serialize(payload, StewardJson.Options);
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO facts(fact_type,payload,observed_at) VALUES($type,$payload,$at); SELECT last_insert_rowid();";
            command.Parameters.AddWithValue("$type", factType);
            command.Parameters.AddWithValue("$payload", json);
            command.Parameters.AddWithValue("$at", observedAt.ToString("O"));
            return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
        }
        finally { _mutex.Release(); }
    }

    public async Task<IReadOnlyList<JournaledFact>> ReadFactsAfterAsync(long cursor, int maximumCount = 256, CancellationToken cancellationToken = default)
    {
        if (cursor < 0 || maximumCount <= 0) throw new ArgumentOutOfRangeException(nameof(cursor));
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT sequence,fact_type,payload,observed_at FROM facts WHERE sequence>$cursor ORDER BY sequence LIMIT $limit";
        command.Parameters.AddWithValue("$cursor", cursor);
        command.Parameters.AddWithValue("$limit", maximumCount);
        var result = new List<JournaledFact>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(new(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), DateTimeOffset.Parse(reader.GetString(3))));
        return result;
    }

    public async Task BeginSessionAsync(Guid sessionId, NodeIncarnationId incarnationId, CancellationToken cancellationToken = default)
    {
        if (sessionId == Guid.Empty || incarnationId != Identity.IncarnationId)
            throw new StaleAcknowledgementException("Session cannot bind to a stale incarnation.");
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await WriteMetadataAsync(connection, "session_id", sessionId.ToString("D"), cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    public async Task AcknowledgeFactsAsync(Guid sessionId, NodeIncarnationId incarnationId, long contiguousCursor, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            var active = await ReadMetadataAsync(connection, "session_id", cancellationToken);
            var ack = long.Parse((await ReadMetadataAsync(connection, "ack_cursor", cancellationToken)) ?? "0");
            if (incarnationId != Identity.IncarnationId || active != sessionId.ToString("D"))
                throw new StaleAcknowledgementException("Acknowledgement is bound to a stale session or incarnation.");
            if (contiguousCursor < ack)
                throw new StaleAcknowledgementException("Acknowledgement cursor moved backwards.");
            var max = await ScalarLongAsync(connection, "SELECT COALESCE(MAX(sequence),0) FROM facts", cancellationToken);
            if (contiguousCursor > max)
                throw new InvalidOperationException("Acknowledgement skips facts that do not exist.");
            await WriteMetadataAsync(connection, "ack_cursor", contiguousCursor.ToString(), cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    public async Task<long> GetAcknowledgedCursorAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return long.Parse((await ReadMetadataAsync(connection, "ack_cursor", cancellationToken)) ?? "0");
    }

    public async Task SetStreamCursorAsync(StreamKind stream, long cursor, CancellationToken cancellationToken = default)
    {
        if (cursor < 0) throw new ArgumentOutOfRangeException(nameof(cursor));
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO stream_cursors(stream,cursor) VALUES($stream,$cursor)
            ON CONFLICT(stream) DO UPDATE SET cursor=MAX(cursor,excluded.cursor)
            """;
        command.Parameters.AddWithValue("$stream", stream.ToString());
        command.Parameters.AddWithValue("$cursor", cursor);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyDictionary<StreamKind, long>> GetStreamCursorsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT stream,cursor FROM stream_cursors";
        var result = new Dictionary<StreamKind, long>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result[Enum.Parse<StreamKind>(reader.GetString(0))] = reader.GetInt64(1);
        return result;
    }

    public async Task RecordAttemptAsync(TaskAttemptDto attempt, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(attempt, StewardJson.Options);
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
            await using (var existing = connection.CreateCommand())
            {
                existing.Transaction = transaction;
                existing.CommandText = "SELECT task_id,generation FROM attempts WHERE attempt_id=$id";
                existing.Parameters.AddWithValue("$id", attempt.TaskAttemptId.ToString());
                await using var reader = await existing.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken) &&
                    (reader.GetString(0) != attempt.TaskId.ToString() || reader.GetInt32(1) != attempt.Generation))
                    throw new AttemptIdentityConflictException("TaskAttemptId cannot be reused for a different Task or generation.");
            }

            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO attempts(attempt_id,task_id,generation,state,payload,updated_at) VALUES($id,$task,$generation,$state,$payload,$at)
                ON CONFLICT(attempt_id) DO UPDATE SET state=excluded.state,payload=excluded.payload,updated_at=excluded.updated_at
                WHERE attempts.task_id=excluded.task_id AND attempts.generation=excluded.generation
                """;
            command.Parameters.AddWithValue("$id", attempt.TaskAttemptId.ToString());
            command.Parameters.AddWithValue("$task", attempt.TaskId.ToString());
            command.Parameters.AddWithValue("$generation", attempt.Generation);
            command.Parameters.AddWithValue("$state", attempt.State.ToString());
            command.Parameters.AddWithValue("$payload", json);
            command.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await ExecuteAsync(connection, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;", cancellationToken);
        return connection;
    }

    private static async Task<DelegationDto?> ReadDelegationAsync(
        SqliteConnection connection, SqliteTransaction transaction, DelegationId id, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT payload FROM delegations WHERE id=$id";
        command.Parameters.AddWithValue("$id", id.ToString());
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return json is null ? null : JsonSerializer.Deserialize<DelegationDto>(json, StewardJson.Options);
    }

    private static async Task<(long Accepted, long Current)> ReadAuthorityRevisionsAsync(
        SqliteConnection connection, SqliteTransaction transaction, DelegationId id, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT accepted_revision,current_revision FROM delegation_authority_state WHERE delegation_id=$id";
        command.Parameters.AddWithValue("$id", id.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
            throw new InvalidOperationException("Delegation authority state does not exist.");
        return (reader.GetInt64(0), reader.GetInt64(1));
    }

    private static async Task<IReadOnlyList<StartAuthorityReservation>> ReadActiveReservationsAsync(
        SqliteConnection connection, SqliteTransaction transaction, DelegationId delegationId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT reservation_id,attempt_id,task_id,generation,resources
            FROM start_reservations WHERE delegation_id=$delegation AND state='active'
            """;
        command.Parameters.AddWithValue("$delegation", delegationId.ToString());
        var reservations = new List<StartAuthorityReservation>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            reservations.Add(new(
                Guid.Parse(reader.GetString(0)), TaskAttemptId.Parse(reader.GetString(1)), delegationId,
                TaskId.Parse(reader.GetString(2)), reader.GetInt32(3), ReadResources(reader.GetString(4)),
                new Dictionary<string, decimal>(), []));
        return reservations;
    }

    private static async Task<StartAuthorityReservation?> ReadReservationByAttemptAsync(
        SqliteConnection connection, SqliteTransaction transaction, TaskAttemptId attemptId, CancellationToken cancellationToken)
    {
        Guid reservationId;
        DelegationId delegationId;
        TaskId taskId;
        int generation;
        ResourceRequirements resources;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT reservation_id,delegation_id,task_id,generation,resources
                FROM start_reservations WHERE attempt_id=$attempt
                """;
            command.Parameters.AddWithValue("$attempt", attemptId.ToString());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
                return null;
            reservationId = Guid.Parse(reader.GetString(0));
            delegationId = DelegationId.Parse(reader.GetString(1));
            taskId = TaskId.Parse(reader.GetString(2));
            generation = reader.GetInt32(3);
            resources = ReadResources(reader.GetString(4));
        }

        var rates = new Dictionary<string, decimal>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT scope,amount FROM reservation_rates WHERE reservation_id=$id";
            command.Parameters.AddWithValue("$id", reservationId.ToString("D"));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                rates.Add(reader.GetString(0), ParseDecimal(reader.GetString(1)));
        }
        var identities = new List<IdentityGrantId>();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT grant_id FROM reservation_identities WHERE reservation_id=$id";
            command.Parameters.AddWithValue("$id", reservationId.ToString("D"));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                identities.Add(IdentityGrantId.Parse(reader.GetString(0)));
        }
        return new(reservationId, attemptId, delegationId, taskId, generation, resources, rates, identities);
    }

    private static async Task<IReadOnlyDictionary<string, (decimal Amount, DateTimeOffset ExpiresAt)>> ReadRateBindingsAsync(
        SqliteConnection connection, SqliteTransaction transaction, DelegationId delegationId,
        TaskId taskId, int generation, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT scope,amount,expires_at FROM task_rate_bindings
            WHERE delegation_id=$delegation AND task_id=$task AND generation=$generation
            """;
        command.Parameters.AddWithValue("$delegation", delegationId.ToString());
        command.Parameters.AddWithValue("$task", taskId.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        var result = new Dictionary<string, (decimal Amount, DateTimeOffset ExpiresAt)>(StringComparer.Ordinal);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(reader.GetString(0), (ParseDecimal(reader.GetString(1)), DateTimeOffset.Parse(reader.GetString(2))));
        return result;
    }

    private static async Task<(decimal Allocated, decimal Consumed)?> ReadRateLedgerAsync(
        SqliteConnection connection, SqliteTransaction transaction, DelegationId delegationId,
        string scope, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT allocated,consumed FROM rate_authority_ledger WHERE delegation_id=$delegation AND scope=$scope";
        command.Parameters.AddWithValue("$delegation", delegationId.ToString());
        command.Parameters.AddWithValue("$scope", scope);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? (ParseDecimal(reader.GetString(0)), ParseDecimal(reader.GetString(1)))
            : null;
    }

    private static async Task<IReadOnlySet<IdentityGrantId>> ReadIdentityBindingsAsync(
        SqliteConnection connection, SqliteTransaction transaction, DelegationId delegationId,
        TaskId taskId, int generation, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT grant_id FROM task_identity_bindings
            WHERE delegation_id=$delegation AND task_id=$task AND generation=$generation
            """;
        command.Parameters.AddWithValue("$delegation", delegationId.ToString());
        command.Parameters.AddWithValue("$task", taskId.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        var result = new HashSet<IdentityGrantId>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(IdentityGrantId.Parse(reader.GetString(0)));
        return result;
    }

    private static async Task<long> InsertFactAsync(
        SqliteConnection connection, SqliteTransaction transaction, string factType,
        object payload, DateTimeOffset observedAt, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO facts(fact_type,payload,observed_at) VALUES($type,$payload,$at); SELECT last_insert_rowid();";
        command.Parameters.AddWithValue("$type", factType);
        command.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(payload, StewardJson.Options));
        command.Parameters.AddWithValue("$at", observedAt.ToString("O"));
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static ResourceRequirements SumResources(IEnumerable<ResourceRequirements> values)
    {
        var list = values.ToArray();
        return new(
            list.Sum(x => x.CpuCores), list.Sum(x => x.MemoryBytes), list.Sum(x => x.DiskBytes),
            list.Sum(x => x.GpuCount), list.Sum(x => x.ProcessCount), list.Sum(x => x.ContainerCount),
            list.Sum(x => x.VmCount), list.Sum(x => x.ConcurrencyUnits));
    }

    private static ResourceRequirements ToDomain(ResourceRequirementsDto value) =>
        new(value.CpuCores, value.MemoryBytes, value.DiskBytes, value.GpuCount, value.ProcessCount,
            value.ContainerCount, value.VmCount, value.ConcurrencyUnits);

    private static ResourceRequirementsDto ToDto(ResourceRequirements value) =>
        new(value.CpuCores, value.MemoryBytes, value.DiskBytes, value.GpuCount, value.ProcessCount,
            value.ContainerCount, value.VmCount, value.ConcurrencyUnits);

    private static ResourceRequirements ReadResources(string json) =>
        ToDomain(JsonSerializer.Deserialize<ResourceRequirementsDto>(json, StewardJson.Options)!);

    private static DomainRuleViolationException Limit(DomainErrorCode code, string message) => new(code, message);
    private static string DecimalText(decimal value) => value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    private static decimal ParseDecimal(string value) => decimal.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
    private static (string Name, object Value) P(string name, object value) => (name, value);

    private async Task PersistCommandOutcomeAsync(CommandId commandId, CommandOutcome outcome, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await UpdateCommandOutcomeAsync(connection, commandId, outcome, cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    private static async Task<(string Id, string Hash, CommandOutcome Outcome)?> FindCommandAsync(
        SqliteConnection connection,
        string key,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT id,request_hash,outcome_status,outcome_payload FROM commands WHERE idempotency_key=$key";
        command.Parameters.AddWithValue("$key", key);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? (reader.GetString(0), reader.GetString(1), new CommandOutcome(reader.GetString(2), reader.GetString(3)))
            : null;
    }

    private static async Task UpdateCommandOutcomeAsync(
        SqliteConnection connection,
        CommandId commandId,
        CommandOutcome outcome,
        CancellationToken cancellationToken)
    {
        await using var update = connection.CreateCommand();
        update.CommandText = "UPDATE commands SET outcome_status=$status,outcome_payload=$payload,completed_at=$at WHERE id=$id";
        update.Parameters.AddWithValue("$status", outcome.Status);
        update.Parameters.AddWithValue("$payload", outcome.PayloadJson);
        update.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("O"));
        update.Parameters.AddWithValue("$id", commandId.ToString());
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException("Command reservation does not exist.");
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var parameter in parameters)
            command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<string?> ReadMetadataAsync(SqliteConnection connection, string key, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM metadata WHERE key=$key";
        command.Parameters.AddWithValue("$key", key);
        return (string?)await command.ExecuteScalarAsync(cancellationToken);
    }

    private static async Task WriteMetadataAsync(SqliteConnection connection, string key, string value, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO metadata(key,value) VALUES($key,$value) ON CONFLICT(key) DO UPDATE SET value=excluded.value";
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$value", value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<long> ScalarLongAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private void EnsureInitialized() => _ = Identity;
    public ValueTask DisposeAsync() { _mutex.Dispose(); return ValueTask.CompletedTask; }
}
