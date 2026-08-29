using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Persistence.Sqlite;
using Steward.Scheduling;

namespace Steward.Orchestration;

public sealed record ControlOrchestrationOptions(
    DelegationPartitionOptions Delegation,
    bool IdentityGrantDispatchEnabled = false)
{
    public ControlOrchestrationOptions Validate()
    {
        Delegation.Validate();
        return this;
    }
}

public enum FactDisposition { Applied, Duplicate, Stale, Recovery }
public sealed record PersistedNodeFact(
    NodeIncarnationId NodeIncarnationId,
    long Sequence,
    string Kind,
    string PayloadJson,
    DateTimeOffset ProcessedAt);
public sealed record PersistedAttemptFactPage(
    IReadOnlyList<PersistedNodeFact> Facts,
    long PageCursor);

public sealed class ControlOrchestrator
{
    private readonly SqliteControlStore controlStore;
    private readonly CompositeScheduler scheduler;
    private readonly ISchedulerStateStore schedulerStore;
    private readonly ControlOrchestrationOptions options;
    private readonly TimeProvider timeProvider;
    private readonly IControlIdentityGrantCatalog? identityGrants;
    private readonly GlobalRateAllocator? rateAllocator;
    private readonly Dictionary<WorkloadId, WorkloadPlan> plans = [];
    private readonly Dictionary<WorkloadId, PoolId> demandPools = [];
    private readonly Dictionary<WorkloadId, SchedulerState> schedulerStates = [];
    private readonly SemaphoreSlim gate = new(1, 1);

    public ControlOrchestrator(
        SqliteControlStore controlStore,
        CompositeScheduler scheduler,
        ISchedulerStateStore schedulerStore,
        ControlOrchestrationOptions options,
        TimeProvider? timeProvider = null,
        IControlIdentityGrantCatalog? identityGrants = null,
        GlobalRateAllocator? rateAllocator = null)
    {
        this.controlStore = controlStore ?? throw new ArgumentNullException(nameof(controlStore));
        this.scheduler = scheduler ?? throw new ArgumentNullException(nameof(scheduler));
        this.schedulerStore = schedulerStore ?? throw new ArgumentNullException(nameof(schedulerStore));
        this.options = options?.Validate() ?? throw new ArgumentNullException(nameof(options));
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.identityGrants = identityGrants;
        this.rateAllocator = rateAllocator;
    }

    public SqliteControlStore Store => controlStore;

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await controlStore.InitializeAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS orchestration_node_facts(
                node_incarnation_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                kind TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                processed_at TEXT NOT NULL,
                PRIMARY KEY(node_incarnation_id, sequence)
            );
            CREATE TABLE IF NOT EXISTS orchestration_node_cursors(
                node_incarnation_id TEXT PRIMARY KEY,
                contiguous_cursor INTEGER NOT NULL CHECK(contiguous_cursor >= 0),
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orchestration_plans(
                workload_id TEXT PRIMARY KEY,
                plan_revision_id TEXT NOT NULL,
                storage_schema_version TEXT NOT NULL,
                deterministic_hash TEXT NOT NULL,
                demand_pool_id TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orchestration_node_endpoints(
                host_id TEXT PRIMARY KEY,
                node_incarnation_id TEXT NOT NULL UNIQUE,
                pool_id TEXT NOT NULL,
                transport_kind TEXT NOT NULL,
                transport_version TEXT NOT NULL,
                peer_identity TEXT NOT NULL,
                peer_public_key_reference TEXT NOT NULL,
                registration_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                enabled INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orchestration_pool_registrations(
                pool_id TEXT PRIMARY KEY,
                registration_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orchestration_submissions(
                idempotency_key TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                workload_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await LoadPersistedPlansAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task<SchedulingResult> RegisterAndScheduleAsync(
        WorkloadPlan plan,
        IReadOnlyList<HostCapacitySnapshot> hosts,
        PoolId demandPool,
        DateTimeOffset now,
        CancellationToken cancellationToken = default) =>
        RegisterAndScheduleAsync(
            plan, hosts, demandPool, now, null, null, cancellationToken);

    public async Task<SchedulingResult> RegisterAndScheduleAsync(
        WorkloadPlan plan,
        IReadOnlyList<HostCapacitySnapshot> hosts,
        PoolId demandPool,
        DateTimeOffset now,
        string? idempotencyKey,
        string? requestHash,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if ((!options.IdentityGrantDispatchEnabled || identityGrants is null) &&
            plan.Tasks.Any(x => (x.IdentityGrantIds?.Count ?? 0) > 0))
            throw new InvalidOperationException(
                "Identity-bound dispatch is explicitly disabled because no production identity grant resolver is configured.");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var registered = await scheduler.RegisterAsync(plan, cancellationToken).ConfigureAwait(false);
            await PersistInitialSnapshotsAsync(
                plan, demandPool, now, idempotencyKey, requestHash, cancellationToken).ConfigureAwait(false);
            plans[plan.WorkloadId] = plan;
            demandPools[plan.WorkloadId] = demandPool;
            schedulerStates[plan.WorkloadId] = registered;
            schedulerStates[plan.WorkloadId] =
                await scheduler.SetHostsAsync(plan, hosts, cancellationToken).ConfigureAwait(false);
            return await ScheduleAndDispatchCoreAsync(plan, demandPool, now, cancellationToken).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    public async Task<SchedulingResult> ScheduleAsync(
        WorkloadId workloadId,
        PoolId demandPool,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var plan = RequirePlan(workloadId);
            return await ScheduleAndDispatchCoreAsync(plan, demandPool, now, cancellationToken).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    public async Task CancelAsync(
        WorkloadId workloadId,
        TimeSpan gracePeriod,
        CancellationToken cancellationToken = default)
    {
        if (gracePeriod < TimeSpan.Zero || gracePeriod > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(gracePeriod));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var plan = RequirePlan(workloadId);
            var before = schedulerStates.TryGetValue(workloadId, out var current)
                ? current
                : throw new InvalidOperationException("Scheduler state is not registered in this Control process.");
            var state = await scheduler.CancelAsync(plan, cancellationToken).ConfigureAwait(false);
            schedulerStates[plan.WorkloadId] = state;
            var persisted = new HashSet<TaskId>();
            foreach (var item in before.Tasks.Where(x => x.Claim is not null && !IsScheduledTerminal(x.State)))
            {
                var attempt = await controlStore.GetTaskAttemptAsync(item.Claim!.AttemptId, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("Scheduled attempt snapshot is missing.");
                var commandId = DeterministicId<CommandId>($"cancel:{attempt.Payload.TaskAttemptId}:{attempt.Revision}");
                var identity = Identity(plan, attempt.Payload);
                var command = Command(
                    commandId, $"cancel:{attempt.Payload.TaskAttemptId}:{attempt.Revision}",
                    attempt.Payload.Generation, attempt.Payload.NodeIncarnationId, "cancel", timeProvider.GetUtcNow());
                var message = new CancelTaskMessage(command, identity,
                    checked((int)gracePeriod.TotalMilliseconds));
                var task = await controlStore.GetTaskAsync(item.TaskId, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("Task snapshot is missing.");
                var updated = task with
                {
                    Revision = task.Revision + 1,
                    Payload = task.Payload with
                    {
                        DesiredState = TaskDesiredState.Cancelled,
                        ObservedState = TaskObservedState.Cancelling
                    }
                };
                await controlStore.SaveTaskAsync(updated, task.Revision,
                    [Outbox($"cancel:{commandId}", OrchestrationMessageKinds.CancelTask, message, command.IdempotencyKey)],
                    cancellationToken).ConfigureAwait(false);
                persisted.Add(item.TaskId);
            }
            foreach (var item in state.Tasks.Where(x => !persisted.Contains(x.TaskId)))
                await PersistTaskProjectionAsync(plan, state, item.TaskId, cancellationToken).ConfigureAwait(false);
            await PersistWorkloadProjectionAsync(plan, state, [], cancellationToken).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    public async Task RetryAsync(
        WorkloadId workloadId,
        TaskId taskId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var plan = RequirePlan(workloadId);
            var state = await scheduler.RetryAsync(plan, taskId, now, cancellationToken).ConfigureAwait(false);
            schedulerStates[workloadId] = state;
            await PersistTaskProjectionAsync(plan, state, taskId, cancellationToken).ConfigureAwait(false);
            await PersistWorkloadProjectionAsync(plan, state, [], cancellationToken).ConfigureAwait(false);
            await ScheduleAndDispatchCoreAsync(
                plan, demandPools[workloadId], now, cancellationToken).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    public async Task ResolveRecoveryAbsentAsync(
        WorkloadId workloadId,
        TaskId taskId,
        int generation,
        DateTimeOffset retryAt,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var plan = RequirePlan(workloadId);
            var state = await scheduler.ResolveAmbiguousAbsentAsync(
                plan, taskId, generation, retryAt, cancellationToken).ConfigureAwait(false);
            schedulerStates[workloadId] = state;
            await PersistTaskProjectionAsync(plan, state, taskId, cancellationToken).ConfigureAwait(false);
            await PersistWorkloadProjectionAsync(plan, state, [], cancellationToken).ConfigureAwait(false);
            await ScheduleAndDispatchCoreAsync(
                plan, demandPools[workloadId], retryAt, cancellationToken).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    public async Task<long> GetNodeCursorAsync(
        NodeIncarnationId incarnationId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT contiguous_cursor FROM orchestration_node_cursors
            WHERE node_incarnation_id=$incarnation
            """;
        command.Parameters.AddWithValue("$incarnation", incarnationId.ToString());
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return value is null ? 0 : Convert.ToInt64(value);
    }

    public async Task<IReadOnlyList<PersistedNodeFact>> ReadTaskFactsAsync(
        TaskId taskId,
        long afterSequence,
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (afterSequence < 0 || limit is <= 0 or > 1000)
            throw new ArgumentOutOfRangeException(nameof(afterSequence));
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT node_incarnation_id,sequence,kind,payload_json,processed_at
            FROM orchestration_node_facts
            WHERE sequence>$cursor
              AND json_extract(payload_json,'$.identity.taskId')=$task
            ORDER BY processed_at,sequence LIMIT $limit
            """;
        command.Parameters.AddWithValue("$cursor", afterSequence);
        command.Parameters.AddWithValue("$task", taskId.ToString());
        command.Parameters.AddWithValue("$limit", limit);
        var result = new List<PersistedNodeFact>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(new(
                NodeIncarnationId.Parse(reader.GetString(0)),
                reader.GetInt64(1), reader.GetString(2), reader.GetString(3),
                DateTimeOffset.Parse(reader.GetString(4))));
        return result;
    }

    public async Task<PersistedAttemptFactPage> ReadAttemptFactsAsync(
        NodeIncarnationId nodeId,
        TaskAttemptId attemptId,
        int generation,
        long afterSequence,
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (generation <= 0 || afterSequence < 0 || limit is <= 0 or > 1000)
            throw new ArgumentOutOfRangeException(nameof(generation));
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT node_incarnation_id,sequence,kind,payload_json,processed_at
            FROM orchestration_node_facts
            WHERE node_incarnation_id=$node AND sequence>$cursor
              AND json_extract(payload_json,'$.identity.attemptId')=$attempt
              AND json_extract(payload_json,'$.identity.generation')=$generation
            ORDER BY sequence LIMIT $limit
            """;
        command.Parameters.AddWithValue("$node", nodeId.ToString());
        command.Parameters.AddWithValue("$attempt", attemptId.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        command.Parameters.AddWithValue("$cursor", afterSequence);
        command.Parameters.AddWithValue("$limit", limit);
        var facts = new List<PersistedNodeFact>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            facts.Add(new(
                NodeIncarnationId.Parse(reader.GetString(0)), reader.GetInt64(1),
                reader.GetString(2), reader.GetString(3), DateTimeOffset.Parse(reader.GetString(4))));
        return new(facts, facts.LastOrDefault()?.Sequence ?? afterSequence);
    }

    public async Task<FactDisposition> ApplyNodeFactAsync(
        NodeIncarnationId sessionIncarnation,
        long sequence,
        string kind,
        object fact,
        CancellationToken cancellationToken = default)
    {
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        var payloadJson = JsonSerializer.Serialize(fact, fact.GetType(), StewardJson.Options);
        var hash = Hash($"{kind}\n{payloadJson}");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var prior = await ReadFactAsync(sessionIncarnation, sequence, cancellationToken).ConfigureAwait(false);
            if (prior is not null)
            {
                if (prior.Value.Kind == kind && prior.Value.Hash == hash &&
                    prior.Value.PayloadJson == payloadJson)
                {
                    var identity = FactIdentity(fact);
                    if (identity is not null &&
                        await ValidateIdentityAsync(sessionIncarnation, identity, cancellationToken).ConfigureAwait(false)
                            == FactDisposition.Recovery)
                    {
                        await MarkConflictRecoveryAsync(
                            fact, "A duplicate Node fact no longer matches persisted attempt identity.", cancellationToken)
                            .ConfigureAwait(false);
                        return FactDisposition.Recovery;
                    }
                    return FactDisposition.Duplicate;
                }
                await MarkConflictRecoveryAsync(fact, "A Node fact sequence was reused with different content.", cancellationToken)
                    .ConfigureAwait(false);
                return FactDisposition.Recovery;
            }
            var cursor = await GetNodeCursorAsync(sessionIncarnation, cancellationToken).ConfigureAwait(false);
            if (sequence != cursor + 1)
            {
                await MarkConflictRecoveryAsync(fact, "Node fact sequence is not contiguous.", cancellationToken)
                    .ConfigureAwait(false);
                return FactDisposition.Recovery;
            }

            var disposition = await ReduceFactAsync(
                sessionIncarnation, sequence, kind, fact, hash, payloadJson, cancellationToken).ConfigureAwait(false);
            return disposition;
        }
        finally { gate.Release(); }
    }

    private async Task<SchedulingResult> ScheduleAndDispatchCoreAsync(
        WorkloadPlan plan,
        PoolId demandPool,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var result = await scheduler.ScheduleAsync(plan, now, demandPool, cancellationToken).ConfigureAwait(false);
        schedulerStates[plan.WorkloadId] = result.State;
        if (result.Placements.Count == 0)
        {
            await PersistWorkloadProjectionAsync(plan, result.State, [], cancellationToken).ConfigureAwait(false);
            return result;
        }

        var placedIds = result.Placements.Select(x => x.TaskId).ToHashSet();
        var dispatchState = result.State with
        {
            Tasks = result.State.Tasks.Where(x => placedIds.Contains(x.TaskId)).ToArray()
        };
        var delegations = DelegationPartitioner.Create(plan, dispatchState, now, options.Delegation)
            .Select(WithDeterministicId).ToArray();
        var outbox = new List<OutboxMessage>();
        foreach (var delegation in delegations)
        {
            outbox.Add(Outbox(
                $"delegation:{delegation.DelegationId}",
                OrchestrationMessageKinds.Delegation,
                new DelegationMessage(delegation),
                $"delegation:{delegation.DelegationId}"));
            foreach (var binding in delegation.TaskAuthorityBindings ?? [])
            {
                var scheduled = result.State.Tasks.Single(x => x.TaskId == binding.TaskId);
                var node = plan.Tasks.Single(x => x.TaskId == binding.TaskId);
                var attemptId = scheduled.Claim?.AttemptId
                    ?? throw new InvalidOperationException("Placement is missing its attempt claim.");
                var commandId = DeterministicId<CommandId>($"execute:{attemptId}");
                var identity = new AttemptIdentity(
                    plan.WorkloadId, plan.PlanRevisionId, node.TaskId, attemptId, scheduled.AttemptGeneration,
                    delegation.HostId, delegation.NodeIncarnationId, delegation.DelegationId, commandId);
                var command = Command(
                    commandId, $"execute:{attemptId}", scheduled.AttemptGeneration,
                    delegation.NodeIncarnationId, "execute", now);
                var grantReferences = new List<TaskIdentityGrantReference>();
                foreach (var grantId in binding.IdentityGrantIds)
                {
                    var grant = await identityGrants!.ResolveAsync(
                        grantId, plan.WorkloadId, node.TaskId, scheduled.AttemptGeneration,
                        delegation.HostId, delegation.NodeIncarnationId, cancellationToken)
                        .ConfigureAwait(false);
                    if (grant is null || grant.ExpiresAt <= now)
                        throw new IdentityResolutionException(
                            ProblemCodes.IdentityRenewalUnavailable,
                            "Required Task identity grant is unavailable or expired.");
                    if (grant.IdentityGrantId != grantId ||
                        grant.WorkloadId != plan.WorkloadId ||
                        grant.TaskId != node.TaskId ||
                        grant.Generation != scheduled.AttemptGeneration ||
                        grant.HostId != delegation.HostId ||
                        grant.NodeIncarnationId != delegation.NodeIncarnationId)
                        throw new IdentityResolutionException(
                            "identity.binding-invalid",
                            "Identity grant metadata does not match its exact Task authority.");
                    grantReferences.Add(grant);
                }
                var execute = new ExecuteTaskMessage(
                    command, identity, node.TaskType, node.TaskTypeVersion,
                    node.Input.MediaType, node.Input.SchemaVersion, node.Input.CanonicalJson,
                    ToDto(node.Resources),
                    binding.RateLimits.ToDictionary(x => x.Scope, x => x.MaximumAmount, StringComparer.Ordinal),
                    binding.IdentityGrantIds,
                    attemptId.ToString(),
                    grantReferences);
                outbox.Add(Outbox(
                    $"execute:{commandId}", OrchestrationMessageKinds.ExecuteTask, execute, command.IdempotencyKey));

                var existingAttempt = await controlStore.GetTaskAttemptAsync(attemptId, cancellationToken).ConfigureAwait(false);
                if (existingAttempt is null)
                    await controlStore.SaveTaskAttemptAsync(AttemptEnvelope(identity, delegation.AuthorityExpiresAt, now), null,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                await PersistTaskProjectionAsync(plan, result.State, node.TaskId, cancellationToken).ConfigureAwait(false);
            }
        }
        await PersistWorkloadProjectionAsync(plan, result.State, outbox, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private async Task PersistInitialSnapshotsAsync(
        WorkloadPlan plan,
        PoolId demandPool,
        DateTimeOffset now,
        string? idempotencyKey,
        string? requestHash,
        CancellationToken cancellationToken)
    {
        var workload = InitialWorkload(plan, now);
        var tasks = plan.Tasks.Select(node => InitialTask(plan, node, now)).ToArray();
        var planJson = OrchestrationPlanSerializer.Serialize(plan);
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: false);
        var submissionExists = false;
        if (idempotencyKey is not null)
        {
            if (string.IsNullOrWhiteSpace(requestHash))
                throw new ArgumentException("A submission request hash is required with an idempotency key.");
            await using var idempotency = connection.CreateCommand();
            idempotency.Transaction = transaction;
            idempotency.CommandText = """
                SELECT request_hash,workload_id FROM orchestration_submissions
                WHERE idempotency_key=$key
                """;
            idempotency.Parameters.AddWithValue("$key", idempotencyKey);
            await using var idempotencyReader = await idempotency.ExecuteReaderAsync(cancellationToken);
            if (await idempotencyReader.ReadAsync(cancellationToken))
            {
                submissionExists = true;
                if (idempotencyReader.GetString(0) != requestHash ||
                    idempotencyReader.GetString(1) != plan.WorkloadId.ToString())
                    throw new PersistenceException(
                        PersistenceErrorCode.IdempotencyConflict,
                        "Workload submission idempotency key conflicts with durable input.");
            }
        }
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT deterministic_hash,plan_json,demand_pool_id
                FROM orchestration_plans WHERE workload_id=$workload
                """;
            query.Parameters.AddWithValue("$workload", plan.WorkloadId.ToString());
            await using var reader = await query.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var persisted = OrchestrationPlanSerializer.Deserialize(reader.GetString(1), reader.GetString(0));
                if (persisted.PlanRevisionId != plan.PlanRevisionId ||
                    persisted.DeterministicHash != plan.DeterministicHash)
                    throw new SchedulerRevisionConflictException(
                        "Persisted Workload has another immutable plan.");
                if (PoolId.Parse(reader.GetString(2)) != demandPool)
                    throw new SchedulerRevisionConflictException(
                        "Persisted Workload has another demand-pool association.");
                await InsertSubmissionIdentityAsync(
                    connection, transaction, submissionExists ? null : idempotencyKey,
                    requestHash, plan.WorkloadId, now, cancellationToken)
                    .ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
        }

        await ExecuteAsync(connection, transaction, """
            INSERT INTO workloads(workload_id,revision,plan_revision_id,desired_state,observed_state,snapshot_json,updated_at)
            VALUES($id,0,$plan,$desired,$observed,$json,$now)
            """, cancellationToken,
            ("$id", plan.WorkloadId.ToString()), ("$plan", plan.PlanRevisionId.ToString()),
            ("$desired", workload.Payload.DesiredState.ToString()),
            ("$observed", workload.Payload.ObservedState.ToString()),
            ("$json", JsonSerializer.Serialize(workload, StewardJson.Options)),
            ("$now", now.ToString("O"))).ConfigureAwait(false);
        foreach (var task in tasks)
            await ExecuteAsync(connection, transaction, """
                INSERT INTO tasks(task_id,workload_id,plan_revision_id,revision,accepted_generation,desired_state,observed_state,snapshot_json,updated_at)
                VALUES($id,$workload,$plan,0,0,$desired,$observed,$json,$now)
                """, cancellationToken,
                ("$id", task.Payload.TaskId.ToString()), ("$workload", plan.WorkloadId.ToString()),
                ("$plan", plan.PlanRevisionId.ToString()), ("$desired", task.Payload.DesiredState.ToString()),
                ("$observed", task.Payload.ObservedState.ToString()),
                ("$json", JsonSerializer.Serialize(task, StewardJson.Options)),
                ("$now", now.ToString("O"))).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, """
            INSERT INTO orchestration_plans(
                workload_id,plan_revision_id,storage_schema_version,deterministic_hash,demand_pool_id,plan_json,created_at)
            VALUES($workload,$revision,$schema,$hash,$pool,$json,$now)
            """, cancellationToken,
            ("$workload", plan.WorkloadId.ToString()), ("$revision", plan.PlanRevisionId.ToString()),
            ("$schema", OrchestrationPlanSerializer.StorageSchemaVersion), ("$hash", plan.DeterministicHash),
            ("$pool", demandPool.ToString()), ("$json", planJson), ("$now", now.ToString("O")))
            .ConfigureAwait(false);
        await InsertSubmissionIdentityAsync(
            connection, transaction, submissionExists ? null : idempotencyKey,
            requestHash, plan.WorkloadId, now, cancellationToken)
            .ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task InsertSubmissionIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string? idempotencyKey,
        string? requestHash,
        WorkloadId workloadId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (idempotencyKey is null) return;
        try
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
            INSERT INTO orchestration_submissions(
                idempotency_key,request_hash,workload_id,created_at)
            VALUES($key,$hash,$workload,$now)
            """;
            command.Parameters.AddWithValue("$key", idempotencyKey);
            command.Parameters.AddWithValue("$hash", requestHash!);
            command.Parameters.AddWithValue("$workload", workloadId.ToString());
            command.Parameters.AddWithValue("$now", now.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
        {
            throw new PersistenceException(
                PersistenceErrorCode.IdempotencyConflict,
                "Workload submission idempotency identity conflicts with durable state.",
                exception);
        }
    }

    private static ContractEnvelope<WorkloadDto> InitialWorkload(WorkloadPlan plan, DateTimeOffset now)
    {
        var planner = new ExtensionMetadataDto(
            plan.PlannerType, plan.PlannerVersion,
            JsonSerializer.SerializeToElement(new { plan.DeterministicHash }, StewardJson.Options));
        return new ContractEnvelope<WorkloadDto>(
            "steward.workload", "1.0.0", [], [], now, 0,
            new(plan.WorkloadId, plan.PlanRevisionId, plan.PlannerType,
                WorkloadDesiredState.Active, WorkloadObservedState.Planning,
                plan.Tasks.Select(x => x.TaskId).ToArray(), [], planner));
    }

    private static ContractEnvelope<TaskDto> InitialTask(
        WorkloadPlan plan, TaskPlanNode node, DateTimeOffset now) =>
        new("steward.task", "1.0.0", [], [], now, 0,
            new(node.TaskId, plan.WorkloadId, plan.PlanRevisionId, node.TaskType, node.TaskTypeVersion,
                TaskDesiredState.Ready,
                node.Dependencies.Count == 0 ? TaskObservedState.Queued : TaskObservedState.Blocked,
                0, node.InterruptionClass, TaskCapabilities.Execute, ToDto(node.Resources),
                node.Dependencies,
                new(node.TaskType, node.TaskTypeVersion,
                    JsonSerializer.SerializeToElement(new
                    {
                        inputMediaType = node.Input.MediaType,
                        inputSchemaVersion = node.Input.SchemaVersion,
                        inputJson = node.Input.CanonicalJson
                    }, StewardJson.Options))));

    private async Task LoadPersistedPlansAsync(CancellationToken cancellationToken)
    {
        var rows = new List<(string WorkloadId, string RevisionId, string Schema, string Hash, string Pool, string Json)>();
        await using (var connection = await controlStore.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT workload_id,plan_revision_id,storage_schema_version,deterministic_hash,demand_pool_id,plan_json
                FROM orchestration_plans ORDER BY workload_id
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                rows.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2),
                    reader.GetString(3), reader.GetString(4), reader.GetString(5)));
        }
        foreach (var row in rows)
        {
            if (row.Schema != OrchestrationPlanSerializer.StorageSchemaVersion)
                throw new InvalidDataException($"Orchestration plan schema '{row.Schema}' is unsupported.");
            var plan = OrchestrationPlanSerializer.Deserialize(row.Json, row.Hash);
            if (plan.WorkloadId != WorkloadId.Parse(row.WorkloadId) ||
                plan.PlanRevisionId != PlanRevisionId.Parse(row.RevisionId))
                throw new InvalidDataException("Persisted orchestration plan identity columns do not match its content.");
            var workload = await controlStore.GetWorkloadAsync(plan.WorkloadId, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Persisted orchestration plan has no Workload snapshot.");
            if (workload.Payload.PlanRevisionId != plan.PlanRevisionId)
                throw new InvalidDataException("Persisted Workload snapshot has another plan revision.");
            var state = await schedulerStore.LoadAsync(plan.WorkloadId, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Persisted orchestration plan has no durable scheduler state.");
            SchedulerStateValidator.Validate(state, plan);
            plans.Add(plan.WorkloadId, plan);
            demandPools.Add(plan.WorkloadId, PoolId.Parse(row.Pool));
            schedulerStates.Add(plan.WorkloadId, state);
        }
    }

    private async Task PersistTaskProjectionAsync(
        WorkloadPlan plan, SchedulerState state, TaskId taskId, CancellationToken cancellationToken)
    {
        var snapshot = await controlStore.GetTaskAsync(taskId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Task snapshot is missing.");
        var scheduled = state.Tasks.Single(x => x.TaskId == taskId);
        var updated = snapshot with
        {
            Revision = snapshot.Revision + 1,
            Payload = snapshot.Payload with
            {
                AcceptedGeneration = scheduled.AttemptGeneration,
                ObservedState = ToObserved(scheduled.State)
            }
        };
        await controlStore.SaveTaskAsync(updated, snapshot.Revision, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    private async Task PersistWorkloadProjectionAsync(
        WorkloadPlan plan,
        SchedulerState state,
        IReadOnlyList<OutboxMessage> outbox,
        CancellationToken cancellationToken)
    {
        var snapshot = await controlStore.GetWorkloadAsync(plan.WorkloadId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Workload snapshot is missing.");
        var reduced = WorkloadResultReducer.Reduce(plan, state);
        var updated = snapshot with
        {
            Revision = snapshot.Revision + 1,
            Payload = snapshot.Payload with
            {
                DesiredState = state.Intent,
                ObservedState = reduced.State
            }
        };
        await controlStore.SaveWorkloadAsync(
            updated, snapshot.Revision, outbox, cancellationToken).ConfigureAwait(false);
    }

    private async Task<FactDisposition> ReduceFactAsync(
        NodeIncarnationId sessionIncarnation,
        long sequence,
        string kind,
        object fact,
        string hash,
        string payloadJson,
        CancellationToken cancellationToken)
    {
        if (fact is DelegationAcceptedFact delegation)
        {
            if (delegation.NodeIncarnationId != sessionIncarnation)
                throw new InvalidOperationException("Delegation acceptance has a stale Node incarnation.");
            await CommitFactAsync(sessionIncarnation, sequence, kind, hash, payloadJson,
                $"delegation:{delegation.DelegationId}", null, null, null, cancellationToken).ConfigureAwait(false);
            return FactDisposition.Applied;
        }
        if (fact is RateFeedbackFact feedback)
        {
            if (rateAllocator is null)
                throw new InvalidOperationException("Global rate allocator is unavailable.");
            await rateAllocator.ReportRetryAfterAsync(
                feedback.Scope, feedback.RetryAfter, timeProvider.GetUtcNow(), cancellationToken);
            await CommitFactAsync(sessionIncarnation, sequence, kind, hash, payloadJson,
                null, null, null, null, cancellationToken);
            return FactDisposition.Applied;
        }
        if (fact is CommandAcknowledgedFact commandAck)
        {
            var match = await ValidateIdentityAsync(sessionIncarnation, commandAck.Identity, cancellationToken).ConfigureAwait(false);
            if (match == FactDisposition.Recovery)
            {
                await MarkConflictRecoveryAsync(fact, "Command acknowledgement identity conflicts with persisted authority.", cancellationToken)
                    .ConfigureAwait(false);
                return match;
            }
            await CommitFactAsync(sessionIncarnation, sequence, kind, hash, payloadJson,
                $"{commandAck.Operation}:{commandAck.AcknowledgedCommandId}", null, null, null, cancellationToken).ConfigureAwait(false);
            return match;
        }
        var identity = FactIdentity(fact)
            ?? throw new OrchestrationMessageException($"Message '{kind}' is not a Node fact.");
        var identityDisposition = await ValidateIdentityAsync(sessionIncarnation, identity, cancellationToken).ConfigureAwait(false);
        if (identityDisposition == FactDisposition.Recovery)
        {
            await MarkConflictRecoveryAsync(fact, "Node fact identity conflicts with persisted attempt authority.", cancellationToken)
                .ConfigureAwait(false);
            return identityDisposition;
        }
        if (identityDisposition == FactDisposition.Stale)
        {
            await CommitFactAsync(sessionIncarnation, sequence, kind, hash, payloadJson,
                null, null, null, null, cancellationToken).ConfigureAwait(false);
            return identityDisposition;
        }

        var plan = RequirePlan(identity.WorkloadId);
        var task = await controlStore.GetTaskAsync(identity.TaskId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Task snapshot is missing.");
        var attempt = await controlStore.GetTaskAttemptAsync(identity.AttemptId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Attempt snapshot is missing.");
        ContractEnvelope<TaskDto>? taskUpdate = null;
        ContractEnvelope<TaskAttemptDto>? attemptUpdate = null;
        var state = schedulerStates.TryGetValue(plan.WorkloadId, out var currentState)
            ? currentState
            : throw new InvalidOperationException("Scheduler state is not registered in this Control process.");
        string? ack = null;
        PortableObjectDto? portable = null;

        switch (fact)
        {
            case TaskAcceptedFact:
                attempt = NextAttempt(attempt, TaskAttemptState.Accepted);
                task = NextTask(task, TaskObservedState.Preparing);
                attemptUpdate = attempt;
                taskUpdate = task;
                ack = $"execute:{identity.CommandId}";
                break;
            case TaskRunningFact:
                if (state.Tasks.Single(x => x.TaskId == identity.TaskId).State == ScheduledTaskState.Placed)
                    state = await scheduler.MarkRunningAsync(plan, identity.TaskId, identity.Generation, cancellationToken)
                        .ConfigureAwait(false);
                schedulerStates[plan.WorkloadId] = state;
                attempt = NextAttempt(attempt, TaskAttemptState.Running);
                task = NextTask(task, TaskObservedState.Running);
                attemptUpdate = attempt;
                taskUpdate = task;
                break;
            case TaskProgressFact:
            case TaskLogCursorFact:
                break;
            case TaskArtifactFact artifact:
                portable = new(artifact.PortableObjectId, PortableObjectKind.Artifact, artifact.MediaType,
                    artifact.ContentHash, artifact.SizeBytes, identity.AttemptId, null, artifact.Portable,
                    artifact.Portable ? artifact.Reference : null,
                    timeProvider.GetUtcNow(), new("orchestration", "1.0", JsonSerializer.SerializeToElement(new { artifact.Name })));
                break;
            case TaskCheckpointFact checkpoint:
                state = await scheduler.SetCheckpointAsync(plan, identity.TaskId, identity.Generation, cancellationToken)
                    .ConfigureAwait(false);
                schedulerStates[plan.WorkloadId] = state;
                portable = new(checkpoint.PortableObjectId, PortableObjectKind.TaskCheckpoint, "application/octet-stream",
                    checkpoint.ContentHash, checkpoint.SizeBytes, identity.AttemptId, null, checkpoint.Portable,
                    checkpoint.Portable ? checkpoint.Reference : null,
                    timeProvider.GetUtcNow(), new("orchestration", "1.0", JsonSerializer.SerializeToElement(new { })));
                break;
            case TaskTerminalFact terminal:
                var success = terminal.State == TaskAttemptState.Succeeded;
                state = await scheduler.CompleteAsync(
                    plan, identity.TaskId, identity.Generation, success, terminal.Receipt,
                    timeProvider.GetUtcNow(), poison: terminal.State == TaskAttemptState.Interrupted,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                schedulerStates[plan.WorkloadId] = state;
                attempt = NextAttempt(attempt, terminal.State);
                task = NextTask(task, terminal.State switch
                {
                    TaskAttemptState.Cancelled => TaskObservedState.Cancelled,
                    TaskAttemptState.Interrupted or TaskAttemptState.Checkpointed => TaskObservedState.Interrupted,
                    _ => ToObserved(state.Tasks.Single(x => x.TaskId == identity.TaskId).State)
                });
                attemptUpdate = attempt;
                taskUpdate = task;
                break;
            case TaskRecoveryFact:
                if (state.Tasks.Single(x => x.TaskId == identity.TaskId).State != ScheduledTaskState.Ambiguous)
                    state = await scheduler.MarkAmbiguousAsync(plan, identity.TaskId, identity.Generation, cancellationToken)
                        .ConfigureAwait(false);
                schedulerStates[plan.WorkloadId] = state;
                attempt = NextAttempt(attempt, TaskAttemptState.Recovering, RecoveryCertainty.Ambiguous);
                task = NextTask(task, TaskObservedState.Recovering);
                attemptUpdate = attempt;
                taskUpdate = task;
                break;
            case AgentActivityFact:
            case AgentFinalFact:
                break;
        }

        var workload = await controlStore.GetWorkloadAsync(identity.WorkloadId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Workload snapshot is missing.");
        var reduced = WorkloadResultReducer.Reduce(plan, state);
        workload = workload with
        {
            Revision = workload.Revision + 1,
            Payload = workload.Payload with { DesiredState = state.Intent, ObservedState = reduced.State }
        };
        await CommitFactAsync(sessionIncarnation, sequence, kind, hash, payloadJson, ack,
            taskUpdate, attemptUpdate, workload, cancellationToken, portable).ConfigureAwait(false);
        if (fact is TaskTerminalFact &&
            plan.Tasks.Any(x => x.Dependencies.Contains(identity.TaskId)) &&
            demandPools.TryGetValue(identity.WorkloadId, out var demandPool))
        {
            var refreshedHosts = state.Hosts.Select(x =>
                x.HostId == identity.HostId && x.IncarnationId == identity.NodeIncarnationId
                    ? x with { ObservedAt = timeProvider.GetUtcNow(), Available = true }
                    : x).ToArray();
            state = await scheduler.SetHostsAsync(plan, refreshedHosts, cancellationToken).ConfigureAwait(false);
            schedulerStates[plan.WorkloadId] = state;
            await ScheduleAndDispatchCoreAsync(
                plan, demandPool, timeProvider.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        }
        return fact is TaskRecoveryFact ? FactDisposition.Recovery : FactDisposition.Applied;
    }

    private async Task<FactDisposition> ValidateIdentityAsync(
        NodeIncarnationId sessionIncarnation,
        AttemptIdentity identity,
        CancellationToken cancellationToken)
    {
        var task = await controlStore.GetTaskAsync(identity.TaskId, cancellationToken).ConfigureAwait(false);
        var attempt = await controlStore.GetTaskAttemptAsync(identity.AttemptId, cancellationToken).ConfigureAwait(false);
        if (task is null || attempt is null) return FactDisposition.Recovery;
        var exact = sessionIncarnation == identity.NodeIncarnationId &&
            task.Payload.WorkloadId == identity.WorkloadId &&
            task.Payload.PlanRevisionId == identity.PlanRevisionId &&
            attempt.Payload.TaskId == identity.TaskId &&
            attempt.Payload.Generation == identity.Generation &&
            attempt.Payload.HostId == identity.HostId &&
            attempt.Payload.NodeIncarnationId == identity.NodeIncarnationId &&
            attempt.Payload.DelegationId == identity.DelegationId &&
            attempt.Payload.CommandId == identity.CommandId;
        if (!exact) return FactDisposition.Recovery;
        return identity.Generation < task.Payload.AcceptedGeneration ? FactDisposition.Stale : FactDisposition.Applied;
    }

    private async Task CommitFactAsync(
        NodeIncarnationId incarnation,
        long sequence,
        string kind,
        string hash,
        string payloadJson,
        string? acknowledgedMessageId,
        ContractEnvelope<TaskDto>? task,
        ContractEnvelope<TaskAttemptDto>? attempt,
        ContractEnvelope<WorkloadDto>? workload,
        CancellationToken cancellationToken,
        PortableObjectDto? portable = null)
    {
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: false);
        if (task is not null)
            await UpdateSnapshotAsync(connection, transaction, "tasks", "task_id", task.Payload.TaskId.ToString(),
                task.Revision - 1, task.Revision, task.Payload.ObservedState.ToString(),
                JsonSerializer.Serialize(task, StewardJson.Options), cancellationToken).ConfigureAwait(false);
        if (attempt is not null)
            await UpdateSnapshotAsync(connection, transaction, "task_attempts", "attempt_id", attempt.Payload.TaskAttemptId.ToString(),
                attempt.Revision - 1, attempt.Revision, attempt.Payload.State.ToString(),
                JsonSerializer.Serialize(attempt, StewardJson.Options), cancellationToken).ConfigureAwait(false);
        if (workload is not null)
            await UpdateSnapshotAsync(connection, transaction, "workloads", "workload_id", workload.Payload.WorkloadId.ToString(),
                workload.Revision - 1, workload.Revision, workload.Payload.ObservedState.ToString(),
                JsonSerializer.Serialize(workload, StewardJson.Options), cancellationToken).ConfigureAwait(false);
        if (portable is not null)
            await InsertPortableAsync(connection, transaction, portable, cancellationToken).ConfigureAwait(false);

        var notificationId = DeterministicId<NotificationId>($"fact:{incarnation}:{sequence}");
        var notificationPayload = JsonSerializer.Serialize(new
        {
            kind,
            sequence,
            nodeIncarnationId = incarnation,
            payload = JsonSerializer.Deserialize<JsonElement>(payloadJson)
        }, StewardJson.Options);
        await ExecuteAsync(connection, transaction, """
            INSERT INTO notification_outbox(notification_id,stream,payload_hash,payload_json,created_at)
            VALUES($notification,$stream,$notificationHash,$notificationPayload,$now)
            """, cancellationToken,
            ("$notification", notificationId.ToString()),
            ("$stream", workload is null ? $"node:{incarnation}" : $"workload:{workload.Payload.WorkloadId}"),
            ("$notificationHash", Hash(notificationPayload)),
            ("$notificationPayload", notificationPayload),
            ("$now", timeProvider.GetUtcNow().ToString("O"))).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, """
            INSERT INTO orchestration_node_facts(node_incarnation_id,sequence,kind,payload_hash,payload_json,processed_at)
            VALUES($incarnation,$sequence,$kind,$hash,$payload,$now);
            INSERT INTO orchestration_node_cursors(node_incarnation_id,contiguous_cursor,updated_at)
            VALUES($incarnation,$sequence,$now)
            ON CONFLICT(node_incarnation_id) DO UPDATE SET
              contiguous_cursor=excluded.contiguous_cursor,updated_at=excluded.updated_at;
            """, cancellationToken,
            ("$incarnation", incarnation.ToString()), ("$sequence", sequence), ("$kind", kind),
            ("$hash", hash), ("$payload", payloadJson), ("$now", timeProvider.GetUtcNow().ToString("O")))
            .ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, """
            UPDATE orchestration_node_endpoints SET observed_at=$now
            WHERE node_incarnation_id=$incarnation
            """, cancellationToken,
            ("$now", timeProvider.GetUtcNow().ToString("O")),
            ("$incarnation", incarnation.ToString())).ConfigureAwait(false);
        if (acknowledgedMessageId is not null)
            await ExecuteAsync(connection, transaction, """
                UPDATE aggregate_outbox SET acknowledged_at=COALESCE(acknowledged_at,$now)
                WHERE message_id=$message
                """, cancellationToken, ("$now", timeProvider.GetUtcNow().ToString("O")),
                ("$message", acknowledgedMessageId)).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task MarkConflictRecoveryAsync(
        object fact, string detail, CancellationToken cancellationToken)
    {
        var identity = FactIdentity(fact);
        if (identity is null) return;
        if (plans.TryGetValue(identity.WorkloadId, out var plan) &&
            schedulerStates.TryGetValue(identity.WorkloadId, out var schedulingState))
        {
            var scheduled = schedulingState.Tasks.SingleOrDefault(x => x.TaskId == identity.TaskId);
            if (scheduled is not null &&
                scheduled.AttemptGeneration == identity.Generation &&
                !IsScheduledTerminal(scheduled.State) &&
                scheduled.State != ScheduledTaskState.Ambiguous)
            {
                schedulerStates[identity.WorkloadId] = await scheduler.MarkAmbiguousAsync(
                    plan, identity.TaskId, identity.Generation, cancellationToken).ConfigureAwait(false);
            }
        }
        var task = await controlStore.GetTaskAsync(identity.TaskId, cancellationToken).ConfigureAwait(false);
        var attempt = await controlStore.GetTaskAttemptAsync(identity.AttemptId, cancellationToken).ConfigureAwait(false);
        var workload = await controlStore.GetWorkloadAsync(identity.WorkloadId, cancellationToken).ConfigureAwait(false);
        if (task is not null)
            await controlStore.SaveTaskAsync(
                NextTask(task, TaskObservedState.Recovering), task.Revision, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        if (attempt is not null && !IsTerminal(attempt.Payload.State))
            await controlStore.SaveTaskAttemptAsync(
                NextAttempt(attempt, TaskAttemptState.Recovering, RecoveryCertainty.Ambiguous),
                attempt.Revision, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (workload is not null && workload.Payload.ObservedState != WorkloadObservedState.Recovering)
            await controlStore.SaveWorkloadAsync(workload with
            {
                Revision = workload.Revision + 1,
                Payload = workload.Payload with { ObservedState = WorkloadObservedState.Recovering }
            }, workload.Revision,
            [new($"recovery:{identity.AttemptId}:{workload.Revision + 1}", "orchestration.recovery",
                JsonSerializer.Serialize(new { detail }, StewardJson.Options))], cancellationToken).ConfigureAwait(false);
    }

    private async Task<(string Kind, string Hash, string PayloadJson)?> ReadFactAsync(
        NodeIncarnationId incarnation, long sequence, CancellationToken cancellationToken)
    {
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT kind,payload_hash,payload_json FROM orchestration_node_facts
            WHERE node_incarnation_id=$incarnation AND sequence=$sequence
            """;
        command.Parameters.AddWithValue("$incarnation", incarnation.ToString());
        command.Parameters.AddWithValue("$sequence", sequence);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? (reader.GetString(0), reader.GetString(1), reader.GetString(2))
            : null;
    }

    private WorkloadPlan RequirePlan(WorkloadId workloadId) =>
        plans.TryGetValue(workloadId, out var plan)
            ? plan
            : throw new KeyNotFoundException($"Workload plan '{workloadId}' is not registered in this Control process.");

    private static AttemptIdentity? FactIdentity(object fact) => fact switch
    {
        TaskAcceptedFact value => value.Identity,
        TaskRunningFact value => value.Identity,
        TaskProgressFact value => value.Identity,
        TaskLogCursorFact value => value.Identity,
        TaskArtifactFact value => value.Identity,
        TaskCheckpointFact value => value.Identity,
        TaskTerminalFact value => value.Identity,
        TaskRecoveryFact value => value.Identity,
        CommandAcknowledgedFact value => value.Identity,
        AgentActivityFact value => value.Identity,
        AgentFinalFact value => value.Identity,
        _ => null
    };

    private static ContractEnvelope<TaskAttemptDto> AttemptEnvelope(
        AttemptIdentity identity, DateTimeOffset expiresAt, DateTimeOffset now) =>
        new("steward.task-attempt", "1.0.0", [], [], now, 0,
            new(identity.AttemptId, identity.TaskId, identity.Generation, identity.HostId,
                identity.NodeIncarnationId, TaskAttemptState.Dispatched, RecoveryCertainty.Certain,
                identity.DelegationId, identity.CommandId, expiresAt,
                new("orchestration", "1.0", JsonSerializer.SerializeToElement(new { identity.WorkloadId }))));

    private static ContractEnvelope<TaskDto> NextTask(
        ContractEnvelope<TaskDto> value, TaskObservedState state) =>
        value with { Revision = value.Revision + 1, Payload = value.Payload with { ObservedState = state } };

    private static ContractEnvelope<TaskAttemptDto> NextAttempt(
        ContractEnvelope<TaskAttemptDto> value,
        TaskAttemptState state,
        RecoveryCertainty certainty = RecoveryCertainty.Certain) =>
        value with
        {
            Revision = value.Revision + 1,
            Payload = value.Payload with { State = state, RecoveryCertainty = certainty }
        };

    private static DelegationDto WithDeterministicId(DelegationDto value)
    {
        var key = string.Join("|", value.TaskAuthorityBindings!.Select(x => $"{x.TaskId}:{x.Generation}"));
        return value with { DelegationId = DeterministicId<DelegationId>($"delegation:{value.PlanRevisionId}:{value.HostId}:{key}") };
    }

    private static AttemptIdentity Identity(WorkloadPlan plan, TaskAttemptDto attempt) =>
        new(plan.WorkloadId, plan.PlanRevisionId, attempt.TaskId, attempt.TaskAttemptId, attempt.Generation,
            attempt.HostId, attempt.NodeIncarnationId, attempt.DelegationId, attempt.CommandId);

    private static CommandDto Command(
        CommandId id,
        string idempotencyKey,
        int generation,
        NodeIncarnationId incarnation,
        string capability,
        DateTimeOffset now) =>
        new(id, idempotencyKey, 0, generation, incarnation, now.AddDays(7), "steward.control", capability,
            new(capability, "1.0", JsonSerializer.SerializeToElement(new { }, StewardJson.Options)));

    private static OutboxMessage Outbox(string id, string kind, object value, string idempotencyKey) =>
        new(id, kind, Encoding.UTF8.GetString(OrchestrationMessageCodec.Encode(value, DateTimeOffset.UtcNow).Span),
            idempotencyKey);

    private static ResourceRequirementsDto ToDto(ResourceRequirements value) =>
        new(value.CpuCores, value.MemoryBytes, value.DiskBytes, value.GpuCount,
            value.ProcessCount, value.ContainerCount, value.VmCount, value.ConcurrencyUnits);

    private static TaskObservedState ToObserved(ScheduledTaskState state) => state switch
    {
        ScheduledTaskState.Blocked => TaskObservedState.Blocked,
        ScheduledTaskState.Ready => TaskObservedState.Queued,
        ScheduledTaskState.Placed => TaskObservedState.Queued,
        ScheduledTaskState.Running => TaskObservedState.Running,
        ScheduledTaskState.Pausing => TaskObservedState.Pausing,
        ScheduledTaskState.Paused => TaskObservedState.Paused,
        ScheduledTaskState.Cancelling => TaskObservedState.Cancelling,
        ScheduledTaskState.Succeeded => TaskObservedState.Succeeded,
        ScheduledTaskState.Failed or ScheduledTaskState.Quarantined => TaskObservedState.Failed,
        ScheduledTaskState.Cancelled or ScheduledTaskState.SkippedDependency => TaskObservedState.Cancelled,
        ScheduledTaskState.Interrupted => TaskObservedState.Interrupted,
        ScheduledTaskState.Ambiguous => TaskObservedState.Recovering,
        _ => throw new ArgumentOutOfRangeException(nameof(state))
    };

    private static bool IsTerminal(TaskAttemptState state) =>
        state is TaskAttemptState.Succeeded or TaskAttemptState.Failed or TaskAttemptState.Cancelled
            or TaskAttemptState.Interrupted or TaskAttemptState.Checkpointed;

    private static bool IsScheduledTerminal(ScheduledTaskState state) =>
        state is ScheduledTaskState.Succeeded or ScheduledTaskState.Failed or ScheduledTaskState.Cancelled
            or ScheduledTaskState.Interrupted or ScheduledTaskState.Quarantined or ScheduledTaskState.SkippedDependency;

    private static T DeterministicId<T>(string value) where T : struct, IStewardId
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value))[..16];
        if (new Guid(bytes) == Guid.Empty) bytes[0] = 1;
        return (T)Activator.CreateInstance(typeof(T), new Guid(bytes))!;
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static async Task UpdateSnapshotAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string table,
        string idColumn,
        string id,
        long expectedRevision,
        long revision,
        string state,
        string json,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"""
            UPDATE {table} SET revision=$revision,state=$state,snapshot_json=$json,updated_at=$now
            WHERE {idColumn}=$id AND revision=$expected
            """;
        if (table == "tasks")
            command.CommandText = $"""
                UPDATE {table} SET revision=$revision,observed_state=$state,snapshot_json=$json,updated_at=$now
                WHERE {idColumn}=$id AND revision=$expected
                """;
        else if (table == "workloads")
            command.CommandText = $"""
                UPDATE {table} SET revision=$revision,observed_state=$state,snapshot_json=$json,updated_at=$now
                WHERE {idColumn}=$id AND revision=$expected
                """;
        command.Parameters.AddWithValue("$revision", revision);
        command.Parameters.AddWithValue("$state", state);
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$expected", expectedRevision);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            throw new PersistenceException(PersistenceErrorCode.RevisionConflict,
                $"Atomic orchestration projection update for '{id}' lost its revision race.");
    }

    private static async Task InsertPortableAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        PortableObjectDto value,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO portable_objects(portable_object_id,kind,content_hash,size_bytes,complete,store_receipt,metadata_json,created_at)
            VALUES($id,$kind,$hash,$size,$complete,$receipt,$metadata,$created)
            ON CONFLICT(portable_object_id) DO UPDATE SET
              store_receipt=excluded.store_receipt,metadata_json=excluded.metadata_json
            WHERE portable_objects.kind=excluded.kind
              AND portable_objects.content_hash=excluded.content_hash
              AND portable_objects.size_bytes=excluded.size_bytes
              AND portable_objects.complete=excluded.complete
            """;
        command.Parameters.AddWithValue("$id", value.PortableObjectId.ToString());
        command.Parameters.AddWithValue("$kind", value.Kind.ToString());
        command.Parameters.AddWithValue("$hash", value.ContentHash);
        command.Parameters.AddWithValue("$size", value.SizeBytes);
        command.Parameters.AddWithValue("$complete", value.Complete);
        command.Parameters.AddWithValue("$receipt", (object?)value.StoreReceipt ?? DBNull.Value);
        command.Parameters.AddWithValue("$metadata", JsonSerializer.Serialize(value, StewardJson.Options));
        command.Parameters.AddWithValue("$created", value.CreatedAt.ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidDataException("Portable artifact identity conflicts with durable content.");
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
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
