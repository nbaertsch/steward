using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Steward.Contracts;
using Steward.Domain;
using Steward.Node;
using Steward.Transport;

namespace Steward.EndToEnd.Tests;

public sealed class NodeAuthorityTests
{
    [Fact]
    public async Task Disconnect_restart_replays_ordered_facts_exactly_once_and_rejects_stale_ack()
    {
        var path = DatabasePath();
        var incarnation = NodeIncarnationId.New();
        try
        {
            await using (var first = new NodeJournal(path))
            {
                await first.InitializeAsync(incarnation);
                await first.AcceptDelegationAsync(Delegation(incarnation));
                var reconciliation = new ReconciliationService(first);
                Assert.Equal(1, await reconciliation.EmitAsync("accepted", new { value = 1 }, DateTimeOffset.UtcNow));
                Assert.Equal(2, await reconciliation.EmitAsync("running", new { value = 2 }, DateTimeOffset.UtcNow));
                Assert.Equal(3, await reconciliation.EmitAsync("completed", new { value = 3 }, DateTimeOffset.UtcNow));
            }

            await using var restarted = new NodeJournal(path);
            var restartedIdentity = await restarted.InitializeAsync(incarnation);
            Assert.Equal(incarnation, restartedIdentity.IncarnationId);
            var session = Guid.NewGuid();
            await restarted.BeginSessionAsync(session, incarnation);
            var reconciliationAfterRestart = new ReconciliationService(restarted);
            var replay = await reconciliationAfterRestart.ReplayUnacknowledgedAsync();
            Assert.Equal([1L, 2L, 3L], replay.Select(x => x.Sequence));

            await Assert.ThrowsAsync<StaleAcknowledgementException>(
                () => reconciliationAfterRestart.AcknowledgeAsync(Guid.NewGuid(), incarnation, 3));
            await reconciliationAfterRestart.AcknowledgeAsync(session, incarnation, 3);
            Assert.Empty(await reconciliationAfterRestart.ReplayUnacknowledgedAsync());
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Duplicate_command_returns_persisted_result_and_payload_conflict_is_rejected()
    {
        var path = DatabasePath();
        try
        {
            var incarnation = NodeIncarnationId.New();
            var executions = 0;
            var command = Command(incarnation, "same-key", "one");
            await using (var journal = new NodeJournal(path))
            {
                await journal.InitializeAsync(incarnation);
                var first = await journal.ExecuteCommandAsync(command, _ =>
                {
                    executions++;
                    return Task.FromResult(new CommandOutcome("ok", """{"result":1}"""));
                });
                var duplicate = await journal.ExecuteCommandAsync(command, _ => throw new Exception("must not execute"));
                Assert.Equal(first, duplicate);
            }

            await using var restarted = new NodeJournal(path);
            await restarted.InitializeAsync(incarnation);
            var storedCommand = await restarted.ExecuteCommandAsync(command, _ => throw new Exception("persisted completion must replay"));
            Assert.Equal("ok", storedCommand.Status);
            Assert.Equal(1, executions);
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Same_idempotency_identity_with_different_payload_is_rejected()
    {
        var path = DatabasePath();
        try
        {
            var incarnation = NodeIncarnationId.New();
            await using var journal = new NodeJournal(path);
            await journal.InitializeAsync(incarnation);
            var first = Command(incarnation, "identity", "one");
            await journal.ExecuteCommandAsync(first, _ => Task.FromResult(new CommandOutcome("ok", "{}")));
            var conflict = first with { Payload = Metadata("command", "two") };
            await Assert.ThrowsAsync<IdempotencyConflictException>(
                () => journal.ExecuteCommandAsync(conflict, _ => Task.FromResult(new CommandOutcome("bad", "{}"))));
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Delegation_refuses_deadline_generation_and_resource_violations_and_exposes_drain_state()
    {
        var path = DatabasePath();
        try
        {
            var incarnation = NodeIncarnationId.New();
            var dto = Delegation(incarnation);
            await using var journal = new NodeJournal(path);
            await journal.InitializeAsync(incarnation);
            await journal.AcceptDelegationAsync(dto);
            var authority = new DelegatedExecutionAuthority(journal);

            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                authority.ReserveStartAuthorityAsync(TaskAttemptId.New(), dto.DelegationId, TaskId.New(), 1, new ResourceRequirements(1), null, null, dto.AcceptedAt.AddMinutes(1)));
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                authority.ReserveStartAuthorityAsync(TaskAttemptId.New(), dto.DelegationId, dto.AllowedGenerations[0].TaskId, 3, new ResourceRequirements(1), null, null, dto.AcceptedAt.AddMinutes(1)));
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                authority.ReserveStartAuthorityAsync(TaskAttemptId.New(), dto.DelegationId, dto.AllowedGenerations[0].TaskId, 1, new ResourceRequirements(3), null, null, dto.AcceptedAt.AddMinutes(1)));
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                authority.ReserveStartAuthorityAsync(TaskAttemptId.New(), dto.DelegationId, dto.AllowedGenerations[0].TaskId, 1, new ResourceRequirements(1), null, null, dto.NoNewStartsAfter));

            Assert.Equal(DelegationAuthorityState.Draining, DelegatedExecutionAuthority.GetState(dto, dto.DrainAt));
            Assert.Equal(DelegationAuthorityState.Expired, DelegatedExecutionAuthority.GetState(dto, dto.AuthorityExpiresAt));
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Multiplexing_enforces_backpressure_payload_and_required_features()
    {
        var incarnation = NodeIncarnationId.New();
        var session = Guid.NewGuid();
        var securityA = new VerifiedSessionSecurity(true, true, "node", "control", "binding");
        var securityB = new VerifiedSessionSecurity(true, true, "control", "node", "binding");
        var pair = InMemoryDuplexCarrier.CreatePair(securityA, securityB);
        var helloA = Hello(session, incarnation, Set("resume"), Set("resume"), 4, 1);
        var helloB = Hello(session, incarnation, Set("resume"), Set(), 4, 1);
        var connectA = pair.First.ConnectAsync(helloA).AsTask();
        var connectB = pair.Second.ConnectAsync(helloB).AsTask();
        await using var a = await connectA;
        await using var b = await connectB;
        Assert.True(a.TrySend(Frame(session, incarnation, 1, "a")));
        Assert.False(a.TrySend(Frame(session, incarnation, 2, "b")));
        Assert.Throws<TransportProtocolException>(() => a.TrySend(Frame(session, incarnation, 2, "payload-too-large")));

        var unsupportedPair = InMemoryDuplexCarrier.CreatePair(securityA, securityB);
        var badA = unsupportedPair.First.ConnectAsync(Hello(session, incarnation, Set("new"), Set("new"), 2, 4)).AsTask();
        var badB = unsupportedPair.Second.ConnectAsync(Hello(session, incarnation, Set(), Set(), 2, 4)).AsTask();
        await Assert.ThrowsAsync<TransportProtocolException>(() => badA);
        await Assert.ThrowsAsync<TransportProtocolException>(() => badB);
    }

    [Fact]
    public async Task Pending_connection_and_reconnect_delay_are_cancellable_and_bounded()
    {
        var secure = new VerifiedSessionSecurity(true, true, "a", "b", "binding");
        var pair = InMemoryDuplexCarrier.CreatePair(secure, secure);
        using var cancellation = new CancellationTokenSource();
        var pending = pair.First.ConnectAsync(Hello(Guid.NewGuid(), NodeIncarnationId.New(), Set(), Set(), 8, 1), cancellation.Token).AsTask();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);

        var session = Guid.NewGuid();
        var incarnation = NodeIncarnationId.New();
        var firstReconnect = pair.First.ConnectAsync(Hello(session, incarnation, Set(), Set(), 8, 1)).AsTask();
        var secondReconnect = pair.Second.ConnectAsync(Hello(session, incarnation, Set(), Set(), 8, 1)).AsTask();
        await using var reconnectedFirst = await firstReconnect;
        await using var reconnectedSecond = await secondReconnect;

        Assert.InRange(
            Worker.ComputeBackoff(100, TimeSpan.FromMilliseconds(100), TimeSpan.FromSeconds(2), 1),
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task Command_callback_can_append_fact_without_deadlock_and_concurrent_duplicate_is_uncertain()
    {
        var path = DatabasePath();
        try
        {
            var incarnation = NodeIncarnationId.New();
            await using var journal = new NodeJournal(path);
            await journal.InitializeAsync(incarnation, Guid.NewGuid());
            var command = Command(incarnation, "concurrent", "payload");
            var callbackEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseCallback = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var execution = journal.ExecuteCommandAsync(command, async cancellationToken =>
            {
                await journal.AppendFactAsync("inside-command", new { ok = true }, DateTimeOffset.UtcNow, cancellationToken);
                callbackEntered.SetResult();
                await releaseCallback.Task.WaitAsync(cancellationToken);
                return new CommandOutcome("ok", "{}");
            });

            await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.ThrowsAsync<CommandExecutionUncertainException>(
                () => journal.ExecuteCommandAsync(command, _ => throw new Exception("must never execute")));
            releaseCallback.SetResult();
            Assert.Equal("ok", (await execution).Status);
            Assert.Single(await journal.ReadFactsAfterAsync(0));
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Restart_observing_accepted_command_requires_reconciliation_and_never_reexecutes()
    {
        var path = DatabasePath();
        var incarnation = NodeIncarnationId.New();
        var boot = Guid.NewGuid();
        var command = Command(incarnation, "crash-boundary", "payload");
        try
        {
            await using (var first = new NodeJournal(path))
            {
                await first.InitializeAsync(incarnation, boot);
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    first.ExecuteCommandAsync(command, _ => throw new OperationCanceledException()));
            }

            await using var restarted = new NodeJournal(path);
            await restarted.InitializeAsync(incarnation, boot);
            var executed = false;
            await Assert.ThrowsAsync<CommandExecutionUncertainException>(() =>
                restarted.ExecuteCommandAsync(command, _ =>
                {
                    executed = true;
                    return Task.FromResult(new CommandOutcome("bad", "{}"));
                }));
            Assert.False(executed);
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Journal_rejects_newer_schema_and_tracks_stable_or_changed_host_boot()
    {
        var path = DatabasePath();
        var incarnation = NodeIncarnationId.New();
        var boot = Guid.NewGuid();
        try
        {
            await using (var first = new NodeJournal(path))
            {
                var identity = await first.InitializeAsync(incarnation, boot);
                Assert.False(identity.RebootDetected);
                Assert.True(identity.HostBootIdentityVerified);
            }
            await using (var restart = new NodeJournal(path))
            {
                var identity = await restart.InitializeAsync(incarnation, boot);
                Assert.False(identity.RebootDetected);
                Assert.Equal(boot, identity.PreviousHostBootId);
            }
            await using (var reboot = new NodeJournal(path))
            {
                var nextBoot = Guid.NewGuid();
                var identity = await reboot.InitializeAsync(incarnation, nextBoot);
                Assert.True(identity.RebootDetected);
                Assert.Equal(boot, identity.PreviousHostBootId);
                Assert.Equal(nextBoot, identity.CurrentHostBootId);
            }

            await using (var connection = new SqliteConnection($"Data Source={path};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "UPDATE metadata SET value=$version WHERE key='schema_version'";
                command.Parameters.AddWithValue("$version", (NodeJournal.CurrentSchemaVersion + 1).ToString());
                await command.ExecuteNonQueryAsync();
            }
            await using var newer = new NodeJournal(path);
            await Assert.ThrowsAsync<UnsupportedJournalSchemaException>(() => newer.InitializeAsync(incarnation, boot));
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Attempt_id_cannot_be_reused_for_another_task_or_generation()
    {
        var path = DatabasePath();
        try
        {
            var incarnation = NodeIncarnationId.New();
            await using var journal = new NodeJournal(path);
            await journal.InitializeAsync(incarnation, Guid.NewGuid());
            var attemptId = TaskAttemptId.New();
            var first = Attempt(attemptId, TaskId.New(), 1, incarnation);
            await journal.RecordAttemptAsync(first);
            await journal.RecordAttemptAsync(first with { State = TaskAttemptState.Running });
            await Assert.ThrowsAsync<AttemptIdentityConflictException>(
                () => journal.RecordAttemptAsync(first with { TaskId = TaskId.New() }));
            await Assert.ThrowsAsync<AttemptIdentityConflictException>(
                () => journal.RecordAttemptAsync(first with { Generation = 2 }));
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Concurrent_starts_atomically_observe_rate_concurrency_and_resource_limits()
    {
        var path = DatabasePath();
        try
        {
            var incarnation = NodeIncarnationId.New();
            var tasks = Enumerable.Range(0, 20).Select(_ => TaskId.New()).ToArray();
            var delegation = BoundDelegation(incarnation, tasks, rateBudget: 4, concurrency: 4, cpuLimit: 4);
            await using var journal = new NodeJournal(path);
            await journal.InitializeAsync(incarnation, Guid.NewGuid());
            await journal.AcceptDelegationAsync(delegation);
            var authority = new DelegatedExecutionAuthority(journal);

            var starts = tasks.Select(async task =>
            {
                try
                {
                    return await authority.ReserveStartAuthorityAsync(
                        TaskAttemptId.New(), delegation.DelegationId, task, 1,
                        new ResourceRequirements(cpuCores: 1),
                        new Dictionary<string, decimal> { ["api"] = 1 }, null,
                        delegation.AcceptedAt.AddMinutes(1));
                }
                catch (DomainRuleViolationException) { return null; }
            });
            var results = await Task.WhenAll(starts);
            Assert.Equal(4, results.Count(x => x is not null));
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Reservations_survive_restart_terminal_release_does_not_refund_rate_and_control_can_reconcile_unused()
    {
        var path = DatabasePath();
        var incarnation = NodeIncarnationId.New();
        var tasks = new[] { TaskId.New(), TaskId.New() };
        var delegation = BoundDelegation(incarnation, tasks, rateBudget: 1, concurrency: 1, cpuLimit: 1);
        StartAuthorityReservation first;
        try
        {
            await using (var journal = new NodeJournal(path))
            {
                await journal.InitializeAsync(incarnation, Guid.NewGuid());
                await journal.AcceptDelegationAsync(delegation);
                first = await journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[0], 1,
                    new ResourceRequirements(cpuCores: 1),
                    new Dictionary<string, decimal> { ["api"] = 1 }, null,
                    delegation.AcceptedAt.AddMinutes(1));
            }

            await using var restarted = new NodeJournal(path);
            await restarted.InitializeAsync(incarnation, Guid.NewGuid());
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                restarted.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[1], 1,
                    new ResourceRequirements(cpuCores: 1),
                    new Dictionary<string, decimal> { ["api"] = 1 }, null,
                    delegation.AcceptedAt.AddMinutes(2)));

            var sequence = await restarted.CompleteStartReservationAsync(
                first.ReservationId, "completed", new { success = true },
                delegation.AuthorityExpiresAt.AddHours(1));
            Assert.Equal(sequence, await restarted.CompleteStartReservationAsync(
                first.ReservationId, "completed", new { success = true },
                delegation.AuthorityExpiresAt.AddHours(1)));
            Assert.Single(await restarted.ReadFactsAfterAsync(0));

            // Capacity was released, but externally consumed rate remains charged.
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                restarted.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[1], 1,
                    new ResourceRequirements(cpuCores: 1),
                    new Dictionary<string, decimal> { ["api"] = 1 }, null,
                    delegation.AcceptedAt.AddMinutes(2)));
            var controlObservedAt = delegation.AcceptedAt.AddMinutes(2);
            await restarted.ReconcileUnusedRateAsync(
                delegation.DelegationId, "api", 1, delegation.RevocationRevision,
                controlObservedAt);
            Assert.Equal(controlObservedAt,
                (await restarted.ReadFactsAfterAsync(0))
                .Single(x => x.FactType == "externalRateReconciledUnused").ObservedAt);
            var second = await restarted.ReserveStartAuthorityAsync(
                TaskAttemptId.New(), delegation.DelegationId, tasks[1], 1,
                new ResourceRequirements(cpuCores: 1),
                new Dictionary<string, decimal> { ["api"] = 1 }, null,
                delegation.AcceptedAt.AddMinutes(2));
            Assert.Equal(tasks[1], second.TaskId);
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Rate_and_identity_authority_require_exact_task_generation_binding()
    {
        var path = DatabasePath();
        try
        {
            var incarnation = NodeIncarnationId.New();
            var tasks = new[] { TaskId.New(), TaskId.New() };
            var grant = IdentityGrantId.New();
            var delegation = BoundDelegation(incarnation, tasks, 2, 2, 2, grant);
            await using var journal = new NodeJournal(path);
            await journal.InitializeAsync(incarnation, Guid.NewGuid());
            await journal.AcceptDelegationAsync(delegation);

            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[0], 1,
                    new ResourceRequirements(cpuCores: 1), null, null,
                    delegation.AcceptedAt.AddMinutes(1)));
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[0], 1,
                    new ResourceRequirements(cpuCores: 1),
                    new Dictionary<string, decimal> { ["api"] = 0.5m }, [grant],
                    delegation.AcceptedAt.AddMinutes(1)));
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[0], 1,
                    new ResourceRequirements(cpuCores: 1),
                    new Dictionary<string, decimal> { ["api"] = 1 }, null,
                    delegation.AcceptedAt.AddMinutes(1)));
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[1], 1,
                    new ResourceRequirements(cpuCores: 1),
                    new Dictionary<string, decimal> { ["api"] = 1 }, [grant],
                    delegation.AcceptedAt.AddMinutes(1)));
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[0], 2,
                    new ResourceRequirements(cpuCores: 1),
                    new Dictionary<string, decimal> { ["api"] = 1 }, [grant],
                    delegation.AcceptedAt.AddMinutes(1)));

            var valid = await journal.ReserveStartAuthorityAsync(
                TaskAttemptId.New(), delegation.DelegationId, tasks[0], 1,
                new ResourceRequirements(cpuCores: 1),
                new Dictionary<string, decimal> { ["api"] = 1 }, [grant],
                delegation.AcceptedAt.AddMinutes(1));
            Assert.Contains(grant, valid.IdentityGrantIds);
            Assert.Equal(1, valid.ConsumedRates["api"]);

            var legacy = Delegation(incarnation);
            await journal.AcceptDelegationAsync(legacy);
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), legacy.DelegationId, legacy.AllowedGenerations[0].TaskId, 1,
                    new ResourceRequirements(cpuCores: 1),
                    new Dictionary<string, decimal> { ["api"] = 1 }, null,
                    legacy.AcceptedAt.AddMinutes(1)));
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Drain_expiry_and_revocation_block_starts_but_truthful_completion_remains_allowed()
    {
        var path = DatabasePath();
        try
        {
            var incarnation = NodeIncarnationId.New();
            var tasks = new[] { TaskId.New(), TaskId.New() };
            var delegation = BoundDelegation(incarnation, tasks, 0, 2, 2);
            await using var journal = new NodeJournal(path);
            await journal.InitializeAsync(incarnation, Guid.NewGuid());
            await journal.AcceptDelegationAsync(delegation);
            var running = await journal.ReserveStartAuthorityAsync(
                TaskAttemptId.New(), delegation.DelegationId, tasks[0], 1,
                new ResourceRequirements(cpuCores: 1), null, null,
                delegation.AcceptedAt.AddMinutes(1));

            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[1], 1,
                    new ResourceRequirements(cpuCores: 1), null, null, delegation.DrainAt));
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[1], 2,
                    new ResourceRequirements(cpuCores: 1), null, null, delegation.NoNewStartsAfter));
            await journal.AdvanceDelegationRevocationAsync(delegation.DelegationId, delegation.RevocationRevision + 1);
            await Assert.ThrowsAsync<DomainRuleViolationException>(() =>
                journal.ReserveStartAuthorityAsync(
                    TaskAttemptId.New(), delegation.DelegationId, tasks[1], 1,
                    new ResourceRequirements(cpuCores: 1), null, null,
                    delegation.AcceptedAt.AddMinutes(2)));
            var sequence = await journal.CompleteStartReservationAsync(
                running.ReservationId, "completed-after-expiry", new { truthful = true },
                delegation.AuthorityExpiresAt.AddMinutes(1));
            Assert.Equal(1, sequence);
            Assert.Equal("completed-after-expiry", (await journal.ReadFactsAfterAsync(0)).Single().FactType);
        }
        finally { DeleteDatabase(path); }
    }

    private static SessionHello Hello(Guid session, NodeIncarnationId incarnation, IReadOnlySet<string> supported, IReadOnlySet<string> required, int payload, int buffered) =>
        new(session, incarnation, 1, 0, supported, required, new Dictionary<StreamKind, long>(), new TransportLimits(payload, buffered));

    private static IReadOnlySet<string> Set(params string[] values) => values.ToHashSet(StringComparer.Ordinal);

    private static TransportFrame Frame(Guid session, NodeIncarnationId incarnation, long sequence, string payload) =>
        new(session, incarnation, StreamKind.Events, sequence, sequence, Encoding.UTF8.GetBytes(payload));

    private static CommandDto Command(NodeIncarnationId incarnation, string key, string value) =>
        new(CommandId.New(), key, 0, null, incarnation, DateTimeOffset.UtcNow.AddHours(1), "test", "execute", Metadata("command", value));

    private static DelegationDto Delegation(NodeIncarnationId incarnation)
    {
        var now = DateTimeOffset.UtcNow;
        return new(
            DelegationId.New(), HostId.New(), incarnation, PlanRevisionId.New(),
            [new AttemptGenerationRangeDto(TaskId.New(), 1, 2)],
            new ResourceRequirementsDto(2, 1024, 1024, 0, 2, 0, 0, 2),
            2, 1024,
            [new RateLimitDto("api", 10, now.AddMinutes(10))],
            [IdentityGrantId.New()],
            now, now.AddMinutes(5), now.AddMinutes(10), now.AddMinutes(15), 0);
    }

    private static DelegationDto BoundDelegation(
        NodeIncarnationId incarnation,
        IReadOnlyList<TaskId> tasks,
        decimal rateBudget,
        int concurrency,
        decimal cpuLimit,
        IdentityGrantId? grant = null)
    {
        var now = DateTimeOffset.UtcNow;
        var grants = grant is null ? Array.Empty<IdentityGrantId>() : [grant.Value];
        var bindings = tasks.Select((task, index) => new TaskAuthorityBindingDto(
            task, 1,
            rateBudget > 0 && (index == 0 || grant is null)
                ? [new RateLimitDto("api", 1, now.AddMinutes(10))]
                : Array.Empty<RateLimitDto>(),
            index == 0 && grant is not null ? [grant.Value] : Array.Empty<IdentityGrantId>())).ToArray();
        return new(
            DelegationId.New(), HostId.New(), incarnation, PlanRevisionId.New(),
            tasks.Select(x => new AttemptGenerationRangeDto(x, 1, 2)).ToArray(),
            new ResourceRequirementsDto(cpuLimit, 10_000, 10_000, 0, concurrency, 0, 0, concurrency),
            concurrency, 10_000,
            rateBudget > 0 ? [new RateLimitDto("api", rateBudget, now.AddMinutes(10))] : [],
            grants, now, now.AddMinutes(5), now.AddMinutes(5), now.AddMinutes(15), 0, bindings);
    }

    private static ExtensionMetadataDto Metadata(string kind, string value) =>
        ExtensionMetadataDto.Create(kind, "1.0", new { value });

    private static TaskAttemptDto Attempt(TaskAttemptId attemptId, TaskId taskId, int generation, NodeIncarnationId incarnation) =>
        new(
            attemptId, taskId, generation, HostId.New(), incarnation, TaskAttemptState.Accepted,
            RecoveryCertainty.Certain, DelegationId.New(), CommandId.New(), DateTimeOffset.UtcNow.AddHours(1),
            Metadata("attempt", "value"));

    private static string DatabasePath()
    {
        var directory = Path.Combine("tests", "Steward.EndToEnd.Tests", "TestData");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, $"{Guid.NewGuid():N}.db");
    }

    private static void DeleteDatabase(string path)
    {
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            if (File.Exists(path + suffix)) File.Delete(path + suffix);
    }
}
