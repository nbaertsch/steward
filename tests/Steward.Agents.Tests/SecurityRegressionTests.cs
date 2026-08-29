using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Data.Sqlite;
using Steward.Agents;
using Steward.Domain;

namespace Steward.Agents.Tests;

public sealed class SecurityRegressionTests
{
    [Fact]
    public async Task RestartAtDispatchBoundaryBlocksWithoutDuplicateDispatch()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        var now = DateTimeOffset.UtcNow;
        await using (var first = new SqliteAgentStore(path))
        {
            await first.CreateAsync(agent, new("runtime", "1"));
            await first.SubmitTurnAsync(agent, new(AgentTurnId.New(), "work"));
            var owner = Guid.NewGuid();
            Assert.True(await first.TryAcquireRuntimeOwnershipAsync(agent, owner, now, TimeSpan.FromSeconds(5)));
            Assert.NotNull(await first.TryClaimNextAsync(agent, owner, now, false));
        }
        var dispatcher = new Dispatcher { ReconcileFact = ManagedExecutionFact.Present };
        await using (var restarted = new SqliteAgentStore(path))
        {
            var service = RecoveringService(restarted, dispatcher, now.AddSeconds(10));
            Assert.Equal(1, await service.ReconcileRecoveringAsync(agent));
            Assert.False(await service.RunNextAsync(agent));
            Assert.Empty(dispatcher.Dispatches);
            Assert.Single(await restarted.ReadRecoveringTurnsAsync(agent));
        }
        Cleanup(path);
    }

    [Fact]
    public async Task RestartAtResponseBoundaryCompletesFromManagedFactWithoutRedispatch()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        var now = DateTimeOffset.UtcNow;
        AgentTurnId turn;
        ManagedAgentExecution execution;
        await using (var first = new SqliteAgentStore(path))
        {
            await first.CreateAsync(agent, new("runtime", "1"));
            turn = (await first.SubmitTurnAsync(agent, new(AgentTurnId.New(), "work"))).TurnId;
            var owner = Guid.NewGuid();
            await first.TryAcquireRuntimeOwnershipAsync(agent, owner, now, TimeSpan.FromSeconds(5));
            var claimed = (await first.TryClaimNextAsync(agent, owner, now, false))!;
            execution = Lease(claimed);
            await first.SetExecutionAsync(agent, turn, execution);
        }
        var dispatcher = new Dispatcher
        {
            ReconcileFact = ManagedExecutionFact.Succeeded,
            ReconcileResponse = "recovered response"
        };
        await using (var restarted = new SqliteAgentStore(path))
        {
            var service = RecoveringService(restarted, dispatcher, now.AddSeconds(10));
            await service.ReconcileRecoveringAsync(agent);
            Assert.Empty(dispatcher.Dispatches);
            Assert.Equal("recovered response", (await restarted.GetTurnAsync(agent, turn))!.Response);
            Assert.Equal("recovered response", Assert.Single(await restarted.ReadAsync(agent, 0, 10)).Payload);
        }
        Cleanup(path);
    }

    [Fact]
    public async Task RestartAtRuntimeBoundaryRemainsBlockedWhileExecutionIsPresent()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        var now = DateTimeOffset.UtcNow;
        await using (var first = new SqliteAgentStore(path))
        {
            await first.CreateAsync(agent, new("runtime", "1"));
            var turn = await first.SubmitTurnAsync(agent, new(AgentTurnId.New(), "work"));
            var owner = Guid.NewGuid();
            await first.TryAcquireRuntimeOwnershipAsync(agent, owner, now, TimeSpan.FromSeconds(5));
            var claimed = (await first.TryClaimNextAsync(agent, owner, now, false))!;
            await first.SetExecutionAsync(agent, turn.TurnId, Lease(claimed));
        }
        var dispatcher = new Dispatcher { ReconcileFact = ManagedExecutionFact.Present };
        await using (var restarted = new SqliteAgentStore(path))
        {
            var service = RecoveringService(restarted, dispatcher, now.AddSeconds(10));
            await service.ReconcileRecoveringAsync(agent);
            Assert.False(await service.RunNextAsync(agent));
            var recovering = Assert.Single(await restarted.ReadRecoveringTurnsAsync(agent));
            Assert.NotNull(recovering.Execution);
            Assert.Empty(dispatcher.Dispatches);
        }
        Cleanup(path);
    }

    [Fact]
    public async Task CrashAfterRuntimeFinalFinalizesPendingResultExactlyOnce()
    {
        var state = await CreatePendingResultAsync("runtime-final");
        var dispatcher = new Dispatcher { ReconcileFact = ManagedExecutionFact.Present };
        await using (var restarted = new SqliteAgentStore(state.Path))
        {
            var service = RecoveringService(restarted, dispatcher, state.RecoveryNow);
            await service.ReconcileRecoveringAsync(state.AgentId);
            Assert.Equal(["input", "runtime-final"],
                (await restarted.ReadContextAsync(state.AgentId)).Select(x => x.Text));
            Assert.Single(await restarted.ReadAsync(state.AgentId, 0, 10));
            Assert.Null(await restarted.GetPendingResultAsync(state.AgentId, state.TurnId));
        }
        Cleanup(state.Path);
    }

    [Fact]
    public async Task CrashAfterDispatcherTerminalUsesKnownFactWithoutDuplicateContext()
    {
        var state = await CreatePendingResultAsync("reported-final");
        var dispatcher = new Dispatcher
        {
            ReconcileFact = ManagedExecutionFact.Succeeded,
            ReconcileResponse = "reported-final"
        };
        await dispatcher.ReportTerminalAsync(state.Execution,
            new(AgentTerminalKind.Responded, "reported-final", null, null), CancellationToken.None);
        await using (var restarted = new SqliteAgentStore(state.Path))
        {
            var service = RecoveringService(restarted, dispatcher, state.RecoveryNow);
            await service.ReconcileRecoveringAsync(state.AgentId);
            Assert.Equal(2, (await restarted.ReadContextAsync(state.AgentId)).Count);
            Assert.Single(await restarted.ReadAsync(state.AgentId, 0, 10));
        }
        Cleanup(state.Path);
    }

    [Fact]
    public async Task CrashAfterAtomicFinalizeDoesNotDuplicateContextOrNotification()
    {
        var state = await CreatePendingResultAsync("finalized");
        await using (var store = new SqliteAgentStore(state.Path))
        {
            await store.MarkPendingResultReportedAsync(state.AgentId, state.TurnId, state.Execution.LeaseId);
            await store.FinalizePendingResultAsync(state.AgentId, state.TurnId, state.Execution.LeaseId);
        }
        await using (var restarted = new SqliteAgentStore(state.Path))
        {
            var service = RecoveringService(restarted, new Dispatcher(), state.RecoveryNow);
            Assert.Equal(0, await service.ReconcileRecoveringAsync(state.AgentId));
            Assert.Equal(2, (await restarted.ReadContextAsync(state.AgentId)).Count);
            Assert.Single(await restarted.ReadAsync(state.AgentId, 0, 10));
        }
        Cleanup(state.Path);
    }

    [Fact]
    public async Task RuntimeNeverRunsWithoutAcceptedManagedLease()
    {
        await using var fixture = new StoreFixture();
        var dispatcher = new Dispatcher { Accept = false };
        var runtime = new CountingRuntime();
        var service = new StewardAgentService(fixture.Store, runtime, dispatcher);
        var agent = StewardAgentId.New();
        var turn = AgentTurnId.New();
        await service.CreateAsync(agent);
        await service.SubmitAsync(agent, new(turn, "blocked"));
        Assert.True(await service.RunNextAsync(agent));
        Assert.Equal(0, runtime.Invocations);
        Assert.Equal("dispatch-not-authorized", (await fixture.Store.GetTurnAsync(agent, turn))!.ErrorCode);
    }

    [Fact]
    public async Task SuccessAndFailureEachReportOneManagedTerminalOutcome()
    {
        await using var fixture = new StoreFixture();
        var dispatcher = new Dispatcher();
        var success = new StewardAgentService(fixture.Store, new CountingRuntime(), dispatcher);
        var agent = StewardAgentId.New();
        await success.CreateAsync(agent);
        await success.SubmitAsync(agent, new(AgentTurnId.New(), "success"));
        await success.RunNextAsync(agent);
        var failure = new StewardAgentService(
            fixture.Store, new ThrowingRuntime(), dispatcher, ownerId: success.OwnerId);
        await failure.SubmitAsync(agent, new(AgentTurnId.New(), "failure"));
        await failure.RunNextAsync(agent);
        Assert.Equal(2, dispatcher.Reports.Count);
        Assert.Single(dispatcher.Reports, x => x.Kind == AgentTerminalKind.Responded);
        Assert.Single(dispatcher.Reports, x => x.Kind == AgentTerminalKind.Failed);
    }

    [Fact]
    public async Task ConcurrentStoresClaimOnlyOneNonparallelTurn()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        await using var first = new SqliteAgentStore(path);
        await using var second = new SqliteAgentStore(path);
        await first.CreateAsync(agent, new("runtime", "1"));
        await first.SubmitTurnAsync(agent, new(AgentTurnId.New(), "one"));
        await first.SubmitTurnAsync(agent, new(AgentTurnId.New(), "two"));
        var owner = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await first.TryAcquireRuntimeOwnershipAsync(agent, owner, now, TimeSpan.FromMinutes(1));
        var claims = await Task.WhenAll(
            first.TryClaimNextAsync(agent, owner, now, false),
            second.TryClaimNextAsync(agent, owner, now, false));
        Assert.Single(claims, x => x is not null);
        await first.DisposeAsync();
        await second.DisposeAsync();
        Cleanup(path);
    }

    [Fact]
    public async Task LiveOwnerCannotBeStolenButExpiredOwnerCanBeRecovered()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        var firstOwner = Guid.NewGuid();
        var secondOwner = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await using var first = new SqliteAgentStore(path);
        await using var second = new SqliteAgentStore(path);
        await first.CreateAsync(agent, new("runtime", "1"));
        await first.SubmitTurnAsync(agent, new(AgentTurnId.New(), "owned"));
        Assert.True(await first.TryAcquireRuntimeOwnershipAsync(
            agent, firstOwner, now, TimeSpan.FromMinutes(1)));
        Assert.NotNull(await first.TryClaimNextAsync(agent, firstOwner, now, false));
        Assert.False(await second.TryAcquireRuntimeOwnershipAsync(
            agent, secondOwner, now.AddSeconds(10), TimeSpan.FromMinutes(1)));
        Assert.Equal(0, await second.RecoverAbandonedTurnsAsync(agent, secondOwner, now.AddSeconds(10)));
        Assert.Equal(AgentTurnStatus.Dispatching, Assert.Single(await first.ReadPendingTurnsAsync(agent)).Status);
        Assert.True(await first.TryRenewRuntimeOwnershipAsync(
            agent, firstOwner, now.AddSeconds(50), TimeSpan.FromMinutes(1)));
        Assert.False(await second.TryAcquireRuntimeOwnershipAsync(
            agent, secondOwner, now.AddSeconds(70), TimeSpan.FromMinutes(1)));
        var expired = now.AddMinutes(2);
        Assert.True(await second.TryAcquireRuntimeOwnershipAsync(
            agent, secondOwner, expired, TimeSpan.FromMinutes(1)));
        Assert.Equal(1, await second.RecoverAbandonedTurnsAsync(agent, secondOwner, expired));
        Assert.Equal(AgentTurnStatus.Recovering, Assert.Single(await second.ReadRecoveringTurnsAsync(agent)).Status);
        await first.DisposeAsync();
        await second.DisposeAsync();
        Cleanup(path);
    }

    [Fact]
    public async Task AgentCreateIdempotencyComparesAllImmutableFields()
    {
        await using var fixture = new StoreFixture();
        var agent = StewardAgentId.New();
        await fixture.Store.CreateAsync(agent, new("runtime", "1", true), "parent-a");
        await fixture.Store.CreateAsync(agent, new("runtime", "1", true), "parent-a");
        await Assert.ThrowsAsync<AgentConflictException>(() =>
            fixture.Store.CreateAsync(agent, new("runtime", "1", false), "parent-a"));
        await Assert.ThrowsAsync<AgentConflictException>(() =>
            fixture.Store.CreateAsync(agent, new("runtime", "1", true), "parent-b"));
    }

    [Fact]
    public async Task MigrationRequiresDrainedSessionButAllowsQueuedAndTerminalTurns()
    {
        await using var fixture = new StoreFixture();
        var now = DateTimeOffset.UtcNow;

        foreach (var activeState in new[]
                 {
                     AgentTurnStatus.Dispatching,
                     AgentTurnStatus.Running,
                     AgentTurnStatus.Recovering
                 })
        {
            var agent = StewardAgentId.New();
            var owner = Guid.NewGuid();
            await fixture.Store.CreateAsync(agent, new("runtime", "1"));
            await fixture.Store.TryAcquireRuntimeOwnershipAsync(
                agent, owner, now, TimeSpan.FromSeconds(5));
            var submitted = await fixture.Store.SubmitTurnAsync(
                agent, new(AgentTurnId.New(), activeState.ToString()));
            var claimed = (await fixture.Store.TryClaimNextAsync(agent, owner, now, false))!;
            if (activeState is AgentTurnStatus.Running or AgentTurnStatus.Recovering)
                await fixture.Store.SetExecutionAsync(agent, submitted.TurnId, Lease(claimed));
            if (activeState == AgentTurnStatus.Recovering)
            {
                var recoveryOwner = Guid.NewGuid();
                var expired = now.AddSeconds(10);
                await fixture.Store.TryAcquireRuntimeOwnershipAsync(
                    agent, recoveryOwner, expired, TimeSpan.FromSeconds(5));
                Assert.Equal(1, await fixture.Store.RecoverAbandonedTurnsAsync(
                    agent, recoveryOwner, expired));
            }

            var descriptor = (await fixture.Store.GetAsync(agent))!;
            Assert.Null(await fixture.Store.BeginMigrationAsync(
                agent, HostId.New(), descriptor.Revision));
            Assert.False((await fixture.Store.GetAsync(agent))!.Frozen);
            Assert.Null(await fixture.Store.GetMigrationAsync(agent));
        }

        var queuedAgent = StewardAgentId.New();
        await fixture.Store.CreateAsync(queuedAgent, new("runtime", "1"));
        await fixture.Store.SubmitTurnAsync(queuedAgent, new(AgentTurnId.New(), "queued"));
        var queuedDescriptor = (await fixture.Store.GetAsync(queuedAgent))!;
        Assert.NotNull(await fixture.Store.BeginMigrationAsync(
            queuedAgent, HostId.New(), queuedDescriptor.Revision));
        Assert.True((await fixture.Store.GetAsync(queuedAgent))!.Frozen);

        var terminalAgent = StewardAgentId.New();
        var terminalOwner = Guid.NewGuid();
        await fixture.Store.CreateAsync(terminalAgent, new("runtime", "1"));
        await fixture.Store.TryAcquireRuntimeOwnershipAsync(
            terminalAgent, terminalOwner, now, TimeSpan.FromMinutes(1));
        var terminalTurn = await fixture.Store.SubmitTurnAsync(
            terminalAgent, new(AgentTurnId.New(), "terminal"));
        var terminalClaim = (await fixture.Store.TryClaimNextAsync(
            terminalAgent, terminalOwner, now, false))!;
        await fixture.Store.SetExecutionAsync(terminalAgent, terminalTurn.TurnId, Lease(terminalClaim));
        await fixture.Store.FailAsync(terminalAgent, terminalTurn.TurnId, "test-failure", null);
        var terminalDescriptor = (await fixture.Store.GetAsync(terminalAgent))!;
        Assert.NotNull(await fixture.Store.BeginMigrationAsync(
            terminalAgent, HostId.New(), terminalDescriptor.Revision));
        Assert.True((await fixture.Store.GetAsync(terminalAgent))!.Frozen);
    }

    [Fact]
    public async Task ConcurrentSequencesAndFullRequestIdempotencyRemainExact()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        await using var first = new SqliteAgentStore(path);
        await using var second = new SqliteAgentStore(path);
        await first.CreateAsync(agent, new("runtime", "1"));
        await Task.WhenAll(
            first.AppendContextAsync(agent, "a", TextProvenance.User),
            second.AppendContextAsync(agent, "b", TextProvenance.Tool));
        Assert.Equal([1L, 2L], (await first.ReadContextAsync(agent)).Select(x => x.Sequence));
        var id = AgentTurnId.New();
        await first.SubmitTurnAsync(agent, new(id, "same", TextProvenance.User, "client"));
        await Assert.ThrowsAsync<AgentConflictException>(() =>
            second.SubmitTurnAsync(agent, new(id, "same", TextProvenance.Tool, "client")));
        await first.DisposeAsync();
        await second.DisposeAsync();
        Cleanup(path);
    }

    [Fact]
    public async Task LogicalDatabaseCorruptionFailsClosed()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        var turn = AgentTurnId.New();
        await using (var store = new SqliteAgentStore(path))
        {
            await store.CreateAsync(agent, new("runtime", "1"));
            await store.SubmitTurnAsync(agent, new(turn, "work"));
        }
        var builder = new SqliteConnectionStringBuilder { DataSource = path, Pooling = false };
        await using (var connection = new SqliteConnection(builder.ToString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "UPDATE turns SET status=99 WHERE turn_id=$turn";
            command.Parameters.AddWithValue("$turn", turn.ToString());
            await command.ExecuteNonQueryAsync();
        }
        await using (var store = new SqliteAgentStore(path))
            await Assert.ThrowsAsync<AgentStoreException>(() => store.GetTurnAsync(agent, turn));
        Cleanup(path);
    }

    [Fact]
    public async Task CheckpointImportRejectsConflictingExistingIdentity()
    {
        await using var fixture = new StoreFixture();
        var agent = StewardAgentId.New();
        await fixture.Store.CreateAsync(agent, new("runtime", "1"));
        await fixture.Store.AppendContextAsync(agent, "original", TextProvenance.User);
        await Assert.ThrowsAsync<AgentConflictException>(() => fixture.Store.ImportCheckpointAsync(
            agent, [new(1, "different", TextProvenance.User, 3, null, null, null)], []));
        var turn = await fixture.Store.SubmitTurnAsync(agent,
            new(AgentTurnId.New(), "original", TextProvenance.User, "client-a"));
        var conflicting = turn with { ClientRequestId = "client-b" };
        await Assert.ThrowsAsync<AgentConflictException>(() =>
            fixture.Store.ImportCheckpointAsync(agent, [], [conflicting]));
    }

    [Fact]
    public async Task CompletionCancellationRaceCreatesOneTruthfulNotification()
    {
        await using var fixture = new StoreFixture();
        var agent = StewardAgentId.New();
        await fixture.Store.CreateAsync(agent, new("runtime", "1"));
        var turn = await fixture.Store.SubmitTurnAsync(agent, new(AgentTurnId.New(), "race"));
        var owner = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await fixture.Store.TryAcquireRuntimeOwnershipAsync(agent, owner, now, TimeSpan.FromMinutes(1));
        var claimed = (await fixture.Store.TryClaimNextAsync(agent, owner, now, false))!;
        await fixture.Store.SetExecutionAsync(agent, turn.TurnId, Lease(claimed));
        var outcomes = await Task.WhenAll(
            Capture(() => fixture.Store.CompleteAsync(agent, turn.TurnId, "response")),
            Capture(async () => { await fixture.Store.CancelAsync(agent, turn.TurnId); }));
        Assert.Single(outcomes, x => x is null);
        var persisted = (await fixture.Store.GetTurnAsync(agent, turn.TurnId))!;
        var notification = Assert.Single(await fixture.Store.ReadAsync(agent, 0, 10));
        Assert.True(
            (persisted.Status == AgentTurnStatus.Responded && notification.Kind == "response") ||
            (persisted.Status == AgentTurnStatus.Cancelled && notification.Kind == "cancelled"));
    }

    [Fact]
    public async Task RepeatedTerminalWriteIsExactAndNeverDuplicatesNotification()
    {
        await using var fixture = new StoreFixture();
        var agent = StewardAgentId.New();
        await fixture.Store.CreateAsync(agent, new("runtime", "1"));
        var turn = await fixture.Store.SubmitTurnAsync(agent, new(AgentTurnId.New(), "failure"));
        var owner = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await fixture.Store.TryAcquireRuntimeOwnershipAsync(agent, owner, now, TimeSpan.FromMinutes(1));
        var claimed = (await fixture.Store.TryClaimNextAsync(agent, owner, now, false))!;
        await fixture.Store.SetExecutionAsync(agent, turn.TurnId, Lease(claimed));
        await fixture.Store.FailAsync(agent, turn.TurnId, "stable-code", null);
        await fixture.Store.FailAsync(agent, turn.TurnId, "stable-code", null);
        await Assert.ThrowsAsync<AgentConflictException>(() =>
            fixture.Store.FailAsync(agent, turn.TurnId, "different-code", null));
        var notification = Assert.Single(await fixture.Store.ReadAsync(agent, 0, 10));
        Assert.Equal("code:stable-code", notification.Payload);
    }

    [Fact]
    public async Task RuntimeExceptionDoesNotPersistSecretAndFailureNotifiesParent()
    {
        await using var fixture = new StoreFixture();
        var service = new StewardAgentService(fixture.Store,
            new ThrowingRuntime("https://example.invalid/?sig=TOPSECRET"), new Dispatcher());
        var agent = StewardAgentId.New();
        var turn = AgentTurnId.New();
        await service.CreateAsync(agent);
        await service.SubmitAsync(agent, new(turn, "fail"));
        await service.RunNextAsync(agent);
        var record = (await fixture.Store.GetTurnAsync(agent, turn))!;
        Assert.Equal("agent-runtime-failed", record.ErrorCode);
        Assert.DoesNotContain("TOPSECRET", record.SafeErrorDetail ?? "", StringComparison.Ordinal);
        var notification = Assert.Single(await fixture.Store.ReadAsync(agent, 0, 10));
        Assert.Equal("failure", notification.Kind);
        Assert.Equal("code:agent-runtime-failed", notification.Payload);
        Assert.Equal(TextProvenance.Steward, notification.Provenance);
        Assert.DoesNotContain("TOPSECRET", notification.Payload, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RepeatedCompactionPreservesLineageAndRecentSemanticContext()
    {
        await using var fixture = new StoreFixture();
        var agent = StewardAgentId.New();
        await fixture.Store.CreateAsync(agent, new("runtime", "1"));
        await fixture.Store.AppendContextAsync(agent, new string('a', 120), TextProvenance.User);
        await fixture.Store.AppendContextAsync(agent, "recent-one", TextProvenance.Runtime);
        var budget = new ContextBudget(140, 100);
        await fixture.Store.CompactContextAsync(agent, budget, new BoundedExtractiveContextCompactor());
        var first = await fixture.Store.ReadContextAsync(agent);
        var checkpoint = first[0].CheckpointId;
        Assert.Contains(first, x => x.Text == "recent-one");
        await fixture.Store.AppendContextAsync(agent, new string('b', 120), TextProvenance.User);
        await fixture.Store.AppendContextAsync(agent, "recent-two", TextProvenance.Runtime);
        await fixture.Store.CompactContextAsync(agent, budget, new BoundedExtractiveContextCompactor());
        var second = await fixture.Store.ReadContextAsync(agent);
        Assert.Equal(checkpoint, second[0].ParentCheckpointId);
        Assert.Contains(second, x => x.Text == "recent-two");
    }

    private sealed class Dispatcher : IAgentTaskDispatcher
    {
        public bool Accept { get; set; } = true;
        public ManagedExecutionFact ReconcileFact { get; set; } = ManagedExecutionFact.Present;
        public string? ReconcileResponse { get; set; }
        public List<AgentTaskIntent> Dispatches { get; } = [];
        public List<AgentTerminalReport> Reports { get; } = [];
        private readonly HashSet<Guid> _terminalLeases = [];
        public Task<ManagedAgentExecution?> DispatchAsync(
            AgentTaskIntent intent, CancellationToken cancellationToken)
        {
            Dispatches.Add(intent);
            return Task.FromResult<ManagedAgentExecution?>(Accept
                ? new(Guid.NewGuid(), intent.WorkloadId, intent.TaskId, TaskAttemptId.New(), 1,
                    HostId.New(), NodeIncarnationId.New(), DateTimeOffset.UtcNow)
                : null);
        }
        public Task<ManagedExecutionStatus> ReconcileAsync(
            WorkloadId workloadId, TaskId taskId, ManagedAgentExecution? execution,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ManagedExecutionStatus(
                ReconcileFact, execution, ReconcileResponse,
                ReconcileFact == ManagedExecutionFact.Failed ? "managed-failure" : null));
        public Task<bool> ReportTerminalAsync(
            ManagedAgentExecution execution, AgentTerminalReport report, CancellationToken cancellationToken)
        {
            if (!_terminalLeases.Add(execution.LeaseId)) return Task.FromResult(false);
            Reports.Add(report);
            return Task.FromResult(true);
        }
        public Task CancelAsync(ManagedAgentExecution execution, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class CountingRuntime : IAgentRuntime
    {
        public int Invocations { get; private set; }
        public AgentRuntimeDescriptor Descriptor { get; } = new("runtime", "1");
        public async IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
            AgentRuntimeRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Invocations++;
            await Task.Yield();
            yield return new AgentFinalResponse("done");
        }
    }

    private sealed class ThrowingRuntime(string message = "runtime failed") : IAgentRuntime
    {
        public AgentRuntimeDescriptor Descriptor { get; } = new("runtime", "1");
        public async IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
            AgentRuntimeRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            throw new InvalidOperationException(message);
#pragma warning disable CS0162
            yield break;
#pragma warning restore CS0162
        }
    }

    private sealed class StoreFixture : IAsyncDisposable
    {
        public StoreFixture()
        {
            Path = NewPath();
            Store = new(Path);
        }
        public string Path { get; }
        public SqliteAgentStore Store { get; }
        public async ValueTask DisposeAsync()
        {
            await Store.DisposeAsync();
            Cleanup(Path);
        }
    }

    private static ManagedAgentExecution Lease(AgentTurnRecord turn) =>
        new(Guid.NewGuid(), turn.WorkloadId!.Value, turn.TaskId!.Value, TaskAttemptId.New(), 1,
            HostId.New(), NodeIncarnationId.New(), DateTimeOffset.UtcNow);
    private static async Task<PendingState> CreatePendingResultAsync(string response)
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        var turnId = AgentTurnId.New();
        var now = DateTimeOffset.UtcNow;
        ManagedAgentExecution execution;
        await using (var store = new SqliteAgentStore(path))
        {
            await store.CreateAsync(agent, new("runtime", "1"));
            await store.SubmitTurnAsync(agent, new(turnId, "input"));
            var owner = Guid.NewGuid();
            await store.TryAcquireRuntimeOwnershipAsync(agent, owner, now, TimeSpan.FromSeconds(5));
            var claimed = (await store.TryClaimNextAsync(agent, owner, now, false))!;
            execution = Lease(claimed);
            await store.SetExecutionAsync(agent, turnId, execution);
            await store.SavePendingResultAsync(agent, turnId, execution, response);
        }
        return new(path, agent, turnId, execution, now.AddSeconds(10));
    }
    private sealed record PendingState(
        string Path, StewardAgentId AgentId, AgentTurnId TurnId,
        ManagedAgentExecution Execution, DateTimeOffset RecoveryNow);
    private static StewardAgentService RecoveringService(
        IAgentStore store, IAgentTaskDispatcher dispatcher, DateTimeOffset now) =>
        new(store, new CountingRuntime(), dispatcher, ownerId: Guid.NewGuid(),
            timeProvider: new FixedTimeProvider(now), ownershipLease: TimeSpan.FromSeconds(5));
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
    private static async Task<Exception?> Capture(Func<Task> action)
    {
        try
        {
            await action();
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }
    private static string NewPath() =>
        Path.Combine(AppContext.BaseDirectory, $"security-{Guid.NewGuid():N}.db");
    private static void Cleanup(string path)
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            if (File.Exists(path + suffix)) File.Delete(path + suffix);
    }
}
