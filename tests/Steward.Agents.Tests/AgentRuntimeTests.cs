using System.Runtime.CompilerServices;
using Steward.Agents;
using Steward.Domain;

namespace Steward.Agents.Tests;

public sealed class AgentRuntimeTests
{
    [Fact]
    public async Task MultiTurnContextIsRetainedAndNotificationsReplayAfterDisconnect()
    {
        await using var fixture = new Fixture();
        var service = fixture.Service();
        var agent = StewardAgentId.New();
        await service.CreateAsync(agent, "parent/local");
        var first = AgentTurnId.New();
        var second = AgentTurnId.New();
        await service.SubmitAsync(agent, new(first, "one"));
        Assert.True(await service.RunNextAsync(agent));
        await service.SubmitAsync(agent, new(second, "two"));
        Assert.True(await service.RunNextAsync(agent));

        var context = await fixture.Store.ReadContextAsync(agent);
        Assert.Equal(["one", "echo:one", "two", "echo:two"], context.Select(x => x.Text));
        var disconnectedReplay = await fixture.Store.ReadAsync(agent, 0, 10);
        Assert.Equal(["echo:one", "echo:two"], disconnectedReplay.Select(x => x.Payload));
        Assert.Equal(disconnectedReplay, await fixture.Store.ReadAsync(agent, 0, 10));
        await fixture.Store.AcknowledgeAsync(agent, 2);
        Assert.Empty(await fixture.Store.ReadAsync(agent, 2, 10));
    }

    [Fact]
    public async Task ContextCompactsDeterministicallyAtCap()
    {
        await using var fixture = new Fixture();
        var agent = StewardAgentId.New();
        await fixture.Store.CreateAsync(agent, new("fake", "1"));
        await fixture.Store.AppendContextAsync(agent, new string('x', 100), TextProvenance.User);
        await fixture.Store.CompactContextAsync(agent, new(50, 100), new DeterministicContextCompactor());
        var context = await fixture.Store.ReadContextAsync(agent);
        Assert.Single(context);
        Assert.NotNull(context[0].CheckpointId);
        Assert.NotNull(context[0].SummarySha256);
        Assert.StartsWith("context-checkpoint:", context[0].Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RestartRecoversQueueAndResponseExactly()
    {
        var path = Fixture.NewPath();
        var agent = StewardAgentId.New();
        var turn = AgentTurnId.New();
        await using (var first = new SqliteAgentStore(path))
        {
            await first.CreateAsync(agent, new("fake", "1"));
            await first.SubmitTurnAsync(agent, new(turn, "durable"));
            var owner = Guid.NewGuid();
            var now = DateTimeOffset.UtcNow;
            Assert.True(await first.TryAcquireRuntimeOwnershipAsync(agent, owner, now, TimeSpan.FromSeconds(5)));
            Assert.NotNull(await first.TryClaimNextAsync(agent, owner, now, false));
        }
        await using (var second = new SqliteAgentStore(path))
        {
            Assert.Equal(AgentTurnStatus.Dispatching, (await second.GetTurnAsync(agent, turn))!.Status);
            var dispatcher = new RecordingDispatcher { ReconcileFact = ManagedExecutionFact.Absent };
            var recoveryNow = DateTimeOffset.UtcNow.AddSeconds(10);
            var service = new StewardAgentService(second, new DeterministicAgentRuntime(), dispatcher,
                ownerId: Guid.NewGuid(), timeProvider: new FixedTimeProvider(recoveryNow),
                ownershipLease: TimeSpan.FromSeconds(5));
            Assert.Equal(1, await service.ReconcileRecoveringAsync(agent));
            Assert.NotNull(await second.TryClaimNextAsync(agent, service.OwnerId, recoveryNow, false));
            var lease = dispatcher.CreateExecution(
                (await second.GetTurnAsync(agent, turn))!);
            await second.SetExecutionAsync(agent, turn, lease);
            await second.CompleteAsync(agent, turn, "exact response");
        }
        await using (var third = new SqliteAgentStore(path))
        {
            Assert.Equal("exact response", (await third.GetTurnAsync(agent, turn))!.Response);
            Assert.Equal("exact response", Assert.Single(await third.ReadAsync(agent, 0, 10)).Payload);
        }
        Fixture.Cleanup(path);
    }

    [Fact]
    public async Task DuplicateTurnIsIdempotentButDifferentBodyConflicts()
    {
        await using var fixture = new Fixture();
        var agent = StewardAgentId.New();
        var turn = AgentTurnId.New();
        await fixture.Store.CreateAsync(agent, new("fake", "1"));
        var original = await fixture.Store.SubmitTurnAsync(agent, new(turn, "same"));
        var replay = await fixture.Store.SubmitTurnAsync(agent, new(turn, "same"));
        Assert.Equal(original.QueueSequence, replay.QueueSequence);
        await Assert.ThrowsAsync<AgentConflictException>(
            () => fixture.Store.SubmitTurnAsync(agent, new(turn, "different")));
    }

    [Fact]
    public async Task RuntimeFailureIsDurableAndOneTurnRunsAtATime()
    {
        await using var fixture = new Fixture();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var runtime = new BlockingRuntime(gate);
        var service = fixture.Service(runtime);
        var agent = StewardAgentId.New();
        var first = AgentTurnId.New();
        var second = AgentTurnId.New();
        await service.CreateAsync(agent);
        await service.SubmitAsync(agent, new(first, "first"));
        await service.SubmitAsync(agent, new(second, "second"));
        var active = service.RunNextAsync(agent);
        await runtime.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(await service.RunNextAsync(agent));
        gate.SetResult();
        Assert.True(await active);

        var failing = fixture.Service(new FailingRuntime(), ownerId: service.OwnerId);
        Assert.True(await failing.RunNextAsync(agent));
        Assert.Equal(AgentTurnStatus.Failed, (await fixture.Store.GetTurnAsync(agent, second))!.Status);
        Assert.Equal("agent-runtime-failed", (await fixture.Store.GetTurnAsync(agent, second))!.ErrorCode);
    }

    [Fact]
    public async Task CancellationDispatchesManagedTaskCancellation()
    {
        await using var fixture = new Fixture();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var runtime = new BlockingRuntime(gate);
        var dispatcher = new RecordingDispatcher();
        var service = fixture.Service(runtime, dispatcher);
        var agent = StewardAgentId.New();
        var turn = AgentTurnId.New();
        await service.CreateAsync(agent);
        await service.SubmitAsync(agent, new(turn, "cancel me"));
        var active = service.RunNextAsync(agent);
        await runtime.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(await service.CancelAsync(agent, turn));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => active);
        Assert.Single(dispatcher.Cancellations);
        Assert.Single(dispatcher.Reports, x => x.Report.Kind == AgentTerminalKind.Cancelled);
        Assert.Equal(AgentTurnStatus.Cancelled, (await fixture.Store.GetTurnAsync(agent, turn))!.Status);
    }

    [Fact]
    public async Task EveryRemediationUsesManagedTaskDispatcher()
    {
        await using var fixture = new Fixture();
        var dispatcher = new RecordingDispatcher();
        var service = fixture.Service(dispatcher: dispatcher);
        var agent = StewardAgentId.New();
        var turn = AgentTurnId.New();
        await service.CreateAsync(agent);
        var record = await service.SubmitAsync(agent, new(turn, "work"));
        foreach (var command in new[]
                 {
                     AgentCommandKind.Inspect, AgentCommandKind.Diagnose, AgentCommandKind.Commit,
                     AgentCommandKind.RequestRetry, AgentCommandKind.RequestRestart
                 })
        {
            var execution = await service.DispatchCommandAsync(
                agent, turn, command, command.ToString(), TextProvenance.User);
            Assert.Equal(record.WorkloadId, execution.WorkloadId);
            Assert.Equal(record.TaskId, execution.TaskId);
        }
        Assert.All(dispatcher.Intents, intent =>
        {
            Assert.Equal(record.WorkloadId, intent.WorkloadId);
            Assert.Equal(record.TaskId, intent.TaskId);
        });
        Assert.Equal(5, dispatcher.Intents.Count);
        Assert.Empty(dispatcher.Reports);
    }

    [Fact]
    public async Task CursorAckIsMonotonicAndBounded()
    {
        await using var fixture = new Fixture();
        var service = fixture.Service();
        var agent = StewardAgentId.New();
        await service.CreateAsync(agent);
        await service.SubmitAsync(agent, new(AgentTurnId.New(), "one"));
        await service.RunNextAsync(agent);
        await fixture.Store.AcknowledgeAsync(agent, 1);
        await Assert.ThrowsAsync<AgentConflictException>(() => fixture.Store.AcknowledgeAsync(agent, 0));
        await Assert.ThrowsAsync<AgentConflictException>(() => fixture.Store.AcknowledgeAsync(agent, 2));
    }

    [Fact]
    public void CorruptedDatabaseIsRejected()
    {
        var path = Fixture.NewPath();
        File.WriteAllText(path, "not a sqlite database");
        Assert.Throws<AgentStoreException>(() => new SqliteAgentStore(path));
        Fixture.Cleanup(path);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        public Fixture()
        {
            Path = NewPath();
            Store = new(Path);
        }
        public string Path { get; }
        public SqliteAgentStore Store { get; }
        public StewardAgentService Service(
            IAgentRuntime? runtime = null,
            RecordingDispatcher? dispatcher = null,
            Guid? ownerId = null) =>
            new(Store, runtime ?? new DeterministicAgentRuntime(), dispatcher ?? new RecordingDispatcher(),
                ownerId: ownerId);
        public async ValueTask DisposeAsync()
        {
            await Store.DisposeAsync();
            Cleanup(Path);
        }
        public static string NewPath() =>
            System.IO.Path.Combine(AppContext.BaseDirectory, $"agent-{Guid.NewGuid():N}.db");
        public static void Cleanup(string path)
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
                if (File.Exists(path + suffix)) File.Delete(path + suffix);
        }
    }

    private sealed class RecordingDispatcher : IAgentTaskDispatcher
    {
        public List<AgentTaskIntent> Intents { get; } = [];
        public List<ManagedAgentExecution> Cancellations { get; } = [];
        public List<(ManagedAgentExecution Execution, AgentTerminalReport Report)> Reports { get; } = [];
        public bool AcceptDispatch { get; set; } = true;
        public ManagedExecutionFact ReconcileFact { get; set; } = ManagedExecutionFact.Present;
        public Task<ManagedAgentExecution?> DispatchAsync(AgentTaskIntent intent, CancellationToken cancellationToken)
        {
            Intents.Add(intent);
            return Task.FromResult<ManagedAgentExecution?>(AcceptDispatch ? CreateExecution(intent) : null);
        }
        public Task<ManagedExecutionStatus> ReconcileAsync(
            WorkloadId workloadId, TaskId taskId, ManagedAgentExecution? execution,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ManagedExecutionStatus(ReconcileFact, execution));
        public Task<bool> ReportTerminalAsync(
            ManagedAgentExecution execution, AgentTerminalReport report, CancellationToken cancellationToken)
        {
            if (Reports.Any(x => x.Execution.LeaseId == execution.LeaseId))
                return Task.FromResult(false);
            Reports.Add((execution, report));
            return Task.FromResult(true);
        }
        public Task CancelAsync(ManagedAgentExecution execution, CancellationToken cancellationToken)
        {
            Cancellations.Add(execution);
            return Task.CompletedTask;
        }
        public ManagedAgentExecution CreateExecution(AgentTaskIntent intent) =>
            new(Guid.NewGuid(), intent.WorkloadId, intent.TaskId, TaskAttemptId.New(), 1,
                HostId.New(), NodeIncarnationId.New(), DateTimeOffset.UtcNow);
        public ManagedAgentExecution CreateExecution(AgentTurnRecord turn) =>
            new(Guid.NewGuid(), turn.WorkloadId!.Value, turn.TaskId!.Value, TaskAttemptId.New(), 1,
                HostId.New(), NodeIncarnationId.New(), DateTimeOffset.UtcNow);
    }

    private sealed class BlockingRuntime(TaskCompletionSource gate) : IAgentRuntime
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public AgentRuntimeDescriptor Descriptor { get; } = new("blocking", "1");
        public async IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
            AgentRuntimeRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Started.SetResult();
            await gate.Task.WaitAsync(cancellationToken);
            yield return new AgentFinalResponse("done");
        }
    }

    private sealed class FailingRuntime : IAgentRuntime
    {
        public AgentRuntimeDescriptor Descriptor { get; } = new("blocking", "1");
        public async IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
            AgentRuntimeRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            throw new InvalidOperationException("runtime failed");
#pragma warning disable CS0162
            yield break;
#pragma warning restore CS0162
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
