using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using Azure.Core;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using System.Net.Http.Json;
using Steward.Application;
using Steward.Agents;
using Steward.Contracts;
using Steward.Control;
using Steward.Domain;
using Steward.Node;
using Steward.Node.Host;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;
using Steward.PortableState;
using Steward.Providers.Abstractions;
using Steward.Scheduling;
using Steward.Stack.Local;
using Steward.Tasks.Abstractions;
using Steward.Tasks.Agent;
using Steward.Transport;
using Steward.Workloads.Evals;
using Steward.Terminal.Abstractions;
using Steward.Terminal.Windows;

namespace Steward.Orchestration.Tests;

public sealed class OrchestrationTests
{
    [Fact]
    public async Task Production_composition_is_durable_by_default_and_fails_closed_when_enabled_without_identity()
    {
        var root = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "composition-validation", Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(root);
        try
        {
            var core = new ControlHostOrchestrationOptions().Validate(
                Path.Combine(root, "control.db"));
            Assert.True(core.Enabled);
            Assert.EndsWith(
                ".scheduler.db", core.SchedulerDatabasePath,
                StringComparison.Ordinal);
            Assert.EndsWith(
                ".rates.db", core.GlobalRateDatabasePath,
                StringComparison.Ordinal);
            var localConfiguration = new Dictionary<string, string?>
            {
                ["Steward:LocalStack:DataRoot"] = root,
                ["Steward:LocalStack:PortableStateRoot"] =
                    Path.Combine(root, "objects"),
                ["Steward:LocalStack:CredentialVaultRoot"] =
                    Path.Combine(root, "credentials")
            };
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton(new SqliteControlStore(Path.Combine(root, "control.db")));
            services.AddStewardLocalStack(
                new ConfigurationBuilder()
                    .AddInMemoryCollection(localConfiguration)
                    .Build());
            OrchestrationComposition.AddStewardOrchestration(
                services,
                new ConfigurationBuilder().AddInMemoryCollection().Build(),
                Path.Combine(root, "control.db"));
            await using (var provider = services.BuildServiceProvider())
            {
                Assert.IsType<SqliteSchedulerStateStore>(provider.GetRequiredService<ISchedulerStateStore>());
                Assert.IsType<SqliteGlobalRateStateStore>(provider.GetRequiredService<IGlobalRateStateStore>());
                Assert.IsType<SqlitePoolStateStore>(provider.GetRequiredService<IPoolStateStore>());
                Assert.Null(provider.GetService<ITransportCarrier>());
                Assert.IsType<LocalStackContentAddressedObjectStore>(
                    provider.GetRequiredService<Steward.PortableState.IPortableObjectStore>());
            }

            Assert.Throws<InvalidOperationException>(() =>
                new LocalStackOptions { TransportEnabled = true }.Validate());
            Assert.Throws<InvalidOperationException>(() => new NodeHostOptions
            {
                JournalPath = Path.Combine(root, "node.db")
            }.Validate());
            Assert.Throws<ArgumentException>(() =>
                new NodeExecutionOptions("relative-workspace").ValidateAndGetRoot());

            using var controlKey = ECDsa.Create();
            var controlKeyPath = Path.Combine(root, "control.pem");
            await File.WriteAllTextAsync(controlKeyPath, controlKey.ExportPkcs8PrivateKeyPem());
            var nodeOptions = new List<LocalNodeEndpointOptions>();
            var sessionIds = new List<Guid>();
            for (var index = 0; index < 3; index++)
            {
                using var nodeKey = ECDsa.Create();
                var nodeKeyPath = Path.Combine(root, $"node-{index}.pem");
                await File.WriteAllTextAsync(nodeKeyPath, nodeKey.ExportSubjectPublicKeyInfoPem());
                var sessionId = Guid.NewGuid();
                sessionIds.Add(sessionId);
                nodeOptions.Add(new()
                {
                    HostId = Steward.Domain.HostId.New().ToString(),
                    NodeIncarnationId = Steward.Domain.NodeIncarnationId.New().ToString(),
                    PoolId = Steward.Domain.PoolId.New().ToString(),
                    DialDirection = LocalDirectDialDirection.ControlDialsNode,
                    Endpoint = $"wss://node-{index}.example.invalid/steward",
                    SessionId = sessionId.ToString(),
                    PeerIdentity = $"node-{index}",
                    PeerPublicKeyPemPath = nodeKeyPath
                });
            }
            var enabled = new LocalStackOptions
            {
                DataRoot = root,
                PortableStateRoot = Path.Combine(root, "objects-2"),
                CredentialVaultRoot = Path.Combine(root, "credentials-2"),
                TransportEnabled = true,
                TransportIdentity = "control",
                TransportPrivateKeyPemPath = controlKeyPath,
                Nodes = nodeOptions
            }.Validate();
            Assert.Equal(3, enabled.Nodes.Count);
            Assert.Equal(
                sessionIds.ToArray(),
                enabled.Nodes.Select(node =>
                    node.Transport.Data
                        .Deserialize<LocalDirectTransportBinding>()!
                        .SessionId!.Value)
                    .ToArray());
            nodeOptions[2].HostId = nodeOptions[0].HostId;
            Assert.Throws<InvalidOperationException>(() => new LocalStackOptions
            {
                DataRoot = root,
                PortableStateRoot = Path.Combine(root, "objects-3"),
                CredentialVaultRoot = Path.Combine(root, "credentials-3"),
                TransportEnabled = true,
                TransportIdentity = "control",
                TransportPrivateKeyPemPath = controlKeyPath,
                Nodes = nodeOptions
            }.Validate());
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void DevBox_composition_accepts_renewable_credential_injection_without_fixed_token()
    {
        var keyName = "STEWARD_TEST_DEVBOX_HMAC_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(
            keyName, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        try
        {
            var credential = new RotatingTokenCredential();
            var registry = new LocalDevBoxProviderOptions
            {
                Enabled = true,
                Endpoint = "https://devcenter.example.invalid/",
                OperationHandleHmacKeyEnvironmentVariable = keyName
            }.CreateRegistry(credential);
            Assert.Contains("devbox", registry.AvailableProviders);
            var first = credential.GetToken(
                new(["https://devcenter.azure.com/.default"]), CancellationToken.None);
            var second = credential.GetToken(
                new(["https://devcenter.azure.com/.default"]), CancellationToken.None);
            Assert.NotEqual(first.Token, second.Token);
        }
        finally { Environment.SetEnvironmentVariable(keyName, null); }
    }

    [Fact]
    public async Task Managed_remote_agent_runtime_replays_remote_events_without_local_process()
        {
            var root = Path.Combine(
                AppContext.BaseDirectory, "agent-process", Guid.NewGuid().ToString("N"));
            var source = new FakeRemoteAgentSource();
            var runtime = new ManagedRemoteAgentRuntime(source, new(
                true, Path.Combine(Environment.SystemDirectory, "where.exe"), [], root,
                PoolId.New(), 1024 * 1024,
                TimeSpan.FromMilliseconds(10), ["git"], new Dictionary<string, string>
                {
                    ["sdk"] = "dotnet10"
                }));
            try
            {
                foreach (var text in new[] { "first", "second" })
                {
                    var agentId = StewardAgentId.New();
                    var turnId = AgentTurnId.New();
                    var execution = new ManagedAgentExecution(
                        Guid.NewGuid(), WorkloadId.New(), TaskId.New(), TaskAttemptId.New(),
                        1, HostId.New(), NodeIncarnationId.New(), DateTimeOffset.UtcNow);
                    var request = new AgentRuntimeRequest(
                        new(agentId, "process-jsonl", "1.0.0", false, "parent", 0, 0, 0, 0, false),
                        new(agentId, turnId, text, TextProvenance.User, null,
                            AgentTurnStatus.Running, 1, null, null, null, null,
                            execution.WorkloadId, execution.TaskId, execution),
                        execution, [], []);
                    var events = new List<AgentRuntimeEvent>();
                    await foreach (var item in runtime.ExecuteAsync(request, CancellationToken.None))
                        events.Add(item);
                    Assert.Contains(events, x => x is AgentActivity);
                    Assert.Equal($"fixture:{text}", Assert.IsType<AgentFinalResponse>(events.Last()).Text);
                }

                Assert.Equal(2, source.Reads);
            }
            finally
            {
                try { Directory.Delete(root, true); } catch (IOException) { }
            }
    }

    [Fact]
    public async Task Agent_turn_task_executes_configured_process_once_and_persists_final_before_terminal()
            {
                var root = Path.Combine(
                    AppContext.BaseDirectory, "agent-task-type", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(root);
                try
                {
                    var executable = Path.Combine(Environment.SystemDirectory, "where.exe");
                    var executor = new AgentFixtureExecutor();
                    var type = new AgentTurnTaskType(
                        executor, new AgentTurnStateStore(Path.Combine(root, "agent-state.db")),
                        executable, "process-jsonl/1.0");
                    var input = new AgentTurnTaskInput(
                        StewardAgentId.New(), AgentTurnId.New(), "remote-only", "User",
                        ["context"], ["git"], new Dictionary<string, string>(),
                        "process-jsonl/1.0", executable, ["dotnet"], 1024 * 1024);
                    var context = new TaskExecutionContext(
                        TaskAttemptId.New(), 1, root,
                        JsonSerializer.SerializeToElement(input, StewardJson.Options));
                    Assert.True(type.Validate(context.Input).IsValid);
                    var handle = await type.StartAsync(context, CancellationToken.None);
                    Assert.Equal(1, executor.Starts);
                    Assert.Contains("remote-only", await File.ReadAllTextAsync(executor.StandardInputPath!));
                    Assert.Equal(ExecutionState.Exited,
                        (await type.ObserveAsync(handle, CancellationToken.None)).State);
                    var outputs = await type.ReadOutputsAsync(handle, 0, 10, CancellationToken.None);
                    Assert.Single(outputs.Outputs, x => x is TaskRuntimeAgentFinal);
                    Assert.Contains(outputs.Outputs, x =>
                        x is TaskRuntimeAgentActivity activity && activity.Text == "wörking");
                    Assert.Equal(1, executor.Starts);
                }
                finally
                {
                    Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                    try { Directory.Delete(root, true); } catch (IOException) { }
                }
    }

    [Fact]
    public async Task Remote_agent_runtime_uses_node_fact_sequence_and_stops_on_terminal_without_final()
                {
                    var execution = new ManagedAgentExecution(
                        Guid.NewGuid(), WorkloadId.New(), TaskId.New(), TaskAttemptId.New(),
                        2, HostId.New(), NodeIncarnationId.New(), DateTimeOffset.UtcNow);
                    var request = new AgentRuntimeRequest(
                        new(StewardAgentId.New(), "remote", "1.0", false, null, 0, 0, 0, 0, false),
                        new(StewardAgentId.New(), AgentTurnId.New(), "turn", TextProvenance.User,
                            null, AgentTurnStatus.Running, 1, null, null, null, null,
                            execution.WorkloadId, execution.TaskId, execution),
                        execution, [], []);
                    var source = new SequencedRemoteSource();
                    var runtime = new ManagedRemoteAgentRuntime(source, new(
                        true, Path.Combine(Environment.SystemDirectory, "where.exe"), [],
                        Environment.CurrentDirectory, PoolId.New(), 1024,
                        TimeSpan.FromMilliseconds(1), [], new Dictionary<string, string>()));
                    var values = new List<AgentRuntimeEvent>();
                    await foreach (var item in runtime.ExecuteAsync(request, CancellationToken.None))
                        values.Add(item);
                    Assert.Equal(3, values.Count);
                    Assert.Equal([0L, 5L, 8L], source.Cursors);

                    var failed = new ManagedRemoteAgentRuntime(
                        new TerminalRemoteSource(TaskAttemptState.Failed), new(
                            true, Path.Combine(Environment.SystemDirectory, "where.exe"), [],
                            Environment.CurrentDirectory, PoolId.New(), 1024,
                            TimeSpan.FromMilliseconds(1), [], new Dictionary<string, string>()));
                    var exception = await Assert.ThrowsAsync<RemoteAgentExecutionException>(async () =>
                    {
                        await foreach (var _ in failed.ExecuteAsync(request, CancellationToken.None)) { }
                    });
                    Assert.Equal("agent-task-failed", exception.Code);
    }

    [Fact]
    public void Agent_turn_state_store_replays_identically_and_rejects_conflicting_sequence_after_restart()
                {
                    var root = Path.Combine(
                        AppContext.BaseDirectory, "agent-event-conflict", Guid.NewGuid().ToString("N"));
                    Directory.CreateDirectory(root);
                    try
                    {
                        var path = Path.Combine(root, "events.db");
                        var attempt = TaskAttemptId.New();
                        var first = new AgentTurnStateStore(path);
                        first.Append(attempt, 1, new(1, "activity", "same", null));
                        first.Append(attempt, 1, new(1, "activity", "same", null));
                        var restarted = new AgentTurnStateStore(path);
                        Assert.Single(restarted.Read(attempt, 1, 0));
                        Assert.Throws<InvalidDataException>(() =>
                            restarted.Append(attempt, 1, new(1, "activity", "different", null)));
                }
                finally
                {
                    Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                    try { Directory.Delete(root, true); } catch (IOException) { }
                }
    }

    [Fact]
    public async Task Agent_dispatch_resolves_exact_attempt_beyond_outbox_page_and_after_acknowledgement()
    {
        using var fixture = await Fixture.CreateAsync();
        var registrations = new ControlNodeRegistrationStore(fixture.Control);
        await registrations.RegisterAsync(new(
            fixture.Host.HostId, fixture.Incarnation, fixture.Host.PoolId,
            DirectTransport(46030), "node", "node.pem",
            new ResourceRequirements(8, 1024L * 1024 * 1024, 1024L * 1024 * 1024,
                processCount: 8, concurrencyUnits: 8),
            [], [], DateTimeOffset.UtcNow));
        await using (var connection = await fixture.Control.OpenConnectionAsync())
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
              WITH RECURSIVE values_to_insert(value) AS (
                SELECT 1 UNION ALL SELECT value + 1 FROM values_to_insert WHERE value < 1001)
              INSERT INTO aggregate_outbox(
                message_id,kind,idempotency_key,payload_hash,payload_json,created_at,available_at)
              SELECT printf('00000000-0000-0000-0000-%012d',value),'backlog',
                'backlog-' || value,'00','{}',$now,$now FROM values_to_insert;
              """;
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync();
        }
        var application = new ExecutableWorkloadApplicationService(
            fixture.Orchestrator, registrations,
            new WorkloadPlanFactoryRegistry([new AgentTurnWorkloadPlanFactory()]));
        var options = new ValidatedAgentExecutionOptions(
            true, Path.Combine(Environment.SystemDirectory, "where.exe"), [],
            Environment.CurrentDirectory, fixture.Host.PoolId, 1024 * 1024,
            TimeSpan.FromMilliseconds(10), [], new Dictionary<string, string>());
        var dispatcher = new OrchestrationAgentTaskDispatcher(
            application, fixture.Control, fixture.Orchestrator, options);
        var intent = new AgentTaskIntent(
            StewardAgentId.New(), AgentTurnId.New(), WorkloadId.New(), TaskId.New(),
            AgentCommandKind.CodingOperation, "remote", TextProvenance.User);

        var execution = Assert.IsType<ManagedAgentExecution>(
            await dispatcher.DispatchAsync(intent, CancellationToken.None));
        foreach (var item in await fixture.Control.ReadOutboxAsync(1000))
            await fixture.Control.AcknowledgeOutboxAsync(item.Sequence);

        var attempt = await fixture.Control.GetTaskAttemptByTaskGenerationAsync(
            execution.TaskId, execution.AttemptGeneration);
        Assert.Equal(execution.AttemptId, attempt!.Payload.TaskAttemptId);
        Assert.Equal(ManagedExecutionFact.Present,
            (await dispatcher.ReconcileAsync(
                execution.WorkloadId, execution.TaskId, execution, CancellationToken.None)).Fact);
    }

    [Fact]
    public async Task Evaluation_retry_after_fact_blocks_global_allocations_across_workloads()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory, "rate-feedback", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var now = DateTimeOffset.UtcNow;
            var rates = new GlobalRateAllocator(new InMemoryGlobalRateStateStore());
            await rates.ConfigureAsync("eval-provider", 10, 1, 0, now);
            var schedulerState = new InMemorySchedulerStateStore();
            var store = new SqliteControlStore(Path.Combine(root, "control.db"));
            var orchestrator = new ControlOrchestrator(
                store, new CompositeScheduler(schedulerState), schedulerState,
                new(new(100, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5),
                    1024 * 1024, 4)),
                rateAllocator: rates);
            await orchestrator.InitializeAsync();
            var incarnation = NodeIncarnationId.New();
            var feedback = new RateFeedbackFact(
                1, "eval-provider", now.AddMinutes(5));

            Assert.Equal(FactDisposition.Applied,
                await orchestrator.ApplyNodeFactAsync(
                    incarnation, 1, OrchestrationMessageKinds.RateFeedback, feedback));
            Assert.Equal(FactDisposition.Duplicate,
                await orchestrator.ApplyNodeFactAsync(
                    incarnation, 1, OrchestrationMessageKinds.RateFeedback, feedback));
            foreach (var workload in new[] { WorkloadId.New(), WorkloadId.New() })
            {
                Assert.Null(await rates.TryClaimAsync(
                    workload, TaskId.New(), 1, HostId.New(),
                    [new ExternalRateRequirement("eval-provider", 1)],
                    now.AddSeconds(1), TimeSpan.FromMinutes(1)));
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Agent_worker_isolates_ownership_conflict_and_processes_next_agent()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory, "agent-worker", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var store = new SqliteAgentStore(Path.Combine(root, "agents.db"));
            var runtime = new CancellationThenResponseAgentRuntime();
            var dispatcher = new WorkerAgentDispatcher();
            var firstOwner = new StewardAgentService(
                store, runtime, dispatcher, ownerId: Guid.NewGuid());
            var workerService = new StewardAgentService(
                store, runtime, dispatcher, ownerId: Guid.NewGuid());
            var conflicted = new StewardAgentId(Guid.Parse("00000000-0000-0000-0000-000000000001"));
            var cancelled = new StewardAgentId(Guid.Parse("00000000-0000-0000-0000-000000000002"));
            var executable = new StewardAgentId(Guid.Parse("00000000-0000-0000-0000-000000000003"));
            await firstOwner.CreateAsync(conflicted);
            await workerService.CreateAsync(cancelled);
            await workerService.CreateAsync(executable);
            var blocked = AgentTurnId.New();
            await firstOwner.SubmitAsync(conflicted, new(blocked, "blocked"));
            var cancelledTurn = AgentTurnId.New();
            await workerService.SubmitAsync(cancelled, new(cancelledTurn, "cancel"));
            var runnable = AgentTurnId.New();
            await workerService.SubmitAsync(executable, new(runnable, "runs"));
            var worker = new AgentTurnBackgroundWorker(
                store, workerService,
                new(true, Path.Combine(Environment.SystemDirectory, "where.exe"), [], root,
                    PoolId.New(), 1024, TimeSpan.FromMilliseconds(10), [],
                    new Dictionary<string, string>()),
                NullLogger<AgentTurnBackgroundWorker>.Instance);
            await worker.StartAsync(CancellationToken.None);
            try
            {
                await WaitUntilAsync(async () =>
                    (await store.GetTurnAsync(executable, runnable))?.Status ==
                    AgentTurnStatus.Responded);
                Assert.Equal(AgentTurnStatus.Cancelled,
                    (await store.GetTurnAsync(cancelled, cancelledTurn))!.Status);
            }
            finally { await worker.StopAsync(CancellationToken.None); }
            Assert.Equal(AgentTurnStatus.Queued,
                (await store.GetTurnAsync(conflicted, blocked))!.Status);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Dynamic_node_session_stops_when_disabled_and_restarts_once_when_reenabled()
    {
        using var fixture = await Fixture.CreateAsync();
        var registrations = new ControlNodeRegistrationStore(fixture.Control);
        var registration = new NodeEndpointRegistration(
            fixture.Host.HostId, fixture.Incarnation, fixture.Host.PoolId,
            LocalStackOptions.TransportBinding(new LocalDirectTransportBinding(
                LocalDirectDialDirection.ControlDialsNode,
                new Uri("ws://127.0.0.1:45123/steward/"))),
            "node", "node.pem", fixture.Host.Capacity,
            [], [], DateTimeOffset.UtcNow);
        await registrations.RegisterAsync(registration);
        var carrierFactory = new TrackingControlCarrierFactory();
        var options = new ValidatedLocalStackOptions(
            Environment.CurrentDirectory,
            Environment.CurrentDirectory,
            Environment.CurrentDirectory,
            true,
            "control",
            "control.pem",
            [registration],
            256 * 1024,
            256);
        var worker = new LocalControlSessionWorker(
            options, carrierFactory, registrations, fixture.Orchestrator,
            new ControlTerminalRouter(), new ControlTerminalRevocationStore(fixture.Control),
            new DirectSessionControlIdentityHandler(
                new LocalControlIdentityGrantCatalog(
                    new DpapiProtectedIdentityVault(
                        Path.Combine(fixture.RootPath, "credentials")),
                    new LocalIdentityGrantStore(
                        Path.Combine(fixture.RootPath, "identity.db")))),
            [],
            NullLogger<LocalControlSessionWorker>.Instance);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => Task.FromResult(carrierFactory.Connects == 1));
            await registrations.RegisterAsync(registration with
            {
                Enabled = false,
                ObservedAt = DateTimeOffset.UtcNow
            });
            await WaitUntilAsync(() => Task.FromResult(carrierFactory.Disposals == 1));
            await registrations.RegisterAsync(registration with
            {
                Enabled = true,
                ObservedAt = DateTimeOffset.UtcNow
            });
            await WaitUntilAsync(() => Task.FromResult(carrierFactory.Connects == 2));
            await Task.Delay(250);
            Assert.Equal(2, carrierFactory.Connects);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
        Assert.Equal(2, carrierFactory.Disposals);
    }

    [Fact]
    public void Mutation_token_rejects_permissive_existing_file_and_generated_file_is_private()
        {
            var root = Path.Combine(
                AppContext.BaseDirectory, "token-acl", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            try
            {
                var generated = Path.Combine(root, "generated.token");
                _ = new LocalMutationSecurity(generated);
                if (OperatingSystem.IsWindows())
                {
                    Assert.True(new FileInfo(generated).GetAccessControl().AreAccessRulesProtected);
                    var permissive = Path.Combine(root, "permissive.token");
                    File.WriteAllText(permissive, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
                    var acl = new FileInfo(permissive).GetAccessControl();
                    acl.SetAccessRuleProtection(true, false);
                    acl.AddAccessRule(new(
                        new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                        FileSystemRights.ReadData, AccessControlType.Allow));
                    new FileInfo(permissive).SetAccessControl(acl);
                    Assert.Throws<InvalidDataException>(() => new LocalMutationSecurity(permissive));
                }
                else
                {
                    var mode = File.GetUnixFileMode(generated);
                    Assert.Equal(0, (int)(mode & (UnixFileMode.GroupRead | UnixFileMode.OtherRead)));
                }
            }
            finally
            {
                try { Directory.Delete(root, true); } catch (IOException) { }
            }
    }

    [Fact]
    public async Task Production_evaluation_store_survives_recreation_and_commits_results_idempotently()
    {
        var root = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "evaluation-store", Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "eval.db");
        try
        {
            var attempt = TaskAttemptId.New();
            var state = new EvaluationRunnerState(
                attempt, 1, new string('a', 64), 12, [],
                ImmutableArray<DurableRunnerEvent>.Empty, null, null, null, null);
            var first = new SqliteEvaluationStore(path);
            await first.SaveAsync(state, default);
            var result = new EvaluationCaseResult(
                "case", 1, "1.0", new string('b', 40), "sha256:" + new string('c', 64),
                "model", EvaluationCaseStatus.Passed, 1, new Dictionary<string, decimal>(),
                [], EvaluationFailureClassification.None, new string('d', 64));
            var taskId = TaskId.New();
            await first.RecordTaskResultAsync(taskId, result);

            var restarted = new SqliteEvaluationStore(path);
            var loadedState = await restarted.LoadAsync(attempt, 1, default);
            Assert.Equal(state.DefinitionHash, loadedState!.DefinitionHash);
            Assert.Equal(state.StdoutOffset, loadedState.StdoutOffset);
            var loadedResult = Assert.Single(await restarted.ReadTaskResultsAsync(taskId, default));
            Assert.Equal(result.CaseId, loadedResult.CaseId);
            Assert.Equal(result.ReceiptHash, loadedResult.ReceiptHash);
            await restarted.RecordTaskResultAsync(taskId, result);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task Application_submission_shards_300_tasks_across_three_routed_node_pumps()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory, "three-node-application", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var schedulerStore = new SqliteSchedulerStateStore(Path.Combine(root, "scheduler.db"));
        try
        {
            var controlStore = new SqliteControlStore(Path.Combine(root, "control.db"));
            var orchestrator = new ControlOrchestrator(
                controlStore, new CompositeScheduler(schedulerStore), schedulerStore,
                new(new(100, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5),
                    1024 * 1024, 100)));
            await orchestrator.InitializeAsync();
            var registrations = new ControlNodeRegistrationStore(controlStore);
            var pool = PoolId.New();
            var endpoints = Enumerable.Range(0, 3).Select(index =>
                new NodeEndpointRegistration(
                    HostId.New(), NodeIncarnationId.New(), pool,
                    DirectTransport(46000 + index),
                    $"node-{index}", $"keys/node-{index}.pem",
                    new ResourceRequirements(100, 10_000, 10_000, processCount: 100, concurrencyUnits: 100),
                    [], [], DateTimeOffset.UtcNow)).ToArray();
            foreach (var endpoint in endpoints) await registrations.RegisterAsync(endpoint);
            var application = new ExecutableWorkloadApplicationService(
                orchestrator, registrations,
                new WorkloadPlanFactoryRegistry([new SyntheticPlanFactory(300)]));
            var submitted = await application.SubmitAsync(new(
                "synthetic-300", JsonSerializer.SerializeToElement(new { }),
                pool, "synthetic-300"));
            Assert.Equal(300, submitted.Payload.TaskIds.Count);

            var nodes = new List<(NodeJournal Journal, NodeCommandProcessor Processor, LeanTaskType Type)>();
            var sessions = new List<(Task Control, Task Node)>();
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(120));
            foreach (var endpoint in endpoints)
            {
                var journal = new NodeJournal(Path.Combine(root, $"node-{endpoint.HostId}.db"));
                await journal.InitializeAsync(endpoint.NodeIncarnationId, Guid.NewGuid());
                var type = new LeanTaskType();
                var processor = new NodeCommandProcessor(
                    journal, new TaskTypeRegistry([type]),
                    new(Path.Combine(root, "workspaces")), observationInterval: TimeSpan.FromMilliseconds(1));
                nodes.Add((journal, processor, type));
                sessions.Add(await ConnectAsync(
                    orchestrator, endpoint, journal, processor, cancellation.Token));
            }

            await WaitUntilAsync(async () =>
                (await controlStore.GetWorkloadAsync(submitted.Payload.WorkloadId))?.Payload.ObservedState ==
                WorkloadObservedState.Succeeded, TimeSpan.FromSeconds(110));
            cancellation.Cancel();
            foreach (var session in sessions)
            {
                await IgnoreCancellationAsync(session.Control);
                await IgnoreCancellationAsync(session.Node);
            }
            foreach (var node in nodes)
            {
                await node.Processor.WaitForAttemptsAsync().WaitAsync(TimeSpan.FromSeconds(5));
                await node.Processor.DisposeAsync();
                await node.Journal.DisposeAsync();
            }
            Assert.Equal(300, nodes.Sum(x => x.Type.Started.Count));
            Assert.All(nodes, x => Assert.Equal(100, x.Type.Started.Count));
            Assert.Equal(300, nodes.SelectMany(x => x.Type.Started).Distinct().Count());
        }
        finally
        {
            await schedulerStore.DisposeAsync();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Task_bound_identity_is_resolved_at_execution_and_secret_is_never_serialized()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory, "identity-delivery", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var schedulerStore = new InMemorySchedulerStateStore();
        const string secret = "secret-token-that-must-not-be-persisted";
        try
        {
            var controlStore = new SqliteControlStore(Path.Combine(root, "control.db"));
            var host = HostId.New();
            var incarnation = NodeIncarnationId.New();
            var pool = PoolId.New();
            var grantId = IdentityGrantId.New();
            var taskId = TaskId.New();
            var workloadId = WorkloadId.New();
            var planId = PlanRevisionId.New();
            var catalog = new FakeIdentityCatalog(grantId, workloadId, taskId, host, incarnation);
            var orchestrator = new ControlOrchestrator(
                controlStore, new CompositeScheduler(schedulerStore), schedulerStore,
                new(new(10, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5), 1024 * 1024, 1),
                    IdentityGrantDispatchEnabled: true),
                identityGrants: catalog);
            await orchestrator.InitializeAsync();
            var plan = new WorkloadPlan(
                workloadId, planId, WorkloadPlan.CurrentSchemaVersion, "identity-test", "1.0",
                [new(taskId, "task", "identity-aware", "1.0", new ResourceRequirements(1),
                    TaskInput.Empty, [], new HashSet<string>(), null, null, host, 0,
                    InterruptionClass.Restartable, [], "result", [grantId])]);
            await orchestrator.RegisterAndScheduleAsync(
                plan,
                [new(host, incarnation, pool, new ResourceRequirements(1), [], [], DateTimeOffset.UtcNow)],
                pool, DateTimeOffset.UtcNow);

            await using var journal = new NodeJournal(Path.Combine(root, "node.db"));
            await journal.InitializeAsync(incarnation, Guid.NewGuid());
            var type = new IdentityAwareTaskType();
            var resolver = new FakeIdentityResolver(secret);
            await using var processor = new NodeCommandProcessor(
                journal, new TaskTypeRegistry([type]), new(Path.Combine(root, "workspaces")),
                identityResolver: resolver);
            var endpoint = new NodeEndpointRegistration(
                host, incarnation, pool, DirectTransport(46010),
                "node", "node.pem",
                new ResourceRequirements(1), [], [], DateTimeOffset.UtcNow);
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var session = await ConnectAsync(orchestrator, endpoint, journal, processor, cancellation.Token);
            await WaitUntilAsync(async () =>
                (await controlStore.GetWorkloadAsync(workloadId))?.Payload.ObservedState ==
                WorkloadObservedState.Succeeded);
            cancellation.Cancel();
            await IgnoreCancellationAsync(session.Control);
            await IgnoreCancellationAsync(session.Node);
            Assert.Equal(1, type.IdentityHandleCount);
            Assert.Equal(1, resolver.ResolveCount);
            Assert.False(await ContainsTextAsync(controlStore.DatabasePath, secret));
            Assert.False(await ContainsTextAsync(Path.Combine(root, "node.db"), secret));
            if (File.Exists($"{controlStore.DatabasePath}-wal"))
                Assert.False(await ContainsTextAsync($"{controlStore.DatabasePath}-wal", secret));
            if (File.Exists(Path.Combine(root, "node.db-wal")))
                Assert.False(await ContainsTextAsync(Path.Combine(root, "node.db-wal"), secret));
        }
        finally
        {
            await schedulerStore.DisposeAsync();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Pool_application_enforces_maximum_and_blocks_destructive_active_host_action()
        {
            var root = Path.Combine(
                AppContext.BaseDirectory, "pool-application", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var schedulerStore = new InMemorySchedulerStateStore();
            try
            {
                var controlStore = new SqliteControlStore(Path.Combine(root, "control.db"));
                var orchestrator = new ControlOrchestrator(
                    controlStore, new CompositeScheduler(schedulerStore), schedulerStore,
                    new(new(10, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5), 1024 * 1024, 2)));
                await orchestrator.InitializeAsync();
                var poolStore = new SqlitePoolStateStore(Path.Combine(root, "pools.db"));
                var coordinator = new PoolCoordinator(poolStore);
                var provider = new FakeHostProvider();
                var nodeStore = new ControlNodeRegistrationStore(controlStore);
                var enrollment = new FakeEnrollmentWorkflow();
                var service = new HostPoolApplicationService(
                    controlStore, poolStore, coordinator,
                    new HostProviderRegistry([
                        new KeyValuePair<string, IHostProvider>("fake", provider)
                    ]),
                    nodeStore, enrollment: enrollment);
                var pool = PoolId.New();
                await service.RegisterPoolAsync(new(
                    new(pool, 0, 2, TimeSpan.FromMinutes(1)),
                    new("fake", "project", "pool")));
                var reconciliation = await service.ReconcileAsync(
                    pool, [new("a"), new("b"), new("c")], DateTimeOffset.UtcNow);
                Assert.Equal(2, reconciliation.Members.Count);
                Assert.Equal(2, provider.Created);
                Assert.Equal(2, enrollment.Enrolled);
                Assert.Equal(2, (await nodeStore.ListAsync()).Count);

                var member = reconciliation.Members[0];
                var plan = new WorkloadPlan(
                    WorkloadId.New(), PlanRevisionId.New(), WorkloadPlan.CurrentSchemaVersion,
                    "test", "1.0",
                    [new(TaskId.New(), "active", "lean", "1.0", new ResourceRequirements(1),
                        TaskInput.Empty, [], new HashSet<string>(), null, null, member.HostId, 0,
                        InterruptionClass.NonInterruptible, [], "result")]);
                await orchestrator.RegisterAndScheduleAsync(
                    plan, [(await nodeStore.ListAsync()).Single(x => x.HostId == member.HostId).ToSnapshot()],
                    pool, DateTimeOffset.UtcNow);
                var blocked = await Assert.ThrowsAsync<ApplicationContractException>(
                    () => service.StopAsync(member.HostId, force: false));
                Assert.Equal(ProblemCodes.LifecycleBlockedByActiveWork, blocked.Code);
        }
        finally
        {
            await schedulerStore.DisposeAsync();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Pool_provider_handles_resume_after_control_restart_without_duplicate_create()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "pool-provider-restart",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var controlStore = new SqliteControlStore(
                Path.Combine(root, "control.db"));
            await using var schedulerStore =
                new InMemorySchedulerStateStore();
            var orchestrator = new ControlOrchestrator(
                controlStore,
                new CompositeScheduler(schedulerStore),
                schedulerStore,
                new(new(
                    10,
                    TimeSpan.FromHours(1),
                    TimeSpan.FromMinutes(5),
                    1024 * 1024,
                    2)));
            await orchestrator.InitializeAsync();
            var poolStore = new SqlitePoolStateStore(
                Path.Combine(root, "pools.db"));
            var provider = new FakeHostProvider
            {
                DelayCreates = true
            };
            var nodeStore = new ControlNodeRegistrationStore(controlStore);
            var enrollment = new FakeEnrollmentWorkflow();
            var pool = PoolId.New();
            var registration = new PoolRegistration(
                new(pool, 0, 2, TimeSpan.FromMinutes(90)),
                new("fake", "project", "pool"));

            var first = new HostPoolApplicationService(
                controlStore,
                poolStore,
                new PoolCoordinator(poolStore),
                new HostProviderRegistry([
                    new KeyValuePair<string, IHostProvider>(
                        "fake",
                        provider)
                ]),
                nodeStore,
                enrollment: enrollment);
            await first.RegisterPoolAsync(registration);
            _ = await first.ReconcileAsync(
                pool,
                [new("a"), new("b")],
                DateTimeOffset.UtcNow);
            Assert.Equal(2, provider.Created);
            Assert.Equal(0, enrollment.Enrolled);

            await using (var connection =
                         await controlStore.OpenConnectionAsync())
            {
                await using var count = connection.CreateCommand();
                count.CommandText = """
                    SELECT COUNT(*)
                    FROM orchestration_provider_operations;
                    """;
                Assert.Equal(
                    2L,
                    Convert.ToInt64(await count.ExecuteScalarAsync()));
            }

            provider.CompleteCreates = true;
            var restarted = new HostPoolApplicationService(
                controlStore,
                poolStore,
                new PoolCoordinator(poolStore),
                new HostProviderRegistry([
                    new KeyValuePair<string, IHostProvider>(
                        "fake",
                        provider)
                ]),
                nodeStore,
                enrollment: enrollment);
            _ = await restarted.ReconcileAsync(
                pool,
                [new("a"), new("b")],
                DateTimeOffset.UtcNow.AddMinutes(1));

            Assert.Equal(2, provider.Created);
            Assert.Equal(2, provider.Reconciled);
            Assert.Equal(2, enrollment.Enrolled);
            Assert.Equal(2, (await nodeStore.ListAsync()).Count);
            await using (var connection =
                         await controlStore.OpenConnectionAsync())
            {
                await using var count = connection.CreateCommand();
                count.CommandText = """
                    SELECT COUNT(*)
                    FROM orchestration_provider_operations;
                    """;
                Assert.Equal(
                    0L,
                    Convert.ToInt64(await count.ExecuteScalarAsync()));
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); }
            catch (IOException) { }
        }
    }

    [Fact]
    public async Task General_process_application_submission_creates_attempt_and_completes_through_node()
        {
            using var fixture = await Fixture.CreateAsync();
            var registrations = new ControlNodeRegistrationStore(fixture.Control);
            await registrations.RegisterAsync(new(
                fixture.Host.HostId, fixture.Incarnation, fixture.Host.PoolId,
                DirectTransport(46031), "node", "node.pem",
                fixture.Host.Capacity,
                [], [], DateTimeOffset.UtcNow));
            var application = new ExecutableWorkloadApplicationService(
                fixture.Orchestrator, registrations,
                new WorkloadPlanFactoryRegistry([
                    new GeneralTaskWorkloadPlanFactory("process", compose: false)
                ]));
            var input = new GeneralTaskWorkloadInput(JsonSerializer.SerializeToElement(
                new Steward.Tasks.Process.ProcessTaskDefinition(
                    Path.Combine(Environment.SystemDirectory, "where.exe"), ["dotnet"])),
                new ResourceRequirements(1, 1, 1, processCount: 1, concurrencyUnits: 1));
            var workload = await application.SubmitAsync(new(
                "process", JsonSerializer.SerializeToElement(input, StewardJson.Options),
                fixture.Host.PoolId, "process-http-shared-handler"));
            Assert.Single(workload.Payload.TaskIds);
            Assert.NotEmpty(await fixture.Control.ReadOutboxAsync());

            await using var journal = await fixture.OpenNodeAsync();
            await using var processor = fixture.CreateNodeProcessor(journal, new LeanTaskType("process"));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var session = await fixture.ConnectAsync(journal, processor, cancellation.Token);
            await WaitUntilAsync(async () =>
                (await fixture.Control.GetWorkloadAsync(workload.Payload.WorkloadId))?.Payload.ObservedState ==
                WorkloadObservedState.Succeeded);
            cancellation.Cancel();
            await IgnoreCancellationAsync(session.Control);
            await IgnoreCancellationAsync(session.Node);
            Assert.NotNull(await fixture.Control.GetTaskAsync(workload.Payload.TaskIds[0]));
    }

    [Fact]
    public void General_process_workload_normalizes_integral_exponent_values()
    {
        var executable = JsonSerializer.Serialize(
            Path.Combine(Environment.SystemDirectory, "where.exe"));
        using var input = JsonDocument.Parse(
            "{\"definition\":{\"executable\":" + executable +
            ",\"maxOutputBytes\":1048576,\"requiredDiskReserveBytes\":0}}");
        var plan = new GeneralTaskWorkloadPlanFactory(
            "process",
            compose: false).Create(
                WorkloadId.New(),
                PlanRevisionId.New(),
                input.RootElement);
        var definition = plan.Tasks.Single().Input.CanonicalJson;
        Assert.Contains("\"maxOutputBytes\":1.048576e6", definition);
        Assert.Equal(
            1_048_576,
            JsonSerializer.Deserialize<Steward.Tasks.Process.ProcessTaskDefinition>(
                definition,
                CanonicalTaskJson.CreateOptions())!.MaxOutputBytes);
    }

    [Fact]
    public async Task Terminal_roundtrip_routes_only_selected_host_and_replays_output_cursor()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = await Fixture.CreateAsync();
        var workspace = Path.Combine(
            AppContext.BaseDirectory, "terminal-route", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workspace);
        try
        {
            var router = new ControlTerminalRouter();
            var terminalJournal = new TerminalJournal(Path.Combine(workspace, "terminal.db"));
            var terminalRevocations = new DurableTerminalRevocationStore(
                Path.Combine(workspace, "terminal-revocations.db"));
            await using var terminal = new TerminalSessionService(
                terminalJournal, fixture.Host.HostId, fixture.Incarnation,
                fixture.BootId.ToString("D"),
                currentRevocationRevision: () => terminalRevocations.CurrentRevision);
            await using var nodeJournal = await fixture.OpenNodeAsync();
            await using var processor = new NodeCommandProcessor(
                nodeJournal, new TaskTypeRegistry([new LeanTaskType()]),
                new NodeExecutionOptions(Path.Combine(workspace, "tasks")),
                terminal: new NodeTerminalCommandProcessor(terminal, terminalRevocations));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var session = await ConnectTerminalAsync(
                fixture.Orchestrator, fixture.Host, nodeJournal, processor, router, cancellation.Token);
            var registrations = new ControlNodeRegistrationStore(fixture.Control);
            await registrations.RegisterAsync(new(
                fixture.Host.HostId, fixture.Incarnation, fixture.Host.PoolId,
                DirectTransport(46032), "node", "node.pem",
                fixture.Host.Capacity,
                ["terminal.elevated-service"], [], DateTimeOffset.UtcNow));
            var app = new TerminalApplicationService(
                fixture.Control, router, new ControlTerminalRevocationStore(fixture.Control), registrations,
                new(new HashSet<string> { "test-user" },
                    new HashSet<HostId> { fixture.Host.HostId }, [workspace],
                    new HashSet<string> { "test-user" },
                    new HashSet<HostId> { fixture.Host.HostId },
                    TimeSpan.FromMinutes(10), 1024 * 1024, 4 * 1024 * 1024),
                new TestActor("test-user"));
            await Assert.ThrowsAsync<ApplicationContractException>(() => app.IssueAsync(new(
                HostId.New(), fixture.Incarnation, "forged", workspace, null,
                TimeSpan.FromMinutes(5))));
            await Assert.ThrowsAsync<ApplicationContractException>(() => app.IssueAsync(new(
                fixture.Host.HostId, fixture.Incarnation, "forged",
                Path.GetPathRoot(workspace)!, null, TimeSpan.FromMinutes(5))));
            var elevated = await app.IssueAsync(new(
                fixture.Host.HostId, fixture.Incarnation, "ignored-body-actor", workspace, null,
                TimeSpan.FromMinutes(5), ElevationRequested: true,
                MaximumInputBytes: 1024 * 1024, MaximumOutputBytes: 4 * 1024 * 1024));
            Assert.True(elevated.ElevationGranted);
            var authority = await app.IssueAsync(new(
                fixture.Host.HostId, fixture.Incarnation, "test-user", workspace, null,
                TimeSpan.FromMinutes(5), MaximumInputBytes: 1024 * 1024,
                MaximumOutputBytes: 4 * 1024 * 1024));
            var shell = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            var marker = "steward-terminal-" + Guid.NewGuid().ToString("N");
            var opened = await app.OpenAsync(new(
                TerminalContractLimits.SchemaVersion, "open-1", authority,
                TerminalShellKind.CommandPrompt, shell, ["/D", "/Q", "/K", $"title {marker}"],
                workspace, 80, 25), cancellation.Token);
            _ = opened;
            TerminalSessionSnapshot snapshot;
            do
            {
                var current = await app.GetAsync(authority.SessionId, cancellation.Token);
                snapshot = TerminalWireCodec.FromElement<TerminalSessionSnapshot>(
                    current.Snapshot!.Value)!;
                if (snapshot.State != TerminalSessionState.Open) await Task.Delay(25);
            } while (snapshot.State != TerminalSessionState.Open);
            var input = Encoding.UTF8.GetBytes("echo managed-input\r\n");
            TerminalWireResponse? afterInput = null;
            for (var attempt = 0; attempt < 20 && afterInput is null; attempt++)
            {
                try
                {
                    afterInput = await app.InputAsync(authority.SessionId, new(
                        authority.SessionId, default!, "input-1",
                        snapshot.Revision, input), cancellation.Token);
                }
                catch (ApplicationContractException exception)
                    when (exception.Message.Contains(
                        "revision does not match",
                        StringComparison.Ordinal))
                {
                    var current = await app.GetAsync(
                        authority.SessionId,
                        cancellation.Token);
                    snapshot = TerminalWireCodec.FromElement<
                        TerminalSessionSnapshot>(current.Snapshot!.Value)!;
                }
            }
            Assert.NotNull(afterInput);
            var inputSnapshot = TerminalWireCodec.FromElement<TerminalSessionSnapshot>(afterInput.Snapshot!.Value)!;
            TerminalWireResponse output;
            do
            {
                output = await app.OutputAsync(authority.SessionId, new(
                    authority.SessionId, default!, 0, 0, 100,
                    TerminalContractLimits.MaximumOutputReadBytes, false), cancellation.Token);
                if (!output.Output!.Any(x => Encoding.UTF8.GetString(x.Data.Span)
                        .Contains(marker, StringComparison.Ordinal)))
                    await Task.Delay(25);
            } while (!output.Output!.Any(x => Encoding.UTF8.GetString(x.Data.Span)
                         .Contains(marker, StringComparison.Ordinal)));
            var cursor = output.Output!.Max(x => x.Sequence);
            var replay = await app.OutputAsync(authority.SessionId, new(
                authority.SessionId, default!, cursor, output.Output!.Last().Offset +
                output.Output!.Last().Length, 100, TerminalContractLimits.MaximumOutputReadBytes, false),
                cancellation.Token);
            Assert.All(replay.Output!, x =>
            {
                Assert.True(x.EndOfStream);
                Assert.Equal(0, x.Length);
            });
            cancellation.Cancel();
            await IgnoreCancellationAsync(session.Control);
            await IgnoreCancellationAsync(session.Node);
            await app.RevokeAsync(authority.SessionId);
            using var reconnectCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var reconnected = await ConnectTerminalAsync(
                fixture.Orchestrator, fixture.Host, nodeJournal, processor, router,
                reconnectCancellation.Token);
            await Task.Delay(250);
            var revokedGet = await Assert.ThrowsAsync<TerminalException>(() =>
                terminal.GetAsync(
                    authority.SessionId,
                    new(authority.HostId, authority.NodeIncarnationId, authority.Actor, 1)).AsTask());
            Assert.Equal(TerminalProblemCode.AuthorityRevoked, revokedGet.Problem.Code);
            await Assert.ThrowsAsync<TerminalException>(() =>
                terminal.WriteInputAsync(new(
                    authority.SessionId,
                    new(authority.HostId, authority.NodeIncarnationId, authority.Actor, 1),
                    "denied-after-revoke", inputSnapshot.Revision, "echo denied\r\n"u8.ToArray())).AsTask());
            reconnectCancellation.Cancel();
            await IgnoreCancellationAsync(reconnected.Control);
            await IgnoreCancellationAsync(reconnected.Node);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                router.SendAsync(HostId.New(), "get",
                    new TerminalGetCommand(authority.SessionId, default!), CancellationToken.None));
        }
        finally
        {
            try { Directory.Delete(workspace, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Http_submission_uses_shared_handler_and_completes_through_node_pump()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory, "http-application", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var tokenPath = Path.Combine(root, "control.session");
            await using var factory = new WebApplicationFactory<OrchestrationDoctorService>()
                .WithWebHostBuilder(builder =>
                {
                    builder.UseSetting("Control:DatabasePath", Path.Combine(root, "control.db"));
                    builder.UseSetting("Control:LocalSessionTokenPath", tokenPath);
                    builder.UseSetting(
                        "Control:Orchestration:WorkspaceRoot", Path.Combine(root, "workspaces"));
                    builder.UseSetting(
                        "Control:Orchestration:SchedulerDatabasePath", Path.Combine(root, "scheduler.db"));
                    builder.UseSetting(
                        "Control:Orchestration:GlobalRateDatabasePath", Path.Combine(root, "rates.db"));
                });
            using var client = factory.CreateClient();
            using (var rejected = await client.PostAsJsonAsync("/nodes", new { }))
                Assert.Equal(System.Net.HttpStatusCode.Forbidden, rejected.StatusCode);
            client.DefaultRequestHeaders.Add(LocalMutationSecurity.HeaderName, new string('0', 64));
            using (var wrong = await client.PostAsJsonAsync("/nodes", new { }))
                Assert.Equal(System.Net.HttpStatusCode.Forbidden, wrong.StatusCode);
            client.DefaultRequestHeaders.Remove(LocalMutationSecurity.HeaderName);
            client.DefaultRequestHeaders.Add(
                LocalMutationSecurity.HeaderName, File.ReadAllText(tokenPath).Trim());
            using (var browser = new HttpRequestMessage(HttpMethod.Post, "/nodes")
            {
                Content = JsonContent.Create(new { })
            })
            {
                browser.Headers.Add("Origin", "https://attacker.example");
                using var rejectedOrigin = await client.SendAsync(browser);
                Assert.Equal(System.Net.HttpStatusCode.Forbidden, rejectedOrigin.StatusCode);
            }
            var host = HostId.New();
            var incarnation = NodeIncarnationId.New();
            var pool = PoolId.New();
            var endpoint = new NodeEndpointRegistration(
                host, incarnation, pool,
                LocalStackOptions.TransportBinding(new LocalDirectTransportBinding(
                    LocalDirectDialDirection.ControlDialsNode,
                    new Uri("ws://127.0.0.1:45124/steward/"))),
                "node", "node.pem",
                new ResourceRequirements(2, 1024, 1024, processCount: 2, concurrencyUnits: 2),
                [], [], DateTimeOffset.UtcNow);
            using (var registered = await client.PostAsJsonAsync("/nodes", new RegisterNodeRequest(
                       host.ToString(), incarnation.ToString(), pool.ToString(),
                       endpoint.Transport, endpoint.PeerIdentity,
                       endpoint.PeerPublicKeyReference,
                       endpoint.Capacity, [], [], endpoint.ObservedAt)))
                Assert.True(registered.IsSuccessStatusCode,
                    await registered.Content.ReadAsStringAsync());
            var input = new GeneralTaskWorkloadInput(
                JsonSerializer.SerializeToElement(new Steward.Tasks.Process.ProcessTaskDefinition(
                    Path.Combine(Environment.SystemDirectory, "where.exe"), ["dotnet"])),
                new ResourceRequirements(1, 1, 1, processCount: 1, concurrencyUnits: 1));
            var submit = new
            {
                kind = "process",
                input = JsonSerializer.SerializeToElement(input, StewardJson.Options),
                poolId = pool.ToString(),
                idempotencyKey = "http-process"
            };
            using var response = await client.PostAsJsonAsync("/workloads", submit);
            response.EnsureSuccessStatusCode();
            var workloadJson = await response.Content.ReadFromJsonAsync<JsonElement>();
            var workloadId = WorkloadId.Parse(workloadJson.GetProperty("payload")
                .GetProperty("workloadId").GetString()!);
            var beforeReplay = (await factory.Services.GetRequiredService<SqliteControlStore>()
                .ReadOutboxAsync()).Count;
            using var replay = await client.PostAsJsonAsync("/workloads", submit);
            replay.EnsureSuccessStatusCode();
            var replayed = await replay.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(workloadId, WorkloadId.Parse(replayed.GetProperty("payload")
                .GetProperty("workloadId").GetString()!));
            Assert.Equal(beforeReplay, (await factory.Services.GetRequiredService<SqliteControlStore>()
                .ReadOutboxAsync()).Count);
            using var changed = await client.PostAsJsonAsync("/workloads", new
            {
                kind = "process",
                input = JsonSerializer.SerializeToElement(input with
                {
                    RetryCap = 1
                }, StewardJson.Options),
                poolId = pool.ToString(),
                idempotencyKey = "http-process"
            });
            Assert.Equal(System.Net.HttpStatusCode.Conflict, changed.StatusCode);
            using var headerConflictRequest = new HttpRequestMessage(HttpMethod.Post, "/workloads")
            {
                Content = JsonContent.Create(submit)
            };
            headerConflictRequest.Headers.Add("Idempotency-Key", "different");
            using var headerConflict = await client.SendAsync(headerConflictRequest);
            Assert.Equal(System.Net.HttpStatusCode.BadRequest, headerConflict.StatusCode);
            using var agentResponse = await client.PostAsJsonAsync(
                "/agents", new CreateAgentRequest(ParentRoute: "parent"), StewardJson.Options);
            agentResponse.EnsureSuccessStatusCode();
            var agentJson = await agentResponse.Content.ReadFromJsonAsync<JsonElement>();
            var agentId = StewardAgentId.Parse(agentJson.GetProperty("agentId")
                .GetString()!);
            using var turnResponse = await client.PostAsJsonAsync(
                $"/agents/{agentId}/turns",
                new SubmitAgentTurnRequest("inspect workload"));
            Assert.Equal(System.Net.HttpStatusCode.Accepted, turnResponse.StatusCode);

            var orchestrator = factory.Services.GetRequiredService<ControlOrchestrator>();
            await using var journal = new NodeJournal(Path.Combine(root, "node.db"));
            await journal.InitializeAsync(incarnation, Guid.NewGuid());
            await using var processor = new NodeCommandProcessor(
                journal, new TaskTypeRegistry([new LeanTaskType("process")]),
                new(Path.Combine(root, "workspaces")));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var session = await ConnectAsync(orchestrator, endpoint, journal, processor, cancellation.Token);
            await WaitUntilAsync(async () =>
            {
                await ThrowIfFaultedAsync(session.Control, session.Node);
                using var status = await client.GetAsync($"/workloads/{workloadId}");
                if (!status.IsSuccessStatusCode) return false;
                var snapshot = await status.Content.ReadFromJsonAsync<JsonElement>();
                return snapshot.GetProperty("payload").GetProperty("observedState").GetInt32() ==
                    (int)WorkloadObservedState.Succeeded;
            });
            cancellation.Cancel();
            await IgnoreCancellationAsync(session.Control);
            await IgnoreCancellationAsync(session.Node);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    [Fact]
    public void Codec_uses_closed_discriminators_and_enforces_bounds()
    {
        Assert.Throws<OrchestrationMessageException>(() =>
            OrchestrationMessageCodec.Encode(new { arbitrary = true }, DateTimeOffset.UtcNow));
        var unknown = Encoding.UTF8.GetBytes(
            """{"schema":"steward.orchestration-message","version":"1.0","kind":"evil.clr","createdAt":"2026-01-01T00:00:00Z","payload":{}}""");
        Assert.Throws<OrchestrationMessageException>(() => OrchestrationMessageCodec.Decode(unknown));
        Assert.Throws<OrchestrationMessageException>(() =>
            OrchestrationMessageCodec.Encode(
                new TaskProgressFact(Identity(), .5, new string('x', OrchestrationMessageCodec.MaximumTextLength + 1)),
                DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task Three_task_dependency_survives_disconnect_and_node_restart_then_replays_once()
    {
        using var fixture = await Fixture.CreateAsync();
        var fake = new DeterministicTaskType(blockUntilReleased: true);
        var plan = Plan(3);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);

        await using (var nodeJournal = await fixture.OpenNodeAsync())
        {
            var node = fixture.CreateNodeProcessor(nodeJournal, fake);
            using var firstSession = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var running = await fixture.ConnectAsync(nodeJournal, node, firstSession.Token);
            await WaitUntilAsync(async () =>
            {
                await ThrowIfFaultedAsync(running.Control, running.Node);
                return (await fixture.Control.ReadOutboxAsync()).Count == 0 &&
                    (await nodeJournal.ReadFactsAfterAsync(0)).Count(x => x.FactType == OrchestrationMessageKinds.TaskRunning) == 2;
            });

            firstSession.Cancel();
            await IgnoreCancellationAsync(running.Control);
            await IgnoreCancellationAsync(running.Node);
            fake.Release();
            await node.WaitForAttemptsAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }

        await using (var restartedJournal = await fixture.OpenNodeAsync())
        {
            var restartedNode = fixture.CreateNodeProcessor(restartedJournal, fake);
            using var reconnect = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var running = await fixture.ConnectAsync(restartedJournal, restartedNode, reconnect.Token);
            await WaitUntilAsync(async () =>
                (await fixture.Control.GetWorkloadAsync(plan.WorkloadId))?.Payload.ObservedState ==
                WorkloadObservedState.Succeeded, TimeSpan.FromSeconds(10));
            reconnect.Cancel();
            await IgnoreCancellationAsync(running.Control);
            await IgnoreCancellationAsync(running.Node);
            await restartedNode.WaitForAttemptsAsync().WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(3, fake.StartCount);
            var workload = await fixture.Control.GetWorkloadAsync(plan.WorkloadId);
            Assert.Equal(WorkloadObservedState.Succeeded, workload!.Payload.ObservedState);
            foreach (var task in plan.Tasks)
                Assert.Equal(TaskObservedState.Succeeded,
                    (await fixture.Control.GetTaskAsync(task.TaskId))!.Payload.ObservedState);
            var notifications = await fixture.Control.ReadNotificationsAsync(
                $"workload:{plan.WorkloadId}", 0, 1000);
            Assert.Equal(3, notifications.Count(x => x.PayloadJson.Contains(
                OrchestrationMessageKinds.TaskTerminal, StringComparison.Ordinal)));

            var terminal = (await restartedJournal.ReadFactsAfterAsync(0, 1000))
                .First(x => x.FactType == OrchestrationMessageKinds.TaskTerminal);
            var decoded = OrchestrationMessageCodec.DecodeJournaledFact(terminal.FactType, terminal.PayloadJson);
            Assert.Equal(FactDisposition.Duplicate,
                await fixture.Orchestrator.ApplyNodeFactAsync(
                    fixture.Incarnation, terminal.Sequence, terminal.FactType, decoded));
            Assert.Equal(3, fake.StartCount);
        }
    }

    [Fact]
    public async Task Duplicate_execute_during_running_returns_persisted_started_outcome()
    {
        using var fixture = await Fixture.CreateAsync();
        var fake = new DeterministicTaskType(blockUntilReleased: true);
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        var messages = await fixture.Control.ReadOutboxAsync();
        var execute = (ExecuteTaskMessage)OrchestrationMessageCodec.Decode(
            Encoding.UTF8.GetBytes(messages.Single(x => x.Kind == OrchestrationMessageKinds.ExecuteTask).PayloadJson)).Value;
        Assert.Equal(execute.Identity.AttemptId.ToString(), execute.Workspace);
        Assert.False(Path.IsPathFullyQualified(execute.Workspace));

        await using var journal = await fixture.OpenNodeAsync();
        var node = fixture.CreateNodeProcessor(journal, fake);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var running = await fixture.ConnectAsync(journal, node, cancellation.Token);
        await WaitUntilAsync(async () => (await journal.ReadFactsAfterAsync(0))
            .Any(x => x.FactType == OrchestrationMessageKinds.TaskRunning));
        var duplicate = await journal.ReserveOrchestrationCommandAsync(execute.Command);
        Assert.False(duplicate.IsNew);
        Assert.Equal("started", duplicate.Outcome.Status);
        Assert.Equal(1, fake.StartCount);
        Assert.DoesNotContain(await journal.ReadFactsAfterAsync(0),
            x => x.FactType == OrchestrationMessageKinds.TaskRecovery);
        fake.Release();
        await node.WaitForAttemptsAsync().WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await IgnoreCancellationAsync(running.Control);
        await IgnoreCancellationAsync(running.Node);
    }

    [Fact]
    public async Task Cancellation_is_serviced_while_execution_runs_and_has_one_terminal_fact()
    {
        using var fixture = await Fixture.CreateAsync();
        var fake = new DeterministicTaskType(blockUntilReleased: true);
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        await using var journal = await fixture.OpenNodeAsync();
        var node = fixture.CreateNodeProcessor(journal, fake);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var running = await fixture.ConnectAsync(journal, node, cancellation.Token);
        await WaitUntilAsync(async () =>
        {
            await ThrowIfFaultedAsync(running.Control, running.Node);
            return (await journal.ReadFactsAfterAsync(0))
                .Any(x => x.FactType == OrchestrationMessageKinds.TaskRunning);
        });

        await fixture.Orchestrator.CancelAsync(plan.WorkloadId, TimeSpan.Zero);
        try
        {
            await WaitUntilAsync(async () =>
                (await fixture.Control.GetWorkloadAsync(plan.WorkloadId))?.Payload.ObservedState ==
                WorkloadObservedState.Cancelled);
        }
        catch (TaskCanceledException exception)
        {
            var state = (await fixture.Control.GetWorkloadAsync(plan.WorkloadId))?.Payload.ObservedState;
            var facts = string.Join(",", (await journal.ReadFactsAfterAsync(0, 1000)).Select(x => x.FactType));
            throw new InvalidOperationException($"Cancellation timed out; workload={state}; facts={facts}", exception);
        }
        fake.Release();
        cancellation.Cancel();
        await IgnoreCancellationAsync(running.Control);
        await IgnoreCancellationAsync(running.Node);
        await node.WaitForAttemptsAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(TaskObservedState.Cancelled,
            (await fixture.Control.GetTaskAsync(plan.Tasks[0].TaskId))!.Payload.ObservedState);
        Assert.Single(await journal.ReadFactsAfterAsync(0, 1000),
            x => x.FactType == OrchestrationMessageKinds.TaskTerminal);
    }

    [Fact]
    public async Task Conflicting_stale_completion_enters_recovery_instead_of_being_silently_ignored()
    {
        using var fixture = await Fixture.CreateAsync();
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        var executeItem = (await fixture.Control.ReadOutboxAsync())
            .Single(x => x.Kind == OrchestrationMessageKinds.ExecuteTask);
        var execute = (ExecuteTaskMessage)OrchestrationMessageCodec.Decode(
            Encoding.UTF8.GetBytes(executeItem.PayloadJson)).Value;
        var conflicting = new TaskTerminalFact(
            execute.Identity with { Generation = execute.Identity.Generation + 1 },
            TaskAttemptState.Succeeded, 0, "receipt", null);

        Assert.Equal(FactDisposition.Recovery,
            await fixture.Orchestrator.ApplyNodeFactAsync(
                fixture.Incarnation, 1, OrchestrationMessageKinds.TaskTerminal, conflicting));
        Assert.Equal(TaskObservedState.Recovering,
            (await fixture.Control.GetTaskAsync(plan.Tasks[0].TaskId))!.Payload.ObservedState);
    }

    [Fact]
    public async Task Exact_completion_for_superseded_generation_is_recorded_as_stale_without_mutation()
    {
        using var fixture = await Fixture.CreateAsync();
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        var executeItem = (await fixture.Control.ReadOutboxAsync())
            .Single(x => x.Kind == OrchestrationMessageKinds.ExecuteTask);
        var execute = (ExecuteTaskMessage)OrchestrationMessageCodec.Decode(
            Encoding.UTF8.GetBytes(executeItem.PayloadJson)).Value;
        var task = (await fixture.Control.GetTaskAsync(execute.Identity.TaskId))!;
        await fixture.Control.SaveTaskAsync(task with
        {
            Revision = task.Revision + 1,
            Payload = task.Payload with { AcceptedGeneration = execute.Identity.Generation + 1 }
        }, task.Revision);

        var stale = new TaskTerminalFact(
            execute.Identity, TaskAttemptState.Succeeded, 0, "old-receipt", null);
        Assert.Equal(FactDisposition.Stale,
            await fixture.Orchestrator.ApplyNodeFactAsync(
                fixture.Incarnation, 1, OrchestrationMessageKinds.TaskTerminal, stale));
        var unchanged = await fixture.Control.GetTaskAsync(execute.Identity.TaskId);
        Assert.Equal(execute.Identity.Generation + 1, unchanged!.Payload.AcceptedGeneration);
        Assert.Equal(TaskObservedState.Queued, unchanged.Payload.ObservedState);
    }

    [Fact]
    public async Task Recovery_fact_after_terminal_completion_is_idempotent()
    {
        using var fixture = await Fixture.CreateAsync();
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        var executeItem = (await fixture.Control.ReadOutboxAsync())
            .Single(x => x.Kind == OrchestrationMessageKinds.ExecuteTask);
        var execute = (ExecuteTaskMessage)OrchestrationMessageCodec.Decode(
            Encoding.UTF8.GetBytes(executeItem.PayloadJson)).Value;

        Assert.Equal(
            FactDisposition.Applied,
            await fixture.Orchestrator.ApplyNodeFactAsync(
                fixture.Incarnation,
                1,
                OrchestrationMessageKinds.TaskAccepted,
                new TaskAcceptedFact(execute.Identity)));
        Assert.Equal(
            FactDisposition.Applied,
            await fixture.Orchestrator.ApplyNodeFactAsync(
                fixture.Incarnation,
                2,
                OrchestrationMessageKinds.TaskRunning,
                new TaskRunningFact(execute.Identity)));
        Assert.Equal(
            FactDisposition.Applied,
            await fixture.Orchestrator.ApplyNodeFactAsync(
                fixture.Incarnation,
                3,
                OrchestrationMessageKinds.TaskTerminal,
                new TaskTerminalFact(
                    execute.Identity,
                    TaskAttemptState.Succeeded,
                    0,
                    "receipt",
                    null)));

        Assert.Equal(
            FactDisposition.Recovery,
            await fixture.Orchestrator.ApplyNodeFactAsync(
                fixture.Incarnation,
                4,
                OrchestrationMessageKinds.TaskRecovery,
                new TaskRecoveryFact(
                    execute.Identity,
                    "late-recovery",
                    "late replay")));
        Assert.Equal(
            TaskObservedState.Succeeded,
            (await fixture.Control.GetTaskAsync(
                execute.Identity.TaskId))!.Payload.ObservedState);
        Assert.Equal(
            TaskAttemptState.Succeeded,
            (await fixture.Control.GetTaskAttemptAsync(
                execute.Identity.AttemptId))!.Payload.State);
    }

    [Fact]
    public async Task Completion_cancel_race_records_one_terminal_outcome()
    {
        using var fixture = await Fixture.CreateAsync();
        var fake = new DeterministicTaskType(blockUntilReleased: true);
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        await using var journal = await fixture.OpenNodeAsync();
        var node = fixture.CreateNodeProcessor(journal, fake);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var running = await fixture.ConnectAsync(journal, node, cancellation.Token);
        await WaitUntilAsync(async () =>
            (await fixture.Control.GetTaskAsync(plan.Tasks[0].TaskId))?.Payload.ObservedState ==
            TaskObservedState.Running);

        var cancel = fixture.Orchestrator.CancelAsync(plan.WorkloadId, TimeSpan.Zero);
        fake.Release();
        await cancel;
        await WaitUntilAsync(async () =>
        {
            var state = (await fixture.Control.GetWorkloadAsync(plan.WorkloadId))!.Payload.ObservedState;
            return state is WorkloadObservedState.Succeeded or WorkloadObservedState.Cancelled;
        });
        cancellation.Cancel();
        await IgnoreCancellationAsync(running.Control);
        await IgnoreCancellationAsync(running.Node);
        await node.WaitForAttemptsAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(await journal.ReadFactsAfterAsync(0, 1000),
            x => x.FactType == OrchestrationMessageKinds.TaskTerminal);
        Assert.Equal(1, fake.StartCount);
    }

    [Fact]
    public async Task Node_restart_recovers_running_execution_without_duplicate_start()
    {
        using var fixture = await Fixture.CreateAsync();
        var fake = new DeterministicTaskType(blockUntilReleased: true);
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);

        await using (var journal = await fixture.OpenNodeAsync())
        await using (var firstNode = fixture.CreateNodeProcessor(journal, fake))
        {
            using var firstSession = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var running = await fixture.ConnectAsync(journal, firstNode, firstSession.Token);
            await WaitUntilAsync(async () => (await journal.ReadFactsAfterAsync(0))
                .Any(x => x.FactType == OrchestrationMessageKinds.TaskRunning));
            firstSession.Cancel();
            await IgnoreCancellationAsync(running.Control);
            await IgnoreCancellationAsync(running.Node);
        }

        await using (var restartedJournal = await fixture.OpenNodeAsync())
        await using (var restartedNode = fixture.CreateNodeProcessor(restartedJournal, fake))
        {
            using var secondSession = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var running = await fixture.ConnectAsync(restartedJournal, restartedNode, secondSession.Token);
            await WaitUntilAsync(() => Task.FromResult(fake.RecoveryCount == 1));
            fake.Release();
            await WaitUntilAsync(async () =>
                (await fixture.Control.GetWorkloadAsync(plan.WorkloadId))?.Payload.ObservedState ==
                WorkloadObservedState.Succeeded);
            secondSession.Cancel();
            await IgnoreCancellationAsync(running.Control);
            await IgnoreCancellationAsync(running.Node);
        }
        Assert.Equal(1, fake.StartCount);
        Assert.Equal(1, fake.RecoveryCount);
    }

    [Fact]
    public async Task Control_restart_reloads_plan_and_scheduler_then_releases_dependency()
    {
        using var fixture = await Fixture.CreateAsync(durableScheduler: true);
        var fake = new DeterministicTaskType(blockUntilReleased: true);
        var plan = Plan(3);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        await using var journal = await fixture.OpenNodeAsync();
        await using var node = fixture.CreateNodeProcessor(journal, fake);

        using (var firstSession = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            var running = await fixture.ConnectAsync(journal, node, firstSession.Token);
            await WaitUntilAsync(async () =>
                (await fixture.Control.ReadOutboxAsync()).Count == 0 &&
                (await journal.ReadFactsAfterAsync(0)).Count(
                    x => x.FactType == OrchestrationMessageKinds.TaskRunning) == 2);
            firstSession.Cancel();
            await IgnoreCancellationAsync(running.Control);
            await IgnoreCancellationAsync(running.Node);
        }

        await fixture.RestartControlAsync();
        fake.Release();
        await node.WaitForAttemptsAsync().WaitAsync(TimeSpan.FromSeconds(5));
        using (var secondSession = new CancellationTokenSource(TimeSpan.FromSeconds(15)))
        {
            var running = await fixture.ConnectAsync(journal, node, secondSession.Token);
            await WaitUntilAsync(async () =>
                (await fixture.Control.GetWorkloadAsync(plan.WorkloadId))?.Payload.ObservedState ==
                WorkloadObservedState.Succeeded, TimeSpan.FromSeconds(10));
            secondSession.Cancel();
            await IgnoreCancellationAsync(running.Control);
            await IgnoreCancellationAsync(running.Node);
        }
        Assert.Equal(3, fake.StartCount);
        Assert.Equal(3, (await fixture.Control.ReadNotificationsAsync(
            $"workload:{plan.WorkloadId}", 0, 1000)).Count(
                x => x.PayloadJson.Contains(OrchestrationMessageKinds.TaskTerminal, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Unsupported_running_recovery_is_ambiguous_and_never_relaunches()
    {
        using var fixture = await Fixture.CreateAsync();
        var taskType = new NonRecoverableLongTaskType();
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        await using (var journal = await fixture.OpenNodeAsync())
        await using (var node = fixture.CreateNodeProcessor(journal, taskType))
        {
            using var session = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var running = await fixture.ConnectAsync(journal, node, session.Token);
            await WaitUntilAsync(async () => (await journal.ReadFactsAfterAsync(0))
                .Any(x => x.FactType == OrchestrationMessageKinds.TaskRunning));
            session.Cancel();
            await IgnoreCancellationAsync(running.Control);
            await IgnoreCancellationAsync(running.Node);
        }

        await using var restartedJournal = await fixture.OpenNodeAsync();
        await using var restartedNode = fixture.CreateNodeProcessor(restartedJournal, taskType);
        await restartedNode.RecoverDurableAttemptsAsync();
        Assert.Contains(await restartedJournal.ReadFactsAfterAsync(0, 1000),
            x => x.FactType == OrchestrationMessageKinds.TaskRecovery);
        Assert.Equal(1, taskType.StartCount);
    }

    [Fact]
    public async Task Recoverable_runtime_proving_execution_absent_records_interruption_without_relaunch()
    {
        using var fixture = await Fixture.CreateAsync();
        var original = new DeterministicTaskType(blockUntilReleased: true);
        var plan = Plan(1);
        await fixture.Orchestrator.RegisterAndScheduleAsync(
            plan, [fixture.Host], fixture.Host.PoolId, fixture.Now);
        await using (var journal = await fixture.OpenNodeAsync())
        await using (var node = fixture.CreateNodeProcessor(journal, original))
        {
            using var session = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var running = await fixture.ConnectAsync(journal, node, session.Token);
            await WaitUntilAsync(async () => (await journal.ReadFactsAfterAsync(0))
                .Any(x => x.FactType == OrchestrationMessageKinds.TaskRunning));
            session.Cancel();
            await IgnoreCancellationAsync(running.Control);
            await IgnoreCancellationAsync(running.Node);
        }

        var replacement = new DeterministicTaskType(blockUntilReleased: true);
        await using var restartedJournal = await fixture.OpenNodeAsync();
        await using var restartedNode = fixture.CreateNodeProcessor(restartedJournal, replacement);
        await restartedNode.RecoverDurableAttemptsAsync();
        var terminal = (await restartedJournal.ReadFactsAfterAsync(0, 1000))
            .Where(x => x.FactType == OrchestrationMessageKinds.TaskTerminal)
            .Select(x => (TaskTerminalFact)OrchestrationMessageCodec.DecodeJournaledFact(
                x.FactType, x.PayloadJson))
            .Single();
        Assert.Equal(TaskAttemptState.Interrupted, terminal.State);
        Assert.Equal(1, original.StartCount);
        Assert.Equal(0, replacement.StartCount);
    }

    private static WorkloadPlan Plan(int count)
    {
        var workload = WorkloadId.New();
        var revision = PlanRevisionId.New();
        var ids = Enumerable.Range(0, count).Select(_ => TaskId.New()).ToArray();
        var tasks = ids.Select((id, index) => new TaskPlanNode(
            id,
            $"task-{index}",
            "deterministic",
            "1.0",
            new ResourceRequirements(cpuCores: 1, memoryBytes: 64, processCount: 1, concurrencyUnits: 1),
            TaskInput.Parse("application/json", "1.0", JsonSerializer.Serialize(new { index })),
            index < 2 ? [] : [ids[0], ids[1]],
            new HashSet<string>(),
            null,
            null,
            null,
            0,
            InterruptionClass.Restartable,
            [],
            $"result-{index}")).ToArray();
        return new(workload, revision, WorkloadPlan.CurrentSchemaVersion,
            "test", "1.0", tasks, AggregateFailurePolicy.FailFast, count);
    }

    private static AttemptIdentity Identity() =>
        new(WorkloadId.New(), PlanRevisionId.New(), TaskId.New(), TaskAttemptId.New(), 1,
            HostId.New(), NodeIncarnationId.New(), DelegationId.New(), CommandId.New());

    private static async Task WaitUntilAsync(Func<Task<bool>> condition, TimeSpan? timeout = null)
    {
        using var cancellation = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(5));
        while (!await condition())
            await Task.Delay(20, cancellation.Token);
    }

    private static async Task IgnoreCancellationAsync(Task task)
    {
        try { await task; }
        catch (OperationCanceledException) { }
        catch (ChannelClosedException) { }
    }

    private static async Task<bool> ContainsTextAsync(string path, string value)
    {
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 4096, true);
        using var memory = new MemoryStream();
        await stream.CopyToAsync(memory);
        return Encoding.UTF8.GetString(memory.ToArray()).Contains(value, StringComparison.Ordinal);
    }

    private static async Task<(Task Control, Task Node)> ConnectAsync(
        ControlOrchestrator orchestrator,
        NodeEndpointRegistration endpoint,
        NodeJournal journal,
        NodeCommandProcessor node,
        CancellationToken cancellationToken)
    {
        var securityA = new VerifiedSessionSecurity(true, true, "control", "node", "binding");
        var securityB = new VerifiedSessionSecurity(true, true, "node", "control", "binding");
        var carriers = InMemoryDuplexCarrier.CreatePair(securityA, securityB);
        var session = Guid.NewGuid();
        var cursor = await orchestrator.GetNodeCursorAsync(endpoint.NodeIncarnationId);
        var nodeCursors = await journal.GetStreamCursorsAsync();
        var limits = new TransportLimits(OrchestrationMessageCodec.MaximumPayloadBytes, 256);
        var first = carriers.First.ConnectAsync(new(
            session, endpoint.NodeIncarnationId, 1, 0, new HashSet<string>(),
            new HashSet<string>(), new Dictionary<StreamKind, long> { [StreamKind.Events] = cursor },
            limits), cancellationToken).AsTask();
        var second = carriers.Second.ConnectAsync(new(
            session, endpoint.NodeIncarnationId, 1, 0, new HashSet<string>(),
            new HashSet<string>(), nodeCursors, limits), cancellationToken).AsTask();
        var controlConnection = await first;
        var nodeConnection = await second;
        return (
            RunAndDisposeConnectionAsync(controlConnection, connection =>
                new ControlSessionPump(orchestrator, endpoint.HostId, endpoint.NodeIncarnationId)
                    .RunSessionAsync(connection, cancellationToken)),
            RunAndDisposeConnectionAsync(nodeConnection, connection =>
                node.RunSessionAsync(connection, cancellationToken)));
    }

    private static async Task<(Task Control, Task Node)> ConnectTerminalAsync(
        ControlOrchestrator orchestrator,
        HostCapacitySnapshot host,
        NodeJournal journal,
        NodeCommandProcessor node,
        ControlTerminalRouter terminal,
        CancellationToken cancellationToken)
    {
        var endpoint = new NodeEndpointRegistration(
            host.HostId, host.IncarnationId, host.PoolId,
            DirectTransport(46020),
            "node", "node.pem", host.Capacity, host.Capabilities,
            host.SetupFingerprints, DateTimeOffset.UtcNow);
        var security = new VerifiedSessionSecurity(true, true, "a", "b", "binding");
        var carriers = InMemoryDuplexCarrier.CreatePair(security, security);
        var id = Guid.NewGuid();
        var limits = new TransportLimits(32 * 1024, 256);
        var first = carriers.First.ConnectAsync(new(
            id, host.IncarnationId, 1, 0, new HashSet<string>(),
            new HashSet<string>(), new Dictionary<StreamKind, long>
            {
                [StreamKind.Terminal] = terminal.GetReceivedCursor(host.IncarnationId)
            }, limits), cancellationToken).AsTask();
        var second = carriers.Second.ConnectAsync(new(
            id, host.IncarnationId, 1, 0, new HashSet<string>(),
            new HashSet<string>(), await journal.GetStreamCursorsAsync(), limits), cancellationToken).AsTask();
        var controlConnection = await first;
        var nodeConnection = await second;
        return (
            RunAndDisposeConnectionAsync(controlConnection, connection =>
                new ControlSessionPump(
                    orchestrator, endpoint.HostId, endpoint.NodeIncarnationId, terminal,
                    new ControlTerminalRevocationStore(orchestrator.Store))
                    .RunSessionAsync(connection, cancellationToken)),
            RunAndDisposeConnectionAsync(nodeConnection, connection =>
                node.RunSessionAsync(connection, cancellationToken)));
    }

    private static async Task RunAndDisposeConnectionAsync(
        ITransportConnection connection,
        Func<ITransportConnection, Task> run)
    {
        await using (connection) await run(connection);
    }

    private static async Task ThrowIfFaultedAsync(params Task[] tasks)
    {
        foreach (var task in tasks)
            if (task.IsFaulted)
                await task;
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string directory;
        private ISchedulerStateStore schedulerStore;
        private readonly string controlPath;
        private readonly string schedulerPath;
        public DateTimeOffset Now { get; } = DateTimeOffset.UtcNow;
        public NodeIncarnationId Incarnation { get; } = NodeIncarnationId.New();
        public Guid BootId { get; } = Guid.NewGuid();
        public SqliteControlStore Control { get; private set; }
        public ControlOrchestrator Orchestrator { get; private set; }
        public HostCapacitySnapshot Host { get; }
        public string RootPath => directory;

        private Fixture(string directory, bool durableScheduler)
        {
            this.directory = directory;
            controlPath = Path.Combine(directory, "control.db");
            schedulerPath = Path.Combine(directory, "scheduler.db");
            Control = new(controlPath);
            schedulerStore = durableScheduler
                ? new SqliteSchedulerStateStore(schedulerPath)
                : new InMemorySchedulerStateStore();
            Orchestrator = new(
                Control,
                new CompositeScheduler(schedulerStore),
                schedulerStore,
                new(new(100, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5),
                    1024 * 1024, 4)));
            Host = new(HostId.New(), Incarnation, PoolId.New(),
                new ResourceRequirements(8, 4096, 4096, processCount: 8, concurrencyUnits: 8),
                [], [], Now);
        }

        public static async Task<Fixture> CreateAsync(bool durableScheduler = false)
        {
            var directory = Path.Combine(
                AppContext.BaseDirectory, "orchestration-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var fixture = new Fixture(directory, durableScheduler);
            await fixture.Orchestrator.InitializeAsync();
            return fixture;
        }

        public async Task RestartControlAsync()
        {
            if (schedulerStore is not SqliteSchedulerStateStore)
                throw new InvalidOperationException("Control restart test requires the durable scheduler store.");
            await schedulerStore.DisposeAsync();
            Control = new(controlPath);
            schedulerStore = new SqliteSchedulerStateStore(schedulerPath);
            Orchestrator = new(
                Control,
                new CompositeScheduler(schedulerStore),
                schedulerStore,
                new(new(100, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5),
                    1024 * 1024, 4)));
            await Orchestrator.InitializeAsync();
        }

        public async Task<NodeJournal> OpenNodeAsync()
        {
            var journal = new NodeJournal(Path.Combine(directory, "node.db"));
            await journal.InitializeAsync(Incarnation, BootId);
            return journal;
        }

        public NodeCommandProcessor CreateNodeProcessor(NodeJournal journal, params ITaskType[] taskTypes) =>
            new(journal, new TaskTypeRegistry(taskTypes),
                new NodeExecutionOptions(Path.Combine(directory, "workspaces")));

        public async Task<(Task Control, Task Node)> ConnectAsync(
            NodeJournal journal,
            NodeCommandProcessor node,
            CancellationToken cancellationToken)
        {
            var securityA = new VerifiedSessionSecurity(true, true, "control", "node", "binding");
            var securityB = new VerifiedSessionSecurity(true, true, "node", "control", "binding");
            var carriers = InMemoryDuplexCarrier.CreatePair(securityA, securityB);
            var session = Guid.NewGuid();
            var controlCursor = await Orchestrator.GetNodeCursorAsync(Incarnation);
            var nodeCursors = await journal.GetStreamCursorsAsync();
            var limits = new TransportLimits(OrchestrationMessageCodec.MaximumPayloadBytes, 256);
            var controlHello = new SessionHello(session, Incarnation, 1, 0,
                new HashSet<string>(), new HashSet<string>(),
                new Dictionary<StreamKind, long> { [StreamKind.Events] = controlCursor }, limits);
            var nodeHello = new SessionHello(session, Incarnation, 1, 0,
                new HashSet<string>(), new HashSet<string>(), nodeCursors, limits);
            var controlConnect = carriers.First.ConnectAsync(controlHello, cancellationToken).AsTask();
            var nodeConnect = carriers.Second.ConnectAsync(nodeHello, cancellationToken).AsTask();
            var controlConnection = await controlConnect;
            var nodeConnection = await nodeConnect;
            var controlTask = RunAndDisposeAsync(
                controlConnection,
                connection => new ControlSessionPump(
                    Orchestrator, Host.HostId, Incarnation).RunSessionAsync(connection, cancellationToken));
            var nodeTask = RunAndDisposeAsync(
                nodeConnection,
                connection => node.RunSessionAsync(connection, cancellationToken));
            return (controlTask, nodeTask);
        }

        private static async Task RunAndDisposeAsync(
            ITransportConnection connection,
            Func<ITransportConnection, Task> run)
        {
            await using (connection)
                await run(connection);
        }

        public void Dispose()
        {
            schedulerStore.DisposeAsync().AsTask().GetAwaiter().GetResult();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            for (var attempt = 0; attempt < 10 && Directory.Exists(directory); attempt++)
            {
                try { Directory.Delete(directory, true); }
                catch (IOException)
                {
                    if (attempt < 9) Thread.Sleep(50);
                }
            }
        }
    }

    private sealed class DeterministicTaskType(bool blockUntilReleased)
        : TaskTypeBase, ITaskOutputSource, IRecoverableTaskType
    {
        private readonly TaskCompletionSource release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ConcurrentDictionary<TaskAttemptId, FakeHandle> handles = [];
        private readonly ConcurrentDictionary<TaskAttemptId, byte> outputRead = [];
        private int startCount;
        private int recoveryCount;

        public int StartCount => Volatile.Read(ref startCount);
        public int RecoveryCount => Volatile.Read(ref recoveryCount);
        public override TaskTypeVersion Type { get; } = new("deterministic", new Version(1, 0));
        public override TaskCapabilities Capabilities =>
            TaskCapabilities.Prepare | TaskCapabilities.Execute | TaskCapabilities.Observe |
            TaskCapabilities.Cancel | TaskCapabilities.Cleanup | TaskCapabilities.OfflineExecution;
        public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;

        public void Release() => release.TrySetResult();
        public override ValidationResult Validate(JsonElement input) =>
            input.ValueKind == JsonValueKind.Object ? ValidationResult.Valid : ValidationResult.Invalid("object required");
        public override ValueTask<SetupResult> SetupAsync(
            TaskExecutionContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new SetupResult(false, "deterministic"));
        public override ValueTask<IExecutionHandle> StartAsync(
            TaskExecutionContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref startCount);
            var handle = new FakeHandle(context.AttemptId, context.Generation);
            handles[context.AttemptId] = handle;
            return ValueTask.FromResult<IExecutionHandle>(handle);
        }
        public override ValueTask<ExecutionObservation> ObserveAsync(
            IExecutionHandle execution, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var handle = handles[execution.AttemptId];
            if (handle.Cancelled) return ValueTask.FromResult(new ExecutionObservation(ExecutionState.Interrupted));
            if (!blockUntilReleased || release.Task.IsCompleted)
                return ValueTask.FromResult(new ExecutionObservation(ExecutionState.Exited, 0));
            return ValueTask.FromResult(new ExecutionObservation(ExecutionState.Running));
        }
        public override ValueTask CancelAsync(
            IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken)
        {
            handles[execution.AttemptId].Cancelled = true;
            return ValueTask.CompletedTask;
        }
        public ValueTask<TaskExecutionRecoveryResult> RecoverExecutionAsync(
            TaskExecutionContext context,
            string currentBootIdentity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref recoveryCount);
            return ValueTask.FromResult(
                handles.TryGetValue(context.AttemptId, out var handle) &&
                handle.Generation == context.Generation
                    ? new TaskExecutionRecoveryResult(TaskExecutionRecoveryStatus.Present, handle, "fake.present")
                    : new TaskExecutionRecoveryResult(TaskExecutionRecoveryStatus.Absent, Code: "fake.absent"));
        }
        public override ValueTask<CleanupResult> CleanupAsync(
            TaskExecutionContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new CleanupResult(true));
        public ValueTask<TaskOutputBatch> ReadOutputsAsync(
            IExecutionHandle execution, long afterCursor, int maximumCount, CancellationToken cancellationToken)
        {
            if (!outputRead.TryAdd(execution.AttemptId, 0))
                return ValueTask.FromResult(new TaskOutputBatch(afterCursor, []));
            IReadOnlyList<TaskRuntimeOutput> output =
            [
                new TaskRuntimeProgress(.5, "half"),
                new TaskRuntimeLogCursor("stdout", 0, 4, new string('a', 64), false),
                new TaskRuntimeArtifact(PortableObjectId.New(), "result", "application/json",
                    $"memory://{execution.AttemptId}", 2, new string('b', 64))
            ];
            return ValueTask.FromResult(new TaskOutputBatch(afterCursor + output.Count, output));
        }

        private sealed class FakeHandle(TaskAttemptId attemptId, int generation) : IExecutionHandle
        {
            public TaskAttemptId AttemptId { get; } = attemptId;
            public int Generation { get; } = generation;
            public int ProcessId => 1;
            public long ProcessCreationTimeUtcTicks => 1;
            public bool Cancelled { get; set; }
        }
    }

    private sealed class NonRecoverableLongTaskType : TaskTypeBase
        {
            private int starts;
            public int StartCount => starts;
            public override TaskTypeVersion Type { get; } = new("deterministic", new Version(1, 0));
            public override TaskCapabilities Capabilities =>
                TaskCapabilities.Execute | TaskCapabilities.Observe | TaskCapabilities.Cancel;
            public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;
            public override ValidationResult Validate(JsonElement input) => ValidationResult.Valid;
            public override ValueTask<IExecutionHandle> StartAsync(
                TaskExecutionContext context, CancellationToken cancellationToken)
            {
                Interlocked.Increment(ref starts);
                return ValueTask.FromResult<IExecutionHandle>(new Handle(context.AttemptId, context.Generation));
            }
            public override ValueTask<ExecutionObservation> ObserveAsync(
                IExecutionHandle execution, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.FromResult(new ExecutionObservation(ExecutionState.Running));
            }
            public override ValueTask CancelAsync(
                IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken) =>
                ValueTask.CompletedTask;

            private sealed record Handle(TaskAttemptId AttemptId, int Generation) : IExecutionHandle
            {
                public int ProcessId => 1;
                public long ProcessCreationTimeUtcTicks => 1;
            }
        }

    private sealed class SyntheticPlanFactory(int count) : IWorkloadPlanFactory
        {
            public string Kind => "synthetic-300";
            public WorkloadPlan Create(
                WorkloadId workloadId, PlanRevisionId planRevisionId, JsonElement input) =>
                new(workloadId, planRevisionId, WorkloadPlan.CurrentSchemaVersion,
                    Kind, "1.0",
                    Enumerable.Range(0, count).Select(index => new TaskPlanNode(
                        new(new Guid(index + 1, 0, 0, new byte[8])),
                        $"task-{index:D3}", "lean", "1.0",
                        new ResourceRequirements(1, 1, 1, processCount: 1, concurrencyUnits: 1),
                        TaskInput.Empty, [], new HashSet<string>(), null, null, null, 0,
                        InterruptionClass.Restartable, [], $"result-{index:D3}")).ToArray(),
                    AggregateFailurePolicy.FailFast, count);
        }

        private sealed class LeanTaskType(string name = "lean") : TaskTypeBase
        {
            public ConcurrentBag<TaskAttemptId> Started { get; } = [];
            public override TaskTypeVersion Type => new(name, new Version(1, 0));
            public override TaskCapabilities Capabilities =>
                TaskCapabilities.Execute | TaskCapabilities.Observe | TaskCapabilities.Cancel;
            public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;
            public override ValidationResult Validate(JsonElement input) => ValidationResult.Valid;
            public override ValueTask<IExecutionHandle> StartAsync(
                TaskExecutionContext context, CancellationToken cancellationToken)
            {
                Started.Add(context.AttemptId);
                return ValueTask.FromResult<IExecutionHandle>(new LeanHandle(context.AttemptId, context.Generation));
            }
            public override ValueTask<ExecutionObservation> ObserveAsync(
                IExecutionHandle execution, CancellationToken cancellationToken) =>
                ValueTask.FromResult(new ExecutionObservation(ExecutionState.Exited, 0));
            public override ValueTask CancelAsync(
                IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken) =>
                ValueTask.CompletedTask;
            private sealed record LeanHandle(TaskAttemptId AttemptId, int Generation) : IExecutionHandle
            {
                public int ProcessId => 0;
                public long ProcessCreationTimeUtcTicks => 0;
            }
        }

    private sealed class FakeIdentityCatalog(
                IdentityGrantId grantId,
                WorkloadId workloadId,
                TaskId taskId,
                HostId hostId,
                NodeIncarnationId incarnationId) : IControlIdentityGrantCatalog
            {
                public ValueTask<TaskIdentityGrantReference?> ResolveAsync(
                    IdentityGrantId requestedGrantId,
                    WorkloadId requestedWorkloadId,
                    TaskId requestedTaskId,
                    int generation,
                    HostId requestedHostId,
                    NodeIncarnationId requestedIncarnationId,
                    CancellationToken cancellationToken) =>
                    ValueTask.FromResult<TaskIdentityGrantReference?>(new(
                        grantId, workloadId, taskId, generation, hostId, incarnationId,
                        "https://inference.example", ["inference.invoke"],
                        DateTimeOffset.UtcNow.AddHours(1), IdentityRenewalMode.LocalBroker));
    }

    private sealed class FakeIdentityResolver(string secret) : ITaskIdentityResolver
            {
                private readonly InMemoryProtectedIdentityVault vault = new();
                public int ResolveCount { get; private set; }

                public ValueTask<TaskIdentityLease> ResolveAsync(
                    AttemptIdentity identity,
                    IReadOnlyList<TaskIdentityGrantReference> grants,
                    CancellationToken cancellationToken)
                {
                    Assert.Single(grants);
                    Assert.Equal(identity.TaskId, grants[0].TaskId);
                    ResolveCount++;
                    var handle = vault.Store("fake-broker", secret, grants[0].ExpiresAt);
                    return ValueTask.FromResult(new TaskIdentityLease([handle], () =>
                    {
                        vault.Remove(handle);
                        return ValueTask.CompletedTask;
                    }));
                }
    }

    private sealed class IdentityAwareTaskType : TaskTypeBase
            {
                public int IdentityHandleCount { get; private set; }
                public override TaskTypeVersion Type => new("identity-aware", new Version(1, 0));
                public override TaskCapabilities Capabilities =>
                    TaskCapabilities.Execute | TaskCapabilities.Observe | TaskCapabilities.Cancel;
                public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;
                public override ValidationResult Validate(JsonElement input) => ValidationResult.Valid;
                public override ValueTask<IExecutionHandle> StartAsync(
                    TaskExecutionContext context, CancellationToken cancellationToken)
                {
                    IdentityHandleCount = context.IdentityHandles?.Count ?? 0;
                    return ValueTask.FromResult<IExecutionHandle>(new Handle(context.AttemptId, context.Generation));
                }
                public override ValueTask<ExecutionObservation> ObserveAsync(
                    IExecutionHandle execution, CancellationToken cancellationToken) =>
                    ValueTask.FromResult(new ExecutionObservation(ExecutionState.Exited, 0));
                public override ValueTask CancelAsync(
                    IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken) =>
                    ValueTask.CompletedTask;
                private sealed record Handle(TaskAttemptId AttemptId, int Generation) : IExecutionHandle
                {
                    public int ProcessId => 0;
                    public long ProcessCreationTimeUtcTicks => 0;
                }
            }

    private sealed class FakeHostProvider : IHostProvider
        {
            private readonly Dictionary<
                ProviderOperationId, ProviderEffect> pendingCreates = [];
            public int Created { get; private set; }
            public int Reconciled { get; private set; }
            public bool DelayCreates { get; init; }
            public bool CompleteCreates { get; set; }
            public Task<ProviderCapabilities> DiscoverCapabilitiesAsync(
                ProviderBinding binding, CancellationToken cancellationToken = default) =>
                Task.FromResult(new ProviderCapabilities(
                    ProviderCapability.Discover | ProviderCapability.Inspect | ProviderCapability.Create |
                    ProviderCapability.Start | ProviderCapability.Stop | ProviderCapability.Delete,
                    new Dictionary<ProviderCapability, string>()));
            public async IAsyncEnumerable<ProviderResource> DiscoverAsync(
                ProviderBinding binding,
                [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
            {
                await Task.CompletedTask;
                yield break;
            }

            public Task<ProviderResource?> InspectAsync(
                ProviderBinding binding, string resourceName, CancellationToken cancellationToken = default) =>
                Task.FromResult<ProviderResource?>(null);
            public Task<ProviderOperationResult> CreateAsync(
                ProviderEffect effect, CancellationToken cancellationToken = default)
            {
                Created++;
                if (DelayCreates)
                {
                    pendingCreates[effect.OperationId] = effect;
                    return Task.FromResult(new ProviderOperationResult(
                        ProviderOperationStatus.Running,
                        new(
                            effect.OperationId,
                            effect.IdempotencyKey,
                            "fake",
                            effect.HostId.ToString()),
                        null));
                }
                return Result(effect, ProviderHostStatus.Running);
            }
            public Task<ProviderOperationResult> StartAsync(
                ProviderEffect effect, CancellationToken cancellationToken = default) =>
                Result(effect, ProviderHostStatus.Running);
            public Task<ProviderOperationResult> StopAsync(
                ProviderEffect effect, CancellationToken cancellationToken = default) =>
                Result(effect, ProviderHostStatus.Stopped);
            public Task<ProviderOperationResult> DeleteAsync(
                ProviderEffect effect, CancellationToken cancellationToken = default) =>
                Result(effect, ProviderHostStatus.Deleted);
            public Task<ProviderOperationResult> RepairAsync(
                ProviderEffect effect, CancellationToken cancellationToken = default) =>
                Result(effect, ProviderHostStatus.Running);
            public Task<ProviderOperationResult> RestoreAsync(
                ProviderEffect effect, CancellationToken cancellationToken = default) =>
                Result(effect, ProviderHostStatus.Running);
            public Task<ProviderOperationResult> ReconcileAsync(
                ProviderOperationHandle handle, CancellationToken cancellationToken = default)
            {
                Reconciled++;
                var effect = pendingCreates[handle.OperationId];
                return Task.FromResult(CompleteCreates
                    ? new ProviderOperationResult(
                        ProviderOperationStatus.Succeeded,
                        handle,
                        new(
                            effect.HostId.ToString(),
                            effect.ResourceName,
                            ProviderHostStatus.Running,
                            new Dictionary<string, string>()))
                    : new ProviderOperationResult(
                        ProviderOperationStatus.Running,
                        handle,
                        null));
            }
            private static Task<ProviderOperationResult> Result(
                ProviderEffect effect, ProviderHostStatus status) =>
                Task.FromResult(new ProviderOperationResult(
                    ProviderOperationStatus.Succeeded, null,
                    new(effect.HostId.ToString(), effect.ResourceName, status,
                        new Dictionary<string, string>())));
    }

    private sealed class FakeEnrollmentWorkflow : IProvisionedNodeEnrollmentWorkflow
    {
        public int Enrolled { get; private set; }
        public Task<NodeEndpointRegistration> BootstrapAndEnrollAsync(
            PoolRegistration pool,
            PoolMember member,
            ProviderResource resource,
            CancellationToken cancellationToken)
        {
            Enrolled++;
            return Task.FromResult(new NodeEndpointRegistration(
                member.HostId, member.IncarnationId, member.PoolId,
                DirectTransport(46100 + Enrolled),
                $"node-{Enrolled}", $"node-{Enrolled}.pem",
                new ResourceRequirements(2), [], [], DateTimeOffset.UtcNow));
        }
    }

    private sealed class RotatingTokenCredential : TokenCredential
        {
            private int count;
            public override AccessToken GetToken(
                TokenRequestContext requestContext, CancellationToken cancellationToken) =>
                new($"token-{Interlocked.Increment(ref count)}", DateTimeOffset.UtcNow.AddMinutes(5));
            public override ValueTask<AccessToken> GetTokenAsync(
                TokenRequestContext requestContext, CancellationToken cancellationToken) =>
                ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }

    private sealed class FakeRemoteAgentSource : IOrchestrationAgentEventSource
    {
        public int Reads { get; private set; }
        public Task<RemoteAgentEventPage> ReadEventsAsync(
            ManagedAgentExecution execution, long afterSequence, CancellationToken cancellationToken)
        {
            Reads++;
            IReadOnlyList<RemoteAgentEvent> values =
            [
                new(3, new AgentActivity("fixture-started")),
                new(7, new AgentFinalResponse($"fixture:{(Reads == 1 ? "first" : "second")}"))
            ];
            return Task.FromResult(new RemoteAgentEventPage(
                values.Where(x => x.NodeSequence > afterSequence).ToArray(),
                TaskAttemptState.Succeeded, RecoveryCertainty.Certain));
        }
    }

    private sealed class AgentFixtureExecutor : IProcessExecutor
        {
            public int Starts { get; private set; }
            public string? StandardInputPath { get; private set; }
            public ValueTask<IExecutionHandle> StartAsync(
                ProcessLaunchRequest request, CancellationToken cancellationToken)
            {
                Starts++;
                StandardInputPath = request.StandardInputPath;
                return ValueTask.FromResult<IExecutionHandle>(
                    new AgentFixtureHandle(request.AttemptId, request.Generation));
            }

            public ValueTask<ExecutionObservation> ObserveAsync(
                IExecutionHandle execution, CancellationToken cancellationToken) =>
                ValueTask.FromResult(new ExecutionObservation(ExecutionState.Exited, 0));
            public ValueTask<SpoolRead> ReadOutputAsync(
                IExecutionHandle execution, string stream, long offset, int maximumBytes,
                CancellationToken cancellationToken)
            {
                var all = Encoding.UTF8.GetBytes(
                    """{"type":"activity","text":"wörking"}""" + "\n" +
                    """{"type":"final","text":"done"}""" + "\n");
                var count = (int)Math.Min(5, Math.Max(0, all.Length - offset));
                var bytes = all.AsMemory((int)offset, count).ToArray();
                return ValueTask.FromResult(new SpoolRead(
                    new(stream, "memory", offset + bytes.Length, all.Length, false), bytes));
            }

            public ValueTask CancelAsync(
                IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken) =>
                ValueTask.CompletedTask;
            public ValueTask<IExecutionHandle> RecoverAsync(
                TaskAttemptId attemptId, int generation, string currentBootId,
                CancellationToken cancellationToken) =>
                ValueTask.FromResult<IExecutionHandle>(new AgentFixtureHandle(attemptId, generation));
            private sealed record AgentFixtureHandle(
                TaskAttemptId AttemptId, int Generation) : IExecutionHandle
            {
                public int ProcessId => 1;
                public long ProcessCreationTimeUtcTicks => 1;
        }
    }

    private sealed class SequencedRemoteSource : IOrchestrationAgentEventSource
    {
        public List<long> Cursors { get; } = [];
        public Task<RemoteAgentEventPage> ReadEventsAsync(
            ManagedAgentExecution execution, long afterSequence, CancellationToken cancellationToken)
        {
            Cursors.Add(afterSequence);
            return Task.FromResult(Cursors.Count switch
            {
                1 => new RemoteAgentEventPage(
                    [new(5, new AgentActivity("once"))], TaskAttemptState.Running, RecoveryCertainty.Certain),
                2 => new RemoteAgentEventPage(
                    [new(8, new AgentActivity("still-working"))],
                    TaskAttemptState.Succeeded, RecoveryCertainty.Certain, PageCursor: 8),
                _ => new RemoteAgentEventPage(
                    [new(9, new AgentFinalResponse("final"))],
                    TaskAttemptState.Succeeded, RecoveryCertainty.Certain)
            });
        }
    }

    private sealed class CancellationThenResponseAgentRuntime : IAgentRuntime
    {
        public AgentRuntimeDescriptor Descriptor { get; } =
            new("cancellation-regression", "1.0");

        public async IAsyncEnumerable<AgentRuntimeEvent> ExecuteAsync(
            AgentRuntimeRequest request,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            if (request.Turn.Text == "cancel")
                throw new OperationCanceledException("Injected lease-loss cancellation.");
            cancellationToken.ThrowIfCancellationRequested();
            yield return new AgentFinalResponse($"echo:{request.Turn.Text}");
        }
    }

    private sealed class TerminalRemoteSource(TaskAttemptState state) : IOrchestrationAgentEventSource
    {
        public Task<RemoteAgentEventPage> ReadEventsAsync(
            ManagedAgentExecution execution, long afterSequence, CancellationToken cancellationToken) =>
            Task.FromResult(new RemoteAgentEventPage([], state, RecoveryCertainty.Certain));
    }

    private sealed class WorkerAgentDispatcher : IAgentTaskDispatcher
    {
        public Task<ManagedAgentExecution?> DispatchAsync(
            AgentTaskIntent intent, CancellationToken cancellationToken) =>
            Task.FromResult<ManagedAgentExecution?>(new(
                Guid.NewGuid(), intent.WorkloadId, intent.TaskId, TaskAttemptId.New(),
                1, HostId.New(), NodeIncarnationId.New(), DateTimeOffset.UtcNow));

        public Task<ManagedExecutionStatus> ReconcileAsync(
            WorkloadId workloadId, TaskId taskId, ManagedAgentExecution? execution,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ManagedExecutionStatus(ManagedExecutionFact.Present, execution));

        public Task<bool> ReportTerminalAsync(
            ManagedAgentExecution execution, AgentTerminalReport report,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task CancelAsync(
            ManagedAgentExecution execution, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class TrackingControlCarrierFactory : ILocalTransportFactory
    {
        private int connects;
        private int disposals;
        public int Connects => Volatile.Read(ref connects);
        public int Disposals => Volatile.Read(ref disposals);

        public ITransportCarrier CreateDialer(
            NodeEndpointRegistration node,
            TransportEndpointRole localRole) => new Carrier(this);

        public ITransportConnectionAcceptor CreateAcceptor(
            NodeEndpointRegistration node,
            TransportEndpointRole localRole) =>
            throw new NotSupportedException();

        private sealed class Carrier(TrackingControlCarrierFactory owner)
            : ITransportCarrier, IAsyncDisposable
        {
            public async ValueTask<ITransportConnection> ConnectAsync(
                SessionHello hello, CancellationToken cancellationToken = default)
            {
                Interlocked.Increment(ref owner.connects);
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("Unreachable.");
            }

            public ValueTask DisposeAsync()
            {
                Interlocked.Increment(ref owner.disposals);
                return ValueTask.CompletedTask;
            }
        }
    }

    private static ExtensionMetadataDto DirectTransport(int port) =>
        LocalStackOptions.TransportBinding(new LocalDirectTransportBinding(
            LocalDirectDialDirection.ControlDialsNode,
            new Uri($"ws://127.0.0.1:{port}/steward/")));

    private sealed record TestActor(string Actor) : ILocalActorContext;
}
