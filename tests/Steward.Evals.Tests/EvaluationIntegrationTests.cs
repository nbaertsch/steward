using System.Text.Json;
using Steward.Domain;
using Steward.Tasks.Abstractions;
using Steward.Workloads.Evals;

namespace Steward.Evals.Tests;

public sealed class EvaluationIntegrationTests
{
    [Fact]
    public void ThreeHundred_cases_are_deterministic_and_use_bounded_aggregation()
    {
        var input = Input(Enumerable.Range(0, 300)
            .Select(x => EvaluationCase.Create($"case-{x:D3}", new { value = x })));
        var planner = HarborPlanner();
        var workloadId = WorkloadId.New();

        var first = planner.Plan(new(workloadId, PlanRevisionId.New(), input));
        var second = planner.Plan(new(workloadId, PlanRevisionId.New(), input));
        var firstCases = first.Tasks.Where(x => x.LogicalKey.StartsWith("eval/", StringComparison.Ordinal)).ToArray();
        var secondCases = second.Tasks.Where(x => x.LogicalKey.StartsWith("eval/", StringComparison.Ordinal)).ToArray();

        Assert.Equal(300, firstCases.Length);
        Assert.Equal(firstCases.Select(x => x.TaskId), secondCases.Select(x => x.TaskId));
        Assert.All(first.Tasks, x => Assert.InRange(x.Dependencies.Count, 0, 256));
        Assert.Equal(2, first.Tasks.Count(x => x.LogicalKey.StartsWith("aggregate/00/", StringComparison.Ordinal)));
    }

    [Fact]
    public void Identical_inputs_in_different_workloads_have_distinct_task_ids()
    {
        var input = Input([EvaluationCase.Create("a", new { })]);
        var first = HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input));
        var second = HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input));

        Assert.Empty(first.Tasks.Select(x => x.TaskId).Intersect(second.Tasks.Select(x => x.TaskId)));
    }

    [Fact]
    public void Equivalent_definition_property_order_has_same_inventory_hash_and_task_ids()
    {
        var firstInventory = NormalizedHarnessInventory.Parse("""[{"caseId":"a","definition":{"z":2,"a":1}}]""");
        var secondInventory = NormalizedHarnessInventory.Parse("""[{"definition":{"a":1,"z":2},"caseId":"a"}]""");
        Assert.Equal(firstInventory.ContentHash, secondInventory.ContentHash);

        var workloadId = WorkloadId.New();
        var first = HarborPlanner().Plan(new(workloadId, PlanRevisionId.New(), Input(firstInventory.Cases)));
        var second = HarborPlanner().Plan(new(workloadId, PlanRevisionId.New(), Input(secondInventory.Cases)));
        Assert.Equal(first.Tasks.Select(x => x.TaskId), second.Tasks.Select(x => x.TaskId));
    }

    [Fact]
    public void Private_acquisition_contains_typed_identity_references_but_no_credentials()
    {
        var input = Input([EvaluationCase.Create("a", new { })]) with
        {
            IdentityCapabilities =
            [
                new("identity://github/app-installation", "source.read"),
                new("identity://packages/feed-reader", "packages.read"),
                new("identity://inference/profile", "inference.use")
            ]
        };
        var setupProfile = Setup();
        setupProfile = setupProfile with
        {
            RepositoryAcquisition = setupProfile.RepositoryAcquisition! with
                { RequiredIdentityCapabilities = ["source.read"] },
            PackageAcquisition =
            [
                setupProfile.PackageAcquisition!.Single() with
                    { RequiredIdentityCapabilities = ["packages.read"] }
            ]
        };
        var harness = new HarborEvaluationAdapter(Profile(@"C:\tools\harbor.exe") with
            { RequiredIdentityCapabilities = ["inference.use"] });
        var plan = new HarborEvaluationPlanner(harness, setupProfile)
            .Plan(new(WorkloadId.New(), PlanRevisionId.New(), input));
        var sourceSetup = plan.Tasks.Single(x => x.LogicalKey == "setup/repository").Input.CanonicalJson;
        var packageSetup = plan.Tasks.Single(x => x.LogicalKey == "setup/packages/000").Input.CanonicalJson;
        var evaluation = plan.Tasks.Single(x => x.LogicalKey.StartsWith("eval/", StringComparison.Ordinal)).Input.CanonicalJson;

        Assert.Contains("identity://github/app-installation", sourceSetup);
        Assert.DoesNotContain("identity://packages/feed-reader", sourceSetup);
        Assert.Contains("identity://packages/feed-reader", packageSetup);
        Assert.DoesNotContain("identity://github/app-installation", packageSetup);
        Assert.Contains("identity://inference/profile", evaluation);
        Assert.DoesNotContain("identity://github/app-installation", evaluation);
        Assert.DoesNotContain("identity://packages/feed-reader", evaluation);
        Assert.DoesNotContain("password", sourceSetup, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Case_resources_are_scheduler_placeable_without_host_pinning()
    {
        var resources = new EvaluationResourcePolicy(2, 4_000, 5_000, ConcurrencyUnits: 1);
        var input = Input(Enumerable.Range(0, 4).Select(x => EvaluationCase.Create($"c{x}", new { }))) with
        {
            CaseResources = resources,
            ShardPolicy = new(4, 2)
        };
        var cases = HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input)).Tasks
            .Where(x => x.LogicalKey.StartsWith("eval/", StringComparison.Ordinal)).ToArray();

        Assert.All(cases, task =>
        {
            Assert.Null(task.RequiredHostId);
            Assert.Equal(2, task.Resources.CpuCores);
            Assert.Equal(1, task.Resources.ConcurrencyUnits);
        });
        Assert.Equal(2, cases.Select(x => x.AffinityKey).Distinct().Count());
        Assert.Equal(4, HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input)).MaximumConcurrency);
    }

    [Fact]
    public void Command_is_an_argument_vector_and_shell_executables_are_rejected()
    {
        var adapter = HarborAdapter();
        var command = adapter.CreateCommand(Input([EvaluationCase.Create("a; echo bad", new { })]),
            EvaluationCase.Create("a; echo bad", new { }), 2);

        Assert.Equal(@"C:\tools\harbor.exe", command.Executable);
        Assert.Contains("a; echo bad", command.Arguments);
        Assert.DoesNotContain(command.Arguments, x => x is "-c" or "/c");
        Assert.Throws<ArgumentException>(() => new HarborEvaluationAdapter(
            Profile(@"C:\tools\run.CMD")));
    }

    [Fact]
    public void Command_replacements_are_literal_and_templates_reject_unknown_placeholders()
    {
        var input = Input([EvaluationCase.Create("{modelProfile}", new { })]);
        var command = HarborAdapter().CreateCommand(input, input.Inventory.Cases[0], 1);
        Assert.Contains("{modelProfile}", command.Arguments);

        var invalidSetup = Setup() with
        {
            RepositoryAcquisition = new(@"C:\tools\source.exe", ["{unknown}"])
        };
        Assert.Throws<ArgumentException>(() => new HarborEvaluationPlanner(HarborAdapter(), invalidSetup)
            .Plan(new(WorkloadId.New(), PlanRevisionId.New(), Input([EvaluationCase.Create("a", new { })]))));
    }

    [Fact]
    public void Missing_command_identity_capability_is_rejected()
    {
        var adapter = new HarborEvaluationAdapter(Profile(@"C:\tools\harbor.exe") with
            { RequiredIdentityCapabilities = ["inference.use"] });
        Assert.Throws<ArgumentException>(() => new HarborEvaluationPlanner(adapter, Setup())
            .Plan(new(WorkloadId.New(), PlanRevisionId.New(), Input([EvaluationCase.Create("a", new { })]))));
    }

    [Fact]
    public void Json_lines_parser_reports_progress_and_structured_result()
    {
        var parser = new JsonLinesEvaluationResultParser();
        var progress = parser.ParseProgress("""{"type":"progress","caseId":"a","fraction":0.5,"message":"half"}""");
        var result = parser.ParseResult(
            $$"""{"type":"result","caseId":"a","attemptGeneration":3,"harnessVersion":"1.2","commit":"{{RepositoryCommit}}","datasetHash":"{{DatasetHash}}","modelProfile":"model","status":"passed","score":0.9,"metrics":{"latency":12},"artifacts":["b","a"]}""",
            new(3, "1.2", RepositoryCommit, DatasetHash, "model"));

        Assert.Equal(.5, progress!.Fraction);
        Assert.Equal(3, result!.AttemptGeneration);
        Assert.Equal(0.9m, result.Score);
        Assert.Equal(["a", "b"], result.ArtifactReferences);
        Assert.Equal(64, result.ReceiptHash.Length);
    }

    [Fact]
    public void Deterministic_fake_runner_exercises_adapter_contract_without_live_harness()
    {
        var adapter = HarborAdapter();
        var input = Input([EvaluationCase.Create("fake-1", new { prompt = "hello" })]);
        var command = adapter.CreateCommand(input, input.Inventory.Cases[0], 4);
        var lines = DeterministicFakeRunner.Run(command, "fake-1", input);

        Assert.Equal("fake-1", adapter.ResultParser.ParseProgress(lines[0])!.CaseId);
        var result = adapter.ResultParser.ParseResult(lines[1],
            new(4, adapter.HarnessVersion, input.Repository.ResolvedCommit,
                input.Dataset.ContentHash, input.ModelProfileReference));
        Assert.Equal(EvaluationCaseStatus.Passed, result!.Status);
        Assert.Equal(.75m, result.Score);
    }

    [Fact]
    public void Docker_profile_emits_compose_setup_dependency()
    {
        var input = Input([EvaluationCase.Create("a", new { })]) with
        {
            Runtime = new("1.2", "setup-1", true, "compose.yaml")
        };
        var setup = Setup() with
        {
            DockerPreparation = new(@"C:\tools\docker.exe",
                ["compose", "--file", "{composeFile}", "create"])
        };
        var plan = new HarborEvaluationPlanner(HarborAdapter(), setup)
            .Plan(new(WorkloadId.New(), PlanRevisionId.New(), input));
        var compose = plan.Tasks.Single(x => x.LogicalKey == "setup/docker");
        var evaluation = plan.Tasks.Single(x => x.LogicalKey == "eval/a");

        Assert.Contains(compose.TaskId, evaluation.Dependencies);
        Assert.Equal("process", compose.TaskType);
        Assert.Contains("\"create\"", compose.Input.CanonicalJson);
        Assert.DoesNotContain("abort-on-container-exit", compose.Input.CanonicalJson);
        Assert.Contains("docker", compose.RequiredHostCapabilities);
    }

    [Theory]
    [InlineData(EvaluationFailureSignal.Http429, true, true, false, false)]
    [InlineData(EvaluationFailureSignal.Infrastructure, true, false, false, false)]
    [InlineData(EvaluationFailureSignal.DeterministicAssertion, false, false, true, false)]
    [InlineData(EvaluationFailureSignal.Setup, false, false, true, true)]
    public void Retry_classification_is_explicit(EvaluationFailureSignal signal, bool retry, bool rate,
        bool failure, bool quarantine)
    {
        var decision = EvaluationRetryPolicy.Classify(signal);
        Assert.Equal(retry, decision.RetryCase);
        Assert.Equal(rate, decision.ReportRateFeedback);
        Assert.Equal(failure, decision.IsCaseFailure);
        Assert.Equal(quarantine, decision.QuarantineSetupFingerprint);
    }

    [Fact]
    public void Resume_omits_completed_cases()
    {
        var input = Input(Enumerable.Range(0, 3).Select(x => EvaluationCase.Create($"c{x}", new { })));
        var completed = Result("c1", 1);
        var plan = HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input,
            [new(completed, "portable://results/c1.json")]));

        Assert.DoesNotContain(plan.Tasks, x => x.LogicalKey == "eval/c1");
        Assert.Contains(plan.Tasks, x => x.LogicalKey == "eval/c0");
        Assert.Contains(plan.Tasks, x => x.LogicalKey.StartsWith("aggregate/receipts/", StringComparison.Ordinal));
    }

    [Fact]
    public void Reducer_selects_latest_generation_and_is_reproducible()
    {
        var context0 = new EvaluationResultContext(0, "1.2", RepositoryCommit, DatasetHash, "model");
        var context1 = context0 with { AttemptGeneration = 1 };
        var old = EvaluationCaseResult.Create("a", context0, EvaluationCaseStatus.Error, null,
            failureClassification: EvaluationFailureClassification.Infrastructure);
        var latest = EvaluationCaseResult.Create("a", context1, EvaluationCaseStatus.Passed, 1);
        var other = EvaluationCaseResult.Create("b", context0, EvaluationCaseStatus.Passed, .5m);

        var first = EvaluationResultReducer.Reduce([old, other, latest], ["a", "b"]);
        var second = EvaluationResultReducer.Reduce([latest, old, other], ["b", "a"]);

        Assert.Equal(2, first.Cases.Length);
        Assert.Equal(1, first.Cases.Single(x => x.CaseId == "a").AttemptGeneration);
        Assert.Equal(first.ManifestHash, second.ManifestHash);
    }

    [Fact]
    public void Unsupported_harness_version_is_rejected()
    {
        var input = Input([EvaluationCase.Create("a", new { })]) with
        {
            Runtime = new("9.9", "setup-1")
        };
        Assert.Throws<NotSupportedException>(() =>
            HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input)));
    }

    [Fact]
    public void Malformed_empty_duplicate_and_unbounded_inventories_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => NormalizedHarnessInventory.Parse("{"));
        Assert.Throws<ArgumentException>(() => new NormalizedHarnessInventory([]));
        Assert.Throws<ArgumentException>(() => new NormalizedHarnessInventory(
            [EvaluationCase.Create("a", new { }), EvaluationCase.Create("a", new { })]));
        Assert.Throws<ArgumentException>(() => new NormalizedHarnessInventory(
            Enumerable.Range(0, EvaluationLimits.MaximumCases + 1)
                .Select(x => EvaluationCase.Create(x.ToString(), new { }))));
    }

    [Theory]
    [InlineData("http://example.test/repo.git")]
    [InlineData("https://user@example.test/repo.git")]
    [InlineData("https://example.test/repo.git?token=x")]
    [InlineData("https://example.test/repo.git#main")]
    public void Source_URI_must_be_plain_https(string value)
    {
        var source = new EvaluationSource(new Uri(value), "main", RepositoryCommit);
        Assert.Throws<ArgumentException>(() => source.Validate("Repository"));
    }

    [Fact]
    public void Source_commit_kind_requires_full_configured_hash()
    {
        Assert.Throws<ArgumentException>(() =>
            new EvaluationSource(new Uri("https://example.test/a.git"), "main", "abc").Validate("Repository"));
        new EvaluationSource(new Uri("https://example.test/a.git"), "main",
            new string('a', 64), CommitKind: SourceCommitKind.GitSha256).Validate("Repository");
    }

    [Theory]
    [InlineData("sha256:short")]
    [InlineData("dataset")]
    [InlineData("md5:0123456789abcdef0123456789abcdef")]
    public void Dataset_digest_is_algorithm_prefixed_and_bounded(string digest)
    {
        Assert.Throws<ArgumentException>(() => new EvaluationDataset("set", digest).Validate());
    }

    [Theory]
    [InlineData("identity://github/source")]
    [InlineData("identity://azure/packages")]
    public void Typed_identity_references_are_accepted(string reference) =>
        new IdentityCapabilityReference(reference, "source.read").Validate();

    [Theory]
    [InlineData("secret-name")]
    [InlineData("identity://user@example.test/source")]
    [InlineData("identity://github/source?token=x")]
    [InlineData("identity://github/source#fragment")]
    public void Untyped_or_decorated_identity_references_are_rejected(string reference) =>
        Assert.Throws<ArgumentException>(() => new IdentityCapabilityReference(reference, "source.read").Validate());

    [Theory]
    [InlineData("../outside")]
    [InlineData("C:\\outside")]
    [InlineData("\\\\server\\share")]
    [InlineData("NUL.txt")]
    [InlineData("https://example.test/result")]
    public void Unsafe_result_locations_are_rejected(string location) =>
        Assert.Throws<ArgumentException>(() => new EvaluationLocations(location, "output").Validate());

    [Theory]
    [InlineData("results/cases")]
    [InlineData("portable://results/run-1")]
    public void Safe_result_locations_are_accepted(string location) =>
        new EvaluationLocations(location, "output").Validate();

    [Fact]
    public void Conflicting_same_generation_receipts_are_rejected()
    {
        var first = Result("a", 2);
        var second = EvaluationCaseResult.Create("a",
            new(2, "1.2", RepositoryCommit, DatasetHash, "inference-profile://test"),
            EvaluationCaseStatus.Passed, .5m);
        Assert.Throws<ArgumentException>(() => EvaluationResultReducer.Reduce([first, second], ["a"]));
    }

    [Fact]
    public void Final_reduction_rejects_missing_or_extra_cases()
    {
        Assert.Throws<ArgumentException>(() => EvaluationResultReducer.Reduce([Result("a", 0)], ["a", "b"]));
        Assert.Throws<ArgumentException>(() => EvaluationResultReducer.Reduce(
            [Result("a", 0), Result("b", 0)], ["a"]));
    }

    [Fact]
    public async Task Evaluation_runner_executes_vector_and_exposes_validated_result_and_events()
    {
        var input = Input([EvaluationCase.Create("runner-case", new { })]);
        var plan = HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input));
        var node = plan.Tasks.Single(x => x.LogicalKey == "eval/runner-case");
        var output = JsonSerializer.Serialize(new
        {
            type = "progress", caseId = "runner-case", fraction = .5
        }) + "\n" + JsonSerializer.Serialize(new
        {
            type = "result", caseId = "runner-case", attemptGeneration = 3, harnessVersion = "1.2",
            commit = RepositoryCommit, datasetHash = DatasetHash, modelProfile = "inference-profile://test",
            status = "passed", score = 1, artifacts = new[] { "artifacts/result.json" }
        }) + "\n";
        var executor = new FakeProcessExecutor(output);
        var taskType = new EvaluationRunnerTaskType(executor, new FakeRunnerStateStore(), new FakeRateFeedbackSink());
        using var document = JsonDocument.Parse(node.Input.CanonicalJson);
        var context = new TaskExecutionContext(TaskAttemptId.New(), 3, Environment.CurrentDirectory,
            document.RootElement.Clone());

        var execution = await taskType.StartAsync(context, default);
        var observation = await taskType.ObserveAsync(execution, default);
        var outcome = await taskType.ReadOutcomeAsync(execution);

        Assert.Equal(ExecutionState.Exited, observation.State);
        Assert.Equal(0, observation.ExitCode);
        Assert.Equal("runner-case", outcome.Result!.CaseId);
        Assert.True(outcome.Result.HasValidReceipt());
        Assert.Contains(outcome.Events, x => x is TaskProgressEvent);
        Assert.Contains(outcome.Events, x => x is TaskArtifactEvent);
        Assert.Equal(@"C:\tools\harbor.exe", executor.Request!.ApplicationPath);
        Assert.Contains("3", executor.Request.Arguments);
        Assert.DoesNotContain(EvaluationHarnessAdapterBase.AttemptGenerationToken, executor.Request.Arguments);
        Assert.DoesNotContain(executor.Request.Arguments, x => x is "-c" or "/c");
    }

    [Fact]
    public async Task Evaluation_runner_exposes_429_as_rate_feedback_not_case_failure()
    {
        var input = Input([EvaluationCase.Create("throttled", new { })]);
        var node = HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input)).Tasks
            .Single(x => x.LogicalKey == "eval/throttled");
        var retryAfter = DateTimeOffset.UtcNow.AddMinutes(1);
        var executor = new FakeProcessExecutor(JsonSerializer.Serialize(new
        {
            type = "failure", signal = "http429", retryAfter
        }) + "\n");
        var sink = new FakeRateFeedbackSink();
        var taskType = new EvaluationRunnerTaskType(executor, new FakeRunnerStateStore(), sink);
        using var document = JsonDocument.Parse(node.Input.CanonicalJson);
        var context = new TaskExecutionContext(TaskAttemptId.New(), 0, Environment.CurrentDirectory,
            document.RootElement.Clone());

        var execution = await taskType.StartAsync(context, default);
        _ = await taskType.ObserveAsync(execution, default);
        var decision = (await taskType.ReadOutcomeAsync(execution)).Failure!;

        Assert.True(decision.ReportRateFeedback);
        Assert.True(decision.RetryCase);
        Assert.False(decision.IsCaseFailure);
        Assert.Equal("inference", sink.Scope);
        Assert.Equal(retryAfter, sink.RetryAfter);
        Assert.Null((await taskType.ReadOutcomeAsync(execution)).TerminalReceipt);
    }

    [Fact]
    public async Task Runner_recovers_mid_line_without_duplicate_progress()
    {
        var (node, context, fullOutput) = RunnerFixture("recover-mid", 5);
        var split = fullOutput.IndexOf("\"result\"", StringComparison.Ordinal) + 4;
        var executor = new FakeProcessExecutor(fullOutput[..split]);
        var store = new FakeRunnerStateStore();
        var first = new EvaluationRunnerTaskType(executor, store, new FakeRateFeedbackSink());
        var execution = await first.StartAsync(context, default);
        var before = await first.ReadOutcomeAsync(execution);
        Assert.Single(before.Events);

        executor.Output = fullOutput;
        var recovered = new EvaluationRunnerTaskType(executor, store, new FakeRateFeedbackSink());
        await recovered.RegisterRecoveredExecutionAsync(context, execution);
        var observation = await recovered.ObserveAsync(execution, default);
        var after = await recovered.ReadOutcomeAsync(execution);

        Assert.Equal(0, observation.ExitCode);
        Assert.Single(after.Events.OfType<TaskProgressEvent>());
        Assert.NotNull(after.Result);
    }

    [Fact]
    public async Task Runner_recovers_parsed_result_before_terminal_observation()
    {
        var (node, context, output) = RunnerFixture("recover-result", 6);
        var executor = new FakeProcessExecutor(output);
        var store = new FakeRunnerStateStore();
        var first = new EvaluationRunnerTaskType(executor, store, new FakeRateFeedbackSink());
        var execution = await first.StartAsync(context, default);
        var before = await first.ReadOutcomeAsync(execution);
        Assert.NotNull(before.TerminalReceipt);

        var recovered = new EvaluationRunnerTaskType(executor, store, new FakeRateFeedbackSink());
        await recovered.RecoverAsync(context, execution);
        var observation = await recovered.ObserveAsync(execution, default);
        var after = await recovered.ReadOutcomeAsync(execution);

        Assert.Equal(0, observation.ExitCode);
        Assert.Equal(before.TerminalReceipt, after.TerminalReceipt);
        Assert.Single(after.Events.OfType<TaskProgressEvent>());
        Assert.Single(after.Events.OfType<TaskArtifactEvent>());
    }

    [Fact]
    public async Task Runner_cancels_a_no_newline_line_over_one_mebibyte()
    {
        var (node, context, _) = RunnerFixture("oversized", 0);
        var executor = new FakeProcessExecutor(new string('x', EvaluationLimits.MaximumJsonLineBytes + 1));
        var taskType = new EvaluationRunnerTaskType(executor, new FakeRunnerStateStore(), new FakeRateFeedbackSink());
        var execution = await taskType.StartAsync(context, default);
        _ = await taskType.ReadOutcomeAsync(execution);
        var outcome = await taskType.ReadOutcomeAsync(execution);

        Assert.True(executor.Cancelled);
        Assert.Equal(EvaluationRunnerErrorCode.OutputLineTooLarge, outcome.ErrorCode);
        Assert.Null(outcome.TerminalReceipt);
    }

    [Theory]
    [InlineData("numeric-type")]
    [InlineData("numeric-failure-classification")]
    [InlineData("undefined-status")]
    [InlineData("undefined-signal")]
    public async Task Malformed_parser_kinds_are_managed_and_sanitized(string kind)
    {
        var (_, context, _) = RunnerFixture("malformed", 0);
        var line = kind switch
        {
            "numeric-type" => """{"type":42,"credential":"must-not-leak"}""",
            "undefined-signal" => """{"type":"failure","signal":"999","credential":"must-not-leak"}""",
            "numeric-failure-classification" => ResultLine("malformed", 0,
                "\"status\":\"failed\",\"failureClassification\":999,\"credential\":\"must-not-leak\","),
            "undefined-status" => ResultLine("malformed", 0,
                "\"status\":\"999\",\"failureClassification\":\"task\",\"credential\":\"must-not-leak\","),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        var executor = new FakeProcessExecutor(line + "\n");
        var taskType = new EvaluationRunnerTaskType(
            executor, new FakeRunnerStateStore(), new FakeRateFeedbackSink());
        var execution = await taskType.StartAsync(context, default);

        var observation = await taskType.ObserveAsync(execution, default);
        var outcome = await taskType.ReadOutcomeAsync(execution);

        Assert.True(executor.Cancelled);
        Assert.Equal(EvaluationRunnerErrorCode.MalformedOutput, outcome.ErrorCode);
        Assert.Equal("MalformedOutput", observation.Detail);
        Assert.DoesNotContain("must-not-leak", observation.Detail);
        Assert.Null(outcome.TerminalReceipt);
    }

    [Fact]
    public async Task Recovery_creates_missing_initial_state_and_replays_from_zero()
    {
        var (_, context, output) = RunnerFixture("launch-gap", 7);
        var executor = new FakeProcessExecutor(output);
        var store = new FakeRunnerStateStore();
        var recovered = new EvaluationRunnerTaskType(executor, store, new FakeRateFeedbackSink());
        var handle = new FakeExecution(context.AttemptId, context.Generation);

        await recovered.RegisterRecoveredExecutionAsync(context, handle);
        var observation = await recovered.ObserveAsync(handle, default);
        var outcome = await recovered.ReadOutcomeAsync(handle);

        Assert.Equal(0, observation.ExitCode);
        Assert.NotNull(outcome.Result);
        Assert.True(store.Contains(context.AttemptId, context.Generation));
    }

    [Fact]
    public async Task Cleanup_retains_state_until_downstream_receipt_is_committed()
    {
        var (_, context, output) = RunnerFixture("retain", 1);
        var store = new FakeRunnerStateStore();
        var taskType = new EvaluationRunnerTaskType(
            new FakeProcessExecutor(output), store, new FakeRateFeedbackSink());
        var execution = await taskType.StartAsync(context, default);
        _ = await taskType.ObserveAsync(execution, default);

        var cleanup = await taskType.CleanupAsync(context, default);
        Assert.True(cleanup.Completed);
        Assert.True(store.Contains(context.AttemptId, context.Generation));

        await taskType.ReleaseDurableStateAsync(context.AttemptId, context.Generation);
        Assert.False(store.Contains(context.AttemptId, context.Generation));
    }

    [Fact]
    public async Task Durable_result_is_committed_before_runner_state_is_released()
    {
        var (taskId, context, output) = RunnerFixture("commit-before-release", 1);
        var store = new FakeRunnerStateStore();
        var writer = new RecordingResultWriter();
        var taskType = new EvaluationRunnerTaskType(
            new FakeProcessExecutor(output), store, new FakeRateFeedbackSink(),
            resultWriter: writer);
        var execution = await taskType.StartAsync(context, default);
        _ = await taskType.ObserveAsync(execution, default);

        var receipt = await taskType.CommitTerminalResultAsync(execution, taskId.TaskId, default);
        Assert.NotNull(receipt);
        Assert.Equal(taskId.TaskId, writer.TaskId);
        Assert.NotNull(writer.Result);
        Assert.True(store.Contains(context.AttemptId, context.Generation));

        await taskType.ReleaseDurableStateAsync(context.AttemptId, context.Generation);
        Assert.False(store.Contains(context.AttemptId, context.Generation));
    }

    [Fact]
    public void Parser_rejects_result_with_mismatched_immutable_context()
    {
        var parser = new JsonLinesEvaluationResultParser();
        var line = JsonSerializer.Serialize(new
        {
            type = "result", caseId = "a", attemptGeneration = 1, harnessVersion = "wrong",
            commit = RepositoryCommit, datasetHash = DatasetHash, modelProfile = "inference-profile://test",
            status = "passed"
        });
        Assert.Throws<FormatException>(() => parser.ParseResult(line,
            new(1, "1.2", RepositoryCommit, DatasetHash, "inference-profile://test")));
    }

    [Fact]
    public void Parser_rejects_unbounded_or_invalid_structured_values()
    {
        var parser = new JsonLinesEvaluationResultParser();
        Assert.Throws<FormatException>(() => parser.ParseProgress(JsonSerializer.Serialize(new
        {
            type = "progress", caseId = "a", fraction = .5,
            message = new string('x', EvaluationLimits.MaximumProgressMessageLength + 1)
        })));
        var context = new EvaluationResultContext(0, "1.2", RepositoryCommit, DatasetHash,
            "inference-profile://test");
        Assert.Throws<FormatException>(() => parser.ParseResult(
            $$"""{"type":"result","caseId":"a","attemptGeneration":0,"harnessVersion":"1.2","commit":"{{RepositoryCommit}}","datasetHash":"{{DatasetHash}}","modelProfile":"inference-profile://test","status":"passed","metrics":{"overflow":1e1000},"artifacts":[]}""",
            context));
        Assert.Throws<FormatException>(() => parser.ParseResult(
            $$"""{"type":"result","caseId":"a","attemptGeneration":0,"harnessVersion":"1.2","commit":"{{RepositoryCommit}}","datasetHash":"{{DatasetHash}}","modelProfile":"inference-profile://test","status":"passed","metrics":{},"artifacts":{} }""",
            context));
    }

    [Fact]
    public void Resume_rejects_wrong_context_or_invalid_receipt()
    {
        var input = Input([EvaluationCase.Create("a", new { })]);
        var wrongContext = EvaluationCaseResult.Create("a",
            new(0, "1.2", new string('a', 40), DatasetHash, "inference-profile://test"),
            EvaluationCaseStatus.Passed, 1);
        Assert.Throws<ArgumentException>(() => HarborPlanner().Plan(
            new(WorkloadId.New(), PlanRevisionId.New(), input,
                [new(wrongContext, "portable://results/a")])));
        Assert.Throws<ArgumentException>(() => HarborPlanner().Plan(
            new(WorkloadId.New(), PlanRevisionId.New(), input,
                [new(Result("a", 0) with { ReceiptHash = new string('0', 64) }, "portable://results/a")])));
    }

    [Fact]
    public async Task Reducer_task_resolves_validated_portable_receipts()
    {
        var input = Input([EvaluationCase.Create("done", new { })]);
        var completed = Result("done", 2);
        var plan = HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input,
            [new(completed, "portable://results/done")]));
        var node = plan.Tasks.Single(x => x.LogicalKey.StartsWith("aggregate/receipts/", StringComparison.Ordinal));
        var store = new FakeResultStore(completed);
        var taskType = new EvaluationReducerTaskType(store);
        using var document = JsonDocument.Parse(node.Input.CanonicalJson);
        var context = new TaskExecutionContext(TaskAttemptId.New(), 0, Environment.CurrentDirectory,
            document.RootElement.Clone());

        var execution = await taskType.StartAsync(context, default);
        var observation = await taskType.ObserveAsync(execution, default);

        Assert.Equal(0, observation.ExitCode);
        Assert.Equal(completed.ReceiptHash, taskType.GetOutcome(execution).Manifest!.Cases.Single().ReceiptHash);

        var recoveredType = new EvaluationReducerTaskType(store);
        var recovered = await recoveredType.RecoverAsync(context);
        Assert.Equal(0, (await recoveredType.ObserveAsync(recovered, default)).ExitCode);
        Assert.Equal(1, store.WriteCount);
    }

    [Fact]
    public void Saber_uses_its_own_versioned_profile()
    {
        var adapter = new SaberEvaluationAdapter(new("saber", "1.2", "profile-2",
            @"C:\tools\saber.exe", ["run", "{caseId}", "--dataset", "{datasetHash}"]));
        var planner = new SaberEvaluationPlanner(adapter, Setup());
        var plan = planner.Plan(new(WorkloadId.New(), PlanRevisionId.New(), Input([EvaluationCase.Create("a", new { })])));
        Assert.Equal("saber-evaluation", plan.PlannerType);
    }

    [Fact]
    public void Optional_live_fixture_is_explicitly_opt_in()
    {
        var enabled = string.Equals(Environment.GetEnvironmentVariable("STEWARD_RUN_LIVE_EVAL_FIXTURES"), "1",
            StringComparison.Ordinal);
        if (!enabled) return;
        Assert.False(string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("STEWARD_EVAL_FIXTURE")));
    }

    private static HarborEvaluationPlanner HarborPlanner() => new(HarborAdapter(), Setup());

    private static HarborEvaluationAdapter HarborAdapter() => new(Profile(@"C:\tools\harbor.exe"));

    private static HarnessCommandProfile Profile(string executable) =>
        new("harbor", "1.2", "profile-1", executable,
            ["run", "--case", "{caseId}", "--dataset-hash", "{datasetHash}", "--model", "{modelProfile}",
             "--generation", "{generation}"]);

    private static EvaluationSetupProfile Setup() => new("setup-profile-1",
        new(@"C:\tools\source.exe", ["acquire", "{uri}", "{resolvedCommit}", "harness"]),
        new(@"C:\tools\source.exe", ["acquire", "{uri}", "{resolvedCommit}", "repository"]),
        [new(@"C:\tools\packages.exe", ["restore", "--locked"])]);

    private static EvaluationWorkloadInput Input(IEnumerable<EvaluationCase> cases) => new(
        new(new Uri("https://example.test/harbor.git"), "v1.2", HarnessCommit),
        new(new Uri("https://example.test/repository.git"), "main", RepositoryCommit),
        new("eval-set-v1", DatasetHash),
        "standard",
        [],
        "inference-profile://test",
        new(16, 50),
        new("results/eval.jsonl", "artifacts/"),
        new("1.2", "setup-1"),
        [],
        new(cases));

    private static class DeterministicFakeRunner
    {
        internal static string[] Run(EvaluationCommand command, string caseId, EvaluationWorkloadInput input)
        {
            Assert.Contains(caseId, command.Arguments);
            return
            [
                JsonSerializer.Serialize(new { type = "progress", caseId, fraction = .5, message = "fake" }),
                JsonSerializer.Serialize(new
                {
                    type = "result", caseId, attemptGeneration = 4, harnessVersion = "1.2",
                    commit = input.Repository.ResolvedCommit, datasetHash = input.Dataset.ContentHash,
                    modelProfile = input.ModelProfileReference, status = "passed", score = .75m,
                    metrics = new { deterministic = 1 }, artifacts = new[] { "fake/result.json" }
                })
            ];
        }

    }

    private const string RepositoryCommit = "fedcba9876543210fedcba9876543210fedcba98";
    private const string HarnessCommit = "0123456789abcdef0123456789abcdef01234567";
    private const string DatasetHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static EvaluationCaseResult Result(string caseId, int generation) =>
        EvaluationCaseResult.Create(caseId,
            new(generation, "1.2", RepositoryCommit, DatasetHash, "inference-profile://test"),
            EvaluationCaseStatus.Passed, 1);

    private static (Steward.Scheduling.TaskPlanNode Node, TaskExecutionContext Context, string Output)
        RunnerFixture(string caseId, int generation)
    {
        var input = Input([EvaluationCase.Create(caseId, new { })]);
        var node = HarborPlanner().Plan(new(WorkloadId.New(), PlanRevisionId.New(), input)).Tasks
            .Single(x => x.LogicalKey == $"eval/{caseId}");
        using var document = JsonDocument.Parse(node.Input.CanonicalJson);
        var context = new TaskExecutionContext(TaskAttemptId.New(), generation, Environment.CurrentDirectory,
            document.RootElement.Clone());
        var output = JsonSerializer.Serialize(new { type = "progress", caseId, fraction = .25 }) + "\n" +
            JsonSerializer.Serialize(new
            {
                type = "result", caseId, attemptGeneration = generation, harnessVersion = "1.2",
                commit = RepositoryCommit, datasetHash = DatasetHash, modelProfile = "inference-profile://test",
                status = "passed", score = 1, artifacts = new[] { $"artifacts/{caseId}.json" }
            }) + "\n";
        return (node, context, output);
    }

    private static string ResultLine(string caseId, int generation, string replacement)
        => $$"""{"type":"result","caseId":"{{caseId}}","attemptGeneration":{{generation}},"harnessVersion":"1.2","commit":"{{RepositoryCommit}}","datasetHash":"{{DatasetHash}}","modelProfile":"inference-profile://test",{{replacement}}"metrics":{},"artifacts":[]}""";

    private sealed record FakeExecution(TaskAttemptId AttemptId, int Generation) : IExecutionHandle
    {
        public int ProcessId => 42;
        public long ProcessCreationTimeUtcTicks => 1;
    }

    private sealed class FakeProcessExecutor(string output) : IProcessExecutor
    {
        internal string Output { get; set; } = output;
        internal ProcessLaunchRequest? Request { get; private set; }
        internal bool Cancelled { get; private set; }

        public ValueTask<IExecutionHandle> StartAsync(ProcessLaunchRequest request, CancellationToken cancellationToken)
        {
            Request = request;
            return ValueTask.FromResult<IExecutionHandle>(new FakeExecution(request.AttemptId, request.Generation));
        }

        public ValueTask<ExecutionObservation> ObserveAsync(IExecutionHandle execution, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new ExecutionObservation(ExecutionState.Exited, 0));

        public ValueTask<SpoolRead> ReadOutputAsync(IExecutionHandle execution, string stream, long offset,
            int maximumBytes, CancellationToken cancellationToken)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(Output);
            var count = Math.Min(maximumBytes, bytes.Length - checked((int)offset));
            var data = bytes.AsMemory(checked((int)offset), count);
            return ValueTask.FromResult(new SpoolRead(
                new(stream, "fake", offset + count, bytes.Length, false), data));
        }

        public ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken) =>
            Cancel();

        public ValueTask<IExecutionHandle> RecoverAsync(TaskAttemptId attemptId, int generation,
            string currentBootId, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IExecutionHandle>(new FakeExecution(attemptId, generation));

        private ValueTask Cancel()
        {
            Cancelled = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeRunnerStateStore : IRunnerStateStore
    {
        private readonly Dictionary<(TaskAttemptId, int), EvaluationRunnerState> states = [];

        public ValueTask<EvaluationRunnerState?> LoadAsync(
            TaskAttemptId attemptId, int generation, CancellationToken cancellationToken) =>
            ValueTask.FromResult(states.GetValueOrDefault((attemptId, generation)));

        public ValueTask SaveAsync(EvaluationRunnerState state, CancellationToken cancellationToken)
        {
            states[(state.AttemptId, state.Generation)] = state;
            return ValueTask.CompletedTask;
        }

        public ValueTask DeleteAsync(TaskAttemptId attemptId, int generation, CancellationToken cancellationToken)
        {
            states.Remove((attemptId, generation));
            return ValueTask.CompletedTask;
        }

        internal bool Contains(TaskAttemptId attemptId, int generation) =>
            states.ContainsKey((attemptId, generation));
    }

    private sealed class FakeRateFeedbackSink : IEvaluationRateFeedbackSink
    {
        internal string? Scope { get; private set; }
        internal DateTimeOffset? RetryAfter { get; private set; }

        public ValueTask ReportThrottleAsync(
            string scope, DateTimeOffset retryAfter, CancellationToken cancellationToken)
        {
            Scope = scope;
            RetryAfter = retryAfter;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeResultStore(EvaluationCaseResult result) : IEvaluationResultStore
    {
        private EvaluationManifestReceipt? manifest;
        internal int WriteCount { get; private set; }

        public ValueTask<IReadOnlyList<EvaluationCaseResult>> ReadTaskResultsAsync(
            TaskId taskId, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<EvaluationCaseResult>>([]);

        public ValueTask<EvaluationCaseResult> ReadPortableResultAsync(
            string reference, CancellationToken cancellationToken) => ValueTask.FromResult(result);

        public ValueTask<EvaluationManifestReceipt?> ReadManifestAsync(
            string location, string manifestKey, CancellationToken cancellationToken) =>
            ValueTask.FromResult(manifest);

        public ValueTask<EvaluationManifestReceipt> WriteManifestAsync(
            string location, string manifestKey, EvaluationExportManifest value, CancellationToken cancellationToken)
        {
            WriteCount++;
            manifest = new("artifacts/manifest.json", value.ManifestHash, value);
            return ValueTask.FromResult(manifest);
        }
    }

    private sealed class RecordingResultWriter : IEvaluationTaskResultWriter
        {
            public TaskId? TaskId { get; private set; }
            public EvaluationCaseResult? Result { get; private set; }

            public ValueTask RecordTaskResultAsync(
                TaskId taskId,
                EvaluationCaseResult result,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                TaskId = taskId;
                Result = result;
                return ValueTask.CompletedTask;
        }
    }
}
