using System.Collections.Immutable;
using System.Text.Json;
using Steward.Domain;
using Steward.Scheduling;

namespace Steward.Workloads.Evals;

public sealed record SetupCommandTemplate(
    string Executable,
    IReadOnlyList<string> Arguments,
    string? WorkingDirectory = null,
    IReadOnlyList<string>? RequiredIdentityCapabilities = null)
{
    internal void Validate()
    {
        if (!Path.IsPathFullyQualified(Executable)) throw new ArgumentException("Setup executable must be an absolute path.");
        if (new[] { ".cmd", ".bat", ".ps1", ".sh" }.Contains(Path.GetExtension(Executable), StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("Setup executable cannot be a shell script.");
        if (Arguments.Count > 128) throw new ArgumentException("Setup command has too many arguments.");
        if (WorkingDirectory is not null && (string.IsNullOrWhiteSpace(WorkingDirectory) ||
            Path.IsPathFullyQualified(WorkingDirectory) || WorkingDirectory.Split('/', '\\').Contains("..")))
            throw new ArgumentException("Setup working directory must be workspace-relative.");
        if ((RequiredIdentityCapabilities ?? []).Any(string.IsNullOrWhiteSpace) ||
            (RequiredIdentityCapabilities ?? []).Distinct(StringComparer.Ordinal).Count() !=
            (RequiredIdentityCapabilities?.Count ?? 0))
            throw new ArgumentException("Setup identity capability names must be non-empty and unique.");
    }
}

public sealed record EvaluationSetupProfile(
    string ProfileVersion,
    SetupCommandTemplate? HarnessAcquisition,
    SetupCommandTemplate? RepositoryAcquisition,
    IReadOnlyList<SetupCommandTemplate>? PackageAcquisition = null,
    SetupCommandTemplate? DockerPreparation = null,
    SetupCommandTemplate? RegisteredSourceValidation = null,
    bool HarnessOwnsDockerLifecycle = false)
{
    public void Validate(EvaluationWorkloadInput input)
    {
        EvaluationSource.Required(ProfileVersion, "Setup profile version");
        if (input.Harness.Uri is not null && HarnessAcquisition is null)
            throw new ArgumentException("Harness URI acquisition requires an injected setup command profile.");
        if (input.Repository.Uri is not null && RepositoryAcquisition is null)
            throw new ArgumentException("Repository URI acquisition requires an injected setup command profile.");
        if ((input.Harness.Uri is null || input.Repository.Uri is null) && RegisteredSourceValidation is null)
            throw new ArgumentException("Registered local sources require an injected validation command profile.");
        HarnessAcquisition?.Validate();
        RepositoryAcquisition?.Validate();
        RegisteredSourceValidation?.Validate();
        foreach (var command in PackageAcquisition ?? []) command.Validate();
        DockerPreparation?.Validate();
        if (DockerPreparation is not null && HarnessOwnsDockerLifecycle)
            throw new ArgumentException("Docker preparation and harness-owned Docker lifecycle are mutually exclusive.");
        if (input.Runtime.RequiresDocker && DockerPreparation is null && !HarnessOwnsDockerLifecycle)
            throw new ArgumentException("Docker workloads require finite preparation or an explicit harness-owned lifecycle.");
        foreach (var (command, name) in Commands())
            EvaluationIdentity.SelectRequired(input.IdentityCapabilities,
                command.RequiredIdentityCapabilities ?? [], name);

        IEnumerable<(SetupCommandTemplate Command, string Name)> Commands()
        {
            if (input.Harness.Uri is not null && HarnessAcquisition is not null)
                yield return (HarnessAcquisition, "Harness acquisition");
            if (input.Repository.Uri is not null && RepositoryAcquisition is not null)
                yield return (RepositoryAcquisition, "Repository acquisition");
            if ((input.Harness.Uri is null || input.Repository.Uri is null) && RegisteredSourceValidation is not null)
                yield return (RegisteredSourceValidation, "Local source validation");
            if (input.Runtime.RequiresDocker && !HarnessOwnsDockerLifecycle && DockerPreparation is not null)
                yield return (DockerPreparation, "Docker preparation");
            foreach (var command in PackageAcquisition ?? []) yield return (command, "Package acquisition");
        }
    }
}

public abstract class EvaluationPlannerBase
{
    private const string PlannerVersionValue = "1.0";
    private readonly IEvaluationHarnessAdapter adapter;
    private readonly EvaluationSetupProfile setupProfile;

    protected EvaluationPlannerBase(IEvaluationHarnessAdapter adapter, EvaluationSetupProfile setupProfile, string expectedHarness)
    {
        this.adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        ArgumentNullException.ThrowIfNull(setupProfile);
        this.setupProfile = setupProfile with
        {
            PackageAcquisition = setupProfile.PackageAcquisition?.Select(Snapshot).ToImmutableArray(),
            HarnessAcquisition = setupProfile.HarnessAcquisition is null ? null : Snapshot(setupProfile.HarnessAcquisition),
            RepositoryAcquisition = setupProfile.RepositoryAcquisition is null ? null : Snapshot(setupProfile.RepositoryAcquisition),
            DockerPreparation = setupProfile.DockerPreparation is null ? null : Snapshot(setupProfile.DockerPreparation),
            RegisteredSourceValidation = setupProfile.RegisteredSourceValidation is null
                ? null : Snapshot(setupProfile.RegisteredSourceValidation)
        };
        if (!string.Equals(adapter.HarnessName, expectedHarness, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"The {expectedHarness} planner requires a {expectedHarness} adapter.", nameof(adapter));
    }

    private static SetupCommandTemplate Snapshot(SetupCommandTemplate command) =>
        command with
        {
            Arguments = command.Arguments.ToImmutableArray(),
            RequiredIdentityCapabilities = command.RequiredIdentityCapabilities?.ToImmutableArray()
        };

    public WorkloadPlan Plan(EvaluationPlanRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Input);
        request.Input.Validate();
        var input = request.Input.Snapshot();
        adapter.Validate(input);
        setupProfile.Validate(input);
        var expectedContext = new EvaluationResultContext(0, adapter.HarnessVersion, request.Input.Repository.ResolvedCommit,
            request.Input.Dataset.ContentHash, request.Input.ModelProfileReference);
        var completedResults = request.CompletedResults?.ToArray() ?? [];
        foreach (var completedResult in completedResults)
            completedResult.Validate(expectedContext with { AttemptGeneration = completedResult.Result.AttemptGeneration });
        if (completedResults.Select(x => x.Result.CaseId).Distinct(StringComparer.Ordinal).Count() != completedResults.Length)
            throw new ArgumentException("Completed results must contain at most one selected receipt per case.", nameof(request));
        var completed = completedResults.Select(x => x.Result.CaseId).ToHashSet(StringComparer.Ordinal);
        var inventoryIds = input.Inventory.Cases.Select(x => x.CaseId).ToHashSet(StringComparer.Ordinal);
        if (completed.Any(x => !inventoryIds.Contains(x)))
            throw new ArgumentException("Completed case IDs must exist in the immutable inventory.", nameof(request));

        var selectedCases = input.Inventory.Cases.Where(x => MatchesFilters(x.CaseId, input.TaskFilters)).ToArray();
        if (selectedCases.Length == 0) throw new ArgumentException("Task filters selected no evaluation cases.", nameof(request));
        var selectedIds = selectedCases.Select(x => x.CaseId).ToHashSet(StringComparer.Ordinal);
        if (completed.Any(x => !selectedIds.Contains(x)))
            throw new ArgumentException("Completed results must belong to the selected case set.", nameof(request));
        var fingerprint = EvaluationHash.Sha256($"{request.WorkloadId}\n{InputFingerprint(input)}");
        var nodes = new List<TaskPlanNode>();
        var setupIds = AddSetupTasks(nodes, input, fingerprint);
        var pendingCases = selectedCases.Where(x => !completed.Contains(x.CaseId)).ToArray();
        var caseIds = new List<TaskId>();
        var selectedOrdinals = selectedCases.Select((item, index) => (item.CaseId, index))
            .ToDictionary(x => x.CaseId, x => x.index, StringComparer.Ordinal);
        var replicaCount = input.ReplicaCount;
        foreach (var evaluationCase in pendingCases)
        {
            var command = adapter.CreateCommandTemplate(input, evaluationCase);
            var baseShard = selectedOrdinals[evaluationCase.CaseId] / input.ShardPolicy.PreferredCasesPerHost;
            for (var replica = 0; replica < replicaCount; replica++)
            {
                var logicalKey = replicaCount == 1
                    ? $"eval/{EscapeKey(evaluationCase.CaseId)}"
                    : $"eval/{EscapeKey(evaluationCase.CaseId)}/r{replica}";
                var taskId = Id(fingerprint, logicalKey);
                caseIds.Add(taskId);
                // Distribute replicas of the same case to different shards for node diversity
                var shard = replicaCount == 1
                    ? baseShard
                    : baseShard * replicaCount + replica;
                var affinity = input.ShardPolicy.PreferOneHost
                    ? $"eval:{fingerprint}"
                    : $"eval:{fingerprint}:shard:{shard:D6}";
                var replicaResultLocation = replicaCount == 1
                    ? input.Locations.ResultLocation
                    : $"{input.Locations.ResultLocation}/r{replica}";
                var replicaOutputLocation = replicaCount == 1
                    ? input.Locations.OutputLocation
                    : $"{input.Locations.OutputLocation}/r{replica}";
                var runnerInput = CreateInput("steward.eval.runner/1.0", new
                {
                    harness = adapter.HarnessName,
                    harnessVersion = adapter.HarnessVersion,
                    adapterProfileVersion = adapter.ProfileVersion,
                    caseId = evaluationCase.CaseId,
                    caseDefinition = evaluationCase.Definition,
                    inventoryHash = input.Inventory.ContentHash,
                    dataset = new { identity = input.Dataset.Identity, hash = input.Dataset.ContentHash },
                    evaluationSet = input.EvaluationSet,
                    taskFilters = input.TaskFilters.Order(StringComparer.Ordinal).ToArray(),
                    modelProfileReference = input.ModelProfileReference,
                    repositoryCommit = input.Repository.ResolvedCommit,
                    harnessCommit = input.Harness.ResolvedCommit,
                    resultLocation = replicaResultLocation,
                    outputLocation = replicaOutputLocation,
                    replicaIndex = replica,
                    replicaCount = replicaCount,
                    command = new
                    {
                        executable = command.Executable,
                        arguments = command.Arguments,
                        workingDirectory = command.WorkingDirectory,
                        environmentReferences = command.EnvironmentReferences
                    },
                    parserContract = "steward.eval.json-lines/1.0",
                    retryPolicy = "steward.eval.retry/1.0",
                    maximumWorkloadConcurrency = input.ShardPolicy.MaximumConcurrency,
                    inferenceRateScope = input.InferenceRateScope,
                    maxOutputBytes = 64 * 1024 * 1024,
                    requiredDiskReserveBytes = 256 * 1024 * 1024,
                    identityRequirements = command.EnvironmentReferences?.Select(x =>
                        new IdentityCapabilityReference(x.Value, x.Key)).ToArray() ?? []
                });
                var resultKey = replicaCount == 1
                    ? $"eval-case:{evaluationCase.CaseId}"
                    : $"eval-case:{evaluationCase.CaseId}:r{replica}";
                nodes.Add(new(taskId, logicalKey, "evaluation-runner", "1.0",
                    (input.CaseResources ?? new()).ToRequirements(), runnerInput, setupIds,
                    RequiredCapabilities(input), fingerprint, affinity, null, 3, InterruptionClass.Restartable,
                    [new ExternalRateRequirement(input.InferenceRateScope, input.InferenceUnitsPerCase)],
                    resultKey));
            }
        }

        AddAggregateTasks(nodes, input, fingerprint, caseIds, completedResults, selectedCases.Select(x => x.CaseId).ToArray());
        return new(request.WorkloadId, request.PlanRevisionId, WorkloadPlan.CurrentSchemaVersion,
            $"{adapter.HarnessName}-evaluation", PlannerVersionValue, nodes, AggregateFailurePolicy.PartialSuccess,
            input.ShardPolicy.MaximumConcurrency);
    }

    private IReadOnlyList<TaskId> AddSetupTasks(List<TaskPlanNode> nodes, EvaluationWorkloadInput input, string fingerprint)
    {
        var dependencies = new List<TaskId>();
        AddSourceTask(nodes, dependencies, input, fingerprint, "harness", input.Harness,
            input.Harness.Uri is null ? setupProfile.RegisteredSourceValidation : setupProfile.HarnessAcquisition);
        AddSourceTask(nodes, dependencies, input, fingerprint, "repository", input.Repository,
            input.Repository.Uri is null ? setupProfile.RegisteredSourceValidation : setupProfile.RepositoryAcquisition);

        var packageIndex = 0;
        foreach (var package in setupProfile.PackageAcquisition ?? [])
        {
            var key = $"setup/packages/{packageIndex++:D3}";
            var id = Id(fingerprint, key);
            nodes.Add(ProcessNode(id, key, ExpandSetup(package, input, null), dependencies.ToArray(), input, fingerprint,
                $"setup:{fingerprint}:packages"));
            dependencies.Add(id);
        }

        if (input.Runtime.RequiresDocker && !setupProfile.HarnessOwnsDockerLifecycle)
        {
            var key = "setup/docker";
            var id = Id(fingerprint, key);
            var preparation = ExpandSetup(setupProfile.DockerPreparation!, input, null);
            nodes.Add(new(id, key, "process", "1.0",
                new ResourceRequirements(.25m, 256 * 1024 * 1024, 512 * 1024 * 1024, containerCount: 1, processCount: 1, concurrencyUnits: 1),
                ProcessInput(preparation, SelectIdentities(input, preparation), input.Repository),
                dependencies.ToArray(), new HashSet<string>(["process", "docker", "compose"], StringComparer.Ordinal),
                fingerprint, $"setup:{fingerprint}", null, 2, InterruptionClass.Restartable, [],
                $"setup:{fingerprint}:docker"));
            dependencies.Add(id);
        }
        return dependencies;
    }

    private static void AddSourceTask(
        List<TaskPlanNode> nodes, List<TaskId> dependencies, EvaluationWorkloadInput input, string fingerprint,
        string name, EvaluationSource source, SetupCommandTemplate? template)
    {
        var key = $"setup/{name}";
        var id = Id(fingerprint, key);
        TaskInput taskInput;
        var command = ExpandSetup(template!, input, source);
        taskInput = ProcessInput(command, SelectIdentities(input, command), source);
        nodes.Add(new(id, key, "process", "1.0",
            new ResourceRequirements(.25m, 256 * 1024 * 1024, 1024 * 1024 * 1024, processCount: 1, concurrencyUnits: 1),
            taskInput, dependencies.ToArray(), new HashSet<string>(["process"], StringComparer.Ordinal),
            fingerprint, $"setup:{fingerprint}", null, 2, InterruptionClass.Restartable, [],
            $"setup:{fingerprint}:{name}"));
        dependencies.Add(id);
    }

    private static TaskPlanNode ProcessNode(TaskId id, string key, SetupCommandTemplate command,
        IReadOnlyList<TaskId> dependencies, EvaluationWorkloadInput input, string fingerprint, string reductionKey) =>
        new(id, key, "process", "1.0",
            new ResourceRequirements(.25m, 256 * 1024 * 1024, 512 * 1024 * 1024, processCount: 1, concurrencyUnits: 1),
            ProcessInput(command, SelectIdentities(input, command), input.Repository), dependencies,
            new HashSet<string>(["process"], StringComparer.Ordinal), fingerprint, $"setup:{fingerprint}", null,
            2, InterruptionClass.Restartable, [], reductionKey);

    private static TaskInput ProcessInput(SetupCommandTemplate command,
        IReadOnlyList<IdentityCapabilityReference> identities, EvaluationSource source) =>
        CreateInput("steward.task.process/1.0", new
        {
            executable = command.Executable,
            arguments = command.Arguments,
            workingDirectory = command.WorkingDirectory,
            maxOutputBytes = 64 * 1024 * 1024,
            requiredDiskReserveBytes = 256 * 1024 * 1024,
            requestedRef = source.RequestedRef,
            exactCommit = source.ResolvedCommit,
            sourceUri = source.Uri?.AbsoluteUri,
            registeredLocalSource = source.RegisteredLocalSource,
            identityRequirements = identities
        });

    private static SetupCommandTemplate ExpandSetup(SetupCommandTemplate command, EvaluationWorkloadInput input, EvaluationSource? source)
    {
        var replacements = new Dictionary<string, string?>
        {
            ["{uri}"] = source?.Uri?.AbsoluteUri,
            ["{requestedRef}"] = source?.RequestedRef,
            ["{resolvedCommit}"] = source?.ResolvedCommit,
            ["{registeredLocalSource}"] = source?.RegisteredLocalSource,
            ["{repositoryCommit}"] = input.Repository.ResolvedCommit,
            ["{harnessCommit}"] = input.Harness.ResolvedCommit,
            ["{setupVersion}"] = input.Runtime.SetupVersion,
            ["{composeFile}"] = input.Runtime.ComposeFile
        };
        var arguments = command.Arguments.Select(value => EvaluationTemplate.Expand(value, replacements)).ToArray();
        return command with { Arguments = arguments };
    }

    private static IReadOnlyList<IdentityCapabilityReference> SelectIdentities(
        EvaluationWorkloadInput input, SetupCommandTemplate command) =>
        EvaluationIdentity.SelectRequired(input.IdentityCapabilities,
            command.RequiredIdentityCapabilities ?? [], "Setup command");

    private static void AddAggregateTasks(List<TaskPlanNode> nodes, EvaluationWorkloadInput input, string fingerprint,
        IReadOnlyList<TaskId> pendingCaseIds, IReadOnlyList<CompletedEvaluationResult> completed,
        IReadOnlyList<string> expectedCaseIds)
    {
        var layer = pendingCaseIds.ToList();
        var receiptBatchIndex = 0;
        foreach (var batch in completed.Chunk(32))
        {
            var key = $"aggregate/receipts/{receiptBatchIndex++:D4}";
            var id = Id(fingerprint, key);
            nodes.Add(AggregateNode(id, key, [], input, fingerprint, false, batch, [], null));
            layer.Add(id);
        }

        var level = 0;
        if (layer.Count == 0)
        {
            var key = "aggregate/final";
            var id = Id(fingerprint, key);
            nodes.Add(AggregateNode(id, key, [], input, fingerprint, true, [], expectedCaseIds,
                EvaluationHash.Sha256(EvaluationJson.Serialize(expectedCaseIds.Order(StringComparer.Ordinal)))));
            return;
        }

        while (layer.Count > WorkloadPlanLimits.MaximumDependenciesPerTask)
        {
            var next = new List<TaskId>();
            foreach (var batch in layer.Chunk(WorkloadPlanLimits.MaximumDependenciesPerTask).Select((items, index) => (items, index)))
            {
                var key = $"aggregate/{level:D2}/{batch.index:D4}";
                var id = Id(fingerprint, key);
                nodes.Add(AggregateNode(id, key, batch.items, input, fingerprint, false, [], [], null));
                next.Add(id);
            }
            layer = next;
            level++;
        }
        nodes.Add(AggregateNode(Id(fingerprint, "aggregate/final"), "aggregate/final", layer, input, fingerprint,
            true, [], expectedCaseIds,
            EvaluationHash.Sha256(EvaluationJson.Serialize(expectedCaseIds.Order(StringComparer.Ordinal)))));
    }

    private static TaskPlanNode AggregateNode(TaskId id, string key, IReadOnlyList<TaskId> dependencies,
        EvaluationWorkloadInput input, string fingerprint, bool final,
        IReadOnlyList<CompletedEvaluationResult> completed, IReadOnlyList<string> expectedCaseIds,
        string? expectedCaseSetHash) =>
        new(id, key, "evaluation-reducer", "1.0",
            new ResourceRequirements(.25m, 256 * 1024 * 1024, 256 * 1024 * 1024, processCount: 1, concurrencyUnits: 1),
            CreateInput("steward.eval.reducer/1.0", new
            {
                final,
                harnessVersion = input.Runtime.RuntimeVersion,
                commit = input.Repository.ResolvedCommit,
                datasetHash = input.Dataset.ContentHash,
                modelProfile = input.ModelProfileReference,
                resultLocation = input.Locations.ResultLocation,
                outputLocation = input.Locations.OutputLocation,
                manifestKey = EvaluationHash.Sha256($"{fingerprint}\n{key}"),
                completedResults = completed.Select(x => new
                {
                    x.Result.CaseId, x.Result.AttemptGeneration, x.Result.ReceiptHash,
                    x.PortableResultReference
                }).ToArray(),
                inputTaskIds = dependencies.Select(x => x.ToString()).Order(StringComparer.Ordinal).ToArray(),
                expectedCaseCount = expectedCaseIds.Count,
                expectedCaseSetHash
            }),
            dependencies, new HashSet<string>(["process"], StringComparer.Ordinal), fingerprint, null, null,
            2, InterruptionClass.Restartable, [], $"eval-aggregate:{fingerprint}");

    private static IReadOnlySet<string> RequiredCapabilities(EvaluationWorkloadInput input)
    {
        var result = new HashSet<string>(["process", "bounded-output"], StringComparer.Ordinal);
        if (input.Runtime.RequiresDocker) { result.Add("docker"); result.Add("compose"); }
        return result;
    }

    private static bool MatchesFilters(string caseId, IReadOnlyList<string> filters)
    {
        if (filters.Count == 0) return true;
        foreach (var filter in filters)
        {
            if (filter == "*") return true;
            if (filter.EndsWith('*') && caseId.StartsWith(filter[..^1], StringComparison.Ordinal)) return true;
            if (string.Equals(caseId, filter, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private string InputFingerprint(EvaluationWorkloadInput input) => EvaluationHash.Sha256(EvaluationJson.Serialize(new
    {
        harness = input.Harness.ToDto(), repository = input.Repository.ToDto(),
        dataset = input.Dataset, input.EvaluationSet,
        taskFilters = input.TaskFilters.Order(StringComparer.Ordinal).ToArray(), input.ModelProfileReference,
        input.ShardPolicy, input.Locations, input.Runtime,
        identityCapabilities = input.IdentityCapabilities.OrderBy(x => x.Reference, StringComparer.Ordinal)
            .ThenBy(x => x.Capability, StringComparer.Ordinal).ToArray(),
        inventoryHash = input.Inventory.ContentHash, input.CaseResources, input.InferenceRateScope,
        input.InferenceUnitsPerCase, adapter.HarnessName, adapter.HarnessVersion,
        adapterProfileVersion = adapter.ProfileVersion, setupProfileVersion = setupProfile.ProfileVersion
    }));

    private static TaskInput CreateInput(string schema, object value) =>
        TaskInput.Parse("application/json", schema[(schema.LastIndexOf('/') + 1)..],
            JsonSerializer.Serialize(value, EvaluationJson.Options));

    private static TaskId Id(string fingerprint, string key) => new(EvaluationHash.DeterministicGuid($"{fingerprint}\n{key}"));
    private static string EscapeKey(string value) => Uri.EscapeDataString(value);
}

public sealed class HarborEvaluationPlanner : EvaluationPlannerBase
{
    public HarborEvaluationPlanner(IEvaluationHarnessAdapter adapter, EvaluationSetupProfile setupProfile)
        : base(adapter, setupProfile, "harbor") { }
}

public sealed class SaberEvaluationPlanner : EvaluationPlannerBase
{
    public SaberEvaluationPlanner(IEvaluationHarnessAdapter adapter, EvaluationSetupProfile setupProfile)
        : base(adapter, setupProfile, "saber") { }
}
