using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Domain;
using Steward.Tasks.Abstractions;

namespace Steward.Workloads.Evals;

public sealed record CompletedResultReference(
    string CaseId,
    int AttemptGeneration,
    string ReceiptHash,
    string PortableResultReference);

public sealed record EvaluationReducerTaskDefinition(
    bool Final,
    string HarnessVersion,
    string Commit,
    string DatasetHash,
    string ModelProfile,
    string ResultLocation,
    string OutputLocation,
    string ManifestKey,
    IReadOnlyList<CompletedResultReference> CompletedResults,
    IReadOnlyList<string> InputTaskIds,
    int ExpectedCaseCount,
    string? ExpectedCaseSetHash);

public interface IEvaluationResultStore
{
    ValueTask<IReadOnlyList<EvaluationCaseResult>> ReadTaskResultsAsync(
        TaskId taskId, CancellationToken cancellationToken);
    ValueTask<EvaluationCaseResult> ReadPortableResultAsync(
        string reference, CancellationToken cancellationToken);
    ValueTask<EvaluationManifestReceipt?> ReadManifestAsync(
        string location, string manifestKey, CancellationToken cancellationToken);
    ValueTask<EvaluationManifestReceipt> WriteManifestAsync(
        string location, string manifestKey, EvaluationExportManifest manifest, CancellationToken cancellationToken);
}

public sealed record EvaluationManifestReceipt(
    string ArtifactReference,
    string ManifestHash,
    EvaluationExportManifest Manifest);

public enum EvaluationReducerErrorCode
{
    MissingResults,
    ImmutableContextMismatch,
    ExpectedCaseSetMismatch,
    ReceiptMismatch,
    ResultStoreFailure
}

public sealed record EvaluationReducerOutcome(
    EvaluationExportManifest? Manifest,
    string? ArtifactReference,
    ImmutableArray<TaskEvent> Events,
    EvaluationReducerErrorCode? ErrorCode);

public sealed class EvaluationReducerTaskType(IEvaluationResultStore store)
    : TaskTypeBase, IRecoverableTaskType, ITaskOutputSource
{
    private readonly ConcurrentDictionary<(TaskAttemptId, int), ReducerHandle> executions = new();
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public override TaskTypeVersion Type { get; } = new("evaluation-reducer", new Version(1, 0));
    public override TaskCapabilities Capabilities =>
        TaskCapabilities.Execute | TaskCapabilities.Observe | TaskCapabilities.Cancel |
        TaskCapabilities.Restart | TaskCapabilities.Cleanup;
    public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;

    public override ValidationResult Validate(JsonElement input)
    {
        EvaluationReducerTaskDefinition? definition;
        try { definition = input.Deserialize<EvaluationReducerTaskDefinition>(JsonOptions); }
        catch (JsonException exception) { return ValidationResult.Invalid(exception.Message); }
        if (definition is null) return ValidationResult.Invalid("Definition is required.");
        var errors = new List<string>();
        if (definition.InputTaskIds is null) errors.Add("InputTaskIds is required.");
        if (definition.CompletedResults is null) errors.Add("CompletedResults is required.");
        if (definition.InputTaskIds is null || definition.CompletedResults is null)
            return new(false, errors);
        if (definition.InputTaskIds.Count > 256) errors.Add("Reducer input task count exceeds 256.");
        if (definition.CompletedResults.Count > 32) errors.Add("Completed result receipt count exceeds 32.");
        if (definition.InputTaskIds.Any(x => !TaskId.TryParse(x, out _))) errors.Add("Reducer input Task ID is invalid.");
        if (definition.CompletedResults.GroupBy(x => x.CaseId, StringComparer.Ordinal).Any(x => x.Count() > 1))
            errors.Add("Completed result receipt case IDs must be unique.");
        if (definition.ExpectedCaseCount < 0) errors.Add("Expected case count cannot be negative.");
        if (definition.ManifestKey is null || definition.ManifestKey.Length != 64 ||
            !definition.ManifestKey.All(Uri.IsHexDigit)) errors.Add("ManifestKey must be a SHA-256 hash.");
        if (definition.Final && (definition.ExpectedCaseCount < 1 ||
            definition.ExpectedCaseSetHash is null || definition.ExpectedCaseSetHash.Length != 64 ||
            !definition.ExpectedCaseSetHash.All(Uri.IsHexDigit)))
            errors.Add("Final reducers require an expected case count and SHA-256 set hash.");
        if (!EvaluationSource.IsValidCommit(definition.Commit) ||
            !EvaluationDataset.IsValidDigest(definition.DatasetHash))
            errors.Add("Reducer immutable commit or dataset hash is invalid.");
        try
        {
            EvaluationLocations.ValidateLocation(definition.ResultLocation, "Result location");
            EvaluationLocations.ValidateLocation(definition.OutputLocation, "Output location");
            foreach (var item in definition.CompletedResults)
                EvaluationLocations.ValidateLocation(item.PortableResultReference, "Portable result reference");
        }
        catch (ArgumentException exception) { errors.Add(exception.Message); }
        return errors.Count == 0 ? ValidationResult.Valid : new(false, errors);
    }

    public override async ValueTask<IExecutionHandle> StartAsync(
        TaskExecutionContext context, CancellationToken cancellationToken)
    {
        var definition = Get(context);
        var handle = new ReducerHandle(context.AttemptId, context.Generation);
        executions[(handle.AttemptId, handle.Generation)] = handle;
        try
        {
            var existing = await store.ReadManifestAsync(
                definition.OutputLocation, definition.ManifestKey, cancellationToken);
            if (existing is not null)
            {
                ValidateManifestReceipt(existing, definition);
                handle.Succeed(existing.Manifest, existing.ArtifactReference);
                return handle;
            }
            var results = new List<EvaluationCaseResult>();
            foreach (var taskId in definition.InputTaskIds)
                results.AddRange(await store.ReadTaskResultsAsync(TaskId.Parse(taskId), cancellationToken));
            foreach (var receipt in definition.CompletedResults)
            {
                var result = await store.ReadPortableResultAsync(receipt.PortableResultReference, cancellationToken);
                if (result.CaseId != receipt.CaseId || result.AttemptGeneration != receipt.AttemptGeneration ||
                    result.ReceiptHash != receipt.ReceiptHash)
                    throw new ReducerFailureException(EvaluationReducerErrorCode.ReceiptMismatch);
                results.Add(result);
            }

            if (results.Any(x => x.HarnessVersion != definition.HarnessVersion ||
                                 x.Commit != definition.Commit ||
                                 x.DatasetHash != definition.DatasetHash ||
                                 x.ModelProfile != definition.ModelProfile))
                throw new ReducerFailureException(EvaluationReducerErrorCode.ImmutableContextMismatch);
            var actualIds = results.Select(x => x.CaseId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            if (definition.Final &&
                (actualIds.Length != definition.ExpectedCaseCount ||
                 EvaluationHash.Sha256(EvaluationJson.Serialize(actualIds)) != definition.ExpectedCaseSetHash))
                throw new ReducerFailureException(EvaluationReducerErrorCode.ExpectedCaseSetMismatch);
            if (results.Count == 0) throw new ReducerFailureException(EvaluationReducerErrorCode.MissingResults);
            var manifest = EvaluationResultReducer.Reduce(results, actualIds);
            var manifestReceipt = await store.WriteManifestAsync(
                definition.OutputLocation, definition.ManifestKey, manifest, cancellationToken);
            ValidateManifestReceipt(manifestReceipt, definition);
            handle.Succeed(manifest, manifestReceipt.ArtifactReference);
        }
        catch (ReducerFailureException exception) { handle.Fail(exception.Code); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            handle.Fail(EvaluationReducerErrorCode.ResultStoreFailure);
        }
        return handle;
    }

    public override ValueTask<ExecutionObservation> ObserveAsync(
        IExecutionHandle execution, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var handle = GetHandle(execution);
        return ValueTask.FromResult(handle.Observation);
    }

    public override ValueTask CancelAsync(
        IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        GetHandle(execution).Cancel();
        return ValueTask.CompletedTask;
    }

    public override async ValueTask<IExecutionHandle> RestartAsync(
        TaskExecutionContext context, IExecutionHandle execution, CancellationToken cancellationToken)
    {
        executions.TryRemove((execution.AttemptId, execution.Generation), out _);
        return await StartAsync(context, cancellationToken);
    }

    public ValueTask<IExecutionHandle> RecoverAsync(
        TaskExecutionContext context, CancellationToken cancellationToken = default) =>
        StartAsync(context, cancellationToken);

    public async ValueTask<TaskExecutionRecoveryResult> RecoverExecutionAsync(
        TaskExecutionContext context,
        string currentBootIdentity,
        CancellationToken cancellationToken)
    {
        var execution = await RecoverAsync(context, cancellationToken);
        return new(TaskExecutionRecoveryStatus.Present, execution, "eval-reducer.replayed-idempotently");
    }

    public ValueTask<TaskOutputBatch> ReadOutputsAsync(
        IExecutionHandle execution,
        long afterCursor,
        int maximumCount,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (afterCursor < 0 || maximumCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(afterCursor));
        var events = GetOutcome(execution).Events
            .Skip(checked((int)Math.Min(afterCursor, int.MaxValue)))
            .Take(maximumCount)
            .Select(ToRuntimeOutput)
            .ToArray();
        return ValueTask.FromResult(new TaskOutputBatch(afterCursor + events.Length, events));
    }

    public override ValueTask<CleanupResult> CleanupAsync(
        TaskExecutionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        executions.TryRemove((context.AttemptId, context.Generation), out _);
        return ValueTask.FromResult(new CleanupResult(true));
    }

    public EvaluationReducerOutcome GetOutcome(IExecutionHandle execution) => GetHandle(execution).Outcome;

    private ReducerHandle GetHandle(IExecutionHandle execution) =>
        executions.TryGetValue((execution.AttemptId, execution.Generation), out var handle)
            ? handle : throw new InvalidOperationException("Evaluation reducer execution is not registered.");

    private EvaluationReducerTaskDefinition Get(TaskExecutionContext context)
    {
        var validation = Validate(context.Input);
        if (!validation.IsValid) throw new ArgumentException(string.Join("; ", validation.Errors));
        return context.Input.Deserialize<EvaluationReducerTaskDefinition>(JsonOptions)!;
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new CanonicalInt32Converter());
        return options;
    }

    private static void ValidateManifestReceipt(
        EvaluationManifestReceipt receipt, EvaluationReducerTaskDefinition definition)
    {
        EvaluationLocations.ValidateLocation(receipt.ArtifactReference, "Manifest artifact reference");
        if (receipt.ManifestHash != receipt.Manifest.ManifestHash ||
            receipt.Manifest.HarnessVersion != definition.HarnessVersion ||
            receipt.Manifest.Commit != definition.Commit ||
            receipt.Manifest.DatasetHash != definition.DatasetHash ||
            receipt.Manifest.ModelProfile != definition.ModelProfile)
            throw new ReducerFailureException(EvaluationReducerErrorCode.ReceiptMismatch);
        var regenerated = EvaluationResultReducer.Reduce(
            receipt.Manifest.Cases.Select(x => new EvaluationCaseResult(
                x.CaseId, x.AttemptGeneration, receipt.Manifest.HarnessVersion, receipt.Manifest.Commit,
                receipt.Manifest.DatasetHash, receipt.Manifest.ModelProfile, x.Status, x.Score,
                x.Metrics, x.ArtifactReferences, x.FailureClassification, x.ReceiptHash)),
            receipt.Manifest.Cases.Select(x => x.CaseId));
        if (regenerated.ManifestHash != receipt.ManifestHash)
            throw new ReducerFailureException(EvaluationReducerErrorCode.ReceiptMismatch);
        if (definition.Final)
        {
            var ids = receipt.Manifest.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).ToArray();
            if (ids.Length != definition.ExpectedCaseCount ||
                EvaluationHash.Sha256(EvaluationJson.Serialize(ids)) != definition.ExpectedCaseSetHash)
                throw new ReducerFailureException(EvaluationReducerErrorCode.ExpectedCaseSetMismatch);
        }
    }

    private static TaskRuntimeOutput ToRuntimeOutput(TaskEvent value) => value switch
    {
        TaskProgressEvent progress => new TaskRuntimeProgress(progress.Fraction, progress.Message),
        TaskArtifactEvent artifact => new TaskRuntimeArtifact(
            PortableId(artifact), artifact.Name, artifact.MediaType, artifact.Path, artifact.Size,
            EvaluationHash.Sha256(artifact.Path)),
        TaskLogEvent log => new TaskRuntimeLogCursor(
            log.Stream, log.Offset, log.Data.Length,
            EvaluationHash.Sha256(Convert.ToHexString(log.Data.Span)), log.Truncated),
        _ => throw new InvalidOperationException($"Unsupported evaluation event '{value.GetType().Name}'.")
    };

    private static PortableObjectId PortableId(TaskArtifactEvent artifact)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(
                $"{artifact.AttemptId}:{artifact.Generation}:{artifact.Name}:{artifact.Path}"));
        return new(new Guid(hash.AsSpan(0, 16)));
    }

    private sealed class ReducerFailureException(EvaluationReducerErrorCode code) : Exception
    {
        internal EvaluationReducerErrorCode Code { get; } = code;
    }

    private sealed class ReducerHandle(TaskAttemptId attemptId, int generation) : IExecutionHandle
    {
        private readonly List<TaskEvent> events = [];
        private ExecutionObservation observation = new(ExecutionState.Running);
        private EvaluationExportManifest? manifest;
        private string? artifact;
        private EvaluationReducerErrorCode? errorCode;

        public TaskAttemptId AttemptId { get; } = attemptId;
        public int Generation { get; } = generation;
        public int ProcessId => 0;
        public long ProcessCreationTimeUtcTicks { get; } = DateTime.UtcNow.Ticks;
        internal ExecutionObservation Observation => observation;
        internal EvaluationReducerOutcome Outcome => new(manifest, artifact, events.ToImmutableArray(), errorCode);

        internal void Succeed(EvaluationExportManifest value, string reference)
        {
            manifest = value;
            artifact = reference;
            events.Add(new TaskArtifactEvent(AttemptId, Generation, DateTimeOffset.UtcNow,
                "evaluation-manifest", "application/json", reference, 0));
            observation = new(ExecutionState.Exited, 0);
        }

        internal void Fail(EvaluationReducerErrorCode code)
        {
            errorCode = code;
            observation = new(ExecutionState.Exited, -1, code.ToString());
        }

        internal void Cancel() => observation = new(ExecutionState.Interrupted, Detail: "Cancelled.");
    }
}
