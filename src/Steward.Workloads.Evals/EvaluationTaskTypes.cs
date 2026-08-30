using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Steward.Domain;
using Steward.Tasks.Abstractions;

namespace Steward.Workloads.Evals;

public sealed record EvaluationRunnerCommandDefinition(
    string Executable,
    IReadOnlyList<string> Arguments,
    string? WorkingDirectory,
    IReadOnlyDictionary<string, string>? EnvironmentReferences);

public sealed record EvaluationRunnerDatasetDefinition(string Identity, string Hash);

public sealed record EvaluationRunnerTaskDefinition(
    string Harness,
    string HarnessVersion,
    string AdapterProfileVersion,
    string CaseId,
    JsonElement CaseDefinition,
    string InventoryHash,
    EvaluationRunnerDatasetDefinition Dataset,
    string EvaluationSet,
    IReadOnlyList<string> TaskFilters,
    string ModelProfileReference,
    string RepositoryCommit,
    string HarnessCommit,
    string ResultLocation,
    string OutputLocation,
    EvaluationRunnerCommandDefinition Command,
    string ParserContract,
    string RetryPolicy,
    int MaximumWorkloadConcurrency,
    string InferenceRateScope,
    long MaxOutputBytes,
    long RequiredDiskReserveBytes,
    IReadOnlyList<IdentityCapabilityReference> IdentityRequirements);

public enum EvaluationRunnerErrorCode
{
    MalformedOutput,
    OutputLineTooLarge,
    OutputTruncated,
    ContextMismatch,
    ConflictingResult,
    MissingResult,
    RateFeedbackUnavailable
}

public enum DurableRunnerEventKind { Progress, Artifact }

public sealed record DurableRunnerEvent(
    DurableRunnerEventKind Kind,
    DateTimeOffset Timestamp,
    double? Fraction = null,
    string? Message = null,
    string? Name = null,
    string? Reference = null);

public sealed record EvaluationRunnerState(
    TaskAttemptId AttemptId,
    int Generation,
    string DefinitionHash,
    long StdoutOffset,
    byte[] PendingLineBytes,
    ImmutableArray<DurableRunnerEvent> Events,
    EvaluationCaseResult? Result,
    EvaluationRetryDecision? Failure,
    EvaluationRunnerErrorCode? ErrorCode,
    string? TerminalReceipt);

public interface IRunnerStateStore
{
    ValueTask<EvaluationRunnerState?> LoadAsync(
        TaskAttemptId attemptId, int generation, CancellationToken cancellationToken);
    ValueTask SaveAsync(EvaluationRunnerState state, CancellationToken cancellationToken);
    ValueTask DeleteAsync(TaskAttemptId attemptId, int generation, CancellationToken cancellationToken);
}

public interface IEvaluationTaskResultWriter
{
    ValueTask RecordTaskResultAsync(
        TaskId taskId,
        EvaluationCaseResult result,
        CancellationToken cancellationToken);
}

public sealed record EvaluationRunnerOutcome(
    EvaluationCaseResult? Result,
    EvaluationRetryDecision? Failure,
    ImmutableArray<TaskEvent> Events,
    EvaluationRunnerErrorCode? ErrorCode,
    string? TerminalReceipt);

public sealed class EvaluationRunnerTaskType :
    TaskTypeBase,
    IRecoverableTaskType,
    ITaskOutputSource,
    IDurableTaskResultType
{
    private const int ReadSize = 64 * 1024;
    private readonly IProcessExecutor executor;
    private readonly IRunnerStateStore stateStore;
    private readonly IEvaluationRateFeedbackSink rateFeedback;
    private readonly IReadOnlyDictionary<string, IEvaluationResultParser> parsers;
    private readonly IEvaluationTaskResultWriter? resultWriter;
    private readonly ConcurrentDictionary<(TaskAttemptId, int), RunnerState> states = new();
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public EvaluationRunnerTaskType(
        IProcessExecutor executor,
        IRunnerStateStore stateStore,
        IEvaluationRateFeedbackSink rateFeedback,
        IReadOnlyDictionary<string, IEvaluationResultParser>? parsers = null,
        IEvaluationTaskResultWriter? resultWriter = null)
    {
        this.executor = executor ?? throw new ArgumentNullException(nameof(executor));
        this.stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        this.rateFeedback = rateFeedback ?? throw new ArgumentNullException(nameof(rateFeedback));
        this.resultWriter = resultWriter;
        this.parsers = parsers ?? new Dictionary<string, IEvaluationResultParser>(StringComparer.Ordinal)
        {
            ["steward.eval.json-lines/1.0"] = new JsonLinesEvaluationResultParser()
        };
    }

    public override TaskTypeVersion Type { get; } = new("evaluation-runner", new Version(1, 0));
    public override TaskCapabilities Capabilities =>
        TaskCapabilities.Execute | TaskCapabilities.Observe | TaskCapabilities.Cancel |
        TaskCapabilities.Restart | TaskCapabilities.Cleanup;
    public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;

    public override ValidationResult Validate(JsonElement input)
    {
        EvaluationRunnerTaskDefinition? definition;
        try { definition = input.Deserialize<EvaluationRunnerTaskDefinition>(JsonOptions); }
        catch (JsonException exception) { return ValidationResult.Invalid(exception.Message); }
        if (definition is null) return ValidationResult.Invalid("Definition is required.");
        var errors = new List<string>();
        Required(definition.Harness, nameof(definition.Harness), errors);
        Required(definition.CaseId, nameof(definition.CaseId), errors);
        Required(definition.HarnessVersion, nameof(definition.HarnessVersion), errors);
        Required(definition.AdapterProfileVersion, nameof(definition.AdapterProfileVersion), errors);
        Required(definition.InventoryHash, nameof(definition.InventoryHash), errors);
        Required(definition.EvaluationSet, nameof(definition.EvaluationSet), errors);
        Required(definition.RepositoryCommit, nameof(definition.RepositoryCommit), errors);
        Required(definition.HarnessCommit, nameof(definition.HarnessCommit), errors);
        Required(definition.Dataset?.Identity, "Dataset.Identity", errors);
        Required(definition.Dataset?.Hash, "Dataset.Hash", errors);
        Required(definition.ModelProfileReference, nameof(definition.ModelProfileReference), errors);
        Required(definition.ParserContract, nameof(definition.ParserContract), errors);
        Required(definition.RetryPolicy, nameof(definition.RetryPolicy), errors);
        Required(definition.InferenceRateScope, nameof(definition.InferenceRateScope), errors);
        if (!EvaluationSource.IsValidCommit(definition.RepositoryCommit) ||
            !EvaluationSource.IsValidCommit(definition.HarnessCommit))
            errors.Add("Repository and harness commits must be full Git hashes.");
        if (!EvaluationDataset.IsValidDigest(definition.Dataset?.Hash))
            errors.Add("Dataset hash must be an algorithm-prefixed digest.");
        if (definition.MaximumWorkloadConcurrency <= 0) errors.Add("MaximumWorkloadConcurrency must be positive.");
        if (definition.IdentityRequirements is null) errors.Add("IdentityRequirements is required.");
        else foreach (var identity in definition.IdentityRequirements)
            try { identity.Validate(); } catch (ArgumentException exception) { errors.Add(exception.Message); }
        if (definition.TaskFilters is null) errors.Add("TaskFilters is required.");
        if (definition.Command is null) errors.Add("Command is required.");
        else
        {
            if (!Path.IsPathFullyQualified(definition.Command.Executable)) errors.Add("Command executable must be absolute.");
            if (new[] { ".cmd", ".bat", ".ps1", ".sh" }.Contains(
                Path.GetExtension(definition.Command.Executable), StringComparer.OrdinalIgnoreCase))
                errors.Add("Command executable cannot be a shell script.");
            if (definition.Command.Arguments is null || definition.Command.Arguments.Count > 128)
                errors.Add("Command arguments must contain at most 128 entries.");
            if (definition.Command.WorkingDirectory is not null &&
                !WorkspacePaths.IsSafeRelative(definition.Command.WorkingDirectory))
                errors.Add("Command working directory must be workspace-relative.");
            if (definition.IdentityRequirements is not null && definition.Command.EnvironmentReferences is not null &&
                definition.Command.EnvironmentReferences.Any(x => !definition.IdentityRequirements.Any(identity =>
                    identity.Capability == x.Key && identity.Reference == x.Value)))
                errors.Add("Command environment references must name declared identity capabilities.");
        }
        if (definition.ParserContract is null || !parsers.ContainsKey(definition.ParserContract))
            errors.Add("Parser contract is not registered.");
        if (definition.MaxOutputBytes is <= 0 or > 1024L * 1024 * 1024)
            errors.Add("MaxOutputBytes is outside the supported bound.");
        if (definition.RequiredDiskReserveBytes < 0) errors.Add("RequiredDiskReserveBytes cannot be negative.");
        try
        {
            EvaluationLocations.ValidateLocation(definition.ResultLocation, "Result location");
            EvaluationLocations.ValidateLocation(definition.OutputLocation, "Output location");
        }
        catch (ArgumentException exception) { errors.Add(exception.Message); }
        return errors.Count == 0 ? ValidationResult.Valid : new(false, errors);
    }

    public override async ValueTask<IExecutionHandle> StartAsync(
        TaskExecutionContext context, CancellationToken cancellationToken)
    {
        var definition = Get(context);
        var workingDirectory = definition.Command.WorkingDirectory is null
            ? context.Workspace : WorkspacePaths.Resolve(context.Workspace, definition.Command.WorkingDirectory);
        var arguments = definition.Command.Arguments.Select(x => x.Replace(
            EvaluationHarnessAdapterBase.AttemptGenerationToken,
            context.Generation.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)).ToArray();
        var request = new ProcessLaunchRequest(context.AttemptId, context.Generation, definition.Command.Executable,
            arguments, workingDirectory, Path.Combine(context.Workspace, ".steward", "spool"),
            definition.MaxOutputBytes, definition.RequiredDiskReserveBytes);
        var state = RunnerState.Create(definition, parsers[definition.ParserContract],
            DefinitionHash(context.Input), context.AttemptId, context.Generation);
        await stateStore.SaveAsync(state.Snapshot, cancellationToken);
        try
        {
            var execution = await executor.StartAsync(request, cancellationToken);
            states[(execution.AttemptId, execution.Generation)] = state;
            return execution;
        }
        catch
        {
            try { await stateStore.DeleteAsync(context.AttemptId, context.Generation, CancellationToken.None); }
            catch { }
            throw;
        }
    }

    public async ValueTask RegisterRecoveredExecutionAsync(
        TaskExecutionContext context, IExecutionHandle execution, CancellationToken cancellationToken = default)
    {
        if (execution.AttemptId != context.AttemptId || execution.Generation != context.Generation)
            throw new ArgumentException("Recovered execution identity does not match its Task context.", nameof(execution));
        var definition = Get(context);
        var definitionHash = DefinitionHash(context.Input);
        var persisted = await stateStore.LoadAsync(context.AttemptId, context.Generation, cancellationToken);
        if (persisted is null)
        {
            persisted = RunnerState.Create(definition, parsers[definition.ParserContract],
                definitionHash, context.AttemptId, context.Generation).Snapshot;
            await stateStore.SaveAsync(persisted, cancellationToken);
        }
        if (persisted.DefinitionHash != definitionHash)
            throw new InvalidOperationException("Durable evaluation runner state belongs to different immutable input.");
        states[(execution.AttemptId, execution.Generation)] =
            RunnerState.Restore(definition, parsers[definition.ParserContract], persisted);
    }

    public ValueTask RecoverAsync(
        TaskExecutionContext context, IExecutionHandle execution, CancellationToken cancellationToken = default) =>
        RegisterRecoveredExecutionAsync(context, execution, cancellationToken);

    public async ValueTask<IExecutionHandle> RecoverAsync(
        TaskExecutionContext context, string currentBootId, CancellationToken cancellationToken = default)
    {
        var execution = await executor.RecoverAsync(
            context.AttemptId, context.Generation, currentBootId, cancellationToken);
        await RegisterRecoveredExecutionAsync(context, execution, cancellationToken);
        return execution;
    }

    public async ValueTask<TaskExecutionRecoveryResult> RecoverExecutionAsync(
        TaskExecutionContext context,
        string currentBootIdentity,
        CancellationToken cancellationToken)
    {
        try
        {
            var execution = await RecoverAsync(context, currentBootIdentity, cancellationToken);
            return new(TaskExecutionRecoveryStatus.Present, execution, "eval-runner.present");
        }
        catch (ExecutionRecoveryException exception)
        {
            return new(
                exception.IsAmbiguous ? TaskExecutionRecoveryStatus.Ambiguous : TaskExecutionRecoveryStatus.Absent,
                Code: exception.IsAmbiguous ? "eval-runner.identity-ambiguous" : "eval-runner.absent");
        }
        catch (KeyNotFoundException)
        {
            return new(TaskExecutionRecoveryStatus.Absent, Code: "eval-runner.not-journaled");
        }
    }

    public override async ValueTask<ExecutionObservation> ObserveAsync(
        IExecutionHandle execution, CancellationToken cancellationToken)
    {
        var state = GetState(execution);
        await DrainAsync(execution, state, cancellationToken);
        var observation = await executor.ObserveAsync(execution, cancellationToken);
        if (observation.State == ExecutionState.Exited)
        {
            await DrainAsync(execution, state, cancellationToken);
            await state.CompletePendingLineAsync(execution, rateFeedback, cancellationToken);
            await stateStore.SaveAsync(state.Snapshot, cancellationToken);
            if (state.ErrorCode is not null) return observation with { ExitCode = -1, Detail = state.ErrorCode.ToString() };
            if (state.Result is null)
            {
                if (state.Failure is not null)
                    return observation with { ExitCode = -1, Detail = "RetryableEvaluationFailure" };
                state.Fail(EvaluationRunnerErrorCode.MissingResult, EvaluationFailureSignal.Harness);
                await stateStore.SaveAsync(state.Snapshot, cancellationToken);
                return observation with { ExitCode = observation.ExitCode == 0 ? -1 : observation.ExitCode,
                    Detail = EvaluationRunnerErrorCode.MissingResult.ToString() };
            }
            if (state.Failure?.RetryCase == true)
                return observation with { ExitCode = -1, Detail = "RetryableEvaluationFailure" };
        }
        return observation;
    }

    public override ValueTask CancelAsync(
        IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken) =>
        executor.CancelAsync(execution, gracePeriod, cancellationToken);

    public override async ValueTask<IExecutionHandle> RestartAsync(
        TaskExecutionContext context, IExecutionHandle execution, CancellationToken cancellationToken)
    {
        await executor.CancelAsync(execution, TimeSpan.FromSeconds(5), cancellationToken);
        states.TryRemove((execution.AttemptId, execution.Generation), out _);
        return await StartAsync(context, cancellationToken);
    }

    public override async ValueTask<CleanupResult> CleanupAsync(
        TaskExecutionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        states.TryRemove((context.AttemptId, context.Generation), out _);
        await Task.CompletedTask;
        return new(true, "Durable runner state retained until the downstream result receipt is committed.");
    }

    public ValueTask ReleaseDurableStateAsync(
        TaskAttemptId attemptId, int generation, CancellationToken cancellationToken = default) =>
        stateStore.DeleteAsync(attemptId, generation, cancellationToken);

    public async ValueTask<string?> CommitTerminalResultAsync(
        IExecutionHandle execution,
        TaskId taskId,
        CancellationToken cancellationToken)
    {
        var outcome = await ReadOutcomeAsync(execution, cancellationToken);
        if (outcome.Result is null) return outcome.TerminalReceipt;
        if (resultWriter is null)
            throw new InvalidOperationException("A durable evaluation result writer is required.");
        await resultWriter.RecordTaskResultAsync(taskId, outcome.Result, cancellationToken);
        return outcome.TerminalReceipt ?? outcome.Result.ReceiptHash;
    }

    public async ValueTask<EvaluationRunnerOutcome> ReadOutcomeAsync(
        IExecutionHandle execution, CancellationToken cancellationToken = default)
    {
        var state = GetState(execution);
        await DrainAsync(execution, state, cancellationToken);
        return state.Outcome(execution);
    }

    public async ValueTask<TaskOutputBatch> ReadOutputsAsync(
        IExecutionHandle execution,
        long afterCursor,
        int maximumCount,
        CancellationToken cancellationToken)
    {
        if (afterCursor < 0 || maximumCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(afterCursor));
        var outcome = await ReadOutcomeAsync(execution, cancellationToken);
        var events = outcome.Events.Skip(checked((int)Math.Min(afterCursor, int.MaxValue)))
            .Take(maximumCount)
            .Select(ToRuntimeOutput)
            .ToArray();
        return new(afterCursor + events.Length, events);
    }

    private async ValueTask DrainAsync(IExecutionHandle execution, RunnerState state, CancellationToken cancellationToken)
    {
        while (state.ErrorCode is null)
        {
            var read = await executor.ReadOutputAsync(execution, "stdout", state.Offset, ReadSize, cancellationToken);
            state.Offset = read.Cursor.Offset;
            if (read.Cursor.Truncated)
            {
                state.Fail(EvaluationRunnerErrorCode.OutputTruncated, EvaluationFailureSignal.Infrastructure);
                await stateStore.SaveAsync(state.Snapshot, cancellationToken);
                await executor.CancelAsync(execution, TimeSpan.Zero, cancellationToken);
                return;
            }
            if (read.Data.IsEmpty) return;
            await state.AcceptAsync(read.Data, execution, rateFeedback, cancellationToken);
            await stateStore.SaveAsync(state.Snapshot, cancellationToken);
            if (state.ErrorCode is not null)
            {
                await executor.CancelAsync(execution, TimeSpan.Zero, cancellationToken);
                return;
            }
        }
    }

    private RunnerState GetState(IExecutionHandle execution) =>
        states.TryGetValue((execution.AttemptId, execution.Generation), out var state)
            ? state : throw new InvalidOperationException("Evaluation execution is not registered.");

    private EvaluationRunnerTaskDefinition Get(TaskExecutionContext context)
    {
        var validation = Validate(context.Input);
        if (!validation.IsValid) throw new ArgumentException(string.Join("; ", validation.Errors));
        return context.Input.Deserialize<EvaluationRunnerTaskDefinition>(JsonOptions)!;
    }

    private static string DefinitionHash(JsonElement input) =>
        EvaluationHash.Sha256(EvaluationJson.Serialize(input));

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

    private static void Required(string? value, string name, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value)) errors.Add($"{name} is required.");
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new CanonicalInt32Converter());
        options.Converters.Add(new CanonicalInt64Converter());
        return options;
    }

    private sealed class RunnerState
    {
        private static readonly UTF8Encoding StrictUtf8 = new(false, true);
        private readonly EvaluationRunnerTaskDefinition definition;
        private readonly IEvaluationResultParser parser;
        private readonly List<byte> pending;
        private readonly List<DurableRunnerEvent> events;

        private RunnerState(
            EvaluationRunnerTaskDefinition definition, IEvaluationResultParser parser,
            EvaluationRunnerState snapshot)
        {
            this.definition = definition;
            this.parser = parser;
            Snapshot = snapshot with { PendingLineBytes = snapshot.PendingLineBytes.ToArray() };
            pending = [.. snapshot.PendingLineBytes];
            events = [.. snapshot.Events];
        }

        internal EvaluationRunnerState Snapshot { get; private set; }
        internal long Offset { get => Snapshot.StdoutOffset; set => Snapshot = Snapshot with { StdoutOffset = value }; }
        internal EvaluationCaseResult? Result => Snapshot.Result;
        internal EvaluationRetryDecision? Failure => Snapshot.Failure;
        internal EvaluationRunnerErrorCode? ErrorCode => Snapshot.ErrorCode;

        internal static RunnerState Create(
            EvaluationRunnerTaskDefinition definition, IEvaluationResultParser parser,
            string hash, TaskAttemptId attemptId, int generation) =>
            new(definition, parser, new(attemptId, generation, hash, 0, [],
                [], null, null, null, null));

        internal static RunnerState Restore(
            EvaluationRunnerTaskDefinition definition, IEvaluationResultParser parser,
            EvaluationRunnerState snapshot) => new(definition, parser, snapshot);

        internal EvaluationRunnerOutcome Outcome(IExecutionHandle execution) =>
            new(Snapshot.Result, Snapshot.Failure, events.Select(x => ToTaskEvent(x, execution)).ToImmutableArray(),
                Snapshot.ErrorCode, Snapshot.TerminalReceipt);

        internal async ValueTask AcceptAsync(
            ReadOnlyMemory<byte> bytes, IExecutionHandle execution,
            IEvaluationRateFeedbackSink rateFeedback, CancellationToken cancellationToken)
        {
            foreach (var value in bytes.ToArray())
            {
                if (value == (byte)'\n')
                {
                    await ParsePendingLineAsync(execution, rateFeedback, cancellationToken);
                    pending.Clear();
                }
                else
                {
                    pending.Add(value);
                    if (pending.Count > EvaluationLimits.MaximumJsonLineBytes)
                    {
                        pending.Clear();
                        Fail(EvaluationRunnerErrorCode.OutputLineTooLarge, EvaluationFailureSignal.Harness);
                        break;
                    }
                }
            }
            SyncSnapshot();
        }

        internal async ValueTask CompletePendingLineAsync(
            IExecutionHandle execution, IEvaluationRateFeedbackSink rateFeedback,
            CancellationToken cancellationToken)
        {
            if (pending.Count > 0) await ParsePendingLineAsync(execution, rateFeedback, cancellationToken);
            pending.Clear();
            SyncSnapshot();
        }

        private async ValueTask ParsePendingLineAsync(
            IExecutionHandle execution, IEvaluationRateFeedbackSink rateFeedback,
            CancellationToken cancellationToken)
        {
            if (pending.Count == 0 || ErrorCode is not null) return;
            string line;
            try { line = StrictUtf8.GetString(pending.ToArray()).TrimEnd('\r'); }
            catch (DecoderFallbackException)
            {
                Fail(EvaluationRunnerErrorCode.MalformedOutput, EvaluationFailureSignal.Harness);
                return;
            }
            try
            {
                var progress = parser.ParseProgress(line);
                if (progress is not null)
                {
                    if (progress.CaseId != definition.CaseId)
                        throw new InvalidDataException();
                    events.Add(new(DurableRunnerEventKind.Progress, DateTimeOffset.UtcNow,
                        progress.Fraction, progress.Message));
                    return;
                }
                var notice = parser.ParseFailure(line);
                if (notice is not null)
                {
                    Snapshot = Snapshot with { Failure = EvaluationRetryPolicy.Classify(notice.Signal) };
                    if (notice.Signal is EvaluationFailureSignal.Http429 or EvaluationFailureSignal.InferenceThrottle)
                    {
                        try
                        {
                            await rateFeedback.ReportThrottleAsync(
                                definition.InferenceRateScope, notice.RetryAfter!.Value, cancellationToken);
                        }
                        catch (OperationCanceledException) { throw; }
                        catch
                        {
                            Fail(EvaluationRunnerErrorCode.RateFeedbackUnavailable,
                                EvaluationFailureSignal.Infrastructure);
                        }
                    }
                    return;
                }
                var context = new EvaluationResultContext(execution.Generation, definition.HarnessVersion,
                    definition.RepositoryCommit, definition.Dataset.Hash, definition.ModelProfileReference);
                var result = parser.ParseResult(line, context);
                if (result is null) return;
                if (result.CaseId != definition.CaseId) throw new InvalidDataException();
                if (Result is not null && Result.ReceiptHash != result.ReceiptHash)
                {
                    Fail(EvaluationRunnerErrorCode.ConflictingResult, EvaluationFailureSignal.Harness);
                    return;
                }
                Snapshot = Snapshot with
                {
                    Result = result,
                    TerminalReceipt = result.ReceiptHash,
                    Failure = result.FailureClassification switch
                    {
                        EvaluationFailureClassification.None => null,
                        EvaluationFailureClassification.Infrastructure =>
                            EvaluationRetryPolicy.Classify(EvaluationFailureSignal.Infrastructure),
                        EvaluationFailureClassification.Harness =>
                            EvaluationRetryPolicy.Classify(EvaluationFailureSignal.Harness),
                        EvaluationFailureClassification.Task =>
                            EvaluationRetryPolicy.Classify(EvaluationFailureSignal.Task),
                        _ => throw new InvalidDataException()
                    }
                };
                foreach (var artifact in result.ArtifactReferences)
                    events.Add(new(DurableRunnerEventKind.Artifact, DateTimeOffset.UtcNow,
                        Name: Path.GetFileName(artifact), Reference: artifact));
            }
            catch (Exception exception) when (exception is FormatException or ArgumentException or JsonException or
                                                       InvalidDataException or InvalidOperationException or OverflowException)
            {
                Fail(exception is InvalidDataException
                    ? EvaluationRunnerErrorCode.ContextMismatch
                    : EvaluationRunnerErrorCode.MalformedOutput, EvaluationFailureSignal.Harness);
            }
        }

        internal void Fail(EvaluationRunnerErrorCode errorCode, EvaluationFailureSignal signal) =>
            Snapshot = Snapshot with
            {
                ErrorCode = errorCode,
                Failure = EvaluationRetryPolicy.Classify(signal),
                TerminalReceipt = null,
                Result = null
            };

        private void SyncSnapshot() =>
            Snapshot = Snapshot with
            {
                PendingLineBytes = pending.ToArray(),
                Events = events.ToImmutableArray()
            };

        private static TaskEvent ToTaskEvent(DurableRunnerEvent value, IExecutionHandle execution) =>
            value.Kind == DurableRunnerEventKind.Progress
                ? new TaskProgressEvent(execution.AttemptId, execution.Generation, value.Timestamp,
                    value.Fraction ?? 0, value.Message)
                : new TaskArtifactEvent(execution.AttemptId, execution.Generation, value.Timestamp,
                    value.Name ?? "artifact", "application/octet-stream", value.Reference ?? string.Empty, 0);
    }
}
