using System.Text.Json;
using Steward.Domain;

namespace Steward.Tasks.Abstractions;

public readonly record struct TaskTypeVersion(string Name, Version Version)
{
    public override string ToString() => $"{Name}/{Version}";
}

public sealed record ProtectedIdentityHandle(Guid HandleId, string Provider, DateTimeOffset ExpiresAt)
{
    public override string ToString() => $"protected:{Provider}:{HandleId:D}";
}

[System.Text.Json.Serialization.JsonConverter(typeof(TaskPayloadJsonConverter))]
public sealed record TaskPayload
{
    public const int MaximumUtf8Bytes = 64 * 1024;
    public const int MaximumDepth = 64;

    private TaskPayload(string canonicalJson) => CanonicalJson = canonicalJson;

    public string CanonicalJson { get; }

    public static TaskPayload Parse(string canonicalJson)
    {
        ArgumentNullException.ThrowIfNull(canonicalJson);
        if (System.Text.Encoding.UTF8.GetByteCount(canonicalJson) > MaximumUtf8Bytes)
            throw new ArgumentException(
                "Task payload exceeds the UTF-8 size limit.",
                nameof(canonicalJson));
        using var document = JsonDocument.Parse(
            canonicalJson,
            new JsonDocumentOptions
            {
                MaxDepth = MaximumDepth,
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false
            });
        if (document.RootElement.ValueKind == JsonValueKind.Undefined)
            throw new ArgumentException(
                "Task payload is undefined.",
                nameof(canonicalJson));
        return new TaskPayload(canonicalJson);
    }

    public static TaskPayload From<T>(
        T value,
        JsonSerializerOptions? options = null) =>
        Parse(JsonSerializer.Serialize(value, options));

    public T? Deserialize<T>(JsonSerializerOptions? options = null) =>
        JsonSerializer.Deserialize<T>(CanonicalJson, options);
}
internal sealed class TaskPayloadJsonConverter
    : System.Text.Json.Serialization.JsonConverter<TaskPayload>
{
    public override TaskPayload Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        return TaskPayload.Parse(document.RootElement.GetRawText());
    }

    public override void Write(
        Utf8JsonWriter writer,
        TaskPayload value,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.Parse(value.CanonicalJson);
        document.RootElement.WriteTo(writer);
    }
}
public sealed record TaskExecutionContext(
    TaskAttemptId AttemptId,
    int Generation,
    string Workspace,
    TaskPayload Input,
    IReadOnlyList<ProtectedIdentityHandle>? IdentityHandles = null);

public sealed record ValidationResult(bool IsValid, IReadOnlyList<string> Errors)
{
    public static ValidationResult Valid { get; } = new(true, []);
    public static ValidationResult Invalid(params string[] errors) => new(false, errors);
}

public sealed record ReadinessResult(bool IsReady, string? Detail = null);
public sealed record SetupResult(bool Changed, string Fingerprint);
public sealed record CheckpointResult(string Reference, long Size);
public sealed record CleanupResult(bool Completed, string? Detail = null);

public abstract record TaskEvent(TaskAttemptId AttemptId, int Generation, DateTimeOffset Timestamp);
public sealed record TaskProgressEvent(TaskAttemptId AttemptId, int Generation, DateTimeOffset Timestamp, double Fraction, string? Message)
    : TaskEvent(AttemptId, Generation, Timestamp);
public sealed record TaskLogEvent(TaskAttemptId AttemptId, int Generation, DateTimeOffset Timestamp, string Stream, long Offset, ReadOnlyMemory<byte> Data, bool Truncated)
    : TaskEvent(AttemptId, Generation, Timestamp);
public sealed record TaskArtifactEvent(TaskAttemptId AttemptId, int Generation, DateTimeOffset Timestamp, string Name, string MediaType, string Path, long Size)
    : TaskEvent(AttemptId, Generation, Timestamp);

public enum ExecutionState { Launching, Running, Paused, Exited, Recovering, Interrupted }
public sealed record ExecutionObservation(ExecutionState State, int? ExitCode = null, string? Detail = null);

public enum InterruptionResolution { Recover, ResumeFromCheckpoint, Restart, Interrupt }

public static class InterruptionPolicy
{
    public static InterruptionResolution Resolve(InterruptionClass interruptionClass, bool bootChanged, bool checkpointAvailable)
    {
        if (!bootChanged) return InterruptionResolution.Recover;
        return interruptionClass switch
        {
            InterruptionClass.CheckpointResumable when checkpointAvailable => InterruptionResolution.ResumeFromCheckpoint,
            InterruptionClass.CheckpointResumable => InterruptionResolution.Interrupt,
            InterruptionClass.Restartable => InterruptionResolution.Restart,
            InterruptionClass.NonInterruptible => InterruptionResolution.Interrupt,
            _ => throw new ArgumentOutOfRangeException(nameof(interruptionClass))
        };
    }
}

public interface ITaskType
{
    TaskTypeVersion Type { get; }
    TaskCapabilities Capabilities { get; }
    InterruptionClass InterruptionClass { get; }
    ValidationResult Validate(TaskPayload input);
    ValueTask<ReadinessResult> ProbeReadinessAsync(TaskExecutionContext context, CancellationToken cancellationToken);
    ValueTask<SetupResult> SetupAsync(TaskExecutionContext context, CancellationToken cancellationToken);
    ValueTask<IExecutionHandle> StartAsync(TaskExecutionContext context, CancellationToken cancellationToken);
    ValueTask<ExecutionObservation> ObserveAsync(IExecutionHandle execution, CancellationToken cancellationToken);
    ValueTask<CheckpointResult> CheckpointAsync(IExecutionHandle execution, CancellationToken cancellationToken);
    ValueTask PauseAsync(IExecutionHandle execution, CancellationToken cancellationToken);
    ValueTask ResumeAsync(IExecutionHandle execution, CancellationToken cancellationToken);
    ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken);
    ValueTask<IExecutionHandle> RestartAsync(TaskExecutionContext context, IExecutionHandle execution, CancellationToken cancellationToken);
    ValueTask<CleanupResult> CleanupAsync(TaskExecutionContext context, CancellationToken cancellationToken);
}

public enum TaskExecutionRecoveryStatus
{
    Present,
    Absent,
    Ambiguous
}

public sealed record TaskExecutionRecoveryResult(
    TaskExecutionRecoveryStatus Status,
    IExecutionHandle? Execution = null,
    string Code = "runtime.recovery");

public interface IRecoverableTaskType
{
    ValueTask<TaskExecutionRecoveryResult> RecoverExecutionAsync(
        TaskExecutionContext context,
        string currentBootIdentity,
        CancellationToken cancellationToken);
}

public abstract record TaskRuntimeOutput;
public sealed record TaskRuntimeProgress(double Fraction, string? Message) : TaskRuntimeOutput;
public sealed record TaskRuntimeLogCursor(
    string Stream,
    long Offset,
    long Length,
    string ContentHash,
    bool Truncated) : TaskRuntimeOutput;
public sealed record TaskRuntimeArtifact(
    PortableObjectId PortableObjectId,
    string Name,
    string MediaType,
    string Reference,
    long SizeBytes,
    string ContentHash) : TaskRuntimeOutput;
public sealed record TaskRuntimeCheckpoint(
    PortableObjectId PortableObjectId,
    string Reference,
    long SizeBytes,
    string ContentHash) : TaskRuntimeOutput;
public sealed record TaskRuntimeAgentActivity(string Text) : TaskRuntimeOutput;
public sealed record TaskRuntimeAgentFinal(string Text, string Receipt) : TaskRuntimeOutput;

public sealed record TaskOutputBatch(long NextCursor, IReadOnlyList<TaskRuntimeOutput> Outputs);

public interface ITaskOutputSource
{
    ValueTask<TaskOutputBatch> ReadOutputsAsync(
        IExecutionHandle execution,
        long afterCursor,
        int maximumCount,
        CancellationToken cancellationToken);
}

public interface IDurableTaskResultType
{
    ValueTask<string?> CommitTerminalResultAsync(
        IExecutionHandle execution,
        TaskId taskId,
        CancellationToken cancellationToken);
    ValueTask ReleaseDurableStateAsync(
        TaskAttemptId attemptId,
        int generation,
        CancellationToken cancellationToken);
}

public abstract class TaskTypeBase : ITaskType
{
    public abstract TaskTypeVersion Type { get; }
    public abstract TaskCapabilities Capabilities { get; }
    public abstract InterruptionClass InterruptionClass { get; }
    public abstract ValidationResult Validate(TaskPayload input);

    public virtual ValueTask<ReadinessResult> ProbeReadinessAsync(TaskExecutionContext context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(new ReadinessResult(true));
    public virtual ValueTask<SetupResult> SetupAsync(TaskExecutionContext context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(new SetupResult(false, string.Empty));
    public abstract ValueTask<IExecutionHandle> StartAsync(TaskExecutionContext context, CancellationToken cancellationToken);
    public abstract ValueTask<ExecutionObservation> ObserveAsync(IExecutionHandle execution, CancellationToken cancellationToken);
    public virtual ValueTask<CheckpointResult> CheckpointAsync(IExecutionHandle execution, CancellationToken cancellationToken) =>
        Unsupported<CheckpointResult>(TaskCapabilities.Checkpoint);
    public virtual ValueTask PauseAsync(IExecutionHandle execution, CancellationToken cancellationToken) =>
        Unsupported(TaskCapabilities.Pause);
    public virtual ValueTask ResumeAsync(IExecutionHandle execution, CancellationToken cancellationToken) =>
        Unsupported(TaskCapabilities.Resume);
    public abstract ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken);
    public virtual ValueTask<IExecutionHandle> RestartAsync(TaskExecutionContext context, IExecutionHandle execution, CancellationToken cancellationToken) =>
        Unsupported<IExecutionHandle>(TaskCapabilities.Restart);
    public virtual ValueTask<CleanupResult> CleanupAsync(TaskExecutionContext context, CancellationToken cancellationToken) =>
        Unsupported<CleanupResult>(TaskCapabilities.Cleanup);

    protected ValueTask Unsupported(TaskCapabilities capability) =>
        throw new NotSupportedException($"{Type} does not support {capability}.");
    protected ValueTask<T> Unsupported<T>(TaskCapabilities capability) =>
        throw new NotSupportedException($"{Type} does not support {capability}.");
}

public enum ProcessIsolationCapability
{
    Process,
    Compose,
    Evaluation,
    Agent,
    Terminal
}

public sealed record ProcessIsolationProfile(
    int Version,
    ProcessIsolationCapability Capability,
    string WorkspaceRoot,
    string Workspace,
    TaskAttemptId AttemptId,
    int Generation)
{
    public static ProcessIsolationProfile ForTask(
        TaskExecutionContext context,
        ProcessIsolationCapability capability)
    {
        ArgumentNullException.ThrowIfNull(context);
        var root = Directory.GetParent(Path.GetFullPath(context.Workspace))
            ?.FullName ?? throw new ArgumentException(
                "Task workspace has no authority root.",
                nameof(context));
        return new ProcessIsolationProfile(
            1,
            capability,
            root,
            Path.GetFullPath(context.Workspace),
            context.AttemptId,
            context.Generation);
    }
}
internal sealed record ProcessLaunchRequest(
    TaskAttemptId AttemptId,
    int Generation,
    string ApplicationPath,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    string SpoolDirectory,
    long MaxOutputBytes,
    long RequiredDiskReserveBytes,
    bool RequiresInteractiveSession = false,
    GracefulSignal? GracefulSignal = null,
    ProcessResourceLimits? ResourceLimits = null,
    string? StandardInputPath = null,
    ProcessIsolationProfile? Isolation = null);

public sealed record ProcessResourceLimits(long? ProcessMemoryBytes = null, long? JobMemoryBytes = null, uint? ActiveProcessLimit = null);

public enum GracefulSignal { CtrlBreak, CloseMainWindow }

public interface IExecutionHandle
{
    TaskAttemptId AttemptId { get; }
    int Generation { get; }
    int ProcessId { get; }
    long ProcessCreationTimeUtcTicks { get; }
}

public sealed record SpoolCursor(string Stream, string Path, long Offset, long Length, bool Truncated);
public sealed record SpoolRead(SpoolCursor Cursor, ReadOnlyMemory<byte> Data);

internal interface IProcessExecutor
{
    ValueTask<IExecutionHandle> StartAsync(ProcessLaunchRequest request, CancellationToken cancellationToken);
    ValueTask<ExecutionObservation> ObserveAsync(IExecutionHandle execution, CancellationToken cancellationToken);
    ValueTask<SpoolRead> ReadOutputAsync(IExecutionHandle execution, string stream, long offset, int maximumBytes, CancellationToken cancellationToken);
    ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken);
    ValueTask<IExecutionHandle> RecoverAsync(TaskAttemptId attemptId, int generation, string currentBootId, CancellationToken cancellationToken);
}

[Flags]
public enum HostRuntimeCapabilities
{
    None = 0,
    Process = 1 << 0,
    ResourceControl = 1 << 1,
    BoundedFileOutput = 1 << 2,
    ProcessTreeCancellation = 1 << 3,
    ProcessRecovery = 1 << 4
}

public sealed record HostRuntimeDescriptor(string Name, Version Version, HostRuntimeCapabilities Capabilities);

internal interface IHostRuntime
{
    HostRuntimeDescriptor Descriptor { get; }
    IProcessExecutor Processes { get; }
}

public sealed class ExecutionRecoveryException(string message, bool isAmbiguous) : InvalidOperationException(message)
{
    public bool IsAmbiguous { get; } = isAmbiguous;
}
