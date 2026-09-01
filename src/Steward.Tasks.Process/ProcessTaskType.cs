using System.Text.Json;
using Steward.Domain;
using Steward.Tasks.Abstractions;

namespace Steward.Tasks.Process;

internal sealed record ProcessTaskDefinition(
    string Executable,
    IReadOnlyList<string>? Arguments = null,
    string? WorkingDirectory = null,
    string? ReadinessPath = null,
    IReadOnlyList<string>? SetupDirectories = null,
    IReadOnlyList<string>? CleanupPaths = null,
    long MaxOutputBytes = 64 * 1024 * 1024,
    long RequiredDiskReserveBytes = 256 * 1024 * 1024,
    GracefulSignal? GracefulSignal = null);

internal sealed class ProcessTaskType(
    IProcessExecutor executor,
    Action<string>? diagnostic = null) :
    TaskTypeBase,
    IRecoverableTaskType,
    ITaskOutputSource
{
    private const int MaximumOutputReadBytes = 64 * 1024;
    private const long CursorMask = 0x7fff_ffff;
    private static readonly JsonSerializerOptions JsonOptions =
        CanonicalTaskJson.CreateOptions();
    public override TaskTypeVersion Type { get; } = new("process", new Version(1, 0));
    public override TaskCapabilities Capabilities =>
        TaskCapabilities.Prepare | TaskCapabilities.Execute | TaskCapabilities.Observe |
        TaskCapabilities.Cancel | TaskCapabilities.Restart | TaskCapabilities.Cleanup;
    public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;

    public override ValidationResult Validate(TaskPayload input)
    {
        ProcessTaskDefinition? definition;
        try { definition = input.Deserialize<ProcessTaskDefinition>(JsonOptions); }
        catch (JsonException exception) { return ValidationResult.Invalid(exception.Message); }
        if (definition is null) return ValidationResult.Invalid("Definition is required.");
        var errors = new List<string>();
        if (!Path.IsPathFullyQualified(definition.Executable)) errors.Add("Executable must be an absolute path.");
        if (Path.GetExtension(definition.Executable).Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
            Path.GetExtension(definition.Executable).Equals(".cmd", StringComparison.OrdinalIgnoreCase))
            errors.Add("Shell and batch files are not supported.");
        if (definition.MaxOutputBytes is <= 0 or > CursorMask)
            errors.Add($"MaxOutputBytes must be between 1 and {CursorMask}.");
        if (definition.RequiredDiskReserveBytes < 0) errors.Add("RequiredDiskReserveBytes cannot be negative.");
        if (definition.GracefulSignal == GracefulSignal.CtrlBreak) errors.Add("CTRL_BREAK is unavailable for non-interactive execution.");
        ValidatePath(definition.WorkingDirectory, "WorkingDirectory", errors);
        ValidatePath(definition.ReadinessPath, "ReadinessPath", errors);
        foreach (var path in definition.SetupDirectories ?? []) ValidatePath(path, "SetupDirectories", errors, required: true);
        foreach (var path in definition.CleanupPaths ?? []) ValidatePath(path, "CleanupPaths", errors, required: true);
        return errors.Count == 0 ? ValidationResult.Valid : new(false, errors);
    }

    public override ValueTask<ReadinessResult> ProbeReadinessAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var definition = Get(context);
        var readinessPath = definition.ReadinessPath is null
            ? definition.Executable
            : WorkspacePaths.Resolve(context.Workspace, definition.ReadinessPath);
        var detail = definition.ReadinessPath is null
            ? "Executable availability"
            : "Readiness path";
        var ready = File.Exists(readinessPath);
        if (!ready)
            diagnostic?.Invoke(
                $"{detail} failed for managed path '{readinessPath}'.");
        return ValueTask.FromResult(new ReadinessResult(ready, detail));
    }

    public override ValueTask<SetupResult> SetupAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var definition = Get(context);
        var changed = false;
        foreach (var item in definition.SetupDirectories ?? [])
        {
            var path = WorkspacePaths.Resolve(context.Workspace, item);
            if (!Directory.Exists(path)) { Directory.CreateDirectory(path); changed = true; }
        }
        var fingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(definition, JsonOptions))));
        return ValueTask.FromResult(new SetupResult(changed, fingerprint));
    }

    public override ValueTask<IExecutionHandle> StartAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        var definition = Get(context);
        var workingDirectory = definition.WorkingDirectory is null
            ? context.Workspace : WorkspacePaths.Resolve(context.Workspace, definition.WorkingDirectory);
        return executor.StartAsync(new(context.AttemptId, context.Generation, definition.Executable,
            definition.Arguments ?? [], workingDirectory, Path.Combine(context.Workspace, ".steward", "spool"),
            definition.MaxOutputBytes, definition.RequiredDiskReserveBytes, false, definition.GracefulSignal,
            Isolation: ProcessIsolationProfile.ForTask(
                context,
                ProcessIsolationCapability.Process)), cancellationToken);
    }

    public override ValueTask<ExecutionObservation> ObserveAsync(IExecutionHandle execution, CancellationToken cancellationToken) =>
        executor.ObserveAsync(execution, cancellationToken);

    public async ValueTask<TaskExecutionRecoveryResult> RecoverExecutionAsync(
        TaskExecutionContext context,
        string currentBootIdentity,
        CancellationToken cancellationToken)
    {
        try
        {
            var execution = await executor.RecoverAsync(
                context.AttemptId, context.Generation, currentBootIdentity, cancellationToken);
            return new(TaskExecutionRecoveryStatus.Present, execution, "process.present");
        }
        catch (ExecutionRecoveryException exception)
        {
            return new(
                exception.IsAmbiguous ? TaskExecutionRecoveryStatus.Ambiguous : TaskExecutionRecoveryStatus.Absent,
                Code: exception.IsAmbiguous ? "process.identity-ambiguous" : "process.absent");
        }
        catch (KeyNotFoundException)
        {
            return new(TaskExecutionRecoveryStatus.Absent, Code: "process.not-journaled");
        }
    }

    public async ValueTask<TaskOutputBatch> ReadOutputsAsync(
        IExecutionHandle execution,
        long afterCursor,
        int maximumCount,
        CancellationToken cancellationToken)
    {
        if (afterCursor < 0 || maximumCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(afterCursor));
        var stdoutOffset = afterCursor >> 31;
        var stderrOffset = afterCursor & CursorMask;
        var outputs = new List<TaskRuntimeOutput>(2);
        if (maximumCount > 0)
        {
            var stdout = await executor.ReadOutputAsync(
                execution, "stdout", stdoutOffset, MaximumOutputReadBytes, cancellationToken);
            if (!stdout.Data.IsEmpty || stdout.Cursor.Truncated)
            {
                outputs.Add(ToOutput("stdout", stdoutOffset, stdout));
                stdoutOffset = stdout.Cursor.Offset;
            }
        }
        if (maximumCount > outputs.Count)
        {
            var stderr = await executor.ReadOutputAsync(
                execution, "stderr", stderrOffset, MaximumOutputReadBytes, cancellationToken);
            if (!stderr.Data.IsEmpty || stderr.Cursor.Truncated)
            {
                outputs.Add(ToOutput("stderr", stderrOffset, stderr));
                stderrOffset = stderr.Cursor.Offset;
            }
        }
        if (stdoutOffset > CursorMask || stderrOffset > CursorMask)
            throw new InvalidOperationException("Process output cursor exceeds its durable bound.");
        return new((stdoutOffset << 31) | stderrOffset, outputs);
    }

    public override ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken) =>
        executor.CancelAsync(execution, gracePeriod, cancellationToken);

    public override async ValueTask<IExecutionHandle> RestartAsync(TaskExecutionContext context, IExecutionHandle execution, CancellationToken cancellationToken)
    {
        await executor.CancelAsync(execution, TimeSpan.FromSeconds(5), cancellationToken);
        return await StartAsync(context, cancellationToken);
    }

    public override ValueTask<CleanupResult> CleanupAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var item in Get(context).CleanupPaths ?? [])
        {
            var path = WorkspacePaths.Resolve(context.Workspace, item);
            if (Directory.Exists(path)) Directory.Delete(path, true);
            else if (File.Exists(path)) File.Delete(path);
        }
        return ValueTask.FromResult(new CleanupResult(true));
    }

    private ProcessTaskDefinition Get(TaskExecutionContext context)
    {
        var validation = Validate(context.Input);
        if (!validation.IsValid) throw new ArgumentException(string.Join("; ", validation.Errors));
        return context.Input.Deserialize<ProcessTaskDefinition>(JsonOptions)!;
    }

    private static void ValidatePath(string? path, string name, List<string> errors, bool required = false)
    {
        if (path is null && !required) return;
        if (!WorkspacePaths.IsSafeRelative(path)) errors.Add($"{name} entries must be non-empty workspace-relative paths without '..'.");
    }

    private static TaskRuntimeLogCursor ToOutput(string stream, long offset, SpoolRead read) =>
        new(stream, offset, read.Data.Length,
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(read.Data.Span)).ToLowerInvariant(),
            read.Cursor.Truncated);
}
