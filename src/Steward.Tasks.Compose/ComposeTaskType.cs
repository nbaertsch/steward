using System.Collections.Concurrent;
using System.Text.Json;
using Steward.Domain;
using Steward.Tasks.Abstractions;

namespace Steward.Tasks.Compose;

internal sealed record ComposeTaskDefinition(
    string DockerExecutable,
    string ComposeFile,
    string ProjectName,
    string? WorkingDirectory = null,
    IReadOnlyList<string>? Profiles = null,
    long MaxOutputBytes = 64 * 1024 * 1024,
    long RequiredDiskReserveBytes = 256 * 1024 * 1024,
    bool RemoveVolumesOnCleanup = false);

/// <summary>
/// Supervises the Docker CLI process. Containers remain owned and isolated by
/// the Docker engine; Job Object containment does not extend into containers.
/// </summary>
internal sealed class ComposeTaskType(IProcessExecutor executor) : TaskTypeBase, IRecoverableTaskType, ITaskOutputSource
{
    private const int MaximumOutputReadBytes = 64 * 1024;
    private const long CursorMask = 0x7fff_ffff;
    private readonly ConcurrentDictionary<(TaskAttemptId AttemptId, int Generation), TaskExecutionContext> managed = new();
    private static readonly JsonSerializerOptions JsonOptions =
        CanonicalTaskJson.CreateOptions();
    public override TaskTypeVersion Type { get; } = new("docker-compose", new Version(1, 0));
    public override TaskCapabilities Capabilities =>
        TaskCapabilities.Prepare | TaskCapabilities.Execute | TaskCapabilities.Observe |
        TaskCapabilities.Cancel | TaskCapabilities.Restart | TaskCapabilities.Cleanup;
    public override InterruptionClass InterruptionClass => InterruptionClass.Restartable;

    public override ValidationResult Validate(TaskPayload input)
    {
        ComposeTaskDefinition? definition;
        try { definition = input.Deserialize<ComposeTaskDefinition>(JsonOptions); }
        catch (JsonException exception) { return ValidationResult.Invalid(exception.Message); }
        if (definition is null) return ValidationResult.Invalid("Definition is required.");
        var errors = new List<string>();
        if (!Path.IsPathFullyQualified(definition.DockerExecutable)) errors.Add("DockerExecutable must be an absolute path.");
        if (Path.GetExtension(definition.DockerExecutable).Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
            Path.GetExtension(definition.DockerExecutable).Equals(".bat", StringComparison.OrdinalIgnoreCase))
            errors.Add("DockerExecutable cannot be a shell script.");
        if (string.IsNullOrWhiteSpace(definition.ProjectName) ||
            definition.ProjectName.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_')))
            errors.Add("ProjectName must contain only letters, digits, '-' or '_'.");
        if (string.IsNullOrWhiteSpace(definition.ComposeFile)) errors.Add("ComposeFile is required.");
        else if (!WorkspacePaths.IsSafeRelative(definition.ComposeFile)) errors.Add("ComposeFile must be a workspace-relative path without '..'.");
        if (definition.WorkingDirectory is not null && !WorkspacePaths.IsSafeRelative(definition.WorkingDirectory))
            errors.Add("WorkingDirectory must be a workspace-relative path without '..'.");
        if (definition.Profiles?.Any(profile => string.IsNullOrWhiteSpace(profile) ||
            profile.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.'))) == true)
            errors.Add("Profiles may contain only letters, digits, '-', '_' or '.'.");
        if (definition.MaxOutputBytes is <= 0 or > CursorMask)
            errors.Add($"MaxOutputBytes must be between 1 and {CursorMask}.");
        if (definition.RequiredDiskReserveBytes < 0) errors.Add("RequiredDiskReserveBytes cannot be negative.");
        return errors.Count == 0 ? ValidationResult.Valid : new(false, errors);
    }

    public override async ValueTask<ReadinessResult> ProbeReadinessAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        var execution = await StartCommand(context, ["config", "--quiet"], "readiness", cancellationToken);
        while (true)
        {
            var result = await executor.ObserveAsync(execution, cancellationToken);
            if (result.State == ExecutionState.Exited) return new(result.ExitCode == 0, $"docker compose config exited {result.ExitCode}");
            await Task.Delay(25, cancellationToken);
        }
    }

    public override ValueTask<SetupResult> SetupAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var definition = Get(context);
        var composePath = WorkspacePaths.Resolve(context.Workspace, definition.ComposeFile);
        if (!File.Exists(composePath)) throw new FileNotFoundException("Compose file not found.", composePath);
        var fingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(composePath)));
        return ValueTask.FromResult(new SetupResult(false, fingerprint));
    }

    public override async ValueTask<IExecutionHandle> StartAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        var execution = await StartCommand(context, ["up", "--abort-on-container-exit"], null, cancellationToken);
        managed[(execution.AttemptId, execution.Generation)] = context;
        return execution;
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
            RegisterRecoveredExecution(execution, context);
            return new(TaskExecutionRecoveryStatus.Present, execution, "compose.present");
        }
        catch (ExecutionRecoveryException exception)
        {
            return new(
                exception.IsAmbiguous ? TaskExecutionRecoveryStatus.Ambiguous : TaskExecutionRecoveryStatus.Absent,
                Code: exception.IsAmbiguous ? "compose.identity-ambiguous" : "compose.absent");
        }
        catch (KeyNotFoundException)
        {
            return new(TaskExecutionRecoveryStatus.Absent, Code: "compose.not-journaled");
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
        var stdout = await executor.ReadOutputAsync(
            execution, "stdout", stdoutOffset, MaximumOutputReadBytes, cancellationToken);
        if (!stdout.Data.IsEmpty || stdout.Cursor.Truncated)
        {
            outputs.Add(ToOutput("stdout", stdoutOffset, stdout));
            stdoutOffset = stdout.Cursor.Offset;
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
            throw new InvalidOperationException("Compose output cursor exceeds its durable bound.");
        return new((stdoutOffset << 31) | stderrOffset, outputs);
    }

    public override async ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken)
    {
        if (!managed.TryGetValue((execution.AttemptId, execution.Generation), out var context))
            throw new InvalidOperationException("Recovered Compose execution requires its TaskExecutionContext before cancellation.");
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(gracePeriod > TimeSpan.Zero ? gracePeriod : TimeSpan.FromSeconds(30));
            await ExecuteDownAsync(context, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
        finally
        {
            try { await executor.CancelAsync(execution, TimeSpan.Zero, cancellationToken); }
            catch (InvalidOperationException) { }
            managed.TryRemove((execution.AttemptId, execution.Generation), out _);
        }
    }

    public void RegisterRecoveredExecution(IExecutionHandle execution, TaskExecutionContext context)
    {
        if (execution.AttemptId != context.AttemptId || execution.Generation != context.Generation)
            throw new ArgumentException("Recovered execution identity does not match its Compose context.", nameof(context));
        _ = Get(context);
        managed[(execution.AttemptId, execution.Generation)] = context;
    }

    public override async ValueTask<IExecutionHandle> RestartAsync(TaskExecutionContext context, IExecutionHandle execution, CancellationToken cancellationToken)
    {
        await executor.CancelAsync(execution, TimeSpan.FromSeconds(5), cancellationToken);
        return await StartAsync(context, cancellationToken);
    }

    public override async ValueTask<CleanupResult> CleanupAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        var result = await ExecuteDownAsync(context, cancellationToken);
        return new(result.ExitCode == 0, $"docker compose down exited {result.ExitCode}");
    }

    private async ValueTask<ExecutionObservation> ExecuteDownAsync(TaskExecutionContext context, CancellationToken cancellationToken)
    {
        var definition = Get(context);
        var command = new List<string> { "down", "--remove-orphans" };
        if (definition.RemoveVolumesOnCleanup) command.Add("--volumes");
        var execution = await StartCommand(context, command, "cleanup", cancellationToken);
        try
        {
            while (true)
            {
                var result = await executor.ObserveAsync(execution, cancellationToken);
                if (result.State == ExecutionState.Exited) return result;
                await Task.Delay(25, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            await executor.CancelAsync(execution, TimeSpan.Zero, CancellationToken.None);
            throw;
        }
    }

    private ValueTask<IExecutionHandle> StartCommand(TaskExecutionContext context, IReadOnlyList<string> command, string? operation, CancellationToken cancellationToken)
    {
        var definition = Get(context);
        var workspace = definition.WorkingDirectory is null ? context.Workspace : WorkspacePaths.Resolve(context.Workspace, definition.WorkingDirectory);
        var arguments = new List<string> { "compose", "--project-name", definition.ProjectName, "--file", WorkspacePaths.Resolve(context.Workspace, definition.ComposeFile) };
        foreach (var profile in definition.Profiles ?? []) { arguments.Add("--profile"); arguments.Add(profile); }
        arguments.AddRange(command);
        var attemptId = operation is null ? context.AttemptId : TaskAttemptId.New();
        return executor.StartAsync(new(attemptId, context.Generation, definition.DockerExecutable, arguments,
            workspace, Path.Combine(context.Workspace, ".steward", "spool"), definition.MaxOutputBytes,
            definition.RequiredDiskReserveBytes,
            Isolation: ProcessIsolationProfile.ForTask(
                context,
                ProcessIsolationCapability.Compose)), cancellationToken);
    }

    private ComposeTaskDefinition Get(TaskExecutionContext context)
    {
        var validation = Validate(context.Input);
        if (!validation.IsValid) throw new ArgumentException(string.Join("; ", validation.Errors));
        return context.Input.Deserialize<ComposeTaskDefinition>(JsonOptions)!;
    }

    private static TaskRuntimeLogCursor ToOutput(string stream, long offset, SpoolRead read) =>
        new(stream, offset, read.Data.Length,
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(read.Data.Span)).ToLowerInvariant(),
            read.Cursor.Truncated);
}
