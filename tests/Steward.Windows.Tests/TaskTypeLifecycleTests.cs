using System.Text.Json;
using Steward.Agents;
using Steward.Domain;
using Steward.Tasks.Abstractions;
using Steward.Tasks.Compose;
using Steward.Tasks.Process;

namespace Steward.Windows.Tests;

public sealed class TaskTypeLifecycleTests : IDisposable
{
    private readonly string workspace = Path.Combine(Path.GetTempPath(), "steward-lifecycle", Guid.NewGuid().ToString("N"));

    public TaskTypeLifecycleTests() => Directory.CreateDirectory(workspace);

    [Fact]
    public async Task Process_setup_readiness_cleanup_and_capabilities_are_explicit()
    {
        var executable = Path.Combine(Environment.SystemDirectory, "where.exe");
        var definition = new ProcessTaskDefinition(executable, ["dotnet"], ReadinessPath: "ready",
            SetupDirectories: ["created"], CleanupPaths: ["created"]);
        var context = Context(definition);
        var type = new ProcessTaskType(new FakeExecutor());

        Assert.True(type.Validate(context.Input).IsValid);
        Assert.True((await type.SetupAsync(context, default)).Changed);
        Assert.False((await type.ProbeReadinessAsync(context, default)).IsReady);
        await File.WriteAllTextAsync(Path.Combine(workspace, "ready"), "ready");
        Assert.True((await type.ProbeReadinessAsync(context, default)).IsReady);
        await Assert.ThrowsAsync<NotSupportedException>(() => type.PauseAsync(new FakeHandle(context.AttemptId, 1, 1, 1), default).AsTask());
        Assert.True((await type.CleanupAsync(context, default)).Completed);
        Assert.False(Directory.Exists(Path.Combine(workspace, "created")));
        Assert.DoesNotContain(TaskCapabilities.Pause, Flags(type.Capabilities));
    }

    [Fact]
    public async Task Compose_uses_explicit_docker_project_workspace_and_cleanup_arguments()
    {
        var composeFile = Path.Combine(workspace, "compose.yml");
        await File.WriteAllTextAsync(composeFile, "services: {}");
        var docker = Path.Combine(workspace, "docker.exe");
        await File.WriteAllBytesAsync(docker, []);
        var fake = new FakeExecutor();
        var type = new ComposeTaskType(fake);
        var context = Context(new ComposeTaskDefinition(docker, "compose.yml", "project_1", RemoveVolumesOnCleanup: true));

        Assert.True(type.Validate(context.Input).IsValid);
        Assert.False((await type.SetupAsync(context, default)).Changed);
        Assert.True((await type.ProbeReadinessAsync(context, default)).IsReady);
        await type.StartAsync(context, default);
        var running = await type.StartAsync(Context(new ComposeTaskDefinition(docker, "compose.yml", "project_2")), default);
        await type.CancelAsync(running, TimeSpan.FromSeconds(1), default);
        Assert.True((await type.CleanupAsync(context, default)).Completed);

        Assert.All(fake.Requests, request => Assert.Equal(docker, request.ApplicationPath));
        Assert.All(fake.Requests, request =>
        {
            Assert.Equal("--host", request.Arguments[0]);
            Assert.Equal(
                "npipe:////./pipe/docker_engine",
                request.Arguments[1]);
        });
        Assert.Contains(fake.Requests, request => request.Arguments.Contains("--project-name") && request.Arguments.Contains("project_1"));
        Assert.Contains(fake.Requests, request => request.Arguments.Contains("up") && request.Arguments.Contains("--abort-on-container-exit"));
        Assert.Contains(fake.Requests, request => request.Arguments.Contains("down") && request.Arguments.Contains("--volumes"));
        var cancelledIndex = fake.Events.FindIndex(item => item == $"cancel:{running.AttemptId}");
        var downIndex = fake.Events.FindIndex(item => item.StartsWith("start:", StringComparison.Ordinal) && item.Contains(":down", StringComparison.Ordinal));
        Assert.True(downIndex >= 0 && downIndex < cancelledIndex);
    }

    [Fact]
    public async Task Compose_materializes_declared_content_and_rejects_mismatch()
    {
        var docker = Path.Combine(workspace, "docker.exe");
        await File.WriteAllBytesAsync(docker, []);
        const string content = "services:\n  canary:\n    image: steward/canary\n";
        var type = new ComposeTaskType(new FakeExecutor());
        var context = Context(new ComposeTaskDefinition(
            docker,
            "nested/compose.yml",
            "materialized",
            ComposeContent: content));

        var setup = await type.SetupAsync(context, default);

        Assert.False(setup.Changed);
        Assert.Equal(
            content,
            await File.ReadAllTextAsync(
                Path.Combine(workspace, "nested", "compose.yml")));
        await File.WriteAllTextAsync(
            Path.Combine(workspace, "nested", "compose.yml"),
            "services: {}");
        await Assert.ThrowsAsync<InvalidDataException>(
            () => type.SetupAsync(context, default).AsTask());
    }

    [Fact]
    public async Task Recovered_compose_context_can_issue_down_after_original_cli_exit()
    {
        var docker = Path.Combine(workspace, "docker.exe");
        await File.WriteAllBytesAsync(docker, []);
        await File.WriteAllTextAsync(Path.Combine(workspace, "compose.yml"), "services: {}");
        var fake = new FakeExecutor();
        var type = new ComposeTaskType(fake);
        var context = Context(new ComposeTaskDefinition(docker, "compose.yml", "recovered"));
        var recovered = new FakeHandle(context.AttemptId, context.Generation, 42, 42);

        type.RegisterRecoveredExecution(recovered, context);
        await type.CancelAsync(recovered, TimeSpan.FromSeconds(1), default);

        Assert.Contains(fake.Requests, request =>
            request.Arguments.Contains("down") &&
            request.Arguments.Contains("--remove-orphans") &&
            request.Arguments.Contains("recovered"));
    }

    [Fact]
    public async Task Process_recovery_and_output_cursors_are_exact_and_bounded()
    {
        var fake = new FakeExecutor();
        var type = new ProcessTaskType(fake);
        var context = Context(new ProcessTaskDefinition(
            Path.Combine(Environment.SystemDirectory, "where.exe")));
        fake.Recovered = new FakeHandle(context.AttemptId, context.Generation, 42, 42);

        var recovery = await type.RecoverExecutionAsync(context, "boot", default);
        Assert.Equal(TaskExecutionRecoveryStatus.Present, recovery.Status);
        var first = await type.ReadOutputsAsync(recovery.Execution!, 0, 2, default);
        Assert.Equal(2, first.Outputs.Count);
        Assert.All(first.Outputs.Cast<TaskRuntimeLogCursor>(), output =>
        {
            Assert.Equal(64, output.ContentHash.Length);
            Assert.InRange(output.Length, 1, 64 * 1024);
        });
        var replay = await type.ReadOutputsAsync(recovery.Execution!, first.NextCursor, 2, default);
        Assert.Empty(replay.Outputs);
        Assert.Equal(first.NextCursor, replay.NextCursor);
    }

    [Fact]
    public void Task_paths_reject_workspace_escape_and_invalid_limits()
    {
        var executable = Path.Combine(Environment.SystemDirectory, "where.exe");
        var process = new ProcessTaskType(new FakeExecutor());
        Assert.False(process.Validate(Context(new ProcessTaskDefinition(executable, WorkingDirectory: "..\\outside")).Input).IsValid);
        Assert.False(process.Validate(Context(new ProcessTaskDefinition(executable, ReadinessPath: "C:\\outside")).Input).IsValid);
        Assert.False(process.Validate(Context(new ProcessTaskDefinition(executable, SetupDirectories: ["safe\\..\\outside"])).Input).IsValid);

        var compose = new ComposeTaskType(new FakeExecutor());
        Assert.False(compose.Validate(Context(new ComposeTaskDefinition(executable, "..\\compose.yml", "bad name",
            Profiles: ["bad profile"], MaxOutputBytes: 0, RequiredDiskReserveBytes: -1)).Input).IsValid);
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("con.txt")]
    [InlineData("nested\\PRN.")]
    [InlineData("nested\\AUX   ")]
    [InlineData("NUL.log")]
    [InlineData("COM1")]
    [InlineData("com9.trace")]
    [InlineData("LPT1")]
    [InlineData("lpt9...")]
    [InlineData("CON :stream")]
    public void Windows_reserved_device_components_are_rejected_across_task_paths(string relativePath)
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.False(WorkspacePaths.IsSafeRelative(relativePath));
        Assert.Throws<ArgumentException>(() => WorkspacePaths.Resolve(workspace, relativePath));

        var executable = Path.Combine(Environment.SystemDirectory, "where.exe");
        var process = new ProcessTaskType(new FakeExecutor());
        Assert.False(process.Validate(Context(new ProcessTaskDefinition(
            executable, WorkingDirectory: relativePath, ReadinessPath: relativePath,
            SetupDirectories: [relativePath], CleanupPaths: [relativePath])).Input).IsValid);

        var compose = new ComposeTaskType(new FakeExecutor());
        Assert.False(compose.Validate(Context(new ComposeTaskDefinition(
            executable, relativePath, "reserved", WorkingDirectory: relativePath)).Input).IsValid);

        var worktree = Path.Combine(workspace, relativePath);
        Assert.Throws<ArgumentException>(() =>
            new ReparseAwareWorktreePathValidator().ValidateContainedPath(workspace, worktree));
    }

    [Theory]
    [InlineData("console")]
    [InlineData("COM0")]
    [InlineData("COM10")]
    [InlineData("LPT0.txt")]
    [InlineData("LPT10.txt")]
    [InlineData("auxiliary.log")]
    public void Similar_non_device_components_remain_valid(string relativePath)
    {
        Assert.True(WorkspacePaths.IsSafeRelative(relativePath));
        Assert.Equal(Path.GetFullPath(Path.Combine(workspace, relativePath)),
            WorkspacePaths.Resolve(workspace, relativePath));
    }

    [Fact]
    public async Task Cleanup_rejects_reparse_point_before_destructive_delete()
    {
        if (!OperatingSystem.IsWindows()) return;
        var outside = Path.Combine(Path.GetDirectoryName(workspace)!, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outside);
        await File.WriteAllTextAsync(Path.Combine(outside, "keep"), "safe");
        var link = Path.Combine(workspace, "linked");
        using var command = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            ArgumentList = { "/d", "/c", "mklink", "/J", link, outside },
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
        await command.WaitForExitAsync();
        Assert.Equal(0, command.ExitCode);
        var executable = Path.Combine(Environment.SystemDirectory, "where.exe");
        var type = new ProcessTaskType(new FakeExecutor());
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            type.CleanupAsync(Context(new ProcessTaskDefinition(executable, CleanupPaths: ["linked"])), default).AsTask());
        Assert.True(File.Exists(Path.Combine(outside, "keep")));
        Directory.Delete(link);
        Directory.Delete(outside, true);
    }

    [Theory]
    [InlineData(InterruptionClass.CheckpointResumable, true, InterruptionResolution.ResumeFromCheckpoint)]
    [InlineData(InterruptionClass.CheckpointResumable, false, InterruptionResolution.Interrupt)]
    [InlineData(InterruptionClass.Restartable, false, InterruptionResolution.Restart)]
    [InlineData(InterruptionClass.NonInterruptible, true, InterruptionResolution.Interrupt)]
    public void Changed_boot_resolves_by_interruption_class(
        InterruptionClass interruptionClass, bool checkpoint, InterruptionResolution expected) =>
        Assert.Equal(expected, InterruptionPolicy.Resolve(interruptionClass, true, checkpoint));

    private TaskExecutionContext Context<T>(T definition) =>
        new(TaskAttemptId.New(), 1, workspace, TaskPayload.From(definition));

    private static IEnumerable<TaskCapabilities> Flags(TaskCapabilities value) =>
        Enum.GetValues<TaskCapabilities>().Where(flag => flag != TaskCapabilities.None && value.HasFlag(flag));

    public void Dispose()
    {
        try { Directory.Delete(workspace, true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private sealed record FakeHandle(TaskAttemptId AttemptId, int Generation, int ProcessId, long ProcessCreationTimeUtcTicks) : IExecutionHandle;

    private sealed class FakeExecutor : IProcessExecutor
    {
        public IExecutionHandle? Recovered { get; set; }
        public List<ProcessLaunchRequest> Requests { get; } = [];
        public List<string> Events { get; } = [];
        public ValueTask<IExecutionHandle> StartAsync(ProcessLaunchRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            var operation = request.Arguments.Contains("down") ? "down" : request.Arguments.Contains("up") ? "up" : "other";
            Events.Add($"start:{request.AttemptId}:{operation}");
            return ValueTask.FromResult<IExecutionHandle>(new FakeHandle(request.AttemptId, request.Generation, Requests.Count, Requests.Count));
        }
        public ValueTask<ExecutionObservation> ObserveAsync(IExecutionHandle execution, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new ExecutionObservation(ExecutionState.Exited, 0));
        public ValueTask<SpoolRead> ReadOutputAsync(IExecutionHandle execution, string stream, long offset, int maximumBytes, CancellationToken cancellationToken)
        {
            var bytes = offset == 0 ? System.Text.Encoding.UTF8.GetBytes(stream) : [];
            return ValueTask.FromResult(new SpoolRead(
                new(stream, $"{stream}.log", offset + bytes.Length, bytes.Length, false), bytes));
        }
        public ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken)
        {
            Events.Add($"cancel:{execution.AttemptId}");
            return ValueTask.CompletedTask;
        }
        public ValueTask<IExecutionHandle> RecoverAsync(TaskAttemptId attemptId, int generation, string currentBootId, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Recovered ?? throw new KeyNotFoundException());
    }
}
