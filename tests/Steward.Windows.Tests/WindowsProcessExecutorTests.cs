using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Steward.Domain;
using Steward.Runtime.Windows;
using Steward.Tasks.Abstractions;

namespace Steward.Windows.Tests;

public sealed class WindowsProcessExecutorTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "steward-tests", Guid.NewGuid().ToString("N"));
    private readonly InProcessJobHandleKeeper keeper = new();
    private readonly NodeIncarnationId nodeIncarnationId = NodeIncarnationId.New();

    public WindowsProcessExecutorTests() => Directory.CreateDirectory(directory);

    [Fact]
    public void Boot_identity_uses_Windows_kernel_evidence_or_is_unverified()
    {
        if (!OperatingSystem.IsWindows()) return;

        var first = WindowsBootIdentity.Capture();
        var second = WindowsBootIdentity.Capture();

        Assert.False(string.IsNullOrWhiteSpace(first.Identity));
        Assert.False(string.IsNullOrWhiteSpace(first.Source));
        if (first.Verified)
        {
            Assert.Equal(
                "NtQuerySystemInformation.SystemTimeOfDayInformation",
                first.Source);
            Assert.Equal(first.Identity, second.Identity);
            Assert.True(second.Verified);
        }
        else
        {
            Assert.StartsWith("unverified/", first.Identity,
                StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("plain")]
    [InlineData("with space")]
    [InlineData("quote\"inside")]
    [InlineData("trailing slash\\")]
    [InlineData("both \\\" things")]
    public void Windows_argument_encoding_round_trips(string value)
    {
        var encoded = WindowsProcessExecutor.QuoteWindowsArgument(value);
        var pointer = CommandLineToArgvW("probe.exe " + encoded, out var count);
        Assert.NotEqual(IntPtr.Zero, pointer);
        try
        {
            Assert.Equal(2, count);
            Assert.Equal(value, Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, IntPtr.Size)));
        }
        finally { LocalFree(pointer); }
    }

    [Fact]
    public async Task Rejects_batch_and_interactive_launches()
    {
        if (!OperatingSystem.IsWindows()) return;
        var batch = Path.Combine(directory, "run.cmd");
        await File.WriteAllTextAsync(batch, "@echo off");
        using var executor = CreateExecutor();
        await Assert.ThrowsAsync<NotSupportedException>(() =>
            executor.StartAsync(Request(batch), default).AsTask());
        var executable = Path.Combine(Environment.SystemDirectory, "where.exe");
        await Assert.ThrowsAsync<NotSupportedException>(() =>
            executor.StartAsync(Request(executable) with { RequiresInteractiveSession = true }, default).AsTask());
    }

    [Fact]
    public async Task Child_inherits_only_declared_standard_handles()
    {
        if (!OperatingSystem.IsWindows()) return;
        var sentinelPath = Path.Combine(directory, "sentinel");
        using var sentinel = File.OpenHandle(sentinelPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
        Assert.True(SetHandleInformation(sentinel, 1, 1));
        var value = sentinel.DangerousGetHandle().ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture);
        using var executor = CreateExecutor();
        var handle = await executor.StartAsync(Request(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            ["/d", "/c", $"echo X >&{value}"]), default);
        await WaitForExit(executor, handle);
        Assert.Equal(0, new FileInfo(sentinelPath).Length);
    }

    [Fact]
    public async Task Large_output_does_not_block_and_is_capped()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var executor = CreateExecutor();
        var request = Request(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            ["/d", "/c", "for /L %i in (1,1,10000) do @echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"])
            with
        { MaxOutputBytes = 32 * 1024 };
        var handle = await executor.StartAsync(request, default);
        await WaitForExit(executor, handle);
        var journal = new ExecutionJournal(Path.Combine(directory, "journal.db"));
        Assert.True(SpinWait.SpinUntil(() => journal.Get(handle.AttemptId, handle.Generation)!.OutputTruncated, TimeSpan.FromSeconds(5)));
        var entry = journal.Get(handle.AttemptId, handle.Generation)!;
        Assert.True(entry.OutputTruncated);
        Assert.True(new FileInfo(entry.StdoutPath).Length + new FileInfo(entry.StderrPath).Length <= request.MaxOutputBytes);
    }

    [Fact]
    public async Task AppContainer_child_process_escape_fails_closed()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var executor = CreateExecutor();
        var startedFile = Path.Combine(directory, "child.started");
        var escapedFile = Path.Combine(directory, "child.escaped");
        var childScript = Path.Combine(directory, "child.cmd");
        await File.WriteAllTextAsync(
            childScript,
            "@echo started>%1\r\n" +
            "@ping 127.0.0.1 -n 8 >nul\r\n" +
            "@echo escaped>%2\r\n");
        var command =
            $"cmd.exe /d /c {childScript} {startedFile} {escapedFile}";
        var handle = await executor.StartAsync(Request(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            ["/d", "/c", command]), default);
        await WaitForExit(executor, handle);
        var standardError = await executor.ReadOutputAsync(
            handle,
            "stderr",
            0,
            4096,
            default);
        Assert.Contains(
            "Access is denied",
            System.Text.Encoding.UTF8.GetString(standardError.Data.Span),
            StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(startedFile));
        Assert.False(File.Exists(escapedFile));
    }

    [Fact]
    public async Task Cancellation_terminates_the_atomic_Job_root()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var executor = CreateExecutor();
        var handle = await executor.StartAsync(Request(
            Path.Combine(Environment.SystemDirectory, "ping.exe"),
            ["127.0.0.1", "-n", "120"]), default);

        await executor.CancelAsync(
            handle,
            TimeSpan.FromMilliseconds(100),
            default);

        Assert.True(SpinWait.SpinUntil(
            () => !IsRunning(handle.ProcessId),
            TimeSpan.FromSeconds(10)));
    }
    [Fact]
    public async Task Recovery_rejects_pid_creation_time_mismatch()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = new ExecutionJournal(Path.Combine(directory, "journal.db"));
        var id = TaskAttemptId.New();
        journal.InsertPlanned(new(id, 1, null, null, $@"Local\Steward.{id.Value:N}.1", "boot", LaunchPhase.Planned, "launching",
            Path.Combine(directory, "out"), Path.Combine(directory, "err"), 0, 0, false, 100));
        journal.SetProcess(id, 1, Environment.ProcessId, 1, Environment.CurrentManagedThreadId, LaunchPhase.AssignedToJob);
        journal.SetPhase(id, 1, LaunchPhase.Resumed, "running");
        using var executor = new WindowsProcessExecutor(journal, keeper, nodeIncarnationId, "boot");
        var error = await Assert.ThrowsAsync<ExecutionRecoveryException>(() => executor.RecoverAsync(id, 1, "boot", default).AsTask());
        Assert.True(error.IsAmbiguous);
    }

    [Fact]
    public async Task Planned_crash_boundary_is_ambiguous_not_relaunched()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = new ExecutionJournal(Path.Combine(directory, "journal.db"));
        var id = TaskAttemptId.New();
        journal.InsertPlanned(new(id, 1, null, null, $@"Local\Steward.{id.Value:N}.1", "boot", LaunchPhase.Planned, "launching",
            Path.Combine(directory, "out"), Path.Combine(directory, "err"), 0, 0, false, 100));
        using var executor = new WindowsProcessExecutor(journal, keeper, nodeIncarnationId, "boot");
        var error = await Assert.ThrowsAsync<ExecutionRecoveryException>(() => executor.RecoverAsync(id, 1, "boot", default).AsTask());
        Assert.False(error.IsAmbiguous);
    }

    [Fact]
    public async Task Unverified_boot_identity_mismatch_requires_ambiguous_reconciliation()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = new ExecutionJournal(
            Path.Combine(directory, "unverified-boot.db"));
        var id = TaskAttemptId.New();
        journal.InsertPlanned(new(
            id,
            1,
            null,
            null,
            $@"Local\Steward.{id.Value:N}.1",
            "prior-boot",
            LaunchPhase.Planned,
            "launching",
            Path.Combine(directory, "out"),
            Path.Combine(directory, "err"),
            0,
            0,
            false,
            100));
        using var executor = new WindowsProcessExecutor(
            journal,
            keeper,
            nodeIncarnationId,
            "current-boot",
            bootIdentityVerified: false);

        var error = await Assert.ThrowsAsync<ExecutionRecoveryException>(
            () => executor.RecoverAsync(
                id,
                1,
                "current-boot",
                default).AsTask());

        Assert.True(error.IsAmbiguous);
    }

    [Theory]
    [InlineData(LaunchBoundary.JobRetained, false)]
    [InlineData(LaunchBoundary.ProcessCreated, true)]
    [InlineData(LaunchBoundary.IdentityJournaled, true)]
    [InlineData(LaunchBoundary.ProcessResumed, true)]
    public async Task Injected_launch_boundaries_recover_without_duplicate(LaunchBoundary boundary, bool processExpected)
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = new ExecutionJournal(Path.Combine(directory, $"{boundary}.db"));
        var request = Request(
            Path.Combine(Environment.SystemDirectory, "ping.exe"),
            ["127.0.0.1", "-n", "120"]);
        using (var crashing = new WindowsProcessExecutor(journal, keeper, nodeIncarnationId, "boot", new CrashAt(boundary)))
            await Assert.ThrowsAsync<InjectedLaunchCrashException>(() => crashing.StartAsync(request, default).AsTask());

        using var recovery = new WindowsProcessExecutor(journal, keeper, nodeIncarnationId, "boot");
        if (!processExpected)
        {
            var absent = await Assert.ThrowsAsync<ExecutionRecoveryException>(
                () => recovery.RecoverAsync(request.AttemptId, request.Generation, "boot", default).AsTask());
            Assert.False(absent.IsAmbiguous);
            keeper.Release(new JobLeaseIdentity($@"Local\Steward.{request.AttemptId.Value:N}.{request.Generation}",
                request.AttemptId, request.Generation, nodeIncarnationId));
            return;
        }
        var recovered = await recovery.RecoverAsync(request.AttemptId, request.Generation, "boot", default);
        Assert.Equal(request.AttemptId, recovered.AttemptId);
        await recovery.CancelAsync(recovered, TimeSpan.Zero, default);
    }

    [Fact]
    public async Task Spool_monitor_failure_records_evidence_and_fails_closed()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = new ExecutionJournal(Path.Combine(directory, "monitor.db"));
        using var executor = new WindowsProcessExecutor(journal, keeper, nodeIncarnationId, "boot", spoolFiles: new FailingSpoolFiles());
        var handle = await executor.StartAsync(Request(
            Path.Combine(Environment.SystemDirectory, "ping.exe"),
            ["127.0.0.1", "-n", "120"]), default);
        Assert.True(SpinWait.SpinUntil(() => journal.Get(handle.AttemptId, 1)!.FailureDetail is not null, TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(() => !IsRunning(handle.ProcessId), TimeSpan.FromSeconds(5)));
        var entry = journal.Get(handle.AttemptId, 1)!;
        Assert.Equal("recovering", entry.State);
        Assert.Contains("IOException", entry.FailureDetail);
    }

    [Fact]
    public void Journal_rejects_unknown_schema_and_duplicate_launch()
    {
        var path = Path.Combine(directory, "version.db");
        using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version=999;";
            command.ExecuteNonQuery();
        }
        Assert.Throws<ExecutionJournalSchemaException>(() => new ExecutionJournal(path));

        var journal = new ExecutionJournal(Path.Combine(directory, "duplicate.db"));
        var id = TaskAttemptId.New();
        var entry = new ExecutionJournalEntry(id, 1, null, null, $@"Local\Steward.{id.Value:N}.1", "boot",
            LaunchPhase.Planned, "launching", Path.Combine(directory, "out"), Path.Combine(directory, "err"), 0, 0, false, 100);
        journal.InsertPlanned(entry);
        Assert.Throws<ExecutionRecoveryException>(() => journal.InsertPlanned(entry));
        journal.SetProcess(id, 1, Environment.ProcessId, DateTime.UtcNow.Ticks, Environment.CurrentManagedThreadId,
            LaunchPhase.AssignedToJob);
        Assert.Throws<ExecutionIdentityConflictException>(() =>
            journal.SetProcess(id, 1, Environment.ProcessId, DateTime.UtcNow.Ticks, Environment.CurrentManagedThreadId,
                LaunchPhase.AssignedToJob));
    }

    [Fact]
    public async Task Retained_keeper_allows_reopen_after_executor_restart()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = new ExecutionJournal(Path.Combine(directory, "journal.db"));
        IExecutionHandle handle;
        using (var first = new WindowsProcessExecutor(journal, keeper, nodeIncarnationId, "boot"))
            handle = await first.StartAsync(Request(
            Path.Combine(Environment.SystemDirectory, "ping.exe"),
            ["127.0.0.1", "-n", "120"]), default);
        Assert.False(keeper.SurvivesClientRestart);
        using var replacement = new WindowsProcessExecutor(journal, keeper, nodeIncarnationId, "boot");
        var recovered = await replacement.RecoverAsync(handle.AttemptId, handle.Generation, "boot", default);
        Assert.Equal(handle.ProcessCreationTimeUtcTicks, recovered.ProcessCreationTimeUtcTicks);
        await replacement.CancelAsync(recovered, TimeSpan.Zero, default);
    }

    private WindowsProcessExecutor CreateExecutor() =>
        new(new ExecutionJournal(Path.Combine(directory, "journal.db")), keeper, nodeIncarnationId, "boot");

    private ProcessLaunchRequest Request(
        string executable,
        IReadOnlyList<string>? arguments = null)
    {
        var attemptId = TaskAttemptId.New();
        return new ProcessLaunchRequest(
            attemptId,
            1,
            executable,
            arguments ?? [],
            directory,
            Path.Combine(directory, "spool"),
            1024 * 1024,
            0,
            Isolation: new ProcessIsolationProfile(
                1,
                ProcessIsolationCapability.Process,
                Path.GetDirectoryName(directory)!,
                directory,
                attemptId,
                1));
    }

    private static async Task WaitForExit(IProcessExecutor executor, IExecutionHandle handle)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while ((await executor.ObserveAsync(handle, timeout.Token)).State != ExecutionState.Exited)
            await Task.Delay(25, timeout.Token);
    }

    private static bool IsRunning(int pid)
    {
        try { using var process = Process.GetProcessById(pid); return !process.HasExited; }
        catch (ArgumentException) { return false; }
    }

    public void Dispose()
    {
        keeper.Dispose();
        try { Directory.Delete(directory, true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private sealed class CrashAt(LaunchBoundary boundary) : ILaunchBoundaryObserver
    {
        public void Reached(LaunchBoundary reached)
        {
            if (reached == boundary) throw new InjectedLaunchCrashException(boundary);
        }
    }

    private sealed class FailingSpoolFiles : ISpoolFileOperations
    {
        public long GetLength(string path) => throw new IOException("injected spool failure");
        public void Trim(string path, long length) => throw new IOException("injected spool failure");
    }

#pragma warning disable SYSLIB1054
    [DllImport("shell32.dll", SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string commandLine, out int argumentCount);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(Microsoft.Win32.SafeHandles.SafeFileHandle handle, uint mask, uint flags);
#pragma warning restore SYSLIB1054
}
