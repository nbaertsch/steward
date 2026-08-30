using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Steward.Domain;
using Steward.Tasks.Abstractions;

namespace Steward.Runtime.Windows;

public sealed record WindowsExecutionHandle(
    TaskAttemptId AttemptId,
    int Generation,
    int ProcessId,
    long ProcessCreationTimeUtcTicks,
    string JobName,
    string StdoutPath,
    string StderrPath) : IExecutionHandle;

public enum LaunchBoundary { Planned, JobRetained, ProcessCreated, IdentityJournaled, ProcessResumed }

public interface ILaunchBoundaryObserver
{
    void Reached(LaunchBoundary boundary);
}

public sealed class InjectedLaunchCrashException(LaunchBoundary boundary)
    : Exception($"Injected process crash at {boundary}.")
{
    public LaunchBoundary Boundary { get; } = boundary;
}

public interface ISpoolFileOperations
{
    long GetLength(string path);
    void Trim(string path, long length);
}

public sealed class WindowsProcessExecutor : IProcessExecutor, IDisposable
{
    private sealed class SystemSpoolFileOperations : ISpoolFileOperations
    {
        public long GetLength(string path) => new FileInfo(path).Length;
        public void Trim(string path, long length)
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length > length) file.SetLength(length);
        }
    }

    private sealed class ProcessAttributeList : IDisposable
    {
        private IntPtr attributeList;
        private IntPtr handles;
        private IntPtr jobs;
        private bool initialized;

        public IntPtr Pointer => attributeList;

        public ProcessAttributeList(SafeFileHandle stdout, SafeFileHandle stderr, SafeFileHandle stdin, SafeFileHandle job)
        {
            nuint size = 0;
            _ = NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            if (Marshal.GetLastWin32Error() != NativeMethods.ErrorInsufficientBuffer || size == 0)
                throw new PlatformNotSupportedException("Extended process attribute lists are unavailable.");
            try
            {
                attributeList = Marshal.AllocHGlobal(checked((int)size));
                if (!NativeMethods.InitializeProcThreadAttributeList(attributeList, 2, 0, ref size))
                    NativeMethods.ThrowLastError(nameof(NativeMethods.InitializeProcThreadAttributeList));
                initialized = true;

                handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handles, 0, stdout.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size, stderr.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size * 2, stdin.DangerousGetHandle());
                if (!NativeMethods.UpdateProcThreadAttribute(attributeList, 0, NativeMethods.ProcThreadAttributeHandleList,
                        handles, checked((nuint)(IntPtr.Size * 3)), IntPtr.Zero, IntPtr.Zero))
                    NativeMethods.ThrowLastError("PROC_THREAD_ATTRIBUTE_HANDLE_LIST");

                jobs = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
                if (!NativeMethods.UpdateProcThreadAttribute(attributeList, 0, NativeMethods.ProcThreadAttributeJobList,
                        jobs, checked((nuint)IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                    throw new PlatformNotSupportedException(
                        $"PROC_THREAD_ATTRIBUTE_JOB_LIST is unavailable (Win32 {Marshal.GetLastWin32Error()}).");
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            if (initialized) NativeMethods.DeleteProcThreadAttributeList(attributeList);
            if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
            if (jobs != IntPtr.Zero) Marshal.FreeHGlobal(jobs);
            attributeList = IntPtr.Zero;
            handles = IntPtr.Zero;
            jobs = IntPtr.Zero;
            initialized = false;
        }
    }

    private sealed record ActiveExecution(SafeFileHandle Process, SafeFileHandle Job, CancellationTokenSource Monitor, GracefulSignal? GracefulSignal);
    private readonly ExecutionJournal journal;
    private readonly IJobHandleKeeper keeper;
    private readonly string bootId;
    private readonly NodeIncarnationId nodeIncarnationId;
    private readonly ILaunchBoundaryObserver? launchObserver;
    private readonly ISpoolFileOperations spoolFiles;
    private readonly ConcurrentDictionary<(TaskAttemptId, int), ActiveExecution> active = new();
    private bool disposed;

    public WindowsProcessExecutor(
        ExecutionJournal journal,
        IJobHandleKeeper keeper,
        NodeIncarnationId nodeIncarnationId,
        string? bootId = null,
        ILaunchBoundaryObserver? launchObserver = null,
        ISpoolFileOperations? spoolFiles = null)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows process execution requires Windows.");
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
            throw new PlatformNotSupportedException("Atomic Job-list process creation requires Windows 10 or later.");
        this.journal = journal;
        this.keeper = keeper;
        this.bootId = bootId ?? CurrentBootId();
        if (nodeIncarnationId.Value == Guid.Empty) throw new ArgumentException("Node incarnation is required.", nameof(nodeIncarnationId));
        this.nodeIncarnationId = nodeIncarnationId;
        this.launchObserver = launchObserver;
        this.spoolFiles = spoolFiles ?? new SystemSpoolFileOperations();
    }

    public async ValueTask<IExecutionHandle> StartAsync(ProcessLaunchRequest request, CancellationToken cancellationToken)
    {
        Validate(request);
        cancellationToken.ThrowIfCancellationRequested();
        Directory.CreateDirectory(request.SpoolDirectory);
        EnsureDiskReserve(request.SpoolDirectory, checked(request.RequiredDiskReserveBytes + request.MaxOutputBytes));
        var stdout = Path.Combine(request.SpoolDirectory, $"{request.AttemptId}.{request.Generation}.stdout");
        var stderr = Path.Combine(request.SpoolDirectory, $"{request.AttemptId}.{request.Generation}.stderr");
        var jobName = $@"Local\Steward.{request.AttemptId.Value:N}.{request.Generation}";
        var lease = new JobLeaseIdentity(jobName, request.AttemptId, request.Generation, nodeIncarnationId);
        journal.InsertPlanned(new(request.AttemptId, request.Generation, null, null, jobName, bootId,
            LaunchPhase.Planned, "launching", stdout, stderr, 0, 0, false, request.MaxOutputBytes));
        launchObserver?.Reached(LaunchBoundary.Planned);

        using var stdoutFile = OpenInheritableSpool(stdout);
        using var stderrFile = OpenInheritableSpool(stderr);
        using var stdinFile = OpenInheritableInput(request.StandardInputPath);
        var job = NativeMethods.CreateJobObject(IntPtr.Zero, jobName);
        if (job.IsInvalid) NativeMethods.ThrowLastError(nameof(NativeMethods.CreateJobObject));
        var alreadyExists = Marshal.GetLastWin32Error() == 183;
        if (alreadyExists)
        {
            job.Dispose();
            throw new ExecutionRecoveryException($"Job '{jobName}' already exists; reconcile instead of relaunching.", true);
        }
        NativeMethods.ProcessInformation pi = default;
        SafeFileHandle? processHandle = null;
        SafeFileHandle? launchJob = null;
        var retained = false;
        try
        {
            ApplyResourceLimits(job, request.ResourceLimits);
            keeper.Retain(lease, job);
            retained = true;
            launchObserver?.Reached(LaunchBoundary.JobRetained);
            launchJob = keeper.Open(lease);
            using var attributes = new ProcessAttributeList(stdoutFile, stderrFile, stdinFile, launchJob);
            var startup = new NativeMethods.StartupInfoEx
            {
                StartupInfo = new NativeMethods.StartupInfo
                {
                    cb = (uint)Marshal.SizeOf<NativeMethods.StartupInfoEx>(),
                    dwFlags = 0x00000100,
                    hStdInput = stdinFile.DangerousGetHandle(),
                    hStdOutput = stdoutFile.DangerousGetHandle(),
                    hStdError = stderrFile.DangerousGetHandle()
                },
                AttributeList = attributes.Pointer
            };
            var commandLine = (QuoteWindowsArgument(request.ApplicationPath) + " " +
                               string.Join(" ", request.Arguments.Select(QuoteWindowsArgument)) + "\0").ToCharArray();
            if (!NativeMethods.CreateProcess(request.ApplicationPath, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    NativeMethods.CreateSuspended | NativeMethods.CreateNoWindow | NativeMethods.CreateNewProcessGroup |
                    NativeMethods.ExtendedStartupInfoPresent,
                    IntPtr.Zero, request.WorkingDirectory, ref startup, out pi))
                NativeMethods.ThrowLastError(nameof(NativeMethods.CreateProcess));

            using var thread = new SafeFileHandle(pi.hThread, true);
            processHandle = new SafeFileHandle(pi.hProcess, true);
            pi.hProcess = IntPtr.Zero;
            launchObserver?.Reached(LaunchBoundary.ProcessCreated);
            var creationTicks = GetCreationTime(processHandle);
            journal.SetProcess(request.AttemptId, request.Generation, checked((int)pi.dwProcessId), creationTicks,
                checked((int)pi.dwThreadId), LaunchPhase.AssignedToJob);
            launchObserver?.Reached(LaunchBoundary.IdentityJournaled);
            if (NativeMethods.ResumeThread(thread) == uint.MaxValue)
                NativeMethods.ThrowLastError(nameof(NativeMethods.ResumeThread));
            launchObserver?.Reached(LaunchBoundary.ProcessResumed);
            journal.SetPhase(request.AttemptId, request.Generation, LaunchPhase.Resumed, "running");

            var monitor = new CancellationTokenSource();
            var handle = new WindowsExecutionHandle(request.AttemptId, request.Generation, checked((int)pi.dwProcessId),
                creationTicks, jobName, stdout, stderr);
            active[(request.AttemptId, request.Generation)] = new(processHandle, launchJob, monitor, request.GracefulSignal);
            processHandle = null;
            launchJob = null;
            _ = MonitorOutputAsync(handle, request.MaxOutputBytes, monitor.Token);
            await Task.Yield();
            return handle;
        }
        catch (InjectedLaunchCrashException)
        {
            processHandle?.Dispose();
            launchJob?.Dispose();
            if (pi.hProcess != IntPtr.Zero) new SafeFileHandle(pi.hProcess, true).Dispose();
            if (!retained) job.Dispose();
            throw;
        }
        catch
        {
            if (launchJob is not null && !launchJob.IsInvalid)
                NativeMethods.TerminateJobObject(launchJob, 0xE0000001);
            processHandle?.Dispose();
            if (pi.hProcess != IntPtr.Zero) new SafeFileHandle(pi.hProcess, true).Dispose();
            launchJob?.Dispose();
            if (retained) keeper.Release(lease);
            throw;
        }
    }

    public ValueTask<ExecutionObservation> ObserveAsync(IExecutionHandle execution, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var current = RequireActive(execution);
        if (!NativeMethods.GetExitCodeProcess(current.Process, out var exitCode))
            NativeMethods.ThrowLastError(nameof(NativeMethods.GetExitCodeProcess));
        if (exitCode == NativeMethods.StillActive)
            return ValueTask.FromResult(new ExecutionObservation(ExecutionState.Running));
        journal.SetPhase(execution.AttemptId, execution.Generation, LaunchPhase.Exited, exitCode == 0 ? "succeeded" : "failed");
        CompleteActive(execution);
        return ValueTask.FromResult(new ExecutionObservation(ExecutionState.Exited, unchecked((int)exitCode)));
    }

    public async ValueTask<SpoolRead> ReadOutputAsync(IExecutionHandle execution, string stream, long offset, int maximumBytes, CancellationToken cancellationToken)
    {
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        var entry = journal.Get(execution.AttemptId, execution.Generation) ?? throw new KeyNotFoundException("Execution not journaled.");
        var path = stream switch { "stdout" => entry.StdoutPath, "stderr" => entry.StderrPath, _ => throw new ArgumentOutOfRangeException(nameof(stream)) };
        await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, true);
        var length = file.Length;
        if (offset > length) throw new ArgumentOutOfRangeException(nameof(offset));
        file.Position = offset;
        var buffer = new byte[Math.Min(maximumBytes, checked((int)Math.Min(int.MaxValue, length - offset)))];
        var count = await file.ReadAsync(buffer, cancellationToken);
        var next = offset + count;
        journal.SetCursor(execution.AttemptId, execution.Generation, stream, next);
        return new(new(stream, path, next, length, entry.OutputTruncated), buffer.AsMemory(0, count));
    }

    public async ValueTask CancelAsync(IExecutionHandle execution, TimeSpan gracePeriod, CancellationToken cancellationToken)
    {
        var current = RequireActive(execution);
        var entry = journal.Get(execution.AttemptId, execution.Generation);
        if (entry?.State == "running" && gracePeriod > TimeSpan.Zero && current.GracefulSignal == GracefulSignal.CloseMainWindow)
        {
            try
            {
                using var process = Process.GetProcessById(execution.ProcessId);
                if (process.CloseMainWindow())
                    await process.WaitForExitAsync(cancellationToken).WaitAsync(gracePeriod, cancellationToken);
            }
            catch (TimeoutException) { }
            catch (InvalidOperationException) { }
        }
        if (NativeMethods.GetExitCodeProcess(current.Process, out var code) && code == NativeMethods.StillActive &&
            !NativeMethods.TerminateJobObject(current.Job, 0xC000013A))
            NativeMethods.ThrowLastError(nameof(NativeMethods.TerminateJobObject));
        NativeMethods.WaitForSingleObject(current.Process, 5000);
        journal.SetPhase(execution.AttemptId, execution.Generation, LaunchPhase.Exited, "cancelled");
        CompleteActive(execution);
    }

    public ValueTask<IExecutionHandle> RecoverAsync(TaskAttemptId attemptId, int generation, string currentBootId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var entry = journal.Get(attemptId, generation) ?? throw new KeyNotFoundException("Execution not journaled.");
        var lease = new JobLeaseIdentity(entry.JobName, attemptId, generation, nodeIncarnationId);
        if (!StringComparer.Ordinal.Equals(entry.BootId, currentBootId))
            throw new ExecutionRecoveryException("Boot identity changed; apply the TaskType interruption class.", false);
        if (entry.Phase != LaunchPhase.Planned)
        {
            if (entry.ProcessId is null || entry.ProcessCreationTimeUtcTicks is null)
                throw new ExecutionRecoveryException("Incomplete process identity is ambiguous.", true);
            using var identityProcess = NativeMethods.OpenProcess(
                NativeMethods.ProcessQueryLimitedInformation | NativeMethods.Synchronize, false, checked((uint)entry.ProcessId.Value));
            if (identityProcess.IsInvalid)
                throw new ExecutionRecoveryException("The journaled process no longer exists.", false);
            if (GetCreationTime(identityProcess) != entry.ProcessCreationTimeUtcTicks.Value)
                throw new ExecutionRecoveryException("PID creation time does not match the immutable execution identity.", true);
        }
        SafeFileHandle job;
        try { job = keeper.Open(lease); }
        catch (Exception exception) when (exception is KeyNotFoundException or IOException)
        {
            job = NativeMethods.OpenJobObject(NativeMethods.JobObjectAllAccess, false, entry.JobName);
            if (job.IsInvalid)
                throw new ExecutionRecoveryException(
                    entry.Phase == LaunchPhase.Planned
                        ? "No retained Job exists; execution is absent."
                        : "The process exists but its retained Job cannot be verified.",
                    entry.Phase != LaunchPhase.Planned);
        }

        if (entry.Phase == LaunchPhase.Planned)
        {
            var processIds = GetJobProcessIds(job);
            if (processIds.Count == 0)
            {
                job.Dispose();
                keeper.Release(lease);
                throw new ExecutionRecoveryException("The retained Job contains no process; execution is absent.", false);
            }
            if (processIds.Count != 1)
            {
                job.Dispose();
                throw new ExecutionRecoveryException("The retained Job contains multiple processes and cannot identify the launch root.", true);
            }

            var discoveredPid = checked((int)processIds[0]);
            var discoveredProcess = NativeMethods.OpenProcess(
                NativeMethods.ProcessQueryLimitedInformation | NativeMethods.ProcessTerminate | NativeMethods.Synchronize,
                false, processIds[0]);
            if (discoveredProcess.IsInvalid)
            {
                job.Dispose();
                throw new ExecutionRecoveryException("The retained Job process cannot be verified.", true);
            }
            var discoveredCreation = GetCreationTime(discoveredProcess);
            var discoveredThread = FindProcessThread(processIds[0]);
            try
            {
                journal.SetProcess(attemptId, generation, discoveredPid, discoveredCreation, checked((int)discoveredThread),
                    LaunchPhase.AssignedToJob);
            }
            catch
            {
                discoveredProcess.Dispose();
                job.Dispose();
                throw;
            }
            entry = journal.Get(attemptId, generation)!;
            discoveredProcess.Dispose();
        }
        if (entry.ProcessId is null || entry.ProcessCreationTimeUtcTicks is null)
        {
            job.Dispose();
            throw new ExecutionRecoveryException("Incomplete process identity is ambiguous.", true);
        }

        var process = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation | NativeMethods.ProcessTerminate | NativeMethods.Synchronize,
            false, checked((uint)entry.ProcessId.Value));
        if (process.IsInvalid)
        {
            job.Dispose();
            throw new ExecutionRecoveryException("The journaled process no longer exists.", false);
        }
        var actualCreation = GetCreationTime(process);
        if (actualCreation != entry.ProcessCreationTimeUtcTicks.Value)
        {
            process.Dispose();
            throw new ExecutionRecoveryException("PID creation time does not match the immutable execution identity.", true);
        }

        if (!NativeMethods.IsProcessInJob(process, job, out var isMember) || !isMember)
        {
            process.Dispose();
            job.Dispose();
            throw new ExecutionRecoveryException("Process is not a member of the expected Job Object.", true);
        }
        if (entry.Phase < LaunchPhase.Resumed)
        {
            var threadId = entry.ThreadId is > 0 ? checked((uint)entry.ThreadId.Value) : FindProcessThread(checked((uint)entry.ProcessId.Value));
            using var thread = NativeMethods.OpenThread(
                NativeMethods.ThreadSuspendResume | NativeMethods.ThreadQueryLimitedInformation, false, threadId);
            if (thread.IsInvalid || NativeMethods.ResumeThread(thread) == uint.MaxValue)
            {
                process.Dispose();
                job.Dispose();
                throw new ExecutionRecoveryException("The suspended root thread cannot be resumed safely.", true);
            }
            journal.SetPhase(attemptId, generation, LaunchPhase.Resumed, "running");
        }
        var monitor = new CancellationTokenSource();
        active[(attemptId, generation)] = new(process, job, monitor, null);
        var handle = new WindowsExecutionHandle(attemptId, generation, entry.ProcessId.Value,
            entry.ProcessCreationTimeUtcTicks.Value, entry.JobName, entry.StdoutPath, entry.StderrPath);
        _ = MonitorOutputAsync(handle, entry.OutputLimit, monitor.Token);
        return ValueTask.FromResult<IExecutionHandle>(handle);
    }

    public static string QuoteWindowsArgument(string argument)
    {
        ArgumentNullException.ThrowIfNull(argument);
        if (argument.Length > 0 && !argument.Any(c => char.IsWhiteSpace(c) || c == '"')) return argument;
        var result = new StringBuilder("\"");
        var slashes = 0;
        foreach (var c in argument)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') result.Append('\\', slashes * 2 + 1).Append(c);
            else result.Append('\\', slashes).Append(c);
            slashes = 0;
        }
        result.Append('\\', slashes * 2).Append('"');
        return result.ToString();
    }

    public static string CurrentBootId()
    {
        var boot = DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
        return new DateTimeOffset(boot.Year, boot.Month, boot.Day, boot.Hour, boot.Minute, 0, TimeSpan.Zero).ToString("O");
    }

    private async Task MonitorOutputAsync(WindowsExecutionHandle handle, long maximum, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var stdout = spoolFiles.GetLength(handle.StdoutPath);
                var stderr = spoolFiles.GetLength(handle.StderrPath);
                if (stdout + stderr > maximum)
                {
                    var current = RequireActive(handle);
                    NativeMethods.TerminateJobObject(current.Job, 0xE0000002);
                    NativeMethods.WaitForSingleObject(current.Process, 5000);
                    spoolFiles.Trim(handle.StdoutPath, Math.Min(stdout, maximum));
                    spoolFiles.Trim(handle.StderrPath, Math.Max(0, maximum - Math.Min(stdout, maximum)));
                    journal.MarkTruncated(handle.AttemptId, handle.Generation);
                    return;
                }
                if (!NativeMethods.GetExitCodeProcess(RequireActive(handle).Process, out var exit) || exit != NativeMethods.StillActive) return;
                await Task.Delay(25, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            if (active.TryGetValue((handle.AttemptId, handle.Generation), out var current))
                NativeMethods.TerminateJobObject(current.Job, 0xE0000003);
            journal.MarkMonitorFailure(handle.AttemptId, handle.Generation, $"{exception.GetType().Name}: {exception.Message}");
        }
    }

    private static SafeFileHandle OpenInheritableSpool(string path)
    {
        var handle = File.OpenHandle(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        if (!NativeMethods.SetHandleInformation(handle, NativeMethods.HandleFlagInherit, NativeMethods.HandleFlagInherit))
        {
            handle.Dispose();
            NativeMethods.ThrowLastError(nameof(NativeMethods.SetHandleInformation));
        }
        return handle;
    }

    private static SafeFileHandle OpenInheritableInput(string? path)
    {
        var handle = File.OpenHandle(path ?? "NUL", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (!NativeMethods.SetHandleInformation(handle, NativeMethods.HandleFlagInherit, NativeMethods.HandleFlagInherit))
        {
            handle.Dispose();
            NativeMethods.ThrowLastError(nameof(NativeMethods.SetHandleInformation));
        }
        return handle;
    }

    private static IReadOnlyList<uint> GetJobProcessIds(SafeFileHandle job)
    {
        var capacity = 16;
        while (capacity <= 65536)
        {
            var bytes = checked((uint)(8 + IntPtr.Size * capacity));
            var buffer = Marshal.AllocHGlobal(checked((int)bytes));
            try
            {
                if (NativeMethods.QueryInformationJobObject(job, 3, buffer, bytes, out _))
                {
                    var count = Marshal.ReadInt32(buffer, 4);
                    var result = new uint[count];
                    for (var index = 0; index < count; index++)
                        result[index] = checked((uint)(nuint)Marshal.ReadIntPtr(buffer, 8 + IntPtr.Size * index));
                    return result;
                }
                if (Marshal.GetLastWin32Error() != NativeMethods.ErrorMoreData)
                    NativeMethods.ThrowLastError(nameof(NativeMethods.QueryInformationJobObject));
            }
            finally { Marshal.FreeHGlobal(buffer); }
            capacity *= 2;
        }
        throw new ExecutionRecoveryException("Job process membership exceeds the recovery inspection limit.", true);
    }

    private static uint FindProcessThread(uint processId)
    {
        using var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.Th32csSnapThread, 0);
        if (snapshot.IsInvalid) NativeMethods.ThrowLastError(nameof(NativeMethods.CreateToolhelp32Snapshot));
        var entry = new NativeMethods.ThreadEntry32 { Size = checked((uint)Marshal.SizeOf<NativeMethods.ThreadEntry32>()) };
        if (NativeMethods.Thread32First(snapshot, ref entry))
        {
            do
            {
                if (entry.OwnerProcessId == processId) return entry.ThreadId;
                entry.Size = checked((uint)Marshal.SizeOf<NativeMethods.ThreadEntry32>());
            } while (NativeMethods.Thread32Next(snapshot, ref entry));
        }
        throw new ExecutionRecoveryException("No thread could be verified for the retained Job process.", true);
    }

    private static long GetCreationTime(SafeFileHandle process)
    {
        if (!NativeMethods.GetProcessTimes(process, out var creation, out _, out _, out _))
            NativeMethods.ThrowLastError(nameof(NativeMethods.GetProcessTimes));
        return DateTime.FromFileTimeUtc(creation.ToLong()).Ticks;
    }

    private static void Validate(ProcessLaunchRequest request)
    {
        if (!Path.IsPathFullyQualified(request.ApplicationPath)) throw new ArgumentException("ApplicationPath must be absolute.");
        if (!File.Exists(request.ApplicationPath)) throw new FileNotFoundException("Application does not exist.", request.ApplicationPath);
        if (Path.GetExtension(request.ApplicationPath) is ".bat" or ".cmd") throw new NotSupportedException("Batch and command scripts require a shell and are not supported.");
        if (request.RequiresInteractiveSession) throw new NotSupportedException("Interactive process execution is not supported.");
        if (request.GracefulSignal == GracefulSignal.CtrlBreak)
            throw new NotSupportedException("CTRL_BREAK delivery is not supported by this non-interactive executor.");
        if (!Path.IsPathFullyQualified(request.WorkingDirectory) || !Directory.Exists(request.WorkingDirectory)) throw new DirectoryNotFoundException(request.WorkingDirectory);
        if (request.MaxOutputBytes <= 0) throw new ArgumentOutOfRangeException(nameof(request.MaxOutputBytes));
        if (request.RequiredDiskReserveBytes < 0) throw new ArgumentOutOfRangeException(nameof(request.RequiredDiskReserveBytes));
        if (request.StandardInputPath is not null &&
            (!Path.IsPathFullyQualified(request.StandardInputPath) ||
             !File.Exists(request.StandardInputPath)))
            throw new ArgumentException("Standard input path must be an existing absolute file.");
        if (request.ResourceLimits is { } limits &&
            (limits.ProcessMemoryBytes <= 0 || limits.JobMemoryBytes <= 0 || limits.ActiveProcessLimit == 0))
            throw new ArgumentOutOfRangeException(nameof(request.ResourceLimits), "Configured resource limits must be positive.");
    }

    private static void EnsureDiskReserve(string path, long reserve)
    {
        var root = Path.GetPathRoot(Path.GetFullPath(path))!;
        if (new DriveInfo(root).AvailableFreeSpace - reserve <= 0)
            throw new IOException("Execution rejected because the configured disk reserve cannot be maintained.");
    }

    private static void ApplyResourceLimits(SafeFileHandle job, ProcessResourceLimits? limits)
    {
        if (limits is null) return;
        if (limits.ProcessMemoryBytes <= 0 || limits.JobMemoryBytes <= 0 || limits.ActiveProcessLimit == 0)
            throw new ArgumentOutOfRangeException(nameof(limits), "Configured resource limits must be positive.");
        var information = new NativeMethods.JobObjectExtendedLimitInformation();
        if (limits.ProcessMemoryBytes is long processMemory)
        {
            information.BasicLimitInformation.LimitFlags |= NativeMethods.JobObjectLimitProcessMemory;
            information.ProcessMemoryLimit = checked((UIntPtr)(ulong)processMemory);
        }
        if (limits.JobMemoryBytes is long jobMemory)
        {
            information.BasicLimitInformation.LimitFlags |= NativeMethods.JobObjectLimitJobMemory;
            information.JobMemoryLimit = checked((UIntPtr)(ulong)jobMemory);
        }
        if (limits.ActiveProcessLimit is uint processCount)
        {
            information.BasicLimitInformation.LimitFlags |= NativeMethods.JobObjectLimitActiveProcess;
            information.BasicLimitInformation.ActiveProcessLimit = processCount;
        }
        if (!NativeMethods.SetInformationJobObject(job, 9, ref information,
                checked((uint)Marshal.SizeOf<NativeMethods.JobObjectExtendedLimitInformation>())))
            NativeMethods.ThrowLastError(nameof(NativeMethods.SetInformationJobObject));
    }

    private ActiveExecution RequireActive(IExecutionHandle execution) =>
        active.TryGetValue((execution.AttemptId, execution.Generation), out var value)
            ? value
            : throw new InvalidOperationException("Execution is not active in this executor.");

    private void CompleteActive(IExecutionHandle execution)
    {
        if (!active.TryRemove((execution.AttemptId, execution.Generation), out var item)) return;
        item.Monitor.Cancel();
        item.Monitor.Dispose();
        item.Process.Dispose();
        item.Job.Dispose();
        if (execution is WindowsExecutionHandle windows)
            keeper.Release(new JobLeaseIdentity(windows.JobName, execution.AttemptId, execution.Generation, nodeIncarnationId));
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        foreach (var item in active.Values)
        {
            item.Monitor.Cancel();
            item.Monitor.Dispose();
            item.Process.Dispose();
            item.Job.Dispose();
        }
        active.Clear();
    }
}
