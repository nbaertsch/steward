using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Steward.Runtime.Windows;
using Steward.Tasks.Abstractions;
using Steward.Terminal.Abstractions;

namespace Steward.Terminal.Windows;

public sealed record ConPtyTerminalRuntimeOptions(
    IReadOnlySet<string> AllowedShellExecutables,
    int OutputChunkBytes = 16 * 1024,
    int MaximumInputChunkBytes = 64 * 1024,
    bool AllowElevatedServiceIdentity = false)
{
    public static ConPtyTerminalRuntimeOptions CreateDefault()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (!string.IsNullOrWhiteSpace(system))
        {
            paths.Add(Path.Combine(system, "cmd.exe"));
            paths.Add(Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe"));
        }
        var pwsh = Environment.GetEnvironmentVariable("ProgramFiles");
        if (!string.IsNullOrWhiteSpace(pwsh))
            paths.Add(Path.Combine(pwsh, "PowerShell", "7", "pwsh.exe"));
        return new(paths);
    }
}

internal sealed record ConPtyStartRequest(
    TerminalSessionId SessionId,
    TerminalShellKind ShellKind,
    string Executable,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    ProcessIsolationProfile Isolation,
    int Columns,
    int Rows,
    long MaximumOutputBytes,
    bool ElevationGranted);

internal sealed record ConPtyProcessIdentity(
    int ProcessId,
    long CreationTimeUtcTicks,
    string ExecutionIdentity,
    bool IsElevated);

internal sealed class ConPtyTerminalRuntime : IAsyncDisposable
{
    private sealed class PseudoConsoleHandle : SafeHandle
    {
        internal PseudoConsoleHandle(IntPtr handle) : base(IntPtr.Zero, true) => SetHandle(handle);
        public override bool IsInvalid => handle == IntPtr.Zero || handle == new IntPtr(-1);
        protected override bool ReleaseHandle()
        {
            ConPtyNativeMethods.ClosePseudoConsole(handle);
            return true;
        }
    }

    private sealed class AttributeList : IDisposable
    {
        private IntPtr list;
        private IntPtr jobs;
        private IntPtr handles;
        private bool initialized;

        internal IntPtr Pointer => list;

        internal AttributeList(
            PseudoConsoleHandle pseudoConsole,
            SafeFileHandle job,
            SafeFileHandle consoleInput,
            SafeFileHandle consoleOutput,
            WindowsWorkloadIsolation.SecurityCapabilitiesLease securityCapabilities)
        {
            const int attributeCount = 4;
            nuint size = 0;
            _ = ConPtyNativeMethods.InitializeProcThreadAttributeList(
                IntPtr.Zero,
                attributeCount,
                0,
                ref size);
            if (Marshal.GetLastWin32Error() != ConPtyNativeMethods.ErrorInsufficientBuffer || size == 0)
                throw new PlatformNotSupportedException("ConPTY process attributes are unavailable.");
            try
            {
                list = Marshal.AllocHGlobal(checked((int)size));
                if (!ConPtyNativeMethods.InitializeProcThreadAttributeList(
                        list,
                        attributeCount,
                        0,
                        ref size))
                    ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.InitializeProcThreadAttributeList));
                initialized = true;
                handles = Marshal.AllocHGlobal(checked(IntPtr.Size * 2));
                Marshal.WriteIntPtr(handles, 0, consoleInput.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size, consoleOutput.DangerousGetHandle());
                if (!ConPtyNativeMethods.UpdateProcThreadAttribute(
                        list, 0, ConPtyNativeMethods.ProcThreadAttributeHandleList,
                        handles, checked((nuint)(IntPtr.Size * 2)), IntPtr.Zero, IntPtr.Zero))
                    ConPtyNativeMethods.ThrowLastError(
                        "PROC_THREAD_ATTRIBUTE_HANDLE_LIST");

                if (!ConPtyNativeMethods.UpdateProcThreadAttribute(
                        list, 0, ConPtyNativeMethods.ProcThreadAttributePseudoConsole,
                        pseudoConsole.DangerousGetHandle(), checked((nuint)IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                    ConPtyNativeMethods.ThrowLastError("PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE");

                jobs = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
                if (!ConPtyNativeMethods.UpdateProcThreadAttribute(
                        list, 0, ConPtyNativeMethods.ProcThreadAttributeJobList,
                        jobs, checked((nuint)IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                    ConPtyNativeMethods.ThrowLastError("PROC_THREAD_ATTRIBUTE_JOB_LIST");

                if (!ConPtyNativeMethods.UpdateProcThreadAttribute(
                        list,
                        0,
                        ConPtyNativeMethods.ProcThreadAttributeSecurityCapabilities,
                        securityCapabilities.Pointer,
                        securityCapabilities.Size,
                        IntPtr.Zero,
                        IntPtr.Zero))
                    ConPtyNativeMethods.ThrowLastError(
                        "PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES");
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            if (initialized)
                ConPtyNativeMethods.DeleteProcThreadAttributeList(list);
            if (list != IntPtr.Zero)
                Marshal.FreeHGlobal(list);
            if (jobs != IntPtr.Zero)
                Marshal.FreeHGlobal(jobs);
            if (handles != IntPtr.Zero)
                Marshal.FreeHGlobal(handles);
            list = IntPtr.Zero;
            jobs = IntPtr.Zero;
            handles = IntPtr.Zero;
            initialized = false;
        }
    }

    private sealed class ActiveSession : IAsyncDisposable
    {
        internal required PseudoConsoleHandle PseudoConsole { get; init; }
        internal required SafeFileHandle ConsoleInput { get; init; }
        internal required SafeFileHandle ConsoleOutput { get; init; }
        internal required SafeFileHandle Input { get; init; }
        internal required FileStream Output { get; init; }
        internal required SafeFileHandle Process { get; init; }
        internal required SafeFileHandle Job { get; init; }
        internal required ConPtyProcessIdentity Identity { get; init; }
        internal required ProcessIsolationProfile Isolation { get; init; }
        internal required CancellationTokenSource Lifetime { get; init; }
        internal required SemaphoreSlim InputLock { get; init; }
        internal required long MaximumOutputBytes { get; init; }
        internal Task? Pump { get; set; }
        internal Task? ProcessMonitor { get; set; }
        internal long OutputBytes;
        internal int Closed;
        private int disposed;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;
            Lifetime.Cancel();
            Input.Dispose();
            PseudoConsole.Dispose();
            ConsoleInput.Dispose();
            ConsoleOutput.Dispose();
            Output.Dispose();
            Process.Dispose();
            Job.Dispose();
            WindowsWorkloadIsolation.Release(
                Isolation.AttemptId,
                Isolation.Generation);
            InputLock.Dispose();
            Lifetime.Dispose();
            await ValueTask.CompletedTask;
        }
    }

    private readonly ConPtyTerminalRuntimeOptions options;
    private readonly ConcurrentDictionary<TerminalSessionId, ActiveSession> sessions = new();
    private bool disposed;

    internal ConPtyTerminalRuntime(ConPtyTerminalRuntimeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            throw new PlatformNotSupportedException("Windows ConPTY requires Windows 10 version 1809 or later.");
        if (options.OutputChunkBytes is <= 0 or > 1024 * 1024 ||
            options.MaximumInputChunkBytes is <= 0 or > 1024 * 1024 ||
            options.AllowedShellExecutables.Count == 0)
            throw new ArgumentOutOfRangeException(nameof(options));
        this.options = options with
        {
            AllowedShellExecutables = new HashSet<string>(
                options.AllowedShellExecutables.Select(Path.GetFullPath),
                StringComparer.OrdinalIgnoreCase)
        };
    }

    internal async ValueTask<ConPtyProcessIdentity> StartAsync(
        ConPtyStartRequest request,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> outputSink,
        Func<string, ValueTask> completion,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        Validate(request);
        cancellationToken.ThrowIfCancellationRequested();
        WindowsWorkloadIsolation.Prepare(request.Isolation);
        var elevated = IsCurrentProcessElevated();
        if (request.ElevationGranted && (!options.AllowElevatedServiceIdentity || !elevated))
            throw Problem(TerminalProblemCode.ElevationUnavailable,
                "Granted elevation requires an explicitly enabled elevated service identity.");

        SafeFileHandle? inputRead = null;
        SafeFileHandle? inputWrite = null;
        SafeFileHandle? outputRead = null;
        SafeFileHandle? outputWrite = null;
        PseudoConsoleHandle? pseudoConsole = null;
        SafeFileHandle? process = null;
        SafeFileHandle? job = null;
        ConPtyNativeMethods.ProcessInformation processInformation = default;
        ActiveSession? active = null;
        var releaseIsolation = true;
        try
        {
            CreatePipe(out inputRead, out inputWrite, parentIsWrite: true);
            CreatePipe(out outputRead, out outputWrite, parentIsWrite: false);
            var size = ToCoord(request.Columns, request.Rows);
            var result = ConPtyNativeMethods.CreatePseudoConsole(size, inputRead, outputWrite, 0, out var pseudoConsoleValue);
            if (result != 0)
                ConPtyNativeMethods.ThrowHResult(result, nameof(ConPtyNativeMethods.CreatePseudoConsole));
            pseudoConsole = new(pseudoConsoleValue);

            job = ConPtyNativeMethods.CreateJobObject(IntPtr.Zero, null);
            if (job.IsInvalid)
                ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.CreateJobObject));
            var limits = new ConPtyNativeMethods.JobObjectExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = ConPtyNativeMethods.JobObjectLimitKillOnJobClose;
            if (!ConPtyNativeMethods.SetInformationJobObject(job, 9, ref limits,
                    checked((uint)Marshal.SizeOf<ConPtyNativeMethods.JobObjectExtendedLimitInformation>())))
                ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.SetInformationJobObject));

            using var securityCapabilities =
                WindowsWorkloadIsolation.CreateSecurityCapabilities(
                    request.Isolation);
            using var attributes = new AttributeList(
                pseudoConsole,
                job,
                inputRead,
                outputWrite,
                securityCapabilities);
            var startup = new ConPtyNativeMethods.StartupInfoEx
            {
                StartupInfo = new ConPtyNativeMethods.StartupInfo
                {
                    cb = checked((uint)Marshal.SizeOf<ConPtyNativeMethods.StartupInfoEx>()),
                    dwFlags = ConPtyNativeMethods.StartfUseStdHandles,
                    hStdInput = inputRead.DangerousGetHandle(),
                    hStdOutput = outputWrite.DangerousGetHandle(),
                    hStdError = outputWrite.DangerousGetHandle()
                },
                AttributeList = attributes.Pointer
            };
            var commandLine = BuildCommandLine(request.Executable, request.Arguments);
            using var environment = WindowsWorkloadIsolation.AllocateEnvironment(
                request.Isolation,
                request.Executable);
            if (!ConPtyNativeMethods.CreateProcess(
                    request.Executable, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    ConPtyNativeMethods.CreateSuspended |
                    ConPtyNativeMethods.ExtendedStartupInfoPresent |
                    ConPtyNativeMethods.CreateUnicodeEnvironment,
                    environment.Pointer, request.WorkingDirectory, ref startup, out processInformation))
                ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.CreateProcess));
            process = new SafeFileHandle(processInformation.Process, true);
            processInformation.Process = IntPtr.Zero;
            using var thread = new SafeFileHandle(processInformation.Thread, true);
            processInformation.Thread = IntPtr.Zero;
            var authority = WindowsWorkloadIsolation.Describe(
                request.Isolation);
            var identity = new ConPtyProcessIdentity(
                checked((int)processInformation.ProcessId),
                GetCreationTime(process),
                authority.RestrictedSid,
                request.ElevationGranted && elevated);
            if (ConPtyNativeMethods.ResumeThread(thread) == uint.MaxValue)
                ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.ResumeThread));
            active = new ActiveSession
            {
                PseudoConsole = pseudoConsole,
                ConsoleInput = inputRead,
                ConsoleOutput = outputWrite,
                Input = inputWrite,
                Output = new FileStream(outputRead, FileAccess.Read, options.OutputChunkBytes, false),
                Process = process,
                Job = job,
                Identity = identity,
                Isolation = request.Isolation,
                Lifetime = new CancellationTokenSource(),
                InputLock = new SemaphoreSlim(1, 1),
                MaximumOutputBytes = request.MaximumOutputBytes
            };
            pseudoConsole = null;
            inputRead = null;
            inputWrite = null;
            outputRead = null;
            outputWrite = null;
            process = null;
            job = null;
            releaseIsolation = false;
            if (!sessions.TryAdd(request.SessionId, active))
                throw Problem(TerminalProblemCode.IdempotencyConflict, "Terminal runtime identity is already active.");
            active.Pump = PumpOutputAsync(request.SessionId, active, outputSink, completion);
            active.ProcessMonitor = Task.Run(() =>
            {
                _ = ConPtyNativeMethods.WaitForSingleObject(active.Process, uint.MaxValue);
                active.PseudoConsole.Dispose();
                Thread.Sleep(250);
                active.ConsoleInput.Dispose();
                active.ConsoleOutput.Dispose();
            });
            await Task.Yield();
            return identity;
        }
        catch
        {
            if (process is not null && job is not null && !job.IsInvalid)
                _ = ConPtyNativeMethods.TerminateJobObject(job, 0xE0000001);
            if (active is not null)
            {
                _ = sessions.TryRemove(request.SessionId, out _);
                await active.DisposeAsync().ConfigureAwait(false);
            }
            throw;
        }
        finally
        {
            inputRead?.Dispose();
            inputWrite?.Dispose();
            outputRead?.Dispose();
            outputWrite?.Dispose();
            pseudoConsole?.Dispose();
            process?.Dispose();
            job?.Dispose();
            if (processInformation.Process != IntPtr.Zero)
                new SafeFileHandle(processInformation.Process, true).Dispose();
            if (processInformation.Thread != IntPtr.Zero)
                new SafeFileHandle(processInformation.Thread, true).Dispose();
            if (releaseIsolation)
                WindowsWorkloadIsolation.Release(
                    request.Isolation.AttemptId,
                    request.Isolation.Generation);
        }
    }

    internal async ValueTask WriteAsync(
        TerminalSessionId sessionId,
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        if (data.IsEmpty || data.Length > options.MaximumInputChunkBytes)
            throw Problem(TerminalProblemCode.InvalidRequest, "Terminal input message size is invalid.");
        var active = RequireActive(sessionId);
        VerifyIdentity(active);
        await active.InputLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var buffer = data.ToArray();
            await Task.Run(() =>
            {
                if (!ConPtyNativeMethods.WriteFile(active.Input, buffer, checked((uint)buffer.Length),
                        out var written, IntPtr.Zero) || written != buffer.Length)
                    ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.WriteFile));
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or Win32Exception)
        {
            throw Problem(TerminalProblemCode.Interrupted, "Terminal input stream is unavailable.",
                TerminalProblemDisposition.RequiresReconciliation, true);
        }
        finally
        {
            active.InputLock.Release();
        }
    }

    internal void Resize(TerminalSessionId sessionId, int columns, int rows)
    {
        var active = RequireActive(sessionId);
        VerifyIdentity(active);
        var result = ConPtyNativeMethods.ResizePseudoConsole(active.PseudoConsole.DangerousGetHandle(), ToCoord(columns, rows));
        if (result != 0)
            throw Problem(TerminalProblemCode.RuntimeUnavailable, "Terminal resize failed.",
                TerminalProblemDisposition.RetrySafe, false);
    }

    internal async ValueTask CloseAsync(
        TerminalSessionId sessionId,
        TerminalShellKind shellKind,
        TimeSpan gracePeriod,
        CancellationToken cancellationToken)
    {
        if (!sessions.TryGetValue(sessionId, out var active))
            return;
        if (Interlocked.Exchange(ref active.Closed, 1) != 0)
            return;
        _ = sessions.TryRemove(sessionId, out _);
        VerifyIdentity(active);
        if (gracePeriod > TimeSpan.Zero)
        {
            var exit = shellKind == TerminalShellKind.CommandPrompt ? "exit\r\n"u8.ToArray() : "exit\r\n"u8.ToArray();
            try
            {
                await active.InputLock.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    if (!ConPtyNativeMethods.WriteFile(active.Input, exit, checked((uint)exit.Length),
                            out var written, IntPtr.Zero) || written != exit.Length)
                        ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.WriteFile));
                }
                finally
                {
                    active.InputLock.Release();
                }
                var wait = Task.Run(() => ConPtyNativeMethods.WaitForSingleObject(
                    active.Process, checked((uint)Math.Min(gracePeriod.TotalMilliseconds, uint.MaxValue - 1))), cancellationToken);
                await wait.WaitAsync(gracePeriod + TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException) { }
            catch (IOException) { }
        }
        if (ConPtyNativeMethods.GetExitCodeProcess(active.Process, out var code) &&
            code == ConPtyNativeMethods.StillActive &&
            !ConPtyNativeMethods.TerminateJobObject(active.Job, 0xC000013A))
            ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.TerminateJobObject));
        _ = ConPtyNativeMethods.WaitForSingleObject(active.Process, 5_000);
        active.Lifetime.Cancel();
        if (active.Pump is not null)
        {
            try { await active.Pump.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); }
            catch (TimeoutException) { }
        }
        await active.DisposeAsync().ConfigureAwait(false);
    }

    internal bool IsActive(TerminalSessionId sessionId) => sessions.ContainsKey(sessionId);

    private async Task PumpOutputAsync(
        TerminalSessionId sessionId,
        ActiveSession active,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> outputSink,
        Func<string, ValueTask> completion)
    {
        var buffer = new byte[options.OutputChunkBytes];
        var reason = "process-exited";
        try
        {
            while (!active.Lifetime.IsCancellationRequested)
            {
                var read = await active.Output.ReadAsync(buffer, active.Lifetime.Token).ConfigureAwait(false);
                if (read == 0)
                    break;
                var remaining = active.MaximumOutputBytes - active.OutputBytes;
                if (remaining <= 0)
                {
                    reason = "output-limit-reached";
                    _ = ConPtyNativeMethods.TerminateJobObject(active.Job, 0xE0000002);
                    break;
                }
                var accepted = checked((int)Math.Min(read, remaining));
                active.OutputBytes += accepted;
                await outputSink(buffer.AsMemory(0, accepted).ToArray(), active.Lifetime.Token).ConfigureAwait(false);
                if (accepted != read)
                {
                    reason = "output-limit-reached";
                    _ = ConPtyNativeMethods.TerminateJobObject(active.Job, 0xE0000002);
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (active.Lifetime.IsCancellationRequested)
        {
            reason = "cancelled";
        }
        catch (IOException)
        {
            reason = "output-stream-interrupted";
        }
        catch (TerminalException)
        {
            reason = "output-journal-rejected";
            _ = ConPtyNativeMethods.TerminateJobObject(active.Job, 0xE0000003);
        }
        finally
        {
            try { await completion(reason).ConfigureAwait(false); }
            catch (TerminalException) { }
            if (sessions.TryRemove(sessionId, out _))
                await active.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void Validate(ConPtyStartRequest request)
    {
        if (!options.AllowedShellExecutables.Contains(Path.GetFullPath(request.Executable)) ||
            !File.Exists(request.Executable) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetExtension(request.Executable), ".exe"))
            throw Problem(TerminalProblemCode.InvalidRequest, "Shell executable is not in the configured allowlist.");
        var expectedName = request.ShellKind switch
        {
            TerminalShellKind.PowerShell => "powershell.exe",
            TerminalShellKind.Pwsh => "pwsh.exe",
            TerminalShellKind.CommandPrompt => "cmd.exe",
            _ => ""
        };
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFileName(request.Executable), expectedName))
            throw Problem(TerminalProblemCode.InvalidRequest, "Shell kind does not match the configured executable.");
        if (!Directory.Exists(request.WorkingDirectory))
            throw Problem(TerminalProblemCode.PathRejected, "Terminal working directory does not exist.");
        TerminalContractLimits.ValidateSize(request.Columns, request.Rows);
    }

    private static void CreatePipe(
        out SafeFileHandle read,
        out SafeFileHandle write,
        bool parentIsWrite)
    {
        var security = new ConPtyNativeMethods.SecurityAttributes
        {
            Length = checked((uint)Marshal.SizeOf<ConPtyNativeMethods.SecurityAttributes>()),
            InheritHandle = true
        };
        if (!ConPtyNativeMethods.CreatePipe(out read, out write, ref security, 0))
            ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.CreatePipe));
        var parent = parentIsWrite ? write : read;
        if (!ConPtyNativeMethods.SetHandleInformation(parent, ConPtyNativeMethods.HandleFlagInherit, 0))
        {
            read.Dispose();
            write.Dispose();
            ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.SetHandleInformation));
        }
    }

    private static ConPtyNativeMethods.Coord ToCoord(int columns, int rows) =>
        new() { X = checked((short)columns), Y = checked((short)rows) };

    private ActiveSession RequireActive(TerminalSessionId sessionId) =>
        sessions.TryGetValue(sessionId, out var active)
            ? active
            : throw Problem(TerminalProblemCode.Interrupted, "Terminal runtime session is not active.",
                TerminalProblemDisposition.RequiresReconciliation, true);

    private static void VerifyIdentity(ActiveSession active)
    {
        if (!ConPtyNativeMethods.GetProcessTimes(active.Process, out var creation, out _, out _, out _) ||
            creation.ToLong() != active.Identity.CreationTimeUtcTicks)
            throw Problem(TerminalProblemCode.ProcessIdentityMismatch, "Terminal process identity could not be verified.",
                TerminalProblemDisposition.RequiresReconciliation, true);
    }

    private static long GetCreationTime(SafeFileHandle process)
    {
        if (!ConPtyNativeMethods.GetProcessTimes(process, out var creation, out _, out _, out _))
            ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.GetProcessTimes));
        return creation.ToLong();
    }

    private static bool IsCurrentProcessElevated()
    {
        if (!ConPtyNativeMethods.OpenProcessToken(ConPtyNativeMethods.GetCurrentProcess(),
                ConPtyNativeMethods.TokenQuery, out var token))
            ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.OpenProcessToken));
        using (token)
        {
            if (!ConPtyNativeMethods.GetTokenInformation(token, 20, out var elevation,
                    checked((uint)Marshal.SizeOf<ConPtyNativeMethods.TokenElevation>()), out _))
                ConPtyNativeMethods.ThrowLastError(nameof(ConPtyNativeMethods.GetTokenInformation));
            return elevation.TokenIsElevated != 0;
        }
    }

    internal static StringBuilder BuildCommandLine(string executable, IReadOnlyList<string> arguments) =>
        new(QuoteWindowsArgument(executable) +
            (arguments.Count == 0 ? "" : " " + string.Join(" ", arguments.Select(QuoteWindowsArgument))));

    internal static string QuoteWindowsArgument(string argument)
    {
        if (argument.Length > 0 && !argument.Any(character => char.IsWhiteSpace(character) || character == '"'))
            return argument;
        var builder = new StringBuilder("\"");
        var slashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                slashes++;
                continue;
            }
            if (character == '"')
            {
                builder.Append('\\', checked(slashes * 2 + 1)).Append('"');
                slashes = 0;
                continue;
            }
            builder.Append('\\', slashes).Append(character);
            slashes = 0;
        }
        builder.Append('\\', checked(slashes * 2)).Append('"');
        return builder.ToString();
    }

    private static TerminalException Problem(
        TerminalProblemCode code,
        string detail,
        TerminalProblemDisposition disposition = TerminalProblemDisposition.Terminal,
        bool sideEffectMayHaveOccurred = false) =>
        new(new(code, detail, disposition, sideEffectMayHaveOccurred));

    public async ValueTask DisposeAsync()
    {
        if (disposed)
            return;
        disposed = true;
        foreach (var session in sessions.Keys.ToArray())
        {
            try { await CloseAsync(session, TerminalShellKind.CommandPrompt, TimeSpan.Zero, CancellationToken.None).ConfigureAwait(false); }
            catch (TerminalException) { }
        }
    }
}
