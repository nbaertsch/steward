using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public sealed class WindowsAppIsolatedConnectionLeaseFactory(
    RdCoreCapabilityReport capability,
    IWindows365EndUserResourceCatalog resourceCatalog,
    RdpDvcPerConnectionConfiguration? dvcConfiguration = null) :
    IRdCoreConnectionLeaseFactory
{
    public async Task<IRdCoreConnectionLeaseHandle> CreateAsync(
        RdCoreConnectionStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!capability.IsCompatible || capability.Artifacts is null)
            throw new RdCoreLoadException(
                capability.Code,
                "A compatible Microsoft Windows App package is required.");

        var classified =
            DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(
                request.ProviderResourceUri);
        if (classified.Kind != DevBoxProviderRdpKind.WindowsAppResource)
            throw new InvalidDataException(
                "The isolated Windows App connection requires an ms-avd resource.");
        var resourceId = ReadUniqueQueryValue(
            request.ProviderResourceUri,
            "resourceid");
        if (!Guid.TryParse(resourceId, out var parsedResourceId) ||
            parsedResourceId == Guid.Empty)
            throw new InvalidDataException(
                "The ms-avd resource ID must be a nonempty GUID.");
        if (!string.Equals(
                request.ProviderResourceUri.OriginalString,
                request.ProviderResourceUri.AbsoluteUri,
                StringComparison.Ordinal) ||
            request.ProviderResourceUri.OriginalString.Contains('"') ||
            request.ProviderResourceUri.OriginalString.Any(char.IsControl))
            throw new InvalidDataException(
                "The provider URI is not safe for exact Windows App activation.");

        var entityId = await resourceCatalog.ResolveEntityIdAsync(
                request.ProviderResourceUri,
                cancellationToken)
            .ConfigureAwait(false);
        if (!Guid.TryParse(entityId, out var parsedEntityId) ||
            parsedEntityId == Guid.Empty)
            throw new InvalidDataException(
                "The Windows 365 entity ID must be a nonempty GUID.");
        var route = dvcConfiguration?.Create(request.ConnectionId);
        try
        {
            return new WindowsAppIsolatedConnectionLease(
                capability.Artifacts,
                parsedEntityId,
                route?.ConfigurationPath);
        }
        catch
        {
            if (route is not null)
                RdpDvcEmbeddingConfigurationStore.Delete(
                    route.ConfigurationPath);
            throw;
        }
    }

    private static string ReadUniqueQueryValue(Uri uri, string name)
    {
        string? value = null;
        foreach (var item in uri.Query.TrimStart('?').Split(
                     '&',
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = item.IndexOf('=');
            if (separator <= 0 ||
                !string.Equals(
                    Uri.UnescapeDataString(item[..separator]),
                    name,
                    StringComparison.OrdinalIgnoreCase))
                continue;
            if (value is not null)
                throw new InvalidDataException(
                    $"The provider URI contains duplicate '{name}' values.");
            value = Uri.UnescapeDataString(item[(separator + 1)..]);
        }
        return value ?? throw new InvalidDataException(
            $"The provider URI is missing '{name}'.");
    }
}

internal sealed class WindowsAppIsolatedConnectionLease(
    RdCorePackageArtifacts artifacts,
    Guid entityId,
    string? embeddingConfigurationPath = null) :
    IExternallyProvenRdCoreConnectionLeaseHandle,
    IRdCorePresentationLeaseHandle
{
    private const uint DesktopCreateWindow = 0x0002;
    private const uint DesktopReadObjects = 0x0001;
    private const uint DesktopWriteObjects = 0x0080;
    private const uint DesktopSwitchDesktop = 0x0100;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const int ErrorInsufficientBuffer = 122;
    private const uint WmClose = 0x0010;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectUiLimitHandles = 0x00000001;
    private const uint JobObjectUiLimitSystemParameters = 0x00000008;
    private const uint JobObjectUiLimitDisplaySettings = 0x00000010;
    private const uint JobObjectUiLimitDesktop = 0x00000040;
    private const uint JobObjectUiLimitExitWindows = 0x00000080;
    private const int JobObjectBasicUiRestrictionsClass = 4;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private static readonly string[] PackageProcessNames =
    [
        "Windows365",
        "msrdc",
        "msrdcw",
        "RdpTwainProxy",
        "triage-tool"
    ];
    private readonly object sync = new();
    private readonly CancellationTokenSource containmentStop = new();
    private readonly TaskCompletionSource containmentFailure = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private nint desktop;
    private nint priorDesktop;
    private nint job;
    private nint process;
    private uint processId;
    private string? desktopName;
    private Task? containmentMonitor;
    private WindowsAppOutOfProcOverride? outOfProcOverride;
    private int state = (int)RdCoreConnectionState.Resolving;
    private bool disposed;

    public RdCoreConnectionState State =>
        (RdCoreConnectionState)Volatile.Read(ref state);
    public Task ConnectionFailure => containmentFailure.Task;

    public event EventHandler? Connected;
    public event EventHandler? WtsPluginsLoaded;

    public Task ConnectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (process != 0)
                throw new InvalidOperationException(
                    "The isolated Windows App lease was already started.");
            try
            {
                Start(cancellationToken);
            }
            catch (Exception startupFailure)
            {
                try
                {
                    CleanupFailedStart();
                }
                catch (Exception cleanupFailure)
                {
                    throw new AggregateException(
                        "The isolated Windows App launch and cleanup both failed.",
                        startupFailure,
                        cleanupFailure);
                }
                throw;
            }
        }
        return Task.CompletedTask;
    }

    public void ConfirmConnected()
    {
        if (containmentFailure.Task.IsCompleted)
            containmentFailure.Task.GetAwaiter().GetResult();
        WindowsAppOutOfProcOverride? startupOverride;
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (process == 0 || !Native.IsProcessRunning(process))
                throw new InvalidOperationException(
                    "The isolated Windows App connection process exited.");
            Volatile.Write(
                ref state,
                (int)RdCoreConnectionState.Connected);
            startupOverride = outOfProcOverride;
            outOfProcOverride = null;
        }
        startupOverride?.Dispose();
        Connected?.Invoke(this, EventArgs.Empty);
        WtsPluginsLoaded?.Invoke(this, EventArgs.Empty);
    }

    public Task ShowAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (State != RdCoreConnectionState.Connected ||
                desktop == 0)
                throw new InvalidOperationException(
                    "The isolated Windows App connection is not connected.");
            if (priorDesktop != 0)
                return Task.CompletedTask;
            priorDesktop = Native.OpenInputDesktop(
                0,
                false,
                DesktopSwitchDesktop);
            if (priorDesktop == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!Native.SwitchDesktop(desktop))
            {
                var error = Marshal.GetLastWin32Error();
                Native.CloseDesktop(priorDesktop);
                priorDesktop = 0;
                throw new Win32Exception(error);
            }
        }
        return Task.CompletedTask;
    }

    public Task HideAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            if (priorDesktop == 0)
                return Task.CompletedTask;
            if (!Native.SwitchDesktop(priorDesktop))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            Native.CloseDesktop(priorDesktop);
            priorDesktop = 0;
        }
        return Task.CompletedTask;
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken)
    {
        await HideAsync(cancellationToken).ConfigureAwait(false);
        containmentStop.Cancel();
        nint ownedDesktop;
        nint ownedProcess;
        uint ownedProcessId;
        lock (sync)
        {
            ownedDesktop = desktop;
            ownedProcess = process;
            ownedProcessId = processId;
        }
        if (ownedProcess == 0)
            return;

        Native.RequestClose(
            ownedDesktop,
            ownedProcessId);
        var stopped = await WaitForExitAsync(
                ownedProcess,
                TimeSpan.FromSeconds(5),
                cancellationToken)
            .ConfigureAwait(false);
        if (!Native.TerminateJob(job, 1) &&
            !stopped)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        Volatile.Write(
            ref state,
            (int)RdCoreConnectionState.Disconnected);
    }

    public async ValueTask DisposeAsync()
    {
        lock (sync)
        {
            if (disposed)
                return;
            disposed = true;
        }
        containmentStop.Cancel();
        if (containmentMonitor is not null)
        {
            try
            {
                await containmentMonitor.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (containmentStop.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                Trace.TraceError(
                    "Windows App containment monitor cleanup failed: {0}; 0x{1:X8}.",
                    exception.GetType().Name,
                    exception.HResult);
            }
        }
        try
        {
            await DisconnectAsync(CancellationToken.None)
                .ConfigureAwait(false);
        }
        finally
        {
            lock (sync)
            {
                if (process != 0)
                {
                    Native.CloseHandle(process);
                    process = 0;
                }
                if (job != 0)
                {
                    Native.CloseHandle(job);
                    job = 0;
                }
                if (desktop != 0)
                {
                    Native.CloseDesktop(desktop);
                    desktop = 0;
                }
                if (priorDesktop != 0)
                {
                    Native.CloseDesktop(priorDesktop);
                    priorDesktop = 0;
                }
                outOfProcOverride?.Dispose();
                outOfProcOverride = null;
            }
            containmentStop.Dispose();
            if (embeddingConfigurationPath is not null)
                RdpDvcEmbeddingConfigurationStore.Delete(
                    embeddingConfigurationPath);
        }
    }

    private void Start(CancellationToken cancellationToken)
    {
        outOfProcOverride =
            WindowsAppOutOfProcOverride.Disable(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var executable = Path.GetFullPath(
            Path.Combine(
                artifacts.PackageRoot,
                "wnc",
                "Windows365.exe"));
        if (!File.Exists(executable) ||
            File.GetAttributes(executable)
                .HasFlag(FileAttributes.ReparsePoint) ||
            !IsWithinPackage(executable, artifacts.PackageRoot))
            throw new InvalidDataException(
                "The validated Windows App connection executable is unavailable.");

        desktopName = "Steward-" + Guid.NewGuid().ToString("N");
        desktop = Native.CreateDesktop(
            desktopName,
            0,
            0,
            0,
            DesktopCreateWindow |
            DesktopReadObjects |
            DesktopWriteObjects |
            DesktopSwitchDesktop,
            0);
        if (desktop == 0)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        job = Native.CreateRestrictedJob();

        var desktopPointer = Marshal.StringToHGlobalUni(
            @"winsta0\" + desktopName);
        var environment = CreateEnvironmentBlock(
            embeddingConfigurationPath);
        try
        {
            var commandLine = new StringBuilder(
                $"\"{executable}\" --ExecutionMode connectionclient " +
                "--UseRDCore --LaunchProfile SwitchLight " +
                $"--ResourceId {entityId:D}");
            var startup = new StartupInfo
            {
                Size = Marshal.SizeOf<StartupInfo>(),
                Desktop = desktopPointer
            };
            if (!Native.CreateProcess(
                    executable,
                    commandLine,
                    0,
                    0,
                    false,
                    CreateSuspended | CreateUnicodeEnvironment,
                    environment,
                    Path.GetDirectoryName(executable)!,
                    ref startup,
                    out var created))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            process = created.Process;
            processId = created.ProcessId;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var packageFullName = Native.GetPackageFullName(process);
                if (!string.Equals(
                        packageFullName,
                        artifacts.PackageFullName,
                        StringComparison.Ordinal))
                    throw new InvalidDataException(
                        "The Windows App process package identity changed.");
                if (!Native.AssignProcessToJobObject(job, process))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (Native.ResumeThread(created.Thread) == uint.MaxValue)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (!Native.IsProcessConfinedToDesktop(
                        processId,
                        desktopName,
                        TimeSpan.FromSeconds(10)))
                    throw new InvalidDataException(
                        "The Windows App process escaped its isolated desktop: " +
                        Native.DescribeProcessDesktops(processId));
                Thread.Sleep(500);
                if (Native.HasOtherPackageProcessInCurrentSession(
                        processId,
                        artifacts.PackageRoot) &&
                    !Native.ValidateOtherPackageProcesses(
                        processId,
                        artifacts.PackageRoot))
                    throw new InvalidDataException(
                        "A Windows App service process was not headless.");
            }
            catch
            {
                Native.TerminateProcess(process, 1);
                throw;
            }
            finally
            {
                Native.CloseHandle(created.Thread);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(environment);
            Marshal.FreeHGlobal(desktopPointer);
        }
        Volatile.Write(
            ref state,
            (int)RdCoreConnectionState.Connecting);
        containmentMonitor = MonitorContainmentAsync(
            desktopName,
            containmentStop.Token);
    }

    private void CleanupFailedStart()
    {
        Volatile.Write(
            ref state,
            (int)RdCoreConnectionState.Failed);
        if (job != 0)
            Native.TerminateJob(job, 1);
        else if (process != 0)
            Native.TerminateProcess(process, 1);
        if (process != 0)
        {
            Native.CloseHandle(process);
            process = 0;
        }
        if (job != 0)
        {
            Native.CloseHandle(job);
            job = 0;
        }
        if (desktop != 0)
        {
            Native.CloseDesktop(desktop);
            desktop = 0;
        }
        outOfProcOverride?.Dispose();
        outOfProcOverride = null;
    }

    private static nint CreateEnvironmentBlock(
        string? embeddingConfigurationPath)
    {
        var values = BuildChildEnvironmentValues(
            embeddingConfigurationPath);
        var block = string.Join(
                '\0',
                values.OrderBy(
                        static value => value.Key,
                        StringComparer.OrdinalIgnoreCase)
                    .Select(static value =>
                        value.Key + "=" + value.Value)) +
            "\0\0";
        return Marshal.StringToHGlobalUni(block);
    }

    internal static IReadOnlyDictionary<string, string>
        BuildChildEnvironmentValues(
            string? embeddingConfigurationPath)
    {
        var hook = Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "Steward.WindowsApp.RdCoreHook.dll"));
        var harmony = Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "0Harmony.dll"));
        var shim = Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "Steward.RdpDvc.Shim.Windows.dll"));
        var managedPlugin = Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "Steward.RdpDvc.Client.Windows.dll"));
        foreach (var path in new[] { hook, harmony, shim, managedPlugin })
        {
            if (!File.Exists(path) ||
                File.GetAttributes(path)
                    .HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "The Steward RDCore instrumentation is unavailable.");
        }
        var values = Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(
                static entry => (string)entry.Key,
                static entry => (string?)entry.Value ?? string.Empty,
                StringComparer.OrdinalIgnoreCase);
        values["DOTNET_STARTUP_HOOKS"] = hook;
        values["STEWARD_RDCORE_HARMONY_PATH"] = harmony;
        values["STEWARD_RDCORE_SHIM_PATH"] = shim;
        values["STEWARD_RDCORE_MANAGED_PLUGIN_PATH"] = managedPlugin;
        if (embeddingConfigurationPath is not null)
            values[
                RdpDvcEmbeddingConfigurationStore
                    .ConfigurationPathEnvironmentVariable] =
                embeddingConfigurationPath;
        var evidenceDirectory = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "Steward",
            "connection-host");
        Directory.CreateDirectory(evidenceDirectory);
        values["STEWARD_RDCORE_HOOK_EVIDENCE_PATH"] = Path.Combine(
            evidenceDirectory,
            "rdcore-hook-" + Guid.NewGuid().ToString("N") + ".log");
        values["STEWARD_RDCORE_SHIM_EVIDENCE_PATH"] = Path.Combine(
            evidenceDirectory,
            "rdcore-shim-" + Guid.NewGuid().ToString("N") + ".log");
        return values;
    }

    private async Task MonitorContainmentAsync(
        string expectedDesktop,
        CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await Task.Delay(100, cancellationToken)
                    .ConfigureAwait(false);
                if (!Native.IsProcessRunning(process))
                    throw new InvalidOperationException(
                        "The isolated Windows App connection process exited.");
                if (!Native.IsProcessConfinedToDesktop(
                        processId,
                        expectedDesktop,
                        TimeSpan.Zero))
                    throw new InvalidDataException(
                        "The Windows App process escaped its isolated desktop: " +
                        Native.DescribeProcessDesktops(processId));
                if (Native.HasOtherPackageProcessInCurrentSession(
                        processId,
                        artifacts.PackageRoot) &&
                    !Native.ValidateOtherPackageProcesses(
                        processId,
                        artifacts.PackageRoot))
                    throw new InvalidDataException(
                        "A Windows App service process was not headless.");
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            Native.TerminateJob(job, 1);
            Volatile.Write(
                ref state,
                (int)RdCoreConnectionState.Failed);
            containmentFailure.TrySetException(exception);
        }
    }

    private static bool IsWithinPackage(string path, string packageRoot)
    {
        var relative = Path.GetRelativePath(
            Path.GetFullPath(packageRoot),
            path);
        return relative.Length != 0 &&
            relative != "." &&
            !relative.StartsWith("..", StringComparison.Ordinal) &&
            !Path.IsPathFullyQualified(relative);
    }

    private static async Task<bool> WaitForExitAsync(
        nint processHandle,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = Stopwatch.GetTimestamp() +
            (long)(timeout.TotalSeconds * Stopwatch.Frequency);
        while (Stopwatch.GetTimestamp() < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Native.IsProcessRunning(processHandle))
                return true;
            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        }
        return !Native.IsProcessRunning(processHandle);
    }

    private static class Native
    {
        internal static bool IsProcessRunning(nint handle) =>
            GetExitCodeProcess(handle, out var code) && code == 259;

        internal static bool HasOtherPackageProcessInCurrentSession(
            uint allowedProcessId,
            string packageRoot)
        {
            var candidates = SnapshotPackageProcesses(
                packageRoot,
                out var complete);
            if (!complete)
                throw new InvalidDataException(
                    "The Windows App process snapshot was incomplete.");
            var found = false;
            foreach (var candidate in candidates)
            {
                try
                {
                    if (candidate.Id != allowedProcessId)
                        found = true;
                }
                catch (InvalidOperationException)
                {
                }
                finally
                {
                    candidate.Dispose();
                }
            }
            return found;
        }

        internal static bool ValidateOtherPackageProcesses(
            uint allowedProcessId,
            string packageRoot)
        {
            var succeeded = true;
            var candidates = SnapshotPackageProcesses(
                packageRoot,
                out var complete);
            succeeded = complete;
            foreach (var candidate in candidates)
            {
                try
                {
                    if (candidate.Id == allowedProcessId)
                        continue;
                    if (HasVisibleProcessWindowOnInputDesktop(
                            checked((uint)candidate.Id)))
                    {
                        succeeded = false;
                        continue;
                    }
                }
                catch (Exception exception)
                    when (exception is
                        InvalidOperationException or
                        Win32Exception)
                {
                    succeeded = false;
                }
                finally
                {
                    candidate.Dispose();
                }
            }
            return succeeded;
        }

        private static IReadOnlyList<Process> SnapshotPackageProcesses(
            string packageRoot,
            out bool complete)
        {
            complete = true;
            var result = new List<Process>();
            using var current = Process.GetCurrentProcess();
            var normalizedRoot = Path.GetFullPath(packageRoot)
                .TrimEnd(Path.DirectorySeparatorChar) +
                Path.DirectorySeparatorChar;
            var seen = new HashSet<int>();
            foreach (var name in PackageProcessNames)
            {
                foreach (var candidate in Process.GetProcessesByName(name))
                {
                    if (!seen.Add(candidate.Id))
                    {
                        candidate.Dispose();
                        continue;
                    }
                    try
                    {
                        if (candidate.SessionId != current.SessionId)
                        {
                            candidate.Dispose();
                            continue;
                        }
                        var executable = ReadProcessImagePath(candidate);
                        if (executable is not null &&
                            Path.GetFullPath(executable).StartsWith(
                                normalizedRoot,
                                StringComparison.OrdinalIgnoreCase))
                            result.Add(candidate);
                        else
                            candidate.Dispose();
                    }
                    catch (InvalidOperationException)
                    {
                        candidate.Dispose();
                    }
                    catch (Win32Exception)
                    {
                        result.Add(candidate);
                    }
                }
            }
            return result;
        }

        internal static nint CreateRestrictedJob()
        {
            var handle = CreateJobObject(0, null);
            if (handle == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var limits = new JobObjectExtendedLimitInformation
                {
                    BasicLimitInformation =
                    {
                        LimitFlags = JobObjectLimitKillOnJobClose
                    }
                };
                if (!SetInformationJobObjectExtended(
                        handle,
                        JobObjectExtendedLimitInformationClass,
                        ref limits,
                        checked((uint)Marshal.SizeOf<
                            JobObjectExtendedLimitInformation>())))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                var restrictions = new JobObjectBasicUiRestrictions
                {
                    RestrictionsClass =
                        JobObjectUiLimitHandles |
                        JobObjectUiLimitSystemParameters |
                        JobObjectUiLimitDisplaySettings |
                        JobObjectUiLimitDesktop |
                        JobObjectUiLimitExitWindows
                };
                if (!SetInformationJobObjectUi(
                        handle,
                        JobObjectBasicUiRestrictionsClass,
                        ref restrictions,
                        checked((uint)Marshal.SizeOf<
                            JobObjectBasicUiRestrictions>())))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return handle;
            }
            catch
            {
                CloseHandle(handle);
                throw;
            }
        }

        internal static bool TerminateJob(nint handle, uint exitCode) =>
            handle != 0 && TerminateJobObject(handle, exitCode);

        internal static bool IsProcessConfinedToDesktop(
            uint ownerProcessId,
            string desktopName,
            TimeSpan timeout)
        {
            _ = timeout;
            try
            {
                using var candidate = Process.GetProcessById(
                    checked((int)ownerProcessId));
                var names = candidate.Threads
                    .Cast<ProcessThread>()
                    .Select(thread => ReadDesktopName(
                        GetThreadDesktop(
                            checked((uint)thread.Id))))
                    .Where(static name => name is not null)
                    .ToArray();
                if (names.Length != 0)
                    return names.All(name => string.Equals(
                        name,
                        desktopName,
                        StringComparison.Ordinal));
                return !HasProcessWindowOnInputDesktop(
                    ownerProcessId);
            }
            catch (Exception exception)
                when (exception is
                    ArgumentException or
                    InvalidOperationException or
                    Win32Exception)
            {
                return false;
            }
        }

        internal static string DescribeProcessDesktops(
            uint ownerProcessId)
        {
            try
            {
                using var candidate = Process.GetProcessById(
                    checked((int)ownerProcessId));
                var names = candidate.Threads
                    .Cast<ProcessThread>()
                    .Select(thread => ReadDesktopName(
                        GetThreadDesktop(
                            checked((uint)thread.Id))) ?? "<unreadable>")
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray();
                return (names.Length == 0
                        ? "<none>"
                        : string.Join(",", names)) +
                    (HasProcessWindowOnInputDesktop(ownerProcessId)
                        ? ",input-window"
                        : ",no-input-window");
            }
            catch (Exception exception)
                when (exception is
                    ArgumentException or
                    InvalidOperationException or
                    Win32Exception)
            {
                return "<unavailable>";
            }
        }

        private static string? ReadDesktopName(nint desktopHandle)
        {
            if (desktopHandle == 0)
                return null;
            uint required = 0;
            GetUserObjectInformation(
                desktopHandle,
                2,
                0,
                0,
                out required);
            if (required == 0)
                return null;
            var buffer = Marshal.AllocHGlobal(checked((int)required));
            try
            {
                return GetUserObjectInformation(
                        desktopHandle,
                        2,
                        buffer,
                        required,
                        out _)
                    ? Marshal.PtrToStringUni(buffer)
                    : null;
            }

            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static bool HasProcessWindowOnInputDesktop(
            uint ownerProcessId)
        {
            var found = false;
            if (!EnumWindows(
                    (window, _) =>
                    {
                        GetWindowThreadProcessId(
                            window,
                            out var windowProcessId);
                        if (windowProcessId != ownerProcessId)
                            return true;
                        found = true;
                        return false;
                    },
                    0))
            {
                var error = Marshal.GetLastWin32Error();
                if (!found && error != 0)
                    throw new Win32Exception(error);
            }
            return found;
        }

        private static bool HasVisibleProcessWindowOnInputDesktop(
            uint ownerProcessId)
        {
            var found = false;
            if (!EnumWindows(
                    (window, _) =>
                    {
                        GetWindowThreadProcessId(
                            window,
                            out var windowProcessId);
                        if (windowProcessId != ownerProcessId ||
                            !IsWindowVisible(window) ||
                            !GetWindowRect(window, out var rectangle) ||
                            rectangle.Right <= rectangle.Left ||
                            rectangle.Bottom <= rectangle.Top)
                            return true;
                        found = true;
                        return false;
                    },
                    0))
            {
                var error = Marshal.GetLastWin32Error();
                if (!found && error != 0)
                    throw new Win32Exception(error);
            }
            return found;
        }

        private static string? ReadProcessImagePath(Process process)
        {
            const uint processQueryLimitedInformation = 0x1000;
            var handle = OpenProcess(
                processQueryLimitedInformation,
                false,
                checked((uint)process.Id));
            if (handle == 0)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == 87)
                    return null;
                throw new Win32Exception(error);
            }
            try
            {
                var capacity = 32768;
                var buffer = new StringBuilder(capacity);
                if (QueryFullProcessImageName(
                        handle,
                        0,
                        buffer,
                        ref capacity))
                    return buffer.ToString();
                var error = Marshal.GetLastWin32Error();
                if (error == 87)
                    return null;
                throw new Win32Exception(error);
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        internal static string GetPackageFullName(nint processHandle)
        {
            uint length = 0;
            var result = GetPackageFullNameNative(
                processHandle,
                ref length,
                null);
            if (result != ErrorInsufficientBuffer)
                throw new Win32Exception(result);
            var buffer = new char[length];
            result = GetPackageFullNameNative(
                processHandle,
                ref length,
                buffer);
            if (result != 0)
                throw new Win32Exception(result);
            return new string(buffer, 0, checked((int)length - 1));
        }

        internal static void RequestClose(nint desktop, uint ownerProcessId)
        {
            if (desktop == 0)
                return;
            EnumDesktopWindows(
                desktop,
                (window, _) =>
                {
                    GetWindowThreadProcessId(window, out var windowProcessId);
                    if (windowProcessId == ownerProcessId)
                        PostMessage(window, WmClose, 0, 0);
                    return true;
                },
                0);
        }

        [DllImport(
            "user32.dll",
            EntryPoint = "CreateDesktopW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        internal static extern nint CreateDesktop(
            string desktop,
            nint device,
            nint deviceMode,
            uint flags,
            uint desiredAccess,
            nint securityAttributes);

        [DllImport("user32.dll", SetLastError = true)]
        internal static extern nint OpenInputDesktop(
            uint flags,
            [MarshalAs(UnmanagedType.Bool)] bool inherit,
            uint desiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SwitchDesktop(nint desktop);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseDesktop(nint desktop);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateProcessW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcess(
            string applicationName,
            StringBuilder commandLine,
            nint processAttributes,
            nint threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            nint environment,
            string currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(nint thread);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateJobObjectW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        internal static extern nint CreateJobObject(
            nint securityAttributes,
            string? name);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "SetInformationJobObject",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObjectExtended(
            nint job,
            int informationClass,
            ref JobObjectExtendedLimitInformation information,
            uint informationLength);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "SetInformationJobObject",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObjectUi(
            nint job,
            int informationClass,
            ref JobObjectBasicUiRestrictions information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(
            nint job,
            nint process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(
            nint job,
            uint exitCode);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "GetPackageFullName",
            CharSet = CharSet.Unicode)]
        private static extern int GetPackageFullNameNative(
            nint process,
            ref uint packageFullNameLength,
            [Out] char[]? packageFullName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(
            nint process,
            out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(
            nint process,
            uint exitCode);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(nint handle);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumDesktopWindows(
            nint desktop,
            EnumDesktopWindowsCallback callback,
            nint parameter);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumWindows(
            EnumDesktopWindowsCallback callback,
            nint parameter);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(
            nint window,
            out uint processId);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWindowVisible(nint window);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowRect(
            nint window,
            out Rectangle rectangle);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "QueryFullProcessImageNameW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(
            nint process,
            uint flags,
            StringBuilder executableName,
            ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nint OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint processId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PostMessage(
            nint window,
            uint message,
            nint wParam,
            nint lParam);

        [DllImport("user32.dll")]
        private static extern nint GetThreadDesktop(uint threadId);

        [DllImport(
            "user32.dll",
            EntryPoint = "GetUserObjectInformationW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetUserObjectInformation(
            nint handle,
            int index,
            nint information,
            uint length,
            out uint needed);

        internal delegate bool EnumDesktopWindowsCallback(
            nint window,
            nint parameter);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        internal int Size;
        internal nint Reserved;
        internal nint Desktop;
        internal nint Title;
        internal int X;
        internal int Y;
        internal int XSize;
        internal int YSize;
        internal int XCountChars;
        internal int YCountChars;
        internal int FillAttribute;
        internal int Flags;
        internal short ShowWindow;
        internal short ReservedSize;
        internal nint ReservedBytes;
        internal nint StandardInput;
        internal nint StandardOutput;
        internal nint StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal nint Process;
        internal nint Thread;
        internal uint ProcessId;
        internal uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Rectangle
    {
        internal int Left;
        internal int Top;
        internal int Right;
        internal int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicUiRestrictions
    {
        internal uint RestrictionsClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal nuint MinimumWorkingSetSize;
        internal nuint MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal nuint Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        internal JobObjectBasicLimitInformation BasicLimitInformation;
        internal IoCounters IoInfo;
        internal nuint ProcessMemoryLimit;
        internal nuint JobMemoryLimit;
        internal nuint PeakProcessMemoryUsed;
        internal nuint PeakJobMemoryUsed;
    }
}
