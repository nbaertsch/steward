using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Steward.RdpDvc.LiveAcceptance;

internal interface ISurfaceGuard : IAsyncDisposable
{
    SurfaceObservationEvidence Initial { get; }

    Task Violation { get; }

    SurfaceObservationEvidence Observe();

    void ThrowIfViolated();
}

internal sealed partial class WindowsSurfaceGuard : ISurfaceGuard
{
    private static readonly HashSet<string> CandidateProcessNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "msrdc",
            "msrdcw",
            "rdcore",
            "rdclient",
            "rdclientwpf",
            "windowsapp",
            "windows365",
            "microsoftcorporationii.windows365"
        };

    private readonly string packageRoot;
    private readonly TimeSpan interval;
    private readonly CancellationTokenSource stop = new();
    private readonly TaskCompletionSource violation =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Dictionary<ProcessIdentity, SafeProcessHandle>
        candidateHandles = [];
    private readonly object sync = new();
    private readonly Observation baseline;
    private readonly Task monitor;
    private Exception? failure;

    internal WindowsSurfaceGuard(
        string packageRoot,
        TimeSpan? samplingInterval = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "The RDCore live surface guard requires Windows.");
        this.packageRoot = Path.GetFullPath(packageRoot)
            .TrimEnd(Path.DirectorySeparatorChar) +
            Path.DirectorySeparatorChar;
        interval = samplingInterval ?? TimeSpan.FromMilliseconds(25);
        if (interval <= TimeSpan.Zero ||
            interval > TimeSpan.FromSeconds(1))
            throw new ArgumentOutOfRangeException(
                nameof(samplingInterval));
        baseline = Capture();
        Initial = ToEvidence(baseline);
        monitor = MonitorAsync();
    }

    public SurfaceObservationEvidence Initial { get; }

    public Task Violation => violation.Task;

    public SurfaceObservationEvidence Observe()
    {
        var current = Capture();
        Evaluate(current);
        ThrowIfViolated();
        return ToEvidence(current);
    }

    public void ThrowIfViolated()
    {
        lock (sync)
        {
            if (failure is not null)
            {
                Console.Error.WriteLine(
                    $"LIVE SURFACE FAILURE: {failure.Message}");
                throw new HeadlessSurfaceViolationException(
                    "A top-level visible-window or foreground change occurred before View.",
                    failure);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        try
        {
            await monitor.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (stop.IsCancellationRequested)
        {
        }
        lock (sync)
        {
            foreach (var handle in candidateHandles.Values)
                handle.Dispose();
            candidateHandles.Clear();
        }
        stop.Dispose();
    }

    private async Task MonitorAsync()
    {
        try
        {
            while (true)
            {
                await Task.Delay(interval, stop.Token).ConfigureAwait(false);
                var current = Capture();
                Evaluate(current);
                if (failure is not null)
                    return;
            }
        }

        catch (OperationCanceledException)
            when (stop.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            lock (sync)
                failure = exception;
            TerminateExactCandidates();
            violation.TrySetResult();
        }
    }

    private void Evaluate(Observation current)
    {
        TrackCandidates(current);
        HashSet<int> candidates;
        lock (sync)
            candidates = candidateHandles.Keys
                .Select(static process => process.ProcessId)
                .ToHashSet();
        if (current.VisibleWindowOwners.Overlaps(candidates) ||
            current.ForegroundWindowOwner is int foregroundOwner &&
            candidates.Contains(foregroundOwner))
            FailClosed(current);
    }

    private void TrackCandidates(Observation observation)
    {
        foreach (var process in observation.Processes)
        {
            if (baseline.Processes.Contains(process) ||
                !IsCandidate(process))
                continue;
            lock (sync)
            {
                if (candidateHandles.ContainsKey(process))
                    continue;
                var handle = NativeMethods.OpenProcess(
                    NativeMethods.ProcessTerminate |
                    NativeMethods.ProcessQueryLimitedInformation,
                    false,
                    process.ProcessId);
                if (!handle.IsInvalid &&
                    process.StartFileTime != 0 &&
                    NativeMethods.GetProcessTimes(
                        handle,
                        out var creation,
                        out _,
                        out _,
                        out _) &&
                    creation.ToInt64() == process.StartFileTime)
                    candidateHandles.Add(process, handle);
                else
                    handle.Dispose();
            }
        }
    }

    private bool IsCandidate(ProcessIdentity process) =>
        CandidateProcessNames.Contains(process.Name) ||
        process.ImagePath is { } image &&
        Path.GetFullPath(image).StartsWith(
            packageRoot,
            StringComparison.OrdinalIgnoreCase);

    private void FailClosed(Observation current)
    {
        var newProcessNames = current.Processes
            .Except(baseline.Processes)
            .Select(static process => process.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase);
        HashSet<int> candidates;
        lock (sync)
            candidates = candidateHandles.Keys
                .Select(static process => process.ProcessId)
                .ToHashSet();
        lock (sync)
            failure = new InvalidOperationException(
                "A Steward-owned process surfaced UI while View was unauthorized; " +
                $"candidateForeground=" +
                $"{current.ForegroundWindowOwner is int owner && candidates.Contains(owner)}; " +
                $"candidateVisibleWindows=" +
                $"{current.VisibleWindowOwners.Count(candidates.Contains)}; " +
                $"newProcesses={string.Join(',', newProcessNames)}.");
        TerminateExactCandidates();
        violation.TrySetResult();
    }

    private void TerminateExactCandidates()
    {
        lock (sync)
        {
            foreach (var handle in candidateHandles.Values)
            {
                if (!handle.IsInvalid && !handle.IsClosed)
                    _ = NativeMethods.TerminateProcess(handle, 1);
            }
        }
    }

    private static Observation Capture()
    {
        var processes = new HashSet<ProcessIdentity>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var name = process.ProcessName;
                    long startFileTime;
                    try
                    {
                        startFileTime = process.StartTime.ToFileTimeUtc();
                    }
                    catch (Exception exception)
                        when (exception is
                            InvalidOperationException or
                            NotSupportedException or
                            Win32Exception)
                    {
                        startFileTime = 0;
                    }
                    processes.Add(
                        new(
                            process.Id,
                            startFileTime,
                            name,
                            TryGetImagePath(process)));
                }
                catch (Exception exception)
                    when (exception is
                        InvalidOperationException or
                        NotSupportedException or
                        Win32Exception)
                {
                }
            }
        }

        var windows = new HashSet<nint>();
        var visible = new HashSet<nint>();
        var visibleWindowOwners = new HashSet<int>();
        if (!NativeMethods.EnumWindows(
                (window, _) =>
                {
                    windows.Add(window);
                    if (NativeMethods.IsWindowVisible(window))
                    {
                        visible.Add(window);
                        NativeMethods.GetWindowThreadProcessId(
                            window,
                            out var owner);
                        if (owner <= int.MaxValue)
                            visibleWindowOwners.Add((int)owner);
                    }
                    return true;
                },
                nint.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        var foreground = NativeMethods.GetForegroundWindow();
        int? foregroundOwner = null;
        if (foreground != 0)
        {
            _ = NativeMethods.GetWindowThreadProcessId(
                foreground,
                out var owner);
            if (owner <= int.MaxValue)
                foregroundOwner = (int)owner;
        }
        return new(
            processes,
            windows,
            visible,
            visibleWindowOwners,
            foreground,
            foregroundOwner);
    }

    private static string? TryGetImagePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch (Exception exception)
            when (exception is
                InvalidOperationException or
                NotSupportedException or
                Win32Exception)
        {
            return null;
        }
    }

    private static SurfaceObservationEvidence ToEvidence(
        Observation observation) =>
        new(
            DateTimeOffset.UtcNow,
            observation.Processes.Count,
            observation.Windows.Count,
            HashSet(observation.Processes.Select(
                static process =>
                    $"{process.ProcessId}:{process.StartFileTime}:{process.Name}")),
            HashSet(observation.Windows.Select(
                static window => window.ToInt64().ToString())),
            observation.ForegroundWindow.ToInt64());

    private static string HashSet(IEnumerable<string> values) =>
        RemoteBootstrapEvidenceLoader.Hash(
            Encoding.UTF8.GetBytes(
                string.Join(
                    '\n',
                    values.Order(StringComparer.Ordinal))));

    private sealed record Observation(
        HashSet<ProcessIdentity> Processes,
        HashSet<nint> Windows,
        HashSet<nint> VisibleWindows,
        HashSet<int> VisibleWindowOwners,
        nint ForegroundWindow,
        int? ForegroundWindowOwner);

    private sealed class ProcessIdentity(
        int processId,
        long startFileTime,
        string name,
        string? imagePath) : IEquatable<ProcessIdentity>
    {
        public int ProcessId { get; } = processId;
        public long StartFileTime { get; } = startFileTime;
        public string Name { get; } = name;
        public string? ImagePath { get; } = imagePath;

        public bool Equals(ProcessIdentity? other) =>
            other is not null &&
            ProcessId == other.ProcessId &&
            StartFileTime == other.StartFileTime;

        public override bool Equals(object? value) =>
            value is ProcessIdentity other && Equals(other);

        public override int GetHashCode() =>
            HashCode.Combine(ProcessId, StartFileTime);
    }

    private static partial class NativeMethods
    {
        internal const uint ProcessTerminate = 0x0001;
        internal const uint ProcessQueryLimitedInformation = 0x1000;

        internal delegate bool EnumWindowsCallback(
            nint window,
            nint parameter);

        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool EnumWindows(
            EnumWindowsCallback callback,
            nint parameter);

        [LibraryImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool IsWindowVisible(nint window);

        [LibraryImport("user32.dll")]
        internal static partial nint GetForegroundWindow();

        [LibraryImport("user32.dll", SetLastError = true)]
        internal static partial uint GetWindowThreadProcessId(
            nint window,
            out uint processId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        internal static partial SafeProcessHandle OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool GetProcessTimes(
            SafeProcessHandle process,
            out FileTime creationTime,
            out FileTime exitTime,
            out FileTime kernelTime,
            out FileTime userTime);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool TerminateProcess(
            SafeProcessHandle process,
            uint exitCode);

        [StructLayout(LayoutKind.Sequential)]
        internal readonly struct FileTime
        {
            private readonly uint low;
            private readonly uint high;

            internal long ToInt64() =>
                unchecked((long)(((ulong)high << 32) | low));
        }
    }
}

internal sealed class HeadlessSurfaceViolationException(
    string message,
    Exception innerException) : InvalidOperationException(
        message,
        innerException);
