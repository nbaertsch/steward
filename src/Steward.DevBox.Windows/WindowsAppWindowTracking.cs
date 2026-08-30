using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Steward.DevBox.Windows;

public readonly record struct WindowsAppWindowIdentity(
    IntPtr Handle,
    uint ProcessId);

public sealed record WindowsAppWindowCandidate(
    WindowsAppWindowIdentity Identity);

public enum WindowsAppWindowDiscoveryState
{
    Found,
    NotFound,
    Ambiguous
}

public sealed record WindowsAppWindowDiscovery(
    WindowsAppWindowDiscoveryState State,
    WindowsAppWindowIdentity? Window);

public static class WindowsAppWindowSelector
{
    public static WindowsAppWindowDiscovery Select(
        IReadOnlyList<WindowsAppWindowCandidate> before,
        IReadOnlyList<WindowsAppWindowCandidate> after)
    {
        var prior = before.Select(value => value.Identity)
            .ToHashSet();
        var created = after
            .Where(value => !prior.Contains(value.Identity))
            .ToArray();
        if (created.Length == 1)
            return new(
                WindowsAppWindowDiscoveryState.Found,
                created[0].Identity);
        if (created.Length > 1)
            return new(
                WindowsAppWindowDiscoveryState.Ambiguous,
                null);
        return after.Count switch
        {
            0 => new(
                WindowsAppWindowDiscoveryState.NotFound,
                null),
            1 => new(
                WindowsAppWindowDiscoveryState.Found,
                after[0].Identity),
            _ => new(
                WindowsAppWindowDiscoveryState.Ambiguous,
                null)
        };
    }
}

public interface IWindowsAppWindowTracker
{
    IReadOnlyList<WindowsAppWindowCandidate> Snapshot();

    Task<WindowsAppWindowDiscovery> FindActivatedWindowAsync(
        IReadOnlyList<WindowsAppWindowCandidate> before,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    bool IsAlive(WindowsAppWindowIdentity window);
    bool Surface(WindowsAppWindowIdentity window);
}

public sealed class WindowsAppWindowTracker : IWindowsAppWindowTracker
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int RestoreWindow = 9;
    private const int ErrorInsufficientBuffer = 122;
    private const string PackagePrefix =
        "MicrosoftCorporationII.Windows365_";
    private const string PublisherSuffix = "__8wekyb3d8bbwe";

    public IReadOnlyList<WindowsAppWindowCandidate> Snapshot()
    {
        var values = new List<WindowsAppWindowCandidate>();
        var currentSession = Process.GetCurrentProcess().SessionId;
        _ = EnumWindows((window, parameter) =>
        {
            _ = parameter;
            if (!IsWindowVisible(window))
                return true;
            GetWindowThreadProcessId(window, out var processId);
            if (processId == 0 ||
                !IsOfficialWindowsAppProcess(
                    processId,
                    currentSession))
                return true;
            values.Add(new(
                new(window, processId)));
            return true;
        }, IntPtr.Zero);
        return values
            .DistinctBy(value => value.Identity)
            .ToArray();
    }

    public async Task<WindowsAppWindowDiscovery>
        FindActivatedWindowAsync(
            IReadOnlyList<WindowsAppWindowCandidate> before,
            TimeSpan timeout,
            CancellationToken cancellationToken)
    {
        if (timeout <= TimeSpan.Zero ||
            timeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        var deadline = DateTimeOffset.UtcNow + timeout;
        var last = new WindowsAppWindowDiscovery(
            WindowsAppWindowDiscoveryState.NotFound,
            null);
        do
        {
            cancellationToken.ThrowIfCancellationRequested();
            last = WindowsAppWindowSelector.Select(
                before,
                Snapshot());
            if (last.State == WindowsAppWindowDiscoveryState.Found)
                return last;
            await Task.Delay(
                    TimeSpan.FromMilliseconds(250),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);
        return last;
    }

    public bool IsAlive(WindowsAppWindowIdentity window) =>
        Snapshot().Any(value =>
            value.Identity == window);

    public bool Surface(WindowsAppWindowIdentity window)
    {
        if (!IsAlive(window))
            return false;
        if (IsIconic(window.Handle))
            _ = ShowWindowAsync(window.Handle, RestoreWindow);
        return SetForegroundWindow(window.Handle);
    }

    private static bool IsOfficialWindowsAppProcess(
        uint processId,
        int currentSession)
    {
        try
        {
            using var process = Process.GetProcessById(
                checked((int)processId));
            if (process.SessionId != currentSession ||
                !string.Equals(
                    process.ProcessName,
                    "Windows365",
                    StringComparison.OrdinalIgnoreCase))
                return false;
        }
        catch (Exception exception)
            when (exception is
                ArgumentException or
                InvalidOperationException or
                System.ComponentModel.Win32Exception)
        {
            return false;
        }

        var handle = OpenProcess(
            ProcessQueryLimitedInformation,
            false,
            processId);
        if (handle == IntPtr.Zero)
            return false;
        try
        {
            uint length = 0;
            var result = GetPackageFullName(
                handle,
                ref length,
                null);
            if (result != ErrorInsufficientBuffer ||
                length is <= 1 or > 4096)
                return false;
            var name = new StringBuilder(checked((int)length));
            result = GetPackageFullName(
                handle,
                ref length,
                name);
            if (result != 0)
                return false;
            var value = name.ToString();
            return value.StartsWith(
                       PackagePrefix,
                       StringComparison.OrdinalIgnoreCase) &&
                   value.EndsWith(
                       PublisherSuffix,
                       StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    private delegate bool EnumWindowsCallback(
        IntPtr window,
        IntPtr parameter);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(
        EnumWindowsCallback callback,
        IntPtr parameter);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(
        IntPtr window,
        out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindowAsync(
        IntPtr window,
        int command);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = false)]
    private static extern int GetPackageFullName(
        IntPtr process,
        ref uint packageFullNameLength,
        StringBuilder? packageFullName);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
