using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Steward.DevBox.Windows;

internal sealed class WindowsAppIsolatedDesktopSession : IDisposable
{
    private readonly IWindowsAppIsolatedDesktopNative native;
    private readonly IDisposable desktop;
    private int disposed;

    internal WindowsAppIsolatedDesktopSession(
        IWindowsAppIsolatedDesktopNative native,
        IDisposable desktop,
        string desktopName,
        uint processId)
    {
        this.native = native;
        this.desktop = desktop;
        DesktopName = desktopName;
        ProcessId = processId;
    }

    public string DesktopName { get; }
    public uint ProcessId { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        try
        {
            native.TerminateProcess(ProcessId);
        }
        finally
        {
            desktop.Dispose();
        }
        GC.SuppressFinalize(this);
    }
}

internal sealed class WindowsAppIsolatedDesktopHost
{
    private readonly IWindowsAppIsolatedDesktopNative native;

    public WindowsAppIsolatedDesktopHost() :
        this(new WindowsAppIsolatedDesktopNative())
    {
    }

    internal WindowsAppIsolatedDesktopHost(
        IWindowsAppIsolatedDesktopNative native) =>
        this.native = native;

    public WindowsAppIsolatedDesktopSession Activate(Uri providerUri)
    {
        var (kind, _) =
            DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(providerUri);
        if (kind != DevBoxProviderRdpKind.WindowsAppResource)
            throw new InvalidDataException(
                "Only a validated provider-issued Windows App resource can be activated.");

        var existing = native.SnapshotWindowsAppProcesses();
        if (existing.Count != 0)
            throw new DevBoxRemoteViewerException(
                "WindowsAppIsolatedDesktopExistingProcess",
                "Windows App is already running, so isolated activation cannot be attempted.");
        var desktopName = "Steward.Rdp." + Guid.NewGuid().ToString("N");
        var desktop = native.CreateDesktop(desktopName);
        uint processId = 0;
        try
        {
            processId = native.ActivateProtocol(
                desktop,
                providerUri);
            if (processId == 0 || existing.Contains(processId))
                throw new DevBoxRemoteViewerException(
                    "WindowsAppIsolatedDesktopProcessReuse",
                    "Windows reused an existing Windows App process, so desktop isolation cannot be proven.");
            if (!native.IsProcessConfinedToDesktop(
                    processId,
                    desktopName,
                    TimeSpan.FromSeconds(10)))
                throw new DevBoxRemoteViewerException(
                    "WindowsAppIsolatedDesktopContainmentFailed",
                    "The Windows App process was not confined to the Steward desktop.");
            return new(
                native,
                desktop,
                desktopName,
                processId);
        }
        catch
        {
            try
            {
                if (processId != 0 && !existing.Contains(processId))
                    native.TerminateProcess(processId);
            }
            finally
            {
                desktop.Dispose();
            }
            throw;
        }
    }
}

internal interface IWindowsAppIsolatedDesktopNative
{
    IReadOnlySet<uint> SnapshotWindowsAppProcesses();
    IDisposable CreateDesktop(string name);
    uint ActivateProtocol(IDisposable desktop, Uri uri);
    bool IsProcessConfinedToDesktop(
        uint processId,
        string desktopName,
        TimeSpan timeout);
    void TerminateProcess(uint processId);
}

internal sealed class WindowsAppIsolatedDesktopNative :
    IWindowsAppIsolatedDesktopNative
{
    private const uint DesktopAllAccess = 0x000F01FF;
    private const uint ClsctxInprocServer = 0x1;
    private const int UserObjectName = 2;
    private const string WindowsAppAumid =
        "MicrosoftCorporationII.Windows365_8wekyb3d8bbwe!Windows365";

    public IReadOnlySet<uint> SnapshotWindowsAppProcesses()
    {
        var values = new HashSet<uint>();
        foreach (var process in Process.GetProcessesByName("Windows365"))
        {
            try
            {
                if (process.SessionId ==
                    Process.GetCurrentProcess().SessionId)
                    values.Add(checked((uint)process.Id));
            }
            catch (InvalidOperationException)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
        return values;
    }

    public IDisposable CreateDesktop(string name)
    {
        var handle = CreateDesktopW(
            name,
            IntPtr.Zero,
            IntPtr.Zero,
            0,
            DesktopAllAccess,
            IntPtr.Zero);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return new IsolatedDesktopHandle(name, handle);
    }

    public uint ActivateProtocol(IDisposable desktop, Uri uri)
    {
        if (desktop is not IsolatedDesktopHandle isolated)
            throw new ArgumentException(
                "The desktop handle is invalid.",
                nameof(desktop));
        uint processId = 0;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                if (!SetThreadDesktop(isolated.Handle))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error());
                processId = ActivateProtocolCore(uri);
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        })
        {
            IsBackground = true,
            Name = "Steward isolated Windows App activation"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null)
            throw failure;
        return processId;
    }

    public bool IsProcessConfinedToDesktop(
        uint processId,
        string desktopName,
        TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        do
        {
            try
            {
                using var process = Process.GetProcessById(
                    checked((int)processId));
                var names = process.Threads
                    .Cast<ProcessThread>()
                    .Select(thread => DesktopName(
                        GetThreadDesktop(
                            checked((uint)thread.Id))))
                    .Where(name => name is not null)
                    .ToArray();
                if (names.Length != 0)
                    return names.All(name =>
                        string.Equals(
                            name,
                            desktopName,
                            StringComparison.Ordinal));
            }
            catch (Exception exception)
                when (exception is
                    ArgumentException or
                    InvalidOperationException or
                    Win32Exception)
            {
                return false;
            }
            Thread.Sleep(100);
        }
        while (DateTimeOffset.UtcNow < deadline);
        return false;
    }

    public void TerminateProcess(uint processId)
    {
        try
        {
            using var process = Process.GetProcessById(
                checked((int)processId));
            process.Kill(entireProcessTree: true);
            process.WaitForExit(5000);
        }
        catch (ArgumentException)
        {
        }
    }

    private static uint ActivateProtocolCore(Uri uri)
    {
        var shellItemIid = typeof(IShellItem).GUID;
        Marshal.ThrowExceptionForHR(SHCreateItemFromParsingName(
            uri.OriginalString,
            IntPtr.Zero,
            in shellItemIid,
            out var shellItem));
        try
        {
            var shellItemArrayIid = typeof(IShellItemArray).GUID;
            Marshal.ThrowExceptionForHR(
                SHCreateShellItemArrayFromShellItem(
                    shellItem,
                    in shellItemArrayIid,
                    out var shellItemArray));
            try
            {
                var classId = new Guid(
                    "45BA127D-10A8-46EA-8AB7-56EA9078943C");
                var interfaceId =
                    typeof(IApplicationActivationManager).GUID;
                Marshal.ThrowExceptionForHR(CoCreateInstance(
                    in classId,
                    IntPtr.Zero,
                    ClsctxInprocServer,
                    in interfaceId,
                    out var activationManager));
                try
                {
                    Marshal.ThrowExceptionForHR(
                        activationManager.ActivateForProtocol(
                            WindowsAppAumid,
                            shellItemArray,
                            out var processId));
                    return processId;
                }
                finally
                {
                    Marshal.FinalReleaseComObject(
                        activationManager);
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(shellItemArray);
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(shellItem);
        }
    }

    private static string? DesktopName(IntPtr desktop)
    {
        if (desktop == IntPtr.Zero)
            return null;
        _ = GetUserObjectInformationW(
            desktop,
            UserObjectName,
            IntPtr.Zero,
            0,
            out var required);
        if (required is 0 or > 1024)
            return null;
        var buffer = Marshal.AllocHGlobal(checked((int)required));
        try
        {
            if (!GetUserObjectInformationW(
                    desktop,
                    UserObjectName,
                    buffer,
                    required,
                    out _))
                return null;
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private sealed class IsolatedDesktopHandle(
        string name,
        SafeDesktopHandle handle) : IDisposable
    {
        public string Name { get; } = name;
        public IntPtr Handle => handle.DangerousGetHandle();
        public void Dispose() => handle.Dispose();
    }

    private sealed class SafeDesktopHandle :
        SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeDesktopHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle() =>
            CloseDesktop(handle);
    }

    [ComImport]
    [Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
    }

    [ComImport]
    [Guid("B63EA76D-1F85-456F-A19C-48159EFA858B")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItemArray
    {
    }

    [ComImport]
    [Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IApplicationActivationManager
    {
        [PreserveSig]
        int ActivateApplication(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            [MarshalAs(UnmanagedType.LPWStr)] string? arguments,
            uint options,
            out uint processId);

        [PreserveSig]
        int ActivateForFile(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            IShellItemArray itemArray,
            [MarshalAs(UnmanagedType.LPWStr)] string? verb,
            out uint processId);

        [PreserveSig]
        int ActivateForProtocol(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            IShellItemArray itemArray,
            out uint processId);
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeDesktopHandle CreateDesktopW(
        string desktop,
        IntPtr device,
        IntPtr deviceMode,
        uint flags,
        uint desiredAccess,
        IntPtr securityAttributes);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadDesktop(IntPtr desktop);

    [DllImport("user32.dll")]
    private static extern IntPtr GetThreadDesktop(uint threadId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformationW(
        IntPtr objectHandle,
        int index,
        IntPtr information,
        uint length,
        out uint requiredLength);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDesktop(IntPtr desktop);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHCreateItemFromParsingName(
        string path,
        IntPtr bindContext,
        in Guid interfaceId,
        [MarshalAs(UnmanagedType.Interface)] out IShellItem shellItem);

    [DllImport("shell32.dll")]
    private static extern int SHCreateShellItemArrayFromShellItem(
        IShellItem shellItem,
        in Guid interfaceId,
        [MarshalAs(UnmanagedType.Interface)]
        out IShellItemArray shellItemArray);

    [DllImport("ole32.dll")]
    private static extern int CoCreateInstance(
        in Guid classId,
        IntPtr outer,
        uint context,
        in Guid interfaceId,
        [MarshalAs(UnmanagedType.Interface)]
        out IApplicationActivationManager activationManager);
}
