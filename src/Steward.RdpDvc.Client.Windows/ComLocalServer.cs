// Adapted from microsoft/rdp-dvc-plugin-samples Simple/Advanced .NET
// LocalServer patterns. Copyright (c) Microsoft Corporation.
// Licensed under the MIT License; see the preserved license in
// Steward.Transport.Rdp.Windows.
using System.Runtime.InteropServices;

namespace Steward.RdpDvc.Client.Windows;

internal sealed class ComServerLifetime
{
    private readonly TaskCompletionSource _shutdown =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _activePlugins;

    public void PluginCreated() =>
        Interlocked.Increment(ref _activePlugins);

    public void PluginTerminated()
    {
        var remaining = Interlocked.Decrement(ref _activePlugins);
        if (remaining < 0)
        {
            Interlocked.Exchange(ref _activePlugins, 0);
            return;
        }
        if (remaining == 0)
            _ = CompleteAfterIdleAsync();
    }

    public Task WaitForShutdownAsync(
        CancellationToken cancellationToken) =>
        _shutdown.Task.WaitAsync(cancellationToken);

    private async Task CompleteAfterIdleAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(2))
            .ConfigureAwait(false);
        if (Volatile.Read(ref _activePlugins) == 0)
            _shutdown.TrySetResult();
    }
}

[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
internal sealed class StewardClassFactory(
    Func<StewardDvcPlugin> createPlugin) : IClassFactory
{
    private static readonly Guid IUnknown =
        new("00000000-0000-0000-C000-000000000046");

    public int CreateInstance(
        IntPtr outer,
        ref Guid interfaceId,
        out IntPtr instance)
    {
        instance = IntPtr.Zero;
        if (outer != IntPtr.Zero)
            return HResults.NoAggregation;
        if (interfaceId != IUnknown &&
            interfaceId != typeof(IWTSPlugin).GUID)
            return HResults.NoInterface;
        try
        {
            var plugin = createPlugin();
            var unknown = Marshal.GetIUnknownForObject(plugin);
            try
            {
                var result = Marshal.QueryInterface(
                    unknown,
                    in interfaceId,
                    out instance);
                if (result < 0)
                    _ = plugin.Terminated();
                return result;
            }
            finally
            {
                Marshal.Release(unknown);
            }
        }
        catch (Exception exception)
        {
            return Marshal.GetHRForException(exception);
        }
    }

    public int LockServer(bool shouldLock)
    {
        _ = shouldLock;
        return HResults.Ok;
    }
}

internal sealed class ComLocalServer : IDisposable
{
    private const int CoInitMultiThreaded = 0;
    private const int ClsContextLocalServer = 4;
    private const int RegisterClassMultipleUse = 1;
    private const int RegisterClassSuspended = 4;
    private readonly Action<string> _log;
    private bool _initialized;
    private int _cookie;

    public ComLocalServer(
        IClassFactory factory,
        Action<string> log)
    {
        _log = log;
        var result = CoInitializeEx(IntPtr.Zero, CoInitMultiThreaded);
        if (result < 0)
            Marshal.ThrowExceptionForHR(result);
        _initialized = true;
        var clsid = Steward.Transport.Rdp.Windows
            .StewardRdpDvc.PluginClsid;
        result = CoRegisterClassObject(
            ref clsid,
            factory,
            ClsContextLocalServer,
            RegisterClassMultipleUse |
            RegisterClassSuspended,
            out _cookie);
        if (result < 0)
            Marshal.ThrowExceptionForHR(result);
        result = CoResumeClassObjects();
        if (result < 0)
            Marshal.ThrowExceptionForHR(result);
        _log("COM_CLASS_OBJECT_REGISTERED");
    }

    public void Dispose()
    {
        if (_cookie != 0)
        {
            _ = CoRevokeClassObject(_cookie);
            _cookie = 0;
        }
        if (_initialized)
        {
            CoUninitialize();
            _initialized = false;
        }
        _log("COM_CLASS_OBJECT_REVOKED");
    }

    [DllImport("Ole32.dll")]
    private static extern int CoInitializeEx(
        IntPtr reserved,
        int coInitialize);

    [DllImport("Ole32.dll")]
    private static extern void CoUninitialize();

    [DllImport("Ole32.dll")]
    private static extern int CoRegisterClassObject(
        ref Guid classId,
        [MarshalAs(UnmanagedType.IUnknown)] object factory,
        int context,
        int flags,
        out int cookie);

    [DllImport("Ole32.dll")]
    private static extern int CoResumeClassObjects();

    [DllImport("Ole32.dll")]
    private static extern int CoRevokeClassObject(int cookie);
}
