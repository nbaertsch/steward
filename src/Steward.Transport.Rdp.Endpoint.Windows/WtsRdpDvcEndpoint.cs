// Portions of the WTS channel pattern are adapted from Microsoft's
// rdp-dvc-plugin-samples, Copyright (c) Microsoft Corporation, MIT License.
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace Steward.Transport.Rdp.Windows;

public enum RdpSessionConnectionState
{
    Active,
    Connected,
    Disconnected,
    Other
}

public sealed record RdpSessionDescriptor(
    int SessionId,
    RdpSessionConnectionState State,
    bool IsRemoteDesktop);

public interface IRdpSessionCatalog
{
    IReadOnlyList<RdpSessionDescriptor> GetSessions();
}

public sealed class RdpSessionAmbiguityException(string message) :
    InvalidOperationException(message);

public static class RdpSessionSelector
{
    public static int SelectExactActiveSession(
        IReadOnlyList<RdpSessionDescriptor> sessions,
        int? requestedSessionId = null)
    {
        var active = sessions
            .Where(session =>
                session.State == RdpSessionConnectionState.Active &&
                session.IsRemoteDesktop &&
                (!requestedSessionId.HasValue ||
                 session.SessionId == requestedSessionId.Value))
            .Select(session => session.SessionId)
            .Distinct()
            .ToArray();
        if (active.Length == 1)
            return active[0];
        if (active.Length == 0)
            throw new InvalidOperationException(
                requestedSessionId.HasValue
                    ? "The requested active RDP session is unavailable."
                    : "No active RDP user session is available.");
        throw new RdpSessionAmbiguityException(
            "Multiple active RDP sessions are ambiguous; refusing to choose.");
    }
}

public sealed class WtsRdpSessionCatalog : IRdpSessionCatalog
{
    public IReadOnlyList<RdpSessionDescriptor> GetSessions()
    {
        if (!WtsNativeMethods.WTSEnumerateSessions(
                IntPtr.Zero,
                0,
                1,
                out var buffer,
                out var count))
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "WTSEnumerateSessions failed.");
        try
        {
            var result = new List<RdpSessionDescriptor>(count);
            var size = Marshal.SizeOf<WtsNativeMethods.WtsSessionInfo>();
            for (var index = 0; index < count; index++)
            {
                var info = Marshal.PtrToStructure<
                    WtsNativeMethods.WtsSessionInfo>(
                    IntPtr.Add(buffer, checked(index * size)));
                var state = info.State switch
                {
                    WtsNativeMethods.WtsConnectState.Active =>
                        RdpSessionConnectionState.Active,
                    WtsNativeMethods.WtsConnectState.Connected =>
                        RdpSessionConnectionState.Connected,
                    WtsNativeMethods.WtsConnectState.Disconnected =>
                        RdpSessionConnectionState.Disconnected,
                    _ => RdpSessionConnectionState.Other
                };
                result.Add(new(
                    checked((int)info.SessionId),
                    state,
                    QueryProtocolType(info.SessionId) == 2));
            }
            return result;
        }
        finally
        {
            WtsNativeMethods.WTSFreeMemory(buffer);
        }
    }

    private static ushort QueryProtocolType(uint sessionId)
    {
        if (!WtsNativeMethods.WTSQuerySessionInformation(
                IntPtr.Zero,
                sessionId,
                WtsNativeMethods.WtsInfoClass.ClientProtocolType,
                out var buffer,
                out var bytes))
            return 0;
        try
        {
            return bytes >= sizeof(short)
                ? unchecked((ushort)Marshal.ReadInt16(buffer))
                : (ushort)0;
        }
        finally
        {
            WtsNativeMethods.WTSFreeMemory(buffer);
        }
    }
}

public enum RdpDvcEndpointEventKind
{
    SessionSelected,
    ChannelOpened,
    ChannelClosed,
    ReconnectWaiting
}

public sealed record RdpDvcEndpointEvent(
    RdpDvcEndpointEventKind Kind,
    int? SessionId,
    DateTimeOffset ObservedAtUtc);

public sealed class WtsRdpDvcWireChannelSource(
    IRdpSessionCatalog? sessionCatalog = null,
    int? requestedSessionId = null,
    Action<RdpDvcEndpointEvent>? onEvent = null) :
    IRdpDvcWireChannelSource
{
    private readonly IRdpSessionCatalog _sessionCatalog =
        sessionCatalog ?? new WtsRdpSessionCatalog();

    public ValueTask<RdpDvcWireConnection> OpenChannelAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var sessionId = RdpSessionSelector.SelectExactActiveSession(
            _sessionCatalog.GetSessions(),
            requestedSessionId);
        onEvent?.Invoke(new(
            RdpDvcEndpointEventKind.SessionSelected,
            sessionId,
            DateTimeOffset.UtcNow));
        var handle = WtsNativeMethods.WTSVirtualChannelOpenEx(
            checked((uint)sessionId),
            StewardRdpDvc.ChannelName,
            WtsNativeMethods.WtsChannelOptionDynamic |
            WtsNativeMethods.WtsChannelOptionDynamicPriorityHigh);
        if (handle == IntPtr.Zero)
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"WTSVirtualChannelOpenEx failed for session {sessionId}.");
        onEvent?.Invoke(new(
            RdpDvcEndpointEventKind.ChannelOpened,
            sessionId,
            DateTimeOffset.UtcNow));
        return ValueTask.FromResult(new RdpDvcWireConnection(
            new WtsRdpDvcWireChannel(
                handle,
                sessionId,
                onEvent),
            sessionId));
    }
}

internal sealed class WtsRdpDvcWireChannel(
    IntPtr handle,
    int sessionId,
    Action<RdpDvcEndpointEvent>? onEvent) : IRdpDvcWireChannel
{
    private const int ErrorTimeout = 1460;
    private const int ErrorIoIncomplete = 996;
    private const int ReadTimeoutMilliseconds = 500;
    private const int ReadBufferBytes = 64 * 1024;
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly BoundedChannelPduReassembler _reassembler =
        new(
            RdpDvcMessageCodec.MinimumEncodedSize +
            StewardRdpDvc.MaximumPayloadBytes);
    private int _reading;
    private int _disposed;
    private IntPtr _handle = handle;

    public async ValueTask WritePduAsync(
        ReadOnlyMemory<byte> pdu,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        if (pdu.Length <
                RdpDvcMessageCodec.MinimumEncodedSize ||
            pdu.Length >
                RdpDvcMessageCodec.MinimumEncodedSize +
                StewardRdpDvc.MaximumPayloadBytes)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The WTS write exceeds the Steward DVC PDU bound.");
        await _writeGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var data = pdu.ToArray();
            await Task.Run(
                    () =>
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var current = Volatile.Read(ref _handle);
                        if (current == IntPtr.Zero ||
                            !WtsNativeMethods.WTSVirtualChannelWrite(
                                current,
                                data,
                                checked((uint)data.Length),
                                out var written))
                            throw new Win32Exception(
                                Marshal.GetLastWin32Error(),
                                "WTSVirtualChannelWrite failed.");
                        if (written != data.Length)
                            throw new IOException(
                                "WTSVirtualChannelWrite was partial.");
                    },
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public async ValueTask<byte[]> ReadPduAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        if (Interlocked.Exchange(ref _reading, 1) != 0)
            throw new InvalidOperationException(
                "Only one WTS DVC reader is supported.");
        try
        {
            var buffer = new byte[ReadBufferBytes];
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var read = await Task.Run(
                        () => ReadOnce(buffer),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                    continue;
                var completed = _reassembler.PushReadBuffer(
                    buffer.AsSpan(0, read));
                if (completed is null)
                    continue;
                if (completed.Length <
                    RdpDvcMessageCodec.HeaderSize)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.Malformed,
                        "The WTS channel produced a truncated Steward PDU.");
                var expected = RdpDvcMessageCodec.GetEncodedLength(
                    completed,
                    StewardRdpDvc.MaximumPayloadBytes);
                if (completed.Length != expected)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.Malformed,
                        "The WTS channel PDU has trailing or missing bytes.");
                return completed;
            }
        }
        finally
        {
            Volatile.Write(ref _reading, 0);
        }
    }

    private int ReadOnce(byte[] buffer)
    {
        var current = Volatile.Read(ref _handle);
        if (current == IntPtr.Zero)
            throw new EndOfStreamException("The WTS DVC channel closed.");
        uint bytesRead = 0;
        if (WtsNativeMethods.WTSVirtualChannelRead(
                current,
                ReadTimeoutMilliseconds,
                buffer,
                checked((uint)buffer.Length),
                ref bytesRead))
        {
            if (bytesRead == 0)
                throw new EndOfStreamException(
                    "The WTS DVC channel returned end of stream.");
            return checked((int)bytesRead);
        }
        var error = Marshal.GetLastWin32Error();
        if (error is ErrorTimeout or ErrorIoIncomplete)
            return 0;
        throw new Win32Exception(
            error,
            "WTSVirtualChannelRead failed.");
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            var current = Interlocked.Exchange(
                ref _handle,
                IntPtr.Zero);
            if (current != IntPtr.Zero)
                _ = WtsNativeMethods.WTSVirtualChannelClose(current);
            _writeGate.Dispose();
            onEvent?.Invoke(new(
                RdpDvcEndpointEventKind.ChannelClosed,
                sessionId,
                DateTimeOffset.UtcNow));
        }
        return ValueTask.CompletedTask;
    }
}

public interface IRdpSessionChangeWaiter : IAsyncDisposable
{
    ValueTask WaitForChangeAsync(
        CancellationToken cancellationToken = default);
}

public sealed class PollingRdpSessionChangeWaiter(
    TimeSpan? interval = null) : IRdpSessionChangeWaiter
{
    private readonly TimeSpan _interval =
        interval ?? TimeSpan.FromSeconds(1);

    public async ValueTask WaitForChangeAsync(
        CancellationToken cancellationToken = default)
    {
        if (_interval <= TimeSpan.Zero ||
            _interval > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(interval));
        await Task.Delay(_interval, cancellationToken)
            .ConfigureAwait(false);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public static class RdpSessionChangeWaiter
{
    public static IRdpSessionChangeWaiter CreatePreferred()
    {
        try
        {
            return new WtsSessionNotificationWaiter();
        }
        catch (Win32Exception)
        {
            return new PollingRdpSessionChangeWaiter();
        }
    }
}

public sealed class WtsSessionNotificationWaiter :
    IRdpSessionChangeWaiter
{
    private const uint WmClose = 0x0010;
    private const uint WmDestroy = 0x0002;
    private const uint WmWtsSessionChange = 0x02B1;
    private const int NotifyForAllSessions = 1;
    private const int ErrorClassAlreadyExists = 1410;
    private const string WindowClass =
        "Steward.RdpDvc.SessionNotifications.v1";
    private static readonly ConcurrentDictionary<nint, WtsSessionNotificationWaiter>
        Instances = new();
    private readonly Channel<bool> _changes =
        Channel.CreateBounded<bool>(
            new BoundedChannelOptions(16)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = false,
                SingleWriter = true
            });
    private readonly Thread _thread;
    private readonly TaskCompletionSource<nint> _started =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly WtsNativeMethods.WtsNotificationNativeMethods.WindowProcedure
        _windowProcedure;
    private nint _window;
    private int _disposed;

    public WtsSessionNotificationWaiter()
    {
        _windowProcedure = WindowProc;
        _thread = new Thread(MessageLoop)
        {
            IsBackground = true,
            Name = "Steward RDP session notifications"
        };
        _thread.Start();
        try
        {
            _window = _started.Task.GetAwaiter().GetResult();
        }
        catch
        {
            _thread.Join(TimeSpan.FromSeconds(2));
            throw;
        }
    }

    public async ValueTask WaitForChangeAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        _ = await _changes.Reader.ReadAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private void MessageLoop()
    {
        nint window = 0;
        try
        {
            var windowClass = new WtsNativeMethods
                .WtsNotificationNativeMethods.WindowClass
            {
                WindowProcedure = Marshal.GetFunctionPointerForDelegate(
                    _windowProcedure),
                ClassName = WindowClass
            };
            var atom =
                WtsNativeMethods.WtsNotificationNativeMethods
                    .RegisterClass(ref windowClass);
            var error = Marshal.GetLastWin32Error();
            if (atom == 0 && error != ErrorClassAlreadyExists)
                throw new Win32Exception(
                    error,
                    "RegisterClassW failed for WTS notifications.");
            window = WtsNativeMethods.WtsNotificationNativeMethods
                .CreateWindowEx(
                0,
                WindowClass,
                string.Empty,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0);
            if (window == 0)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateWindowExW failed for WTS notifications.");
            Instances[window] = this;
            if (!WtsNativeMethods.WtsNotificationNativeMethods
                    .WTSRegisterSessionNotificationEx(
                        IntPtr.Zero,
                        window,
                        NotifyForAllSessions))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "WTS session notification registration failed.");
            _started.TrySetResult(window);

            while (WtsNativeMethods.WtsNotificationNativeMethods.GetMessage(
                       out var message,
                       0,
                       0,
                       0) > 0)
            {
                _ = WtsNativeMethods.WtsNotificationNativeMethods
                    .TranslateMessage(
                    ref message);
                _ = WtsNativeMethods.WtsNotificationNativeMethods
                    .DispatchMessage(
                    ref message);
            }
        }
        catch (Exception exception)
        {
            _started.TrySetException(exception);
        }
        finally
        {
            if (window != 0)
            {
                _ = WtsNativeMethods.WtsNotificationNativeMethods
                    .WTSUnRegisterSessionNotification(window);
                Instances.TryRemove(window, out _);
                _ = WtsNativeMethods.WtsNotificationNativeMethods
                    .DestroyWindow(window);
            }
            _changes.Writer.TryComplete();
        }
    }

    private nint WindowProc(
        nint window,
        uint message,
        nint wParam,
        nint lParam)
    {
        _ = wParam;
        _ = lParam;
        if (message == WmWtsSessionChange)
        {
            _changes.Writer.TryWrite(true);
            return 0;
        }
        if (message == WmClose)
        {
            _ = WtsNativeMethods.WtsNotificationNativeMethods
                .DestroyWindow(window);
            return 0;
        }
        if (message == WmDestroy)
        {
            WtsNativeMethods.WtsNotificationNativeMethods
                .PostQuitMessage(0);
            return 0;
        }
        return WtsNativeMethods.WtsNotificationNativeMethods
            .DefWindowProc(
            window,
            message,
            wParam,
            lParam);
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return ValueTask.CompletedTask;
        var window = Interlocked.Exchange(ref _window, 0);
        if (window != 0)
            _ = WtsNativeMethods.WtsNotificationNativeMethods
                .PostMessage(
                window,
                WmClose,
                0,
                0);
        _thread.Join(TimeSpan.FromSeconds(5));
        _changes.Writer.TryComplete();
        return ValueTask.CompletedTask;
    }
}

public sealed class RdpDvcReconnectingWireChannelSource(
    IRdpDvcWireChannelSource inner,
    IRdpSessionChangeWaiter? sessionChanges = null,
    Action<RdpDvcEndpointEvent>? onEvent = null) :
    IRdpDvcWireChannelSource,
    IAsyncDisposable
{
    private const int ErrorIoIncomplete = 996;
    private const int ErrorGeneralFailure = 31;
    private const int ErrorTimeout = 1460;
    private const int ErrorFail = unchecked((int)0x80004005);
    private static readonly TimeSpan ChannelOpenRetryDelay =
        TimeSpan.FromMilliseconds(250);
    private readonly IRdpSessionChangeWaiter _sessionChanges =
        sessionChanges ?? RdpSessionChangeWaiter.CreatePreferred();

    public async ValueTask<RdpDvcWireConnection> OpenChannelAsync(
        CancellationToken cancellationToken = default)
    {
        while (true)
        {
            try
            {
                return await inner.OpenChannelAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException exception)
                when (exception is not RdpSessionAmbiguityException)
            {
                onEvent?.Invoke(new(
                    RdpDvcEndpointEventKind.ReconnectWaiting,
                    null,
                    DateTimeOffset.UtcNow));
                await _sessionChanges.WaitForChangeAsync(
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Win32Exception exception)
                when (exception.NativeErrorCode is
                    ErrorIoIncomplete or
                    ErrorGeneralFailure or
                    ErrorTimeout or
                    ErrorFail)
            {
                onEvent?.Invoke(new(
                    RdpDvcEndpointEventKind.ReconnectWaiting,
                    null,
                    DateTimeOffset.UtcNow));
                await Task.Delay(
                        ChannelOpenRetryDelay,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    public ValueTask DisposeAsync() =>
        _sessionChanges.DisposeAsync();
}

internal static class WtsNativeMethods
{
    internal const uint WtsChannelOptionDynamic = 0x00000001;
    internal const uint WtsChannelOptionDynamicPriorityHigh = 0x00000004;

    internal enum WtsConnectState
    {
        Active,
        Connected,
        ConnectQuery,
        Shadow,
        Disconnected,
        Idle,
        Listen,
        Reset,
        Down,
        Init
    }

    internal static class WtsNotificationNativeMethods
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate nint WindowProcedure(
            nint window,
            uint message,
            nint wParam,
            nint lParam);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WindowClass
        {
            internal uint Style;
            internal nint WindowProcedure;
            internal int ClassExtra;
            internal int WindowExtra;
            internal nint Instance;
            internal nint Icon;
            internal nint Cursor;
            internal nint Background;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string? MenuName;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string? ClassName;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Message
        {
            internal nint Window;
            internal uint Value;
            internal nuint WParam;
            internal nint LParam;
            internal uint Time;
            internal Point Location;
            internal uint Private;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Point
        {
            internal int X;
            internal int Y;
        }

        [DllImport(
            "user32.dll",
            EntryPoint = "RegisterClassW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        internal static extern ushort RegisterClass(ref WindowClass windowClass);

        [DllImport(
            "user32.dll",
            EntryPoint = "CreateWindowExW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        internal static extern nint CreateWindowEx(
            uint extendedStyle,
            string className,
            string windowName,
            uint style,
            int x,
            int y,
            int width,
            int height,
            nint parent,
            nint menu,
            nint instance,
            nint parameter);

        [DllImport(
            "user32.dll",
            EntryPoint = "GetMessageW",
            SetLastError = true)]
        internal static extern int GetMessage(
            out Message message,
            nint window,
            uint minimum,
            uint maximum);

        [DllImport("user32.dll", EntryPoint = "TranslateMessage")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TranslateMessage(ref Message message);

        [DllImport("user32.dll", EntryPoint = "DispatchMessageW")]
        internal static extern nint DispatchMessage(ref Message message);

        [DllImport("user32.dll", EntryPoint = "DefWindowProcW")]
        internal static extern nint DefWindowProc(
            nint window,
            uint message,
            nint wParam,
            nint lParam);

        [DllImport("user32.dll", EntryPoint = "DestroyWindow")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DestroyWindow(nint window);

        [DllImport("user32.dll", EntryPoint = "PostMessageW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool PostMessage(
            nint window,
            uint message,
            nint wParam,
            nint lParam);

        [DllImport("user32.dll")]
        internal static extern void PostQuitMessage(int exitCode);

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSRegisterSessionNotificationEx(
            IntPtr server,
            nint window,
            int flags);

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSUnRegisterSessionNotification(
            nint window);
    }

    internal enum WtsInfoClass
    {
        InitialProgram,
        ApplicationName,
        WorkingDirectory,
        OemId,
        SessionId,
        UserName,
        WinStationName,
        DomainName,
        ConnectState,
        ClientBuildNumber,
        ClientName,
        ClientDirectory,
        ClientProductId,
        ClientHardwareId,
        ClientAddress,
        ClientDisplay,
        ClientProtocolType
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WtsSessionInfo
    {
        internal uint SessionId;
        internal IntPtr WinStationName;
        internal WtsConnectState State;
    }

    [DllImport(
        "Wtsapi32.dll",
        EntryPoint = "WTSEnumerateSessionsW",
        SetLastError = true,
        CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSEnumerateSessions(
        IntPtr server,
        int reserved,
        int version,
        out IntPtr sessionInfo,
        out int count);

    [DllImport(
        "Wtsapi32.dll",
        EntryPoint = "WTSQuerySessionInformationW",
        SetLastError = true,
        CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSQuerySessionInformation(
        IntPtr server,
        uint sessionId,
        WtsInfoClass infoClass,
        out IntPtr buffer,
        out uint bytesReturned);

    [DllImport("Wtsapi32.dll")]
    internal static extern void WTSFreeMemory(IntPtr memory);

    [DllImport(
        "Wtsapi32.dll",
        SetLastError = true,
        CharSet = CharSet.Ansi)]
    internal static extern IntPtr WTSVirtualChannelOpenEx(
        uint sessionId,
        [MarshalAs(UnmanagedType.LPStr)] string virtualName,
        uint flags);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSVirtualChannelRead(
        IntPtr channel,
        uint timeout,
        byte[] buffer,
        uint bufferSize,
        ref uint bytesRead);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSVirtualChannelWrite(
        IntPtr channel,
        byte[] buffer,
        uint length,
        out uint bytesWritten);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSVirtualChannelClose(IntPtr channel);
}
