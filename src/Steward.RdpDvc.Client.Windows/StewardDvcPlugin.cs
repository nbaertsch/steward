using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.Client.Windows;

internal enum PluginLifecycleState
{
    Created,
    Initialized,
    Connected,
    Disconnected,
    Terminated
}

[ComVisible(true)]
[Guid("6F26730D-9E8C-4D94-A7F6-79A2ED5CB28D")]
[ClassInterface(ClassInterfaceType.None)]
internal sealed class StewardDvcPlugin(
    ClientDvcBroker broker,
    RdpDvcEvidencePublisherSession? evidence,
    Action<string> log,
    Action? onTerminated = null) :
    IWTSPlugin,
    IWTSListenerCallback,
    IEmbeddedDvcPlugin
{
    internal StewardDvcPlugin(
        ClientDvcBroker broker,
        Action<string> log,
        Action? onTerminated = null)
        : this(broker, null, log, onTerminated)
    {
    }

    private IWTSVirtualChannelManager? _manager;
    private IWTSListener? _listener;
    private readonly ConcurrentDictionary<
        ClientDvcAttachment,
        byte> _attachments = new();
    private PluginLifecycleState _state;

    internal PluginLifecycleState State => _state;

    public int Initialize(IWTSVirtualChannelManager channelManager)
    {
        if (channelManager is null)
            return HResults.InvalidArgument;
        if (_state != PluginLifecycleState.Created)
            return HResults.Unexpected;
        _manager = channelManager;
        var result = channelManager.CreateListener(
            StewardRdpDvc.ChannelName,
            0,
            this,
            out var listener);
        if (result < 0)
            return result;
        _listener = listener;
        _state = PluginLifecycleState.Initialized;
        try
        {
            if (evidence is not null)
                evidence.PublishAsync(
                            RdpDvcEvidencePublicationEvent
                                .StewardPluginInitialized)
                    .AsTask()
                    .GetAwaiter()
                    .GetResult();
        }
        catch (Exception exception)
        {
            log(
                $"COM_PLUGIN_EVIDENCE_REJECTED_{exception.GetType().Name}");
            return Marshal.GetHRForException(exception);
        }
        log("COM_PLUGIN_INITIALIZED");
        return HResults.Ok;
    }

    public int Connected()
    {
        if (_state is not (
            PluginLifecycleState.Initialized or
            PluginLifecycleState.Disconnected))
            return HResults.Unexpected;
        _state = PluginLifecycleState.Connected;
        log("RDP_CLIENT_CONNECTED");
        return HResults.Ok;
    }

    public int Disconnected(uint disconnectCode)
    {
        _ = disconnectCode;
        if (_state == PluginLifecycleState.Terminated)
            return HResults.Unexpected;
        _state = PluginLifecycleState.Disconnected;
        DisconnectOwnedAttachments();
        log("RDP_CLIENT_DISCONNECTED");
        return HResults.Ok;
    }

    public int Terminated()
    {
        if (_state == PluginLifecycleState.Terminated)
            return HResults.Ok;
        _listener = null;
        _manager = null;
        _state = PluginLifecycleState.Terminated;
        DisconnectOwnedAttachments();
        log("COM_PLUGIN_TERMINATED");
        onTerminated?.Invoke();
        return HResults.Ok;
    }

    public int OnNewChannelConnection(
        IWTSVirtualChannel channel,
        string data,
        out bool accept,
        out IWTSVirtualChannelCallback callback)
    {
        _ = data;
        accept = false;
        callback = null!;
        if (_state is PluginLifecycleState.Created or
            PluginLifecycleState.Terminated)
            return HResults.Unexpected;
        var clientChannel = new ComClientDvcChannel(channel);
        var attachment = evidence is null
            ? broker.TryAttach(clientChannel)
            : broker.TryAttach(clientChannel, evidence);
        if (attachment is null)
        {
            log("DVC_CHANNEL_REJECTED_CAPACITY");
            return HResults.Ok;
        }
        _attachments.TryAdd(attachment, 0);
        accept = true;
        callback = new StewardDvcChannelCallback(
            broker,
            attachment,
            log,
            () => _attachments.TryRemove(
                attachment,
                out _));
        return HResults.Ok;
    }

    private void DisconnectOwnedAttachments()
    {
        var attachments = _attachments.Keys.ToArray();
        foreach (var attachment in attachments)
            _attachments.TryRemove(attachment, out _);
        _ = broker.DisconnectAsync(attachments);
    }
}

[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
internal sealed class StewardDvcChannelCallback(
    ClientDvcBroker broker,
    ClientDvcAttachment attachment,
    Action<string> log,
    Action onClosed) : IWTSVirtualChannelCallback
{
    private int _closed;

    public int OnDataReceived(uint size, IntPtr buffer)
    {
        if (Volatile.Read(ref _closed) != 0)
            return HResults.Unexpected;
        if (size == 0 || buffer == IntPtr.Zero ||
            size >
            RdpDvcMessageCodec.MinimumEncodedSize +
            StewardRdpDvc.MaximumPayloadBytes)
            return HResults.InvalidArgument;
        try
        {
            var data = new byte[checked((int)size)];
            Marshal.Copy(buffer, data, 0, data.Length);
            log($"DVC_DATA_RECEIVED_{data.Length}");
            log(
                "DVC_DATA_PREFIX_" +
                Convert.ToHexString(data.AsSpan(0, Math.Min(8, data.Length))));
            if (!attachment.ReceiveFragment(data))
            {
                log("DVC_BACKPRESSURE_CLOSED");
                _ = CloseAsync();
                return HResults.Fail;
            }
            return HResults.Ok;
        }
        catch (Exception exception)
        {
            log($"DVC_DATA_REJECTED_{exception.GetType().Name}");
            _ = CloseAsync();
            return HResults.Fail;
        }
    }

    public int OnClose()
    {
        _ = CloseAsync();
        return HResults.Ok;
    }

    private async Task CloseAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
            return;
        try
        {
            await broker.DetachAsync(attachment)
                .ConfigureAwait(false);
        }
        finally
        {
            onClosed();
        }
    }
}

internal static class HResults
{
    internal const int Ok = 0;
    internal const int Fail = unchecked((int)0x80004005);
    internal const int NoInterface = unchecked((int)0x80004002);
    internal const int InvalidArgument = unchecked((int)0x80070057);
    internal const int Unexpected = unchecked((int)0x8000FFFF);
    internal const int NoAggregation = unchecked((int)0x80040110);
}
