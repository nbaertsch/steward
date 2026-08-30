using Steward.RdpDvc.Client.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

public sealed class ComLifecycleTests
{
    [Fact]
    public void Class_factory_rejects_aggregation()
    {
        var factory = new StewardClassFactory(
            () => throw new InvalidOperationException(
                "Factory must not run for aggregation."));
        var interfaceId =
            new Guid("A1230201-1439-4E62-A414-190D0AC3D40E");

        var result = factory.CreateInstance(
            new IntPtr(1),
            ref interfaceId,
            out var instance);

        Assert.Equal(HResults.NoAggregation, result);
        Assert.Equal(IntPtr.Zero, instance);
    }

    [Fact]
    public async Task Plugin_lifecycle_creates_stable_listener_and_terminates()
    {
        await using var broker =
            new ClientDvcBroker(_ => { });
        var plugin = new StewardDvcPlugin(broker, _ => { });
        var manager = new FakeManager();

        Assert.Equal(HResults.Ok, plugin.Initialize(manager));
        Assert.Equal(
            Steward.Transport.Rdp.Windows.StewardRdpDvc.ChannelName,
            manager.ChannelName);
        Assert.Equal(
            PluginLifecycleState.Initialized,
            plugin.State);
        Assert.Equal(HResults.Ok, plugin.Connected());
        Assert.Equal(
            PluginLifecycleState.Connected,
            plugin.State);
        Assert.Equal(HResults.Ok, plugin.Disconnected(4));
        Assert.Equal(
            PluginLifecycleState.Disconnected,
            plugin.State);
        Assert.Equal(HResults.Ok, plugin.Connected());
        Assert.Equal(HResults.Ok, plugin.Terminated());
        Assert.Equal(
            PluginLifecycleState.Terminated,
            plugin.State);
        Assert.Equal(
            HResults.Unexpected,
            plugin.Initialize(manager));
    }

    [Fact]
    public async Task Plugins_accept_concurrent_channels_and_disconnect_only_owned()
    {
        await using var broker =
            new ClientDvcBroker(_ => { });
        var first = new FakeClientChannel();
        var second = new FakeClientChannel();
        var third = new FakeClientChannel();
        var firstPlugin =
            new StewardDvcPlugin(broker, _ => { });
        var secondPlugin =
            new StewardDvcPlugin(broker, _ => { });
        Assert.Equal(
            HResults.Ok,
            firstPlugin.Initialize(new FakeManager()));
        Assert.Equal(
            HResults.Ok,
            secondPlugin.Initialize(new FakeManager()));
        Assert.Equal(HResults.Ok, firstPlugin.Connected());
        Assert.Equal(HResults.Ok, secondPlugin.Connected());

        Assert.Equal(
            HResults.Ok,
            firstPlugin.OnNewChannelConnection(
                first,
                string.Empty,
                out var firstAccepted,
                out _));
        Assert.Equal(
            HResults.Ok,
            secondPlugin.OnNewChannelConnection(
                second,
                string.Empty,
                out var secondAccepted,
                out _));
        Assert.Equal(
            HResults.Ok,
            firstPlugin.OnNewChannelConnection(
                third,
                string.Empty,
                out var thirdAccepted,
                out _));

        Assert.True(firstAccepted);
        Assert.True(secondAccepted);
        Assert.True(thirdAccepted);
        Assert.Equal(HResults.Ok, firstPlugin.Disconnected(1));
        Assert.Equal(1, first.CloseCount);
        Assert.Equal(1, third.CloseCount);
        Assert.Equal(0, second.CloseCount);
        Assert.Equal(HResults.Ok, secondPlugin.Disconnected(1));
        Assert.Equal(1, second.CloseCount);
    }

    [Fact]
    public async Task Broker_enforces_concurrent_attachment_bound()
    {
        await using var broker =
            new ClientDvcBroker(_ => { });
        var accepted = Enumerable.Range(
                0,
                ClientDvcBroker.MaximumConcurrentAttachments)
            .Select(_ =>
                broker.TryAttach(new FakeClientChannel()))
            .ToArray();

        Assert.All(accepted, Assert.NotNull);
        Assert.Null(
            broker.TryAttach(new FakeClientChannel()));
    }

    private sealed class FakeManager :
        IWTSVirtualChannelManager
    {
        internal string? ChannelName { get; private set; }

        public int CreateListener(
            string channelName,
            uint flags,
            IWTSListenerCallback listenerCallback,
            out IWTSListener listener)
        {
            _ = flags;
            _ = listenerCallback;
            ChannelName = channelName;
            listener = new FakeListener();
            return HResults.Ok;
        }
    }

    private sealed class FakeListener : IWTSListener
    {
        public int GetConfiguration(out object propertyBag)
        {
            propertyBag = new object();
            return HResults.Ok;
        }
    }

    private sealed class FakeClientChannel :
        IClientDvcChannel,
        IWTSVirtualChannel
    {
        public int CloseCount { get; private set; }

        public int Write(ReadOnlySpan<byte> pdu) => HResults.Ok;

        public int Write(
            uint size,
            IntPtr buffer,
            IntPtr reserved)
        {
            _ = size;
            _ = buffer;
            _ = reserved;
            return HResults.Ok;
        }

        public int Close()
        {
            CloseCount++;
            return HResults.Ok;
        }
    }
}
