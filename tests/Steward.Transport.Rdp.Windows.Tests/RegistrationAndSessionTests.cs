using Microsoft.Win32;
using System.ComponentModel;
using Steward.Transport.Rdp.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

public sealed class RegistrationAndSessionTests
{
    [Fact]
    public void Windows_app_ms_avd_is_not_a_headless_capability()
    {
        var capability =
            RdpDvcHeadlessCapability.WindowsAppMsAvd();

        Assert.False(capability.IsAvailable);
        Assert.Equal(
            HeadlessRdpCapabilityState.Unavailable,
            capability.State);
        Assert.Equal(
            "HEADLESS_MS_AVD_UNSUPPORTED_VISIBLE_ACTIVATION_REQUIRED",
            capability.Code);
    }

    [Fact]
    public void Isolated_desktop_is_a_headless_capability()
    {
        var capability =
            RdpDvcHeadlessCapability.WindowsAppIsolatedDesktop();

        Assert.True(capability.IsAvailable);
        Assert.Equal(
            HeadlessRdpCapabilityState.Available,
            capability.State);
        Assert.Equal(
            "HEADLESS_ISOLATED_DESKTOP_AVAILABLE",
            capability.Code);
    }

    [Fact]
    public void Registration_writes_and_verifies_only_exact_hkcu_entries()
    {
        var registry = new MemoryRegistry();
        registry.SetString(
            @"Software\Microsoft\Terminal Server Client\Default\AddIns\Other",
            "Name",
            "{00000000-0000-0000-0000-000000000001}");
        var registration = new RdpDvcPluginRegistration(
            registry,
            new FixedExecutableValidator(@"C:\Steward\Client.exe"));

        registration.Register(@"C:\ignored.exe");

        Assert.Equal(
            StewardRdpDvc.PluginClsid.ToString("B"),
            registry.ReadString(
                RdpDvcPluginRegistration.AddInKeyPath,
                "Name")?.Value);
        Assert.Equal(
            "\"C:\\Steward\\Client.exe\" -Embedding",
            registry.ReadString(
                RdpDvcPluginRegistration.LocalServerKeyPath,
                null)?.Value);
        Assert.Equal(
            RegistryValueKind.String,
            registry.ReadString(
                RdpDvcPluginRegistration.LocalServerKeyPath,
                null)?.Kind);
        var status = registration.GetStatus();
        Assert.True(status.Registered);
        Assert.True(status.ConfigurationValid);
        Assert.Equal(
            "DvcPluginRegisteredActivationPending",
            status.Code);

        registration.Unregister();

        Assert.NotNull(registry.ReadString(
            @"Software\Microsoft\Terminal Server Client\Default\AddIns\Other",
            "Name"));
        Assert.Null(registry.ReadString(
            RdpDvcPluginRegistration.AddInKeyPath,
            "Name"));
        Assert.Equal(
            "DvcPluginNotRegistered",
            registration.GetStatus().Code);
    }

    [Fact]
    public void Registration_status_rejects_partial_or_wrong_hkcu_shape()
    {
        var registry = new MemoryRegistry();
        registry.SetString(
            RdpDvcPluginRegistration.AddInKeyPath,
            "Name",
            "{00000000-0000-0000-0000-000000000001}");
        var registration = new RdpDvcPluginRegistration(
            registry,
            new FixedExecutableValidator(
                @"C:\Steward\Client.exe"));

        var status = registration.GetStatus();

        Assert.False(status.Registered);
        Assert.False(status.ConfigurationValid);
        Assert.Equal(
            "DvcRegistrationInvalid",
            status.Code);
    }

    [Fact]
    public void Registration_rolls_back_if_exact_readback_differs()
    {
        var registry = new MemoryRegistry
        {
            MutateWrites = true
        };
        var registration = new RdpDvcPluginRegistration(
            registry,
            new FixedExecutableValidator(@"C:\Steward\Client.exe"));

        Assert.Throws<InvalidOperationException>(
            () => registration.Register(@"C:\ignored.exe"));

        Assert.Null(registry.ReadString(
            RdpDvcPluginRegistration.AddInKeyPath,
            "Name"));
        Assert.Null(registry.ReadString(
            RdpDvcPluginRegistration.LocalServerKeyPath,
            null));
    }

    [Fact]
    public void Session_selection_is_exact_and_fails_closed_on_ambiguity()
    {
        var sessions = new[]
        {
            new RdpSessionDescriptor(
                2,
                RdpSessionConnectionState.Disconnected,
                true),
            new RdpSessionDescriptor(
                7,
                RdpSessionConnectionState.Active,
                true)
        };
        Assert.Equal(
            7,
            RdpSessionSelector.SelectExactActiveSession(sessions));
        Assert.Equal(
            7,
            RdpSessionSelector.SelectExactActiveSession(sessions, 7));

        var ambiguous = sessions.Append(
            new(
                8,
                RdpSessionConnectionState.Active,
                true)).ToArray();
        Assert.Throws<RdpSessionAmbiguityException>(
            () => RdpSessionSelector.SelectExactActiveSession(
                ambiguous));
    }

    [Fact]
    public async Task Reconnect_waits_for_session_change_but_not_ambiguity()
    {
        var channel = new EmptyWireChannel();
        var source = new SequencedSource(
            new InvalidOperationException("disconnected"),
            new RdpDvcWireConnection(channel, 9));
        var waiter = new ImmediateWaiter();
        await using var reconnecting =
            new RdpDvcReconnectingWireChannelSource(
                source,
                waiter);

        var opened = await reconnecting.OpenChannelAsync();

        Assert.Equal(9, opened.RdpSessionId);
        Assert.Equal(1, waiter.WaitCount);
        Assert.Equal(2, source.CallCount);

        await using var ambiguous =
            new RdpDvcReconnectingWireChannelSource(
                new SequencedSource(
                    new RdpSessionAmbiguityException("ambiguous")),
                new ImmediateWaiter());
        await Assert.ThrowsAsync<RdpSessionAmbiguityException>(
            () => ambiguous.OpenChannelAsync().AsTask());
    }

    [Fact]
    public async Task Reconnect_wait_honors_cancellation()
    {
        var source = new SequencedSource(
            new InvalidOperationException("disconnected"));
        await using var reconnecting =
            new RdpDvcReconnectingWireChannelSource(
                source,
                new BlockingWaiter());
        using var cancellation = new CancellationTokenSource(
            TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => reconnecting.OpenChannelAsync(
                    cancellation.Token)
                .AsTask());
    }

    [Fact]
    public async Task Reconnect_retries_incomplete_channel_open()
    {
        var source = new SequencedSource(
            new Win32Exception(31),
            new Win32Exception(996),
            new Win32Exception(1460),
            new Win32Exception(unchecked((int)0x80004005)),
            new RdpDvcWireConnection(new EmptyWireChannel(), 11));
        await using var reconnecting =
            new RdpDvcReconnectingWireChannelSource(
                source,
                new ImmediateWaiter());

        var opened = await reconnecting.OpenChannelAsync();

        Assert.Equal(11, opened.RdpSessionId);
        Assert.Equal(5, source.CallCount);
    }

    private sealed class MemoryRegistry : IUserRegistryStore
    {
        private readonly Dictionary<string, RegistryStringValue> _values =
            new(StringComparer.Ordinal);

        internal bool MutateWrites { get; init; }

        public void SetString(
            string keyPath,
            string? valueName,
            string value)
        {
            _values[Key(keyPath, valueName)] = new(
                MutateWrites ? value + "-changed" : value,
                RegistryValueKind.String);
        }

        public RegistryStringValue? ReadString(
            string keyPath,
            string? valueName) =>
            _values.GetValueOrDefault(Key(keyPath, valueName));

        public void DeleteKeyTree(string keyPath)
        {
            foreach (var key in _values.Keys
                         .Where(value =>
                             value.StartsWith(
                                 keyPath + "\0",
                                 StringComparison.Ordinal) ||
                             value.StartsWith(
                                 keyPath + "\\",
                                 StringComparison.Ordinal))
                         .ToArray())
                _values.Remove(key);
        }

        private static string Key(
            string keyPath,
            string? valueName) =>
            $"{keyPath}\0{valueName ?? string.Empty}";
    }

    private sealed class FixedExecutableValidator(string value) :
        IRdpDvcExecutableValidator
    {
        public string Validate(string executablePath)
        {
            _ = executablePath;
            return value;
        }
    }

    private sealed class SequencedSource(
        params object[] outcomes) : IRdpDvcWireChannelSource
    {
        private int _index;

        internal int CallCount => _index;

        public ValueTask<RdpDvcWireConnection> OpenChannelAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var outcome = outcomes[Math.Min(
                _index++,
                outcomes.Length - 1)];
            return outcome switch
            {
                Exception exception =>
                    ValueTask.FromException<RdpDvcWireConnection>(
                        exception),
                RdpDvcWireConnection connection =>
                    ValueTask.FromResult(connection),
                _ => throw new InvalidOperationException()
            };
        }
    }

    private sealed class ImmediateWaiter : IRdpSessionChangeWaiter
    {
        internal int WaitCount { get; private set; }

        public ValueTask WaitForChangeAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WaitCount++;
            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync() =>
            ValueTask.CompletedTask;
    }

    private sealed class BlockingWaiter : IRdpSessionChangeWaiter
    {
        public async ValueTask WaitForChangeAsync(
            CancellationToken cancellationToken = default) =>
            await Task.Delay(
                Timeout.InfiniteTimeSpan,
                cancellationToken);

        public ValueTask DisposeAsync() =>
            ValueTask.CompletedTask;
    }

    private sealed class EmptyWireChannel : IRdpDvcWireChannel
    {
        public ValueTask WritePduAsync(
            ReadOnlyMemory<byte> pdu,
            CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask<byte[]> ReadPduAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<byte[]>(
                new EndOfStreamException());

        public ValueTask DisposeAsync() =>
            ValueTask.CompletedTask;
    }
}
