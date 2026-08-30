using Steward.Transport.Rdp.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

public sealed class RdpDvcSessionStateMachineTests
{
    [Fact]
    public void Take_control_can_transition_directly_from_connected_transport()
    {
        var machine = Connect(2);

        var controlled = machine.TakeControl(2);
        var released = machine.ReleaseControl(2);

        Assert.Equal(RdpDvcSessionState.Controlled, controlled.State);
        Assert.True(controlled.VisibleSurfaceAuthorized);
        Assert.Equal(
            RdpDvcSessionState.ConnectedTransport,
            released.State);
        Assert.False(released.VisibleSurfaceAuthorized);
    }

    [Fact]
    public void Lifecycle_preserves_one_transport_through_view_and_control()
    {
        var machine = Connect(generation: 3);

        var beforeView = machine.Snapshot;
        var viewing = machine.View(3);
        var controlled = machine.TakeControl(3);
        var released = machine.ReleaseControl(3);

        Assert.Equal(
            RdpDvcSessionState.Viewing,
            viewing.State);
        Assert.Equal(
            RdpDvcSessionState.Controlled,
            controlled.State);
        Assert.Equal(
            RdpDvcSessionState.ConnectedTransport,
            released.State);
        Assert.Equal(
            beforeView.ConnectionGeneration,
            released.ConnectionGeneration);
        Assert.True(released.DvcConnected);
        Assert.False(released.VisibleSurfaceAuthorized);
        Assert.Equal(
            "RDP_DVC_CONTROL_RELEASED_TRANSPORT_PRESERVED",
            released.Code);
    }

    [Fact]
    public void Take_control_rejects_a_different_connection_generation()
    {
        var machine = Connect(generation: 5);
        machine.View(5);

        var exception =
            Assert.Throws<RdpDvcSessionTransitionException>(
                () => machine.TakeControl(4));

        Assert.Equal(
            "RDP_DVC_CONNECTION_GENERATION_MISMATCH",
            exception.Code);
        Assert.Equal(
            RdpDvcSessionState.Viewing,
            machine.Snapshot.State);
    }

    [Fact]
    public void Closing_ui_returns_to_transport_without_disconnect()
    {
        var machine = Connect(generation: 8);
        machine.View(8);
        machine.TakeControl(8);

        var closed = machine.CloseVisibleSurface(8);

        Assert.Equal(
            RdpDvcSessionState.ConnectedTransport,
            closed.State);
        Assert.Equal(8, closed.ConnectionGeneration);
        Assert.True(closed.DvcConnected);
        Assert.False(closed.VisibleSurfaceAuthorized);
        Assert.Equal(
            "RDP_DVC_UI_CLOSED_TRANSPORT_PRESERVED",
            closed.Code);
    }

    [Fact]
    public void Visible_surface_before_view_is_a_fatal_headless_violation()
    {
        var machine = Connect(generation: 13);

        var exception =
            Assert.Throws<RdpHeadlessViolationException>(
                () => machine.ObserveVisibleSurface(13));

        Assert.Equal(
            "RDP_DVC_FATAL_UNEXPECTED_VISIBLE_SURFACE",
            exception.Code);
        Assert.Equal(
            RdpDvcSessionState.Failed,
            machine.Snapshot.State);
        Assert.False(machine.Snapshot.DvcConnected);
    }

    [Fact]
    public void Visible_surface_while_connecting_is_a_fatal_headless_violation()
    {
        var machine = new RdpDvcSessionStateMachine();
        machine.BeginResolving();
        machine.BeginConnectingHeadless();

        Assert.Throws<RdpHeadlessViolationException>(
            () => machine.ObserveVisibleSurface(1));

        Assert.Equal(
            RdpDvcSessionState.Failed,
            machine.Snapshot.State);
    }

    [Fact]
    public void Explicit_view_authorizes_visible_surface_for_same_generation()
    {
        var machine = Connect(generation: 21);
        machine.View(21);

        var observed = machine.ObserveVisibleSurface(21);

        Assert.Equal(
            RdpDvcSessionState.Viewing,
            observed.State);
        Assert.True(observed.DvcConnected);
        Assert.True(observed.VisibleSurfaceAuthorized);
    }

    [Fact]
    public void Reconnect_requires_a_new_verified_generation()
    {
        var machine = Connect(generation: 34);
        machine.BeginReconnecting(34);

        var sameGeneration =
            Assert.Throws<RdpDvcSessionTransitionException>(
                () => machine.ConfirmConnectedTransport(
                    VerifiedResult(34)));

        Assert.Equal(
            "RDP_DVC_CONNECTION_GENERATION_NOT_ADVANCED",
            sameGeneration.Code);
        Assert.Equal(
            RdpDvcSessionState.Reconnecting,
            machine.Snapshot.State);

        var reconnected =
            machine.ConfirmConnectedTransport(
                VerifiedResult(35));
        machine.BeginReconnecting(35);
        var disconnected = machine.Disconnect();

        Assert.Equal(
            RdpDvcSessionState.ConnectedTransport,
            reconnected.State);
        Assert.Equal(35, reconnected.ConnectionGeneration);
        Assert.True(reconnected.DvcConnected);
        Assert.Equal(
            RdpDvcSessionState.Disconnected,
            disconnected.State);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Disconnect_and_reconnect_are_valid_during_presentation(
        bool controlled)
    {
        var machine = Connect(40);
        machine.View(40);
        if (controlled)
            machine.TakeControl(40);

        var reconnecting = machine.BeginReconnecting(40);
        Assert.Equal(
            RdpDvcSessionState.Reconnecting,
            reconnecting.State);
        Assert.False(reconnecting.VisibleSurfaceAuthorized);
        machine.ConfirmConnectedTransport(VerifiedResult(41));
        machine.View(41);
        var disconnected = machine.Disconnect();

        Assert.Equal(
            RdpDvcSessionState.Disconnected,
            disconnected.State);
        Assert.False(disconnected.DvcConnected);
    }

    [Fact]
    public void Terminal_states_can_begin_a_fresh_resolution()
    {
        var disconnected = Connect(50);
        disconnected.Disconnect();
        Assert.Equal(
            RdpDvcSessionState.Resolving,
            disconnected.BeginResolving().State);

        var failed = Connect(60);
        failed.Fail("TEST_FAILURE");
        Assert.Equal(
            RdpDvcSessionState.Resolving,
            failed.BeginResolving().State);
    }

    [Fact]
    public void Connected_transport_rejects_unverified_configuration_only_result()
    {
        var machine = new RdpDvcSessionStateMachine();
        machine.BeginResolving();
        machine.BeginConnectingHeadless();
        var configurationOnly =
            RdCoreDvcContract.ValidateConfiguration(
                ValidRequest());

        var exception =
            Assert.Throws<RdpDvcSessionTransitionException>(
                () => machine.ConfirmConnectedTransport(
                    configurationOnly));

        Assert.Equal(
            "RDP_DVC_VERIFIED_EVIDENCE_REQUIRED",
            exception.Code);
        Assert.Equal(
            RdpDvcSessionState.ConnectingHeadless,
            machine.Snapshot.State);
    }

    private static RdpDvcSessionStateMachine Connect(
        long generation)
    {
        var machine = new RdpDvcSessionStateMachine();
        Assert.Equal(
            RdpDvcSessionState.Absent,
            machine.Snapshot.State);
        machine.BeginResolving();
        machine.BeginConnectingHeadless();
        machine.ConfirmConnectedTransport(
            VerifiedResult(generation));
        return machine;
    }

    private static RdCoreDvcConfigurationResult VerifiedResult(
        long generation)
    {
        var evidence = new RdCoreDvcEvidenceSequence(generation);
        evidence.Record(RdCoreDvcEvidenceEvent.RdCoreConnected);
        evidence.Record(RdCoreDvcEvidenceEvent.WtsPluginsLoaded);
        evidence.Record(
            RdCoreDvcEvidenceEvent.StewardComClassActivated);
        evidence.Record(
            RdCoreDvcEvidenceEvent.StewardPluginInitialized,
            StewardRdpDvc.AddInName,
            StewardRdpDvc.PluginClsid);
        evidence.Record(
            RdCoreDvcEvidenceEvent.StewardChannelOpened,
            channelName: StewardRdpDvc.ChannelName);
        evidence.Record(
            RdCoreDvcEvidenceEvent.DvcHmacAuthenticated);
        evidence.Record(
            RdCoreDvcEvidenceEvent.SecurePeerAuthenticated);
        return RdCoreDvcContract.ValidateEvidence(
            ValidRequest(),
            evidence);
    }

    private static RdCoreDvcConfigurationRequest ValidRequest() =>
        new(
            silentMode: true,
            allowThirdPartyPlugins: true,
            new(
                true,
                true,
                RdpDvcPluginRegistration
                    .RegisteredActivationPendingCode));
}
