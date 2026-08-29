using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Steward.Application;
using Steward.Cli;
using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.Desktop.Windows;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Providers.Abstractions;
using Steward.Terminal.Abstractions;
using Steward.Transport.Rdp.Windows;

namespace Steward.Desktop.Windows.Tests;

public sealed class DesktopLogicTests
{
    private static readonly HostId Host = HostId.New();
    private static readonly PoolId Pool = PoolId.New();
    private static readonly NodeIncarnationId Node = NodeIncarnationId.New();

    [Fact]
    public void View_model_reduction_keeps_newest_snapshot()
    {
        var first = Snapshot(4);
        var stale = Snapshot(3);
        var next = Snapshot(5);

        Assert.Same(first, DesktopProjection.Reduce(first, stale));
        Assert.Same(next, DesktopProjection.Reduce(first, next));
    }

    [Fact]
    public void Projection_preserves_complete_discovered_pool_policy()
    {
        var endpoint = new Uri(
            "https://center.test.devcenter.azure.com/");
        var inventory = new DevBoxInventory(
            1,
            DevBoxIdentityConstants.ContextName,
            Guid.NewGuid().ToString(),
            "user@example.test",
            [new(
                1,
                Guid.NewGuid().ToString(),
                endpoint,
                "project",
                "Project",
                "description",
                3,
                ["WriteDevBoxesAsDeveloper", "ReadRemoteConnectionsAsDeveloper"],
                [],
                true,
                false,
                true)],
            [new(
                1,
                endpoint,
                "project",
                "pool",
                "westus",
                "Healthy",
                "Windows",
                "Enabled",
                "sku",
                8,
                32,
                256,
                "image",
                "1",
                "build",
                DateTimeOffset.UnixEpoch,
                "Enabled",
                new(1, "Enabled", 5),
                false)],
            []);
        var registration = new PoolRegistration(
            new(Pool, 1, 10, TimeSpan.FromMinutes(90), TimeSpan.FromDays(7)),
            new("azure-dev-box", "project", "pool"));

        var result = DesktopProjection.Create(
            1,
            Doctor(),
            Orchestration(),
            TerminalPolicy(),
            Identity(),
            true,
            inventory,
            [registration],
            [],
            [],
            Operations());

        var value = Assert.Single(result.Pools);
        Assert.True(value.PermissionEligible);
        Assert.True(value.CanReadRemoteConnections);
        Assert.Equal(8, value.Cpu);
        Assert.Equal(32, value.RamGb);
        Assert.Equal(256, value.DiskGb);
        Assert.Equal(1, value.WarmMinimum);
        Assert.Equal(10, value.HardMaximum);
        Assert.Equal(TimeSpan.FromMinutes(90), value.IdleTimeout);
        Assert.Equal(TimeSpan.FromDays(7), value.StoppedRetention);
    }

    [Fact]
    public void Capability_and_state_gate_context_commands()
    {
        var node = NodeView(PoolMemberState.Stopped);

        Assert.True(CapabilityGate.Node(
            node,
            NodeCommand.Start,
            Orchestration(),
            TerminalPolicy(),
            true).Enabled);
        Assert.False(CapabilityGate.Node(
            node,
            NodeCommand.Drain,
            Orchestration(),
            TerminalPolicy(),
            true).Enabled);
        Assert.False(CapabilityGate.Node(
            node,
            NodeCommand.Reconnect,
            Orchestration(),
            TerminalPolicy(),
            true).Enabled);
    }

    [Fact]
    public void Stale_refresh_cannot_publish()
    {
        var sequence = new RefreshSequence();
        var first = sequence.Begin();
        var second = sequence.Begin();
        var published = 0;

        Assert.False(sequence.TryPublish(first, 1, value => published = value));
        Assert.True(sequence.TryPublish(second, 2, value => published = value));
        Assert.Equal(2, published);
    }

    [Fact]
    public void Destructive_confirmation_names_fenced_host_and_loss()
    {
        var attempt = TaskAttemptId.New();
        var node = NodeView(PoolMemberState.Assigned) with
        {
            AssignedAttemptCount = 1,
            AssignedAttempts = [attempt],
            IncompletePortableObjects = 2
        };

        var value = DestructiveConfirmationFactory.Create(
            node,
            NodeCommand.Delete);

        Assert.True(value.ForceRequired);
        Assert.Contains(Host.ToString(), value.Message, StringComparison.Ordinal);
        Assert.Contains(Node.ToString(), value.Message, StringComparison.Ordinal);
        Assert.Contains(attempt.ToString(), value.Message, StringComparison.Ordinal);
        Assert.Contains("2", value.Message, StringComparison.Ordinal);
        Assert.False(DestructiveConfirmationFactory.Matches(value, "yes"));
        Assert.True(DestructiveConfirmationFactory.Matches(value, "box"));
    }

    [Fact]
    public void External_remote_viewer_requires_running_permitted_devbox()
    {
        var unavailable = CapabilityGate.Node(
            NodeView(PoolMemberState.Warm),
            NodeCommand.OpenRemoteViewer,
            Orchestration(),
            TerminalPolicy(),
            true);
        var available = CapabilityGate.Node(
            NodeView(PoolMemberState.Warm) with
            {
                CanReadRemoteConnections = true,
                DevBox = DevBox("Running")
            },
            NodeCommand.OpenRemoteViewer,
            Orchestration(),
            TerminalPolicy(),
            true);

        Assert.False(unavailable.Enabled);
        Assert.True(available.Enabled);
    }

    [Fact]
    public void External_broker_control_tracks_take_release_and_fullscreen_evidence()
    {
        var state = ExternalViewerInteractionReducer.Reduce(
            ExternalViewerInteractionState.Initial,
            ExternalViewerInteractionAction.BrokerWindowVisible,
            fullscreenLaunchProven: true);

        Assert.True(state.BrokerWindowAvailable);
        Assert.True(state.FullscreenLaunchProven);
        Assert.Equal(
            ExternalViewerFocusTarget.WindowsApp,
            state.LastFocusTarget);

        state = ExternalViewerInteractionReducer.Reduce(
            state,
            ExternalViewerInteractionAction.ReleaseControl);
        Assert.Equal(
            ExternalViewerFocusTarget.Steward,
            state.LastFocusTarget);

        state = ExternalViewerInteractionReducer.Reduce(
            state,
            ExternalViewerInteractionAction.TakeControl);
        Assert.Equal(
            ExternalViewerFocusTarget.WindowsApp,
            state.LastFocusTarget);

        state = ExternalViewerInteractionReducer.Reduce(
            state,
            ExternalViewerInteractionAction.BrokerWindowClosed);
        Assert.False(state.BrokerWindowAvailable);
        Assert.Equal(
            ExternalViewerFocusTarget.Steward,
            state.LastFocusTarget);
    }

    [Fact]
    public async Task Desktop_startup_only_requests_status()
    {
        var host = new RecordingConnectionHostGateway();
        var identity = new FakeConnectionIdentityService(
            ConnectionIdentity(
                DevBoxConnectionIdentityOutcome.InteractionRequired));

        var result = await new ConnectionHostStartupProbe(
                host,
                identity)
            .ProbeAsync(CancellationToken.None);

        Assert.Equal(
            [ConnectionHostOperation.Status],
            host.Operations);
        Assert.Equal(
            DevBoxConnectionIdentityOutcome.InteractionRequired,
            result.Identity.Outcome);
        Assert.Null(result.Host.Status);
    }

    [Theory]
    [InlineData(
        DevBoxConnectionIdentityOutcome.Ready,
        ConnectionReadinessState.Ready)]
    [InlineData(
        DevBoxConnectionIdentityOutcome.InteractionRequired,
        ConnectionReadinessState.Pending)]
    [InlineData(
        DevBoxConnectionIdentityOutcome.AccountMismatch,
        ConnectionReadinessState.Failed)]
    public void Connection_identity_states_are_explicit(
        DevBoxConnectionIdentityOutcome outcome,
        ConnectionReadinessState expected)
    {
        var presentation = ConnectionHostPresentation.Create(
            ConnectionResult(),
            ConnectionIdentity(outcome),
            connectConfigured: true);

        Assert.Equal(expected, presentation.Readiness[0].State);
        Assert.Contains(
            outcome.ToString(),
            presentation.StatusText,
            StringComparison.Ordinal);
        Assert.Equal(
            outcome == DevBoxConnectionIdentityOutcome.Ready,
            presentation.Resolve.Enabled);
    }

    [Fact]
    public void View_control_and_fullscreen_are_capability_gated()
    {
        var unverified = ConnectionHostPresentation.Create(
            ConnectionResult(Status(
                generation: 41,
                dvcConnected: true,
                viewSupported: false,
                controlSupported: false)),
            ConnectionIdentity(DevBoxConnectionIdentityOutcome.Ready),
            connectConfigured: true);

        Assert.False(unverified.View.Enabled);
        Assert.False(unverified.TakeControl.Enabled);
        Assert.False(unverified.Fullscreen.Enabled);
        Assert.Contains(
            "verified",
            unverified.View.Reason!,
            StringComparison.OrdinalIgnoreCase);

        var verified = ConnectionHostPresentation.Create(
            ConnectionResult(Status(
                generation: 41,
                dvcConnected: true,
                viewSupported: true,
                controlSupported: true)),
            ConnectionIdentity(DevBoxConnectionIdentityOutcome.Ready),
            connectConfigured: true);

        Assert.True(verified.View.Enabled);
        Assert.True(verified.Fullscreen.Enabled);
        Assert.False(verified.TakeControl.Enabled);
        Assert.Contains(
            "view first",
            verified.TakeControl.Reason!,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Same_connection_commands_bind_the_generation()
    {
        var generation = 8675309L;
        var view = ConnectionHostPipeGateway.CreateCommand(
            ConnectionHostOperation.View,
            "connection",
            connectionGeneration: generation);
        var control = ConnectionHostPipeGateway.CreateCommand(
            ConnectionHostOperation.TakeControl,
            "connection",
            connectionGeneration: generation);

        Assert.Equal(generation, view.ConnectionGeneration);
        Assert.Equal(generation, control.ConnectionGeneration);
        Assert.Equal("connection", view.ConnectionId);
        Assert.Null(view.ProviderResource);
        Assert.Null(view.AuthorizationToken);
    }

    [Fact]
    public void Status_rendering_orders_readiness_and_hides_secrets()
    {
        var presentation = ConnectionHostPresentation.Create(
            ConnectionResult(Status(
                generation: 17,
                dvcConnected: true,
                viewSupported: true,
                controlSupported: true)),
            ConnectionIdentity(DevBoxConnectionIdentityOutcome.Ready),
            connectConfigured: true);

        Assert.Equal(
            Enumerable.Range(1, 7),
            presentation.Readiness.Select(value => value.Order));
        Assert.Contains(
            "Generation: 17",
            presentation.StatusText,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "ms-avd:",
            presentation.StatusText,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "token",
            presentation.StatusText,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Advanced_fallback_cannot_become_transport_evidence()
    {
        var connection = ConnectionResult(Status(
            generation: 9,
            dvcConnected: true,
            viewSupported: true,
            controlSupported: true));
        var initial = new ConnectionViewerEvidenceState(
            connection,
            null);

        var observed = initial.ObserveAdvancedFallback(
            "WindowsAppWindowVisible",
            DateTimeOffset.UtcNow);

        Assert.Same(connection, observed.ConnectionHost);
        Assert.NotNull(observed.AdvancedFallback);
        Assert.False(observed.AdvancedFallback!.IsTransportEvidence);
    }

    [Fact]
    public void Terminal_gate_enforces_lease_and_elevation()
    {
        var node = NodeView(PoolMemberState.Warm);
        var policy = TerminalPolicy();

        Assert.True(TerminalGate.Evaluate(
            policy,
            node,
            @"C:\work",
            TimeSpan.FromMinutes(30),
            false).Enabled);
        Assert.Equal(
            "TerminalLeaseDenied",
            TerminalGate.Evaluate(
                policy,
                node,
                @"C:\work",
                TimeSpan.FromHours(1),
                false).Code);
        Assert.Equal(
            "TerminalElevationUnavailable",
            TerminalGate.Evaluate(
                policy with { ElevatedHosts = [Host] },
                node,
                @"C:\work",
                TimeSpan.FromMinutes(30),
                true).Code);
    }

    [Fact]
    public async Task Typed_and_compatibility_clients_use_same_fenced_route()
    {
        var handler = new RouteHandler();
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://127.0.0.1:5112/")
        };
        var raw = new ControlClient(http, new TokenProvider());
        var typed = new StewardControlClient(raw);

        _ = await raw.StartHostAsync(
            Host,
            expectedIncarnation: Node);
        _ = await typed.StartHostAsync(Host, Node);

        Assert.Equal(2, handler.Paths.Count);
        Assert.Equal(handler.Paths[0], handler.Paths[1]);
        Assert.Equal(
            "/" + ControlRoutes.HostAction(
                Host,
                "start",
                expectedIncarnation: Node),
            handler.Paths[0]);
    }

    [Fact]
    public async Task Typed_terminal_client_reads_http_and_wire_contracts()
    {
        var now = DateTimeOffset.UtcNow;
        var authority = new TerminalAuthority(
            TerminalContractLimits.SchemaVersion,
            TerminalSessionId.New(),
            Host,
            Node,
            @"TEST\user",
            @"C:\work",
            null,
            now,
            now,
            now.AddMinutes(30),
            TimeSpan.FromMinutes(30),
            1024,
            4096,
            TerminalTranscriptMode.Metadata,
            0,
            TerminalFileTransferCapabilities.None,
            false,
            false,
            0,
            TimeSpan.FromMinutes(30),
            4096);
        var snapshot = new TerminalSessionSnapshot(
            authority.SessionId,
            TerminalSessionState.Open,
            2,
            Host,
            Node,
            authority.Actor,
            authority.WorkspaceRoot,
            null,
            authority.ExpiresAt,
            0,
            0,
            0,
            0,
            string.Empty,
            string.Empty,
            TerminalTranscriptMode.Metadata,
            0,
            false,
            false,
            null,
            42,
            100,
            false,
            "virtual-service-account",
            null);
        var handler = new QueueResponseHandler(
            JsonContent.Create(authority, options: ServerJson()),
            JsonContent.Create(new TerminalWireResponse(
                "request",
                "ok",
                TerminalWireCodec.Element(snapshot),
                [],
                null),
                options: ServerJson()));
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://127.0.0.1:5112/")
        };
        var client = new StewardControlClient(
            new ControlClient(http, new TokenProvider()));

        var issued = await client.IssueTerminalAuthorityAsync(
            new(
                Host,
                Node,
                authority.Actor,
                authority.WorkspaceRoot,
                null,
                TimeSpan.FromMinutes(30)));
        var opened = await client.OpenTerminalAsync(
            new(
                TerminalContractLimits.SchemaVersion,
                "request",
                authority,
                TerminalShellKind.PowerShell,
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ["-NoLogo"],
                authority.WorkspaceRoot,
                120,
                30));

        Assert.Equal(authority.SessionId, issued.SessionId);
        Assert.Equal(Host, issued.HostId);
        Assert.Equal(Node, issued.NodeIncarnationId);
        Assert.Equal(TerminalSessionState.Open, opened.Snapshot?.State);
    }

    private static DesktopSnapshot Snapshot(long sequence) =>
        DesktopProjection.Create(
            sequence,
            Doctor(),
            Orchestration(),
            TerminalPolicy(),
            Identity(),
            true,
            null,
            [],
            [],
            [],
            Operations());

    private static ControlDoctorStatus Doctor() =>
        new(true, 3, "wal", true, "ok", @"C:\control.db");

    private static ControlOrchestrationStatus Orchestration() =>
        new(
            true,
            1,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            []);

    private static TerminalPolicyStatus TerminalPolicy() =>
        new(
            true,
            @"TEST\user",
            [Host],
            [@"C:\work"],
            [],
            TimeSpan.FromMinutes(30),
            1024,
            4096);

    private static DevBoxIdentityStatus Identity() =>
        new(
            1,
            DevBoxIdentityConstants.ContextName,
            false,
            null,
            null,
            null,
            null);

    private static OperationsSnapshot Operations() =>
        new(
            DateTimeOffset.UtcNow,
            [],
            [],
            [],
            [],
            [],
            [],
            []);

    private static DevBoxConnectionIdentityStatus ConnectionIdentity(
        DevBoxConnectionIdentityOutcome outcome) =>
        new(
            DevBoxConnectionIdentityConstants.CurrentVersion,
            DevBoxConnectionIdentityConstants.ContextName,
            outcome,
            outcome == DevBoxConnectionIdentityOutcome.Ready,
            outcome == DevBoxConnectionIdentityOutcome.Ready
                ? Guid.NewGuid().ToString()
                : null,
            outcome == DevBoxConnectionIdentityOutcome.Ready
                ? "user@example.test"
                : null,
            outcome == DevBoxConnectionIdentityOutcome.Ready
                ? DateTimeOffset.UtcNow.AddHours(1)
                : null,
            outcome == DevBoxConnectionIdentityOutcome.InteractionRequired
                ? "Explicit native WAM connection enrollment is required."
                : outcome == DevBoxConnectionIdentityOutcome.AccountMismatch
                    ? "The Windows App account does not match devbox/default."
                    : null);

    private static ConnectionHostStatus Status(
        long generation,
        bool dvcConnected,
        bool viewSupported,
        bool controlSupported,
        RdpDvcSessionState state =
            RdpDvcSessionState.ConnectedTransport) =>
        new(
            ConnectionHostProtocol.CurrentVersion,
            "connection",
            state,
            generation,
            dvcConnected,
            viewSupported,
            controlSupported,
            "RDP_DVC_CONNECTED_TRANSPORT",
            DateTimeOffset.UtcNow);

    private static ConnectionHostCommandResult ConnectionResult(
        ConnectionHostStatus? status = null) =>
        new(
            true,
            true,
            "CONNECTION_HOST_STATUS",
            status);

    private static NodeViewModel NodeView(PoolMemberState state) =>
        new(
            Host,
            Pool,
            Node,
            "box",
            state,
            true,
            "direct/1",
            new ResourceRequirements(
                cpuCores: 8,
                memoryBytes: 32L * 1024 * 1024 * 1024),
            ["terminal"],
            0,
            [],
            false,
            0,
            0,
            10,
            "node.task-running.v1",
            DateTimeOffset.UtcNow,
            null,
            new("azure-dev-box", "project", "pool"),
            false);

    private static DevBoxMemberDetails DevBox(string powerState) =>
        new(
            1,
            new Uri("https://center.test.devcenter.azure.com/"),
            "project",
            "box",
            "pool",
            "westus",
            "Succeeded",
            powerState,
            "Windows",
            "Enabled",
            "sku",
            8,
            32,
            256,
            "image",
            "1",
            "build",
            DateTimeOffset.UnixEpoch,
            "Enabled",
            DateTimeOffset.UnixEpoch);

    private static JsonSerializerOptions ServerJson()
    {
        var options = new JsonSerializerOptions(
            Steward.Contracts.StewardJson.Options);
        options.Converters.Add(new TerminalSessionIdJsonConverter());
        return options;
    }

    private sealed class TokenProvider : IControlMutationTokenProvider
    {
        public ValueTask<string?> GetTokenAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<string?>("local-test-token");
    }

    private sealed class RouteHandler : HttpMessageHandler
    {
        public List<string> Paths { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Paths.Add(request.RequestUri!.PathAndQuery);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(
                    new ProviderOperationResult(
                        ProviderOperationStatus.Succeeded,
                        null,
                        null),
                    options: Steward.Contracts.StewardJson.Options)
            });
        }
    }

    private sealed class QueueResponseHandler(
        params HttpContent[] responseValues)
        : HttpMessageHandler
    {
        private readonly Queue<HttpContent> responses =
            new(responseValues);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = responses.Dequeue()
            });
    }

    private sealed class RecordingConnectionHostGateway :
        IConnectionHostPipeGateway
    {
        public List<ConnectionHostOperation> Operations { get; } = [];
        public bool ConnectConfigured => false;

        public Task<ConnectionHostCommandResult> StatusAsync(
            string connectionId,
            CancellationToken cancellationToken)
        {
            Operations.Add(ConnectionHostOperation.Status);
            return Task.FromResult(ConnectionResult());
        }

        public Task<ConnectionHostCommandResult> ResolveAsync(
            string connectionId,
            Uri providerResource,
            CancellationToken cancellationToken) =>
            Record(ConnectionHostOperation.Resolve);

        public Task<ConnectionHostCommandResult> PrepareAsync(
            string connectionId,
            CancellationToken cancellationToken) =>
            Record(ConnectionHostOperation.Prepare);

        public Task<ConnectionHostCommandResult> ConnectAsync(
            string connectionId,
            CancellationToken cancellationToken) =>
            Record(ConnectionHostOperation.Connect);

        public Task<ConnectionHostCommandResult> ViewAsync(
            string connectionId,
            long connectionGeneration,
            CancellationToken cancellationToken) =>
            Record(ConnectionHostOperation.View);

        public Task<ConnectionHostCommandResult> TakeControlAsync(
            string connectionId,
            long connectionGeneration,
            CancellationToken cancellationToken) =>
            Record(ConnectionHostOperation.TakeControl);

        public Task<ConnectionHostCommandResult> ReleaseControlAsync(
            string connectionId,
            long connectionGeneration,
            CancellationToken cancellationToken) =>
            Record(ConnectionHostOperation.ReleaseControl);

        public Task<ConnectionHostCommandResult> DisconnectAsync(
            string connectionId,
            long? connectionGeneration,
            CancellationToken cancellationToken) =>
            Record(ConnectionHostOperation.Disconnect);

        private Task<ConnectionHostCommandResult> Record(
            ConnectionHostOperation operation)
        {
            Operations.Add(operation);
            return Task.FromResult(ConnectionResult());
        }
    }

    private sealed class FakeConnectionIdentityService(
        DevBoxConnectionIdentityStatus status) :
        IConnectionIdentityService
    {
        public Task<DevBoxConnectionIdentityStatus> StatusAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(status);

        public Task<DevBoxConnectionIdentityStatus> EnrollAsync(
            IntPtr parentWindowHandle,
            CancellationToken cancellationToken) =>
            Task.FromResult(status);

        public Task<DevBoxConnectionIdentityStatus> LogoutAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(status);
    }
}
