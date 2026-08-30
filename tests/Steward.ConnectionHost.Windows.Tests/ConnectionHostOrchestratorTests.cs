using System.Text;
using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class ConnectionHostOrchestratorTests
{
    [Fact]
    public async Task Startup_never_creates_a_connection()
    {
        var fixture = new HostFixture(enableConnections: false);
        await using var host = fixture.CreateHost();

        await host.InitializeAsync();

        Assert.Equal(0, fixture.Runtime.ConnectCount);
    }

    [Fact]
    public async Task Connect_requires_explicit_gate_before_consuming_token()
    {
        var fixture = new HostFixture(enableConnections: false);
        await using var host = fixture.CreateHost();
        await host.InitializeAsync();
        await fixture.ResolveAndPrepareAsync(host, "disabled");
        fixture.Authorization.Register("control-token");

        var response = await host.ExecuteAsync(
            fixture.Command(
                ConnectionHostOperation.Connect,
                "disabled",
                token: "control-token"));

        Assert.False(response.Accepted);
        Assert.Equal(
            "CONNECTION_HOST_LIVE_CONNECT_DISABLED",
            response.Code);
        Assert.Equal(0, fixture.Runtime.ConnectCount);
        Assert.Equal(0, fixture.Authorization.ConsumeCount);
    }

    [Fact]
    public async Task Control_authorization_token_is_single_use()
    {
        var fixture = new HostFixture(enableConnections: true);
        await using var host = fixture.CreateHost();
        await host.InitializeAsync();
        await fixture.ResolveAndPrepareAsync(host, "authorized");
        fixture.Authorization.Register("one-use-token");
        var first = await host.ExecuteAsync(
            fixture.Command(
                ConnectionHostOperation.Connect,
                "authorized",
                token: "one-use-token"));
        await fixture.ResolveAndPrepareAsync(host, "replay");

        var replay = await host.ExecuteAsync(
            fixture.Command(
                ConnectionHostOperation.Connect,
                "replay",
                token: "one-use-token"));

        Assert.True(first.Accepted);
        Assert.False(replay.Accepted);
        Assert.Equal(
            "CONNECTION_HOST_CONTROL_AUTHORIZATION_REJECTED",
            replay.Code);
        Assert.Equal(1, fixture.Runtime.ConnectCount);
    }

    [Fact]
    public async Task Durable_metadata_never_contains_connection_secrets()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "connections.json");
            var fixture = new HostFixture(
                enableConnections: true,
                metadata: new AtomicJsonConnectionMetadataStore(path),
                providerSecret: "PROVIDER_URI_SECRET",
                rdpSecret: "SIGNED_RDP_SECRET");
            await using var host = fixture.CreateHost();
            await host.InitializeAsync();
            await fixture.ResolveAndPrepareAsync(host, "secret-test");
            fixture.Authorization.Register("CONTROL_TOKEN_SECRET");

            var connected = await host.ExecuteAsync(
                fixture.Command(
                    ConnectionHostOperation.Connect,
                    "secret-test",
                    token: "CONTROL_TOKEN_SECRET"));

            Assert.True(connected.Accepted);
            var persisted = await File.ReadAllTextAsync(path);
            Assert.DoesNotContain("PROVIDER_URI_SECRET", persisted);
            Assert.DoesNotContain("SIGNED_RDP_SECRET", persisted);
            Assert.DoesNotContain("CONTROL_TOKEN_SECRET", persisted);
            Assert.DoesNotContain("wvd.microsoft.com", persisted);
            Assert.Equal(
                "ms-avd:connect?env=prod&preview=false" +
                "&resourceId=PROVIDER_URI_SECRET" +
                "&username=user%40example.test&version=1" +
                "&workspaceId=workspace",
                fixture.Runtime.ProviderResources.Single().OriginalString);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Multiple_connection_ids_are_independent()
    {
        var fixture = new HostFixture(enableConnections: true);
        await using var host = fixture.CreateHost();
        await host.InitializeAsync();

        var first = await fixture.ConnectAsync(host, "first", "token-one");
        var second = await fixture.ConnectAsync(host, "second", "token-two");
        var status = await host.ExecuteAsync(
            fixture.Command(ConnectionHostOperation.Status));

        Assert.True(first.Accepted);
        Assert.True(second.Accepted);
        Assert.NotEqual(
            first.Status!.ConnectionGeneration,
            second.Status!.ConnectionGeneration);
        Assert.Equal(2, status.Connections!.Count);
        Assert.Equal(2, fixture.Runtime.ConnectCount);
    }

    [Fact]
    public async Task Stale_generation_is_rejected_before_runtime_view()
    {
        var fixture = new HostFixture(enableConnections: true);
        await using var host = fixture.CreateHost();
        await host.InitializeAsync();
        var connected = await fixture.ConnectAsync(
            host,
            "stale",
            "stale-token");
        var generation = connected.Status!.ConnectionGeneration!.Value;

        var response = await host.ExecuteAsync(
            fixture.Command(
                ConnectionHostOperation.View,
                "stale",
                generation: generation + 1));

        Assert.False(response.Accepted);
        Assert.Equal(
            "RDP_DVC_CONNECTION_GENERATION_MISMATCH",
            response.Code);
        Assert.Equal(0, fixture.Runtime.ViewCount);
    }

    [Fact]
    public async Task New_host_object_reconciles_a_live_owned_runtime_lease()
    {
        var metadata = new MemoryMetadataStore();
        var runtime = new FakeRuntime();
        var firstFixture = new HostFixture(
            enableConnections: true,
            metadata: metadata,
            runtime: runtime);
        await using (var first = firstFixture.CreateHost())
        {
            await first.InitializeAsync();
            await firstFixture.ConnectAsync(
                first,
                "restart",
                "restart-token");
        }

        var secondFixture = new HostFixture(
            enableConnections: false,
            metadata: metadata,
            runtime: runtime);
        await using var second = secondFixture.CreateHost();
        await second.InitializeAsync();
        var status = await second.ExecuteAsync(
            secondFixture.Command(
                ConnectionHostOperation.Status,
                "restart"));

        Assert.True(status.Accepted);
        Assert.Equal(
            RdpDvcSessionState.ConnectedTransport,
            status.Status!.State);
        Assert.Equal(
            "CONNECTION_HOST_RESTART_RECONCILED",
            status.Status.Code);
        Assert.Equal(1, runtime.ConnectCount);
        Assert.Equal(1, runtime.ReconcileCount);
    }

    [Fact]
    public async Task Process_restart_metadata_is_disconnected_without_reattachment()
    {
        var metadata = new MemoryMetadataStore();
        var firstFixture = new HostFixture(
            enableConnections: true,
            metadata: metadata);
        await using (var first = firstFixture.CreateHost())
        {
            await first.InitializeAsync();
            await firstFixture.ConnectAsync(
                first,
                "process-restart",
                "process-restart-token");
        }

        var secondFixture = new HostFixture(
            enableConnections: false,
            metadata: metadata,
            runtime: new FakeRuntime());
        await using var second = secondFixture.CreateHost();
        await second.InitializeAsync();
        var status = await second.ExecuteAsync(
            secondFixture.Command(
                ConnectionHostOperation.Status,
                "process-restart"));

        Assert.Equal(
            RdpDvcSessionState.Disconnected,
            status.Status!.State);
        Assert.Equal(
            "CONNECTION_HOST_RESTART_TRANSPORT_NOT_FOUND",
            status.Status.Code);
        Assert.False(status.Status.DvcConnected);
        Assert.Equal(0, secondFixture.Runtime.ConnectCount);
    }

    [Fact]
    public async Task Closing_ui_preserves_the_transport()
    {
        var fixture = new HostFixture(enableConnections: true);
        await using var host = fixture.CreateHost();
        await host.InitializeAsync();
        var connected = await fixture.ConnectAsync(
            host,
            "close-ui",
            "close-token");
        var generation = connected.Status!.ConnectionGeneration!.Value;
        await host.ExecuteAsync(
            fixture.Command(
                ConnectionHostOperation.View,
                "close-ui",
                generation: generation));
        await host.ExecuteAsync(
            fixture.Command(
                ConnectionHostOperation.TakeControl,
                "close-ui",
                generation: generation));

        var status = await host.NotifyViewClosedAsync(
            "close-ui",
            generation);

        Assert.Equal(
            RdpDvcSessionState.ConnectedTransport,
            status.State);
        Assert.True(status.DvcConnected);
        Assert.Equal(0, fixture.Runtime.DisconnectCount);
    }

    [Fact]
    public async Task View_reuses_existing_connection()
    {
        var fixture = new HostFixture(enableConnections: true);
        await using var host = fixture.CreateHost();
        await host.InitializeAsync();
        var connected = await fixture.ConnectAsync(
            host,
            "view",
            "view-token");
        var generation = connected.Status!.ConnectionGeneration!.Value;

        var viewed = await host.ExecuteAsync(
            fixture.Command(
                ConnectionHostOperation.View,
                "view",
                generation: generation));

        Assert.True(viewed.Accepted);
        Assert.Equal(RdpDvcSessionState.Viewing, viewed.Status!.State);
        Assert.Equal(1, fixture.Runtime.ConnectCount);
        Assert.Equal(1, fixture.Runtime.ViewCount);
    }

    [Fact]
    public async Task View_fails_until_same_connection_capability_is_proved()
    {
        var runtime = new FakeRuntime
        {
            Capabilities = new(
                false,
                false,
                "RDCORE_PRESENTATION_UNPROVEN")
        };
        var fixture = new HostFixture(
            enableConnections: true,
            runtime: runtime);
        await using var host = fixture.CreateHost();
        await host.InitializeAsync();
        var connected = await fixture.ConnectAsync(
            host,
            "unproved",
            "unproved-token");

        var response = await host.ExecuteAsync(
            fixture.Command(
                ConnectionHostOperation.View,
                "unproved",
                generation:
                    connected.Status!.ConnectionGeneration!.Value));

        Assert.False(response.Accepted);
        Assert.Equal(
            "CONNECTION_HOST_SAME_CONNECTION_VIEW_UNPROVEN",
            response.Code);
        Assert.Equal(0, runtime.ViewCount);
    }

    [Fact]
    public async Task Desktop_client_can_reconnect_to_the_same_host()
    {
        var pipeName = "Steward.ConnectionHost.Tests." +
            Guid.NewGuid().ToString("N");
        var fixture = new HostFixture(enableConnections: false);
        await using var host = fixture.CreateHost();
        await host.InitializeAsync();
        var options = new ConnectionHostOptions
        {
            PipeName = pipeName,
            CommandTimeout = TimeSpan.FromSeconds(5)
        };
        using var stop = new CancellationTokenSource();
        var server = new ConnectionHostPipeServer(options, host)
            .RunAsync(stop.Token);
        var client = new ConnectionHostPipeClient(
            pipeName,
            TimeSpan.FromSeconds(5));

        var first = await client.SendAsync(
            fixture.Command(ConnectionHostOperation.Status));
        var second = await client.SendAsync(
            fixture.Command(ConnectionHostOperation.Status));
        stop.Cancel();
        await server;

        Assert.True(first.Accepted);
        Assert.True(second.Accepted);
        Assert.Equal(0, fixture.Runtime.ConnectCount);
    }

    private static string TestDirectory()
    {
        var directory = Path.Combine(
            AppContext.BaseDirectory,
            "connection-host-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private sealed class HostFixture
    {
        private readonly bool enableConnections;
        private readonly IConnectionMetadataStore metadata;
        private readonly string providerSecret;
        private readonly string rdpSecret;

        public HostFixture(
            bool enableConnections,
            IConnectionMetadataStore? metadata = null,
            FakeRuntime? runtime = null,
            string providerSecret = "provider",
            string rdpSecret = "signed-rdp")
        {
            this.enableConnections = enableConnections;
            this.metadata = metadata ?? new MemoryMetadataStore();
            this.providerSecret = providerSecret;
            this.rdpSecret = rdpSecret;
            Runtime = runtime ?? new FakeRuntime();
        }

        public FakeRuntime Runtime { get; }
        public CountingAuthorization Authorization { get; } = new();

        public ConnectionHostOrchestrator CreateHost() =>
            new(
                new ConnectionHostOptions
                {
                    EnableLiveConnections = enableConnections
                },
                new ReadyIdentity(),
                new FakeResolver(rdpSecret),
                new CompatibleInspector(),
                new ReadyRegistration(),
                Runtime,
                Authorization,
                metadata);

        public ConnectionHostCommand Command(
            ConnectionHostOperation operation,
            string? connectionId = null,
            string? token = null,
            long? generation = null) =>
            new(
                ConnectionHostProtocol.CurrentVersion,
                Guid.NewGuid().ToString("N"),
                operation,
                connectionId,
                operation == ConnectionHostOperation.Resolve
                    ? "ms-avd:connect?env=prod&preview=false" +
                      "&resourceId=" + providerSecret +
                      "&username=user%40example.test&version=1" +
                      "&workspaceId=workspace"
                    : null,
                token,
                generation,
                operation == ConnectionHostOperation.Connect
                    ? "evidence-reference-" + connectionId
                    : null);

        public async Task ResolveAndPrepareAsync(
            ConnectionHostOrchestrator host,
            string connectionId)
        {
            Assert.True(
                (await host.ExecuteAsync(
                    Command(
                        ConnectionHostOperation.Resolve,
                        connectionId))).Accepted);
            Assert.True(
                (await host.ExecuteAsync(
                    Command(
                        ConnectionHostOperation.Prepare,
                        connectionId))).Accepted);
        }

        public async Task<ConnectionHostResponse> ConnectAsync(
            ConnectionHostOrchestrator host,
            string connectionId,
            string token)
        {
            await ResolveAndPrepareAsync(host, connectionId);
            Authorization.Register(token);
            return await host.ExecuteAsync(
                Command(
                    ConnectionHostOperation.Connect,
                    connectionId,
                    token));
        }
    }

    private sealed class ReadyIdentity : IDevBoxConnectionIdentityGate
    {
        public Task<DevBoxConnectionIdentityStatus> StatusAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(
                new DevBoxConnectionIdentityStatus(
                    DevBoxConnectionIdentityConstants.CurrentVersion,
                    DevBoxConnectionIdentityConstants.ContextName,
                    DevBoxConnectionIdentityOutcome.Ready,
                    true,
                    null,
                    null,
                    null,
                    null));
    }

    private sealed class FakeResolver(string content) :
        IDevBoxConnectionResolver
    {
        public Task<ISensitiveRdpConnectionMaterial> ResolveAsync(
            Uri providerResource,
            CancellationToken cancellationToken) =>
            Task.FromResult<ISensitiveRdpConnectionMaterial>(
                new FakeMaterial(providerResource, content));
    }

    private sealed class FakeMaterial(
        Uri providerResourceUri,
        string content) :
        ISensitiveRdpConnectionMaterial
    {
        private byte[]? bytes = Encoding.UTF8.GetBytes(content);
        private bool opened;

        public Uri ProviderResourceUri { get; } = providerResourceUri;

        public Stream OpenRdpContent()
        {
            if (opened || bytes is null)
                throw new InvalidOperationException();
            opened = true;
            return new MemoryStream(bytes, writable: false);
        }

        public void Dispose()
        {
            if (bytes is not null)
                Array.Clear(bytes);
            bytes = null;
        }
    }

    private sealed class CompatibleInspector :
        IRdCoreCompatibilityInspector
    {
        public RdCoreCompatibilitySnapshot Inspect() =>
            new(true, "Compatible", Artifacts());

        private static RdCorePackageArtifacts Artifacts() =>
            new(
                "package",
                new Version(1, 0),
                @"C:\package",
                @"C:\package\rdcore.dll",
                @"C:\package\rdcore-native.dll",
                new("rdcore.dll", 1, "00"),
                new("rdcore-native.dll", 1, "00"),
                [],
                []);
    }

    private sealed class ReadyRegistration :
        IDvcRegistrationSnapshotProvider
    {
        public DvcPluginRegistrationStatus GetStatus() =>
            new(
                true,
                true,
                RdpDvcPluginRegistration
                    .RegisteredActivationPendingCode);
    }

    private sealed class CountingAuthorization :
        IControlConnectAuthorizationValidator
    {
        private readonly HashSet<string> tokens =
            new(StringComparer.Ordinal);

        public int ConsumeCount { get; private set; }

        public void Register(string token) => tokens.Add(token);

        public ValueTask<bool> ConsumeAsync(
            string authorizationToken,
            string connectionId,
            CancellationToken cancellationToken)
        {
            ConsumeCount++;
            return ValueTask.FromResult(tokens.Remove(authorizationToken));
        }
    }

    private sealed class FakeRuntime : IRdCoreConnectionRuntime
    {
        private readonly Dictionary<string, RdCoreConnectionRuntimeResult>
            active = new(StringComparer.Ordinal);
        private long generation = 100;

        public RdCorePresentationCapabilities Capabilities { get; set; } =
            new(
                true,
                true,
                RdCorePresentationCapabilities.VerifiedEvidenceCode);

        public int ConnectCount { get; private set; }
        public int ReconcileCount { get; private set; }
        public int ViewCount { get; private set; }
        public int DisconnectCount { get; private set; }
        public List<Uri> ProviderResources { get; } = [];

        public async Task<RdCoreConnectionRuntimeResult> ConnectAsync(
            RdCoreConnectionStartRequest request,
            CancellationToken cancellationToken)
        {
            ConnectCount++;
            ProviderResources.Add(request.ProviderResourceUri);
            using var content = new MemoryStream();
            await request.SignedRdpContent.CopyToAsync(
                content,
                cancellationToken);
            Assert.NotEmpty(content.ToArray());
            var current = Interlocked.Increment(ref generation);
            var result = Result(
                "runtime-" + request.ConnectionId,
                current,
                Capabilities);
            active.Add(result.RuntimeConnectionId, result);
            return result;
        }

        public Task<RdCoreConnectionRuntimeResult?> ReconcileAsync(
            string runtimeConnectionId,
            long connectionGeneration,
            CancellationToken cancellationToken)
        {
            ReconcileCount++;
            active.TryGetValue(runtimeConnectionId, out var result);
            return Task.FromResult(
                result?.ConnectionGeneration == connectionGeneration
                    ? result
                    : null);
        }

        public Task<RdCorePresentationProof> ViewExistingAsync(
            string runtimeConnectionId,
            long connectionGeneration,
            CancellationToken cancellationToken)
        {
            ViewCount++;
            return Task.FromResult(
                Proof(runtimeConnectionId, connectionGeneration));
        }

        public Task<RdCorePresentationProof> TakeControlAsync(
            string runtimeConnectionId,
            long connectionGeneration,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                Proof(runtimeConnectionId, connectionGeneration));

        public Task ReleaseControlAsync(
            string runtimeConnectionId,
            long connectionGeneration,
            CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task DisconnectAsync(
            string runtimeConnectionId,
            long connectionGeneration,
            CancellationToken cancellationToken)
        {
            DisconnectCount++;
            active.Remove(runtimeConnectionId);
            return Task.CompletedTask;
        }

        private static RdCoreConnectionRuntimeResult Result(
            string id,
            long generation,
            RdCorePresentationCapabilities capabilities) =>
            new(id, generation, Evidence(), capabilities);

        private static RdCorePresentationProof Proof(
            string id,
            long generation) =>
            new(
                id,
                generation,
                RdCorePresentationCapabilities.VerifiedEvidenceCode);

        private static IReadOnlyList<RdCoreRuntimeEvidence> Evidence() =>
        [
            new(RdCoreDvcEvidenceEvent.RdCoreConnected),
            new(RdCoreDvcEvidenceEvent.WtsPluginsLoaded),
            new(RdCoreDvcEvidenceEvent.StewardComClassActivated),
            new(
                RdCoreDvcEvidenceEvent.StewardPluginInitialized,
                StewardRdpDvc.AddInName,
                StewardRdpDvc.PluginClsid),
            new(
                RdCoreDvcEvidenceEvent.StewardChannelOpened,
                ChannelName: StewardRdpDvc.ChannelName),
            new(RdCoreDvcEvidenceEvent.DvcHmacAuthenticated),
            new(RdCoreDvcEvidenceEvent.SecurePeerAuthenticated)
        ];
    }

    private sealed class MemoryMetadataStore : IConnectionMetadataStore
    {
        private IReadOnlyList<DurableConnectionMetadata> values = [];

        public Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(values);

        public Task SaveAsync(
            IReadOnlyCollection<DurableConnectionMetadata> connections,
            CancellationToken cancellationToken)
        {
            values = connections.ToArray();
            return Task.CompletedTask;
        }
    }
}
