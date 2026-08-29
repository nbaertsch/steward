using Azure.Core;
using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class ProductionIntegrationTests
{
    private const string TenantId =
        "11111111-2222-3333-4444-555555555555";

    [Fact]
    public async Task Credential_callback_uses_only_bound_avd_identity()
    {
        var source = new FakeTokenSource(Binding());
        var callback = new DevBoxRdCoreCredentialCallback(source);

        var result = await callback.AcquireTokenAsync(
            ValidClaimsRequest(),
            CancellationToken.None);

        Assert.Equal("access-token", result.Token);
        Assert.Equal(TenantId, result.AadResourceTenantId);
        Assert.Equal("user@example.test", result.UserName);
        Assert.Equal(
            DevBoxConnectionAudience.AzureVirtualDesktop,
            source.RequestedAudience);
        Assert.Equal("claims", source.RequestedClaims);
    }

    [Theory]
    [InlineData(
        "wrong-client",
        "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555",
        "https://www.wvd.microsoft.com/",
        "https://www.wvd.microsoft.com/.default",
        "user@example.test")]
    [InlineData(
        "4fb5cc57-dbbc-4cdc-9595-748adff5f414",
        "https://login.microsoftonline.com/common",
        "https://www.wvd.microsoft.com/",
        "https://www.wvd.microsoft.com/.default",
        "user@example.test")]
    [InlineData(
        "4fb5cc57-dbbc-4cdc-9595-748adff5f414",
        "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555",
        "https://management.azure.com/",
        "https://www.wvd.microsoft.com/.default",
        "user@example.test")]
    [InlineData(
        "4fb5cc57-dbbc-4cdc-9595-748adff5f414",
        "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555",
        "https://www.wvd.microsoft.com/",
        "https://management.azure.com/.default",
        "user@example.test")]
    [InlineData(
        "4fb5cc57-dbbc-4cdc-9595-748adff5f414",
        "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555",
        "https://www.wvd.microsoft.com/",
        "https://www.wvd.microsoft.com/.default",
        "other@example.test")]
    public async Task Credential_callback_rejects_unbound_claims(
        string clientId,
        string authority,
        string resource,
        string scope,
        string username)
    {
        var source = new FakeTokenSource(Binding());
        var callback = new DevBoxRdCoreCredentialCallback(source);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await callback.AcquireTokenAsync(
                new(
                    authority,
                    "claims",
                    clientId,
                    resource,
                    scope,
                    username),
                CancellationToken.None));

        Assert.Null(source.RequestedAudience);
    }

    [Fact]
    public async Task Credential_callback_rejects_identity_change()
    {
        var source = new FakeTokenSource(
            Binding(),
            Binding() with { HomeAccountId = "changed-home" });
        var callback = new DevBoxRdCoreCredentialCallback(source);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await callback.AcquireTokenAsync(
                ValidClaimsRequest(),
                CancellationToken.None));
    }

    [Fact]
    public async Task Production_runtime_requires_external_authenticated_evidence()
    {
        var lease = new FakeLease();
        var source = new FakeEvidenceSource(CompleteExternalEvidence());
        var factory = new FakeLeaseFactory(lease);
        await using var runtime = new ProductionRdCoreConnectionRuntime(
            factory,
            source,
            TimeSpan.FromSeconds(2));
        var request = StartRequest();

        var result = await runtime.ConnectAsync(
            request,
            CancellationToken.None);

        Assert.Equal(7, result.Evidence.Count);
        Assert.Equal(request.ProviderResourceUri, factory.ProviderResource);
        Assert.False(result.PresentationCapabilities.IsVerified);
        Assert.Same(
            result,
            await runtime.ReconcileAsync(
                result.RuntimeConnectionId,
                result.ConnectionGeneration,
                CancellationToken.None));
    }

    [Fact]
    public async Task External_process_lease_is_confirmed_by_authenticated_evidence()
    {
        var source = new FakeEvidenceSource(CompleteExternalEvidence());
        var lease = new FakeExternallyProvenLease(
            () => Assert.True(source.EvidenceAwaited));
        await using var runtime = new ProductionRdCoreConnectionRuntime(
            new FakeLeaseFactory(lease),
            source,
            TimeSpan.FromSeconds(2));

        var result = await runtime.ConnectAsync(
            StartRequest(),
            CancellationToken.None);

        Assert.True(lease.Confirmed);
        Assert.Equal(RdCoreConnectionState.Connected, lease.State);
        Assert.Equal(7, result.Evidence.Count);
    }

    [Fact]
    public async Task Production_runtime_registers_ticket_before_rdcore_connect()
    {
        var source = new FakeEvidenceSource(
            CompleteExternalEvidence());
        var lease = new FakeLease(
            () => Assert.True(source.Registered));
        await using var runtime = new ProductionRdCoreConnectionRuntime(
            new FakeLeaseFactory(lease),
            source,
            TimeSpan.FromSeconds(2));

        _ = await runtime.ConnectAsync(
            StartRequest(),
            CancellationToken.None);

        Assert.True(source.Registered);
    }

    [Fact]
    public async Task Production_runtime_fails_before_lease_when_evidence_is_unconfigured()
    {
        var lease = new FakeLease();
        var factory = new FakeLeaseFactory(lease);
        await using var runtime = new ProductionRdCoreConnectionRuntime(
            factory,
            new FakeEvidenceSource(
                CompleteExternalEvidence(),
                isConfigured: false));

        var exception =
            await Assert.ThrowsAsync<ConnectionHostOperationException>(
                () => runtime.ConnectAsync(
                    StartRequest(),
                    CancellationToken.None));

        Assert.Equal(
            "CONNECTION_HOST_DVC_EVIDENCE_SOURCE_UNAVAILABLE",
            exception.Code);
        Assert.Null(factory.ProviderResource);
    }

    [Fact]
    public async Task Production_runtime_rejects_incomplete_dvc_evidence()
    {
        var lease = new FakeLease();
        var source = new FakeEvidenceSource(
        [
            new(RdCoreDvcEvidenceEvent.StewardComClassActivated)
        ]);
        await using var runtime = new ProductionRdCoreConnectionRuntime(
            new FakeLeaseFactory(lease),
            source,
            TimeSpan.FromSeconds(2));

        await Assert.ThrowsAsync<InvalidDataException>(
            () => runtime.ConnectAsync(
                StartRequest(),
                CancellationToken.None));

        Assert.Equal(1, lease.DisconnectCount);
        Assert.True(lease.Disposed);
    }

    [Fact]
    public async Task Production_runtime_rejects_evidence_for_another_connection()
    {
        var lease = new FakeLease();
        var source = new FakeEvidenceSource(
            CompleteExternalEvidence(),
            mismatchedConnection: true);
        await using var runtime = new ProductionRdCoreConnectionRuntime(
            new FakeLeaseFactory(lease),
            source,
            TimeSpan.FromSeconds(2));

        await Assert.ThrowsAsync<InvalidDataException>(
            () => runtime.ConnectAsync(
                StartRequest(),
                CancellationToken.None));

        Assert.Equal(1, lease.DisconnectCount);
    }

    [Fact]
    public async Task Fresh_production_runtime_cannot_adopt_an_in_memory_lease()
    {
        await using var runtime = new ProductionRdCoreConnectionRuntime(
            new FakeLeaseFactory(new FakeLease()),
            new FakeEvidenceSource(CompleteExternalEvidence()));

        var result = await runtime.ReconcileAsync(
            "old-runtime",
            7,
            CancellationToken.None);

        Assert.Null(result);
    }

    private static DevBoxConnectionIdentityBinding Binding() =>
        new(
            TenantId,
            "home-account",
            "user@example.test",
            DevBoxConnectionIdentityConstants.WindowsAppClientId);

    private static RdCoreClaimsTokenRequest ValidClaimsRequest() =>
        new(
            $"https://login.microsoftonline.com/{TenantId}",
            "claims",
            "a85cf173-4192-42f8-81fa-777a763e6e2c",
            "https://www.wvd.microsoft.com/",
            DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope,
            "user@example.test");

    private static RdCoreConnectionStartRequest StartRequest() =>
        new(
            "connection",
            new Uri(
                "ms-avd:connect?env=prod&preview=false" +
                "&resourceId=resource&username=user%40example.test" +
                "&version=1&workspaceId=workspace"),
            new MemoryStream("signed-rdp"u8.ToArray()),
            Artifacts(),
            new(
                true,
                true,
                RdpDvcPluginRegistration
                    .RegisteredActivationPendingCode),
            "evidence-reference");

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

    private static IReadOnlyList<RdCoreRuntimeEvidence>
        CompleteExternalEvidence() =>
        [
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

    private sealed class FakeTokenSource(
        DevBoxConnectionIdentityBinding first,
        DevBoxConnectionIdentityBinding? second = null) :
        IDevBoxConnectionTokenSource
    {
        private int bindingReads;

        public DevBoxConnectionAudience? RequestedAudience { get; private set; }
        public string? RequestedClaims { get; private set; }

        public Task<DevBoxConnectionIdentityBinding> GetBindingAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(
                Interlocked.Increment(ref bindingReads) == 1
                    ? first
                    : second ?? first);

        public Task<AccessToken> AcquireTokenAsync(
            DevBoxConnectionAudience audience,
            CancellationToken cancellationToken,
            string? claims = null)
        {
            RequestedAudience = audience;
            RequestedClaims = claims;
            return Task.FromResult(
                new AccessToken(
                    "access-token",
                    DateTimeOffset.UtcNow.AddMinutes(5)));
        }

        public Task<AccessToken> AcquireWindowsCloudLoginTokenAsync(
            string clientId,
            string redirectUri,
            string resourceUri,
            string scope,
            string? claims,
            CancellationToken cancellationToken)
        {
            RequestedClaims = claims;
            return Task.FromResult(
                new AccessToken(
                    "cloud-login-token",
                    DateTimeOffset.UtcNow.AddMinutes(5)));
        }
    }

    private sealed class FakeLeaseFactory(
        IRdCoreConnectionLeaseHandle lease) :
        IRdCoreConnectionLeaseFactory
    {
        public Uri? ProviderResource { get; private set; }

        public Task<IRdCoreConnectionLeaseHandle> CreateAsync(
            RdCoreConnectionStartRequest request,
            CancellationToken cancellationToken)
        {
            ProviderResource = request.ProviderResourceUri;
            return Task.FromResult<IRdCoreConnectionLeaseHandle>(lease);
        }
    }

    private sealed class FakeLease(
        Action? beforeConnect = null) :
        IRdCoreConnectionLeaseHandle
    {
        public RdCoreConnectionState State { get; private set; } =
            RdCoreConnectionState.Resolving;
        public int DisconnectCount { get; private set; }
        public bool Disposed { get; private set; }
        public event EventHandler? Connected;
        public event EventHandler? WtsPluginsLoaded;

        public Task ConnectAsync(CancellationToken cancellationToken)
        {
            beforeConnect?.Invoke();
            State = RdCoreConnectionState.Connected;
            Connected?.Invoke(this, EventArgs.Empty);
            WtsPluginsLoaded?.Invoke(this, EventArgs.Empty);
            return Task.CompletedTask;
        }

        public Task DisconnectAsync(CancellationToken cancellationToken)
        {
            DisconnectCount++;
            State = RdCoreConnectionState.Disconnected;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeExternallyProvenLease(
        Action beforeConfirm) :
        IExternallyProvenRdCoreConnectionLeaseHandle
    {
        private readonly TaskCompletionSource connectionFailure = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public RdCoreConnectionState State { get; private set; } =
            RdCoreConnectionState.Resolving;
        public Task ConnectionFailure => connectionFailure.Task;
        public bool Confirmed { get; private set; }
        public event EventHandler? Connected;
        public event EventHandler? WtsPluginsLoaded;

        public Task ConnectAsync(CancellationToken cancellationToken)
        {
            State = RdCoreConnectionState.Connecting;
            return Task.CompletedTask;
        }

        public void ConfirmConnected()
        {
            beforeConfirm();
            Confirmed = true;
            State = RdCoreConnectionState.Connected;
            Connected?.Invoke(this, EventArgs.Empty);
            WtsPluginsLoaded?.Invoke(this, EventArgs.Empty);
        }

        public Task DisconnectAsync(CancellationToken cancellationToken)
        {
            State = RdCoreConnectionState.Disconnected;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeEvidenceSource(
        IReadOnlyList<RdCoreRuntimeEvidence> evidence,
        bool mismatchedConnection = false,
        bool isConfigured = true) :
        IRdpDvcRuntimeEvidenceSource
    {
        public bool IsConfigured => isConfigured;
        private RdpDvcRuntimeEvidenceTicket? ticket;
        public bool Registered { get; private set; }
        public bool EvidenceAwaited { get; private set; }

        public ValueTask<RdpDvcRuntimeEvidenceTicket>
            RegisterExpectedAsync(
            string evidenceReference,
            string connectionId,
            string runtimeConnectionId,
            long connectionGeneration,
            CancellationToken cancellationToken)
        {
            Registered = true;
            ticket = new(
                Guid.NewGuid(),
                new(
                    evidenceReference,
                    connectionId,
                    runtimeConnectionId,
                    connectionGeneration,
                    new(
                        Guid.NewGuid(),
                        Guid.NewGuid(),
                        Guid.NewGuid(),
                        42,
                        Guid.NewGuid())));
            return ValueTask.FromResult(ticket);
        }

        public Task<RdpDvcRuntimeEvidenceBatch> WaitForEvidenceAsync(
            RdpDvcRuntimeEvidenceTicket expected,
            CancellationToken cancellationToken)
        {
            Assert.Equal(ticket, expected);
            EvidenceAwaited = true;
            return Task.FromResult(
                new RdpDvcRuntimeEvidenceBatch(
                    mismatchedConnection
                        ? expected.Identity.ConnectionId + "-other"
                        : expected.Identity.ConnectionId,
                    expected.Identity.RuntimeConnectionId,
                    expected.Identity.ConnectionGeneration,
                    evidence,
                    expected.Identity.Route.WtsSessionId > 0
                        ? expected.Identity.Route
                        : expected.Identity.Route.BindWtsSession(42)));
        }

        public ValueTask CancelAsync(
            RdpDvcRuntimeEvidenceTicket expected)
        {
            Assert.Equal(ticket, expected);
            return ValueTask.CompletedTask;
        }
    }
}
