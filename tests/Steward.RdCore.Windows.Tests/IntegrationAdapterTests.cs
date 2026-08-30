using Microsoft.RemoteDesktop.ClientCore;
using Steward.DevBox.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdCore.Windows.Tests;

public sealed class IntegrationAdapterTests
{
    private static readonly Uri ProviderResource = new(
        "ms-avd:connect?env=prod&preview=false&resourceId=resource-exact" +
        "&username=user%40example.com&version=1&workspaceId=workspace-exact");

    [Fact]
    public async Task Catalog_binds_configures_and_maps_harmless_fixture()
    {
        WorkspaceDownloader.ReturnPendingOperation = false;
        WorkspaceDownloader.NextStatus = OperationStatus.Success;
        WorkspaceDownloader.NextResources =
        [
            new WorkspaceResource(
                "resource-exact",
                AccessState.SilentlyConnectable,
                new RdpFile(
                    "full address:s:broker.example.com\r\n",
                    "key",
                    string.Empty))
        ];
        var options = EnabledOptions() with
        {
            AvdFeedUri = new("https://feed.example.com/arm/feed")
        };
        var catalog = new RdCoreAvdResourceCatalog(
            static () => new FixtureSession(),
            options);

        var resources = await catalog.ListAsync(CancellationToken.None);

        var resource = Assert.Single(resources);
        Assert.Equal("workspace-exact", resource.WorkspaceId);
        Assert.Equal("resource-exact", resource.ResourceId);
        Assert.Equal(
            DevBoxAvdEndpointDeviceState.SilentlyConnectible,
            resource.EndpointDeviceState);
        Assert.Null(resource.BrokerRdpContentUri);
        Assert.False(resource.BrokerRdpContent.IsEmpty);
        var manager = Assert.IsType<ActivityManager>(
            ActivityManager.LastCreated);
        Assert.Equal(string.Empty, manager.InitializedAccount);
        var downloader = Assert.IsType<WorkspaceDownloader>(
            manager.LastWorkspaceDownloader);
        var settings = Assert.IsType<WorkspaceSettings>(
            downloader.WorkspaceSettings);
        Assert.Equal(options.AvdFeedUri.AbsoluteUri, settings.FeedUrl);
        Assert.Equal(options.Account, settings.UserName);
        Assert.Equal(0UL, settings.ParentWindowHandle);
        Assert.True(settings.ForceRefresh);
        Assert.False(settings.AllowInteractivePrompts);
        Assert.Equal(0, downloader.ResourceListSubscribers);
        Assert.Equal(0, downloader.CompletionSubscribers);
    }

    [Fact]
    public async Task Catalog_rejects_failed_feed_status()
    {
        WorkspaceDownloader.ReturnPendingOperation = false;
        WorkspaceDownloader.NextResources = [];
        WorkspaceDownloader.NextStatus = OperationStatus.InternalError;
        var catalog = CreateCatalog();

        await Assert.ThrowsAsync<InvalidDataException>(
            () => catalog.ListAsync(CancellationToken.None));
        Assert.True(WorkspaceDownloader.DownloadReturnedNormally);
    }

    [Fact]
    public async Task Catalog_propagates_handler_mapping_failure()
    {
        WorkspaceDownloader.ReturnPendingOperation = false;
        WorkspaceDownloader.NextStatus = OperationStatus.Success;
        WorkspaceDownloader.NextResources = [null!];
        var catalog = CreateCatalog();

        await Assert.ThrowsAsync<InvalidDataException>(
            () => catalog.ListAsync(CancellationToken.None));
        Assert.True(WorkspaceDownloader.DownloadReturnedNormally);
    }

    [Fact]
    public async Task Catalog_accepts_no_resources_published()
    {
        WorkspaceDownloader.ReturnPendingOperation = false;
        WorkspaceDownloader.NextResources = [];
        WorkspaceDownloader.NextStatus =
            OperationStatus.NoResourcesPublished;
        var catalog = CreateCatalog();

        var resources = await catalog.ListAsync(CancellationToken.None);

        Assert.Empty(resources);
    }

    [Fact]
    public async Task Catalog_cancels_pending_download()
    {
        WorkspaceDownloader.NextResources = [];
        WorkspaceDownloader.NextStatus = OperationStatus.Success;
        WorkspaceDownloader.ReturnPendingOperation = true;
        try
        {
            var catalog = CreateCatalog();
            using var cancellation = new CancellationTokenSource(
                TimeSpan.FromMilliseconds(50));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => catalog.ListAsync(cancellation.Token));

            Assert.True(
                Assert.IsType<PendingAsyncOperation<IFeedDownloadResult>>(
                    WorkspaceDownloader.LastPendingOperation).CancelCalled);
        }
        finally
        {
            WorkspaceDownloader.ReturnPendingOperation = false;
        }
    }

    [Fact]
    public async Task Connection_factory_configures_and_wires_without_connecting()
    {
        var options = EnabledOptions();
        var factory = new RdCoreConnectionFactory(
            static () => new FixtureSession(),
            new StubCredentialCallback(),
            options);

        using var lease = await factory.CreateAsync(
            new(
                "full address:s:broker.example.com\r\n",
                ProviderResource),
            CancellationToken.None);

        var manager = Assert.IsType<ActivityManager>(
            ActivityManager.LastCreated);
        Assert.Equal(string.Empty, manager.InitializedAccount);
        Assert.Equal(options.ClaimsClientId, manager.ClaimsClientId);
        Assert.Equal(options.ClaimsRedirectUri, manager.ClaimsRedirectUri);
        var connection = Assert.IsType<Connection>(manager.LastConnection);
        var settings = Assert.IsType<ConnectionSettings>(
            connection.ConnectionSettings);
        Assert.Equal(ConnectionMode.Silent, settings.ConnectionMode);
        Assert.Equal(
            ProviderResource.OriginalString,
            settings.CloudPCSettingsUri);
        Assert.True(settings.AllowThirdPartyPlugins);
        Assert.True(settings.ConsumerHandlesClaimsTokenRequest);
        Assert.Equal(0UL, settings.PopupUIParentWindowHandle);
        Assert.False(settings.StartFullscreen);
        Assert.Equal(1, connection.ConnectedSubscribers);
        Assert.Equal(1, connection.DisconnectedSubscribers);
        Assert.Equal(1, connection.WtsPluginsLoadedSubscribers);
        Assert.Equal(1, connection.ClaimsTokenRequestedSubscribers);
        Assert.Equal(0, connection.ConnectCalls);
        Assert.Equal(0, connection.DisconnectCalls);

        var connectedRaised = false;
        var pluginsRaised = false;
        var disconnectedRaised = false;
        lease.Connected += (_, _) => connectedRaised = true;
        lease.WtsPluginsLoaded += (_, _) => pluginsRaised = true;
        lease.Disconnected += (_, _) => disconnectedRaised = true;
        connection.RaiseConnected();
        connection.RaiseWtsPluginsLoaded();
        var tokenRequest = new ClaimsTokenRequest();
        var tokenArgs = new ClaimsTokenRequestedArgs(tokenRequest);
        connection.RaiseClaimsTokenRequested(tokenArgs);
        connection.RaiseDisconnected();

        Assert.True(connectedRaised);
        Assert.True(pluginsRaised);
        Assert.True(disconnectedRaised);
        Assert.True(lease.WereWtsPluginsLoaded);
        Assert.Equal(RdCoreConnectionState.Disconnected, lease.State);
        Assert.Equal(0, connection.ConnectCalls);
        Assert.Equal(0, connection.DisconnectCalls);
        Assert.True(tokenRequest.IsCompleted);
        Assert.False(tokenRequest.WasCanceled);
        Assert.Equal("token", tokenRequest.Token);
        Assert.True(tokenArgs.DeferralCompleted);
    }

    [Fact]
    public async Task Disabled_gate_prevents_reflection_session_creation()
    {
        var sessionCreated = false;
        var catalog = new RdCoreAvdResourceCatalog(
            () =>
            {
                sessionCreated = true;
                return new FixtureSession();
            },
            new());
        var factory = new RdCoreConnectionFactory(
            () =>
            {
                sessionCreated = true;
                return new FixtureSession();
            },
            new StubCredentialCallback(),
            new());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => catalog.ListAsync(CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => factory.CreateAsync(
                new(
                    "full address:s:broker.example.com\r\n",
                    ProviderResource),
                CancellationToken.None));
        Assert.False(sessionCreated);
    }

    private static RdCoreIntegrationOptions EnabledOptions() =>
        new()
        {
            Enabled = true,
            AvdFeedUri = new("https://feed.example.com/"),
            Account = "user@example.com",
            ClaimsClientId = "client-id",
            ClaimsRedirectUri = "https://login.example.com/callback",
            ClientIdentifier = "Steward.Tests",
            ClientVersion = "1.0",
            OperationTimeout = TimeSpan.FromSeconds(2)
        };

    private static RdCoreAvdResourceCatalog CreateCatalog() =>
        new(
            static () => new FixtureSession(),
            EnabledOptions() with
            {
                AvdFeedUri = new("https://feed.example.com/arm/feed")
            });

    private sealed class FixtureSession : IRdCoreReflectionSession
    {
        public System.Reflection.Assembly Assembly =>
            typeof(ActivityManager).Assembly;

        public void Dispose()
        {
        }
    }

    private sealed class StubCredentialCallback : IRdCoreCredentialCallback
    {
        public ValueTask<RdCoreClaimsToken> AcquireTokenAsync(
            RdCoreClaimsTokenRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(
                new RdCoreClaimsToken(
                    "token",
                    "authority",
                    "user@example.com",
                    AcquiredSilently: true,
                    "tenant",
                    "device",
                    string.Empty));
    }
}
