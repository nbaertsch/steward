using Azure.Core;
using Azure.Identity;
using Steward.DevBox.Windows;

namespace Steward.DevBox.Tests;

public sealed class ConnectionIdentityTests : IDisposable
{
    private const string Tenant =
        "11111111-1111-1111-1111-111111111111";
    private const string OtherTenant =
        "22222222-2222-2222-2222-222222222222";
    private readonly string root = Path.Combine(
        AppContext.BaseDirectory,
        "devbox-connection-identity-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void Control_identity_remains_restricted_to_dev_center()
    {
        Assert.Equal(
            "devbox/default",
            DevBoxIdentityConstants.ContextName);
        Assert.Equal(
            "https://devcenter.azure.com/.default",
            DevBoxIdentityConstants.Scope);
    }

    [Fact]
    public void Connection_identity_uses_installed_windows_app_registration()
    {
        Assert.Equal(
            "4fb5cc57-dbbc-4cdc-9595-748adff5f414",
            DevBoxConnectionIdentityConstants.WindowsAppClientId);
        Assert.Equal(
            "ms-appx-web://microsoft.aad.brokerplugin/" +
            "4fb5cc57-dbbc-4cdc-9595-748adff5f414",
            DevBoxConnectionIdentityConstants.WindowsAppBrokerRedirectUri);
        Assert.Equal(
            "7c0a6aea-533c-458c-9f81-15568f10f6e4/EndUser.Access",
            DevBoxConnectionIdentityConstants.Scope(
                DevBoxConnectionAudience.Windows365EndUser));
        Assert.Equal(
            "https://www.wvd.microsoft.com/.default",
            DevBoxConnectionIdentityConstants.Scope(
                DevBoxConnectionAudience.AzureVirtualDesktop));
    }

    [Fact]
    public async Task Default_enrollment_requires_only_avd_and_reuses_silent_wam()
    {
        var defaultStore = await CreateDefaultStoreAsync();
        var connectionStore = ConnectionStore();
        var broker = new FakeBroker(ConnectionRecord());
        var service = new DevBoxConnectionIdentityService(
            defaultStore,
            connectionStore,
            broker,
            new FakeRemover());

        var enrolled = await service.EnrollAsync(new IntPtr(42), default);
        var status = await service.StatusAsync(default);
        var loaded = await connectionStore.LoadAsync(default);

        Assert.Equal(DevBoxConnectionIdentityOutcome.Ready, enrolled.Outcome);
        Assert.Equal(DevBoxConnectionIdentityOutcome.Ready, status.Outcome);
        Assert.True(enrolled.Enrolled);
        Assert.Equal(
            [DevBoxConnectionAudience.AzureVirtualDesktop],
            broker.EnrollmentAudiences);
        Assert.Equal(
            [DevBoxConnectionAudience.AzureVirtualDesktop],
            broker.SilentAudiences);
        Assert.Equal(
            [DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope],
            loaded.Context.Scopes);
        Assert.Equal(
            DevBoxConnectionIdentityConstants.WindowsAppClientId,
            loaded.Context.ClientId);
        Assert.Equal(
            DevBoxConnectionIdentityConstants.WindowsAppBrokerRedirectUri,
            loaded.Context.RedirectUri);
    }

    [Fact]
    public async Task Windows365_end_user_enrollment_is_explicit_and_optional()
    {
        var broker = new FakeBroker(ConnectionRecord());
        var service = new DevBoxConnectionIdentityService(
            await CreateDefaultStoreAsync(),
            ConnectionStore(),
            broker,
            new FakeRemover());

        var result = await service.EnrollAsync(
            new IntPtr(42),
            includeWindows365EndUser: true,
            default);

        Assert.Equal(DevBoxConnectionIdentityOutcome.Ready, result.Outcome);
        Assert.Equal(
            [
                DevBoxConnectionAudience.AzureVirtualDesktop,
                DevBoxConnectionAudience.Windows365EndUser
            ],
            broker.EnrollmentAudiences);
    }

    [Fact]
    public async Task Optional_audience_is_added_only_after_silent_proof()
    {
        var defaultStore = await CreateDefaultStoreAsync();
        var connectionStore = ConnectionStore();
        await connectionStore.SaveAsync(
            ConnectionContext(),
            ConnectionRecord(),
            default);
        var broker = new FakeBroker(ConnectionRecord());
        var service = new DevBoxConnectionIdentityService(
            defaultStore,
            connectionStore,
            broker,
            new FakeRemover());

        _ = await service.AcquireTokenAsync(
            DevBoxConnectionAudience.Windows365EndUser,
            default);

        var loaded = await connectionStore.LoadAsync(default);
        Assert.Contains(
            DevBoxConnectionIdentityConstants.Windows365EndUserScope,
            loaded.Context.Scopes);
        Assert.Equal(
            [DevBoxConnectionAudience.Windows365EndUser],
            broker.SilentAudiences);
    }

    [Fact]
    public async Task Optional_windows365_failure_does_not_block_devbox_status()
    {
        var defaultStore = await CreateDefaultStoreAsync();
        var connectionStore = ConnectionStore();
        var broker = new FakeBroker(ConnectionRecord());
        var service = new DevBoxConnectionIdentityService(
            defaultStore,
            connectionStore,
            broker,
            new FakeRemover());
        _ = await service.EnrollAsync(
            new IntPtr(42),
            includeWindows365EndUser: true,
            default);
        broker.SilentFailureAudience =
            DevBoxConnectionAudience.Windows365EndUser;

        var status = await service.StatusAsync(default);

        Assert.Equal(DevBoxConnectionIdentityOutcome.Ready, status.Outcome);
        Assert.Equal(
            [DevBoxConnectionAudience.AzureVirtualDesktop],
            broker.SilentAudiences);
    }

    [Theory]
    [InlineData(OtherTenant, "home.tenant")]
    [InlineData(Tenant, "other.home")]
    public async Task Enrollment_rejects_cross_tenant_or_account(
        string tenantId,
        string homeAccountId)
    {
        var remover = new FakeRemover();
        var connectionStore = ConnectionStore();
        var service = new DevBoxConnectionIdentityService(
            await CreateDefaultStoreAsync(),
            connectionStore,
            new FakeBroker(ConnectionRecord(tenantId, homeAccountId)),
            remover);

        var result = await service.EnrollAsync(new IntPtr(42), default);

        Assert.Equal(
            DevBoxConnectionIdentityOutcome.AccountMismatch,
            result.Outcome);
        Assert.False(result.Enrolled);
        Assert.False(connectionStore.Exists);
        Assert.True(remover.Called);
    }

    [Fact]
    public async Task Enrollment_rejects_a_different_public_client_registration()
    {
        var remover = new FakeRemover();
        var service = new DevBoxConnectionIdentityService(
            await CreateDefaultStoreAsync(),
            ConnectionStore(),
            new FakeBroker(
                ConnectionRecord(
                    clientId: "00000000-0000-0000-0000-000000000001")),
            remover);

        var result = await service.EnrollAsync(new IntPtr(42), default);

        Assert.Equal(
            DevBoxConnectionIdentityOutcome.InteractionRequired,
            result.Outcome);
        Assert.True(remover.Called);
    }

    [Fact]
    public async Task Status_rejects_connection_context_after_default_account_changes()
    {
        var defaultStore = await CreateDefaultStoreAsync();
        var connectionStore = ConnectionStore();
        await connectionStore.SaveAsync(
            ConnectionContext(),
            ConnectionRecord(),
            default);
        defaultStore.Delete();
        defaultStore = DefaultStore();
        await SaveDefaultAsync(
            defaultStore,
            OtherTenant,
            "other.home");
        var broker = new FakeBroker(ConnectionRecord());
        var service = new DevBoxConnectionIdentityService(
            defaultStore,
            connectionStore,
            broker,
            new FakeRemover());

        var status = await service.StatusAsync(default);
        var exception = await Assert.ThrowsAsync<
            DevBoxConnectionIdentityException>(() =>
            service.AcquireTokenAsync(
                DevBoxConnectionAudience.AzureVirtualDesktop,
                default));

        Assert.Equal(
            DevBoxConnectionIdentityOutcome.AccountMismatch,
            status.Outcome);
        Assert.Equal(
            DevBoxConnectionIdentityOutcome.AccountMismatch,
            exception.Outcome);
        Assert.Empty(broker.SilentAudiences);
    }

    [Fact]
    public async Task Silent_failure_returns_interaction_required_without_prompting()
    {
        var defaultStore = await CreateDefaultStoreAsync();
        var connectionStore = ConnectionStore();
        await connectionStore.SaveAsync(
            ConnectionContext(),
            ConnectionRecord(),
            default);
        var broker = new FakeBroker(ConnectionRecord())
        {
            SilentFailure = new CredentialUnavailableException(
                "interaction required")
        };
        var service = new DevBoxConnectionIdentityService(
            defaultStore,
            connectionStore,
            broker,
            new FakeRemover());

        var status = await service.StatusAsync(default);

        Assert.Equal(
            DevBoxConnectionIdentityOutcome.InteractionRequired,
            status.Outcome);
        Assert.Equal(0, broker.EnrollmentCalls);
    }

    [Fact]
    public async Task Missing_default_identity_requires_interaction_before_enrollment()
    {
        var broker = new FakeBroker(ConnectionRecord());
        var service = new DevBoxConnectionIdentityService(
            DefaultStore(),
            ConnectionStore(),
            broker,
            new FakeRemover());

        var result = await service.EnrollAsync(new IntPtr(42), default);

        Assert.Equal(
            DevBoxConnectionIdentityOutcome.InteractionRequired,
            result.Outcome);
        Assert.Equal(0, broker.EnrollmentCalls);
    }

    [Fact]
    public async Task Clear_removes_only_connection_context()
    {
        var defaultStore = await CreateDefaultStoreAsync();
        var connectionStore = ConnectionStore();
        await connectionStore.SaveAsync(
            ConnectionContext(),
            ConnectionRecord(),
            default);
        var remover = new FakeRemover();
        var service = new DevBoxConnectionIdentityService(
            defaultStore,
            connectionStore,
            new FakeBroker(ConnectionRecord()),
            remover);

        var status = await service.ClearAsync(default);

        Assert.Equal(
            DevBoxConnectionIdentityOutcome.InteractionRequired,
            status.Outcome);
        Assert.True(remover.Called);
        Assert.False(connectionStore.Exists);
        Assert.True(defaultStore.Exists);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, true);
        GC.SuppressFinalize(this);
    }

    private DevBoxIdentityStore DefaultStore() =>
        new(Path.Combine(root, "default"));

    private DevBoxConnectionIdentityStore ConnectionStore() =>
        new(Path.Combine(root, "connection"));

    private async Task<DevBoxIdentityStore> CreateDefaultStoreAsync()
    {
        var store = DefaultStore();
        await SaveDefaultAsync(store, Tenant, "home.tenant");
        return store;
    }

    private static Task SaveDefaultAsync(
        DevBoxIdentityStore store,
        string tenantId,
        string homeAccountId)
    {
        var context = new DevBoxIdentityContext(
            DevBoxIdentityConstants.CurrentVersion,
            DevBoxIdentityConstants.ContextName,
            tenantId,
            "login.microsoftonline.com",
            "control-client",
            homeAccountId,
            "user@example.test",
            DevBoxIdentityConstants.CacheName,
            DateTimeOffset.UnixEpoch);
        var record = IdentityModelFactory.AuthenticationRecord(
            "user@example.test",
            "login.microsoftonline.com",
            homeAccountId,
            tenantId,
            "control-client");
        return store.SaveAsync(context, record, default);
    }

    private static DevBoxConnectionIdentityContext ConnectionContext() =>
        new(
            DevBoxConnectionIdentityConstants.CurrentVersion,
            DevBoxConnectionIdentityConstants.ContextName,
            Tenant,
            "login.microsoftonline.com",
            DevBoxConnectionIdentityConstants.WindowsAppClientId,
            DevBoxConnectionIdentityConstants.WindowsAppBrokerRedirectUri,
            "home.tenant",
            "user@example.test",
            DevBoxConnectionIdentityConstants.CacheName,
            [DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope],
            DateTimeOffset.UnixEpoch);

    private static AuthenticationRecord ConnectionRecord(
        string tenantId = Tenant,
        string homeAccountId = "home.tenant",
        string clientId =
            DevBoxConnectionIdentityConstants.WindowsAppClientId) =>
        IdentityModelFactory.AuthenticationRecord(
            "user@example.test",
            "login.microsoftonline.com",
            homeAccountId,
            tenantId,
            clientId);

    private sealed class FakeBroker(AuthenticationRecord enrollmentRecord) :
        IDevBoxConnectionBroker
    {
        public int EnrollmentCalls { get; private set; }
        public IReadOnlyList<DevBoxConnectionAudience> EnrollmentAudiences
        {
            get;
            private set;
        } = [];
        public List<DevBoxConnectionAudience> SilentAudiences { get; } = [];
        public Exception? SilentFailure { get; init; }
        public DevBoxConnectionAudience? SilentFailureAudience { get; set; }

        public Task<DevBoxConnectionBrokerEnrollment> EnrollAsync(
            IntPtr parentWindowHandle,
            DevBoxIdentityContext expectedIdentity,
            IReadOnlyList<DevBoxConnectionAudience> audiences,
            CancellationToken cancellationToken)
        {
            EnrollmentCalls++;
            Assert.Equal(new IntPtr(42), parentWindowHandle);
            Assert.Equal(Tenant, expectedIdentity.TenantId);
            Assert.Equal("home.tenant", expectedIdentity.HomeAccountId);
            EnrollmentAudiences = audiences.ToArray();
            return Task.FromResult(
                new DevBoxConnectionBrokerEnrollment(
                    enrollmentRecord,
                    DateTimeOffset.UtcNow.AddMinutes(30)));
        }

        public Task<AccessToken> AcquireSilentAsync(
            DevBoxConnectionIdentityContext context,
            AuthenticationRecord record,
            DevBoxConnectionAudience audience,
            string? claims,
            CancellationToken cancellationToken)
        {
            _ = claims;
            SilentAudiences.Add(audience);
            if (SilentFailure is not null ||
                SilentFailureAudience == audience)
                return Task.FromException<AccessToken>(
                    SilentFailure ??
                    new CredentialUnavailableException(
                        "optional interaction required"));
            return Task.FromResult(
                new AccessToken(
                    "opaque-token",
                    DateTimeOffset.UtcNow.AddMinutes(30)));
        }

        public Task<AccessToken> AcquireWindowsCloudLoginSilentAsync(
            DevBoxConnectionIdentityContext context,
            string clientId,
            string redirectUri,
            string tokenScope,
            string? claims,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                new AccessToken(
                    "opaque-cloud-login-token",
                    DateTimeOffset.UtcNow.AddMinutes(30)));
    }

    private sealed class FakeRemover : IDevBoxAccountRemover
    {
        public bool Called { get; private set; }

        public Task RemoveAsync(
            DevBoxIdentityContext context,
            CancellationToken cancellationToken)
        {
            Called = true;
            return Task.CompletedTask;
        }
    }
}
