using System.Net;
using System.Text;
using Azure.Core;
using Azure.Identity;
using Steward.DevBox.Windows;

namespace Steward.DevBox.Tests;

public sealed class IdentityAndDiscoveryTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        AppContext.BaseDirectory, "devbox-identity-tests", Guid.NewGuid().ToString("N"));
    private const string Tenant = "11111111-1111-1111-1111-111111111111";

    [Fact]
    public async Task Authentication_record_and_context_survive_store_restart()
    {
        var record = IdentityModelFactory.AuthenticationRecord(
            "user@example.test",
            "login.microsoftonline.com",
            "home.tenant",
            Tenant,
            "client");
        var context = Context();
        await new DevBoxIdentityStore(_directory).SaveAsync(context, record, default);

        var loaded = await new DevBoxIdentityStore(_directory).LoadAsync(default);

        Assert.Equal(context, loaded.Context);
        Assert.Equal(record.HomeAccountId, loaded.Record.HomeAccountId);
    }

    [Fact]
    public async Task Missing_and_corrupt_records_fail_closed()
    {
        await Assert.ThrowsAsync<InvalidDataException>(
            () => new DevBoxIdentityStore(_directory).LoadAsync(default));
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(Path.Combine(_directory, "context.v1.json"), "{}");
        await File.WriteAllTextAsync(Path.Combine(_directory, "authentication-record.v1.json"), "{}");
        await Assert.ThrowsAsync<InvalidDataException>(
            () => new DevBoxIdentityStore(_directory).LoadAsync(default));
    }

    [Fact]
    public async Task Logout_removes_account_before_removing_context()
    {
        var store = new DevBoxIdentityStore(_directory);
        await store.SaveAsync(
            Context(),
            IdentityModelFactory.AuthenticationRecord(
                "user@example.test",
                "login.microsoftonline.com",
                "home.tenant",
                Tenant,
                "client"),
            default);
        var remover = new FakeRemover(store);
        var service = new DevBoxIdentityService(store, remover);

        var result = await service.LogoutAsync(default);

        Assert.True(remover.Called);
        Assert.False(result.SignedIn);
        Assert.False(store.Exists);
    }

    [Fact]
    public async Task Discovery_enforces_pagination_origin_and_marks_pool_membership()
    {
        var endpoint = new Uri("https://center.westus.devcenter.azure.com/");
        var transport = new FakeDiscoveryTransport(
            new(
                [new(
                    "project",
                    endpoint,
                    "Project",
                    "description",
                    3,
                    [
                        "CustomizeDevBoxesAsDeveloper",
                        "ReadRemoteConnectionsAsDeveloper",
                        "WriteDevBoxesAsDeveloper"
                    ],
                    [])],
                new Uri($"https://{Tenant}.discovery.devcenter.azure.com/projects?page=2")),
            new([], null));
        var projectClient = new FakeProjectClient(endpoint);
        var service = new DevBoxDiscoveryService(
            new FakeIdentitySource(),
            transport,
            new FakeProjectClientFactory(projectClient));

        var result = await service.DiscoverAsync(default);

        Assert.Equal(2, transport.Calls);
        Assert.Single(result.Projects);
        Assert.True(result.Projects[0].CanCreateDevBoxes);
        Assert.True(result.Projects[0].CanCustomizeDevBoxes);
        Assert.True(result.Projects[0].CanReadRemoteConnections);
        Assert.True(Assert.Single(result.Pools).ExistingMembership);
        Assert.Single(result.DevBoxes);
    }

    [Fact]
    public async Task Tenant_discovery_parses_production_project_uri_shape()
    {
        using var http = new HttpClient(new StubHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """
                    {
                      "value": [
                        {
                          "uri": "https://center.westus.devcenter.azure.com/projects/project",
                          "abilitiesAsDeveloper": [
                            "ReadDevBoxesAsDeveloper",
                            "WriteDevBoxesAsDeveloper"
                          ],
                          "abilitiesAsAdmin": []
                        }
                      ]
                    }
                    """,
                    Encoding.UTF8,
                    "application/json")
            }));
        var transport = new HttpDevBoxTenantDiscoveryTransport(http);

        var page = await transport.GetAsync(
            new($"https://{Tenant}.discovery.devcenter.azure.com/projects"),
            new("opaque", DateTimeOffset.UtcNow.AddMinutes(5)),
            default);

        var project = Assert.Single(page.Projects);
        Assert.Equal("project", project.Name);
        Assert.Equal(
            "https://center.westus.devcenter.azure.com/",
            project.Endpoint.AbsoluteUri);
        Assert.Contains(
            "WriteDevBoxesAsDeveloper",
            project.DeveloperAbilities);
    }

    [Fact]
    public async Task Discovery_rejects_cross_origin_next_link_before_request()
    {
        var transport = new FakeDiscoveryTransport(
            new([], new Uri("https://attacker.example/projects")),
            new([], null));
        var service = new DevBoxDiscoveryService(
            new FakeIdentitySource(),
            transport,
            new FakeProjectClientFactory(
                new FakeProjectClient(new Uri("https://center.westus.devcenter.azure.com/"))));

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.DiscoverAsync(default));
        Assert.Equal(1, transport.Calls);
    }

    [Fact]
    public async Task Control_credential_is_silent_and_restricted_to_devcenter_scope()
    {
        var source = new FakeIdentitySource();
        var credential = new DevBoxSilentTokenCredential(source);

        var token = await credential.GetTokenAsync(
            new([DevBoxIdentityConstants.Scope]), default);
        await Assert.ThrowsAsync<AuthenticationFailedException>(async () =>
            await credential.GetTokenAsync(new(["https://management.azure.com/.default"]), default));

        Assert.Equal("not-persisted", token.Token);
        Assert.Equal(1, source.Calls);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, true);
        GC.SuppressFinalize(this);
    }

    private static DevBoxIdentityContext Context() =>
        new(
            DevBoxIdentityConstants.CurrentVersion,
            DevBoxIdentityConstants.ContextName,
            Tenant,
            "login.microsoftonline.com",
            "client",
            "home.tenant",
            "user@example.test",
            DevBoxIdentityConstants.CacheName,
            DateTimeOffset.UnixEpoch);

    private sealed class FakeRemover(DevBoxIdentityStore store) : IDevBoxAccountRemover
    {
        public bool Called { get; private set; }
        public Task RemoveAsync(DevBoxIdentityContext context, CancellationToken cancellationToken)
        {
            Assert.True(store.Exists);
            Called = true;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeCredential : TokenCredential
    {
        public override AccessToken GetToken(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            new("not-persisted", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }

    private sealed class FakeIdentitySource : IDevBoxSilentCredentialSource
    {
        public int Calls { get; private set; }

        public Task<(DevBoxIdentityContext Context, TokenCredential Credential, AccessToken Token)> OpenAsync(
            CancellationToken cancellationToken)
        {
            Calls++;
            var credential = new FakeCredential();
            return Task.FromResult((
                Context(),
                (TokenCredential)credential,
                credential.GetToken(new([DevBoxIdentityConstants.Scope]), cancellationToken)));
        }
    }

    private sealed class FakeDiscoveryTransport(params DevBoxDiscoveryPage[] pages)
        : IDevBoxTenantDiscoveryTransport
    {
        private readonly Queue<DevBoxDiscoveryPage> _pages = new(pages);
        public int Calls { get; private set; }
        public Task<DevBoxDiscoveryPage> GetAsync(
            Uri uri,
            AccessToken token,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(_pages.Dequeue());
        }
    }

    private sealed class FakeProjectClientFactory(IDevBoxProjectInventoryClient client)
        : IDevBoxProjectInventoryClientFactory
    {
        public IDevBoxProjectInventoryClient Create(Uri endpoint, TokenCredential credential) => client;
    }

    private sealed class FakeProjectClient(Uri endpoint) : IDevBoxProjectInventoryClient
    {
        public async IAsyncEnumerable<DevBoxPoolDetails> GetPoolsAsync(
            DiscoveredDevCenterProject project,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            yield return new(
                1, endpoint, project.Name, "pool", "westus", "Healthy", "Windows",
                "Enabled", "general", 8, 32, 256, "image", "1", "build",
                DateTimeOffset.UnixEpoch, "Enabled", new(1, "Enabled", 5), false);
        }

        public async IAsyncEnumerable<DevBoxMemberDetails> GetDevBoxesAsync(
            DiscoveredDevCenterProject project,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            yield return new(
                1, endpoint, project.Name, "box", "pool", "westus", "Succeeded",
                "Running", "Windows", "Enabled", "general", 8, 32, 256,
                "image", "1", "build", DateTimeOffset.UnixEpoch, "Enabled",
                DateTimeOffset.UnixEpoch);
        }

    }

    private sealed class StubHandler(
        Func<HttpRequestMessage, HttpResponseMessage> response)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(response(request));
    }
}
