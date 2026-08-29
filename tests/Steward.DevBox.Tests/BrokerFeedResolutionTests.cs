using System.Net;
using System.Text;
using System.Text.Json;
using Steward.DevBox.Windows;

namespace Steward.DevBox.Tests;

public sealed class BrokerFeedResolutionTests
{
    private const string ResourceId = "provider-resource";
    private const string WorkspaceId = "provider-workspace";
    private static readonly Uri ProviderResource = new(
        "ms-avd:connect?env=prod&preview=false" +
        $"&resourceId={ResourceId}" +
        "&username=user%40example.test&version=1" +
        $"&workspaceId={WorkspaceId}");
    private static readonly Uri SignedRdpUri = new(
        "https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery/" +
        $"tenants/tenant/rdps/{ResourceId}.rdp?sig=SENSITIVE");

    [Fact]
    public async Task End_user_catalog_maps_exact_direct_launch_to_entity_id()
    {
        var entityId = Guid.NewGuid().ToString();
        var content = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Dedicated = new[]
            {
                new
                {
                    workspaceId = entityId,
                    directLaunchURL = ProviderResource.AbsoluteUri,
                    workspaceName = "box",
                    partnerId = "e3171dd9-9a5f-e5be-b36c-cc7c4f3f3bcf"
                }
            },
            Flex = Array.Empty<object>(),
            FrontlineShared = Array.Empty<object>(),
            Reserve = Array.Empty<object>()
        });
        var transport = new FakeTransport(new DevBoxBrokerHttpResponse(
            HttpStatusCode.OK,
            new Uri("https://windows365.microsoft.com/u/api/v2/cloudPCs"),
            Headers("application/json"),
            content));
        var catalog = new Windows365EndUserResourceCatalog(
            transport,
            "2.0.1315.0",
            "box");

        var resolved = await catalog.ResolveEntityIdAsync(
            ProviderResource,
            CancellationToken.None);

        Assert.Equal(entityId, resolved);
        var request = Assert.Single(transport.Requests);
        Assert.Equal(
            DevBoxConnectionAudience.Windows365EndUser,
            request.Audience);
        Assert.Equal("NxtClient", request.RequestHeaders!["source-client"]);
        Assert.Equal(
            "commercial",
            request.RequestHeaders["cpc-data-boundary"]);
    }

    [Fact]
    public async Task End_user_catalog_rejects_nonmatching_direct_launch()
    {
        var content = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Dedicated = new[]
            {
                new
                {
                    workspaceId = Guid.NewGuid().ToString(),
                    directLaunchURL =
                        "ms-avd:connect?resourceid=other&workspaceId=other",
                    workspaceName = "other-box",
                    partnerId = "e3171dd9-9a5f-e5be-b36c-cc7c4f3f3bcf"
                }
            }
        });
        var catalog = new Windows365EndUserResourceCatalog(
            new FakeTransport(new DevBoxBrokerHttpResponse(
                HttpStatusCode.OK,
                new Uri(
                    "https://windows365.microsoft.com/u/api/v2/cloudPCs"),
                Headers("application/json"),
                content)),
            "2.0.1315.0",
            "box");

        await Assert.ThrowsAsync<InvalidDataException>(
            () => catalog.ResolveEntityIdAsync(
                ProviderResource,
                CancellationToken.None));
    }

    [Fact]
    public async Task Resolves_exact_avd_catalog_tuple_without_windows365_dependency()
    {
        var catalog = new FakeCatalog(
            Descriptor(link: SignedRdpUri));
        var transport = new FakeTransport(
            Rdp(SignedRdpUri, ValidRdp()));
        var resolver = Resolver(catalog, transport);

        using var result = await resolver.ResolveAsync(
            ProviderResource,
            default);

        Assert.Equal(ResourceId, result.ResourceId);
        Assert.Equal(WorkspaceId, result.WorkspaceId);
        Assert.Equal(
            DevBoxAvdEndpointDeviceState.SilentlyConnectible,
            result.EndpointDeviceState);
        Assert.Equal("rdweb.wvd.microsoft.com", result.BrokerHost);
        Assert.Equal(1, catalog.Calls);
        var request = Assert.Single(transport.Requests);
        Assert.Equal(
            DevBoxConnectionAudience.AzureVirtualDesktop,
            request.Audience);
        Assert.Equal(SignedRdpUri, request.Uri);
        Assert.DoesNotContain(
            transport.Requests,
            request => request.Uri.IdnHost.Contains(
                "windows365",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Accepts_validated_inline_catalog_rdp_without_http()
    {
        var transport = new FakeTransport();
        var resolver = Resolver(
            new FakeCatalog(
                Descriptor(content: Encoding.UTF8.GetBytes(ValidRdp()))),
            transport);

        using var result = await resolver.ResolveAsync(
            ProviderResource,
            default);

        Assert.Equal("catalog", result.BrokerHost);
        Assert.Empty(transport.Requests);
        using var content = result.OpenRdpContent();
        using var reader = new StreamReader(content, Encoding.UTF8);
        Assert.Contains(
            "enablecredsspsupport:i:1",
            await reader.ReadToEndAsync(default));
        Assert.Throws<InvalidOperationException>(
            result.OpenRdpContent);
    }

    [Fact]
    public async Task Normalizes_utf16_catalog_rdp_for_rdcore()
    {
        var text = ValidRdp();
        var content = Encoding.Unicode.Preamble.ToArray()
            .Concat(Encoding.Unicode.GetBytes(text))
            .ToArray();
        using var result = await Resolver(
                new FakeCatalog(Descriptor(content: content)),
                new FakeTransport())
            .ResolveAsync(ProviderResource, default);
        using var stream = result.OpenRdpContent();
        using var reader = new StreamReader(
            stream,
            new UTF8Encoding(false, true),
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 1024,
            leaveOpen: false);

        Assert.Equal(text, await reader.ReadToEndAsync(default));
    }

    [Fact]
    public async Task Rejects_ambiguous_avd_catalog_tuple()
    {
        var catalog = new FakeCatalog(
            Descriptor(content: Encoding.UTF8.GetBytes(ValidRdp())),
            Descriptor(content: Encoding.UTF8.GetBytes(ValidRdp())));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            Resolver(catalog, new FakeTransport()).ResolveAsync(
                ProviderResource,
                default));
    }

    [Fact]
    public async Task Rejects_account_mismatch_before_catalog_resolution()
    {
        var identity = new FakeIdentityGate(
            DevBoxConnectionIdentityOutcome.AccountMismatch);
        var catalog = new FakeCatalog(
            Descriptor(content: Encoding.UTF8.GetBytes(ValidRdp())));
        var transport = new FakeTransport();
        var resolver = new DevBoxBrokerFeedResolver(
            identity,
            catalog,
            transport);

        var exception = await Assert.ThrowsAsync<
            DevBoxConnectionIdentityException>(() =>
            resolver.ResolveAsync(ProviderResource, default));

        Assert.Equal(
            DevBoxConnectionIdentityOutcome.AccountMismatch,
            exception.Outcome);
        Assert.Equal(0, catalog.Calls);
        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task Rejects_interaction_required_before_catalog_resolution()
    {
        var identity = new FakeIdentityGate(
            DevBoxConnectionIdentityOutcome.InteractionRequired);
        var catalog = new FakeCatalog(
            Descriptor(content: Encoding.UTF8.GetBytes(ValidRdp())));

        var exception = await Assert.ThrowsAsync<
            DevBoxConnectionIdentityException>(() =>
            new DevBoxBrokerFeedResolver(
                    identity,
                    catalog,
                    new FakeTransport())
                .ResolveAsync(ProviderResource, default));

        Assert.Equal(
            DevBoxConnectionIdentityOutcome.InteractionRequired,
            exception.Outcome);
        Assert.Equal(0, catalog.Calls);
    }

    [Fact]
    public async Task Disposal_zeroes_sensitive_catalog_content_copy()
    {
        var source = Encoding.UTF8.GetBytes(ValidRdp());
        var result = await Resolver(
                new FakeCatalog(Descriptor(content: source)),
                new FakeTransport())
            .ResolveAsync(ProviderResource, default);
        var stream = result.OpenRdpContent();

        result.Dispose();

        Assert.Throws<ObjectDisposedException>(() => result.OpenRdpContent());
        var bytes = new byte[stream.Length];
        _ = stream.Read(bytes);
        Assert.All(bytes, value => Assert.Equal(0, value));
        Assert.Contains(source, value => value != 0);
        stream.Dispose();
    }

    [Theory]
    [InlineData("https://attacker.example/profile.rdp?sig=SENSITIVE")]
    [InlineData("http://rdweb.wvd.microsoft.com/profile.rdp?sig=SENSITIVE")]
    [InlineData("https://rdweb.wvd.microsoft.com/profile.rdp")]
    public async Task Rejects_invalid_catalog_rdp_links(string value)
    {
        var catalog = new FakeCatalog(
            Descriptor(link: new Uri(value)));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            Resolver(catalog, new FakeTransport()).ResolveAsync(
                ProviderResource,
                default));
    }

    [Theory]
    [InlineData("Set-Cookie", "session=surprise")]
    [InlineData("Content-Encoding", "gzip")]
    public async Task Rejects_cookie_and_compression_responses(
        string header,
        string value)
    {
        var response = Rdp(SignedRdpUri, ValidRdp()) with
        {
            Headers = Headers("application/x-rdp", header, value)
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            Resolver(
                    new FakeCatalog(Descriptor(link: SignedRdpUri)),
                    new FakeTransport(response))
                .ResolveAsync(ProviderResource, default));
    }

    [Fact]
    public async Task Rejects_redirects_before_following_them()
    {
        var response = Rdp(SignedRdpUri, ValidRdp()) with
        {
            StatusCode = HttpStatusCode.Redirect
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            Resolver(
                    new FakeCatalog(Descriptor(link: SignedRdpUri)),
                    new FakeTransport(response))
                .ResolveAsync(ProviderResource, default));
    }

    [Theory]
    [InlineData("authentication level:i:0")]
    [InlineData("enablecredsspsupport:i:0")]
    [InlineData("signature:s:")]
    [InlineData("signscope:s:Full Address")]
    public async Task Rejects_rdp_without_signed_rds_authentication(
        string replacement)
    {
        var lines = ValidRdp().Split("\r\n").ToList();
        var name = replacement[..replacement.IndexOf(':')];
        var index = lines.FindIndex(line =>
            line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase));
        lines[index] = replacement;
        var catalog = new FakeCatalog(
            Descriptor(
                content: Encoding.UTF8.GetBytes(
                    string.Join("\r\n", lines))));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            Resolver(catalog, new FakeTransport()).ResolveAsync(
                ProviderResource,
                default));
    }

    [Fact]
    public async Task Enforces_catalog_resource_bound()
    {
        var catalog = new FakeCatalog(
            Descriptor(content: Encoding.UTF8.GetBytes(ValidRdp())),
            new(
                "other-workspace",
                "other-resource",
                DevBoxAvdEndpointDeviceState.SilentlyConnectible,
                null,
                Encoding.UTF8.GetBytes(ValidRdp())));
        var options = new DevBoxBrokerFeedResolverOptions
        {
            MaximumResources = 1
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            Resolver(catalog, new FakeTransport(), options)
                .ResolveAsync(ProviderResource, default));
    }

    [Fact]
    public async Task Rejects_resource_that_is_not_silently_connectible()
    {
        var descriptor = Descriptor(
            content: Encoding.UTF8.GetBytes(ValidRdp())) with
        {
            EndpointDeviceState =
                DevBoxAvdEndpointDeviceState.Available
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            Resolver(
                    new FakeCatalog(descriptor),
                    new FakeTransport())
                .ResolveAsync(ProviderResource, default));
    }

    [Fact]
    public async Task Enforces_timeout_when_catalog_does_not_complete()
    {
        var options = new DevBoxBrokerFeedResolverOptions
        {
            CatalogTimeout = TimeSpan.FromMilliseconds(25)
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Resolver(
                    new HangingCatalog(),
                    new FakeTransport(),
                    options)
                .ResolveAsync(ProviderResource, default));
    }

    [Theory]
    [InlineData(
        DevBoxConnectionAudience.Windows365EndUser,
        "https://rdweb.wvd.microsoft.com/profile.rdp?sig=x")]
    [InlineData(
        DevBoxConnectionAudience.AzureVirtualDesktop,
        "https://attacker.example/profile.rdp?sig=x")]
    public async Task Native_broker_transport_rejects_wrong_audience_or_domain(
        DevBoxConnectionAudience audience,
        string uri)
    {
        var directory = Path.Combine(
            AppContext.BaseDirectory,
            "broker-transport-tests",
            Guid.NewGuid().ToString("N"));
        try
        {
            var identity = new DevBoxConnectionIdentityService(
                new DevBoxIdentityStore(
                    Path.Combine(directory, "default")),
                new DevBoxConnectionIdentityStore(
                    Path.Combine(directory, "connection")));
            using var transport =
                new HttpDevBoxBrokerHttpTransport(identity);

            await Assert.ThrowsAsync<ArgumentException>(() =>
                transport.GetAsync(
                    new(
                        new Uri(uri),
                        audience,
                        1024,
                        TimeSpan.FromSeconds(1),
                        ["application/x-rdp"]),
                    default));
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, true);
        }
    }

    private static DevBoxBrokerFeedResolver Resolver(
        IDevBoxAvdResourceCatalog catalog,
        IDevBoxBrokerHttpTransport transport,
        DevBoxBrokerFeedResolverOptions? options = null) =>
        new(
            new FakeIdentityGate(DevBoxConnectionIdentityOutcome.Ready),
            catalog,
            transport,
            options);

    private static DevBoxAvdResourceDescriptor Descriptor(
        Uri? link = null,
        ReadOnlyMemory<byte> content = default) =>
        new(
            WorkspaceId,
            ResourceId,
            DevBoxAvdEndpointDeviceState.SilentlyConnectible,
            link,
            content);

    private static string ValidRdp() =>
        string.Join(
            "\r\n",
            "full address:s:host.example.test",
            "authentication level:i:2",
            "enablecredsspsupport:i:1",
            "signscope:s:Full Address,Authentication Level,EnableCredSspSupport",
            "signature:s:AQAA-SIGNED");

    private static DevBoxBrokerHttpResponse Rdp(
        Uri uri,
        string value) =>
        new(
            HttpStatusCode.OK,
            uri,
            Headers("application/x-rdp"),
            Encoding.UTF8.GetBytes(value));

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> Headers(
        string contentType,
        string? additionalName = null,
        string? additionalValue = null)
    {
        var headers = new Dictionary<string, IReadOnlyList<string>>(
            StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = [contentType]
        };
        if (additionalName is not null)
            headers[additionalName] = [additionalValue!];
        return headers;
    }

    private sealed class FakeIdentityGate(
        DevBoxConnectionIdentityOutcome outcome) :
        IDevBoxConnectionIdentityGate
    {
        public Task<DevBoxConnectionIdentityStatus> StatusAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(
                new DevBoxConnectionIdentityStatus(
                    DevBoxConnectionIdentityConstants.CurrentVersion,
                    DevBoxConnectionIdentityConstants.ContextName,
                    outcome,
                    outcome == DevBoxConnectionIdentityOutcome.Ready,
                    outcome == DevBoxConnectionIdentityOutcome.Ready
                        ? "tenant"
                        : null,
                    outcome == DevBoxConnectionIdentityOutcome.Ready
                        ? "user@example.test"
                        : null,
                    outcome == DevBoxConnectionIdentityOutcome.Ready
                        ? DateTimeOffset.UtcNow.AddMinutes(30)
                        : null,
                    outcome == DevBoxConnectionIdentityOutcome.Ready
                        ? null
                        : "not ready"));
    }

    private sealed class FakeCatalog(
        params DevBoxAvdResourceDescriptor[] resources) :
        IDevBoxAvdResourceCatalog
    {
        public int Calls { get; private set; }

        public Task<IReadOnlyList<DevBoxAvdResourceDescriptor>> ListAsync(
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<
                IReadOnlyList<DevBoxAvdResourceDescriptor>>(resources);
        }
    }

    private sealed class FakeTransport(
        params DevBoxBrokerHttpResponse[] responses)
        : IDevBoxBrokerHttpTransport
    {
        private readonly Queue<DevBoxBrokerHttpResponse> responses =
            new(responses);

        public List<DevBoxBrokerHttpRequest> Requests { get; } = [];

        public Task<DevBoxBrokerHttpResponse> GetAsync(
            DevBoxBrokerHttpRequest request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(responses.Dequeue());
        }
    }

    private sealed class HangingCatalog : IDevBoxAvdResourceCatalog
    {
        public async Task<IReadOnlyList<DevBoxAvdResourceDescriptor>> ListAsync(
            CancellationToken cancellationToken)
        {
            await Task.Delay(
                Timeout.InfiniteTimeSpan,
                cancellationToken);
            throw new InvalidOperationException();
        }
    }
}
