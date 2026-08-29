using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Steward.DevBox.Windows;

public sealed record DevBoxBrokerHttpRequest(
    Uri Uri,
    DevBoxConnectionAudience Audience,
    int MaximumResponseBytes,
    TimeSpan Timeout,
    IReadOnlyList<string> Accept,
    bool AllowSetCookieResponse = false,
    string? UserAgent = null,
    IReadOnlyDictionary<string, string>? RequestHeaders = null)
{
    public override string ToString() =>
        "DevBoxBrokerHttpRequest { Uri = [REDACTED] }";
}

public sealed record DevBoxBrokerHttpResponse(
    HttpStatusCode StatusCode,
    Uri ResponseUri,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Headers,
    byte[] Content)
{
    public override string ToString() =>
        "DevBoxBrokerHttpResponse { Uri = [REDACTED], Content = [REDACTED] }";
}

public interface IDevBoxBrokerHttpTransport
{
    Task<DevBoxBrokerHttpResponse> GetAsync(
        DevBoxBrokerHttpRequest request,
        CancellationToken cancellationToken);
}

public enum DevBoxAvdEndpointDeviceState
{
    Unknown,
    Unavailable,
    Available,
    StartOnConnect,
    SilentlyConnectible,
    Unhealthy
}

public sealed record DevBoxAvdResourceDescriptor(
    string WorkspaceId,
    string ResourceId,
    DevBoxAvdEndpointDeviceState EndpointDeviceState,
    Uri? BrokerRdpContentUri,
    ReadOnlyMemory<byte> BrokerRdpContent)
{
    public override string ToString() =>
        $"DevBoxAvdResourceDescriptor " +
        $"{{ EndpointDeviceState = {EndpointDeviceState}, " +
        $"Resource = [REDACTED], RdpContent = [REDACTED] }}";
}

public interface IDevBoxAvdResourceCatalog
{
    Task<IReadOnlyList<DevBoxAvdResourceDescriptor>> ListAsync(
        CancellationToken cancellationToken);
}

public sealed class HttpDevBoxAvdResourceCatalog(
    Uri discoveryUri,
    IDevBoxBrokerHttpTransport transport,
    string userAgent) : IDevBoxAvdResourceCatalog
{
    public async Task<IReadOnlyList<DevBoxAvdResourceDescriptor>> ListAsync(
        CancellationToken cancellationToken)
    {
        var discovery = await GetAsync(
                discoveryUri,
                ["application/x-msts-radc-discovery+xml"],
                cancellationToken)
            .ConfigureAwait(false);
        var feeds = ParseDiscovery(discovery.Content);
        var resources = new List<DevBoxAvdResourceDescriptor>();
        foreach (var feed in feeds)
        {
            var response = await GetAsync(
                    feed,
                    ["application/x-msts-radc+xml"],
                    cancellationToken)
                .ConfigureAwait(false);
            ParseWorkspace(
                feed,
                response.Content,
                resources);
        }
        return resources;
    }

    private async Task<DevBoxBrokerHttpResponse> GetAsync(
        Uri uri,
        IReadOnlyList<string> accept,
        CancellationToken cancellationToken)
    {
        var response = await transport.GetAsync(
                new(
                    uri,
                    DevBoxConnectionAudience.AzureVirtualDesktop,
                    4 * 1024 * 1024,
                    TimeSpan.FromMinutes(1),
                    accept,
                    AllowSetCookieResponse: true,
                    UserAgent: userAgent),
                cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new InvalidDataException(
                "The authenticated AVD feed request was unsuccessful.");
        return response;
    }

    private static IReadOnlyList<Uri> ParseDiscovery(byte[] content)
    {
        try
        {
            var document = ParseXml(content);
            var feeds = document
                .Descendants()
                .Where(element =>
                    element.Name.LocalName == "TenantFeedURL")
                .Select(element =>
                    element.Attribute("FeedURL")?.Value)
                .Select(value =>
                    Uri.TryCreate(value, UriKind.Absolute, out var uri)
                        ? uri
                        : null)
                .ToArray();
            if (feeds.Length is 0 or > 16 ||
                feeds.Any(uri => uri is null) ||
                feeds.Distinct().Count() != feeds.Length)
                throw new InvalidDataException(
                    "AVD discovery returned invalid workspace feeds.");
            return feeds.Select(uri => uri!).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    private static void ParseWorkspace(
        Uri feedUri,
        byte[] content,
        List<DevBoxAvdResourceDescriptor> destination)
    {
        try
        {
            var document = ParseXml(content);
            var publishers = document
                .Descendants()
                .Where(element =>
                    element.Name.LocalName == "Publisher")
                .ToArray();
            if (publishers.Length != 1)
                throw new InvalidDataException(
                    "An AVD workspace feed must contain one publisher.");
            var workspaceId = publishers[0].Attribute("ID")?.Value;
            if (string.IsNullOrWhiteSpace(workspaceId) ||
                workspaceId.Length > 4096)
                throw new InvalidDataException(
                    "The AVD workspace publisher ID is invalid.");
            foreach (var resource in publishers[0]
                         .Descendants()
                         .Where(element =>
                             element.Name.LocalName == "Resource"))
            {
                if (destination.Count >= 1024)
                    throw new InvalidDataException(
                        "AVD feeds exceed the resource bound.");
                var rdpFiles = resource
                    .Descendants()
                    .Where(element =>
                        element.Name.LocalName == "ResourceFile" &&
                        string.Equals(
                            element.Attribute("FileExtension")?.Value,
                            ".rdp",
                            StringComparison.OrdinalIgnoreCase))
                    .Select(element => element.Attribute("URL")?.Value)
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
                if (rdpFiles.Length != 1 ||
                    !Uri.TryCreate(
                        feedUri,
                        rdpFiles[0],
                        out var rdpUri))
                    continue;
                var state = ParseDeviceState(
                    resource.Attribute("DeviceState")?.Value);
                if (state !=
                    DevBoxAvdEndpointDeviceState.SilentlyConnectible)
                    continue;
                var resourceIds = new[]
                    {
                        resource.Attribute("ArmPath")?.Value,
                        resource.Attribute("ID")?.Value
                    }
                    .Where(value =>
                        !string.IsNullOrWhiteSpace(value) &&
                        value.Length <= 4096)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
                foreach (var resourceId in resourceIds)
                    destination.Add(new(
                        workspaceId,
                        resourceId!,
                        state,
                        rdpUri,
                        ReadOnlyMemory<byte>.Empty));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    private static DevBoxAvdEndpointDeviceState ParseDeviceState(
        string? value) =>
        value?.ToLowerInvariant() switch
        {
            "available" or "ready" or "running" =>
                DevBoxAvdEndpointDeviceState.SilentlyConnectible,
            "startonconnect" or "startvmonconnect" =>
                DevBoxAvdEndpointDeviceState.StartOnConnect,
            "unhealthy" => DevBoxAvdEndpointDeviceState.Unhealthy,
            _ => DevBoxAvdEndpointDeviceState.Unknown
        };

    private static XDocument ParseXml(byte[] content)
    {
        using var stream = new MemoryStream(content, writable: false);
        using var reader = XmlReader.Create(
            stream,
            new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 4 * 1024 * 1024,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true
            });
        return XDocument.Load(reader, LoadOptions.None);
    }
}

public sealed class HttpDevBoxBrokerHttpTransport : IDevBoxBrokerHttpTransport,
    IDisposable
{
    private readonly DevBoxConnectionIdentityService identity;
    private readonly HttpMessageInvoker invoker;
    private bool disposed;

    public HttpDevBoxBrokerHttpTransport(
        DevBoxConnectionIdentityService identity)
    {
        this.identity = identity;
        invoker = new HttpMessageInvoker(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        });
    }

    public async Task<DevBoxBrokerHttpResponse> GetAsync(
        DevBoxBrokerHttpRequest request,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ValidateRequest(request);
        using var message = new HttpRequestMessage(HttpMethod.Get, request.Uri);
        foreach (var accept in request.Accept)
            message.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue(accept));
        if (request.UserAgent is not null)
            message.Headers.TryAddWithoutValidation(
                "x-ms-user-agent",
                request.UserAgent);
        if (request.RequestHeaders is not null)
        {
            foreach (var header in request.RequestHeaders)
                message.Headers.Add(header.Key, header.Value);
        }
        var token = await identity.AcquireTokenAsync(
            request.Audience,
            cancellationToken).ConfigureAwait(false);
        message.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token.Token);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(request.Timeout);
        using var response = await invoker.SendAsync(
            message,
            timeout.Token).ConfigureAwait(false);
        var responseUri = response.RequestMessage?.RequestUri
            ?? throw new InvalidDataException(
                "The broker response did not identify its request URI.");
        var headers = response.Headers
            .Concat(response.Content.Headers)
            .GroupBy(
                item => item.Key,
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<string>)group
                    .SelectMany(item => item.Value)
                    .ToArray(),
                StringComparer.OrdinalIgnoreCase);
        ValidateResponseHeaders(
            request,
            response.StatusCode,
            responseUri,
            headers,
            response.Content.Headers.ContentLength);
        var content = await ReadBoundedAsync(
            response.Content,
            request.MaximumResponseBytes,
            timeout.Token).ConfigureAwait(false);
        return new(
            response.StatusCode,
            responseUri,
            headers,
            content);
    }

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        invoker.Dispose();
    }

    private static void ValidateRequest(DevBoxBrokerHttpRequest request)
    {
        var validAudience =
            request.Audience ==
                DevBoxConnectionAudience.AzureVirtualDesktop &&
            IsAvdBrokerUri(request.Uri) ||
            request.Audience ==
                DevBoxConnectionAudience.Windows365EndUser &&
            IsWindows365EndUserUri(request.Uri);
        if (!validAudience)
            throw new ArgumentException(
                "The broker request audience and host do not match.",
                nameof(request));
        if (request.MaximumResponseBytes is <= 0 or > 4 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "The broker response bound is unsupported.");
        if (request.Timeout <= TimeSpan.Zero ||
            request.Timeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "The broker request timeout is unsupported.");
        if (request.Accept.Count is 0 or > 4)
            throw new ArgumentException(
                "The broker request must have a bounded Accept allowlist.",
                nameof(request));
        if (request.UserAgent is not null &&
            (request.UserAgent.Length is 0 or > 128 ||
             request.UserAgent.Any(character =>
                 !char.IsAsciiLetterOrDigit(character) &&
                 character is not '.' and not '-' and not '_' and not '/')))
            throw new ArgumentException(
                "The broker user agent is invalid.",
                nameof(request));
        if (request.RequestHeaders is { Count: > 4 } ||
            request.RequestHeaders?.Any(header =>
                !AllowedRequestHeaders.Contains(header.Key) ||
                header.Value.Length is 0 or > 128 ||
                header.Value.Any(char.IsControl)) == true)
            throw new ArgumentException(
                "The broker request headers are invalid.",
                nameof(request));
    }

    private static void ValidateResponseHeaders(
        DevBoxBrokerHttpRequest request,
        HttpStatusCode status,
        Uri responseUri,
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        long? contentLength)
    {
        if (responseUri != request.Uri)
            throw new InvalidDataException(
                "The broker HTTP transport followed an unexpected redirect.");
        if ((int)status is >= 300 and < 400)
            throw new InvalidDataException(
                "The broker service returned a redirect.");
        if (!request.AllowSetCookieResponse &&
            HasHeader(headers, "Set-Cookie"))
            throw new InvalidDataException(
                "The broker service attempted to set a cookie.");
        var encodings = HeaderValues(headers, "Content-Encoding");
        if (encodings.Count != 0 &&
            encodings.Any(value =>
                !string.Equals(
                    value,
                    "identity",
                    StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException(
                "The broker service returned compressed content.");
        if (contentLength > request.MaximumResponseBytes)
            throw new InvalidDataException(
                "The broker response exceeds its size limit.");
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        await using var source = await content.ReadAsStreamAsync(
            cancellationToken).ConfigureAwait(false);
        using var destination = new MemoryStream(
            Math.Min(maximumBytes, 16 * 1024));
        var buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(
                    buffer.AsMemory(0, buffer.Length),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    return destination.ToArray();
                if (destination.Length + read > maximumBytes)
                    throw new InvalidDataException(
                        "The broker response exceeds its size limit.");
                destination.Write(buffer, 0, read);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool IsAvdBrokerUri(Uri uri) =>
        uri.IsAbsoluteUri &&
        uri.Scheme == Uri.UriSchemeHttps &&
        uri.Port == 443 &&
        uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 &&
        (string.Equals(
                uri.IdnHost,
                "wvd.microsoft.com",
                StringComparison.OrdinalIgnoreCase) ||
            uri.IdnHost.EndsWith(
                ".wvd.microsoft.com",
                StringComparison.OrdinalIgnoreCase));

    private static bool IsWindows365EndUserUri(Uri uri) =>
        uri.IsAbsoluteUri &&
        uri.Scheme == Uri.UriSchemeHttps &&
        uri.Port == 443 &&
        uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 &&
        string.Equals(
            uri.IdnHost,
            "windows365.microsoft.com",
            StringComparison.OrdinalIgnoreCase) &&
        uri.AbsolutePath.StartsWith(
            "/u/api/",
            StringComparison.Ordinal);

    private static readonly HashSet<string> AllowedRequestHeaders =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "source-client",
            "client-version",
            "cpc-data-boundary"
        };

    private static bool HasHeader(
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        string name) =>
        headers.Keys.Any(key =>
            string.Equals(
                key,
                name,
                StringComparison.OrdinalIgnoreCase));

    private static IReadOnlyList<string> HeaderValues(
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        string name)
    {
        foreach (var item in headers)
        {
            if (string.Equals(
                    item.Key,
                    name,
                    StringComparison.OrdinalIgnoreCase))
                return item.Value;
        }
        return [];
    }
}

public sealed record DevBoxBrokerFeedResolverOptions
{
    public IReadOnlyList<string> AllowedBrokerDomains { get; init; } =
        ["wvd.microsoft.com"];

    public int MaximumResources { get; init; } = 256;
    public int MaximumRdpBytes { get; init; } = 1024 * 1024;
    public TimeSpan CatalogTimeout { get; init; } =
        TimeSpan.FromSeconds(15);
    public TimeSpan RdpTimeout { get; init; } =
        TimeSpan.FromSeconds(15);
    public Action<string>? DiagnosticSink { get; init; }
    public string? UserAgent { get; init; }
    public bool AllowSetCookieResponse { get; init; }
}

public sealed class SensitiveDevBoxBrokerResult : IDisposable
{
    private byte[]? rdpContent;
    private int opened;

    internal SensitiveDevBoxBrokerResult(
        string resourceId,
        string workspaceId,
        DevBoxAvdEndpointDeviceState endpointDeviceState,
        string brokerHost,
        byte[] rdpContent)
    {
        ResourceId = resourceId;
        WorkspaceId = workspaceId;
        EndpointDeviceState = endpointDeviceState;
        BrokerHost = brokerHost;
        this.rdpContent = rdpContent;
    }

    public string ResourceId { get; }
    public string WorkspaceId { get; }
    public DevBoxAvdEndpointDeviceState EndpointDeviceState { get; }
    public string BrokerHost { get; }
    public int RdpContentLength =>
        rdpContent?.Length ??
        throw new ObjectDisposedException(nameof(SensitiveDevBoxBrokerResult));

    public Stream OpenRdpContent()
    {
        var content = rdpContent ??
            throw new ObjectDisposedException(
                nameof(SensitiveDevBoxBrokerResult));
        if (Interlocked.Exchange(ref opened, 1) != 0)
            throw new InvalidOperationException(
                "The broker RDP content is single-use.");
        return new MemoryStream(content, writable: false);
    }

    public void Dispose()
    {
        var content = Interlocked.Exchange(ref rdpContent, null);
        if (content is not null)
            CryptographicOperations.ZeroMemory(content);
        GC.SuppressFinalize(this);
    }

    public override string ToString() =>
        $"SensitiveDevBoxBrokerResult " +
        $"{{ ResourceId = [REDACTED], WorkspaceId = [REDACTED], " +
        $"EndpointDeviceState = {EndpointDeviceState}, " +
        $"BrokerHost = {BrokerHost}, RdpContent = [REDACTED] }}";
}

public sealed class DevBoxBrokerFeedResolver
{
    private readonly IDevBoxConnectionIdentityGate identity;
    private readonly IDevBoxAvdResourceCatalog catalog;
    private readonly IDevBoxBrokerHttpTransport transport;
    private readonly DevBoxBrokerFeedResolverOptions options;
    private readonly string[] allowedDomains;

    public DevBoxBrokerFeedResolver(
        IDevBoxConnectionIdentityGate identity,
        IDevBoxAvdResourceCatalog catalog,
        IDevBoxBrokerHttpTransport transport,
        DevBoxBrokerFeedResolverOptions? options = null)
    {
        this.identity = identity;
        this.catalog = catalog;
        this.transport = transport;
        this.options = options ?? new();
        ValidateOptions(this.options);
        allowedDomains = this.options.AllowedBrokerDomains
            .Select(domain => domain.Trim().TrimStart('.'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<SensitiveDevBoxBrokerResult> ResolveAsync(
        Uri providerResource,
        CancellationToken cancellationToken)
    {
        var target = ParseProviderResource(providerResource);
        var identityStatus = await identity.StatusAsync(
            cancellationToken).ConfigureAwait(false);
        if (identityStatus.Outcome != DevBoxConnectionIdentityOutcome.Ready)
            throw new DevBoxConnectionIdentityException(
                identityStatus.Outcome,
                identityStatus.Problem ??
                    "The connection identity is not ready.");

        IReadOnlyList<DevBoxAvdResourceDescriptor> resources;
        using (var timeout =
               CancellationTokenSource.CreateLinkedTokenSource(
                   cancellationToken))
        {
            timeout.CancelAfter(options.CatalogTimeout);
            resources = await catalog.ListAsync(timeout.Token)
                .WaitAsync(timeout.Token).ConfigureAwait(false)
                ?? throw new InvalidDataException(
                    "The AVD resource catalog returned no collection.");
        }
        if (resources.Count > options.MaximumResources)
            throw new InvalidDataException(
                "The AVD resource catalog exceeded its resource bound.");
        foreach (var resource in resources)
        {
            if (resource is null)
                throw new InvalidDataException(
                    "The AVD resource catalog returned a null descriptor.");
            ValidateDescriptor(resource);
        }
        var matches = resources
            .Where(resource =>
                string.Equals(
                    resource.ResourceId,
                    target.ResourceId,
                    StringComparison.Ordinal) &&
                string.Equals(
                    resource.WorkspaceId,
                    target.WorkspaceId,
                    StringComparison.Ordinal))
            .ToArray();
        options.DiagnosticSink?.Invoke(
            $"catalog-count-{resources.Count}-" +
            $"workspace-matches-{resources.Count(resource =>
                string.Equals(
                    resource.WorkspaceId,
                    target.WorkspaceId,
                    StringComparison.Ordinal))}-" +
            $"resource-matches-{resources.Count(resource =>
                string.Equals(
                    resource.ResourceId,
                    target.ResourceId,
                    StringComparison.Ordinal))}-" +
            $"exact-matches-{matches.Length}");
        var descriptor = matches.Length switch
        {
            1 => matches[0],
            0 => throw new InvalidDataException(
                "The AVD catalog did not return the provider-issued resource."),
            _ => throw new InvalidDataException(
                "The AVD catalog returned an ambiguous provider-issued resource.")
        };

        byte[] content;
        var brokerHost = "catalog";
        if (descriptor.BrokerRdpContentUri is { } contentUri)
        {
            try
            {
                ValidateSignedRdpUri(contentUri);
            }
            catch (Exception exception)
            {
                options.DiagnosticSink?.Invoke(
                    $"rdp-uri-failed-{exception.GetType().Name}-" +
                    exception.Message.Replace(' ', '_'));
                throw;
            }
            options.DiagnosticSink?.Invoke("rdp-uri-valid");
            brokerHost = contentUri.IdnHost;
            DevBoxBrokerHttpResponse response;
            try
            {
                response = await GetAsync(
                    new(
                        contentUri,
                        DevBoxConnectionAudience.AzureVirtualDesktop,
                        options.MaximumRdpBytes,
                        options.RdpTimeout,
                        [
                            "application/x-rdp",
                            "application/octet-stream",
                            "text/plain"
                        ],
                        AllowSetCookieResponse:
                            options.AllowSetCookieResponse,
                        UserAgent: options.UserAgent),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                options.DiagnosticSink?.Invoke(
                    $"rdp-fetch-failed-{exception.GetType().Name}-" +
                    exception.Message.Replace(' ', '_'));
                throw;
            }
            options.DiagnosticSink?.Invoke(
                $"rdp-fetch-status-{(int)response.StatusCode}");
            try
            {
                ValidateResponse(
                    response,
                    contentUri,
                    options.MaximumRdpBytes,
                    [
                        "application/x-rdp",
                        "application/octet-stream",
                        "text/plain"
                    ],
                    allowSetCookieResponse:
                        options.AllowSetCookieResponse);
            }
            catch (Exception exception)
            {
                options.DiagnosticSink?.Invoke(
                    $"rdp-response-failed-{exception.GetType().Name}-" +
                    exception.Message.Replace(' ', '_') +
                    "-content-type-" +
                    string.Join(
                        '_',
                        response.Headers.GetValueOrDefault(
                            "Content-Type") ?? []));
                throw;
            }
            options.DiagnosticSink?.Invoke("rdp-response-valid");
            content = response.Content;
        }
        else
        {
            content = descriptor.BrokerRdpContent.ToArray();
        }

        try
        {
            byte[] normalized;
            try
            {
                normalized = NormalizeRdp(content);
            }
            catch (Exception exception)
            {
                options.DiagnosticSink?.Invoke(
                    $"rdp-normalize-failed-{exception.GetType().Name}-" +
                    exception.Message.Replace(' ', '_') +
                    $"-bytes-{content.Length}-keys-" +
                    string.Join(',', RdpSettingNames(content)));
                throw;
            }
            options.DiagnosticSink?.Invoke(
                $"rdp-normalized-{normalized.Length}");
            return new(
                target.ResourceId,
                target.WorkspaceId,
                descriptor.EndpointDeviceState,
                brokerHost,
                normalized);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    internal static DevBoxBrokerTarget ParseProviderResource(Uri value)
    {
        var classified =
            DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(value);
        if (classified.Kind !=
            DevBoxProviderRdpKind.WindowsAppResource)
            throw new InvalidDataException(
                "The provider resource is not a supported Windows App resource.");
        var values = ParseQuery(value.Query);
        return new(
            values["resourceId"],
            values["workspaceId"]);
    }

    private async Task<DevBoxBrokerHttpResponse> GetAsync(
        DevBoxBrokerHttpRequest request,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(request.Timeout);
        return await transport.GetAsync(request, timeout.Token)
            .WaitAsync(timeout.Token)
            .ConfigureAwait(false);
    }

    private void ValidateDescriptor(DevBoxAvdResourceDescriptor descriptor)
    {
        if (string.IsNullOrWhiteSpace(descriptor.ResourceId) ||
            descriptor.ResourceId.Length > 4096 ||
            string.IsNullOrWhiteSpace(descriptor.WorkspaceId) ||
            descriptor.WorkspaceId.Length > 4096 ||
            descriptor.EndpointDeviceState !=
                DevBoxAvdEndpointDeviceState.SilentlyConnectible)
            throw new InvalidDataException(
                "The AVD catalog returned an invalid resource descriptor.");
        var hasUri = descriptor.BrokerRdpContentUri is not null;
        var hasContent = !descriptor.BrokerRdpContent.IsEmpty;
        if (hasUri == hasContent)
            throw new InvalidDataException(
                "The AVD resource must contain exactly one broker RDP content source.");
        if (descriptor.BrokerRdpContent.Length > options.MaximumRdpBytes)
            throw new InvalidDataException(
                "The AVD catalog RDP content exceeds its size limit.");
    }

    private void ValidateSignedRdpUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.Port != 443 ||
            uri.UserInfo.Length != 0 ||
            uri.Fragment.Length != 0 ||
            string.IsNullOrWhiteSpace(uri.Query) ||
            uri.OriginalString.Length >
                DevBoxRemoteViewingValidator.MaximumActivationUriCharacters ||
            !IsAllowedBrokerHost(uri.IdnHost))
            throw new InvalidDataException(
                "The AVD catalog returned an invalid broker RDP content link.");
    }

    private bool IsAllowedBrokerHost(string host) =>
        allowedDomains.Any(domain =>
            string.Equals(
                host,
                domain,
                StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(
                "." + domain,
                StringComparison.OrdinalIgnoreCase));

    private static void ValidateResponse(
        DevBoxBrokerHttpResponse response,
        Uri requestedUri,
        int maximumBytes,
        IReadOnlyList<string> contentTypes,
        bool allowSetCookieResponse = false)
    {
        if (response.ResponseUri != requestedUri)
            throw new InvalidDataException(
                "The broker HTTP transport followed an unexpected redirect.");
        if ((int)response.StatusCode is >= 300 and < 400)
            throw new InvalidDataException(
                "The broker service returned a redirect.");
        if (response.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException(
                $"The broker service returned HTTP {(int)response.StatusCode}.");
        if (response.Content.Length > maximumBytes)
            throw new InvalidDataException(
                "The broker response exceeds its size limit.");
        if (!allowSetCookieResponse &&
            HasHeader(response.Headers, "Set-Cookie"))
            throw new InvalidDataException(
                "The broker service attempted to set a cookie.");
        var encodings = HeaderValues(
            response.Headers,
            "Content-Encoding");
        if (encodings.Count != 0 &&
            encodings.Any(value =>
                !string.Equals(
                    value,
                    "identity",
                    StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException(
                "The broker service returned compressed content.");
        var contentType = ContentType(response);
        if (!contentTypes.Contains(
                contentType,
                StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "The broker response content type is unsupported.");
    }

    private static string ContentType(
        DevBoxBrokerHttpResponse response)
    {
        var values = HeaderValues(response.Headers, "Content-Type");
        if (values.Count != 1 ||
            !MediaTypeHeaderValue.TryParse(
                values[0],
                out var contentType) ||
            string.IsNullOrWhiteSpace(contentType.MediaType))
            throw new InvalidDataException(
                "The broker response content type is missing or invalid.");
        return contentType.MediaType;
    }

    private static bool HasHeader(
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        string name) =>
        headers.Keys.Any(key =>
            string.Equals(
                key,
                name,
                StringComparison.OrdinalIgnoreCase));

    private static IReadOnlyList<string> HeaderValues(
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        string name)
    {
        foreach (var item in headers)
        {
            if (string.Equals(
                    item.Key,
                    name,
                    StringComparison.OrdinalIgnoreCase))
                return item.Value;
        }
        return [];
    }

    private static byte[] NormalizeRdp(byte[] content)
    {
        var text = DecodeRdp(content);
        var values = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase);
        var lines = text.Split(["\r\n", "\n"], StringSplitOptions.None);
        if (lines.Length > 2048)
            throw new InvalidDataException(
                "The signed RDP content contains too many settings.");
        foreach (var line in lines)
        {
            if (line.Length == 0)
                continue;
            if (line.Length > 64 * 1024)
                throw new InvalidDataException(
                    "The signed RDP content contains an oversized setting.");
            var first = line.IndexOf(':');
            var second = first < 0
                ? -1
                : line.IndexOf(':', first + 1);
            if (first <= 0 || second <= first + 1)
                throw new InvalidDataException(
                    "The signed RDP content contains an invalid setting.");
            var name = line[..first].Trim();
            var type = line[(first + 1)..second];
            var value = line[(second + 1)..];
            if (name.Length == 0 ||
                type is not ("i" or "s") ||
                !values.TryAdd(name, value))
                throw new InvalidDataException(
                    "The signed RDP content contains an unsupported setting.");
        }

        if (!values.TryGetValue(
                "authentication level",
                out var authenticationLevel) ||
            authenticationLevel is not ("1" or "2") ||
            !values.TryGetValue("signature", out var signature) ||
            string.IsNullOrWhiteSpace(signature) ||
            !values.TryGetValue("signscope", out var signScope) ||
            !SignedSetting(
                signScope,
                "Authentication Level") ||
            !(values.TryGetValue(
                    "enablecredsspsupport",
                    out var credSsp) &&
                credSsp == "1" &&
                SignedSetting(
                    signScope,
                    "EnableCredSspSupport") ||
              values.TryGetValue(
                    "enablerdsaadauth",
                    out var rdsAadAuth) &&
                rdsAadAuth == "1" &&
                SignedSetting(
                    signScope,
                    "EnableRdsAadAuth")))
            throw new InvalidDataException(
                "The broker RDP content does not require signed RDS authentication.");
        return new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true).GetBytes(text);
    }

    private static IReadOnlyList<string> RdpSettingNames(byte[] content) =>
        DecodeRdp(content)
            .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries)
            .Select(line =>
            {
                var separator = line.IndexOf(':');
                return separator > 0
                    ? line[..separator].Trim()
                    : string.Empty;
            })
            .Where(name =>
                name.Length is > 0 and <= 128 &&
                name.All(character =>
                    char.IsAsciiLetterOrDigit(character) ||
                    character is ' ' or '-' or '_'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static bool SignedSetting(
        string signScope,
        string setting) =>
        signScope.Split(
                ',',
                StringSplitOptions.TrimEntries |
                    StringSplitOptions.RemoveEmptyEntries)
            .Contains(setting, StringComparer.OrdinalIgnoreCase);

    private static string DecodeRdp(byte[] content)
    {
        if (content.Length is 0 or > 4 * 1024 * 1024)
            throw new InvalidDataException(
                "The signed RDP content is empty or oversized.");
        Encoding encoding;
        var offset = 0;
        if (content.AsSpan().StartsWith(Encoding.Unicode.Preamble))
        {
            encoding = Encoding.Unicode;
            offset = Encoding.Unicode.Preamble.Length;
        }
        else if (content.AsSpan().StartsWith(
                     Encoding.BigEndianUnicode.Preamble))
        {
            encoding = Encoding.BigEndianUnicode;
            offset = Encoding.BigEndianUnicode.Preamble.Length;
        }
        else if (content.AsSpan().StartsWith(Encoding.UTF8.Preamble))
        {
            encoding = new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false,
                throwOnInvalidBytes: true);
            offset = Encoding.UTF8.Preamble.Length;
        }
        else
        {
            encoding = new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false,
                throwOnInvalidBytes: true);
        }
        try
        {
            var text = encoding.GetString(
                content,
                offset,
                content.Length - offset);
            if (text.Any(character =>
                    character == '\0' ||
                    (char.IsControl(character) &&
                        character is not '\r' and not '\n' and not '\t')))
                throw new InvalidDataException(
                    "The signed RDP content contains invalid characters.");
            return text;
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException(
                "The signed RDP content encoding is invalid.",
                exception);
        }
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var values = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var part in query.TrimStart('?').Split(
                     '&',
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0 || separator == part.Length - 1)
                throw new InvalidDataException(
                    "The provider resource query is invalid.");
            values.Add(
                Uri.UnescapeDataString(part[..separator]),
                Uri.UnescapeDataString(part[(separator + 1)..]));
        }
        return values;
    }

    private static void ValidateOptions(
        DevBoxBrokerFeedResolverOptions options)
    {
        if (options.AllowedBrokerDomains.Count is 0 or > 8 ||
            options.AllowedBrokerDomains.Any(domain =>
                string.IsNullOrWhiteSpace(domain) ||
                domain.Contains('/') ||
                domain.Contains('\\') ||
                !(string.Equals(
                        domain.Trim().TrimStart('.'),
                        "wvd.microsoft.com",
                        StringComparison.OrdinalIgnoreCase) ||
                    domain.Trim().TrimStart('.').EndsWith(
                        ".wvd.microsoft.com",
                        StringComparison.OrdinalIgnoreCase))))
            throw new ArgumentException(
                "The broker domain allowlist is invalid.",
                nameof(options));
        if (options.UserAgent is not null &&
            (options.UserAgent.Length is 0 or > 128 ||
             options.UserAgent.Any(character =>
                 !char.IsAsciiLetterOrDigit(character) &&
                 character is not '.' and not '-' and not '_' and not '/')))
            throw new ArgumentException(
                "The broker user agent is invalid.",
                nameof(options));
        if (options.MaximumResources is <= 0 or > 1024 ||
            options.MaximumRdpBytes is <= 0 or > 4 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "The broker bounds are unsupported.");
        foreach (var timeout in new[]
                 {
                     options.CatalogTimeout,
                     options.RdpTimeout
                 })
        {
            if (timeout <= TimeSpan.Zero ||
                timeout > TimeSpan.FromMinutes(1))
                throw new ArgumentOutOfRangeException(
                    nameof(options),
                    "The broker timeout is unsupported.");
        }
    }
}

internal sealed record DevBoxBrokerTarget(
    string ResourceId,
    string WorkspaceId);
