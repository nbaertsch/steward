using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Developer.DevCenter;
using Azure.Developer.DevCenter.Models;

namespace Steward.DevBox.Windows;

public interface IDevBoxTenantDiscoveryTransport
{
    Task<DevBoxDiscoveryPage> GetAsync(
        Uri uri,
        AccessToken token,
        CancellationToken cancellationToken);
}

public sealed record DevBoxDiscoveryPage(
    IReadOnlyList<DevBoxDiscoveryProjectEntry> Projects,
    Uri? NextLink);

public sealed record DevBoxDiscoveryProjectEntry(
    string Name,
    Uri Endpoint,
    string? DisplayName,
    string? Description,
    int? MaximumDevBoxesPerUser,
    IReadOnlyList<string> DeveloperAbilities,
    IReadOnlyList<string> AdminAbilities);

public sealed class HttpDevBoxTenantDiscoveryTransport(HttpClient client)
    : IDevBoxTenantDiscoveryTransport
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<DevBoxDiscoveryPage> GetAsync(
        Uri uri,
        AccessToken token,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using var response = await client.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new InvalidOperationException("The signed-in account cannot discover Dev Center projects.");
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var payload = await JsonSerializer.DeserializeAsync<DiscoveryResponse>(
            stream, Json, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("Dev Center discovery returned an empty response.");
        if (payload.Value is null)
            throw new InvalidDataException("Dev Center discovery returned no project collection.");
        var projects = payload.Value.Select(Convert).ToArray();
        return new(projects, ParseNext(payload.NextLink));
    }

    private static DevBoxDiscoveryProjectEntry Convert(DiscoveryProject item)
    {
        var discoveredUri = ParseProjectUri(item.Uri);
        var name = item.ProjectName ?? item.Name ?? discoveredUri?.ProjectName;
        var endpointText = item.DevCenterUri ??
            item.Properties?.DevCenterUri ??
            discoveredUri?.Endpoint.AbsoluteUri;
        if (string.IsNullOrWhiteSpace(name) ||
            !Uri.TryCreate(endpointText, UriKind.Absolute, out var endpoint))
            throw new InvalidDataException("Dev Center discovery returned an invalid project.");
        return new(
            name,
            endpoint,
            item.DisplayName,
            item.Description ?? item.Properties?.Description,
            item.MaximumDevBoxesPerUser ??
                item.Properties?.MaximumDevBoxesPerUser,
            NormalizeAbilities(item.AbilitiesAsDeveloper),
            NormalizeAbilities(item.AbilitiesAsAdmin));
    }

    private static IReadOnlyList<string> NormalizeAbilities(
        IReadOnlyList<string>? abilities) =>
        (abilities ?? [])
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Distinct(StringComparer.Ordinal)
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static (Uri Endpoint, string ProjectName)? ParseProjectUri(
        string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.Port != 443 ||
            uri.UserInfo.Length != 0)
            throw new InvalidDataException(
                "Dev Center discovery returned an invalid project URI.");
        var segments = uri.AbsolutePath.Trim('/').Split('/');
        if (segments.Length != 2 ||
            !string.Equals(
                segments[0],
                "projects",
                StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(segments[1]))
            throw new InvalidDataException(
                "Dev Center discovery returned an invalid project URI.");
        return (
            new Uri(uri.GetLeftPart(UriPartial.Authority) + "/"),
            Uri.UnescapeDataString(segments[1]));
    }

    private static Uri? ParseNext(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : Uri.TryCreate(value, UriKind.Absolute, out var uri)
                ? uri
                : throw new InvalidDataException("Dev Center discovery returned an invalid nextLink.");

    private sealed record DiscoveryResponse(
        [property: JsonPropertyName("value")] IReadOnlyList<DiscoveryProject> Value,
        [property: JsonPropertyName("nextLink")] string? NextLink);

    private sealed record DiscoveryProject(
        [property: JsonPropertyName("uri")] string? Uri,
        [property: JsonPropertyName("name")] string? Name,
        [property: JsonPropertyName("projectName")] string? ProjectName,
        [property: JsonPropertyName("devCenterUri")] string? DevCenterUri,
        [property: JsonPropertyName("displayName")] string? DisplayName,
        [property: JsonPropertyName("description")] string? Description,
        [property: JsonPropertyName("maxDevBoxesPerUser")] int? MaximumDevBoxesPerUser,
        [property: JsonPropertyName("abilitiesAsDeveloper")]
        IReadOnlyList<string>? AbilitiesAsDeveloper,
        [property: JsonPropertyName("abilitiesAsAdmin")]
        IReadOnlyList<string>? AbilitiesAsAdmin,
        [property: JsonPropertyName("properties")] DiscoveryProjectProperties? Properties);

    private sealed record DiscoveryProjectProperties(
        [property: JsonPropertyName("devCenterUri")] string? DevCenterUri,
        [property: JsonPropertyName("description")] string? Description,
        [property: JsonPropertyName("maxDevBoxesPerUser")] int? MaximumDevBoxesPerUser);
}

public interface IDevBoxProjectInventoryClient
{
    IAsyncEnumerable<DevBoxPoolDetails> GetPoolsAsync(
        DiscoveredDevCenterProject project,
        CancellationToken cancellationToken);
    IAsyncEnumerable<DevBoxMemberDetails> GetDevBoxesAsync(
        DiscoveredDevCenterProject project,
        CancellationToken cancellationToken);
}

public interface IDevBoxProjectInventoryClientFactory
{
    IDevBoxProjectInventoryClient Create(Uri endpoint, TokenCredential credential);
}

public sealed class AzureDevBoxProjectInventoryClientFactory : IDevBoxProjectInventoryClientFactory
{
    public IDevBoxProjectInventoryClient Create(Uri endpoint, TokenCredential credential) =>
        new AzureDevBoxProjectInventoryClient(new DevBoxesClient(endpoint, credential), endpoint);
}

public sealed class AzureDevBoxProjectInventoryClient(
    DevBoxesClient client,
    Uri endpoint) : IDevBoxProjectInventoryClient
{
    public async IAsyncEnumerable<DevBoxPoolDetails> GetPoolsAsync(
        DiscoveredDevCenterProject project,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var pool in client.GetPoolsAsync(project.Name, cancellationToken).ConfigureAwait(false))
            yield return Convert(project, pool, existingMembership: false);
    }

    public async IAsyncEnumerable<DevBoxMemberDetails> GetDevBoxesAsync(
        DiscoveredDevCenterProject project,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var box in client.GetDevBoxesAsync(project.Name, "me", cancellationToken).ConfigureAwait(false))
            yield return Convert(project, box);
    }

    private DevBoxPoolDetails Convert(
        DiscoveredDevCenterProject project,
        DevBoxPool pool,
        bool existingMembership) =>
        new(
            DevBoxIdentityConstants.CurrentVersion,
            endpoint,
            project.Name,
            pool.Name,
            pool.Location,
            pool.HealthStatus.ToString(),
            pool.OSType?.ToString(),
            pool.LocalAdministratorStatus?.ToString(),
            pool.HardwareProfile?.SkuName?.ToString(),
            pool.HardwareProfile?.VCPUs,
            pool.HardwareProfile?.MemoryGB,
            pool.StorageProfile?.OSDisk?.DiskSizeGB,
            pool.ImageReference?.Name,
            pool.ImageReference?.Version,
            pool.ImageReference?.OSBuildNumber,
            pool.ImageReference?.PublishedDate,
            pool.HibernateSupport?.ToString(),
            pool.StopOnDisconnect is null
                ? null
                : new(
                    DevBoxIdentityConstants.CurrentVersion,
                    pool.StopOnDisconnect.Status.ToString(),
                    pool.StopOnDisconnect.GracePeriodMinutes),
            existingMembership);

    private DevBoxMemberDetails Convert(
        DiscoveredDevCenterProject project,
        Azure.Developer.DevCenter.Models.DevBox box) =>
        new(
            DevBoxIdentityConstants.CurrentVersion,
            endpoint,
            project.Name,
            box.Name,
            box.PoolName,
            box.Location,
            box.ProvisioningState?.ToString(),
            box.PowerState?.ToString(),
            box.OSType?.ToString(),
            box.LocalAdministratorStatus?.ToString(),
            box.HardwareProfile?.SkuName?.ToString(),
            box.HardwareProfile?.VCPUs,
            box.HardwareProfile?.MemoryGB,
            box.StorageProfile?.OSDisk?.DiskSizeGB,
            box.ImageReference?.Name,
            box.ImageReference?.Version,
            box.ImageReference?.OSBuildNumber,
            box.ImageReference?.PublishedDate,
            box.HibernateSupport?.ToString(),
            box.CreatedTime);
}

public sealed class DevBoxDiscoveryService(
    IDevBoxSilentCredentialSource identity,
    IDevBoxTenantDiscoveryTransport discovery,
    IDevBoxProjectInventoryClientFactory clients)
{
    public async Task<DevBoxInventory> DiscoverAsync(CancellationToken cancellationToken)
    {
        var (context, credential, token) = await identity.OpenAsync(cancellationToken).ConfigureAwait(false);
        var origin = new Uri(
            $"https://{context.TenantId.ToLowerInvariant()}.discovery.devcenter.azure.com/projects",
            UriKind.Absolute);
        var entries = new List<DevBoxDiscoveryProjectEntry>();
        var visited = new HashSet<string>(StringComparer.Ordinal);
        Uri? next = origin;
        while (next is not null)
        {
            ValidateDiscoveryUri(origin, next);
            if (!visited.Add(next.AbsoluteUri) || visited.Count > 100)
                throw new InvalidDataException("Dev Center discovery pagination is cyclic or exceeds 100 pages.");
            var page = await discovery.GetAsync(next, token, cancellationToken).ConfigureAwait(false);
            entries.AddRange(page.Projects);
            next = page.NextLink;
        }

        var projects = entries
            .Select(x =>
            {
                ValidateProjectEndpoint(x.Endpoint);
                return new DiscoveredDevCenterProject(
                    DevBoxIdentityConstants.CurrentVersion,
                    context.TenantId,
                    NormalizeEndpoint(x.Endpoint),
                    x.Name,
                    x.DisplayName,
                    x.Description,
                    x.MaximumDevBoxesPerUser,
                    x.DeveloperAbilities,
                    x.AdminAbilities,
                    x.DeveloperAbilities.Contains(
                        "WriteDevBoxesAsDeveloper",
                        StringComparer.Ordinal) ||
                    x.AdminAbilities.Contains(
                        "WriteDevBoxesAsAdmin",
                        StringComparer.Ordinal),
                    x.DeveloperAbilities.Contains(
                        "CustomizeDevBoxesAsDeveloper",
                        StringComparer.Ordinal),
                    x.DeveloperAbilities.Contains(
                        "ReadRemoteConnectionsAsDeveloper",
                        StringComparer.Ordinal));
            })
            .DistinctBy(x => (x.Endpoint.AbsoluteUri, x.Name))
            .ToArray();
        var pools = new List<DevBoxPoolDetails>();
        var boxes = new List<DevBoxMemberDetails>();
        foreach (var project in projects)
        {
            var client = clients.Create(project.Endpoint, credential);
            await foreach (var box in client.GetDevBoxesAsync(project, cancellationToken).ConfigureAwait(false))
                boxes.Add(box);
            await foreach (var pool in client.GetPoolsAsync(project, cancellationToken).ConfigureAwait(false))
            {
                var member = boxes.Any(x =>
                    x.Endpoint == pool.Endpoint &&
                    x.ProjectName == pool.ProjectName &&
                    string.Equals(x.PoolName, pool.Name, StringComparison.OrdinalIgnoreCase));
                pools.Add(pool with { ExistingMembership = member });
            }
        }
        return new(
            DevBoxIdentityConstants.CurrentVersion,
            DevBoxIdentityConstants.ContextName,
            context.TenantId,
            context.Username,
            projects,
            pools,
            boxes);
    }

    public static void ValidateDiscoveryUri(Uri origin, Uri candidate)
    {
        if (!candidate.IsAbsoluteUri ||
            candidate.Scheme != Uri.UriSchemeHttps ||
            !string.Equals(candidate.IdnHost, origin.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            candidate.Port != 443 ||
            candidate.UserInfo.Length != 0 ||
            candidate.AbsolutePath != "/projects")
            throw new InvalidOperationException("Dev Center discovery nextLink is outside the tenant discovery boundary.");
    }

    public static void ValidateProjectEndpoint(Uri endpoint)
    {
        if (!endpoint.IsAbsoluteUri ||
            endpoint.Scheme != Uri.UriSchemeHttps ||
            endpoint.Port != 443 ||
            endpoint.UserInfo.Length != 0 ||
            endpoint.AbsolutePath != "/" ||
            !endpoint.IdnHost.EndsWith(".devcenter.azure.com", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Discovery returned a project endpoint outside the Dev Center service boundary.");
    }

    private static Uri NormalizeEndpoint(Uri endpoint) =>
        new(endpoint.GetLeftPart(UriPartial.Authority) + "/", UriKind.Absolute);
}
