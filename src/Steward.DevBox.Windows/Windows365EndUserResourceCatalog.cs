using System.Text.Json;

namespace Steward.DevBox.Windows;

public interface IWindows365EndUserResourceCatalog
{
    Task<string> ResolveEntityIdAsync(
        Uri providerResource,
        CancellationToken cancellationToken);
}

public sealed class Windows365EndUserResourceCatalog(
    IDevBoxBrokerHttpTransport transport,
    string clientVersion,
    string expectedMachineName,
    Action<string>? diagnosticSink = null) :
    IWindows365EndUserResourceCatalog
{
    private static readonly HashSet<Guid> DevBoxPartnerIds =
    [
        Guid.Parse("e3171dd9-9a5f-e5be-b36c-cc7c4f3f3bcf"),
        Guid.Parse("10099236-61c3-44e0-b9a8-c1036643ae26")
    ];
    private static readonly Uri ResourcesUri = new(
        "https://windows365.microsoft.com/u/api/v2/cloudPCs" +
        "?extend=IsDefault&licenseCategories=" +
        "Dedicated,Flex,FrontlineShared,Reserve");

    public async Task<string> ResolveEntityIdAsync(
        Uri providerResource,
        CancellationToken cancellationToken)
    {
        var target = ReadTarget(providerResource);
        diagnosticSink?.Invoke("entity-catalog-request-start");
        DevBoxBrokerHttpResponse response;
        try
        {
            response = await transport.GetAsync(
                    new(
                        ResourcesUri,
                        DevBoxConnectionAudience.Windows365EndUser,
                        4 * 1024 * 1024,
                        TimeSpan.FromMinutes(1),
                        ["application/json"],
                        AllowSetCookieResponse: true,
                        RequestHeaders: new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["source-client"] = "NxtClient",
                            ["client-version"] = clientVersion,
                            ["cpc-data-boundary"] = "commercial"
                        }),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            diagnosticSink?.Invoke(
                $"entity-catalog-request-failed-{exception.GetType().Name}");
            throw;
        }
        diagnosticSink?.Invoke("entity-catalog-response-received");
        if ((int)response.StatusCode is < 200 or >= 300)
            throw new HttpRequestException(
                "The Windows 365 End User resource catalog failed.",
                null,
                response.StatusCode);

        using var document = JsonDocument.Parse(
            response.Content,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32
            });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException(
                "The Windows 365 resource catalog shape is invalid.");
        var matches = new List<string>();
        var launchShapes = new HashSet<string>(StringComparer.Ordinal);
        var entityShapes = new HashSet<string>(StringComparer.Ordinal);
        var inspected = 0;
        foreach (var category in document.RootElement.EnumerateObject())
        {
            if (category.Value.ValueKind != JsonValueKind.Array)
                continue;
            foreach (var item in category.Value.EnumerateArray())
            {
                if (++inspected > 1024)
                    throw new InvalidDataException(
                        "The Windows 365 resource catalog exceeds its bound.");
                if (item.ValueKind != JsonValueKind.Object ||
                    !TryString(item, "workspaceId", out var entityId))
                    continue;
                var exactMachineMatch =
                    TryString(item, "workspaceName", out var workspaceName) &&
                    string.Equals(
                        workspaceName,
                        expectedMachineName,
                        StringComparison.OrdinalIgnoreCase) &&
                    TryString(item, "partnerId", out var partnerText) &&
                    Guid.TryParse(partnerText, out var partnerId) &&
                    DevBoxPartnerIds.Contains(partnerId);
                entityShapes.Add(
                    "properties=" +
                    string.Join(
                        ",",
                        item.EnumerateObject()
                            .Select(static property => property.Name)
                            .Order(StringComparer.OrdinalIgnoreCase)) +
                    ";devbox-partner=" +
                    (TryString(item, "partnerId", out var shapePartner) &&
                     Guid.TryParse(shapePartner, out var shapePartnerId) &&
                     DevBoxPartnerIds.Contains(shapePartnerId)) +
                    ";machine-match=" + exactMachineMatch);
                if (!TryString(
                        item,
                        "directLaunchURL",
                        out var launchText) ||
                    !Uri.TryCreate(
                        launchText,
                        UriKind.Absolute,
                        out var launchUri))
                {
                    if (exactMachineMatch)
                        matches.Add(entityId);
                    continue;
                }
                launchShapes.Add(
                    launchUri.Scheme + ":" +
                    string.Join(
                        ",",
                        ReadQueryKeys(launchUri)
                            .Order(StringComparer.OrdinalIgnoreCase)));
                if (!TryReadTarget(launchUri, out var candidate))
                {
                    if (exactMachineMatch)
                        matches.Add(entityId);
                    continue;
                }
                if (string.Equals(
                        candidate.WorkspaceId,
                        target.WorkspaceId,
                        StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(
                        candidate.ResourceId,
                        target.ResourceId,
                        StringComparison.OrdinalIgnoreCase))
                    matches.Add(entityId);
            }
        }
        var shape =
            "launch-shapes=" +
            string.Join("|", launchShapes.Order(StringComparer.Ordinal)) +
            ";entity-shapes=" +
            string.Join("|", entityShapes.Order(StringComparer.Ordinal));
        diagnosticSink?.Invoke(shape);
        return matches.Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray() switch
        {
            [var entityId] => entityId,
            [] => throw new InvalidDataException(
                "The exact Windows 365 entity was not found."),
            _ => throw new InvalidDataException(
                "The Windows 365 entity match was ambiguous.")
        };
    }

    private static (string WorkspaceId, string ResourceId) ReadTarget(
        Uri uri) =>
        (
            ReadUniqueQueryValue(uri, "workspaceId"),
            ReadUniqueQueryValue(uri, "resourceid")
        );

    private static bool TryReadTarget(
        Uri uri,
        out (string WorkspaceId, string ResourceId) target)
    {
        target = default;
        try
        {
            target = ReadTarget(uri);
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static IEnumerable<string> ReadQueryKeys(Uri uri)
    {
        foreach (var item in uri.Query.TrimStart('?').Split(
                     '&',
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = item.IndexOf('=');
            if (separator > 0)
                yield return Uri.UnescapeDataString(item[..separator]);
        }
    }

    private static string ReadUniqueQueryValue(Uri uri, string name)
    {
        string? value = null;
        foreach (var item in uri.Query.TrimStart('?').Split(
                     '&',
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = item.IndexOf('=');
            if (separator <= 0 ||
                !string.Equals(
                    Uri.UnescapeDataString(item[..separator]),
                    name,
                    StringComparison.OrdinalIgnoreCase))
                continue;
            if (value is not null)
                throw new InvalidDataException(
                    "The provider URI contains duplicate identifiers.");
            value = Uri.UnescapeDataString(item[(separator + 1)..]);
        }
        return string.IsNullOrWhiteSpace(value) || value.Length > 4096
            ? throw new InvalidDataException(
                "The provider URI is missing a bounded identifier.")
            : value;
    }

    private static bool TryString(
        JsonElement value,
        string name,
        out string result)
    {
        result = string.Empty;
        if (!value.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String)
            return false;
        result = property.GetString() ?? string.Empty;
        return result.Length is > 0 and <= 4096;
    }
}
