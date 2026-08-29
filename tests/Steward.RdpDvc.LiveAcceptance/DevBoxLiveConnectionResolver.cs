using Azure.Developer.DevCenter;
using Steward.DevBox.Windows;

namespace Steward.RdpDvc.LiveAcceptance;

internal sealed record ResolvedDevBoxLiveConnection(
    Uri ProviderResource,
    Uri AvdFeedUri,
    string TenantId,
    string Username);

internal interface IDevBoxRemoteConnectionClient
{
    Task<Uri?> GetRemoteConnectionAsync(
        string project,
        string user,
        string devBox,
        CancellationToken cancellationToken);
}

internal sealed class AzureDevBoxRemoteConnectionClient(
    DevBoxesClient client) : IDevBoxRemoteConnectionClient
{
    public async Task<Uri?> GetRemoteConnectionAsync(
        string project,
        string user,
        string devBox,
        CancellationToken cancellationToken) =>
        (await client.GetRemoteConnectionAsync(
                project,
                user,
                devBox,
                cancellationToken)
            .ConfigureAwait(false)).Value.RdpConnectionUri;
}

internal static class DevBoxLiveConnectionResolver
{
    internal static async Task<ResolvedDevBoxLiveConnection> ResolveAsync(
        LiveAcceptanceOptions options,
        DevBoxIdentityStatus defaultIdentity,
        DevBoxConnectionIdentityStatus connectionIdentity,
        IDevBoxRemoteConnectionClient client,
        CancellationToken cancellationToken)
    {
        Console.Error.WriteLine(
            "LIVE PROVIDER STAGE: endpoint-validation");
        DevBoxDiscoveryService.ValidateProjectEndpoint(
            options.DevBoxEndpoint);
        Console.Error.WriteLine(
            "LIVE PROVIDER STAGE: default-identity-binding");
        if (!defaultIdentity.SignedIn ||
            !string.Equals(
                defaultIdentity.Name,
                DevBoxIdentityConstants.ContextName,
                StringComparison.Ordinal) ||
            !Guid.TryParse(defaultIdentity.TenantId, out var tenantId) ||
            string.IsNullOrWhiteSpace(defaultIdentity.Username))
            throw new InvalidOperationException(
                "The devbox/default identity is not ready.");
        Console.Error.WriteLine(
            "LIVE PROVIDER STAGE: connection-identity-binding");
        if (connectionIdentity.Outcome !=
                DevBoxConnectionIdentityOutcome.Ready ||
            !connectionIdentity.Enrolled ||
            !string.Equals(
                connectionIdentity.Name,
                DevBoxConnectionIdentityConstants.ContextName,
                StringComparison.Ordinal) ||
            !string.Equals(
                connectionIdentity.TenantId,
                defaultIdentity.TenantId,
                StringComparison.Ordinal) ||
            !string.Equals(
                connectionIdentity.Username,
                defaultIdentity.Username,
                StringComparison.Ordinal))
            throw new InvalidOperationException(
                "The RDCore connection identity is not bound to devbox/default.");

        Console.Error.WriteLine(
            "LIVE PROVIDER STAGE: get-remote-connection");
        var providerResource = await client.GetRemoteConnectionAsync(
                options.Project,
                options.User,
                options.DevBox,
                cancellationToken)
            .ConfigureAwait(false) ??
            throw new InvalidDataException(
                "DevBoxesClient.GetRemoteConnection returned no RDP resource.");
        Console.Error.WriteLine(
            "LIVE PROVIDER STAGE: classify-provider-resource");
        (DevBoxProviderRdpKind Kind, IReadOnlyList<string> QueryKeys)
            classified;
        try
        {
            classified =
                DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(
                    providerResource);
        }
        catch (InvalidDataException)
        {
            var keys = providerResource.Query
                .TrimStart('?')
                .Split(
                    '&',
                    StringSplitOptions.RemoveEmptyEntries)
                .Select(item =>
                {
                    var separator = item.IndexOf('=');
                    return separator > 0
                        ? item[..separator]
                        : "<invalid>";
                })
                .Order(StringComparer.Ordinal);
            Console.Error.WriteLine(
                "LIVE PROVIDER SHAPE: " +
                $"scheme={providerResource.Scheme}; " +
                $"path={providerResource.AbsolutePath}; " +
                $"hostPresent={providerResource.Host.Length != 0}; " +
                $"fragmentPresent={providerResource.Fragment.Length != 0}; " +
                $"length={providerResource.OriginalString.Length}; " +
                $"keys={string.Join(',', keys)}");
            throw;
        }
        if (classified.Kind !=
                DevBoxProviderRdpKind.WindowsAppResource)
            throw new InvalidDataException(
                "DevBoxesClient.GetRemoteConnection did not return an exact ms-avd resource.");
        Console.Error.WriteLine(
            "LIVE PROVIDER STAGE: derive-feed");
        var feed = new Uri(
            "https://www.wvd.microsoft.com/api/arm/feeddiscovery" +
            $"?aadtenant={tenantId:D}");
        return new(
            providerResource,
            feed,
            tenantId.ToString("D"),
            defaultIdentity.Username);
    }
}
