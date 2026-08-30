using Azure.Core;

namespace Steward.DevBox.Windows;

public static class DevBoxIdentityConstants
{
    public const int CurrentVersion = 1;
    public const string ContextName = "devbox/default";
    public const string CacheName = "steward.devbox.default.msal.cache";
    public const string Scope = "https://devcenter.azure.com/.default";
}

public sealed record DevBoxIdentityContext(
    int Version,
    string Name,
    string TenantId,
    string Authority,
    string ClientId,
    string HomeAccountId,
    string Username,
    string CacheName,
    DateTimeOffset CreatedAtUtc);

public sealed record DevBoxIdentityStatus(
    int Version,
    string Name,
    bool SignedIn,
    string? TenantId,
    string? Username,
    DateTimeOffset? TokenExpiresOn,
    string? Problem);

public sealed record DiscoveredDevCenterProject(
    int Version,
    string TenantId,
    Uri Endpoint,
    string Name,
    string? DisplayName,
    string? Description,
    int? MaximumDevBoxesPerUser,
    IReadOnlyList<string> DeveloperAbilities,
    IReadOnlyList<string> AdminAbilities,
    bool CanCreateDevBoxes,
    bool CanCustomizeDevBoxes,
    bool CanReadRemoteConnections);

public sealed record DevBoxStopPolicy(
    int Version,
    string Status,
    int? GracePeriodMinutes);

public sealed record DevBoxPoolDetails(
    int Version,
    Uri Endpoint,
    string ProjectName,
    string Name,
    string? Location,
    string? Health,
    string? OperatingSystem,
    string? LocalAdministrator,
    string? Sku,
    int? VirtualCpuCount,
    int? RamGb,
    int? OsDiskGb,
    string? ImageName,
    string? ImageVersion,
    string? ImageBuild,
    DateTimeOffset? ImagePublishedOn,
    string? HibernateSupport,
    DevBoxStopPolicy? StopPolicy,
    bool ExistingMembership);

public sealed record DevBoxMemberDetails(
    int Version,
    Uri Endpoint,
    string ProjectName,
    string Name,
    string? PoolName,
    string? Location,
    string? ProvisioningState,
    string? PowerState,
    string? OperatingSystem,
    string? LocalAdministrator,
    string? Sku,
    int? VirtualCpuCount,
    int? RamGb,
    int? OsDiskGb,
    string? ImageName,
    string? ImageVersion,
    string? ImageBuild,
    DateTimeOffset? ImagePublishedOn,
    string? HibernateSupport,
    DateTimeOffset? CreatedOn);

public sealed record DevBoxInventory(
    int Version,
    string ContextName,
    string TenantId,
    string Username,
    IReadOnlyList<DiscoveredDevCenterProject> Projects,
    IReadOnlyList<DevBoxPoolDetails> Pools,
    IReadOnlyList<DevBoxMemberDetails> DevBoxes);

public interface IDevBoxSilentCredentialSource
{
    Task<(DevBoxIdentityContext Context, TokenCredential Credential, AccessToken Token)> OpenAsync(
        CancellationToken cancellationToken);
}

public interface IDevBoxCommandService
{
    Task<DevBoxIdentityStatus> LoginAsync(
        CancellationToken cancellationToken);
    Task<DevBoxIdentityStatus> StatusAsync(CancellationToken cancellationToken);
    Task<DevBoxIdentityStatus> LogoutAsync(CancellationToken cancellationToken);
    Task<DevBoxInventory> DiscoverAsync(CancellationToken cancellationToken);
}
