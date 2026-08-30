using Azure.Developer.DevCenter;
using Steward.DevBox.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.Desktop.Windows;

public interface IDevBoxDesktopGateway : IDisposable
{
    Task<DevBoxIdentityStatus> LoginAsync(
        IntPtr parentWindowHandle,
        CancellationToken cancellationToken);
    Task<DevBoxIdentityStatus> StatusAsync(CancellationToken cancellationToken);
    Task<DevBoxIdentityStatus> LogoutAsync(CancellationToken cancellationToken);
    Task<DevBoxInventory> DiscoverAsync(CancellationToken cancellationToken);
    Task<SensitiveConnectionHostProviderResource>
        GetConnectionHostProviderResourceAsync(
            Uri endpoint,
            string project,
            string devBoxName,
            CancellationToken cancellationToken);
    Task<DevBoxRemoteViewingResource> GetRemoteViewingResourceAsync(
        Uri endpoint,
        string project,
        string devBoxName,
        CancellationToken cancellationToken);
    Task<DevBoxRemoteViewerLaunchResult> LaunchRemoteViewerAsync(
        DevBoxRemoteViewerHandle handle,
        DevBoxRemoteViewerTarget target,
        CancellationToken cancellationToken);
    DevBoxExternalViewerSessionStatus GetRemoteViewerSessionStatus(
        DevBoxExternalViewerSessionHandle handle);
    DevBoxExternalViewerSessionStatus SurfaceRemoteViewer(
        DevBoxExternalViewerSessionHandle handle,
        DevBoxExternalViewerIntent intent);
    DvcPluginRegistrationStatus GetDvcRegistrationStatus();
    DvcPluginRegistrationStatus RegisterDvcPlugin();
}

public sealed class SensitiveConnectionHostProviderResource(
    Uri providerResource) : IDisposable
{
    private Uri? value = providerResource ??
        throw new ArgumentNullException(nameof(providerResource));

    public Uri Value =>
        value ?? throw new ObjectDisposedException(
            nameof(SensitiveConnectionHostProviderResource));

    public void Dispose()
    {
        value = null;
        GC.SuppressFinalize(this);
    }

    public override string ToString() =>
        "SensitiveConnectionHostProviderResource { Value = [REDACTED] }";
}

public sealed class DevBoxDesktopGateway : IDevBoxDesktopGateway
{
    private readonly HttpClient discoveryHttp;
    private readonly DevBoxIdentityService identity;
    private readonly DevBoxDiscoveryService discovery;
    private readonly DevBoxRemoteViewingService remoteViewing;
    private readonly RdpDvcPluginRegistration dvcRegistration;

    public DevBoxDesktopGateway()
    {
        identity = new(new DevBoxIdentityStore());
        discoveryHttp = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(60)
        };
        discovery = new(
            identity,
            new HttpDevBoxTenantDiscoveryTransport(discoveryHttp),
            new AzureDevBoxProjectInventoryClientFactory());
        remoteViewing = new(identity);
        dvcRegistration = new(
            new CurrentUserRegistryStore(),
            new WindowsRdpDvcExecutableValidator());
    }

    public Task<DevBoxIdentityStatus> LoginAsync(
        IntPtr parentWindowHandle,
        CancellationToken cancellationToken) =>
        identity.LoginAsync(parentWindowHandle, cancellationToken);

    public Task<DevBoxIdentityStatus> StatusAsync(
        CancellationToken cancellationToken) =>
        identity.StatusAsync(cancellationToken);

    public Task<DevBoxIdentityStatus> LogoutAsync(
        CancellationToken cancellationToken) =>
        identity.LogoutAsync(cancellationToken);

    public Task<DevBoxInventory> DiscoverAsync(
        CancellationToken cancellationToken) =>
        discovery.DiscoverAsync(cancellationToken);

    public async Task<SensitiveConnectionHostProviderResource>
        GetConnectionHostProviderResourceAsync(
            Uri endpoint,
            string project,
            string devBoxName,
            CancellationToken cancellationToken)
    {
        DevBoxDiscoveryService.ValidateProjectEndpoint(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(project);
        ArgumentException.ThrowIfNullOrWhiteSpace(devBoxName);
        var (_, credential, _) = await identity.OpenAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var response = await new DevBoxesClient(endpoint, credential)
            .GetRemoteConnectionAsync(
                project,
                "me",
                devBoxName,
                cancellationToken)
            .ConfigureAwait(false);
        var providerResource = response.Value.RdpConnectionUri;
        var (kind, _) =
            DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(
                providerResource);
        if (kind != DevBoxProviderRdpKind.WindowsAppResource ||
            providerResource is null)
            throw new DevBoxRemoteViewerException(
                "ConnectionHostProviderResourceUnavailable",
                "Dev Center returned no supported ConnectionHost provider resource.");
        return new(providerResource);
    }

    public async Task<DevBoxRemoteViewingResource> GetRemoteViewingResourceAsync(
        Uri endpoint,
        string project,
        string devBoxName,
        CancellationToken cancellationToken)
    {
        var resource = await remoteViewing.GetAsync(
            endpoint,
            project,
            devBoxName,
            cancellationToken);
        var dvc = dvcRegistration.GetStatus();
        return resource with
        {
            DvcPluginRegistered = dvc.Registered,
            DvcRegistrationCode = dvc.Code
        };
    }

    public Task<DevBoxRemoteViewerLaunchResult> LaunchRemoteViewerAsync(
        DevBoxRemoteViewerHandle handle,
        DevBoxRemoteViewerTarget target,
        CancellationToken cancellationToken) =>
        remoteViewing.LaunchAsync(
            handle,
            target,
            cancellationToken);

    public DevBoxExternalViewerSessionStatus GetRemoteViewerSessionStatus(
        DevBoxExternalViewerSessionHandle handle) =>
        remoteViewing.GetSessionStatus(handle);

    public DevBoxExternalViewerSessionStatus SurfaceRemoteViewer(
        DevBoxExternalViewerSessionHandle handle,
        DevBoxExternalViewerIntent intent) =>
        remoteViewing.Surface(handle, intent);

    public DvcPluginRegistrationStatus GetDvcRegistrationStatus() =>
        dvcRegistration.GetStatus();

    public DvcPluginRegistrationStatus RegisterDvcPlugin()
    {
        var executable = DvcClientExecutable();
        if (!File.Exists(executable))
            throw new DevBoxRemoteViewerException(
                "DvcPluginExecutableUnavailable",
                "The published Steward DVC client executable is unavailable.");
        dvcRegistration.Register(executable);
        return dvcRegistration.GetStatus();
    }

    public void Dispose()
    {
        discoveryHttp.Dispose();
        GC.SuppressFinalize(this);
    }

    private static string DvcClientExecutable()
    {
        var configured = Environment.GetEnvironmentVariable(
            "STEWARD_RDP_DVC_CLIENT_PATH");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            if (!Path.IsPathFullyQualified(configured))
                throw new DevBoxRemoteViewerException(
                    "DvcPluginExecutableReferenceInvalid",
                    "STEWARD_RDP_DVC_CLIENT_PATH must be absolute.");
            return Path.GetFullPath(configured);
        }
        var desktopDirectory = new DirectoryInfo(
            Path.TrimEndingDirectorySeparator(
                AppContext.BaseDirectory));
        var installRoot = desktopDirectory.Parent?.FullName
            ?? desktopDirectory.FullName;
        return Path.Combine(
            installRoot,
            "Steward.RdpDvc.Client.Windows",
            "Steward.RdpDvc.Client.Windows.exe");
    }
}
