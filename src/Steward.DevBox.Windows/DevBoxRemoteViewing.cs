using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using Azure.Developer.DevCenter;

namespace Steward.DevBox.Windows;

public readonly record struct DevBoxRemoteViewerHandle
{
    public Guid Value { get; }

    public DevBoxRemoteViewerHandle(Guid value) =>
        Value = value != Guid.Empty
            ? value
            : throw new ArgumentException(
                "Remote viewer handle cannot be empty.",
                nameof(value));

    public static DevBoxRemoteViewerHandle New() =>
        new(Guid.NewGuid());

    public override string ToString() => Value.ToString("D");
}

public enum DevBoxProviderRdpKind
{
    Absent,
    WindowsAppResource,
    Unsupported
}

public enum DevBoxRemoteViewerTarget
{
    WindowsApp,
    WebBrowser
}

public readonly record struct DevBoxExternalViewerSessionHandle
{
    public Guid Value { get; }

    public DevBoxExternalViewerSessionHandle(Guid value) =>
        Value = value != Guid.Empty
            ? value
            : throw new ArgumentException(
                "External viewer session handle cannot be empty.",
                nameof(value));

    public static DevBoxExternalViewerSessionHandle New() =>
        new(Guid.NewGuid());

    public override string ToString() => Value.ToString("D");
}

public enum DevBoxExternalViewerSessionState
{
    BrokerWindowVisible,
    BrokerWindowNotFound,
    BrokerWindowAmbiguous,
    BrokerWindowClosed,
    WebBrowserUntracked
}

public enum DevBoxExternalViewerIntent
{
    Show,
    TakeControl
}

public sealed record DevBoxRemoteViewingResource(
    DevBoxRemoteViewerHandle Handle,
    DevBoxProviderRdpKind ProviderRdpKind,
    bool WindowsAppAvailable,
    bool WebBrowserAvailable,
    IReadOnlyList<string> WindowsAppQueryKeys,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string EvidenceCode,
    bool WindowsAppResourceLaunchProven,
    bool FullscreenBrokerViewProven,
    bool EmbeddingSupported,
    bool StewardInputControlSupported,
    string DvcEvidenceStatus,
    bool DvcPluginRegistered = false,
    string DvcRegistrationCode = "DvcStatusNotChecked")
{
    public override string ToString() =>
        $"DevBoxRemoteViewingResource " +
        $"{{ Kind = {ProviderRdpKind}, " +
        $"WindowsAppAvailable = {WindowsAppAvailable}, " +
        $"WebBrowserAvailable = {WebBrowserAvailable}, " +
        $"EvidenceCode = {EvidenceCode} }}";
}

public sealed record DevBoxRemoteViewerLaunchResult(
    DevBoxRemoteViewerTarget Target,
    DateTimeOffset RequestedAtUtc,
    string Code,
    DevBoxExternalViewerSessionHandle? SessionHandle = null,
    DevBoxExternalViewerSessionState SessionState =
        DevBoxExternalViewerSessionState.BrokerWindowNotFound,
    bool SurfaceSupported = false,
    bool ForegroundTakeControlSupported = false);

public sealed record DevBoxExternalViewerSessionStatus(
    DevBoxExternalViewerSessionHandle SessionHandle,
    DevBoxExternalViewerSessionState State,
    DateTimeOffset ObservedAtUtc,
    bool SurfaceSupported,
    bool ForegroundTakeControlSupported,
    string Code);

public sealed class DevBoxRemoteViewerException(
    string code,
    string detail) : InvalidOperationException(detail)
{
    public string Code { get; } = code;
}

public interface IExternalUriActivator
{
    void Activate(Uri uri);
}

public sealed class WindowsShellUriActivator : IExternalUriActivator
{
    public void Activate(Uri uri)
    {
        _ = Process.Start(new ProcessStartInfo(uri.OriginalString)
        {
            UseShellExecute = true
        });
    }
}

public static class DevBoxRemoteViewingValidator
{
    public const int MaximumActivationUriCharacters = 32_768;
    private static readonly IReadOnlySet<string> RequiredMsAvdQueryKeys =
        new HashSet<string>(
        [
            "env",
            "preview",
            "resourceId",
            "username",
            "version",
            "workspaceId"
        ], StringComparer.OrdinalIgnoreCase);

    public static (
        DevBoxProviderRdpKind Kind,
        IReadOnlyList<string> QueryKeys)
        ClassifyProviderRdpUri(Uri? value)
    {
        if (value is null)
            return (DevBoxProviderRdpKind.Absent, []);
        if (!string.Equals(
                value.Scheme,
                "ms-avd",
                StringComparison.OrdinalIgnoreCase))
            return (DevBoxProviderRdpKind.Unsupported, []);
        if (!value.IsAbsoluteUri ||
            value.OriginalString.Length is 0 or
                > MaximumActivationUriCharacters ||
            !string.Equals(
                value.AbsolutePath,
                "connect",
                StringComparison.Ordinal) ||
            value.Host.Length != 0 ||
            value.UserInfo.Length != 0 ||
            value.Fragment.Length != 0)
            throw new InvalidDataException(
                "The provider-issued Windows App resource shape is invalid.");

        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in value.Query.TrimStart('?').Split(
                     '&',
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = item.IndexOf('=');
            if (separator <= 0 ||
                separator == item.Length - 1)
                throw new InvalidDataException(
                    "The provider-issued Windows App resource query is invalid.");
            var key = item[..separator];
            var encodedValue = item[(separator + 1)..];
            if (!RequiredMsAvdQueryKeys.Contains(key) ||
                encodedValue.Length > 16 * 1024 ||
                !keys.Add(key))
                throw new InvalidDataException(
                    "The provider-issued Windows App resource query is unsupported.");
        }
        if (!keys.SetEquals(RequiredMsAvdQueryKeys))
            throw new InvalidDataException(
                "The provider-issued Windows App resource query is incomplete.");
        return (
            DevBoxProviderRdpKind.WindowsAppResource,
            keys.Order(StringComparer.Ordinal).ToArray());
    }

    public static Uri? ValidateWebUri(Uri? value)
    {
        if (value is null)
            return null;
        if (!value.IsAbsoluteUri ||
            value.Scheme != Uri.UriSchemeHttps ||
            value.Port != 443 ||
            string.IsNullOrWhiteSpace(value.IdnHost) ||
            value.UserInfo.Length != 0 ||
            value.OriginalString.Length > MaximumActivationUriCharacters)
            throw new InvalidDataException(
                "The provider-issued web viewer resource is invalid.");
        return value;
    }
}

public sealed class DevBoxRemoteViewingService
{
    private static readonly TimeSpan HandleLifetime =
        TimeSpan.FromMinutes(2);
    private const int MaximumHandles = 32;
    private const int MaximumTrackedSessions = 32;
    private readonly IDevBoxSilentCredentialSource identity;
    private readonly IExternalUriActivator activator;
    private readonly IWindowsAppWindowTracker windowTracker;
    private readonly ConcurrentDictionary<
        DevBoxRemoteViewerHandle,
        SensitiveViewingResource> resources = [];
    private readonly ConcurrentDictionary<
        DevBoxExternalViewerSessionHandle,
        TrackedWindowsAppSession> sessions = [];

    public DevBoxRemoteViewingService(
        IDevBoxSilentCredentialSource identity,
        IExternalUriActivator? activator = null,
        IWindowsAppWindowTracker? windowTracker = null)
    {
        this.identity = identity;
        this.activator = activator ?? new WindowsShellUriActivator();
        this.windowTracker =
            windowTracker ?? new WindowsAppWindowTracker();
    }

    public async Task<DevBoxRemoteViewingResource> GetAsync(
        Uri endpoint,
        string project,
        string devBoxName,
        CancellationToken cancellationToken)
    {
        DevBoxDiscoveryService.ValidateProjectEndpoint(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(project);
        ArgumentException.ThrowIfNullOrWhiteSpace(devBoxName);
        var (_, credential, _) =
            await identity.OpenAsync(cancellationToken)
                .ConfigureAwait(false);
        var client = new DevBoxesClient(endpoint, credential);
        var remote = await client.GetRemoteConnectionAsync(
                project,
                "me",
                devBoxName,
                cancellationToken)
            .ConfigureAwait(false);
        return Cache(
            remote.Value.RdpConnectionUri,
            remote.Value.WebUri);
    }

    public DevBoxRemoteViewingResource Cache(
        Uri? providerRdpUri,
        Uri? webUri)
    {
        var (kind, keys) =
            DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(
                providerRdpUri);
        var validatedWeb =
            DevBoxRemoteViewingValidator.ValidateWebUri(webUri);
        var windowsApp =
            kind == DevBoxProviderRdpKind.WindowsAppResource;
        if (!windowsApp && validatedWeb is null)
            throw new DevBoxRemoteViewerException(
                "DevBoxRemoteViewerUnavailable",
                "Dev Center returned no supported remote viewer resource.");

        var now = DateTimeOffset.UtcNow;
        PurgeExpired(now);
        if (resources.Count >= MaximumHandles)
        {
            var oldest = resources.OrderBy(item =>
                    item.Value.ExpiresAtUtc)
                .First();
            resources.TryRemove(oldest.Key, out _);
        }
        var handle = DevBoxRemoteViewerHandle.New();
        var value = new SensitiveViewingResource(
            windowsApp ? providerRdpUri : null,
            validatedWeb,
            now + HandleLifetime);
        if (!resources.TryAdd(handle, value))
            throw new InvalidOperationException(
                "Remote viewer handle collision.");
        return new(
            handle,
            kind,
            windowsApp,
            validatedWeb is not null,
            keys,
            now,
            value.ExpiresAtUtc,
            kind switch
            {
                DevBoxProviderRdpKind.WindowsAppResource =>
                    "WindowsAppResourceValidated",
                DevBoxProviderRdpKind.Unsupported
                    when validatedWeb is not null =>
                    "UnsupportedRdpSchemeWebFallback",
                _ => "WebViewerValidated"
            },
            WindowsAppResourceLaunchProven: false,
            FullscreenBrokerViewProven: false,
            EmbeddingSupported: false,
            StewardInputControlSupported: false,
            DvcEvidenceStatus:
                "RegistrationSupportedActivationPending");
    }

    public async Task<DevBoxRemoteViewerLaunchResult> LaunchAsync(
        DevBoxRemoteViewerHandle handle,
        DevBoxRemoteViewerTarget target,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        PurgeExpired(now);
        if (!resources.TryGetValue(handle, out var resource))
            throw new DevBoxRemoteViewerException(
                "DevBoxRemoteViewerHandleExpired",
                "The remote viewer resource expired; request a new one.");
        var uri = target switch
        {
            DevBoxRemoteViewerTarget.WindowsApp
                when resource.WindowsAppUri is not null =>
                resource.WindowsAppUri,
            DevBoxRemoteViewerTarget.WebBrowser
                when resource.WebUri is not null =>
                resource.WebUri,
            _ => throw new DevBoxRemoteViewerException(
                "DevBoxRemoteViewerTargetUnavailable",
                "The selected remote viewer target is unavailable.")
        };
        if (!resources.TryRemove(handle, out resource))
            throw new DevBoxRemoteViewerException(
                "DevBoxRemoteViewerHandleExpired",
                "The remote viewer resource expired; request a new one.");
        var before = target == DevBoxRemoteViewerTarget.WindowsApp
            ? windowTracker.Snapshot()
            : [];
        try
        {
            activator.Activate(uri);
        }
        catch (Exception exception)
            when (exception is
                Win32Exception or
                InvalidOperationException)
        {
            if (resource.ExpiresAtUtc > DateTimeOffset.UtcNow)
                resources.TryAdd(handle, resource);
            throw new DevBoxRemoteViewerException(
                target == DevBoxRemoteViewerTarget.WindowsApp
                    ? "WindowsAppProtocolHandlerUnavailable"
                    : "WebBrowserActivationFailed",
                target == DevBoxRemoteViewerTarget.WindowsApp
                    ? "Windows could not activate the ms-avd handler. Install or repair Microsoft Windows App."
                    : "Windows could not activate the default HTTPS browser.");
        }
        if (target == DevBoxRemoteViewerTarget.WebBrowser)
            return new(
                target,
                now,
                "WebViewerActivationRequested",
                SessionState:
                    DevBoxExternalViewerSessionState.WebBrowserUntracked);

        var discovery = await windowTracker.FindActivatedWindowAsync(
                before,
                TimeSpan.FromSeconds(10),
                cancellationToken)
            .ConfigureAwait(false);
        if (discovery.State != WindowsAppWindowDiscoveryState.Found ||
            discovery.Window is null)
            return new(
                target,
                now,
                discovery.State == WindowsAppWindowDiscoveryState.Ambiguous
                    ? "WindowsAppActivationRequestedWindowAmbiguous"
                    : "WindowsAppActivationRequestedWindowNotFound",
                SessionState:
                    discovery.State == WindowsAppWindowDiscoveryState.Ambiguous
                        ? DevBoxExternalViewerSessionState.BrokerWindowAmbiguous
                        : DevBoxExternalViewerSessionState.BrokerWindowNotFound);

        var sessionHandle =
            DevBoxExternalViewerSessionHandle.New();
        PurgeClosedSessions();
        if (sessions.Count >= MaximumTrackedSessions)
        {
            var oldest = sessions.OrderBy(item =>
                    item.Value.CreatedAtUtc)
                .First();
            sessions.TryRemove(oldest.Key, out _);
        }
        if (!sessions.TryAdd(
                sessionHandle,
                new(discovery.Window.Value, DateTimeOffset.UtcNow)))
            throw new InvalidOperationException(
                "External viewer session handle collision.");
        return new(
            target,
            now,
            "WindowsAppBrokerWindowVisible",
            sessionHandle,
            DevBoxExternalViewerSessionState.BrokerWindowVisible,
            SurfaceSupported: true,
            ForegroundTakeControlSupported: true);
    }

    public DevBoxExternalViewerSessionStatus GetSessionStatus(
        DevBoxExternalViewerSessionHandle handle)
    {
        if (!sessions.TryGetValue(handle, out var session))
            throw new DevBoxRemoteViewerException(
                "WindowsAppSessionNotFound",
                "The tracked Windows App broker window is unavailable.");
        var alive = windowTracker.IsAlive(session.Window);
        if (!alive)
            sessions.TryRemove(handle, out _);
        return new(
            handle,
            alive
                ? DevBoxExternalViewerSessionState.BrokerWindowVisible
                : DevBoxExternalViewerSessionState.BrokerWindowClosed,
            DateTimeOffset.UtcNow,
            SurfaceSupported: alive,
            ForegroundTakeControlSupported: alive,
            alive
                ? "WindowsAppBrokerWindowVisible"
                : "WindowsAppBrokerWindowClosed");
    }

    public DevBoxExternalViewerSessionStatus Surface(
        DevBoxExternalViewerSessionHandle handle,
        DevBoxExternalViewerIntent intent)
    {
        if (!sessions.TryGetValue(handle, out var session) ||
            !windowTracker.IsAlive(session.Window))
        {
            sessions.TryRemove(handle, out _);
            throw new DevBoxRemoteViewerException(
                "WindowsAppBrokerWindowClosed",
                "The tracked Windows App broker window is closed.");
        }
        if (!windowTracker.Surface(session.Window))
            throw new DevBoxRemoteViewerException(
                "WindowsAppForegroundDenied",
                "Windows did not grant foreground activation to the Windows App window.");
        return new(
            handle,
            DevBoxExternalViewerSessionState.BrokerWindowVisible,
            DateTimeOffset.UtcNow,
            SurfaceSupported: true,
            ForegroundTakeControlSupported: true,
            intent == DevBoxExternalViewerIntent.TakeControl
                ? "WindowsAppForegroundTakeControlRequested"
                : "WindowsAppWindowSurfaced");
    }

    private void PurgeExpired(DateTimeOffset now)
    {
        foreach (var item in resources)
            if (item.Value.ExpiresAtUtc <= now)
                resources.TryRemove(item.Key, out _);
    }

    private void PurgeClosedSessions()
    {
        foreach (var item in sessions)
            if (!windowTracker.IsAlive(item.Value.Window))
                sessions.TryRemove(item.Key, out _);
    }

    private sealed record SensitiveViewingResource(
        Uri? WindowsAppUri,
        Uri? WebUri,
        DateTimeOffset ExpiresAtUtc);

    private sealed record TrackedWindowsAppSession(
        WindowsAppWindowIdentity Window,
        DateTimeOffset CreatedAtUtc);
}
