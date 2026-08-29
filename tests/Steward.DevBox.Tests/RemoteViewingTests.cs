using Steward.DevBox.Windows;

namespace Steward.DevBox.Tests;

public sealed class RemoteViewingTests
{
    private static readonly Uri ValidMsAvd = new(
        "ms-avd:connect?env=prod&preview=false&resourceId=SENSITIVE_RESOURCE_VALUE" +
        "&username=user&version=1&workspaceId=workspace");

    [Fact]
    public void Accepts_only_bounded_live_ms_avd_shape()
    {
        var (kind, keys) =
            DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(
                ValidMsAvd);

        Assert.Equal(
            DevBoxProviderRdpKind.WindowsAppResource,
            kind);
        Assert.Equal(
            [
                "env",
                "preview",
                "resourceId",
                "username",
                "version",
                "workspaceId"
            ],
            keys);
    }

    [Theory]
    [InlineData("ms-avd:other?env=1&preview=0&resourceId=r&username=u&version=1&workspaceId=w")]
    [InlineData("ms-avd:connect?env=1&preview=0&resourceId=r&username=u&version=1")]
    [InlineData("ms-avd:connect?env=1&preview=0&resourceId=r&username=u&version=1&workspaceId=w&token=x")]
    [InlineData("ms-avd:connect?env=1&env=2&preview=0&resourceId=r&username=u&version=1&workspaceId=w")]
    public void Rejects_malformed_or_unknown_ms_avd_resources(
        string value)
    {
        Assert.Throws<InvalidDataException>(() =>
            DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(
                new Uri(value)));
    }

    [Fact]
    public void Https_rdp_is_not_reinterpreted_as_an_embeddable_profile()
    {
        var service = new DevBoxRemoteViewingService(
            new UnusedIdentitySource());

        var value = service.Cache(
            new Uri("https://devcenter.example/profile.rdp"),
            new Uri("https://windows.cloud.microsoft/remote"));

        Assert.Equal(
            DevBoxProviderRdpKind.Unsupported,
            value.ProviderRdpKind);
        Assert.False(value.WindowsAppAvailable);
        Assert.True(value.WebBrowserAvailable);
        Assert.False(value.EmbeddingSupported);
        Assert.False(value.StewardInputControlSupported);
        Assert.Equal(
            "UnsupportedRdpSchemeWebFallback",
            value.EvidenceCode);
    }

    [Fact]
    public void Safe_resource_text_never_contains_activation_values()
    {
        var service = new DevBoxRemoteViewingService(
            new UnusedIdentitySource());

        var value = service.Cache(
            ValidMsAvd,
            new Uri(
                "https://windows.cloud.microsoft/remote?secret=SENTINEL"));
        var text = value.ToString();

        Assert.DoesNotContain(
            "SENSITIVE_RESOURCE_VALUE",
            text,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "SENTINEL",
            text,
            StringComparison.Ordinal);
        Assert.False(value.EmbeddingSupported);
        Assert.False(value.StewardInputControlSupported);
        Assert.False(value.WindowsAppResourceLaunchProven);
        Assert.False(value.FullscreenBrokerViewProven);
        Assert.Equal(
            "WindowsAppResourceValidated",
            value.EvidenceCode);
        Assert.Equal(
            "RegistrationSupportedActivationPending",
            value.DvcEvidenceStatus);
    }

    [Fact]
    public void Rejects_non_https_web_viewer()
    {
        Assert.Throws<InvalidDataException>(() =>
            DevBoxRemoteViewingValidator.ValidateWebUri(
                new Uri("http://example.test/remote")));
    }

    [Fact]
    public async Task Launch_uses_exact_resource_once_and_tracks_broker_window()
    {
        var activator = new CapturingActivator();
        var tracker = new FakeWindowTracker();
        var service = new DevBoxRemoteViewingService(
            new UnusedIdentitySource(),
            activator,
            tracker);
        var resource = service.Cache(ValidMsAvd, null);

        var result = await service.LaunchAsync(
            resource.Handle,
            DevBoxRemoteViewerTarget.WindowsApp);

        Assert.Equal(
            "WindowsAppBrokerWindowVisible",
            result.Code);
        Assert.Equal(ValidMsAvd, Assert.Single(activator.Values));
        Assert.NotNull(result.SessionHandle);
        Assert.True(result.SurfaceSupported);
        var status = service.GetSessionStatus(
            result.SessionHandle!.Value);
        Assert.Equal(
            DevBoxExternalViewerSessionState.BrokerWindowVisible,
            status.State);
        var surfaced = service.Surface(
            result.SessionHandle.Value,
            DevBoxExternalViewerIntent.TakeControl);
        Assert.Equal(
            "WindowsAppForegroundTakeControlRequested",
            surfaced.Code);
        Assert.True(tracker.SurfaceCalled);
        var error = await Assert.ThrowsAsync<DevBoxRemoteViewerException>(() =>
            service.LaunchAsync(
                resource.Handle,
                DevBoxRemoteViewerTarget.WindowsApp));
        Assert.Equal(
            "DevBoxRemoteViewerHandleExpired",
            error.Code);
    }

    [Fact]
    public void Window_selection_fails_closed_on_ambiguity()
    {
        var first = new WindowsAppWindowCandidate(
            new(new IntPtr(10), 1));
        var second = new WindowsAppWindowCandidate(
            new(new IntPtr(11), 2));

        Assert.Equal(
            WindowsAppWindowDiscoveryState.Found,
            WindowsAppWindowSelector.Select([], [first]).State);
        Assert.Equal(
            WindowsAppWindowDiscoveryState.Ambiguous,
            WindowsAppWindowSelector.Select(
                [],
                [first, second]).State);
    }

    [Fact]
    public void Isolated_host_requires_new_process_and_verified_desktop()
    {
        var native = new FakeIsolatedDesktopNative();
        var host = new WindowsAppIsolatedDesktopHost(native);

        using var session = host.Activate(ValidMsAvd);

        Assert.StartsWith(
            "Steward.Rdp.",
            session.DesktopName,
            StringComparison.Ordinal);
        Assert.Equal(42u, session.ProcessId);
        Assert.Equal(session.DesktopName, native.ExpectedDesktopName);
        session.Dispose();
        Assert.Equal([42u], native.Terminated);
        Assert.True(native.DesktopDisposed);
    }

    [Fact]
    public void Isolated_host_fails_closed_on_process_reuse_or_escape()
    {
        var reused = new FakeIsolatedDesktopNative
        {
            Existing = new HashSet<uint> { 42 }
        };
        var reuseError = Assert.Throws<DevBoxRemoteViewerException>(() =>
            new WindowsAppIsolatedDesktopHost(reused)
                .Activate(ValidMsAvd));
        Assert.Equal(
            "WindowsAppIsolatedDesktopExistingProcess",
            reuseError.Code);
        Assert.Empty(reused.Terminated);
        Assert.False(reused.DesktopDisposed);

        var escaped = new FakeIsolatedDesktopNative
        {
            Confined = false
        };
        var containmentError =
            Assert.Throws<DevBoxRemoteViewerException>(() =>
                new WindowsAppIsolatedDesktopHost(escaped)
                    .Activate(ValidMsAvd));
        Assert.Equal(
            "WindowsAppIsolatedDesktopContainmentFailed",
            containmentError.Code);
        Assert.Equal([42u], escaped.Terminated);
        Assert.True(escaped.DesktopDisposed);
    }

    private sealed class UnusedIdentitySource :
        IDevBoxSilentCredentialSource
    {
        public Task<(
            DevBoxIdentityContext Context,
            Azure.Core.TokenCredential Credential,
            Azure.Core.AccessToken Token)> OpenAsync(
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "Identity is not used by resource validation tests.");
    }

    private sealed class CapturingActivator : IExternalUriActivator
    {
        public List<Uri> Values { get; } = [];
        public void Activate(Uri uri) => Values.Add(uri);
    }

    private sealed class FakeWindowTracker :
        IWindowsAppWindowTracker
    {
        private static readonly WindowsAppWindowIdentity Window =
            new(new IntPtr(42), 7);

        public bool SurfaceCalled { get; private set; }

        public IReadOnlyList<WindowsAppWindowCandidate> Snapshot() =>
            [];

        public Task<WindowsAppWindowDiscovery>
            FindActivatedWindowAsync(
                IReadOnlyList<WindowsAppWindowCandidate> before,
                TimeSpan timeout,
                CancellationToken cancellationToken) =>
            Task.FromResult(new WindowsAppWindowDiscovery(
                WindowsAppWindowDiscoveryState.Found,
                Window));

        public bool IsAlive(WindowsAppWindowIdentity window) =>
            window == Window;

        public bool Surface(WindowsAppWindowIdentity window)
        {
            SurfaceCalled = window == Window;
            return SurfaceCalled;
        }
    }

    private sealed class FakeIsolatedDesktopNative :
        IWindowsAppIsolatedDesktopNative
    {
        public IReadOnlySet<uint> Existing { get; init; } =
            new HashSet<uint>();
        public bool Confined { get; init; } = true;
        public List<uint> Terminated { get; } = [];
        public bool DesktopDisposed { get; private set; }
        public string? ExpectedDesktopName { get; private set; }

        public IReadOnlySet<uint> SnapshotWindowsAppProcesses() =>
            Existing;

        public IDisposable CreateDesktop(string name)
        {
            ExpectedDesktopName = name;
            return new CallbackDisposable(
                () => DesktopDisposed = true);
        }

        public uint ActivateProtocol(
            IDisposable desktop,
            Uri uri) =>
            uri == ValidMsAvd ? 42u : 0u;

        public bool IsProcessConfinedToDesktop(
            uint processId,
            string desktopName,
            TimeSpan timeout) =>
            processId == 42 &&
            desktopName == ExpectedDesktopName &&
            timeout == TimeSpan.FromSeconds(10) &&
            Confined;

        public void TerminateProcess(uint processId) =>
            Terminated.Add(processId);
    }

    private sealed class CallbackDisposable(Action callback) :
        IDisposable
    {
        private int disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
                callback();
        }
    }
}
