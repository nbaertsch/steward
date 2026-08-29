namespace Steward.Rdp.Windows;

public interface IRdpActiveXConfigurationTarget
{
    string Server { set; }
    string GatewayHostname { set; }
    uint GatewayUsageMethod { set; }
    uint GatewayProfileUsageMethod { set; }
    uint GatewayCredentialsSource { set; }
    uint GatewayBrokeringType { set; }
    bool GatewayCredentialSharing { set; }
    bool DisableCredentialsDelegation { set; }
    string LoadBalanceInfo { set; }
    bool EnableRdsAadAuth { set; }
    bool EnableCredSspSupport { set; }
    bool EnableAutoReconnect { set; }
    int MaximumReconnectAttempts { set; }
    bool RedirectClipboard { set; }
    bool RedirectDrives { set; }
    bool RedirectPrinters { set; }
    bool RedirectPorts { set; }
    bool RedirectSmartCards { set; }
    bool RedirectDevices { set; }
    bool RedirectPointOfServiceDevices { set; }
    bool RedirectDirectX { set; }
    uint AudioRedirectionMode { set; }
    bool AudioCaptureRedirection { set; }
    uint VideoPlaybackMode { set; }
    uint PerformanceFlags { set; }
}

public static class RdpActiveXConfigurator
{
    public const uint DisabledVisualEffects =
        0x00000001 |
        0x00000002 |
        0x00000004 |
        0x00000008 |
        0x00000020 |
        0x00000040;

    public static void Apply(
        RdpConnectionProfile profile,
        IRdpActiveXConfigurationTarget target)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(target);

        target.Server = profile.FullAddress;
        target.GatewayHostname = profile.GatewayHostname;
        target.GatewayUsageMethod = checked((uint)profile.GatewayUsageMethod);
        target.GatewayProfileUsageMethod =
            checked((uint)profile.GatewayProfileUsageMethod);
        target.GatewayCredentialsSource =
            checked((uint)profile.GatewayCredentialsSource);
        target.GatewayBrokeringType = profile.GatewayBrokeringType;
        target.GatewayCredentialSharing = false;
        target.DisableCredentialsDelegation = true;
        target.LoadBalanceInfo = profile.LoadBalanceInfo;
        target.EnableRdsAadAuth = profile.EnableRdsAadAuth;
        target.EnableCredSspSupport = profile.EnableCredSspSupport;
        target.EnableAutoReconnect = profile.AutoReconnect;
        target.MaximumReconnectAttempts = profile.MaxReconnectAttempts;

        target.RedirectClipboard = false;
        target.RedirectDrives = false;
        target.RedirectPrinters = false;
        target.RedirectPorts = false;
        target.RedirectSmartCards = false;
        target.RedirectDevices = false;
        target.RedirectPointOfServiceDevices = false;
        target.RedirectDirectX = false;
        target.AudioRedirectionMode = 2;
        target.AudioCaptureRedirection = false;
        target.VideoPlaybackMode = 1;
        target.PerformanceFlags = DisabledVisualEffects;
    }
}

public enum RdpFailureKind
{
    None,
    Configuration,
    ConnectionTimeout,
    LoginTimeout,
    Disconnected,
    Fatal,
    GatewayNotObserved,
    Cancelled
}

public sealed record RdpDiagnosticEvent(
    string Name,
    DateTimeOffset OccurredAtUtc,
    int? Code = null,
    int? ExtendedCode = null);

public sealed record RdpSessionResult(
    bool Succeeded,
    RdpFailureKind FailureKind,
    int? DisconnectReason,
    int? ExtendedDisconnectReason,
    int? FatalErrorCode,
    int? LogonErrorCode,
    bool GatewayUseObserved,
    string? GatewayRemoteEndpoint,
    IReadOnlyList<RdpDiagnosticEvent> Events);

public static class RdpFailureClassifier
{
    public static RdpFailureKind Classify(
        bool connected,
        bool loginComplete,
        bool gatewayObserved,
        int? disconnectReason,
        int? fatalErrorCode,
        bool cancelled)
    {
        if (cancelled)
            return RdpFailureKind.Cancelled;
        if (fatalErrorCode.HasValue)
            return RdpFailureKind.Fatal;
        if (disconnectReason.HasValue)
            return RdpFailureKind.Disconnected;
        if (loginComplete && !gatewayObserved)
            return RdpFailureKind.GatewayNotObserved;
        if (!connected)
            return RdpFailureKind.ConnectionTimeout;
        if (!loginComplete)
            return RdpFailureKind.LoginTimeout;
        return RdpFailureKind.None;
    }
}
