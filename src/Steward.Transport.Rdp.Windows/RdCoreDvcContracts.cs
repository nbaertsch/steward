namespace Steward.Transport.Rdp.Windows;

public sealed class RdCoreDvcConfigurationRequest
{
    public RdCoreDvcConfigurationRequest(
        bool silentMode,
        bool allowThirdPartyPlugins,
        DvcPluginRegistrationStatus dvcRegistration)
    {
        SilentMode = silentMode;
        AllowThirdPartyPlugins = allowThirdPartyPlugins;
        DvcRegistration = dvcRegistration ??
            throw new ArgumentNullException(
                nameof(dvcRegistration));
    }

    public bool SilentMode { get; }
    public bool AllowThirdPartyPlugins { get; }
    public DvcPluginRegistrationStatus DvcRegistration { get; }

    public override string ToString() =>
        "RdCoreDvcConfigurationRequest { Redacted }";
}

public enum RdCoreConnectionState
{
    Unknown,
    Resolving,
    Connecting,
    Connected,
    Reconnecting,
    Disconnected,
    Failed
}

public enum RdCoreDvcEvidenceEvent
{
    RdCoreConnected,
    WtsPluginsLoaded,
    StewardComClassActivated,
    StewardPluginInitialized,
    StewardChannelOpened,
    DvcHmacAuthenticated,
    SecurePeerAuthenticated
}

public sealed class RdCoreDvcEvidenceSequence
{
    private static readonly RdCoreDvcEvidenceEvent[] RequiredOrder =
        Enum.GetValues<RdCoreDvcEvidenceEvent>();
    private readonly object sync = new();
    private int next;

    public RdCoreDvcEvidenceSequence(long connectionGeneration)
    {
        if (connectionGeneration <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(connectionGeneration));
        ConnectionGeneration = connectionGeneration;
    }

    public long ConnectionGeneration { get; }

    public void Record(
        RdCoreDvcEvidenceEvent evidenceEvent,
        string? pluginAddInName = null,
        Guid? pluginClsid = null,
        string? channelName = null)
    {
        lock (sync)
        {
            if (next >= RequiredOrder.Length ||
                RequiredOrder[next] != evidenceEvent)
                throw new InvalidOperationException(
                    "RDCore/DVC evidence was received out of order.");
            if (evidenceEvent ==
                    RdCoreDvcEvidenceEvent.StewardPluginInitialized &&
                (!string.Equals(
                    pluginAddInName,
                    StewardRdpDvc.AddInName,
                    StringComparison.Ordinal) ||
                 pluginClsid != StewardRdpDvc.PluginClsid))
                throw new InvalidOperationException(
                    "The initialized DVC plugin identity is not Steward.");
            if (evidenceEvent ==
                    RdCoreDvcEvidenceEvent.StewardChannelOpened &&
                !string.Equals(
                    channelName,
                    StewardRdpDvc.ChannelName,
                    StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "The opened DVC channel identity is not Steward.");
            next++;
        }
    }

    internal bool IsComplete
    {
        get
        {
            lock (sync)
                return next == RequiredOrder.Length;
        }
    }

    public override string ToString() =>
        "RdCoreDvcEvidenceSequence { Redacted }";
}

public sealed class RdCoreDvcConfigurationResult
{
    internal RdCoreDvcConfigurationResult(
        bool accepted,
        string code,
        long? connectionGeneration)
    {
        Accepted = accepted;
        Code = code;
        ConnectionGeneration = connectionGeneration;
    }

    public bool Accepted { get; }
    public string Code { get; }
    public long? ConnectionGeneration { get; }

    public override string ToString() =>
        $"RdCoreDvcConfigurationResult " +
        $"{{ Accepted = {Accepted}, Code = {Code} }}";
}

public static class RdCoreDvcContract
{
    public const string ConfigurationReadyCode =
        "RDCORE_DVC_CONFIGURATION_READY";
    public const string EvidenceVerifiedCode =
        "RDCORE_DVC_TRANSPORT_READY";

    public static RdCoreDvcConfigurationResult ValidateConfiguration(
        RdCoreDvcConfigurationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.SilentMode)
            return Rejected("RDCORE_SILENT_MODE_REQUIRED");
        if (!request.AllowThirdPartyPlugins)
            return Rejected(
                "RDCORE_ALLOW_THIRD_PARTY_PLUGINS_REQUIRED");
        if (!RdpDvcPluginRegistration.IsExactStewardRegistration(
                request.DvcRegistration))
            return Rejected(
                "RDCORE_EXACT_STEWARD_DVC_REGISTRATION_REQUIRED");
        return new(
            true,
            ConfigurationReadyCode,
            null);
    }

    public static RdCoreDvcConfigurationResult ValidateEvidence(
        RdCoreDvcConfigurationRequest request,
        RdCoreDvcEvidenceSequence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        var configuration = ValidateConfiguration(request);
        if (!configuration.Accepted)
            return configuration;
        if (!evidence.IsComplete)
            return Rejected(
                "RDCORE_DVC_AUTHENTICATED_EVIDENCE_CHAIN_REQUIRED");
        return new(
            true,
            EvidenceVerifiedCode,
            evidence.ConnectionGeneration);
    }

    private static RdCoreDvcConfigurationResult Rejected(
        string code) =>
        new(false, code, null);
}
