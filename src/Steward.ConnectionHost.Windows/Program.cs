using System.Security.AccessControl;
using System.Security.Principal;
using Azure.Developer.DevCenter;
using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Steward.Transport.Rdp.Windows;

var options = new ConnectionHostOptions
{
    EnableLiveConnections = string.Equals(
        Environment.GetEnvironmentVariable(
            "STEWARD_CONNECTION_HOST_ENABLE_LIVE"),
        "true",
        StringComparison.OrdinalIgnoreCase),
    PipeName = Environment.GetEnvironmentVariable(
        "STEWARD_CONNECTION_HOST_PIPE_NAME") ??
        "Steward.ConnectionHost.v1",
    DiagnosticSink = string.Equals(
        Environment.GetEnvironmentVariable(
            "STEWARD_CONNECTION_HOST_DIAGNOSTICS"),
        "true",
        StringComparison.OrdinalIgnoreCase)
        ? Console.Error.WriteLine
        : null
};
var rdCoreEnabled = string.Equals(
    Environment.GetEnvironmentVariable(
        "STEWARD_RDCORE_INTEGRATION_ENABLED"),
    "true",
    StringComparison.OrdinalIgnoreCase);
var connectionHostRoot = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "Steward",
    "connection-host");
var root = Path.Combine(
    connectionHostRoot,
    SafePathSegment(options.PipeName));
var stateStore = new SqliteConnectionMetadataStore(
    Path.Combine(root, "connections.v2.db"),
    Path.Combine(connectionHostRoot, "connections.v1.json"));
var identity = new DevBoxConnectionIdentityService(
    new DevBoxConnectionIdentityStore());
var defaultIdentity = new DevBoxIdentityService(
    new DevBoxIdentityStore());
var registration = new RdpDvcPluginRegistration(
    new CurrentUserRegistryStore(),
    new WindowsRdpDvcExecutableValidator());
var authorization =
    new SingleUseControlConnectAuthorizationValidator();
var controlAuthorizationToken = Environment.GetEnvironmentVariable(
    "STEWARD_CONNECTION_HOST_CONTROL_AUTHORIZATION_TOKEN");
Environment.SetEnvironmentVariable(
    "STEWARD_CONNECTION_HOST_CONTROL_AUTHORIZATION_TOKEN",
    null);
var autoConnectFile = Environment.GetEnvironmentVariable(
    "STEWARD_CONNECTION_HOST_AUTO_CONNECT_FILE");
if (!string.IsNullOrWhiteSpace(controlAuthorizationToken) &&
    !string.IsNullOrWhiteSpace(autoConnectFile))
    throw new InvalidOperationException(
        "ConnectionHost authorization must use either an environment token or a protected auto-connect descriptor, not both.");
if (options.EnableLiveConnections && rdCoreEnabled &&
    controlAuthorizationToken is { Length: > 0 })
{
    authorization.Register(controlAuthorizationToken);
    controlAuthorizationToken = null;
}
HttpDevBoxBrokerHttpTransport? http = null;
ProductionRdpDvcRuntimeEvidenceSource? productionEvidenceSource = null;
RdpDvcOpaqueControlPipeBridge? controlBridge = null;
DpapiRdpDvcEvidenceTicketStore? ticketStore = null;
try
{
    IDevBoxConnectionResolver resolver;
    IRdCoreCompatibilityInspector compatibility;
    IRdCoreConnectionRuntime runtime;
    if (options.EnableLiveConnections && rdCoreEnabled)
    {
        var evidencePipeName = RequireSetting(
            "STEWARD_DVC_EVIDENCE_PIPE_NAME");
        var dvcBrokerPipeName =
            options.PipeName + ".DvcBroker";
        if (dvcBrokerPipeName.Length > 128)
            throw new InvalidOperationException(
                "The per-host DVC broker pipe name is too long.");
        var evidenceKeyFile = RequireExistingFile(
            "STEWARD_DVC_EVIDENCE_KEY_FILE");
        var evidenceTicketDirectory = RequireExistingDirectory(
            "STEWARD_DVC_EVIDENCE_TICKET_DIRECTORY");
        var dvcAuthenticationKeyFile = RequirePrivateFile(
            "STEWARD_DVC_AUTH_KEY_FILE");

        var devBoxName = RequireSetting("STEWARD_DEVBOX_BOX_NAME");
        controlBridge = new(
            new(
                RequireSetting(
                    "STEWARD_CONTROL_RDP_DVC_CARRIER_PIPE_NAME"),
                TimeSpan.FromSeconds(
                    ParseBoundedSeconds(
                        "STEWARD_CONTROL_RDP_DVC_CARRIER_TIMEOUT_SECONDS",
                        30,
                        300)),
                64 * 1024),
            stateStore);
        ticketStore = new(
            evidenceTicketDirectory);
        productionEvidenceSource =
            ProductionRdpDvcRuntimeEvidenceSource.FromProtectedFile(
                ticketStore,
                evidencePipeName,
                evidenceKeyFile);
        var binding = await identity.GetBindingAsync(
                CancellationToken.None)
            .ConfigureAwait(false);
        var report = new RdCoreCompatibilityProbe().Inspect();
        var artifacts = report.Artifacts
            ?? throw new InvalidOperationException(
                "Compatible Windows App artifacts are unavailable.");
        var brokerUserAgent =
            "win365.nxt/" + artifacts.PackageVersion;
        var rdCoreOptions = new RdCoreIntegrationOptions
        {
            Enabled = true,
            AvdFeedUri = ParseUri(
                Environment.GetEnvironmentVariable(
                    "STEWARD_RDCORE_AVD_FEED_URI")),
            Account = binding.Username,
            ConsumerHandlesClaimsTokenRequest =
                !RdCoreProcessIdentity.HasPackageIdentity(),
            ClaimsClientId =
                DevBoxConnectionIdentityConstants.WindowsAppClientId,
            ClaimsRedirectUri =
                DevBoxConnectionIdentityConstants
                    .WindowsAppBrokerRedirectUri,
            OperationTimeout = TimeSpan.FromSeconds(
                ParseBoundedSeconds(
                    "STEWARD_RDCORE_OPERATION_TIMEOUT_SECONDS",
                    15,
                    60)),
            DiagnosticSink = options.DiagnosticSink is null
                ? null
                : value => options.DiagnosticSink(
                    FilterRdCoreDiagnostic(value))
        };
        compatibility = new RdCoreCompatibilityInspector(report);
        http = new HttpDevBoxBrokerHttpTransport(identity);
        var catalog = new HttpDevBoxAvdResourceCatalog(
            rdCoreOptions.AvdFeedUri ??
                throw new InvalidOperationException(
                    "The production AVD feed URI is unavailable."),
            http,
            brokerUserAgent);
        resolver = new DevBoxConnectionResolver(
            new DevBoxBrokerFeedResolver(
                identity,
                catalog,
                http,
                new()
                {
                    CatalogTimeout = rdCoreOptions.OperationTimeout,
                    RdpTimeout = rdCoreOptions.OperationTimeout,
                    MaximumResources = 1024,
                    AllowSetCookieResponse = true,
                    UserAgent = brokerUserAgent
                }),
            new AzureDevBoxRemoteConnectionProvider(defaultIdentity));
        runtime = new ProductionRdCoreConnectionRuntime(
            new WindowsAppIsolatedConnectionLeaseFactory(
                report,
                new Windows365EndUserResourceCatalog(
                    http,
                    artifacts.PackageVersion.ToString(),
                    devBoxName),
                new(
                    root,
                    dvcBrokerPipeName,
                    evidencePipeName,
                    evidenceKeyFile)),
            productionEvidenceSource,
            TimeSpan.FromMinutes(5),
            new ProtectedFileRdpDvcLocalCarrier(
                dvcAuthenticationKeyFile,
                dvcBrokerPipeName,
                evidencePipeName,
                evidenceKeyFile,
                new SqliteConnectionReconnectHighWaterStore(
                    Path.Combine(
                        root,
                        "reconnect-high-water.v2.db")),
                controlBridge),
            generationStore: new SqliteConnectionGenerationStore(
                Path.Combine(root, "connection-generations.v2.db")));
    }
    else
    {
        resolver = new DisabledDevBoxConnectionResolver();
        compatibility = new RdCoreCompatibilityInspector();
        runtime = new DisabledRdCoreConnectionRuntime();
    }

    await using var orchestrator = new ConnectionHostOrchestrator(
        options,
        identity,
        resolver,
        compatibility,
        new DvcRegistrationSnapshotProvider(registration),
        runtime,
        authorization,
        stateStore,
        ticketStore is null
            ? null
            : new DpapiConnectionRecoveryMaterialIssuer(
                authorization,
                ticketStore));
    await orchestrator.InitializeAsync().ConfigureAwait(false);
    var autoConnect =
        await ConnectionHostAutoConnectOptions.LoadAsync(
                autoConnectFile,
                CancellationToken.None)
            .ConfigureAwait(false);
    if (autoConnect is not null)
    {
        if (!options.EnableLiveConnections ||
            !rdCoreEnabled ||
            ticketStore is null)
            throw new InvalidOperationException(
                "ConnectionHost auto-connect requires the production RDCore runtime.");
        var recoveryAuthorization = Convert.ToHexString(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var evidenceReference = "recovery-" +
            System.Security.Cryptography.RandomNumberGenerator.GetHexString(24);
        authorization.Register(recoveryAuthorization);
        var connected = false;
        try
        {
            ticketStore.Write(
                evidenceReference,
                new(
                    autoConnect.SessionId,
                    autoConnect.HostId,
                    autoConnect.NodeIncarnationId,
                    0,
                    Guid.NewGuid(),
                    ProtocolVersion: 2));
            var providerClient = new DevBoxesClient(
                autoConnect.DevBoxEndpoint,
                new DevBoxSilentTokenCredential(defaultIdentity));
            var remote = await providerClient.GetRemoteConnectionAsync(
                    autoConnect.Project,
                    autoConnect.User,
                    autoConnect.DevBox,
                    CancellationToken.None)
                .ConfigureAwait(false);
            var providerResource = remote.Value.RdpConnectionUri ??
                throw new InvalidDataException(
                    "Dev Box returned no RDP resource for auto-connect.");
            await RequireAcceptedAsync(
                    orchestrator,
                    new(
                        ConnectionHostProtocol.CurrentVersion,
                        Guid.NewGuid().ToString("N"),
                        ConnectionHostOperation.Resolve,
                        autoConnect.ConnectionId,
                        providerResource.AbsoluteUri,
                        DesiredConnection: new(
                            autoConnect.DevBoxEndpoint,
                            autoConnect.Project,
                            autoConnect.User,
                            autoConnect.DevBox,
                            autoConnect.SessionId,
                            autoConnect.HostId,
                            autoConnect.NodeIncarnationId)))
                .ConfigureAwait(false);
            await RequireAcceptedAsync(
                    orchestrator,
                    new(
                        ConnectionHostProtocol.CurrentVersion,
                        Guid.NewGuid().ToString("N"),
                        ConnectionHostOperation.Prepare,
                        autoConnect.ConnectionId))
                .ConfigureAwait(false);
            await RequireAcceptedAsync(
                    orchestrator,
                    new(
                        ConnectionHostProtocol.CurrentVersion,
                        Guid.NewGuid().ToString("N"),
                        ConnectionHostOperation.Connect,
                        autoConnect.ConnectionId,
                        AuthorizationToken:
                            recoveryAuthorization,
                        DvcEvidenceReference:
                            evidenceReference))
                .ConfigureAwait(false);
            connected = true;
        }
        finally
        {
            if (!connected)
                await ticketStore.ReleaseAsync(
                        evidenceReference)
                    .ConfigureAwait(false);
        }
        autoConnect = null;
    }
    await new ConnectionHostPipeServer(options, orchestrator)
        .RunAsync(CancellationToken.None)
        .ConfigureAwait(false);
}
finally
{
    http?.Dispose();
    if (productionEvidenceSource is not null)
        await productionEvidenceSource.DisposeAsync()
            .ConfigureAwait(false);

}

static Uri? ParseUri(string? value) =>
    Uri.TryCreate(value, UriKind.Absolute, out var uri)
        ? uri
        : null;

static int ParseBoundedSeconds(
    string name,
    int fallback,
    int maximum) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? int.TryParse(value, out var seconds) &&
          seconds > 0 &&
          seconds <= maximum
            ? seconds
            : throw new InvalidOperationException(
                $"Production setting '{name}' is invalid.")
        : fallback;

static string FilterRdCoreDiagnostic(string value)
{
    var failed = System.Text.RegularExpressions.Regex.Match(
        value,
        @"^(catalog-[a-z-]+-failed-[A-Za-z0-9_.]+-0x[0-9A-Fa-f]{8})");
    if (failed.Success)
        return failed.Groups[1].Value.Length <= 128
            ? failed.Groups[1].Value
            : "catalog-diagnostic-redacted";
    if (value.Contains("-failed-", StringComparison.Ordinal) ||
        value.Contains("-reason-", StringComparison.Ordinal) ||
        value.Contains("-detail-", StringComparison.Ordinal))
        return "catalog-diagnostic-redacted";
    return value.Length <= 128 &&
           (value.StartsWith("catalog-", StringComparison.Ordinal) ||
            value.StartsWith("workspace-", StringComparison.Ordinal)) &&
           value.All(character =>
               char.IsAsciiLetterOrDigit(character) ||
               character is '-' or '_')
        ? value
        : "catalog-diagnostic-redacted";
}

static string RequireSetting(string name) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value
        : throw new InvalidOperationException(
            $"Required production setting '{name}' is missing.");

static string RequireExistingFile(string name)
{
    var configured = RequireSetting(name);
    if (!Path.IsPathFullyQualified(configured))
        throw new InvalidOperationException(
            $"Required production key file '{name}' must be absolute.");
    var path = Path.GetFullPath(configured);
    if (
        !File.Exists(path) ||
        File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        throw new InvalidOperationException(
            $"Required production key file '{name}' is unavailable.");
    return path;
}

static string RequireExistingDirectory(string name)
{
    var configured = RequireSetting(name);
    if (!Path.IsPathFullyQualified(configured))
        throw new InvalidOperationException(
            $"Required production directory '{name}' must be absolute.");
    var path = Path.GetFullPath(configured);
    if (
        !Directory.Exists(path) ||
        File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        throw new InvalidOperationException(
            $"Required production directory '{name}' is unavailable.");
    return path;
}

static string RequirePrivateFile(string name)
{
    var path = RequireExistingFile(name);
    var current = WindowsIdentity.GetCurrent().User
        ?? throw new InvalidOperationException(
            "The current Windows identity has no SID.");
    var system = new SecurityIdentifier(
        WellKnownSidType.LocalSystemSid,
        null);
    var security = new FileInfo(path).GetAccessControl();
    if (!current.Equals(
            security.GetOwner(typeof(SecurityIdentifier))))
        throw new UnauthorizedAccessException(
            $"Required production key file '{name}' has an invalid owner.");
    var rules = security.GetAccessRules(
        includeExplicit: true,
        includeInherited: true,
        typeof(SecurityIdentifier));
    foreach (FileSystemAccessRule rule in rules)
        if (rule.AccessControlType == AccessControlType.Allow &&
            !current.Equals(rule.IdentityReference) &&
            !system.Equals(rule.IdentityReference))
            throw new UnauthorizedAccessException(
                $"Required production key file '{name}' grants unintended access.");
    return path;
}

static string SafePathSegment(string value)
{
    var result = new string(value.Select(character =>
            char.IsAsciiLetterOrDigit(character) ||
            character is '-' or '_' or '.'
                ? character
                : '_')
        .ToArray());
    return string.IsNullOrWhiteSpace(result)
        ? "default"
        : result;
}

static async Task RequireAcceptedAsync(
    ConnectionHostOrchestrator orchestrator,
    ConnectionHostCommand command)
{
    var response = await orchestrator.ExecuteAsync(
            command,
            CancellationToken.None)
        .ConfigureAwait(false);
    if (!response.Accepted)
        throw new InvalidOperationException(
            $"ConnectionHost auto-connect failed with {response.Code}.");
}
internal sealed class AzureDevBoxRemoteConnectionProvider(
    DevBoxIdentityService identity) : IDevBoxRemoteConnectionProvider
{
    public async Task<Uri> GetRemoteConnectionAsync(
        DesiredConnectionRecord desired,
        CancellationToken cancellationToken)
    {
        desired = desired.Validate();
        var client = new DevBoxesClient(
            desired.DevBoxEndpoint,
            new DevBoxSilentTokenCredential(identity));
        var response = await client.GetRemoteConnectionAsync(
                desired.Project,
                desired.User,
                desired.DevBox,
                cancellationToken)
            .ConfigureAwait(false);
        return response.Value.RdpConnectionUri ??
            throw new InvalidDataException(
                "Dev Box returned no RDP resource for desired recovery.");
    }
}
