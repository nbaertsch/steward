using System.Security.AccessControl;
using System.Security.Principal;
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
        StringComparison.OrdinalIgnoreCase)
};
var rdCoreEnabled = string.Equals(
    Environment.GetEnvironmentVariable(
        "STEWARD_RDCORE_INTEGRATION_ENABLED"),
    "true",
    StringComparison.OrdinalIgnoreCase);
var root = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "Steward",
    "connection-host");
var identity = new DevBoxConnectionIdentityService(
    new DevBoxConnectionIdentityStore());
var registration = new RdpDvcPluginRegistration(
    new CurrentUserRegistryStore(),
    new WindowsRdpDvcExecutableValidator());
var authorization =
    new SingleUseControlConnectAuthorizationValidator();
if (options.EnableLiveConnections && rdCoreEnabled &&
    Environment.GetEnvironmentVariable(
        "STEWARD_CONNECTION_HOST_CONTROL_AUTHORIZATION_TOKEN") is
        { Length: > 0 } controlAuthorizationToken)
    authorization.Register(controlAuthorizationToken);
HttpDevBoxBrokerHttpTransport? http = null;
ProductionRdpDvcRuntimeEvidenceSource? productionEvidenceSource = null;
try
{
    IDevBoxConnectionResolver resolver;
    IRdCoreCompatibilityInspector compatibility;
    IRdCoreConnectionRuntime runtime;
    if (options.EnableLiveConnections && rdCoreEnabled)
    {
        var evidencePipeName = RequireSetting(
            "STEWARD_DVC_EVIDENCE_PIPE_NAME");
        var evidenceKeyFile = RequireExistingFile(
            "STEWARD_DVC_EVIDENCE_KEY_FILE");
        var evidenceTicketDirectory = RequireExistingDirectory(
            "STEWARD_DVC_EVIDENCE_TICKET_DIRECTORY");
        var dvcAuthenticationKeyFile = RequirePrivateFile(
            "STEWARD_DVC_AUTH_KEY_FILE");
        var controlSigningPrivateKeyFile = RequirePrivateFile(
            "STEWARD_RDCORE_CONTROL_SIGNING_PRIVATE_KEY_FILE");
        var nodeSigningPublicKeyFile = RequireExistingFile(
            "STEWARD_RDCORE_NODE_TRANSPORT_SIGNING_PUBLIC_KEY_FILE");
        var controlIdentity = RequireSetting(
            "STEWARD_RDCORE_CONTROL_IDENTITY");
        var nodeIdentity = RequireSetting(
            "STEWARD_RDCORE_NODE_IDENTITY");
        var devBoxName = RequireSetting("STEWARD_DEVBOX_BOX_NAME");
        RdpDvcEmbeddingConfigurationStore.Write(
            evidencePipeName,
            evidenceKeyFile);
        productionEvidenceSource =
            ProductionRdpDvcRuntimeEvidenceSource.FromProtectedFile(
                new DpapiRdpDvcEvidenceTicketStore(
                    evidenceTicketDirectory),
                evidencePipeName,
                evidenceKeyFile);
        var binding = await identity.GetBindingAsync(
                CancellationToken.None)
            .ConfigureAwait(false);
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
                    .WindowsAppBrokerRedirectUri
        };
        var report = new RdCoreCompatibilityProbe().Inspect();
        var artifacts = report.Artifacts
            ?? throw new InvalidOperationException(
                "Compatible Windows App artifacts are unavailable.");
        compatibility = new RdCoreCompatibilityInspector(report);
        var catalog = new RdCoreAvdResourceCatalog(
            report,
            rdCoreOptions);
        http = new HttpDevBoxBrokerHttpTransport(identity);
        resolver = new DevBoxConnectionResolver(
            new DevBoxBrokerFeedResolver(identity, catalog, http));
        runtime = new ProductionRdCoreConnectionRuntime(
            new WindowsAppIsolatedConnectionLeaseFactory(
                report,
                new Windows365EndUserResourceCatalog(
                    http,
                    artifacts.PackageVersion.ToString(),
                    devBoxName)),
            productionEvidenceSource,
            TimeSpan.FromMinutes(5),
            new ProtectedFileRdpDvcLocalCarrier(
                dvcAuthenticationKeyFile,
                controlSigningPrivateKeyFile,
                nodeSigningPublicKeyFile,
                controlIdentity,
                nodeIdentity,
                evidencePipeName,
                evidenceKeyFile));
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
        new AtomicJsonConnectionMetadataStore(
            Path.Combine(root, "connections.v1.json")));
    await orchestrator.InitializeAsync().ConfigureAwait(false);
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
