using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using Azure.Developer.DevCenter;
using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.LiveAcceptance;

internal sealed class LiveAcceptanceComposition : IAsyncDisposable
{
    private readonly ConnectionHostOrchestrator orchestrator;
    private readonly HttpDevBoxBrokerHttpTransport http;
    private readonly CancellationTokenSource pipeStop;
    private readonly Task pipeServer;
    private readonly IReadOnlyList<string> unusedTicketPaths;

    private LiveAcceptanceComposition(
        LiveAcceptanceRunner runner,
        IReadOnlyCollection<string> sensitiveValues,
        ConnectionHostOrchestrator orchestrator,
        HttpDevBoxBrokerHttpTransport http,
        CancellationTokenSource pipeStop,
        Task pipeServer,
        IReadOnlyList<string> unusedTicketPaths)
    {
        Runner = runner;
        SensitiveValues = sensitiveValues;
        this.orchestrator = orchestrator;
        this.http = http;
        this.pipeStop = pipeStop;
        this.pipeServer = pipeServer;
        this.unusedTicketPaths = unusedTicketPaths;
    }

    internal LiveAcceptanceRunner Runner { get; }

    internal IReadOnlyCollection<string> SensitiveValues { get; }

    internal static async Task<LiveAcceptanceComposition> CreateAsync(
        LiveAcceptanceOptions options,
        CancellationToken cancellationToken)
    {
        if (!options.HasRequiredConsent)
            throw new InvalidOperationException(
                "Exact live-connect and cloud-read consent are required.");
        Console.Error.WriteLine("LIVE STAGE: rdcore-compatibility");
        var capability = new RdCoreCompatibilityProbe().Inspect();
        Console.Error.WriteLine(
            $"LIVE RDCORE COMPATIBILITY: {capability.Code}");
        foreach (var diagnostic in capability.Diagnostics)
            Console.Error.WriteLine(
                $"LIVE RDCORE DIAGNOSTIC: {diagnostic.Code}; " +
                $"component={diagnostic.Component}; " +
                $"detail={diagnostic.Description}");
        if (!capability.IsCompatible || capability.Artifacts is null)
            throw new InvalidOperationException(
                $"Installed RDCore package compatibility failed with {capability.Code}.");
        var loadedWinRt = AppDomain.CurrentDomain.GetAssemblies()
            .Where(assembly => string.Equals(
                assembly.GetName().Name,
                "WinRT.Runtime",
                StringComparison.OrdinalIgnoreCase))
            .Select(assembly =>
                assembly.GetName().Version?.ToString() ?? "unknown")
            .ToArray();
        Console.Error.WriteLine(
            $"LIVE STAGE: winrt-loaded={string.Join(',', loadedWinRt)}");

        Console.Error.WriteLine("LIVE STAGE: dvc-registration");
        var registration = new RdpDvcPluginRegistration(
            new CurrentUserRegistryStore(),
            new WindowsRdpDvcExecutableValidator());
        var registrationStatus = registration.GetStatus();
        if (!RdpDvcPluginRegistration.IsExactStewardRegistration(
                registrationStatus))
            throw new InvalidOperationException(
                $"Exact Steward DVC registration is required ({registrationStatus.Code}).");

        Console.Error.WriteLine("LIVE STAGE: identity-status");
        var defaultStore = new DevBoxIdentityStore();
        var defaultIdentity = new DevBoxIdentityService(defaultStore);
        var defaultStatus = await defaultIdentity.StatusAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var connectionIdentity = new DevBoxConnectionIdentityService(
            defaultStore,
            new DevBoxConnectionIdentityStore());
        var connectionStatus = await connectionIdentity.StatusAsync(
                cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine("LIVE STAGE: bootstrap-receipt");
        var controlPublicKey = ReadPublicKey(
            options.ControlSigningPublicKeyFile);
        var nodePublicKey = ReadPublicKey(
            options.NodeSigningPublicKeyFile);
        var bootstrap = await BootstrapDeploymentReceiptLoader.PrepareAsync(
                options,
                nodePublicKey,
                controlPublicKey,
                new BootstrapDeployCliInvoker(),
                cancellationToken)
            .ConfigureAwait(false);

        Console.Error.WriteLine("LIVE STAGE: provider-resolution");
        var providerClient = new DevBoxesClient(
            options.DevBoxEndpoint,
            new DevBoxSilentTokenCredential(defaultIdentity));
        var resolved = await DevBoxLiveConnectionResolver.ResolveAsync(
                options,
                defaultStatus,
                connectionStatus,
                new AzureDevBoxRemoteConnectionClient(providerClient),
                cancellationToken)
            .ConfigureAwait(false);

        Console.Error.WriteLine("LIVE STAGE: evidence-tickets");
        var ticketStore = new DpapiRdpDvcEvidenceTicketStore(
            options.EvidenceTicketDirectory);
        var ticketPaths = new List<string>(2);
        try
        {
            foreach (var generation in bootstrap.Generations)
            {
                var route = new RdpDvcEvidenceRoute(
                    options.SessionId,
                    options.HostId.Value,
                    options.NodeIncarnationId.Value,
                    0,
                    generation.ConnectionNonce);
                ticketStore.Write(
                    generation.EvidenceReference,
                    route);
                var path = Path.Combine(
                    options.EvidenceTicketDirectory,
                    generation.EvidenceReference + ".ticket");
                ticketPaths.Add(path);
                var verified = await ticketStore.ResolveAsync(
                        generation.EvidenceReference,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (verified != route || !verified.IsWtsWildcard)
                    throw new InvalidDataException(
                        "The local protected evidence ticket did not preserve its wildcard-WTS preauthorization.");
            }
        }
        catch
        {
            DeleteTickets(ticketPaths);
            throw;
        }

        var pipeName =
            $"Steward.ConnectionHost.LiveAcceptance.{Guid.NewGuid():N}";
        Console.Error.WriteLine("LIVE STAGE: evidence-source");
        RdpDvcEmbeddingConfigurationStore.Write(
            pipeName + ".DvcBroker",
            options.EvidencePipeName,
            options.EvidenceKeyFile);
        var evidenceSource = new AttestingProductionEvidenceSource(
            ProductionRdpDvcRuntimeEvidenceSource.FromProtectedFile(
                ticketStore,
                options.EvidencePipeName,
                options.EvidenceKeyFile),
            options.SessionId,
            options.HostId.Value,
            options.NodeIncarnationId.Value,
            bootstrap.Generations);

        HttpDevBoxBrokerHttpTransport? http = null;
        ConnectionHostOrchestrator? orchestrator = null;
        CancellationTokenSource? pipeStop = null;
        Task? pipeServer = null;
        try
        {
            Console.Error.WriteLine("LIVE STAGE: connection-host");
            Console.Error.WriteLine("LIVE HOST STAGE: rdcore-options");
            var rdCoreOptions = new RdCoreIntegrationOptions
            {
                Enabled = true,
                AvdFeedUri = resolved.AvdFeedUri,
                Account = resolved.Username,
                ClaimsClientId =
                    DevBoxConnectionIdentityConstants.WindowsAppClientId,
                ClaimsRedirectUri =
                    DevBoxConnectionIdentityConstants
                        .WindowsAppBrokerRedirectUri,
                ConsumerHandlesClaimsTokenRequest =
                    !RdCoreProcessIdentity.HasPackageIdentity(),
                ReleaseClaimsOwnershipAfterAvdTokens = false,
                ClientIdentifier =
                    "com.microsoft.rdc.windows.wa.windows365.rdcore." +
                    System.Runtime.InteropServices.RuntimeInformation
                        .OSArchitecture
                        .ToString()
                        .ToLowerInvariant(),
                ClientVersion =
                    capability.Artifacts.PackageVersion.ToString(),
                ClientBuild = checked((ushort)
                    capability.Artifacts.PackageVersion.Build),
                OperationTimeout = options.Timeout > TimeSpan.FromMinutes(1)
                    ? TimeSpan.FromMinutes(1)
                    : options.Timeout,
                DiagnosticSink = stage =>
                    Console.Error.WriteLine(
                        $"LIVE RDCORE STAGE: {stage}")
            };
            Console.Error.WriteLine("LIVE HOST STAGE: resolver");
            http = new HttpDevBoxBrokerHttpTransport(connectionIdentity);
            var resolver = new DevBoxConnectionResolver(
                new DevBoxBrokerFeedResolver(
                    connectionIdentity,
                    new HttpDevBoxAvdResourceCatalog(
                        resolved.AvdFeedUri,
                        http,
                        "win365.nxt/" +
                        capability.Artifacts.PackageVersion),
                    http,
                    new DevBoxBrokerFeedResolverOptions
                    {
                        CatalogTimeout = TimeSpan.FromMinutes(1),
                        RdpTimeout = TimeSpan.FromMinutes(1),
                        MaximumResources = 1024,
                        AllowSetCookieResponse = true,
                        UserAgent = "win365.nxt/" +
                            capability.Artifacts.PackageVersion,
                        DiagnosticSink = diagnostic =>
                            Console.Error.WriteLine(
                                $"LIVE CATALOG MATCH: {diagnostic}")
                    }));
            Console.Error.WriteLine("LIVE HOST STAGE: authorization");
            var authorization =
                new SingleUseControlConnectAuthorizationValidator();
            var tokens = new[]
            {
                CreateAuthorizationToken(),
                CreateAuthorizationToken()
            };
            authorization.Register(tokens[0]);
            authorization.Register(tokens[1]);
            Console.Error.WriteLine("LIVE HOST STAGE: host-options");
            var hostOptions = new ConnectionHostOptions
            {
                EnableLiveConnections = true,
                PipeName = pipeName,
                CommandTimeout = options.Timeout,
                DiagnosticSink = diagnostic =>
                    Console.Error.WriteLine(
                        $"LIVE HOST FAILURE: {diagnostic}")
            };
            Console.Error.WriteLine("LIVE HOST STAGE: orchestrator");
            orchestrator = new ConnectionHostOrchestrator(
                hostOptions,
                connectionIdentity,
                resolver,
                new RdCoreCompatibilityInspector(capability),
                new DvcRegistrationSnapshotProvider(registration),
                new ProductionRdCoreConnectionRuntime(
                    new WindowsAppIsolatedConnectionLeaseFactory(
                        capability,
                        new Windows365EndUserResourceCatalog(
                            http,
                            capability.Artifacts.PackageVersion.ToString(),
                            options.DevBox,
                            diagnostic => Console.Error.WriteLine(
                                $"LIVE END USER SHAPE: {diagnostic}"))),
                    evidenceSource,
                    options.Timeout,
                    new ProtectedFileRdpDvcLocalCarrier(
                        options.DvcAuthenticationKeyFile,
                        hostOptions.PipeName + ".DvcBroker",
                        options.EvidencePipeName,
                        options.EvidenceKeyFile,
                        new SqliteConnectionReconnectHighWaterStore(
                            Path.Combine(
                                options.EvidenceDirectory,
                                "reconnect-high-water.v2.db")),
                        new RdpDvcOpaqueControlPipeBridge(
                            new(
                                Environment.GetEnvironmentVariable(
                                    "STEWARD_CONTROL_RDP_DVC_CARRIER_PIPE_NAME") ??
                                "Steward.Control.RdpDvc.v2",
                                options.Timeout,
                                64 * 1024)),
                        stage => Console.Error.WriteLine(
                            $"LIVE CARRIER STAGE: {stage}")),
                    generationStore: new SqliteConnectionGenerationStore(
                        Path.Combine(
                            options.EvidenceDirectory,
                            "connection-generations.v2.db"))),
                authorization,
                new MemoryConnectionMetadataStore());
            Console.Error.WriteLine("LIVE HOST STAGE: initialize");
            await orchestrator.InitializeAsync(cancellationToken)
                .ConfigureAwait(false);
            Console.Error.WriteLine("LIVE HOST STAGE: pipe-server");
            pipeStop = new CancellationTokenSource();
            pipeServer = new ConnectionHostPipeServer(
                    hostOptions,
                    orchestrator)
                .RunAsync(pipeStop.Token);
            var preflight = new LivePreflightEvidence(
                true,
                capability.Artifacts.PackageFullName,
                capability.Artifacts.PackageVersion.ToString(),
                true,
                DevBoxConnectionIdentityConstants.ContextName,
                true,
                registrationStatus.Code,
                bootstrap.DeployInvoked,
                bootstrap.ReceiptSha256);
            var runner = new LiveAcceptanceRunner(
                options,
                resolved.ProviderResource,
                preflight,
                new PipeConnectionHostCommandClient(
                    new(pipeName, options.Timeout)),
                evidenceSource,
                () => new WindowsSurfaceGuard(
                    capability.Artifacts.PackageRoot),
                tokens,
                bootstrap.Generations
                    .Select(static value => value.EvidenceReference)
                    .ToArray());
            var sensitive = ReadSensitiveValues(
                options,
                resolved.ProviderResource,
                tokens);
            return new(
                runner,
                sensitive,
                orchestrator,
                http,
                pipeStop,
                pipeServer,
                ticketPaths);
        }
        catch
        {
            if (pipeStop is not null)
                pipeStop.Cancel();
            if (pipeServer is not null)
            {
                try
                {
                    await pipeServer.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                    when (pipeStop?.IsCancellationRequested == true)
                {
                }
            }
            if (orchestrator is not null)
                await orchestrator.DisposeAsync().ConfigureAwait(false);
            else
                await evidenceSource.DisposeAsync().ConfigureAwait(false);
            http?.Dispose();
            pipeStop?.Dispose();
            DeleteTickets(ticketPaths);
            RdpDvcEmbeddingConfigurationStore.Delete();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        pipeStop.Cancel();
        try
        {
            await pipeServer.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (pipeStop.IsCancellationRequested)
        {
        }
        await orchestrator.DisposeAsync().ConfigureAwait(false);
        http.Dispose();
        pipeStop.Dispose();
        DeleteTickets(unusedTicketPaths);
        RdpDvcEmbeddingConfigurationStore.Delete();
    }

    private static byte[] ReadPublicKey(string path)
    {
        var pem = File.ReadAllText(path);
        using var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return key.ExportSubjectPublicKeyInfo();
    }

    private static string DescribeJsonShape(JsonElement root)
    {
        var paths = new HashSet<string>(StringComparer.Ordinal);
        Visit(root, "$", 0, paths);
        return string.Join(',', paths.Order(StringComparer.Ordinal).Take(128));
    }

    private static string DescribeXmlShape(byte[] content)
    {
        var shapes = new HashSet<string>(StringComparer.Ordinal);
        using var stream = new MemoryStream(content, writable: false);
        using var reader = XmlReader.Create(
            stream,
            new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 4 * 1024 * 1024
            });
        while (reader.Read() && shapes.Count < 128)
        {
            if (reader.NodeType != XmlNodeType.Element)
                continue;
            var attributes = new List<string>();
            if (reader.HasAttributes)
            {
                while (reader.MoveToNextAttribute())
                    attributes.Add(reader.LocalName);
                reader.MoveToElement();
            }

            shapes.Add(
                $"{reader.Depth}:{reader.LocalName}" +
                (attributes.Count == 0
                    ? string.Empty
                    : $"[{string.Join('|', attributes.Order())}]"));
        }
        return string.Join(',', shapes.Order(StringComparer.Ordinal));
    }

    private static IReadOnlyList<Uri> ExtractWorkspaceFeeds(
        byte[] content)
    {
        var feeds = new List<Uri>();
        using var stream = new MemoryStream(content, writable: false);
        using var reader = XmlReader.Create(
            stream,
            new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 4 * 1024 * 1024
            });
        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element ||
                reader.LocalName != "TenantFeedURL")
                continue;
            var value = reader.GetAttribute("FeedURL");
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                feeds.Count >= 16)
                throw new InvalidDataException(
                    "AVD discovery returned an invalid workspace feed.");
            feeds.Add(uri);
        }
        if (feeds.Count == 0)
            throw new InvalidDataException(
                "AVD discovery returned no workspace feeds.");
        return feeds;
    }

    private static string Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "none";
        return new string(value
                .Take(256)
                .Select(character =>
                    char.IsAsciiLetterOrDigit(character) ||
                    character is ' ' or '.' or '-' or '_' or ':'
                        ? character
                        : '_')
                .ToArray())
            .Replace(' ', '_');
    }

    private static void Visit(
        JsonElement value,
        string path,
        int depth,
        HashSet<string> paths)
    {
        if (depth > 5 || paths.Count >= 128)
            return;
        if (value.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in value.EnumerateObject())
            {
                var child = path + "." + property.Name;
                paths.Add(child);
                Visit(property.Value, child, depth + 1, paths);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            paths.Add(path + "[]");
            foreach (var item in value.EnumerateArray().Take(1))
                Visit(item, path + "[]", depth + 1, paths);
        }
    }

    private static string CreateAuthorizationToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static IReadOnlyCollection<string> ReadSensitiveValues(
        LiveAcceptanceOptions options,
        Uri providerResource,
        IReadOnlyList<string> tokens)
    {
        var key = CurrentUserProtectedDataFile.Read(
            options.EvidenceKeyFile,
            AuthenticatedRdpDvcEvidencePublisher.KeyFilePurpose);
        try
        {
            return new[]
            {
                providerResource.AbsoluteUri,
                tokens[0],
                tokens[1],
                Convert.ToBase64String(key),
                Convert.ToHexString(key)
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void DeleteTickets(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            try
            {
                if (File.Exists(path))
                    CurrentUserProtectedDataFile.Delete(path);
            }
            catch (Exception exception)
                when (exception is
                    IOException or
                    UnauthorizedAccessException or
                    CryptographicException)
            {
            }
        }
    }

    private sealed class MemoryConnectionMetadataStore :
        IConnectionMetadataStore
    {
        public Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<DurableConnectionMetadata>>(
                []);
        }

        public Task SaveAsync(
            IReadOnlyCollection<DurableConnectionMetadata> connections,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }
}
