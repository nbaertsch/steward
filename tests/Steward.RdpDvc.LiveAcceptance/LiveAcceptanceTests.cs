using System.Security.Cryptography;
using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.Domain;
using Steward.Providers.DevBox;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.LiveAcceptance;

public sealed class LiveAcceptanceTests
{
    private static readonly Guid TenantId =
        Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");

    [Fact]
    public void Options_use_devbox_identity_inputs_and_independent_consents()
    {
        var environment = RequiredEnvironment();
        environment["STEWARD_RDCORE_LIVE_ACCEPTANCE"] = "yes";
        environment["STEWARD_RDCORE_LIVE_CLOUD_READ"] =
            LiveAcceptanceOptions.RequiredCloudReadConsent;

        var options = LiveAcceptanceOptions.Parse([], environment);

        Assert.False(options.HasRequiredConsent);
        Assert.Equal("project", options.Project);
        Assert.Equal("box", options.DevBox);
        Assert.DoesNotContain(
            environment.Keys,
            key => key.Contains(
                "PROVIDER_RESOURCE",
                StringComparison.Ordinal));
        environment["STEWARD_RDCORE_LIVE_ACCEPTANCE"] =
            LiveAcceptanceOptions.RequiredConnectConsent;
        Assert.True(
            LiveAcceptanceOptions.Parse([], environment)
                .HasRequiredConsent);
    }

    [Fact]
    public void Bootstrap_deploy_requires_exact_independent_mutation_consent()
    {
        var environment = RequiredEnvironment();
        environment["STEWARD_RDCORE_BOOTSTRAP_DEPLOY_EXECUTABLE"] =
            "Steward.DevBox.BootstrapDeploy.exe";
        environment["STEWARD_RDCORE_BOOTSTRAP_DEPLOY_ARGUMENTS_FILE"] =
            "deploy-arguments.json";
        environment["STEWARD_RDCORE_BOOTSTRAP_DEPLOY_TOOL_SHA256"] =
            new string('b', 64);

        Assert.Throws<ArgumentException>(
            () => LiveAcceptanceOptions.Parse([], environment));

        environment["STEWARD_RDCORE_BOOTSTRAP_DEPLOY_CONSENT"] =
            LiveAcceptanceOptions.RequiredBootstrapDeployConsent;
        Assert.True(
            LiveAcceptanceOptions.Parse([], environment)
                .InvokeBootstrapDeploy);
    }

    [Fact]
    public async Task Typed_remote_connection_is_validated_in_memory_and_feed_uses_bound_tenant()
    {
        var options = Options();
        var provider = ProviderResource();

        var resolved = await DevBoxLiveConnectionResolver.ResolveAsync(
            options,
            DefaultIdentity(),
            ConnectionIdentity(),
            new FakeRemoteConnectionClient(provider),
            CancellationToken.None);

        Assert.Same(provider, resolved.ProviderResource);
        Assert.Equal(
            $"https://www.wvd.microsoft.com/api/arm/feeddiscovery?aadtenant={TenantId:D}",
            resolved.AvdFeedUri.AbsoluteUri);
        Assert.Equal("user@example.test", resolved.Username);
    }

    [Fact]
    public async Task Remote_connection_rejects_identity_mismatch_and_invalid_ms_avd_shape()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => DevBoxLiveConnectionResolver.ResolveAsync(
                Options(),
                DefaultIdentity(),
                ConnectionIdentity() with
                {
                    TenantId = Guid.NewGuid().ToString()
                },
                new FakeRemoteConnectionClient(ProviderResource()),
                CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => DevBoxLiveConnectionResolver.ResolveAsync(
                Options(),
                DefaultIdentity(),
                ConnectionIdentity(),
                new FakeRemoteConnectionClient(
                    new Uri("ms-avd:connect?env=prod")),
                CancellationToken.None));
    }

    [Fact]
    public async Task Signed_preconnect_receipt_creates_two_nonce_references_without_wts()
    {
        var directory = TestDirectory();
        try
        {
            using var node = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            using var control = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            var options = await ReceiptOptionsAsync(
                directory,
                node,
                control);
            var loaded =
                await DevBoxRdpDvcBootstrapReceipts.LoadAttestedAsync(
                    options.BootstrapReceiptFile,
                    CancellationToken.None);
            Assert.Equal(
                new ProviderOperationId(options.BootstrapOperationId),
                loaded.Receipt.OperationId);
            Assert.Equal(
                options.BootstrapBundleVersion,
                loaded.Receipt.BundleVersion);
            Assert.Equal(
                options.BootstrapArchiveSha256,
                loaded.Receipt.ArchiveSha256);
            Assert.True(loaded.Receipt.PreConnectReady);
            Assert.Equal(
                "Queued",
                loaded.Receipt.RemoteReadiness.ScheduledTaskState);

            var result = await BootstrapDeploymentReceiptLoader.PrepareAsync(
                options,
                node.ExportSubjectPublicKeyInfo(),
                control.ExportSubjectPublicKeyInfo(),
                new FakeDeployInvoker(),
                CancellationToken.None);

            Assert.False(result.DeployInvoked);
            Assert.True(result.Receipt.PreConnectReady);
            Assert.Equal(2, result.Generations.Count);
            Assert.Equal(
                result.Receipt.ConnectionNonces,
                result.Generations.Select(
                    generation => generation.ConnectionNonce));
            Assert.Equal(
                2,
                result.Generations
                    .Select(generation => generation.EvidenceReference)
                    .Distinct(StringComparer.Ordinal)
                    .Count());

            var ticketDirectory = Path.Combine(directory, "tickets");
            Directory.CreateDirectory(ticketDirectory);
            var store = new DpapiRdpDvcEvidenceTicketStore(
                ticketDirectory);
            foreach (var generation in result.Generations)
            {
                store.Write(
                    generation.EvidenceReference,
                    new(
                        options.SessionId,
                        options.HostId.Value,
                        options.NodeIncarnationId.Value,
                        0,
                        generation.ConnectionNonce));
                var route = await store.ResolveAsync(
                    generation.EvidenceReference,
                    CancellationToken.None);
                Assert.True(route.IsWtsWildcard);
                Assert.Equal(0, route.WtsSessionId);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Receipt_rejects_fabricated_dvc_ready_or_post_ping_state()
    {
        var directory = TestDirectory();
        try
        {
            using var node = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            using var control = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            var options = await ReceiptOptionsAsync(
                directory,
                node,
                control,
                remoteState: "completed",
                nextGeneration: 2);

            await Assert.ThrowsAsync<InvalidDataException>(
                () => BootstrapDeploymentReceiptLoader.PrepareAsync(
                    options,
                    node.ExportSubjectPublicKeyInfo(),
                    control.ExportSubjectPublicKeyInfo(),
                    new FakeDeployInvoker(),
                    CancellationToken.None));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Optional_bootstrap_deploy_runs_before_receipt_verification()
    {
        var directory = TestDirectory();
        try
        {
            using var node = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            using var control = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            var options = (await ReceiptOptionsAsync(
                directory,
                node,
                control)) with
            {
                BootstrapDeployExecutable = "deploy.exe",
                BootstrapDeployArgumentsFile = "arguments.json",
                BootstrapDeployToolSha256 = new string('b', 64),
                BootstrapDeployConsent =
                    LiveAcceptanceOptions.RequiredBootstrapDeployConsent
            };
            var invoker = new FakeDeployInvoker();

            var result = await BootstrapDeploymentReceiptLoader.PrepareAsync(
                options,
                node.ExportSubjectPublicKeyInfo(),
                control.ExportSubjectPublicKeyInfo(),
                invoker,
                CancellationToken.None);

            Assert.True(result.DeployInvoked);
            Assert.Equal(1, invoker.Calls);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Runner_uses_typed_pipe_without_view_and_requires_bound_wts_fresh_nonce()
    {
        var options = Options();
        var attestations = new FakeAttestations(
        [
            Attestation(101, 7, Guid.Parse(
                "11111111-1111-1111-1111-111111111111")),
            Attestation(102, 8, Guid.Parse(
                "22222222-2222-2222-2222-222222222222"))
        ]);
        var client = new FakeConnectionHostClient([101, 102]);
        var runner = new LiveAcceptanceRunner(
            options,
            ProviderResource(),
            Preflight(),
            client,
            attestations,
            () => new FakeSurfaceGuard(),
            ["token-one", "token-two"],
            ["evidence-reference-one", "evidence-reference-two"]);

        var result = await runner.RunAsync(CancellationToken.None);

        Assert.True(result.Passed);
        Assert.Equal([7, 8], result.Generations.Select(x => x.RdpSessionId));
        Assert.DoesNotContain(
            client.Commands,
            command => command.Operation is
                ConnectionHostOperation.View or
                ConnectionHostOperation.TakeControl);
        Assert.Equal(
            [
                ConnectionHostOperation.Resolve,
                ConnectionHostOperation.Prepare,
                ConnectionHostOperation.Connect,
                ConnectionHostOperation.Disconnect,
                ConnectionHostOperation.Resolve,
                ConnectionHostOperation.Prepare,
                ConnectionHostOperation.Connect,
                ConnectionHostOperation.Disconnect
            ],
            client.Commands.Select(command => command.Operation));
        Assert.All(
            client.Commands.Where(command =>
                command.Operation == ConnectionHostOperation.Resolve),
            command => Assert.Equal(
                ProviderResource().AbsoluteUri,
                command.ProviderResource));
    }

    [Fact]
    public async Task Runner_fails_closed_on_surface_change()
    {
        var guard = new FakeSurfaceGuard(violated: true);
        var runner = new LiveAcceptanceRunner(
            Options(),
            ProviderResource(),
            Preflight(),
            new BlockingConnectClient(),
            new FakeAttestations([]),
            () => guard,
            ["token-one", "token-two"],
            ["evidence-reference-one", "evidence-reference-two"]);

        await Assert.ThrowsAsync<HeadlessSurfaceViolationException>(
            () => runner.RunAsync(CancellationToken.None));
    }

    [Fact]
    public void Evidence_store_rejects_known_secret()
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(
            """{"value":"authorization-secret"}""");

        Assert.Throws<InvalidDataException>(
            () => AcceptanceEvidenceStore.AssertNoSecrets(
                bytes,
                ["authorization-secret"]));
    }

    private static async Task<LiveAcceptanceOptions> ReceiptOptionsAsync(
        string directory,
        ECDsa node,
        ECDsa control,
        string remoteState = "waitingForActiveRdpSession",
        int nextGeneration = 0)
    {
        var options = Options() with
        {
            BootstrapReceiptFile =
                Path.Combine(directory, "receipt.json"),
            NodeSigningPublicKeyFile =
                Path.Combine(directory, "node.pub"),
            ControlSigningPublicKeyFile =
                Path.Combine(directory, "control.pub")
        };
        await File.WriteAllTextAsync(
            options.NodeSigningPublicKeyFile,
            node.ExportSubjectPublicKeyInfoPem());
        await File.WriteAllTextAsync(
            options.ControlSigningPublicKeyFile,
            control.ExportSubjectPublicKeyInfoPem());
        var receipt = new DevBoxRdpDvcBootstrapReceipt(
            1,
            new(options.BootstrapOperationId),
            options.BootstrapBundleVersion,
            options.BootstrapArchiveSha256,
            options.SessionId,
            options.HostId,
            options.NodeIncarnationId,
            [
                Guid.Parse(
                    "11111111-1111-1111-1111-111111111111"),
                Guid.Parse(
                    "22222222-2222-2222-2222-222222222222")
            ],
            DateTimeOffset.UtcNow,
            new(
                1,
                "Queued",
                false,
                remoteState,
                0,
                options.SessionId,
                options.HostId.Value,
                options.NodeIncarnationId.Value,
                nextGeneration,
                DateTimeOffset.UtcNow),
            remoteState == "waitingForActiveRdpSession" &&
                nextGeneration == 0,
            true);
        await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
            options.BootstrapReceiptFile,
            DevBoxRdpDvcBootstrapReceipts.Attest(
                receipt,
                options.NodeIdentity,
                node,
                options.ControlIdentity,
                control),
            CancellationToken.None);
        return options;
    }

    private static Dictionary<string, string?> RequiredEnvironment() =>
        new(StringComparer.Ordinal)
        {
            ["STEWARD_DEVBOX_ENDPOINT"] =
                "https://center.westus.devcenter.azure.com/",
            ["STEWARD_DEVBOX_PROJECT"] = "project",
            ["STEWARD_DEVBOX_USER"] = "me",
            ["STEWARD_DEVBOX_BOX_NAME"] = "box",
            ["STEWARD_RDCORE_SESSION_ID"] =
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ["STEWARD_RDCORE_HOST_ID"] =
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            ["STEWARD_RDCORE_NODE_INCARNATION_ID"] =
                "cccccccc-cccc-cccc-cccc-cccccccccccc",
            ["STEWARD_DVC_EVIDENCE_PIPE_NAME"] =
                "Steward.Evidence.Tests",
            ["STEWARD_DVC_EVIDENCE_KEY_FILE"] = "evidence.key",
            ["STEWARD_DVC_AUTH_KEY_FILE"] = "dvc-auth.key",
            ["STEWARD_DVC_EVIDENCE_TICKET_DIRECTORY"] = "tickets",
            ["STEWARD_RDCORE_CONTROL_SIGNING_PRIVATE_KEY_FILE"] =
                "control.private",
            ["STEWARD_RDCORE_CONTROL_SIGNING_PUBLIC_KEY_FILE"] =
                "control.pub",
            ["STEWARD_RDCORE_CONTROL_IDENTITY"] = "control",
            ["STEWARD_RDCORE_NODE_SIGNING_PUBLIC_KEY_FILE"] = "node.pub",
            ["STEWARD_RDCORE_NODE_TRANSPORT_SIGNING_PUBLIC_KEY_FILE"] =
                "node.transport.pub",
            ["STEWARD_RDCORE_NODE_IDENTITY"] = "node",
            ["STEWARD_RDCORE_BOOTSTRAP_RECEIPT"] = "receipt.json",
            ["STEWARD_RDCORE_BOOTSTRAP_OPERATION_ID"] =
                "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
            ["STEWARD_RDCORE_BOOTSTRAP_BUNDLE_VERSION"] = "1.0.0",
            ["STEWARD_RDCORE_BOOTSTRAP_ARCHIVE_SHA256"] =
                new string('a', 64),
            ["STEWARD_RDCORE_LIVE_EVIDENCE_DIRECTORY"] = "evidence"
        };

    private static LiveAcceptanceOptions Options() =>
        new(
            new("https://center.westus.devcenter.azure.com/"),
            "project",
            "me",
            "box",
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            new(Guid.Parse(
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")),
            new(Guid.Parse(
                "cccccccc-cccc-cccc-cccc-cccccccccccc")),
            "Steward.Evidence.Tests",
            "evidence.key",
            "dvc-auth.key",
            "tickets",
            "control.private",
            "control.pub",
            "control",
            "node.pub",
            "node.transport.pub",
            "node",
            "receipt.json",
            Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
            "1.0.0",
            new string('a', 64),
            null,
            null,
            null,
            "",
            TimeSpan.FromMinutes(30),
            "evidence",
            LiveAcceptanceOptions.RequiredConnectConsent,
            LiveAcceptanceOptions.RequiredCloudReadConsent,
            TimeSpan.FromSeconds(30));

    private static Uri ProviderResource() =>
        new(
            "ms-avd:connect?env=prod&preview=false" +
            "&resourceId=resource&username=user%40example.test" +
            "&version=1&workspaceId=workspace");

    private static DevBoxIdentityStatus DefaultIdentity() =>
        new(
            DevBoxIdentityConstants.CurrentVersion,
            DevBoxIdentityConstants.ContextName,
            true,
            TenantId.ToString(),
            "user@example.test",
            DateTimeOffset.UtcNow.AddMinutes(5),
            null);

    private static DevBoxConnectionIdentityStatus ConnectionIdentity() =>
        new(
            DevBoxConnectionIdentityConstants.CurrentVersion,
            DevBoxConnectionIdentityConstants.ContextName,
            DevBoxConnectionIdentityOutcome.Ready,
            true,
            TenantId.ToString(),
            "user@example.test",
            DateTimeOffset.UtcNow.AddMinutes(5),
            null);

    private static LivePreflightEvidence Preflight() =>
        new(
            true,
            "package",
            "1.0",
            true,
            DevBoxConnectionIdentityConstants.ContextName,
            true,
            RdpDvcPluginRegistration.RegisteredActivationPendingCode,
            false,
            new string('A', 64));

    private static DvcGenerationAttestation Attestation(
        long generation,
        int wtsSession,
        Guid nonce) =>
        new(
            generation,
            wtsSession,
            nonce,
            1,
            TimeSpan.FromMilliseconds(2),
            Enum.GetValues<RdCoreDvcEvidenceEvent>());

    private static string TestDirectory()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "rdcore-live-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class FakeRemoteConnectionClient(Uri provider) :
        IDevBoxRemoteConnectionClient
    {
        public Task<Uri?> GetRemoteConnectionAsync(
            string project,
            string user,
            string devBox,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal("project", project);
            Assert.Equal("me", user);
            Assert.Equal("box", devBox);
            return Task.FromResult<Uri?>(provider);
        }
    }

    private sealed class FakeDeployInvoker : IBootstrapDeployInvoker
    {
        public int Calls { get; private set; }

        public Task InvokeAsync(
            LiveAcceptanceOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeConnectionHostClient(
        IReadOnlyList<long> generations) :
        IConnectionHostCommandClient
    {
        private int connectIndex;

        public List<ConnectionHostCommand> Commands { get; } = [];

        public Task<ConnectionHostResponse> SendAsync(
            ConnectionHostCommand command,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Commands.Add(command);
            var state = command.Operation switch
            {
                ConnectionHostOperation.Resolve or
                ConnectionHostOperation.Prepare =>
                    RdpDvcSessionState.Resolving,
                ConnectionHostOperation.Connect =>
                    RdpDvcSessionState.ConnectedTransport,
                ConnectionHostOperation.Disconnect =>
                    RdpDvcSessionState.Disconnected,
                _ => throw new InvalidOperationException()
            };
            var code = command.Operation switch
            {
                ConnectionHostOperation.Resolve =>
                    "CONNECTION_HOST_RESOLVED",
                ConnectionHostOperation.Prepare =>
                    "CONNECTION_HOST_PREPARED",
                ConnectionHostOperation.Connect =>
                    "RDP_DVC_CONNECTED_TRANSPORT",
                ConnectionHostOperation.Disconnect =>
                    "RDP_DVC_DISCONNECTED",
                _ => throw new InvalidOperationException()
            };
            var generation = command.Operation ==
                ConnectionHostOperation.Connect
                ? generations[connectIndex++]
                : command.ConnectionGeneration;
            return Task.FromResult(
                new ConnectionHostResponse(
                    ConnectionHostProtocol.CurrentVersion,
                    command.RequestId,
                    true,
                    code,
                    new(
                        ConnectionHostProtocol.CurrentVersion,
                        command.ConnectionId!,
                        state,
                        generation,
                        state ==
                            RdpDvcSessionState.ConnectedTransport,
                        false,
                        false,
                        code,
                        DateTimeOffset.UtcNow)));
        }
    }

    private sealed class BlockingConnectClient :
        IConnectionHostCommandClient
    {
        public Task<ConnectionHostResponse> SendAsync(
            ConnectionHostCommand command,
            CancellationToken cancellationToken)
        {
            if (command.Operation != ConnectionHostOperation.Connect)
                return new FakeConnectionHostClient([101, 102])
                    .SendAsync(command, cancellationToken);
            return Task.Delay(Timeout.Infinite, cancellationToken)
                .ContinueWith<ConnectionHostResponse>(
                    static _ => throw new InvalidOperationException(),
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
        }
    }

    private sealed class FakeAttestations(
        IReadOnlyList<DvcGenerationAttestation> values) :
        IDvcGenerationAttestationSource
    {
        private readonly Dictionary<long, DvcGenerationAttestation> values =
            values.ToDictionary(value => value.ConnectionGeneration);

        public DvcGenerationAttestation Get(long connectionGeneration) =>
            values.TryGetValue(connectionGeneration, out var value)
                ? value
                : throw new InvalidDataException();

        public Task CloseAsync(
            long connectionGeneration,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

    private sealed class FakeSurfaceGuard(bool violated = false) :
        ISurfaceGuard
    {
        private readonly TaskCompletionSource violation =
            Completed(violated);

        public SurfaceObservationEvidence Initial { get; } =
            Observation();

        public Task Violation => violation.Task;

        public SurfaceObservationEvidence Observe()
        {
            ThrowIfViolated();
            return Observation();
        }

        public void ThrowIfViolated()
        {
            if (violated)
                throw new HeadlessSurfaceViolationException(
                    "fake visible surface",
                    new InvalidOperationException());
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private static TaskCompletionSource Completed(bool value)
        {
            var source = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            if (value)
                source.TrySetResult();
            return source;
        }

        private static SurfaceObservationEvidence Observation() =>
            new(
                DateTimeOffset.UtcNow,
                10,
                5,
                new string('A', 64),
                new string('B', 64),
                1);
    }
}
