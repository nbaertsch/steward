using System.Security.Cryptography;
using System.Text;
using Azure.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Steward.Application;
using Steward.Control;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;
using Steward.Stack.Local;

namespace Steward.Orchestration.Tests;

public sealed class ControlProviderBootstrapCompositionTests
{
    [Fact]
    public void Disabled_and_incomplete_composition_remain_unavailable()
    {
        var disabled = new ServiceCollection();
        disabled.AddStewardControlProviderBootstrap(
            new ConfigurationBuilder()
                .AddInMemoryCollection()
                .Build());
        disabled.AddStewardLocalStack(
            new ConfigurationBuilder()
                .AddInMemoryCollection()
                .Build());
        using (var provider = disabled.BuildServiceProvider())
        {
            var options = provider.GetRequiredService<
                ValidatedControlProviderBootstrapOptions>();
            Assert.False(options.Enabled);
            Assert.False(options.Available);
            Assert.Equal("disabled", options.Status);
            Assert.Null(provider.GetService<INodeBootstrapper>());
            Assert.Null(provider.GetService<IEnrollmentClaimIssuer>());
            Assert.Null(provider.GetService<
                IRoutableNodeEndpointIssuer>());
            Assert.Null(provider.GetService<IHostRecreateService>());
            Assert.Null(provider.GetService<
                IProvisionedNodeEnrollmentWorkflow>());
        }

        var incompleteConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Control:ProviderBootstrap:Enabled"] = "true"
            })
            .Build();
        var incomplete = new ServiceCollection();
        incomplete.AddStewardControlProviderBootstrap(
            incompleteConfiguration);
        incomplete.AddStewardLocalStack(incompleteConfiguration);
        using var incompleteProvider =
            incomplete.BuildServiceProvider();
        var incompleteOptions = incompleteProvider.GetRequiredService<
            ValidatedControlProviderBootstrapOptions>();
        Assert.True(incompleteOptions.Enabled);
        Assert.False(incompleteOptions.Available);
        Assert.Equal("incomplete", incompleteOptions.Status);
        Assert.Null(incompleteProvider.GetService<INodeBootstrapper>());
        Assert.Null(incompleteProvider.GetService<IHostRecreateService>());
    }

    [Fact]
    public void Invalid_bounded_or_unsigned_configuration_fails_closed()
    {
        using var fixture = BootstrapFixture.Create();
        var invalidLifetime = fixture.Values.ToDictionary();
        invalidLifetime[
            "Control:ProviderBootstrap:EnrollmentClaimLifetime"] =
            "00:16:00";
        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection()
                .AddStewardControlProviderBootstrap(
                    Configuration(invalidLifetime),
                    new TestTokenCredential()));

        var insecureSource = fixture.Values.ToDictionary();
        insecureSource[
            "Control:ProviderBootstrap:PackageSource"] =
            "http://packages.example.invalid/node.zip";
        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection()
                .AddStewardControlProviderBootstrap(
                    Configuration(insecureSource),
                    new TestTokenCredential()));

        var wrongSigner = fixture.Values.ToDictionary();
        wrongSigner[
            "Control:ProviderBootstrap:PackageSigner"] =
            "sha256:" + new string('0', 64);
        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection()
                .AddStewardControlProviderBootstrap(
                    Configuration(wrongSigner),
                    new TestTokenCredential()));
    }

    [Fact]
    public async Task Unavailable_composition_is_reported_by_doctor()
    {
        var root = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "control-provider-bootstrap-unavailable",
            Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(root);
        try
        {
            var configuration = Configuration(
                new Dictionary<string, string?>
                {
                    ["Steward:LocalStack:DataRoot"] = root,
                    ["Steward:LocalStack:PortableStateRoot"] =
                        Path.Combine(root, "objects"),
                    ["Steward:LocalStack:CredentialVaultRoot"] =
                        Path.Combine(root, "credentials")
                });
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton(new SqliteControlStore(
                Path.Combine(root, "control.db")));
            services.AddStewardControlProviderBootstrap(
                configuration);
            services.AddStewardLocalStack(configuration);
            OrchestrationComposition.AddStewardOrchestration(
                services,
                configuration,
                Path.Combine(root, "control.db"));
            await using var provider =
                services.BuildServiceProvider();
            var status = provider.GetRequiredService<
                OrchestrationDoctorService>().Check();
            Assert.Contains(
                "provider-bootstrap-enrollment",
                status.UnavailableCapabilities);
            Assert.Contains(
                "provider-recreate",
                status.UnavailableCapabilities);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Valid_composition_resolves_and_doctor_reports_capabilities()
    {
        using var fixture = BootstrapFixture.Create();
        var services = Services(fixture, includeOrchestration: true);
        await using var provider = services.BuildServiceProvider();

        Assert.True(provider.GetRequiredService<
            ValidatedControlProviderBootstrapOptions>().Available);
        Assert.NotNull(provider.GetService<INodeBootstrapper>());
        Assert.NotNull(provider.GetService<IEnrollmentClaimIssuer>());
        Assert.NotNull(provider.GetService<
            IRoutableNodeEndpointIssuer>());
        Assert.NotNull(provider.GetService<
            IProvisionedNodeEnrollmentWorkflow>());
        Assert.NotNull(provider.GetService<IHostRecreateService>());

        var doctor = provider.GetRequiredService<
            OrchestrationDoctorService>().Check();
        Assert.DoesNotContain(
            "provider-bootstrap-enrollment",
            doctor.UnavailableCapabilities);
        Assert.DoesNotContain(
            "provider-recreate",
            doctor.UnavailableCapabilities);
    }

    [Fact]
    public async Task Enrollment_claims_are_random_protected_durable_and_single_use()
    {
        using var fixture = BootstrapFixture.Create();
        EnrollmentClaim first;
        EnrollmentClaim second;
        using (var provider = Services(fixture)
                   .BuildServiceProvider())
        {
            var issuer = provider.GetRequiredService<
                IEnrollmentClaimIssuer>();
            var host = HostId.New();
            var incarnation = NodeIncarnationId.New();
            first = await issuer.IssueAsync(
                host,
                incarnation,
                "project/me/box",
                CancellationToken.None);
            second = await issuer.IssueAsync(
                host,
                incarnation,
                "project/me/box",
                CancellationToken.None);
            Assert.NotEqual(first.Token, second.Token);
            Assert.InRange(
                first.ExpiresAt - DateTimeOffset.UtcNow,
                TimeSpan.FromMinutes(4),
                TimeSpan.FromMinutes(5));
        }

        var claimFiles = Directory.GetFiles(
            Path.Combine(fixture.StateRoot, "claims"),
            "*.claim");
        Assert.Equal(2, claimFiles.Length);
        foreach (var path in claimFiles)
        {
            var protectedBytes = await File.ReadAllBytesAsync(path);
            var text = Encoding.UTF8.GetString(protectedBytes);
            Assert.DoesNotContain(first.Token, text, StringComparison.Ordinal);
            Assert.DoesNotContain(
                "project/me/box",
                text,
                StringComparison.Ordinal);
        }

        using var restarted = Services(fixture)
            .BuildServiceProvider();
        var consumer = restarted.GetRequiredService<
            IEnrollmentClaimConsumer>();
        await consumer.ConsumeAsync(first, CancellationToken.None);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            async () => await consumer.ConsumeAsync(
                first,
                CancellationToken.None));
        var rebound = second with
        {
            HostId = HostId.New()
        };
        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            async () => await consumer.ConsumeAsync(
                rebound,
                CancellationToken.None));
        await consumer.ConsumeAsync(second, CancellationToken.None);
    }

    [Fact]
    public async Task Bootstrap_restart_preserves_exact_identity_and_issues_real_dvc_route()
    {
        using var fixture = BootstrapFixture.Create();
        var deployment = new RestartingDeployment();
        var hostId = HostId.New();
        var incarnationId = NodeIncarnationId.New();
        var poolId = PoolId.New();
        var operationId = ProviderOperationId.New();
        var resource = new ProviderResource(
            "project/me/box",
            "box",
            ProviderHostStatus.Running,
            new Dictionary<string, string>());

        ProviderOperationHandle handle;
        EnrollmentClaim firstClaim;
        using (var provider = Services(
                       fixture,
                       deployment: deployment)
                   .BuildServiceProvider())
        {
            var issuer = provider.GetRequiredService<
                IEnrollmentClaimIssuer>();
            firstClaim = await issuer.IssueAsync(
                hostId,
                incarnationId,
                resource.ProviderResourceId,
                CancellationToken.None);
            var host = new Host(hostId, poolId, incarnationId);
            var package = provider.GetRequiredService<
                SignedNodePackage>();
            var request = new BootstrapRequest(
                operationId,
                "bootstrap-exact",
                resource,
                host,
                package,
                firstClaim);
            var bootstrapper = provider.GetRequiredService<
                INodeBootstrapper>();

            var wrongName = request with
            {
                Resource = resource with { Name = "other" }
            };
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                bootstrapper.BootstrapAndEnrollAsync(
                    wrongName,
                    CancellationToken.None));

            var started = await bootstrapper.BootstrapAndEnrollAsync(
                request,
                CancellationToken.None);
            Assert.Equal(
                ProviderOperationStatus.Running,
                started.Status);
            handle = Assert.IsType<ProviderOperationHandle>(
                started.Handle);
            await Assert.ThrowsAsync<ArgumentException>(() =>
                bootstrapper.ReconcileAsync(
                    handle with { OpaqueHandle = "tampered" },
                    CancellationToken.None));
        }

        var statePath = Assert.Single(Directory.GetFiles(
            Path.Combine(fixture.StateRoot, "operations"),
            "*.state"));
        var protectedState = Encoding.UTF8.GetString(
            await File.ReadAllBytesAsync(statePath));
        Assert.DoesNotContain(
            firstClaim.Token,
            protectedState,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            resource.ProviderResourceId,
            protectedState,
            StringComparison.Ordinal);

        using var restarted = Services(
                fixture,
                deployment: deployment)
            .BuildServiceProvider();
        var restartedIssuer = restarted.GetRequiredService<
            IEnrollmentClaimIssuer>();
        var resumedClaim = await restartedIssuer.IssueAsync(
            hostId,
            incarnationId,
            resource.ProviderResourceId,
            CancellationToken.None);
        var resumedRequest = new BootstrapRequest(
            operationId,
            "bootstrap-exact",
            resource,
            new Host(hostId, poolId, incarnationId),
            restarted.GetRequiredService<SignedNodePackage>(),
            resumedClaim);
        var completed = await restarted.GetRequiredService<
                INodeBootstrapper>()
            .BootstrapAndEnrollAsync(
                resumedRequest,
                CancellationToken.None);
        Assert.Equal(
            ProviderOperationStatus.Succeeded,
            completed.Status);
        Assert.Equal(2, deployment.DeployCalls);
        Assert.True(deployment.IntentWasStable);

        var member = new PoolMember(
            hostId,
            poolId,
            incarnationId,
            "box",
            PoolMemberState.Warm,
            DateTimeOffset.UtcNow,
            ProviderResourceId: resource.ProviderResourceId);
        var pool = new PoolRegistration(
            new(poolId, 0, 1, TimeSpan.Zero),
            new("azure-dev-box", "project", "pool", "me"));
        var endpoint = await restarted.GetRequiredService<
                IRoutableNodeEndpointIssuer>()
            .IssueAsync(
                pool,
                member,
                resource,
                CancellationToken.None);

        Assert.Equal(hostId, endpoint.HostId);
        Assert.Equal(incarnationId, endpoint.NodeIncarnationId);
        Assert.Equal(
            ControlRdpDvcNodeEndpointIssuer.TransportKind,
            endpoint.Transport.Kind);
        var binding = endpoint.Transport.DeserializeData<
            ControlRdpDvcEndpointBinding>();
        Assert.NotNull(binding);
        Assert.Equal(
            ControlBootstrapState.DeriveSessionId(
                hostId,
                incarnationId),
            binding.SessionId);
        Assert.Equal(hostId.Value, binding.RouteId);
        Assert.Equal(
            resource.ProviderResourceId,
            binding.ProviderResourceId);
        Assert.True(File.Exists(
            binding.AuthenticationKeyReference));
        Assert.Equal(
            32,
            new FileInfo(
                binding.AuthenticationKeyReference).Length);
        Assert.True(File.Exists(
            endpoint.PeerPublicKeyReference));
    }

    private static ServiceCollection Services(
        BootstrapFixture fixture,
        bool includeOrchestration = false,
        IControlDevBoxBootstrapDeployment? deployment = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(
            new SqliteControlStore(
                Path.Combine(fixture.Root, "control.db")));
        services.AddStewardControlProviderBootstrap(
            fixture.Configuration,
            new TestTokenCredential());
        if (deployment is not null)
            services.AddSingleton(deployment);
        services.AddStewardLocalStack(
            fixture.Configuration,
            new TestTokenCredential());
        if (includeOrchestration)
            OrchestrationComposition.AddStewardOrchestration(
                services,
                fixture.Configuration,
                Path.Combine(fixture.Root, "control.db"));
        return services;
    }

    private static IConfiguration Configuration(
        IReadOnlyDictionary<string, string?> values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();

    private sealed class BootstrapFixture : IDisposable
    {
        private BootstrapFixture(
            string root,
            string environmentVariable,
            IReadOnlyDictionary<string, string?> values)
        {
            Root = root;
            EnvironmentVariable = environmentVariable;
            Values = values;
            Configuration = ControlProviderBootstrapCompositionTests
                .Configuration(values);
        }

        internal string Root { get; }
        internal string StateRoot =>
            Path.Combine(Root, "provider-bootstrap");
        internal string EnvironmentVariable { get; }
        internal IReadOnlyDictionary<string, string?> Values { get; }
        internal IConfiguration Configuration { get; }

        internal static BootstrapFixture Create()
        {
            var root = Path.GetFullPath(Path.Combine(
                AppContext.BaseDirectory,
                "control-provider-bootstrap",
                Guid.NewGuid().ToString("N")));
            Directory.CreateDirectory(root);
            using var control = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            using var signer = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            var controlPath = Path.Combine(
                root,
                "control-private.pem");
            var signerPath = Path.Combine(
                root,
                "package-signer.pem");
            File.WriteAllText(
                controlPath,
                control.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(
                signerPath,
                signer.ExportSubjectPublicKeyInfoPem());
            var signerPublic = signer.ExportSubjectPublicKeyInfo();
            var signerIdentity = "sha256:" +
                Convert.ToHexStringLower(
                    SHA256.HashData(signerPublic));
            CryptographicOperations.ZeroMemory(signerPublic);
            var source = new Uri(
                "https://packages.example.invalid/steward-rdp-dvc.zip");
            var contentSha256 = Convert.ToHexStringLower(
                SHA256.HashData(
                    "signed-rdp-dvc-package"u8));
            var identity =
                ControlProviderBootstrapOptions.SignedPackageIdentity(
                    source,
                    contentSha256,
                    signerIdentity);
            var signature = signer.SignData(
                identity,
                HashAlgorithmName.SHA256);
            CryptographicOperations.ZeroMemory(identity);
            var environmentVariable =
                "STEWARD_TEST_CONTROL_BOOTSTRAP_" +
                Guid.NewGuid().ToString("N");
            Environment.SetEnvironmentVariable(
                environmentVariable,
                Convert.ToBase64String(
                    RandomNumberGenerator.GetBytes(32)));
            var values = new Dictionary<string, string?>
            {
                ["Control:ProviderBootstrap:Enabled"] = "true",
                ["Control:ProviderBootstrap:StateRoot"] =
                    Path.Combine(root, "provider-bootstrap"),
                ["Control:ProviderBootstrap:EnrollmentClaimLifetime"] =
                    "00:05:00",
                ["Control:ProviderBootstrap:PackageSource"] =
                    source.AbsoluteUri,
                ["Control:ProviderBootstrap:PackageContentSha256"] =
                    contentSha256,
                ["Control:ProviderBootstrap:PackageSignature"] =
                    Convert.ToBase64String(signature),
                ["Control:ProviderBootstrap:PackageSigner"] =
                    signerIdentity,
                ["Control:ProviderBootstrap:PackageSigningPublicKeyPemPath"] =
                    signerPath,
                ["Steward:LocalStack:DataRoot"] = root,
                ["Steward:LocalStack:PortableStateRoot"] =
                    Path.Combine(root, "objects"),
                ["Steward:LocalStack:CredentialVaultRoot"] =
                    Path.Combine(root, "credentials"),
                ["Steward:LocalStack:TransportEnabled"] = "true",
                ["Steward:LocalStack:TransportIdentity"] = "control",
                ["Steward:LocalStack:TransportPrivateKeyPemPath"] =
                    controlPath,
                ["Steward:LocalStack:RdpDvcControlCarrierEnabled"] =
                    "true",
                ["Steward:LocalStack:RdpDvcControlCarrierPipeName"] =
                    "Steward.Control.RdpDvc.Test",
                ["Steward:LocalStack:DevBox:Enabled"] = "true",
                ["Steward:LocalStack:DevBox:Endpoint"] =
                    "https://center.westus.devcenter.azure.com/",
                ["Steward:LocalStack:DevBox:OperationHandleHmacKeyEnvironmentVariable"] =
                    environmentVariable
            };
            CryptographicOperations.ZeroMemory(signature);
            return new(
                root,
                environmentVariable,
                values);
        }

        public void Dispose()
        {
            Environment.SetEnvironmentVariable(
                EnvironmentVariable,
                null);
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }

    private sealed class RestartingDeployment :
        IControlDevBoxBootstrapDeployment
    {
        private ControlBootstrapState? first;

        internal int DeployCalls { get; private set; }
        internal bool IntentWasStable { get; private set; }

        public Task<ControlBootstrapDeploymentResult> DeployAsync(
            ControlBootstrapState state,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DeployCalls++;
            var handle = new ProviderOperationHandle(
                state.StewardOperationId,
                state.IdempotencyKey,
                DevBoxRdpDvcBootstrapPlan.ProviderName,
                "handle-" + DeployCalls);
            if (first is null)
            {
                first = Clone(state);
                return Task.FromResult(new
                    ControlBootstrapDeploymentResult(
                        new(
                            ProviderOperationStatus.Running,
                            handle,
                            null)));
            }
            IntentWasStable =
                first.OperationId == state.OperationId &&
                first.IdempotencyKey == state.IdempotencyKey &&
                first.Project == state.Project &&
                first.User == state.User &&
                first.DevBox == state.DevBox &&
                first.ProviderResourceId ==
                    state.ProviderResourceId &&
                first.HostId == state.HostId &&
                first.NodeIncarnationId ==
                    state.NodeIncarnationId &&
                first.SessionId == state.SessionId &&
                first.ConnectionNonces.SequenceEqual(
                    state.ConnectionNonces) &&
                first.IntentAuthenticationKey.SequenceEqual(
                    state.IntentAuthenticationKey) &&
                first.IntentNodeSigningPrivateKey.SequenceEqual(
                    state.IntentNodeSigningPrivateKey) &&
                first.BootstrapEncryptionPrivateKey.SequenceEqual(
                    state.BootstrapEncryptionPrivateKey);
            using var node = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            return Task.FromResult(new
                ControlBootstrapDeploymentResult(
                    new(
                        ProviderOperationStatus.Succeeded,
                        handle,
                        null),
                    new(
                        RandomNumberGenerator.GetBytes(32),
                        node.ExportSubjectPublicKeyInfo(),
                        DateTimeOffset.UtcNow)));
        }

        public Task<ControlBootstrapDeploymentResult> ReconcileAsync(
            ControlBootstrapState state,
            ProviderOperationHandle handle,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "Tampered handles must be rejected before deployment reconciliation.");

        private static ControlBootstrapState Clone(
            ControlBootstrapState state) =>
            state with
            {
                ConnectionNonces =
                    state.ConnectionNonces.ToArray(),
                IntentAuthenticationKey =
                    state.IntentAuthenticationKey.ToArray(),
                IntentNodeSigningPrivateKey =
                    state.IntentNodeSigningPrivateKey.ToArray(),
                BootstrapEncryptionPrivateKey =
                    state.BootstrapEncryptionPrivateKey.ToArray(),
                ControlSigningPublicKey =
                    state.ControlSigningPublicKey.ToArray(),
                Capabilities = state.Capabilities.ToArray(),
                SetupFingerprints =
                    state.SetupFingerprints.ToArray()
            };
    }

    private sealed class TestTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            new(
                "test-token",
                DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(
                requestContext,
                cancellationToken));
    }
}
