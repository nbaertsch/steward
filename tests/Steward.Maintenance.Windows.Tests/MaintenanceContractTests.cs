using System.Reflection;
using System.Text;
using System.Text.Json;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class MaintenanceContractTests
{
    [Fact]
    public void Parses_each_closed_versioned_operation()
    {
        MaintenanceOperation[] operations =
        [
            new ActivateEndpointUpdateOperation(1, Artifact(ApprovedArtifactKind.EndpointMsi), Artifact(ApprovedArtifactKind.EndpointReleaseManifest), Artifact(ApprovedArtifactKind.EndpointAttestation), Release("2.0.0"), Provenance()),
            new ConfigureWslOperation(1, WslFeatureSet.WslAndVirtualMachinePlatform, MaintenanceArtifactCatalog.Wsl2712),
            new ImportWslDistributionOperation(1, WslDistribution.Ubuntu2404, Artifact(ApprovedArtifactKind.WslDistribution), WslDistributionConfiguration.RootlessDefaultUser, AssignedUser()),
            new ConfigureDockerOperation(1, MaintenanceArtifactCatalog.DockerEngine2831, MaintenanceArtifactCatalog.DockerCompose540, new DockerDaemonConfiguration(1, DockerIsolation.Process, false, 20, 3)),
            new RepairEndpointOperation(1, RepairTarget.HandleKeeperTask),
            new CollectDiagnosticsOperation(1, DiagnosticKind.MaintenanceAndEndpointHealth, 4096),
            new ContinueAfterRebootOperation(1, RebootReason.WslFeatureEnablement)
        ];

        foreach (var operation in operations)
        {
            var request = Request(operation);
            var parsed = MaintenanceContract.Parse(MaintenanceContract.Serialize(request));
            Assert.Equal(
                MaintenanceContract.Serialize(request),
                MaintenanceContract.Serialize(parsed));
        }
    }

    [Theory]
    [InlineData("future-operation")]
    [InlineData("run-command")]
    public void Rejects_unknown_operations(string operation)
    {
        var json =
            "{\"body\":{\"protocolVersion\":1,\"requestId\":\"" +
            Guid.NewGuid() + "\",\"operationId\":\"" + Guid.NewGuid() +
            "\",\"issuedAtUtc\":\"2026-08-31T20:00:00Z\",\"operation\":" +
            "{\"$operation\":\"" + operation +
            "\",\"version\":1}},\"signature\":\"AA==\"}";

        Assert.Throws<InvalidDataException>(() =>
            MaintenanceContract.Parse(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void Rejects_unknown_protocol_operation_versions_and_members()
    {
        var valid = Encoding.UTF8.GetString(MaintenanceContract.Serialize(
            Request(new CollectDiagnosticsOperation(
                1,
                DiagnosticKind.MaintenanceAndEndpointHealth,
                4096))));

        Assert.Throws<InvalidDataException>(() => MaintenanceContract.Parse(
            Encoding.UTF8.GetBytes(valid.Replace(
                "\"protocolVersion\":1",
                "\"protocolVersion\":2",
                StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(() => MaintenanceContract.Parse(
            Encoding.UTF8.GetBytes(valid.Replace(
                "\"version\":1",
                "\"version\":2",
                StringComparison.Ordinal))));
        Assert.Throws<InvalidDataException>(() => MaintenanceContract.Parse(
            Encoding.UTF8.GetBytes(valid.Replace(
                "\"maximumBytes\":4096",
                "\"maximumBytes\":4096,\"command\":\"cmd.exe\"",
                StringComparison.Ordinal))));
    }

    [Fact]
    public void Rejects_unpinned_or_bearer_bearing_artifacts_and_wrong_provenance()
    {
        var approved = Artifact(ApprovedArtifactKind.EndpointMsi);
        var bundle = Artifact(ApprovedArtifactKind.EndpointAttestation);
        var provenance = Provenance();

        Assert.Throws<MaintenanceProtocolException>(() =>
            MaintenanceContract.ValidateOperation(
                new ActivateEndpointUpdateOperation(
                    1,
                    approved with { Sha256 = "not-a-hash" },
                    Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
                    bundle,
                    Release("2.0.0"),
                    provenance)));
        Assert.Throws<MaintenanceProtocolException>(() =>
            MaintenanceContract.ValidateOperation(
                new ActivateEndpointUpdateOperation(
                    1,
                    approved with { Uri = new Uri(approved.Uri + "?token=secret") },
                    Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
                    bundle,
                    Release("2.0.0"),
                    provenance)));
        Assert.Throws<MaintenanceProtocolException>(() =>
            MaintenanceContract.ValidateOperation(
                new ActivateEndpointUpdateOperation(
                    1,
                    approved,
                    Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
                    bundle,
                    Release("2.0.0"),
                    provenance with { SourceRef = "refs/heads/untrusted" })));
    }

    [Fact]
    public void Wsl_and_Docker_artifacts_are_exact_immutable_contracts()
    {
        var wsl = new ConfigureWslOperation(
            1,
            WslFeatureSet.WslAndVirtualMachinePlatform,
            MaintenanceArtifactCatalog.Wsl2712);
        var docker = new ConfigureDockerOperation(
            1,
            MaintenanceArtifactCatalog.DockerEngine2831,
            MaintenanceArtifactCatalog.DockerCompose540,
            new DockerDaemonConfiguration(
                1, DockerIsolation.Process, false, 20, 3));

        MaintenanceContract.ValidateOperation(wsl);
        MaintenanceContract.ValidateOperation(docker);
        Assert.Equal(
            "03C3337F2FD1048FFA8B971A6F81EFD73AA06DD729A3B459EF1A85CEEF5401D0",
            MaintenanceArtifactCatalog.DockerClientSha256);
        Assert.Equal(
            "3D90A17386321BD5F3BC098480F8D5D2C16EC24EC098CD60C5F3C0020DF0E8AA",
            MaintenanceArtifactCatalog.DockerDaemonSha256);
        Assert.Throws<MaintenanceProtocolException>(() =>
            MaintenanceContract.ValidateOperation(wsl with
            {
                Package = wsl.Package with { Sha256 = new string('F', 64) }
            }));
        Assert.Throws<MaintenanceProtocolException>(() =>
            MaintenanceContract.ValidateOperation(docker with
            {
                ComposePackage = docker.ComposePackage with
                {
                    Uri = new Uri(
                        "https://github.com/docker/compose/releases/download/v5.4.1/docker-compose-windows-x86_64.exe")
                }
            }));
    }

    [Fact]
    public void Wsl_distribution_import_is_bound_to_one_assigned_user()
    {
        var operation = new ImportWslDistributionOperation(
            1,
            WslDistribution.Ubuntu2404,
            Artifact(ApprovedArtifactKind.WslDistribution),
            WslDistributionConfiguration.RootlessDefaultUser,
            AssignedUser());

        MaintenanceContract.ValidateOperation(operation);
        Assert.Throws<MaintenanceProtocolException>(() =>
            MaintenanceContract.ValidateOperation(operation with
            {
                User = operation.User with { Sid = "S-1-5-18" }
            }));
    }

    [Fact]
    public void Canonical_catalog_identity_is_bound_to_product_version_and_run()
    {
        var release = Release("2.0.0");
        var operation = new ActivateEndpointUpdateOperation(
            1,
            Artifact(ApprovedArtifactKind.EndpointMsi),
            Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
            Artifact(ApprovedArtifactKind.EndpointAttestation),
            release,
            Provenance());

        MaintenanceContract.ValidateOperation(operation);

        Assert.Throws<MaintenanceProtocolException>(() =>
            MaintenanceContract.ValidateOperation(operation with
            {
                Release = release with
                {
                    CatalogIdentity = "steward-endpoint/2.0.1/123456789"
                }
            }));
        Assert.Throws<MaintenanceProtocolException>(() =>
            MaintenanceContract.ValidateOperation(operation with
            {
                Release = release with
                {
                    CatalogIdentity = "steward-endpoint/2.0.0/987654321"
                }
            }));
    }

    [Fact]
    public void Release_manifest_parser_accepts_the_builder_shape_and_canonical_identity()
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"steward-release-{Guid.NewGuid():N}.psd1");
        try
        {
            File.WriteAllText(path, """
                @{
                    Version = 4
                    MsiFile = 'Steward.Endpoint.Msi.msi'
                    ProductVersion = '2.0.0'
                    MsiSha256 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                    MsiLength = 1024
                    ProductCode = '33333333-3333-3333-3333-333333333333'
                    UpgradeCode = '37C34E0A-E245-48A4-B07C-78E2955A7E65'
                    CatalogIdentity = 'steward-endpoint/2.0.0/123456789'
                    AttestationBundleFile = 'Steward.Endpoint.Msi.sigstore.json'
                    SourceRepository = 'microsoft/switchyard'
                    SourceCommit = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
                    SourceRef = 'refs/heads/main'
                    SignerWorkflow = 'microsoft/switchyard/.github/workflows/release-endpoint.yml'
                    SourceRunId = '123456789'
                }
                """);
            var operation = new ActivateEndpointUpdateOperation(
                1,
                Artifact(ApprovedArtifactKind.EndpointMsi),
                Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
                Artifact(ApprovedArtifactKind.EndpointAttestation),
                Release("2.0.0"),
                Provenance());

            var manifest = EndpointReleaseManifestParser.Parse(path);
            EndpointReleaseManifestParser.ValidateBinding(manifest, operation);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Public_contract_has_no_generic_command_surface_or_untyped_bags()
    {
        var assembly = typeof(MaintenanceOperation).Assembly;
        var publicProperties = assembly.GetExportedTypes()
            .SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly));
        var forbiddenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Executable", "ExecutablePath", "Command", "Arguments", "Script", "Shell", "Environment", "WorkingDirectory"
        };

        Assert.All(publicProperties, property =>
        {
            Assert.DoesNotContain(property.Name, forbiddenNames);
            Assert.NotEqual(typeof(object), property.PropertyType);
            Assert.False(typeof(System.Collections.IDictionary).IsAssignableFrom(property.PropertyType));
        });
        Assert.DoesNotContain(
            assembly.GetExportedTypes(),
            type => typeof(System.Collections.IDictionary).IsAssignableFrom(type));
    }

    internal static ApprovedArtifact Artifact(ApprovedArtifactKind kind) =>
        new(
            1,
            kind,
            new Uri(kind switch
            {
                ApprovedArtifactKind.EndpointMsi => "https://github.com/microsoft/switchyard/releases/download/v2/Steward.Endpoint.Msi.msi",
                ApprovedArtifactKind.EndpointReleaseManifest => "https://github.com/microsoft/switchyard/releases/download/v2/steward-endpoint.release.psd1",
                ApprovedArtifactKind.EndpointAttestation => "https://github.com/microsoft/switchyard/releases/download/v2/Steward.Endpoint.Msi.sigstore.json",
                ApprovedArtifactKind.DockerEngine or ApprovedArtifactKind.DockerCompose => "https://download.docker.com/win/static/stable/x86_64/approved.zip",
                _ => "https://download.microsoft.com/steward/approved.bin"
            }),
            new string('A', 64),
            1024);

    internal static AssignedUserIdentity AssignedUser() => new(
        1,
        "S-1-12-1-111111111-222222222-333333333-444444444",
        "AzureAD\\assigned.user@example.com");

    internal static EndpointReleaseIdentity Release(string version) => new(
        1,
        $"steward-endpoint/{version}/123456789",
        version,
        new string('A', 64),
        1024,
        Guid.Parse("33333333-3333-3333-3333-333333333333"),
        Guid.Parse("37C34E0A-E245-48A4-B07C-78E2955A7E65"));
    internal static ArtifactProvenance Provenance() => new(
        1,
        "microsoft/switchyard",
        new string('B', 40),
        "refs/heads/main",
        "microsoft/switchyard/.github/workflows/release-endpoint.yml",
        "123456789");

    internal static AuthenticatedMaintenanceRequest Request(
        MaintenanceOperation operation,
        Guid? requestId = null,
        Guid? operationId = null,
        DateTimeOffset? issuedAtUtc = null,
        string signature = "AA==") =>
        new(
            new MaintenanceRequestBody(
                MaintenanceContract.ProtocolVersion,
                requestId ?? Guid.NewGuid(),
                operationId ?? Guid.NewGuid(),
                issuedAtUtc ?? DateTimeOffset.Parse("2026-08-31T20:00:00Z"),
                operation),
            signature);
}




