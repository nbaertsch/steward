using System.Security.Cryptography;
using System.Text.Json;
using Steward.Endpoint.Provisioner;

namespace Steward.Endpoint.Provisioner.Tests;

public sealed class InstallerHandoffExecutorTests : IDisposable
{
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web);
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "steward-provisioner-handoff-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void Fixed_handoff_executes_verified_package_once_and_writes_bound_commit_receipt()
    {
        var fixture = CreateFixture();
        var runtime = new RecordingInstallerRuntime(
            EndpointInstallerRuntimeResult.Committed(0));
        var executor = new EndpointInstallerHandoffExecutor(
            new PhysicalProvisionerFileSystem(),
            runtime);

        var receipt = executor.Execute(fixture.Options);
        var replay = executor.Execute(fixture.Options);

        Assert.Equal(EndpointInstallerReceiptOutcome.Committed, receipt.Outcome);
        Assert.Equal(fixture.Intent.TransactionId, receipt.TransactionId);
        Assert.Equal(fixture.Intent.MsiSha256, receipt.MsiSha256);
        Assert.Equal(fixture.Intent.ProductCode, receipt.ProductCode);
        Assert.Equal(fixture.Intent.UpgradeCode, receipt.UpgradeCode);
        Assert.Equal(1, runtime.InstallCalls);
        Assert.Equal(0, runtime.RecoveryCalls);
        Assert.Equal(receipt, replay);
    }

    [Fact]
    public void Crash_after_start_recovers_terminal_outcome_without_starting_second_MSI()
    {
        var fixture = CreateFixture();
        var runtime = new RecordingInstallerRuntime(
            EndpointInstallerRuntimeResult.RolledBack(1603));
        var files = new PhysicalProvisionerFileSystem();
        files.WriteAtomic(
            fixture.Options.ExecutionStatePath,
            JsonSerializer.SerializeToUtf8Bytes(
                EndpointInstallerExecutionState.Create(fixture.Intent), Json));
        var executor = new EndpointInstallerHandoffExecutor(files, runtime);

        var receipt = executor.Execute(fixture.Options);

        Assert.Equal(EndpointInstallerReceiptOutcome.RolledBack, receipt.Outcome);
        Assert.Equal(0, runtime.InstallCalls);
        Assert.Equal(1, runtime.RecoveryCalls);
    }

    [Fact]
    public void Handoff_rejects_mutated_package_and_unverified_provisioner_before_installer_start()
    {
        var fixture = CreateFixture();
        File.AppendAllText(fixture.PackagePath, "mutation");
        var runtime = new RecordingInstallerRuntime(
            EndpointInstallerRuntimeResult.Committed(0));
        var executor = new EndpointInstallerHandoffExecutor(
            new PhysicalProvisionerFileSystem(),
            runtime);

        Assert.Throws<InvalidDataException>(() =>
            executor.Execute(fixture.Options));
        Assert.Equal(0, runtime.InstallCalls);

        fixture = CreateFixture();
        File.AppendAllText(fixture.Options.ProvisionerPath, "mutation");
        Assert.Throws<InvalidDataException>(() =>
            executor.Execute(fixture.Options));
        Assert.Equal(0, runtime.InstallCalls);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private HandoffFixture CreateFixture()
    {
        Directory.CreateDirectory(root);
        var maintenance = Path.Combine(root, Guid.NewGuid().ToString("N"));
        var versions = Path.Combine(maintenance, "Versions");
        var handoffRoot = Path.Combine(
            maintenance,
            "Maintenance",
            "installer-handoff",
            "11111111111111111111111111111111");
        var releaseName = "release-1.2.3-aaaaaaaaaaaaaaaa";
        var release = Path.Combine(versions, releaseName);
        Directory.CreateDirectory(release);
        Directory.CreateDirectory(handoffRoot);
        Directory.CreateDirectory(Path.Combine(maintenance, "Maintenance"));
        var staging = Path.Combine(maintenance, "Maintenance", "staging");
        Directory.CreateDirectory(staging);
        File.WriteAllText(
            Path.Combine(staging, "update-provisioning.json"),
            "{}");
        File.WriteAllText(
            Path.Combine(staging, "update-artifact-attestation.json"),
            "{}");
        var package = Path.Combine(release, "Steward.Endpoint.Msi.msi");
        File.WriteAllText(package, "verified-msi");
        var provisioner = Path.Combine(root, "Steward.Endpoint.Provisioner.exe");
        File.WriteAllText(provisioner, "verified-provisioner");
        var capability = Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(32));
        var intent = new EndpointInstallerHandoffIntent(
            1,
            Guid.NewGuid(),
            19,
            new EndpointOwnerCapability(capability),
            "1.2.3",
            FileHash(package),
            new FileInfo(package).Length,
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            Guid.Parse("37C34E0A-E245-48A4-B07C-78E2955A7E65"),
            releaseName,
            FileHash(provisioner),
            EndpointInstallerHandoffAction.InstallEndpoint);
        File.WriteAllText(
            Path.Combine(handoffRoot, "intent.json"),
            JsonSerializer.Serialize(intent, Json));
        File.WriteAllText(
            Path.Combine(maintenance, "Maintenance", "service-config.json"),
            JsonSerializer.Serialize(new EndpointInstallerServiceConfiguration(
                1,
                "Steward.Maintenance.v1",
                "S-1-5-21-1-2-3-1001",
                @"TEST\user",
                "control",
                "Steward.Node.22222222222222222222222222222222",
                Guid.Parse("11111111-1111-1111-1111-111111111111"),
                "1.2.3",
                "microsoft/switchyard",
                "release-endpoint.yml",
                Path.Combine(maintenance, "Endpoint"),
                root,
                versions,
                "{37C34E0A-E245-48A4-B07C-78E2955A7E65}"), Json));
        return new HandoffFixture(
            intent,
            package,
            new EndpointInstallerHandoffExecutionOptions(
                Path.Combine(maintenance, "Maintenance"),
                provisioner));
    }

    private static string FileHash(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private sealed record HandoffFixture(
        EndpointInstallerHandoffIntent Intent,
        string PackagePath,
        EndpointInstallerHandoffExecutionOptions Options);

    private sealed class RecordingInstallerRuntime(
        EndpointInstallerRuntimeResult result) : IEndpointInstallerRuntime
    {
        internal int InstallCalls { get; private set; }
        internal int RecoveryCalls { get; private set; }

        public EndpointInstallerRuntimeResult Install(
            VerifiedEndpointInstallerPackage package)
        {
            InstallCalls++;
            return result;
        }

        public EndpointInstallerRuntimeResult Recover(
            EndpointInstallerIdentity identity)
        {
            RecoveryCalls++;
            return result;
        }
    }
}
