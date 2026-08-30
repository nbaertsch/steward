namespace Steward.RdCore.Windows.Tests;

public sealed class MetadataAndProbeTests
{
    [Fact]
    public void Versioned_fingerprint_matches_harmless_projected_fixture()
    {
        var inspector = new RdCoreApiFingerprintInspector(
            new PhysicalRdCoreFileSystem());

        var result = inspector.Inspect(
            typeof(Microsoft.RemoteDesktop.ClientCore.ActivityManager)
                .Assembly.Location);

        Assert.True(result.IsMatch);
        Assert.Empty(result.MissingMembers);
        Assert.Equal(
            "rdcore-clientcore-v2",
            RdCoreApiFingerprintInspector.FingerprintVersion);
    }

    [Fact]
    public void Probe_fails_closed_when_fingerprint_drifts()
    {
        var fileSystem = new StubProbeFileSystem();
        var probe = new RdCoreCompatibilityProbe(
            ExactLocator(fileSystem.Root),
            new RdCorePathValidator(fileSystem),
            new StubSignatureVerifier(AuthenticodeStatus.TrustedMicrosoft),
            new PortableExecutableValidator(fileSystem),
            new StubFingerprintInspector(
                new(
                    RdCoreCapabilityCode.ApiFingerprintMismatch,
                    ["IConnection.Connect"])),
            new StubDependencyInspector(),
            new RdCoreFileSnapshotter(fileSystem));

        var result = probe.Inspect();

        Assert.Equal(RdCoreCapabilityCode.ApiFingerprintMismatch, result.Code);
        Assert.False(result.IsCompatible);
        Assert.Null(result.Artifacts);
    }

    [Fact]
    public void Capability_strings_do_not_disclose_package_paths()
    {
        var secretRoot = @"C:\Users\someone\Sensitive Package Path";
        var fileSystem = new StubProbeFileSystem(secretRoot);
        var probe = new RdCoreCompatibilityProbe(
            ExactLocator(secretRoot),
            new RdCorePathValidator(fileSystem),
            new StubSignatureVerifier(AuthenticodeStatus.TrustedMicrosoft),
            new PortableExecutableValidator(fileSystem),
            new StubFingerprintInspector(
                new(RdCoreCapabilityCode.Compatible, [])),
            new StubDependencyInspector(),
            new RdCoreFileSnapshotter(fileSystem));

        var result = probe.Inspect();

        Assert.True(result.IsCompatible);
        Assert.DoesNotContain(secretRoot, result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(
            secretRoot,
            result.Artifacts!.ToString(),
            StringComparison.Ordinal);
        Assert.All(
            result.Diagnostics,
            diagnostic => Assert.DoesNotContain(
                secretRoot,
                diagnostic.ToString(),
                StringComparison.Ordinal));
    }

    private static Windows365PackageLocator ExactLocator(string root) =>
        new(
            new PackageDiscoveryTests.StubPackageSource(
                PackageDiscoveryTests.Candidate(
                    new Version(2, 0, 200, 0),
                    healthy: true,
                    root)));

    private sealed class StubSignatureVerifier(AuthenticodeStatus status) :
        IAuthenticodeVerifier
    {
        public AuthenticodeStatus Verify(string path) => status;
    }

    private sealed class StubFingerprintInspector(ApiFingerprintResult result) :
        IRdCoreApiFingerprintInspector
    {
        public ApiFingerprintResult Inspect(string projectedAssemblyPath) =>
            result;
    }

    internal sealed class StubDependencyInspector : IRdCoreDependencyInspector
    {
        public DependencyInspectionResult Inspect(ValidatedRdCorePaths paths) =>
            new(
                RdCoreCapabilityCode.Compatible,
                "Fixture dependencies are valid.",
                [],
                []);
    }

    private sealed class StubProbeFileSystem : IRdCoreFileSystem
    {
        public StubProbeFileSystem(
            string root = @"C:\Packages\Windows365")
        {
            Root = Path.GetFullPath(root);
        }

        public string Root { get; }

        public string GetFullPath(string path) => Path.GetFullPath(path);

        public bool DirectoryExists(string path) => true;

        public bool FileExists(string path) => true;

        public FileAttributes GetAttributes(string path) => FileAttributes.Normal;

        public long GetFileLength(string path) => 1024;

        public Stream OpenRead(string path) =>
            File.OpenRead(typeof(MetadataAndProbeTests).Assembly.Location);
    }
}
