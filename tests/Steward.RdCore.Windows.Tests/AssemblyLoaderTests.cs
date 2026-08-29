namespace Steward.RdCore.Windows.Tests;

public sealed class AssemblyLoaderTests
{
    [Fact]
    public void Collectible_loader_loads_only_after_compatible_inspection()
    {
        var fixture = CreateFixture();
        try
        {
            using var loader = CollectibleRdCoreAssemblyLoader.Create(
                fixture.Report,
                CreateGenerationValidator(fixture));
            var assembly = loader.LoadProjectedAssembly();

            Assert.False(loader.IsCollectible);
            Assert.Equal(
                typeof(AssemblyLoaderTests).Assembly.GetName().Name,
                assembly.GetName().Name);
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [Fact]
    public void Collectible_loader_rejects_incompatible_report()
    {
        var report = new RdCoreCapabilityReport(
            RdCoreCapabilityCode.ApiFingerprintMismatch,
            RdCoreApiFingerprintInspector.FingerprintVersion,
            []);

        var exception = Assert.Throws<RdCoreLoadException>(
            () => CollectibleRdCoreAssemblyLoader.Create(
                report,
                new StubGenerationValidator()));

        Assert.Equal(
            RdCoreCapabilityCode.ApiFingerprintMismatch,
            exception.Code);
    }

    [Fact]
    public void Loader_rejects_stale_report_before_loading()
    {
        var fixture = CreateFixture();
        try
        {
            var validator = CreateGenerationValidator(fixture);
            using var loader = CollectibleRdCoreAssemblyLoader.Create(
                fixture.Report,
                validator);
            File.AppendAllText(
                fixture.Report.Artifacts!.ProjectedAssemblyPath,
                "generation changed");

            var exception = Assert.Throws<RdCoreLoadException>(
                loader.LoadProjectedAssembly);

            Assert.Equal(RdCoreCapabilityCode.PackageUpdated, exception.Code);
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [Fact]
    public void Loader_rejects_package_path_change_at_create()
    {
        var fixture = CreateFixture();
        try
        {
            fixture.Source.Candidate = fixture.Package with
            {
                InstalledPath = fixture.Root + "-updated"
            };
            var exception = Assert.Throws<RdCoreLoadException>(
                () => CollectibleRdCoreAssemblyLoader.Create(
                    fixture.Report,
                    CreateGenerationValidator(fixture)));

            Assert.Equal(RdCoreCapabilityCode.PackageUpdated, exception.Code);
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [Fact]
    public void Loader_never_falls_back_to_same_name_application_assembly()
    {
        var fixture = CreateFixture();
        try
        {
            using var loader = CollectibleRdCoreAssemblyLoader.Create(
                fixture.Report,
                CreateGenerationValidator(fixture));

            var exception = Assert.Throws<FileLoadException>(
                () => loader.LoadFromAssemblyName(
                    typeof(AssemblyLoaderTests).Assembly.GetName()));

            Assert.Equal(
                RdCoreCapabilityCode.DependencyNotAllowed,
                Assert.IsType<RdCoreLoadException>(exception.InnerException).Code);
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [Fact]
    public void Loader_rejects_dependency_escape_in_report()
    {
        var fixture = CreateFixture();
        try
        {
            var escaped = fixture.Report.Artifacts! with
            {
                ManagedDependencies =
                [
                    new(
                        new("Escaped", new Version(1, 0), string.Empty),
                        new(
                            @"..\escape.dll",
                            1,
                            new string('0', 64)))
                ]
            };
            var report = new RdCoreCapabilityReport(
                RdCoreCapabilityCode.Compatible,
                RdCoreApiFingerprintInspector.FingerprintVersion,
                [],
                escaped);

            var exception = Assert.Throws<RdCoreLoadException>(
                () => CollectibleRdCoreAssemblyLoader.Create(
                    report,
                    new StubGenerationValidator()));

            Assert.Equal(
                RdCoreCapabilityCode.PathEscapesPackage,
                exception.Code);
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    private static Fixture CreateFixture()
    {
        var fixtureRoot = Path.Combine(
            AppContext.BaseDirectory,
            "rdcore-fixtures",
            Guid.NewGuid().ToString("N"));
        var wnc = Path.Combine(fixtureRoot, "wnc");
        Directory.CreateDirectory(wnc);
        var fixtureAssembly = typeof(AssemblyLoaderTests).Assembly.Location;
        File.Copy(
            fixtureAssembly,
            Path.Combine(
                wnc,
                RdCorePathValidator.ProjectedAssemblyFileName));
        File.Copy(
            fixtureAssembly,
            Path.Combine(wnc, RdCorePathValidator.NativeSdkFileName));
        var fileSystem = new PhysicalRdCoreFileSystem();
        var package = PackageDiscoveryTests.Candidate(
            new Version(2, 0, 200, 0),
            healthy: true,
            fixtureRoot);
        var source = new MutablePackageSource(package);
        var probe = new RdCoreCompatibilityProbe(
            new Windows365PackageLocator(source),
            new RdCorePathValidator(fileSystem),
            new TrustedSignatureVerifier(),
            new PortableExecutableValidator(fileSystem),
            new RdCoreApiFingerprintInspector(fileSystem),
            new MetadataAndProbeTests.StubDependencyInspector(),
            new RdCoreFileSnapshotter(fileSystem));
        var report = probe.Inspect();
        Assert.True(report.IsCompatible);
        return new(fixtureRoot, report, package, source, fileSystem);
    }

    private static RdCoreGenerationValidator CreateGenerationValidator(
        Fixture fixture)
    {
        var pathValidator = new RdCorePathValidator(fixture.FileSystem);
        var signatureVerifier = new TrustedSignatureVerifier();
        var peValidator = new PortableExecutableValidator(fixture.FileSystem);
        return new(
            new Windows365PackageLocator(fixture.Source),
            pathValidator,
            signatureVerifier,
            peValidator,
            new RdCoreApiFingerprintInspector(fixture.FileSystem),
            new MetadataAndProbeTests.StubDependencyInspector(),
            new RdCoreFileSnapshotter(fixture.FileSystem),
            fixture.FileSystem);
    }

    private sealed record Fixture(
        string Root,
        RdCoreCapabilityReport Report,
        AppxPackageCandidate Package,
        MutablePackageSource Source,
        PhysicalRdCoreFileSystem FileSystem);

    private sealed class MutablePackageSource(AppxPackageCandidate candidate) :
        IAppxPackageSource
    {
        public AppxPackageCandidate Candidate { get; set; } = candidate;

        public IReadOnlyList<AppxPackageCandidate> FindWindows365Candidates() =>
            [Candidate];
    }

    private sealed class TrustedSignatureVerifier : IAuthenticodeVerifier
    {
        public AuthenticodeStatus Verify(string path) =>
            AuthenticodeStatus.TrustedMicrosoft;
    }

    private sealed class StubGenerationValidator :
        IRdCoreGenerationValidator
    {
        public GenerationValidationResult Validate(
            RdCorePackageArtifacts artifacts) =>
            new(
                RdCoreCapabilityCode.Compatible,
                "The fixture generation is current.");

        public byte[] ReadVerifiedFile(
            RdCorePackageArtifacts artifacts,
            RdCoreFileIdentity identity)
        {
            return File.ReadAllBytes(
                Path.Combine(artifacts.PackageRoot, identity.RelativePath));
        }
    }
}
