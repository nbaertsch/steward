using System.Runtime.InteropServices;
using System.Security;

namespace Steward.RdCore.Windows;

public sealed class RdCoreCompatibilityProbe
{
    private readonly Windows365PackageLocator packageLocator;
    private readonly RdCorePathValidator pathValidator;
    private readonly IAuthenticodeVerifier signatureVerifier;
    private readonly PortableExecutableValidator portableExecutableValidator;
    private readonly IRdCoreApiFingerprintInspector fingerprintInspector;
    private readonly IRdCoreDependencyInspector dependencyInspector;
    private readonly RdCoreFileSnapshotter snapshotter;

    public RdCoreCompatibilityProbe()
    {
        var fileSystem = new PhysicalRdCoreFileSystem();
        packageLocator = new(new WindowsAppxPackageSource());
        pathValidator = new(fileSystem);
        signatureVerifier = new MicrosoftAuthenticodeVerifier();
        portableExecutableValidator = new(fileSystem);
        fingerprintInspector = new RdCoreApiFingerprintInspector(fileSystem);
        snapshotter = new(fileSystem);
        dependencyInspector = new RdCoreDependencyInspector(
            fileSystem,
            pathValidator,
            signatureVerifier,
            portableExecutableValidator,
            snapshotter);
    }

    internal RdCoreCompatibilityProbe(
        Windows365PackageLocator packageLocator,
        RdCorePathValidator pathValidator,
        IAuthenticodeVerifier signatureVerifier,
        PortableExecutableValidator portableExecutableValidator,
        IRdCoreApiFingerprintInspector fingerprintInspector,
        IRdCoreDependencyInspector dependencyInspector,
        RdCoreFileSnapshotter snapshotter)
    {
        this.packageLocator = packageLocator;
        this.pathValidator = pathValidator;
        this.signatureVerifier = signatureVerifier;
        this.portableExecutableValidator = portableExecutableValidator;
        this.fingerprintInspector = fingerprintInspector;
        this.dependencyInspector = dependencyInspector;
        this.snapshotter = snapshotter;
    }

    public RdCoreCapabilityReport Inspect()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Failure(
                RdCoreCapabilityCode.UnsupportedOperatingSystem,
                "platform",
                "RDCore compatibility inspection is only available on Windows.");
        }

        PackageLocationResult packageResult;
        try
        {
            packageResult = packageLocator.Locate();
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(
                RdCoreCapabilityCode.PackageQueryFailed,
                "package",
                "Windows denied access to package registration data.");
        }
        catch (COMException)
        {
            return Failure(
                RdCoreCapabilityCode.PackageQueryFailed,
                "package",
                "Windows package registration data could not be queried.");
        }
        catch (InvalidOperationException)
        {
            return Failure(
                RdCoreCapabilityCode.PackageQueryFailed,
                "package",
                "Windows package registration data was unavailable.");
        }

        if (packageResult.Code != RdCoreCapabilityCode.Compatible ||
            packageResult.Package is null)
        {
            return Failure(
                packageResult.Code,
                "package",
                packageResult.Description);
        }

        try
        {
            return InspectPackage(packageResult.Package);
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(
                RdCoreCapabilityCode.BinaryInspectionFailed,
                "binary",
                "Windows denied access while inspecting RDCore binaries.");
        }
        catch (IOException)
        {
            return Failure(
                RdCoreCapabilityCode.BinaryInspectionFailed,
                "binary",
                "An RDCore binary changed or became unavailable during inspection.");
        }
        catch (SecurityException)
        {
            return Failure(
                RdCoreCapabilityCode.BinaryInspectionFailed,
                "binary",
                "A security policy prevented RDCore binary inspection.");
        }
        catch (ArgumentException)
        {
            return Failure(
                RdCoreCapabilityCode.PackagePathInvalid,
                "package",
                "The package supplied an invalid installation path.");
        }
        catch (NotSupportedException)
        {
            return Failure(
                RdCoreCapabilityCode.PackagePathInvalid,
                "package",
                "The package supplied an unsupported installation path.");
        }
        catch (BadImageFormatException)
        {
            return Failure(
                RdCoreCapabilityCode.InvalidPortableExecutable,
                "binary",
                "A required RDCore binary is not a valid PE image.");
        }
    }

    private RdCoreCapabilityReport InspectPackage(AppxPackageCandidate package)
    {
        var pathResult = pathValidator.Validate(package.InstalledPath);
        if (pathResult.Code != RdCoreCapabilityCode.Compatible ||
            pathResult.Paths is null)
        {
            return Failure(
                pathResult.Code,
                "package-path",
                pathResult.Description);
        }

        var paths = pathResult.Paths;
        foreach (var artifact in new[]
                 {
                     (Name: "projected-assembly",
                         Path: paths.ProjectedAssemblyPath,
                         Managed: true),
                     (Name: "native-sdk", Path: paths.NativeSdkPath, Managed: false)
                 })
        {
            var signature = signatureVerifier.Verify(artifact.Path);
            if (signature != AuthenticodeStatus.TrustedMicrosoft)
            {
                var code = signature == AuthenticodeStatus.NonMicrosoftSigner
                    ? RdCoreCapabilityCode.BinaryNotMicrosoftSigned
                    : RdCoreCapabilityCode.BinaryNotTrusted;
                return Failure(
                    code,
                    artifact.Name,
                    "A required RDCore binary did not have a trusted Microsoft " +
                    "Authenticode signature.");
            }

            var peResult = portableExecutableValidator.Validate(
                artifact.Path,
                artifact.Managed);
            if (peResult.Code != RdCoreCapabilityCode.Compatible)
            {
                return Failure(
                    peResult.Code,
                    artifact.Name,
                    peResult.Description);
            }
        }

        var fingerprint = fingerprintInspector.Inspect(
            paths.ProjectedAssemblyPath);
        if (!fingerprint.IsMatch)
        {
            return new(
                fingerprint.Code,
                RdCoreApiFingerprintInspector.FingerprintVersion,
                [
                    new(
                        fingerprint.Code,
                        "projected-api",
                        "The installed RDCore projected API does not match " +
                        $"{RdCoreApiFingerprintInspector.FingerprintVersion}; " +
                        $"{fingerprint.MissingMembers.Count} required members " +
                        "were absent or changed: " +
                        string.Join(
                            ",",
                            fingerprint.MissingMembers.Take(16)) +
                        ".")
                ]);
        }

        var dependencies = dependencyInspector.Inspect(paths);
        if (!dependencies.IsCompatible)
        {
            return Failure(
                dependencies.Code,
                "dependencies",
                dependencies.Description);
        }

        var projectedIdentity = snapshotter.Capture(
            paths.PackageRoot,
            paths.ProjectedAssemblyPath);
        var nativeIdentity = snapshotter.Capture(
            paths.PackageRoot,
            paths.NativeSdkPath);
        var artifacts = new RdCorePackageArtifacts(
            package.FullName,
            package.Version,
            paths.PackageRoot,
            paths.ProjectedAssemblyPath,
            paths.NativeSdkPath,
            projectedIdentity,
            nativeIdentity,
            dependencies.ManagedDependencies,
            dependencies.NativeDependencies);
        return new(
            RdCoreCapabilityCode.Compatible,
            RdCoreApiFingerprintInspector.FingerprintVersion,
            [
                new(
                    RdCoreCapabilityCode.Compatible,
                    "rdcore",
                    "The package identity, binaries, and projected API matched.")
            ],
            artifacts);
    }

    private static RdCoreCapabilityReport Failure(
        RdCoreCapabilityCode code,
        string component,
        string description) =>
        new(
            code,
            RdCoreApiFingerprintInspector.FingerprintVersion,
            [new(code, component, description)]);
}
