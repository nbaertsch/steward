using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace Steward.RdCore.Windows;

internal sealed record DependencyInspectionResult(
    RdCoreCapabilityCode Code,
    string Description,
    IReadOnlyList<RdCoreManagedDependency> ManagedDependencies,
    IReadOnlyList<RdCoreNativeDependency> NativeDependencies)
{
    public bool IsCompatible => Code == RdCoreCapabilityCode.Compatible;
}

internal interface IRdCoreDependencyInspector
{
    DependencyInspectionResult Inspect(ValidatedRdCorePaths paths);
}

internal sealed class RdCoreFileSnapshotter
{
    private readonly IRdCoreFileSystem fileSystem;

    public RdCoreFileSnapshotter(IRdCoreFileSystem fileSystem)
    {
        this.fileSystem = fileSystem;
    }

    public RdCoreFileIdentity Capture(string packageRoot, string path)
    {
        var root = fileSystem.GetFullPath(packageRoot);
        var fullPath = fileSystem.GetFullPath(path);
        if (!RdCorePathValidator.IsDescendant(root, fullPath))
        {
            throw new InvalidOperationException(
                "A package file escaped its package root.");
        }

        using var stream = fileSystem.OpenRead(fullPath);
        var hash = SHA256.HashData(stream);
        return new(
            Path.GetRelativePath(root, fullPath),
            fileSystem.GetFileLength(fullPath),
            Convert.ToHexString(hash));
    }

    public byte[] ReadAndVerify(
        RdCorePackageArtifacts artifacts,
        RdCoreFileIdentity expected)
    {
        var root = fileSystem.GetFullPath(artifacts.PackageRoot);
        var path = fileSystem.GetFullPath(
            Path.Combine(root, expected.RelativePath));
        var wnc = fileSystem.GetFullPath(Path.Combine(root, "wnc"));
        if (!RdCorePathValidator.IsDescendant(wnc, path))
        {
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.PathEscapesPackage,
                "A recorded RDCore dependency escaped the package directory.");
        }

        using var stream = fileSystem.OpenRead(path);
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        var bytes = memory.ToArray();
        var hash = Convert.ToHexString(SHA256.HashData(bytes));
        if (bytes.LongLength != expected.Length ||
            !string.Equals(hash, expected.Sha256, StringComparison.Ordinal))
        {
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.PackageUpdated,
                "The Windows 365 package changed after compatibility inspection.");
        }

        return bytes;
    }
}

internal sealed class RdCoreDependencyInspector : IRdCoreDependencyInspector
{
    private readonly IRdCoreFileSystem fileSystem;
    private readonly RdCorePathValidator pathValidator;
    private readonly IAuthenticodeVerifier signatureVerifier;
    private readonly PortableExecutableValidator peValidator;
    private readonly RdCoreFileSnapshotter snapshotter;

    public RdCoreDependencyInspector(
        IRdCoreFileSystem fileSystem,
        RdCorePathValidator pathValidator,
        IAuthenticodeVerifier signatureVerifier,
        PortableExecutableValidator peValidator,
        RdCoreFileSnapshotter snapshotter)
    {
        this.fileSystem = fileSystem;
        this.pathValidator = pathValidator;
        this.signatureVerifier = signatureVerifier;
        this.peValidator = peValidator;
        this.snapshotter = snapshotter;
    }

    public DependencyInspectionResult Inspect(ValidatedRdCorePaths paths)
    {
        var managed = new Dictionary<string, RdCoreManagedDependency>(
            StringComparer.OrdinalIgnoreCase);
        var native = new Dictionary<string, RdCoreNativeDependency>(
            StringComparer.OrdinalIgnoreCase);
        var pending = new Queue<string>();
        pending.Enqueue(paths.ProjectedAssemblyPath);
        var inspected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (pending.TryDequeue(out var assemblyPath))
        {
            if (!inspected.Add(assemblyPath))
            {
                continue;
            }

            using var stream = fileSystem.OpenRead(assemblyPath);
            using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            if (!peReader.HasMetadata)
            {
                return Failure(
                    RdCoreCapabilityCode.ManagedMetadataMissing,
                    "A managed package dependency has no metadata.");
            }

            var metadata = peReader.GetMetadataReader();
            foreach (var referenceHandle in metadata.AssemblyReferences)
            {
                var reference = metadata.GetAssemblyReference(referenceHandle);
                var referenceIdentity = ReadReferenceIdentity(metadata, reference);
                if (TrustedFrameworkAssemblies.IsTrusted(
                        referenceIdentity.Name))
                {
                    continue;
                }

                if (managed.TryGetValue(referenceIdentity.Name, out var existing))
                {
                    if (!SatisfiesReference(
                            existing.Assembly,
                            referenceIdentity))
                    {
                        return Failure(
                            RdCoreCapabilityCode.DependencyIdentityMismatch,
                            $"Managed dependency '{referenceIdentity.Name}' was " +
                            $"referenced as versions {existing.Assembly.Version} " +
                            $"and {referenceIdentity.Version}.");
                    }

                    continue;
                }

                var dependencyPath = fileSystem.GetFullPath(
                    Path.Combine(
                        paths.WncDirectory,
                        referenceIdentity.Name + ".dll"));
                var validation = ValidatePackageBinary(
                    paths.PackageRoot,
                    dependencyPath,
                    requireManagedMetadata: true);
                if (validation.Code != RdCoreCapabilityCode.Compatible)
                {
                    return Failure(
                        validation.Code,
                        $"Managed dependency '{referenceIdentity.Name}' failed " +
                        $"validation: {validation.Description}");
                }

                var actualIdentity = ReadAssemblyIdentity(dependencyPath);
                if (!SatisfiesReference(actualIdentity, referenceIdentity))
                {
                    return Failure(
                        RdCoreCapabilityCode.DependencyIdentityMismatch,
                        "A package dependency did not match its assembly reference.");
                }

                var dependency = new RdCoreManagedDependency(
                    actualIdentity,
                    snapshotter.Capture(paths.PackageRoot, dependencyPath));
                managed.Add(actualIdentity.Name, dependency);
                pending.Enqueue(dependencyPath);
            }

            foreach (var methodHandle in metadata.MethodDefinitions)
            {
                var method = metadata.GetMethodDefinition(methodHandle);
                if ((method.Attributes & MethodAttributes.PinvokeImpl) == 0)
                {
                    continue;
                }

                var import = method.GetImport();
                var module = metadata.GetModuleReference(import.Module);
                var moduleName = metadata.GetString(module.Name);
                var nativeResult = InspectNativeModule(paths, moduleName);
                if (nativeResult.Code != RdCoreCapabilityCode.Compatible)
                {
                    return nativeResult;
                }

                foreach (var dependency in nativeResult.NativeDependencies)
                {
                    native[dependency.ModuleName] = dependency;
                }
            }
        }

        if (!native.ContainsKey(RdCorePathValidator.NativeSdkFileName))
        {
            native.Add(
                RdCorePathValidator.NativeSdkFileName,
                new(
                    RdCorePathValidator.NativeSdkFileName,
                    IsSystem32: false,
                    snapshotter.Capture(
                        paths.PackageRoot,
                        paths.NativeSdkPath)));
        }

        return new(
            RdCoreCapabilityCode.Compatible,
            "Managed and native package dependencies were validated.",
            managed.Values
                .OrderBy(item => item.Assembly.Name, StringComparer.Ordinal)
                .ToArray(),
            native.Values
                .OrderBy(item => item.ModuleName, StringComparer.Ordinal)
                .ToArray());
    }

    private DependencyInspectionResult InspectNativeModule(
        ValidatedRdCorePaths paths,
        string moduleName)
    {
        if (string.IsNullOrWhiteSpace(moduleName) ||
            !string.Equals(
                Path.GetFileName(moduleName),
                moduleName,
                StringComparison.Ordinal))
        {
            return new(
                RdCoreCapabilityCode.Compatible,
                "A non-Windows native module reference was not allowlisted.",
                [],
                []);
        }

        var normalizedModuleName =
            moduleName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? moduleName
                : moduleName + ".dll";
        var packagePath = fileSystem.GetFullPath(
            Path.Combine(paths.WncDirectory, normalizedModuleName));
        if (fileSystem.FileExists(packagePath))
        {
            var validation = ValidatePackageBinary(
                paths.PackageRoot,
                packagePath,
                requireManagedMetadata: false);
            if (validation.Code != RdCoreCapabilityCode.Compatible)
            {
                return Failure(
                    validation.Code,
                    $"Native dependency '{moduleName}' failed validation: " +
                    validation.Description);
            }

            return new(
                RdCoreCapabilityCode.Compatible,
                "The native package dependency was validated.",
                [],
                [
                    new(
                        normalizedModuleName,
                        IsSystem32: false,
                        snapshotter.Capture(paths.PackageRoot, packagePath))
                ]);
        }

        var systemPath = Path.Combine(
            Environment.SystemDirectory,
            normalizedModuleName);
        if (fileSystem.FileExists(systemPath) ||
            normalizedModuleName.StartsWith(
                "api-ms-win-",
                StringComparison.OrdinalIgnoreCase) ||
            normalizedModuleName.StartsWith(
                "ext-ms-win-",
                StringComparison.OrdinalIgnoreCase))
        {
            return new(
                RdCoreCapabilityCode.Compatible,
                "The native dependency is provided by System32.",
                [],
                [new(normalizedModuleName, IsSystem32: true, File: null)]);
        }

        return new(
            RdCoreCapabilityCode.Compatible,
            $"Optional native module '{moduleName}' is unavailable and will " +
            "not be allowlisted.",
            [],
            []);
    }

    private BinaryValidationResult ValidatePackageBinary(
        string packageRoot,
        string path,
        bool requireManagedMetadata)
    {
        var pathResult = pathValidator.ValidateAdditionalBinary(packageRoot, path);
        if (pathResult.Code != RdCoreCapabilityCode.Compatible)
        {
            return pathResult;
        }

        var signature = signatureVerifier.Verify(path);
        if (signature != AuthenticodeStatus.TrustedMicrosoft)
        {
            return new(
                signature == AuthenticodeStatus.NonMicrosoftSigner
                    ? RdCoreCapabilityCode.BinaryNotMicrosoftSigned
                    : RdCoreCapabilityCode.BinaryNotTrusted,
                "A package dependency did not have a trusted Microsoft signature.");
        }

        var peResult = peValidator.Validate(path, requireManagedMetadata);
        return new(peResult.Code, peResult.Description);
    }

    private RdCoreAssemblyIdentity ReadAssemblyIdentity(string path)
    {
        using var stream = fileSystem.OpenRead(path);
        using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        var metadata = peReader.GetMetadataReader();
        var definition = metadata.GetAssemblyDefinition();
        return new(
            metadata.GetString(definition.Name),
            definition.Version,
            GetPublicKeyToken(
                metadata.GetBlobBytes(definition.PublicKey),
                containsFullPublicKey: true));
    }

    private static RdCoreAssemblyIdentity ReadReferenceIdentity(
        MetadataReader metadata,
        AssemblyReference reference) =>
        new(
            metadata.GetString(reference.Name),
            reference.Version,
            GetPublicKeyToken(
                metadata.GetBlobBytes(reference.PublicKeyOrToken),
                (reference.Flags & AssemblyFlags.PublicKey) != 0));

    private static bool SatisfiesReference(
        RdCoreAssemblyIdentity actual,
        RdCoreAssemblyIdentity requested) =>
        string.Equals(
            actual.Name,
            requested.Name,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            actual.PublicKeyToken,
            requested.PublicKeyToken,
            StringComparison.OrdinalIgnoreCase) &&
        actual.Version >= requested.Version;

    private static string GetPublicKeyToken(
        byte[] publicKeyOrToken,
        bool containsFullPublicKey)
    {
        if (publicKeyOrToken.Length == 0)
        {
            return string.Empty;
        }

        if (!containsFullPublicKey)
        {
            return Convert.ToHexString(publicKeyOrToken);
        }

        var assemblyName = new AssemblyName();
        assemblyName.SetPublicKey(publicKeyOrToken);
        return Convert.ToHexString(assemblyName.GetPublicKeyToken() ?? []);
    }

    private static DependencyInspectionResult Failure(
        RdCoreCapabilityCode code,
        string description) =>
        new(code, description, [], []);
}

internal static class TrustedFrameworkAssemblies
{
    private static readonly Lazy<IReadOnlySet<string>> Names =
        new(CreateNames);

    public static bool IsTrusted(string? assemblyName) =>
        assemblyName is not null && Names.Value.Contains(assemblyName);

    private static IReadOnlySet<string> CreateNames()
    {
        var runtimeDirectory = Path.GetFullPath(
            RuntimeEnvironment.GetRuntimeDirectory());
        return Directory.EnumerateFiles(runtimeDirectory, "*.dll")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(name => !string.IsNullOrEmpty(name))
            .Cast<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
}

internal sealed record GenerationValidationResult(
    RdCoreCapabilityCode Code,
    string Description)
{
    public bool IsCompatible => Code == RdCoreCapabilityCode.Compatible;
}

internal interface IRdCoreGenerationValidator
{
    GenerationValidationResult Validate(RdCorePackageArtifacts artifacts);

    byte[] ReadVerifiedFile(
        RdCorePackageArtifacts artifacts,
        RdCoreFileIdentity identity);
}

internal sealed class RdCoreGenerationValidator :
    IRdCoreGenerationValidator
{
    private readonly Windows365PackageLocator packageLocator;
    private readonly RdCorePathValidator pathValidator;
    private readonly IAuthenticodeVerifier signatureVerifier;
    private readonly PortableExecutableValidator peValidator;
    private readonly IRdCoreApiFingerprintInspector fingerprintInspector;
    private readonly IRdCoreDependencyInspector dependencyInspector;
    private readonly RdCoreFileSnapshotter snapshotter;
    private readonly IRdCoreFileSystem fileSystem;

    public RdCoreGenerationValidator(
        Windows365PackageLocator packageLocator,
        RdCorePathValidator pathValidator,
        IAuthenticodeVerifier signatureVerifier,
        PortableExecutableValidator peValidator,
        IRdCoreApiFingerprintInspector fingerprintInspector,
        IRdCoreDependencyInspector dependencyInspector,
        RdCoreFileSnapshotter snapshotter,
        IRdCoreFileSystem fileSystem)
    {
        this.packageLocator = packageLocator;
        this.pathValidator = pathValidator;
        this.signatureVerifier = signatureVerifier;
        this.peValidator = peValidator;
        this.fingerprintInspector = fingerprintInspector;
        this.dependencyInspector = dependencyInspector;
        this.snapshotter = snapshotter;
        this.fileSystem = fileSystem;
    }

    public static RdCoreGenerationValidator CreateProduction()
    {
        var fileSystem = new PhysicalRdCoreFileSystem();
        var pathValidator = new RdCorePathValidator(fileSystem);
        var signatureVerifier = new MicrosoftAuthenticodeVerifier();
        var peValidator = new PortableExecutableValidator(fileSystem);
        var snapshotter = new RdCoreFileSnapshotter(fileSystem);
        return new(
            new Windows365PackageLocator(new WindowsAppxPackageSource()),
            pathValidator,
            signatureVerifier,
            peValidator,
            new RdCoreApiFingerprintInspector(fileSystem),
            new RdCoreDependencyInspector(
                fileSystem,
                pathValidator,
                signatureVerifier,
                peValidator,
                snapshotter),
            snapshotter,
            fileSystem);
    }

    public GenerationValidationResult Validate(RdCorePackageArtifacts artifacts)
    {
        PackageLocationResult packageResult;
        try
        {
            packageResult = packageLocator.Locate();
        }
        catch (UnauthorizedAccessException)
        {
            return Updated();
        }
        catch (COMException)
        {
            return Updated();
        }
        catch (InvalidOperationException)
        {
            return Updated();
        }

        if (packageResult.Code != RdCoreCapabilityCode.Compatible ||
            packageResult.Package is null ||
            !MatchesPackage(artifacts, packageResult.Package))
        {
            return Updated();
        }

        try
        {
            var pathsResult = pathValidator.Validate(
                packageResult.Package.InstalledPath);
            if (pathsResult.Code != RdCoreCapabilityCode.Compatible ||
                pathsResult.Paths is null ||
                !PathsMatch(artifacts, pathsResult.Paths))
            {
                return Updated();
            }

            var projected = ValidateRequiredBinary(
                pathsResult.Paths.ProjectedAssemblyPath,
                requireManagedMetadata: true);
            if (!projected.IsCompatible)
            {
                return projected;
            }

            var native = ValidateRequiredBinary(
                pathsResult.Paths.NativeSdkPath,
                requireManagedMetadata: false);
            if (!native.IsCompatible)
            {
                return native;
            }

            if (snapshotter.Capture(
                    artifacts.PackageRoot,
                    artifacts.ProjectedAssemblyPath) !=
                artifacts.ProjectedAssemblyIdentity ||
                snapshotter.Capture(
                    artifacts.PackageRoot,
                    artifacts.NativeSdkPath) !=
                artifacts.NativeSdkIdentity)
            {
                return Updated();
            }

            var fingerprint = fingerprintInspector.Inspect(
                artifacts.ProjectedAssemblyPath);
            if (!fingerprint.IsMatch)
            {
                return new(
                    fingerprint.Code,
                    "The RDCore API fingerprint changed after inspection.");
            }

            var dependencies = dependencyInspector.Inspect(pathsResult.Paths);
            if (!dependencies.IsCompatible)
            {
                return new(dependencies.Code, dependencies.Description);
            }

            if (!dependencies.ManagedDependencies.SequenceEqual(
                    artifacts.ManagedDependencies) ||
                !dependencies.NativeDependencies.SequenceEqual(
                    artifacts.NativeDependencies))
            {
                return Updated();
            }

            return new(
                RdCoreCapabilityCode.Compatible,
                "The inspected Windows 365 package generation is unchanged.");
        }
        catch (UnauthorizedAccessException)
        {
            return Updated();
        }
        catch (IOException)
        {
            return Updated();
        }
        catch (SecurityException)
        {
            return Updated();
        }
        catch (ArgumentException)
        {
            return Updated();
        }
        catch (NotSupportedException)
        {
            return Updated();
        }
        catch (BadImageFormatException)
        {
            return Updated();
        }
    }

    public byte[] ReadVerifiedFile(
        RdCorePackageArtifacts artifacts,
        RdCoreFileIdentity identity) =>
        snapshotter.ReadAndVerify(artifacts, identity);

    private GenerationValidationResult ValidateRequiredBinary(
        string path,
        bool requireManagedMetadata)
    {
        var signature = signatureVerifier.Verify(path);
        if (signature != AuthenticodeStatus.TrustedMicrosoft)
        {
            return new(
                signature == AuthenticodeStatus.NonMicrosoftSigner
                    ? RdCoreCapabilityCode.BinaryNotMicrosoftSigned
                    : RdCoreCapabilityCode.BinaryNotTrusted,
                "An RDCore binary no longer has a trusted Microsoft signature.");
        }

        var pe = peValidator.Validate(path, requireManagedMetadata);
        return new(pe.Code, pe.Description);
    }

    private bool MatchesPackage(
        RdCorePackageArtifacts artifacts,
        AppxPackageCandidate package) =>
        string.Equals(
            artifacts.PackageFullName,
            package.FullName,
            StringComparison.Ordinal) &&
        artifacts.PackageVersion == package.Version &&
        string.Equals(
            fileSystem.GetFullPath(artifacts.PackageRoot),
            fileSystem.GetFullPath(package.InstalledPath),
            StringComparison.OrdinalIgnoreCase);

    private bool PathsMatch(
        RdCorePackageArtifacts artifacts,
        ValidatedRdCorePaths paths) =>
        string.Equals(
            fileSystem.GetFullPath(artifacts.PackageRoot),
            paths.PackageRoot,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            fileSystem.GetFullPath(artifacts.ProjectedAssemblyPath),
            paths.ProjectedAssemblyPath,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            fileSystem.GetFullPath(artifacts.NativeSdkPath),
            paths.NativeSdkPath,
            StringComparison.OrdinalIgnoreCase);

    private static GenerationValidationResult Updated() =>
        new(
            RdCoreCapabilityCode.PackageUpdated,
            "The Windows 365 package was updated, removed, or replaced after " +
            "compatibility inspection.");
}
