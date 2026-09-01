using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;

namespace Steward.RdCore.Windows;

internal interface IRdCoreAssemblyLoader : IDisposable
{
    bool IsCollectible { get; }

    Assembly LoadProjectedAssembly();
}

internal sealed class CollectibleRdCoreAssemblyLoader : AssemblyLoadContext,
    IRdCoreAssemblyLoader
{
    private const uint LoadLibrarySearchDllLoadDir = 0x00000100;
    private const uint LoadLibrarySearchSystem32 = 0x00000800;

    private readonly RdCorePackageArtifacts artifacts;
    private readonly IRdCoreGenerationValidator generationValidator;
    private readonly IReadOnlyDictionary<string, RdCoreManagedDependency>
        managedDependencies;
    private readonly IReadOnlyDictionary<string, RdCoreNativeDependency>
        nativeDependencies;
    private readonly Dictionary<string, nint> loadedNative =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly string nativeShadowDirectory;
    private readonly object nativeGate = new();
    private bool disposed;

    private CollectibleRdCoreAssemblyLoader(
        RdCorePackageArtifacts artifacts,
        IRdCoreGenerationValidator generationValidator)
        : base($"Steward.RdCore.{Guid.NewGuid():N}", isCollectible: false)
    {
        this.artifacts = artifacts;
        this.generationValidator = generationValidator;
        managedDependencies = artifacts.ManagedDependencies.ToDictionary(
            dependency => dependency.Assembly.Name,
            StringComparer.OrdinalIgnoreCase);
        nativeDependencies = artifacts.NativeDependencies.ToDictionary(
            dependency => NormalizeModuleName(dependency.ModuleName),
            StringComparer.OrdinalIgnoreCase);
        var shadowRoot = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "Steward",
            "rdcore-native");
        Directory.CreateDirectory(shadowRoot);
        if ((File.GetAttributes(shadowRoot) &
             FileAttributes.ReparsePoint) != 0)
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.PathEscapesPackage,
                "The RDCore native shadow root cannot be a reparse point.");
        nativeShadowDirectory = Path.Combine(
            shadowRoot,
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(nativeShadowDirectory);
    }

    public static CollectibleRdCoreAssemblyLoader Create(
        RdCoreCapabilityReport capability) =>
        Create(capability, RdCoreGenerationValidator.CreateProduction());

    internal static CollectibleRdCoreAssemblyLoader Create(
        RdCoreCapabilityReport capability,
        IRdCoreGenerationValidator generationValidator)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(generationValidator);
        if (!capability.IsCompatible || capability.Artifacts is null)
        {
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.ApiFingerprintMismatch,
                "RDCore assemblies can only be loaded after a compatible report.");
        }

        EnsureManifestPathsAreContained(capability.Artifacts);
        ThrowIfInvalid(generationValidator.Validate(capability.Artifacts));
        return new(capability.Artifacts, generationValidator);
    }

    public Assembly LoadProjectedAssembly()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        RevalidateGeneration();
        var bytes = generationValidator.ReadVerifiedFile(
            artifacts,
            artifacts.ProjectedAssemblyIdentity);
        return LoadFromStream(new MemoryStream(bytes, writable: false));
    }

    internal nint ActivateActivityManager()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var module = LoadUnmanagedDll(
            RdCorePathValidator.NativeSdkFileName);
        var export = GetProcAddress(
            module,
            "DllGetActivationFactory");
        if (export == 0)
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.DependencyIdentityMismatch,
                "RDCoreSdk does not export DllGetActivationFactory.");
        var dllGetActivationFactory =
            Marshal.GetDelegateForFunctionPointer<DllGetActivationFactory>(
                export);
        const string activityManager =
            "Microsoft.RemoteDesktop.ClientCore.ActivityManager";
        var result = WindowsCreateString(
            activityManager,
            activityManager.Length,
            out var className);
        if (result < 0)
            throw new InvalidOperationException(
                "RDCore activity class HSTRING creation failed.",
                Marshal.GetExceptionForHR(result));
        try
        {
            result = dllGetActivationFactory(
                className,
                out var factory);
            if (result < 0)
                throw new InvalidOperationException(
                    "RDCore DLL activation factory lookup failed.",
                    Marshal.GetExceptionForHR(result));
            if (factory == 0)
                throw new InvalidOperationException(
                    "RDCore DLL activation factory lookup returned null.");
            try
            {
                var vtable = Marshal.ReadIntPtr(factory);
                var activatePointer = Marshal.ReadIntPtr(
                    vtable,
                    6 * IntPtr.Size);
                var activate =
                    Marshal.GetDelegateForFunctionPointer<ActivateInstance>(
                        activatePointer);
                result = activate(factory, out var instance);
                if (result < 0)
                    throw new InvalidOperationException(
                        "RDCore activity instance activation failed.",
                        Marshal.GetExceptionForHR(result));
                if (instance == 0)
                    throw new InvalidOperationException(
                        "RDCore activity instance activation returned null.");
                return instance;
            }
            finally
            {
                _ = Marshal.Release(factory);
            }
        }
        finally
        {
            _ = WindowsDeleteString(className);
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        GC.SuppressFinalize(this);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (TrustedFrameworkAssemblies.IsTrusted(assemblyName.Name))
        {
            return null;
        }

        if (assemblyName.Name is null ||
            !managedDependencies.TryGetValue(
                assemblyName.Name,
                out var dependency))
        {
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.DependencyNotAllowed,
                "A managed dependency was not present in the validated package " +
                "generation.",
                assemblyName.Name);
        }

        if (!Matches(assemblyName, dependency.Assembly))
        {
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.DependencyIdentityMismatch,
                "A managed dependency request did not match its validated identity.");
        }

        if (string.Equals(
                assemblyName.Name,
                "WinRT.Runtime",
                StringComparison.OrdinalIgnoreCase))
        {
            var shared = AssemblyLoadContext.Default.Assemblies
                .SingleOrDefault(assembly => string.Equals(
                    assembly.GetName().Name,
                    assemblyName.Name,
                    StringComparison.OrdinalIgnoreCase))
                ?? throw new RdCoreLoadException(
                    RdCoreCapabilityCode.DependencyIdentityMismatch,
                    "The process-wide WinRT runtime is unavailable.");
            if (!SatisfiesSharedRuntime(
                    shared.GetName(),
                    dependency.Assembly))
                throw new RdCoreLoadException(
                    RdCoreCapabilityCode.DependencyIdentityMismatch,
                    "The process-wide WinRT runtime is incompatible.");
            return shared;
        }

        RevalidateGeneration();
        var bytes = generationValidator.ReadVerifiedFile(
            artifacts,
            dependency.File);
        return LoadFromStream(new MemoryStream(bytes, writable: false));
    }

    protected override nint LoadUnmanagedDll(string unmanagedDllName)
    {
        var normalizedName = NormalizeModuleName(unmanagedDllName);
        if (string.Equals(
                normalizedName,
                "Microsoft.RemoteDesktop.ClientCore.dll",
                StringComparison.OrdinalIgnoreCase))
            normalizedName = RdCorePathValidator.NativeSdkFileName;
        if (!nativeDependencies.TryGetValue(
                normalizedName,
                out var dependency))
        {
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.DependencyNotAllowed,
                "A native dependency was not present in the validated package " +
                "generation.",
                normalizedName);
        }

        RevalidateGeneration();
        if (dependency.IsSystem32)
        {
            return LoadNativeOrThrow(
                dependency.ModuleName,
                LoadLibrarySearchSystem32);
        }

        if (dependency.File is null)
        {
            throw new RdCoreLoadException(
                RdCoreCapabilityCode.DependencyNotAllowed,
                "A package-native dependency had no validated file identity.");
        }

        lock (nativeGate)
        {
            if (loadedNative.TryGetValue(
                    dependency.ModuleName,
                    out var existing))
                return existing;
            var bytes = generationValidator.ReadVerifiedFile(
                artifacts,
                dependency.File);
            var shadowPath = Path.Combine(
                nativeShadowDirectory,
                dependency.ModuleName);
            using (var stream = new FileStream(
                       shadowPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            if (!string.Equals(
                    Convert.ToHexString(SHA256.HashData(
                        File.ReadAllBytes(shadowPath))),
                    dependency.File.Sha256,
                    StringComparison.Ordinal))
                throw new RdCoreLoadException(
                    RdCoreCapabilityCode.PackageUpdated,
                    "The RDCore native shadow copy failed verification.");
            var loaded = LoadNativeOrThrow(
                shadowPath,
                LoadLibrarySearchDllLoadDir | LoadLibrarySearchSystem32);
            loadedNative.Add(dependency.ModuleName, loaded);
            return loaded;
        }
    }

    private void RevalidateGeneration()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ThrowIfInvalid(generationValidator.Validate(artifacts));
    }

    private static void ThrowIfInvalid(GenerationValidationResult validation)
    {
        if (!validation.IsCompatible)
        {
            throw new RdCoreLoadException(
                validation.Code,
                validation.Description);
        }
    }

    private static bool Matches(
        AssemblyName requested,
        RdCoreAssemblyIdentity expected)
    {
        if (!string.Equals(
                requested.Name,
                expected.Name,
                StringComparison.OrdinalIgnoreCase) ||
            requested.Version is not null &&
            requested.Version > expected.Version)
        {
            return false;
        }

        var requestedToken = Convert.ToHexString(
            requested.GetPublicKeyToken() ?? []);
        return requestedToken.Length == 0 ||
            string.Equals(
                requestedToken,
                expected.PublicKeyToken,
                StringComparison.OrdinalIgnoreCase);
    }

    private static bool SatisfiesSharedRuntime(
        AssemblyName shared,
        RdCoreAssemblyIdentity expected)
    {
        if (!string.Equals(
                shared.Name,
                expected.Name,
                StringComparison.OrdinalIgnoreCase) ||
            shared.Version is null ||
            shared.Version < expected.Version)
            return false;
        return string.Equals(
            Convert.ToHexString(shared.GetPublicKeyToken() ?? []),
            expected.PublicKeyToken,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeModuleName(string moduleName)
    {
        var fileName = Path.GetFileName(moduleName);
        if (!string.Equals(fileName, moduleName, StringComparison.Ordinal))
        {
            return string.Empty;
        }

        return fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? fileName
            : fileName + ".dll";
    }

    private static void EnsureManifestPathsAreContained(
        RdCorePackageArtifacts artifacts)
    {
        var root = Path.GetFullPath(artifacts.PackageRoot);
        var wnc = Path.GetFullPath(Path.Combine(root, "wnc"));
        foreach (var file in EnumeratePackageFiles(artifacts))
        {
            var path = Path.GetFullPath(Path.Combine(root, file.RelativePath));
            if (!RdCorePathValidator.IsDescendant(wnc, path))
            {
                throw new RdCoreLoadException(
                    RdCoreCapabilityCode.PathEscapesPackage,
                    "A recorded dependency escaped the validated package directory.");
            }
        }
    }

    private static IEnumerable<RdCoreFileIdentity> EnumeratePackageFiles(
        RdCorePackageArtifacts artifacts)
    {
        yield return artifacts.ProjectedAssemblyIdentity;
        yield return artifacts.NativeSdkIdentity;
        foreach (var dependency in artifacts.ManagedDependencies)
        {
            yield return dependency.File;
        }

        foreach (var dependency in artifacts.NativeDependencies)
        {
            if (dependency.File is not null)
            {
                yield return dependency.File;
            }
        }
    }

    private static nint LoadNativeOrThrow(string nameOrPath, uint flags)
    {
        var handle = LoadLibraryEx(nameOrPath, nint.Zero, flags);
        if (handle == nint.Zero)
        {
            throw new DllNotFoundException(
                "A validated native RDCore dependency could not be loaded.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return handle;
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "LoadLibraryExW",
        SetLastError = true,
        CharSet = CharSet.Unicode,
        ExactSpelling = true)]
    private static extern nint LoadLibraryEx(
        string fileName,
        nint reserved,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(nint module);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int DllGetActivationFactory(
        nint activatableClassId,
        out nint factory);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int ActivateInstance(
        nint activationFactory,
        out nint instance);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern nint GetProcAddress(
        nint module,
        string procedureName);

    [DllImport("combase.dll")]
    private static extern int WindowsCreateString(
        [MarshalAs(UnmanagedType.LPWStr)] string source,
        int length,
        out nint value);

    [DllImport("combase.dll")]
    private static extern int WindowsDeleteString(nint value);

}
