using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Steward.RdCore.Windows;

internal interface IRdCoreFileSystem
{
    string GetFullPath(string path);

    bool DirectoryExists(string path);

    bool FileExists(string path);

    FileAttributes GetAttributes(string path);

    long GetFileLength(string path);

    Stream OpenRead(string path);
}

internal sealed class PhysicalRdCoreFileSystem : IRdCoreFileSystem
{
    public string GetFullPath(string path) => Path.GetFullPath(path);

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public bool FileExists(string path) => File.Exists(path);

    public FileAttributes GetAttributes(string path) => File.GetAttributes(path);

    public long GetFileLength(string path) => new FileInfo(path).Length;

    public Stream OpenRead(string path) =>
        new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
}

internal sealed record ValidatedRdCorePaths(
    string PackageRoot,
    string WncDirectory,
    string ProjectedAssemblyPath,
    string NativeSdkPath);

internal sealed record BinaryValidationResult(
    RdCoreCapabilityCode Code,
    string Description,
    ValidatedRdCorePaths? Paths = null);

internal sealed class RdCorePathValidator
{
    internal const long DefaultMaximumBinarySize = 64L * 1024 * 1024;
    internal const string ProjectedAssemblyFileName =
        "Microsoft.CloudManagedDesktop.Clients.NxtClient.RDCore.dll";
    internal const string NativeSdkFileName = "RDCoreSdk.dll";

    private readonly IRdCoreFileSystem fileSystem;
    private readonly long maximumBinarySize;

    public RdCorePathValidator(
        IRdCoreFileSystem fileSystem,
        long maximumBinarySize = DefaultMaximumBinarySize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBinarySize);
        this.fileSystem = fileSystem;
        this.maximumBinarySize = maximumBinarySize;
    }

    public BinaryValidationResult Validate(string packageRoot)
    {
        if (string.IsNullOrWhiteSpace(packageRoot))
        {
            return Failure(
                RdCoreCapabilityCode.PackagePathInvalid,
                "The package did not provide an installation directory.");
        }

        var root = fileSystem.GetFullPath(packageRoot);
        if (!fileSystem.DirectoryExists(root))
        {
            return Failure(
                RdCoreCapabilityCode.PackagePathInvalid,
                "The package installation directory is unavailable.");
        }

        var wnc = fileSystem.GetFullPath(Path.Combine(root, "wnc"));
        var projected = fileSystem.GetFullPath(
            Path.Combine(wnc, ProjectedAssemblyFileName));
        var native = fileSystem.GetFullPath(Path.Combine(wnc, NativeSdkFileName));
        foreach (var path in new[] { wnc, projected, native })
        {
            if (!IsDescendant(root, path))
            {
                return Failure(
                    RdCoreCapabilityCode.PathEscapesPackage,
                    "A required RDCore path escaped the package installation root.");
            }
        }

        if (!fileSystem.DirectoryExists(wnc) ||
            !fileSystem.FileExists(projected) ||
            !fileSystem.FileExists(native))
        {
            return Failure(
                RdCoreCapabilityCode.RequiredBinaryMissing,
                "One or more required RDCore binaries are unavailable.");
        }

        foreach (var path in new[] { root, wnc, projected, native })
        {
            if ((fileSystem.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                return Failure(
                    RdCoreCapabilityCode.ReparsePointRejected,
                    "The package path contains a reparse point.");
            }
        }

        foreach (var path in new[] { projected, native })
        {
            var length = fileSystem.GetFileLength(path);
            if (length <= 0 || length > maximumBinarySize)
            {
                return Failure(
                    RdCoreCapabilityCode.FileTooLarge,
                    "A required RDCore binary has an invalid or excessive size.");
            }
        }

        return new(
            RdCoreCapabilityCode.Compatible,
            "The RDCore package paths passed containment and file checks.",
            new(root, wnc, projected, native));
    }

    public BinaryValidationResult ValidateAdditionalBinary(
        string packageRoot,
        string candidatePath)
    {
        var root = fileSystem.GetFullPath(packageRoot);
        var wnc = fileSystem.GetFullPath(Path.Combine(root, "wnc"));
        var candidate = fileSystem.GetFullPath(candidatePath);
        if (!IsDescendant(wnc, candidate))
        {
            return Failure(
                RdCoreCapabilityCode.PathEscapesPackage,
                "A dependency path escaped the package wnc directory.");
        }

        if (!fileSystem.DirectoryExists(root) ||
            !fileSystem.DirectoryExists(wnc) ||
            !fileSystem.FileExists(candidate))
        {
            return Failure(
                RdCoreCapabilityCode.RequiredBinaryMissing,
                "A required package dependency is unavailable.");
        }

        foreach (var path in new[] { root, wnc, candidate })
        {
            if ((fileSystem.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                return Failure(
                    RdCoreCapabilityCode.ReparsePointRejected,
                    "A dependency path contains a reparse point.");
            }
        }

        var length = fileSystem.GetFileLength(candidate);
        if (length <= 0 || length > maximumBinarySize)
        {
            return Failure(
                RdCoreCapabilityCode.FileTooLarge,
                "A package dependency has an invalid or excessive size.");
        }

        return new(
            RdCoreCapabilityCode.Compatible,
            "The package dependency path passed containment and file checks.");
    }

    internal static bool IsDescendant(string root, string candidate)
    {
        var rootWithSeparator = Path.EndsInDirectorySeparator(root)
            ? root
            : root + Path.DirectorySeparatorChar;
        return candidate.StartsWith(
            rootWithSeparator,
            StringComparison.OrdinalIgnoreCase);
    }

    private static BinaryValidationResult Failure(
        RdCoreCapabilityCode code,
        string description) =>
        new(code, description);
}

internal enum AuthenticodeStatus
{
    TrustedMicrosoft,
    Untrusted,
    NonMicrosoftSigner
}

internal interface IAuthenticodeVerifier
{
    AuthenticodeStatus Verify(string path);
}

internal sealed class MicrosoftAuthenticodeVerifier : IAuthenticodeVerifier
{
    private const string MicrosoftPublisher =
        "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, " +
        "S=Washington, C=US";

    public AuthenticodeStatus Verify(string path)
    {
        if (!WinTrust.VerifyEmbeddedSignature(path))
        {
            return AuthenticodeStatus.Untrusted;
        }

        try
        {
#pragma warning disable SYSLIB0057 // Authenticode signer extraction has no loader replacement.
            using var signer = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return string.Equals(
                signer.Subject,
                MicrosoftPublisher,
                StringComparison.Ordinal)
                ? AuthenticodeStatus.TrustedMicrosoft
                : AuthenticodeStatus.NonMicrosoftSigner;
        }
        catch (CryptographicException)
        {
            return AuthenticodeStatus.Untrusted;
        }
    }
}

internal sealed record PortableExecutableResult(
    RdCoreCapabilityCode Code,
    string Description,
    bool HasMetadata);

internal sealed class PortableExecutableValidator
{
    private readonly IRdCoreFileSystem fileSystem;

    public PortableExecutableValidator(IRdCoreFileSystem fileSystem)
    {
        this.fileSystem = fileSystem;
    }

    public PortableExecutableResult Validate(
        string path,
        bool requireManagedMetadata)
    {
        try
        {
            using var stream = fileSystem.OpenRead(path);
            using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            if (reader.PEHeaders.PEHeader is null)
            {
                return Failure(
                    RdCoreCapabilityCode.InvalidPortableExecutable,
                    "A required RDCore binary is not a valid PE image.");
            }

            if (!IsSupportedMachine(reader.PEHeaders.CoffHeader.Machine, reader))
            {
                return Failure(
                    RdCoreCapabilityCode.UnsupportedArchitecture,
                    "A required RDCore binary has an unsupported architecture.");
            }

            if (requireManagedMetadata && !reader.HasMetadata)
            {
                return Failure(
                    RdCoreCapabilityCode.ManagedMetadataMissing,
                    "The projected RDCore assembly has no managed metadata.");
            }

            return new(
                RdCoreCapabilityCode.Compatible,
                "The RDCore binary has a supported PE architecture.",
                reader.HasMetadata);
        }
        catch (BadImageFormatException)
        {
            return Failure(
                RdCoreCapabilityCode.InvalidPortableExecutable,
                "A required RDCore binary is not a valid PE image.");
        }
    }

    private static bool IsSupportedMachine(Machine machine, PEReader reader)
    {
        var expected = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => Machine.Amd64,
            Architecture.X86 => Machine.I386,
            Architecture.Arm => Machine.Arm,
            Architecture.Arm64 => Machine.Arm64,
            _ => Machine.Unknown
        };
        if (machine == expected)
        {
            return true;
        }

        return machine == Machine.I386 &&
            reader.HasMetadata &&
            reader.PEHeaders.CorHeader is { Flags: var flags } &&
            (flags & CorFlags.ILOnly) != 0 &&
            (flags & CorFlags.Requires32Bit) == 0;
    }

    private static PortableExecutableResult Failure(
        RdCoreCapabilityCode code,
        string description) =>
        new(code, description, false);
}

internal static class WinTrust
{
    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static bool VerifyEmbeddedSignature(string filePath)
    {
        var fileInfo = new WinTrustFileInfo(filePath);
        var fileInfoPointer = Marshal.AllocCoTaskMem(
            Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            var trustData = WinTrustData.ForFile(fileInfoPointer);
            var action = GenericVerifyV2;
            var result = WinVerifyTrust(
                nint.Zero,
                ref action,
                ref trustData);
            trustData.StateAction = WinTrustStateAction.Close;
            _ = WinVerifyTrust(nint.Zero, ref action, ref trustData);
            return result == 0;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeCoTaskMem(fileInfoPointer);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(
        nint hwnd,
        [In] ref Guid actionId,
        [In, Out] ref WinTrustData trustData);

    private enum WinTrustDataUiChoice : uint
    {
        None = 2
    }

    private enum WinTrustDataRevocationChecks : uint
    {
        WholeChain = 1
    }

    private enum WinTrustDataChoice : uint
    {
        File = 1
    }

    private enum WinTrustStateAction : uint
    {
        Ignore = 0,
        Verify = 1,
        Close = 2
    }

    [Flags]
    private enum WinTrustProviderFlags : uint
    {
        RevocationCheckChainExcludeRoot = 0x00000400,
        CacheOnlyUrlRetrieval = 0x00001000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustFileInfo
    {
        public WinTrustFileInfo(string filePath)
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>();
            FilePath = filePath;
        }

        public uint StructSize;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string FilePath;

        public nint FileHandle;

        public nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public WinTrustDataUiChoice UiChoice;
        public WinTrustDataRevocationChecks RevocationChecks;
        public WinTrustDataChoice UnionChoice;
        public nint FileInfo;
        public WinTrustStateAction StateAction;
        public nint StateData;
        public nint UrlReference;
        public WinTrustProviderFlags ProviderFlags;
        public uint UiContext;
        public nint SignatureSettings;

        public static WinTrustData ForFile(nint fileInfo) =>
            new()
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = WinTrustDataUiChoice.None,
                RevocationChecks = WinTrustDataRevocationChecks.WholeChain,
                UnionChoice = WinTrustDataChoice.File,
                FileInfo = fileInfo,
                StateAction = WinTrustStateAction.Verify,
                ProviderFlags =
                    WinTrustProviderFlags.RevocationCheckChainExcludeRoot |
                    WinTrustProviderFlags.CacheOnlyUrlRetrieval
            };
    }
}
