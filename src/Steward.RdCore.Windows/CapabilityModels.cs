namespace Steward.RdCore.Windows;

public enum RdCoreCapabilityCode
{
    Compatible,
    UnsupportedOperatingSystem,
    PackageNotFound,
    PackageIdentityMismatch,
    PackageUnhealthy,
    PackageQueryFailed,
    PackagePathInvalid,
    RequiredBinaryMissing,
    ReparsePointRejected,
    PathEscapesPackage,
    FileTooLarge,
    BinaryNotTrusted,
    BinaryNotMicrosoftSigned,
    UnsupportedArchitecture,
    InvalidPortableExecutable,
    ManagedMetadataMissing,
    ApiFingerprintMismatch,
    BinaryInspectionFailed,
    /// <summary>
    /// The inspected AppX package generation was updated, removed, relocated,
    /// or had one of its validated files replaced before loading.
    /// </summary>
    PackageUpdated,
    DependencyNotAllowed,
    DependencyIdentityMismatch
}

public sealed record RdCoreDiagnostic(
    RdCoreCapabilityCode Code,
    string Component,
    string Description)
{
    public override string ToString() => $"{Code}: {Component}";
}

public sealed record RdCorePackageArtifacts(
    string PackageFullName,
    Version PackageVersion,
    string PackageRoot,
    string ProjectedAssemblyPath,
    string NativeSdkPath,
    RdCoreFileIdentity ProjectedAssemblyIdentity,
    RdCoreFileIdentity NativeSdkIdentity,
    IReadOnlyList<RdCoreManagedDependency> ManagedDependencies,
    IReadOnlyList<RdCoreNativeDependency> NativeDependencies)
{
    public override string ToString() =>
        $"Windows 365 package {PackageVersion}; RDCore artifacts validated";
}

public sealed record RdCoreFileIdentity(
    string RelativePath,
    long Length,
    string Sha256)
{
    public override string ToString() =>
        $"{Path.GetFileName(RelativePath)}; length={Length}; SHA-256 recorded";
}

public sealed record RdCoreAssemblyIdentity(
    string Name,
    Version Version,
    string PublicKeyToken)
{
    public override string ToString() => $"{Name}, Version={Version}";
}

public sealed record RdCoreManagedDependency(
    RdCoreAssemblyIdentity Assembly,
    RdCoreFileIdentity File)
{
    public override string ToString() => Assembly.ToString();
}

public sealed record RdCoreNativeDependency(
    string ModuleName,
    bool IsSystem32,
    RdCoreFileIdentity? File)
{
    public override string ToString() =>
        IsSystem32 ? $"{ModuleName}; System32" : $"{ModuleName}; package";
}

public sealed class RdCoreLoadException : InvalidOperationException
{
    public RdCoreLoadException(
        RdCoreCapabilityCode code,
        string message,
        string? detail = null)
        : base(message)
    {
        Code = code;
        Detail = detail;
    }

    public RdCoreCapabilityCode Code { get; }
    public string? Detail { get; }
}

public sealed class RdCoreCapabilityReport
{
    internal RdCoreCapabilityReport(
        RdCoreCapabilityCode code,
        string fingerprintVersion,
        IReadOnlyList<RdCoreDiagnostic> diagnostics,
        RdCorePackageArtifacts? artifacts = null)
    {
        Code = code;
        FingerprintVersion = fingerprintVersion;
        Diagnostics = diagnostics;
        Artifacts = artifacts;
    }

    public RdCoreCapabilityCode Code { get; }

    public string FingerprintVersion { get; }

    public IReadOnlyList<RdCoreDiagnostic> Diagnostics { get; }

    public RdCorePackageArtifacts? Artifacts { get; }

    public bool IsCompatible =>
        Code == RdCoreCapabilityCode.Compatible && Artifacts is not null;

    public override string ToString() =>
        $"RDCore compatibility: {Code}; fingerprint={FingerprintVersion}; " +
        $"diagnostics={Diagnostics.Count}";
}
