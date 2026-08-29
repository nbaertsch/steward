using System.Runtime.InteropServices;
using Windows.ApplicationModel;
using Windows.Management.Deployment;
using Windows.System;

namespace Steward.RdCore.Windows;

internal sealed record AppxPackageCandidate(
    string Name,
    string FullName,
    string FamilyName,
    string Publisher,
    string PublisherId,
    Version Version,
    Architecture? Architecture,
    string InstalledPath,
    bool IsHealthy,
    bool IsMainPackage);

internal interface IAppxPackageSource
{
    IReadOnlyList<AppxPackageCandidate> FindWindows365Candidates();
}

internal sealed class WindowsAppxPackageSource : IAppxPackageSource
{
    public IReadOnlyList<AppxPackageCandidate> FindWindows365Candidates()
    {
        var manager = new PackageManager();
        return manager.FindPackagesForUser(string.Empty)
            .Where(package =>
                string.Equals(
                    package.Id.Name,
                    Windows365PackageLocator.PackageName,
                    StringComparison.Ordinal) ||
                string.Equals(
                    package.Id.FamilyName,
                    Windows365PackageLocator.PackageFamilyName,
                    StringComparison.Ordinal))
            .Select(ToCandidate)
            .ToArray();
    }

    private static AppxPackageCandidate ToCandidate(Package package)
    {
        var version = package.Id.Version;
        return new(
            package.Id.Name,
            package.Id.FullName,
            package.Id.FamilyName,
            package.Id.Publisher,
            package.Id.PublisherId,
            new Version(
                version.Major,
                version.Minor,
                version.Build,
                version.Revision),
            ToRuntimeArchitecture(package.Id.Architecture),
            package.InstalledPath,
            package.Status.VerifyIsOK(),
            !package.IsFramework && !package.IsResourcePackage);
    }

    private static Architecture? ToRuntimeArchitecture(
        ProcessorArchitecture architecture) =>
        architecture switch
        {
            ProcessorArchitecture.X86 => Architecture.X86,
            ProcessorArchitecture.X64 => Architecture.X64,
            ProcessorArchitecture.Arm => Architecture.Arm,
            ProcessorArchitecture.Arm64 => Architecture.Arm64,
            ProcessorArchitecture.Neutral => null,
            _ => (Architecture)(-1)
        };
}

internal sealed record PackageLocationResult(
    RdCoreCapabilityCode Code,
    AppxPackageCandidate? Package,
    string Description);

internal sealed class Windows365PackageLocator
{
    internal const string PackageName = "MicrosoftCorporationII.Windows365";
    internal const string PackageFamilyName =
        "MicrosoftCorporationII.Windows365_8wekyb3d8bbwe";
    internal const string Publisher =
        "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, " +
        "S=Washington, C=US";
    internal const string PublisherId = "8wekyb3d8bbwe";

    private readonly IAppxPackageSource source;

    public Windows365PackageLocator(IAppxPackageSource source)
    {
        this.source = source;
    }

    public PackageLocationResult Locate()
    {
        var candidates = source.FindWindows365Candidates();
        if (candidates.Count == 0)
        {
            return new(
                RdCoreCapabilityCode.PackageNotFound,
                null,
                "The Windows 365 package is not installed for the current user.");
        }

        var exact = candidates.Where(IsExpectedIdentity).ToArray();
        if (exact.Length == 0)
        {
            return new(
                RdCoreCapabilityCode.PackageIdentityMismatch,
                null,
                "An installed package used the Windows 365 name but not its " +
                "required Microsoft identity.");
        }

        var healthy = exact
            .Where(candidate => candidate.IsHealthy && candidate.IsMainPackage)
            .OrderByDescending(candidate => candidate.Version)
            .FirstOrDefault();
        if (healthy is null)
        {
            return new(
                RdCoreCapabilityCode.PackageUnhealthy,
                null,
                "No healthy installed main Windows 365 package was found.");
        }

        if (healthy.Architecture is not null &&
            healthy.Architecture != RuntimeInformation.ProcessArchitecture)
        {
            return new(
                RdCoreCapabilityCode.UnsupportedArchitecture,
                null,
                "The installed Windows 365 package architecture does not match " +
                "the Steward process.");
        }

        return new(
            RdCoreCapabilityCode.Compatible,
            healthy,
            "The expected healthy Windows 365 package was found.");
    }

    private static bool IsExpectedIdentity(AppxPackageCandidate candidate) =>
        string.Equals(candidate.Name, PackageName, StringComparison.Ordinal) &&
        string.Equals(
            candidate.FamilyName,
            PackageFamilyName,
            StringComparison.Ordinal) &&
        string.Equals(candidate.Publisher, Publisher, StringComparison.Ordinal) &&
        string.Equals(
            candidate.PublisherId,
            PublisherId,
            StringComparison.Ordinal);
}
