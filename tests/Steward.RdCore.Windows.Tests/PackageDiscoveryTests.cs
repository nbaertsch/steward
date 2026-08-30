using System.Runtime.InteropServices;

namespace Steward.RdCore.Windows.Tests;

public sealed class PackageDiscoveryTests
{
    [Fact]
    public void Locator_selects_highest_healthy_exact_package()
    {
        var older = Candidate(new Version(2, 0, 100, 0), healthy: true);
        var newer = Candidate(new Version(2, 0, 200, 0), healthy: true);
        var locator = new Windows365PackageLocator(
            new StubPackageSource(older, newer));

        var result = locator.Locate();

        Assert.Equal(RdCoreCapabilityCode.Compatible, result.Code);
        Assert.Equal(newer, result.Package);
    }

    [Fact]
    public void Locator_rejects_spoofed_publisher()
    {
        var spoofed = Candidate(new Version(2, 0, 200, 0), healthy: true) with
        {
            Publisher = "CN=Not Microsoft"
        };
        var locator = new Windows365PackageLocator(
            new StubPackageSource(spoofed));

        var result = locator.Locate();

        Assert.Equal(RdCoreCapabilityCode.PackageIdentityMismatch, result.Code);
        Assert.Null(result.Package);
    }

    [Fact]
    public void Locator_requires_healthy_main_package()
    {
        var unhealthy = Candidate(new Version(2, 0, 200, 0), healthy: false);
        var locator = new Windows365PackageLocator(
            new StubPackageSource(unhealthy));

        var result = locator.Locate();

        Assert.Equal(RdCoreCapabilityCode.PackageUnhealthy, result.Code);
        Assert.Null(result.Package);
    }

    internal static AppxPackageCandidate Candidate(
        Version version,
        bool healthy,
        string installedPath = @"C:\Program Files\WindowsApps\fixture") =>
        new(
            Windows365PackageLocator.PackageName,
            Windows365PackageLocator.PackageName + "_" + version + "_x64__" +
            Windows365PackageLocator.PublisherId,
            Windows365PackageLocator.PackageFamilyName,
            Windows365PackageLocator.Publisher,
            Windows365PackageLocator.PublisherId,
            version,
            RuntimeInformation.ProcessArchitecture,
            installedPath,
            healthy,
            IsMainPackage: true);

    internal sealed class StubPackageSource(
        params AppxPackageCandidate[] candidates) : IAppxPackageSource
    {
        public IReadOnlyList<AppxPackageCandidate> FindWindows365Candidates() =>
            candidates;
    }
}
