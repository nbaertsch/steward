namespace Steward.RdCore.Windows.Tests;

public sealed class RdCoreProcessIdentityTests
{
    [Fact]
    public void Test_process_is_not_package_identified()
    {
        Assert.False(RdCoreProcessIdentity.HasPackageIdentity());
    }
}
