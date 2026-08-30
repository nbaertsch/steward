namespace Steward.RdCore.Windows.Tests;

public sealed class LiveCompatibilityTests
{
    [Fact]
    public void Installed_windows_app_is_compatible_when_explicitly_enabled()
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable(
                    "STEWARD_RDCORE_LIVE_TESTS"),
                "1",
                StringComparison.Ordinal))
        {
            return;
        }

        var result = new RdCoreCompatibilityProbe().Inspect();

        Assert.True(
            result.IsCompatible,
            result + Environment.NewLine +
            string.Join(
                Environment.NewLine,
                result.Diagnostics.Select(diagnostic =>
                    $"{diagnostic}: {diagnostic.Description}")));
        using var loader = CollectibleRdCoreAssemblyLoader.Create(result);
        Assert.False(loader.IsCollectible);
    }
}
