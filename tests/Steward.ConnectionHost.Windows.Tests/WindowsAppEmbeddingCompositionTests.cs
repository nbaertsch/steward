using Steward.ConnectionHost.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class WindowsAppEmbeddingCompositionTests
{
    [Fact]
    public void Per_connection_embedding_path_reaches_child_process_environment()
    {
        var first = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "embedding",
            Guid.NewGuid().ToString("N"),
            "connection.json"));
        var second = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "embedding",
            Guid.NewGuid().ToString("N"),
            "connection.json"));

        var firstEnvironment =
            WindowsAppIsolatedConnectionLease.BuildChildEnvironmentValues(
                first);
        var secondEnvironment =
            WindowsAppIsolatedConnectionLease.BuildChildEnvironmentValues(
                second);

        Assert.Equal(
            first,
            firstEnvironment[
                RdpDvcEmbeddingConfigurationStore
                    .ConfigurationPathEnvironmentVariable]);
        Assert.Equal(
            second,
            secondEnvironment[
                RdpDvcEmbeddingConfigurationStore
                    .ConfigurationPathEnvironmentVariable]);
        Assert.NotEqual(
            firstEnvironment[
                RdpDvcEmbeddingConfigurationStore
                    .ConfigurationPathEnvironmentVariable],
            secondEnvironment[
                RdpDvcEmbeddingConfigurationStore
                    .ConfigurationPathEnvironmentVariable]);
        Assert.EndsWith(
            "Steward.WindowsApp.RdCoreHook.dll",
            firstEnvironment["DOTNET_STARTUP_HOOKS"],
            StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(
            "Steward.RdpDvc.Client.Windows.dll",
            firstEnvironment["STEWARD_RDCORE_MANAGED_PLUGIN_PATH"],
            StringComparison.OrdinalIgnoreCase);
    }
}
