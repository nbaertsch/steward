using Steward.Transport.Rdp.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

[Collection("RdpDvcEmbeddingConfiguration")]
public sealed class RdpDvcEmbeddingConfigurationTests : IDisposable
{
    private readonly string root = Path.Combine(
        AppContext.BaseDirectory,
        "embedding-configuration",
        Guid.NewGuid().ToString("N"));
    private readonly string? previousPath =
        Environment.GetEnvironmentVariable(
            RdpDvcEmbeddingConfigurationStore
                .ConfigurationPathEnvironmentVariable);

    [Fact]
    public void Configured_path_is_used_for_process_isolation()
    {
        Directory.CreateDirectory(root);
        var key = Path.Combine(root, "evidence.key");
        File.WriteAllBytes(key, new byte[32]);
        var configuration = Path.Combine(
            root,
            "node-b1",
            "embedding.json");
        Environment.SetEnvironmentVariable(
            RdpDvcEmbeddingConfigurationStore
                .ConfigurationPathEnvironmentVariable,
            configuration);

        RdpDvcEmbeddingConfigurationStore.Write(
            "Steward.Evidence.b1",
            key);

        Assert.Equal(
            Path.GetFullPath(configuration),
            RdpDvcEmbeddingConfigurationStore.CurrentPath);
        Assert.Equal(
            "Steward.Evidence.b1",
            RdpDvcEmbeddingConfigurationStore.Load().EvidencePipeName);
        Assert.True(File.Exists(configuration));
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(
            RdpDvcEmbeddingConfigurationStore
                .ConfigurationPathEnvironmentVariable,
            previousPath);
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }
}

[CollectionDefinition(
    "RdpDvcEmbeddingConfiguration",
    DisableParallelization = true)]
public sealed class RdpDvcEmbeddingConfigurationCollection;
