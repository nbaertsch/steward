using System.IO.Pipes;
using System.Reflection;
using System.Security.Cryptography;
using Steward.RdpDvc.Client.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

[Collection("RdpDvcEmbeddingConfiguration")]
public sealed class StartupHookContractTests
{
    [Fact]
    public async Task Startup_hook_reflection_contract_activates_public_embedded_host()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "startup-hook-contract",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        byte[]? key = null;
        var prior = Environment.GetEnvironmentVariable(
            RdpDvcEmbeddingConfigurationStore
                .ConfigurationPathEnvironmentVariable);
        try
        {
            key = RandomNumberGenerator.GetBytes(32);
            var keyPath = Path.Combine(root, "evidence.key");
            CurrentUserProtectedDataFile.Write(
                keyPath,
                AuthenticatedRdpDvcEvidencePublisher.KeyFilePurpose,
                key);
            var configurationPath = Path.Combine(root, "embedding.json");
            Environment.SetEnvironmentVariable(
                RdpDvcEmbeddingConfigurationStore
                    .ConfigurationPathEnvironmentVariable,
                configurationPath);
            var evidencePipe = "Steward.Hook.Evidence." +
                Guid.NewGuid().ToString("N");
            RdpDvcEmbeddingConfigurationStore.Write(
                "Steward.Hook.Broker." + Guid.NewGuid().ToString("N"),
                evidencePipe,
                keyPath);
            await using var evidence = new NamedPipeServerStream(
                evidencePipe,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            var receiving = Task.Run(async () =>
            {
                await evidence.WaitForConnectionAsync();
                var frame = await RdpDvcEvidenceIpcProtocol.ReadFrameAsync(
                    evidence,
                    CancellationToken.None);
                var publication = RdpDvcEvidenceIpcProtocol.Decode(frame, key);
                await evidence.WriteAsync(new byte[] { 1 });
                return publication;
            });
            var hostAssembly = typeof(ClientDvcBroker).Assembly;
            var hostType = hostAssembly.GetType(
                "Steward.RdpDvc.Client.Windows.EmbeddedDvcPluginHost",
                throwOnError: true)!;
            var activation = hostType.GetMethod(
                "Start",
                BindingFlags.Static | BindingFlags.Public);

            var plugin = await Task.Run(() => activation!.Invoke(null, null));
            var publication = await receiving.WaitAsync(
                TimeSpan.FromSeconds(5));

            Assert.True(hostType.IsPublic);
            Assert.NotNull(activation);
            Assert.IsAssignableFrom<IEmbeddedDvcPlugin>(plugin);
            Assert.Equal(
                RdpDvcEvidencePublicationEvent.StewardComClassActivated,
                publication.Event);
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                RdpDvcEmbeddingConfigurationStore
                    .ConfigurationPathEnvironmentVariable,
                prior);
            if (key is not null)
                CryptographicOperations.ZeroMemory(key);
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }
}