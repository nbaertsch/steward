using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.Client.Windows;

public interface IEmbeddedDvcPlugin;

public static class EmbeddedDvcPluginHost
{
    private static readonly object Sync = new();
    private static AuthenticatedRdpDvcEvidencePublisher? publisher;
    private static ClientDvcBroker? broker;
    private static StewardDvcPlugin? plugin;

    public static IEmbeddedDvcPlugin Start()
    {
        lock (Sync)
        {
            if (plugin is not null)
                return plugin;
            var configuration =
                RdpDvcEmbeddingConfigurationStore.Load();
            Action<string> log = message => File.AppendAllText(
                configuration.DiagnosticLogFile,
                $"StewardDVC {DateTimeOffset.UtcNow:O} {message}{Environment.NewLine}");
            publisher =
                AuthenticatedRdpDvcEvidencePublisher.FromProtectedFile(
                    configuration.EvidencePipeName,
                    configuration.EvidenceKeyFile);
            broker = new ClientDvcBroker(
                log,
                configuration.BrokerPipeName);
            var evidence = publisher.CreateLifecycleSession();
            evidence.PublishAsync(
                    RdpDvcEvidencePublicationEvent
                        .StewardComClassActivated)
                .AsTask()
                .GetAwaiter()
                .GetResult();
            plugin = new StewardDvcPlugin(
                broker,
                evidence,
                log);
            log("EMBEDDED_PLUGIN_CREATED");
            return plugin;
        }
    }
}
