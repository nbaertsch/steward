using System.Security.Cryptography;
using System.Text;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public sealed record RdpDvcPerConnectionConfiguration(
    string Directory,
    string BrokerNamespace,
    string EvidencePipeName,
    string EvidenceKeyFile)
{
    public RdpDvcPerConnectionRoute Create(
        string connectionId,
        Action<string>? diagnosticSink = null)
    {
        var route = RdpDvcPerConnectionRoute.Create(
            Directory,
            BrokerNamespace,
            connectionId);
        diagnosticSink?.Invoke("windows-app-route-derived");
        RdpDvcEmbeddingConfigurationStore.Write(
            route.ConfigurationPath,
            route.BrokerPipeName,
            EvidencePipeName,
            EvidenceKeyFile,
            diagnosticSink);
        diagnosticSink?.Invoke("windows-app-route-written");
        return route;
    }
}

public sealed record RdpDvcPerConnectionRoute(
    string BrokerPipeName,
    string ConfigurationPath)
{
    public static RdpDvcPerConnectionRoute Create(
        string directory,
        string brokerNamespace,
        string connectionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(brokerNamespace);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionId);
        if (!Path.IsPathFullyQualified(directory))
            throw new ArgumentException(
                "The DVC configuration directory must be absolute.",
                nameof(directory));
        var digest = Convert.ToHexStringLower(
            SHA256.HashData(
                Encoding.UTF8.GetBytes(
                    brokerNamespace + "\n" + connectionId)));
        return new(
            "Steward.RdpDvc." + digest[..32],
            Path.Combine(
                Path.GetFullPath(directory),
                "embedding." + digest + ".json"));
    }
}
