using Steward.Transport;

namespace Steward.Stack.Local;

public sealed class LocalTransportDeploymentStatus(
    ValidatedLocalStackOptions options) : ITransportDeploymentStatus
{
    public bool Enabled => options.TransportEnabled;
    public int ConfiguredEndpointCount => options.Nodes.Count;
    public string ImplementationKind => LocalStackOptions.TransportKind;
}
