namespace Steward.Transport;

public interface ITransportConnectionAcceptor : IAsyncDisposable
{
    ValueTask<ITransportConnection> AcceptAsync(
        SessionHello hello,
        CancellationToken cancellationToken = default);
}

public interface ITransportDeploymentStatus
{
    bool Enabled { get; }
    int ConfiguredEndpointCount { get; }
    string ImplementationKind { get; }
}
