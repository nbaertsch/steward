using Steward.Domain;
using Steward.Maintenance.Windows;

namespace Steward.Orchestration;

public interface ILocalMaintenanceForwarder
{
    Task<MaintenanceResponse> ForwardAsync(
        AuthenticatedMaintenanceRequest request,
        CancellationToken cancellationToken);
}

public sealed class NodeMaintenanceCommandHandler
{
    private readonly HostId hostId;
    private readonly NodeIncarnationId nodeIncarnationId;
    private readonly ILocalMaintenanceForwarder forwarder;

    public NodeMaintenanceCommandHandler(
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        ILocalMaintenanceForwarder forwarder)
    {
        if (hostId == default || nodeIncarnationId == default)
            throw new ArgumentException(
                "Node maintenance identity is invalid.");
        this.hostId = hostId;
        this.nodeIncarnationId = nodeIncarnationId;
        this.forwarder = forwarder ??
            throw new ArgumentNullException(nameof(forwarder));
    }

    public async Task<LocalMaintenanceResultFact> HandleAsync(
        LocalMaintenanceRequestMessage message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.Version != 1 ||
            message.HostId != hostId ||
            message.NodeIncarnationId != nodeIncarnationId)
            throw new OrchestrationMessageException(
                "Local maintenance request targets another Node identity.");
        MaintenanceContract.Validate(message.Request.Body);
        var key = MaintenanceDeliveryKey.Create(message.Request.Body);
        var response = await forwarder.ForwardAsync(
                message.Request,
                cancellationToken)
            .ConfigureAwait(false); if (response.ProtocolVersion != MaintenanceContract.ProtocolVersion ||
            response.RequestId != key.RequestId ||
            response.OperationId != key.OperationId ||
            response.OperationDigest != key.OperationDigest ||
            !Enum.IsDefined(response.Status))
            throw new OrchestrationMessageException(
                "Local maintenance response identity does not match its request.");
        return new LocalMaintenanceResultFact(
            1,
            hostId,
            nodeIncarnationId,
            response);
    }
}
