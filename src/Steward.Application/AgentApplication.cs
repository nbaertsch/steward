using Steward.Agents;
using Steward.Domain;
using Steward.PortableState;

namespace Steward.Application;

public sealed record CreateAgentRequest(
    StewardAgentId? AgentId = null,
    string? ParentRoute = null);
public sealed record SubmitAgentTurnRequest(
    string Text,
    TextProvenance Provenance = TextProvenance.User,
    string? ClientRequestId = null,
    AgentTurnId? TurnId = null);
public sealed record AgentMigrationRequest(
    HostId SourceHostId,
    HostId DestinationHostId,
    GitArtifact GitBundle,
    GitArtifact DirtyPatch,
    AgentEnvironmentManifest Environment,
    IReadOnlyList<PortableObjectId> Lineage);

public sealed class AgentApplicationService
{
    private readonly IAgentStore store;
    private readonly StewardAgentService? service;
    private readonly AgentMigrationOrchestrator? migration;

    public AgentApplicationService(
        IAgentStore store,
        StewardAgentService? service = null,
        AgentMigrationOrchestrator? migration = null)
    {
        this.store = store;
        this.service = service;
        this.migration = migration;
    }

    public Task<AgentDescriptor> CreateAsync(
        CreateAgentRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.ParentRoute?.Length > 512)
            throw new ApplicationContractException("InvalidArgument", "Agent parent route exceeds its bound.");
        var id = request.AgentId ?? StewardAgentId.New();
        return service is null
            ? store.CreateAsync(id, new("orchestration-managed", "1.0"), request.ParentRoute, cancellationToken)
            : service.CreateAsync(id, request.ParentRoute, cancellationToken);
    }

    public Task<AgentDescriptor?> GetAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default) =>
        store.GetAsync(agentId, cancellationToken);

    public Task<AgentTurnRecord> SubmitTurnAsync(
        StewardAgentId agentId,
        SubmitAgentTurnRequest request,
        CancellationToken cancellationToken = default)
    {
        AgentLimits.Text(request.Text, AgentLimits.MaximumTurnBytes, nameof(request.Text));
        var turn = new AgentTurnRequest(
            request.TurnId ?? AgentTurnId.New(), request.Text, request.Provenance, request.ClientRequestId);
        return service is null
            ? store.SubmitTurnAsync(agentId, turn, cancellationToken)
            : service.SubmitAsync(agentId, turn, cancellationToken);
    }

    public Task<bool> CancelTurnAsync(
        StewardAgentId agentId,
        AgentTurnId turnId,
        CancellationToken cancellationToken = default) =>
        service is null
            ? store.CancelAsync(agentId, turnId, cancellationToken)
            : service.CancelAsync(agentId, turnId, cancellationToken);

    public Task<bool> ProcessNextAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken = default)
    {
        if (service is null)
            throw new ApplicationContractException(
                Steward.Contracts.ProblemCodes.CapabilityUnavailable,
                "Managed Agent execution is explicitly disabled because no Agent runtime adapter is configured.",
                Steward.Contracts.ProblemDisposition.Terminal);
        return service.RunNextAsync(agentId, cancellationToken: cancellationToken);
    }

    public Task<IReadOnlyList<AgentNotification>> ReadNotificationsAsync(
        StewardAgentId agentId,
        long afterSequence,
        int maximumCount,
        CancellationToken cancellationToken = default)
    {
        if (afterSequence < 0 || maximumCount is <= 0 or > 100)
            throw new ApplicationContractException(
                "InvalidArgument", "Agent notification cursor or limit is invalid.");
        return store.ReadAsync(agentId, afterSequence, maximumCount, cancellationToken);
    }

    public Task AcknowledgeNotificationsAsync(
        StewardAgentId agentId,
        long throughSequence,
        CancellationToken cancellationToken = default) =>
        store.AcknowledgeAsync(agentId, throughSequence, cancellationToken);

    public Task<MigrationHandoffRecord?> MigrateAsync(
        StewardAgentId agentId,
        AgentMigrationRequest request,
        CancellationToken cancellationToken = default)
    {
        if (migration is null)
            throw new ApplicationContractException(
                "PortableAgentMigrationUnavailable",
                "Agent migration is explicitly disabled because no portable migration transport is configured.",
                Steward.Contracts.ProblemDisposition.Terminal);
        return migration.MigrateAsync(
            agentId, request.SourceHostId, request.DestinationHostId,
            request.GitBundle, request.DirtyPatch, request.Environment,
            request.Lineage, cancellationToken: cancellationToken);
    }
}
