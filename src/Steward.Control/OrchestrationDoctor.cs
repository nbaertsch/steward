using Microsoft.Extensions.DependencyInjection;
using Steward.Orchestration;
using Steward.Scheduling;
using Steward.Transport;

namespace Steward.Control;

public sealed record OrchestrationCapabilityStatus(
    bool TransportEnabled,
    int ConfiguredNodes,
    bool DurableSchedulerReady,
    bool DurableRatesReady,
    bool DurablePoolReady,
    bool IdentityDeliveryEnabled,
    bool ProviderLifecycleEnabled,
    bool PortableStateConfiguredOnControl,
    bool AgentExecutionAdapterEnabled,
    IReadOnlyList<string> UnavailableCapabilities);

public sealed class OrchestrationDoctorService(
    ValidatedControlOrchestrationOptions options,
    ISchedulerStateStore schedulerStore,
    IGlobalRateStateStore rateStore,
    Steward.Providers.Abstractions.IPoolStateStore poolStore,
    Steward.Application.IHostProviderRegistry providers,
    IServiceProvider services)
{
    public OrchestrationCapabilityStatus Check()
    {
        var unavailable = new List<string>();
        if (!options.Enabled) unavailable.Add("remote-orchestration");
        var transport = services.GetService<ITransportDeploymentStatus>();
        var identity = services.GetService<IControlIdentityGrantCatalog>() is not null;
        if (transport?.Enabled != true) unavailable.Add("transport");
        if (!identity) unavailable.Add("identity-grant-dispatch");
        if (providers.AvailableProviders.Count == 0)
            unavailable.Add("provider-lifecycle");
        if (services.GetService<Steward.Application.IProvisionedNodeEnrollmentWorkflow>() is null)
            unavailable.Add("provider-bootstrap-enrollment");
        if (services.GetService<Steward.Application.IHostRecreateService>() is null)
            unavailable.Add("provider-recreate");
        var agentExecution = services.GetService<Steward.Agents.StewardAgentService>() is not null;
        var portable = services.GetService<ControlPortableDownloadService>() is not null;
        if (!agentExecution) unavailable.Add("agent-execution-adapter");
        if (!portable) unavailable.Add("control-portable-download");
        return new(
            transport?.Enabled == true,
            transport?.ConfiguredEndpointCount ?? 0,
            schedulerStore is SqliteSchedulerStateStore,
            rateStore is SqliteGlobalRateStateStore,
            poolStore is SqlitePoolStateStore,
            identity,
            providers.AvailableProviders.Count > 0,
            portable,
            agentExecution,
            unavailable);
    }
}
