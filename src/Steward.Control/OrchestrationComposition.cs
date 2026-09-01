using Steward.Agents;
using Steward.Application;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;
using Steward.PortableState;
using Steward.Providers.Abstractions;
using Steward.Scheduling;

namespace Steward.Control;

public sealed class ControlHostOrchestrationOptions
{
    public bool Enabled { get; set; } = true;
    public string SchedulerDatabasePath { get; set; } = string.Empty;
    public string GlobalRateDatabasePath { get; set; } = string.Empty;

    public ValidatedControlOrchestrationOptions Validate(string controlDatabasePath) =>
        new(
            Enabled,
            FullPathOrDefault(
                SchedulerDatabasePath,
                $"{controlDatabasePath}.scheduler.db",
                nameof(SchedulerDatabasePath)),
            FullPathOrDefault(
                GlobalRateDatabasePath,
                $"{controlDatabasePath}.rates.db",
                nameof(GlobalRateDatabasePath)));

    private static string FullPathOrDefault(
        string value,
        string fallback,
        string name)
    {
        var selected = string.IsNullOrWhiteSpace(value) ? fallback : value;
        if (!Path.IsPathFullyQualified(selected))
            throw new InvalidOperationException(
                $"Control orchestration {name} must be fully qualified.");
        return Path.GetFullPath(selected);
    }
}

public sealed record ValidatedControlOrchestrationOptions(
    bool Enabled,
    string SchedulerDatabasePath,
    string GlobalRateDatabasePath);

public static class OrchestrationComposition
{
    public static IServiceCollection AddStewardOrchestration(
        this IServiceCollection services,
        IConfiguration configuration,
        string controlDatabasePath)
    {
        var configured = new ControlHostOrchestrationOptions();
        configuration.GetSection("Control:Orchestration").Bind(configured);
        var options = configured.Validate(controlDatabasePath);
        services.AddSingleton(options);
        services.AddSingleton<ISchedulerStateStore>(_ =>
            new SqliteSchedulerStateStore(options.SchedulerDatabasePath));
        services.AddSingleton<IGlobalRateStateStore>(_ =>
            new SqliteGlobalRateStateStore(options.GlobalRateDatabasePath));
        services.AddSingleton<GlobalRateAllocator>();
        services.AddSingleton<IPoolStateStore>(_ =>
            new SqlitePoolStateStore(options.SchedulerDatabasePath));
        services.AddSingleton<PoolCoordinator>();
        services.AddSingleton<HostPoolApplicationService>();
        services.AddSingleton<IHostPoolDemandReconciler>(provider =>
            provider.GetRequiredService<HostPoolApplicationService>());
        services.AddSingleton(provider =>
            new CompositeScheduler(
                provider.GetRequiredService<ISchedulerStateStore>(),
                provider.GetRequiredService<GlobalRateAllocator>()));
        services.AddSingleton(provider =>
        {
            var catalog = provider.GetService<IControlIdentityGrantCatalog>();
            return new ControlOrchestrator(
                provider.GetRequiredService<SqliteControlStore>(),
                provider.GetRequiredService<CompositeScheduler>(),
                provider.GetRequiredService<ISchedulerStateStore>(),
                new(
                    new(100, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5),
                        1024L * 1024 * 1024, 16),
                    IdentityGrantDispatchEnabled: catalog is not null),
                identityGrants: catalog,
                rateAllocator: provider.GetRequiredService<GlobalRateAllocator>());
        });
        services.AddSingleton<ControlNodeRegistrationStore>();
        services.AddSingleton<ControlNodeLivenessRegistry>();
        services.AddSingleton<ControlTerminalRouter>();
        services.AddSingleton<ControlTerminalRevocationStore>();

        var terminalOptions = new TerminalPolicyOptions();
        configuration.GetSection("Control:Terminal").Bind(terminalOptions);
        services.AddSingleton(terminalOptions.Validate());
        services.AddSingleton<ILocalActorContext, LocalOsActorContext>();
        services.AddSingleton<TerminalApplicationService>();
        services.AddSingleton<TerminalPolicyStatusService>();
        services.AddSingleton<OperationsApplicationService>();
        services.AddSingleton<OrchestrationDoctorService>();

        services.AddSingleton(new WorkloadPlanFactoryRegistry(
        [
            new EvaluationWorkloadPlanFactory("harbor"),
            new EvaluationWorkloadPlanFactory("saber"),
            new GeneralTaskWorkloadPlanFactory("process", compose: false),
            new GeneralTaskWorkloadPlanFactory("compose", compose: true),
            new AgentTurnWorkloadPlanFactory()
        ]));
        services.AddSingleton(provider =>
            new ExecutableWorkloadApplicationService(
                provider.GetRequiredService<ControlOrchestrator>(),
                provider.GetRequiredService<ControlNodeRegistrationStore>(),
                provider.GetRequiredService<WorkloadPlanFactoryRegistry>(),
                provider.GetRequiredService<HostPoolApplicationService>(),
                message => provider
                    .GetRequiredService<
                        ILogger<ExecutableWorkloadApplicationService>>()
                    .LogError(
                        "Executable Workload capacity reconciliation failed: {Code}",
                        message),
                provider.GetRequiredService<ControlNodeLivenessRegistry>()));

        var agentOptions = new AgentExecutionOptions();
        configuration.GetSection("Control:Agents").Bind(agentOptions);
        var validatedAgents = agentOptions.Validate();
        services.AddSingleton(validatedAgents);
        if (validatedAgents.Enabled)
        {
            services.AddSingleton<OrchestrationAgentTaskDispatcher>();
            services.AddSingleton<IAgentTaskDispatcher>(provider =>
                provider.GetRequiredService<OrchestrationAgentTaskDispatcher>());
            services.AddSingleton<IOrchestrationAgentEventSource>(provider =>
                provider.GetRequiredService<OrchestrationAgentTaskDispatcher>());
            services.AddSingleton<IAgentRuntime, ManagedRemoteAgentRuntime>();
        }

        services.AddSingleton(_ =>
            new SqliteAgentStore($"{controlDatabasePath}.agents.db"));
        services.AddSingleton<IAgentStore>(provider =>
            provider.GetRequiredService<SqliteAgentStore>());
        if (validatedAgents.Enabled)
        {
            services.AddSingleton<StewardAgentService>();
            services.AddHostedService<AgentTurnBackgroundWorker>();
        }
        services.AddSingleton(provider => new AgentApplicationService(
            provider.GetRequiredService<IAgentStore>(),
            provider.GetService<StewardAgentService>(),
            provider.GetService<AgentMigrationOrchestrator>()));

        if (services.Any(x => x.ServiceType == typeof(IPortableObjectStore)))
            services.AddSingleton<ControlPortableDownloadService>();

        services.AddHostedService<ControlOrchestrationInitializer>();
        services.AddHostedService<ControlSchedulingReconciler>();
        return services;
    }
}

public sealed class ControlOrchestrationInitializer(
    ControlOrchestrator orchestrator) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) =>
        orchestrator.InitializeAsync(cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
public sealed class ControlSchedulingReconciler(
    ControlOrchestrator orchestrator,
    IHostPoolDemandReconciler hostPools,
    ILogger<ControlSchedulingReconciler> logger) : BackgroundService
{
    private static readonly TimeSpan RepairInterval =
        TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(RepairInterval);
        do
        {
            try
            {
                var now = DateTimeOffset.UtcNow;
                var repair = await orchestrator.RepairSchedulingAsync(
                        now,
                        stoppingToken)
                    .ConfigureAwait(false);
                foreach (var pool in repair.PoolDemands)
                    _ = await hostPools.ReconcileAsync(
                            pool.PoolId,
                            pool.Demands,
                            now,
                            stoppingToken)
                        .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
                when (exception is
                    Microsoft.Data.Sqlite.SqliteException or
                    IOException)
            {
                logger.LogWarning(
                    "Scheduling repair deferred after transient {Type} " +
                    "with HRESULT 0x{HResult:X8}.",
                    exception.GetType().Name,
                    exception.HResult);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken)
                   .ConfigureAwait(false));
    }
}
