using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Agents;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;
using Steward.Providers.Abstractions;

namespace Steward.Application;

public sealed record PoolRegistration(PoolPolicy Policy, ProviderBinding Provider);
public sealed record HostView(
    HostId HostId,
    PoolId PoolId,
    NodeIncarnationId NodeIncarnationId,
    string ProviderResourceName,
    PoolMemberState State,
    bool Connected);
public sealed record ReconcilePoolRequest(
    IReadOnlyList<PoolDemand> Demands,
    DateTimeOffset? ObservedAt = null);
public sealed record ReconcileProviderOperationRequest(ProviderOperationHandle Handle);

public interface IHostProviderRegistry
{
    bool TryResolve(string provider, out IHostProvider value);
    IReadOnlyList<string> AvailableProviders { get; }
}

public interface IHostRecreateService
{
    Task<ProviderOperationResult> RecreateAsync(
        HostView host,
        PoolRegistration pool,
        bool force,
        CancellationToken cancellationToken);
}

public interface IProvisionedNodeEnrollmentWorkflow
{
    Task<NodeEndpointRegistration> BootstrapAndEnrollAsync(
        PoolRegistration pool,
        PoolMember member,
        ProviderResource resource,
        CancellationToken cancellationToken);
}

public interface IHostPoolDemandReconciler
{
    Task<PoolReconcileResult> ReconcileAsync(
        PoolId poolId,
        IReadOnlyList<PoolDemand> demands,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed class HostProviderRegistry(IEnumerable<KeyValuePair<string, IHostProvider>> providers)
    : IHostProviderRegistry
{
    private readonly IReadOnlyDictionary<string, IHostProvider> values =
        providers.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);

    public bool TryResolve(string provider, out IHostProvider value) =>
        values.TryGetValue(provider, out value!);
    public IReadOnlyList<string> AvailableProviders => values.Keys.Order(StringComparer.Ordinal).ToArray();
}

public sealed class HostPoolApplicationService(
    SqliteControlStore controlStore,
    IPoolStateStore poolStore,
    PoolCoordinator coordinator,
    IHostProviderRegistry providers,
    ControlNodeRegistrationStore nodes,
    SqliteAgentStore? agentStore = null,
    IHostRecreateService? recreateService = null,
    IProvisionedNodeEnrollmentWorkflow? enrollment = null) :
    IHostPoolDemandReconciler
{
    private readonly SqliteProviderOperationStore providerOperations =
        new(controlStore);

    public async Task RegisterPoolAsync(
        PoolRegistration registration,
        CancellationToken cancellationToken = default)
    {
        registration.Policy.Validate();
        ArgumentException.ThrowIfNullOrWhiteSpace(registration.Provider.Provider);
        var json = JsonSerializer.Serialize(registration, StewardJson.Options);
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS orchestration_pool_registrations(
                pool_id TEXT PRIMARY KEY,
                registration_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO orchestration_pool_registrations(pool_id,registration_json,updated_at)
            VALUES($pool,$json,$now)
            ON CONFLICT(pool_id) DO UPDATE SET
              registration_json=excluded.registration_json,updated_at=excluded.updated_at
            WHERE orchestration_pool_registrations.registration_json=excluded.registration_json;
            """;
        command.Parameters.AddWithValue("$pool", registration.Policy.PoolId.ToString());
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken) < 1)
            throw new ApplicationContractException(
                ProblemCodes.RevisionConflict, "Pool identity already has different immutable configuration.");
    }

    public async Task<IReadOnlyList<PoolRegistration>> ListPoolsAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT registration_json FROM orchestration_pool_registrations ORDER BY pool_id
            """;
        var result = new List<PoolRegistration>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(JsonSerializer.Deserialize<PoolRegistration>(
                reader.GetString(0), StewardJson.Options)
                ?? throw new InvalidDataException("Persisted Pool registration is invalid."));
        return result;
    }

    public async Task<IReadOnlyList<HostView>> ListHostsAsync(
        PoolId? poolId = null,
        CancellationToken cancellationToken = default)
    {
        var registrations = await nodes.ListAsync(cancellationToken);
        var pools = (await ListPoolsAsync(cancellationToken)).Select(x => x.Policy.PoolId).Distinct();
        var states = new Dictionary<HostId, PoolMember>();
        foreach (var pool in pools)
            foreach (var member in (await poolStore.LoadAsync(pool, cancellationToken)).Members)
                states[member.HostId] = member;
        return registrations
            .Where(x => poolId is null || x.PoolId == poolId)
            .Select(x =>
            {
                var member = states.GetValueOrDefault(x.HostId);
                return new HostView(
                    x.HostId, x.PoolId, x.NodeIncarnationId,
                    member?.ProviderResourceName ?? x.HostId.ToString(),
                    member?.State ?? PoolMemberState.Warm,
                    x.Enabled);
            }).ToArray();
    }

    public async Task<PoolReconcileResult> ReconcileAsync(
        PoolId poolId,
        IReadOnlyList<PoolDemand> demands,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        var registration = (await ListPoolsAsync(cancellationToken))
            .SingleOrDefault(x => x.Policy.PoolId == poolId)
            ?? throw new KeyNotFoundException("Pool is not registered.");
        if (!providers.TryResolve(registration.Provider.Provider, out var provider))
            throw new ApplicationContractException(
                ProblemCodes.CapabilityUnavailable,
                $"Provider '{registration.Provider.Provider}' is explicitly unavailable.",
                ProblemDisposition.Terminal);
        await ResumePendingProviderOperationsAsync(
            registration,
            provider,
            now,
            cancellationToken);
        var result = await coordinator.ReconcileAsync(
            registration.Policy,
            demands,
            now,
            () => new Host(HostId.New(), poolId, NodeIncarnationId.New()),
            cancellationToken: cancellationToken);
        foreach (var action in result.Actions)
        {
            var effect = new ProviderEffect(
                DeterministicOperation(action, registration.Provider),
                $"pool:{poolId}:{action.Kind}:{action.Host.Id}",
                registration.Provider,
                action.Host.Id.ToString(),
                action.Host.Id,
                action.Host.NodeIncarnationId);
            if (action.Kind == PoolActionKind.Assign)
                continue;
            await providerOperations.BeginAsync(
                poolId,
                action.Kind,
                effect,
                now,
                cancellationToken);
            var providerResult = action.Kind switch
            {
                PoolActionKind.Create => await provider.CreateAsync(effect, cancellationToken),
                PoolActionKind.Start => await provider.StartAsync(effect, cancellationToken),
                PoolActionKind.Drain => await ApplyDestructiveAsync(
                    provider, effect, ProviderCapability.Stop, force: false, cancellationToken),
                PoolActionKind.Delete => await ApplyDestructiveAsync(
                    provider, effect, ProviderCapability.Delete, force: false, cancellationToken),
                _ => throw new ArgumentOutOfRangeException()
            };
            await ApplyProviderOperationResultAsync(
                registration,
                action.Kind,
                effect,
                providerResult,
                now,
                cancellationToken);
        }
        return result;
    }

    private async Task ResumePendingProviderOperationsAsync(
        PoolRegistration registration,
        IHostProvider provider,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var pending = await providerOperations.ListAsync(
            registration.Policy.PoolId,
            cancellationToken);
        foreach (var operation in pending)
        {
            ProviderOperationResult result;
            if (operation.Handle is not null)
            {
                result = await provider.ReconcileAsync(
                    operation.Handle,
                    cancellationToken);
            }
            else if (operation.ActionKind is
                     PoolActionKind.Create or PoolActionKind.Delete)
            {
                var retry = operation.Effect with
                {
                    Attempt =
                        ProviderEffectAttempt
                            .RetryAfterUncertainOutcomeWithoutHandle
                };
                result = operation.ActionKind == PoolActionKind.Create
                    ? await provider.CreateAsync(retry, cancellationToken)
                    : await provider.DeleteAsync(retry, cancellationToken);
            }
            else
            {
                var resource = await provider.InspectAsync(
                    operation.Effect.Binding,
                    operation.Effect.ResourceName,
                    cancellationToken);
                var expected = operation.ActionKind switch
                {
                    PoolActionKind.Start => ProviderHostStatus.Running,
                    PoolActionKind.Drain => ProviderHostStatus.Stopped,
                    _ => ProviderHostStatus.Unknown
                };
                result = resource?.Status == expected
                    ? new(
                        ProviderOperationStatus.Succeeded,
                        null,
                        resource)
                    : new(
                        ProviderOperationStatus.RequiresReconciliation,
                        null,
                        resource,
                        "RequiresReconciliation",
                        "Provider effect outcome remains uncertain.");
            }
            await ApplyProviderOperationResultAsync(
                registration,
                operation.ActionKind,
                operation.Effect,
                result,
                now,
                cancellationToken);
        }
    }

    private async Task ApplyProviderOperationResultAsync(
        PoolRegistration registration,
        PoolActionKind actionKind,
        ProviderEffect effect,
        ProviderOperationResult result,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (result.Handle is not null)
            await providerOperations.AttachHandleAsync(
                effect.OperationId,
                result.Handle,
                now,
                cancellationToken);
        if (result.Status is
            ProviderOperationStatus.Accepted or
            ProviderOperationStatus.Running or
            ProviderOperationStatus.RequiresReconciliation)
            return;

        if (result.Status != ProviderOperationStatus.Succeeded)
        {
            await coordinator.UpdateMemberAsync(
                registration.Policy.PoolId,
                effect.HostId,
                PoolMemberState.Failed,
                now,
                cancellationToken);
            await providerOperations.CompleteAsync(
                effect.OperationId,
                cancellationToken);
            return;
        }

        var state = await poolStore.LoadAsync(
            registration.Policy.PoolId,
            cancellationToken);
        var member = state.Members.Single(
            x => x.HostId == effect.HostId);
        if (actionKind == PoolActionKind.Create)
        {
            if (result.Resource is null || enrollment is null)
                throw new ApplicationContractException(
                    ProblemCodes.CapabilityUnavailable,
                    "Created capacity cannot become ready because " +
                    "bootstrap enrollment is unavailable.",
                    ProblemDisposition.Terminal);
            var endpoint = await enrollment.BootstrapAndEnrollAsync(
                registration,
                member,
                result.Resource,
                cancellationToken);
            if (endpoint.HostId != effect.HostId ||
                endpoint.NodeIncarnationId != effect.IncarnationId)
                throw new InvalidDataException(
                    "Bootstrap enrollment returned another Host or " +
                    "Node incarnation.");
            await nodes.RegisterAsync(endpoint, cancellationToken);
        }

        var nextState = actionKind switch
        {
            PoolActionKind.Create or PoolActionKind.Start =>
                member.DemandId is null
                    ? PoolMemberState.Warm
                    : PoolMemberState.Assigned,
            PoolActionKind.Drain => PoolMemberState.Stopped,
            PoolActionKind.Delete => PoolMemberState.Deleted,
            _ => throw new ArgumentOutOfRangeException(nameof(actionKind))
        };
        await coordinator.UpdateMemberAsync(
            registration.Policy.PoolId,
            effect.HostId,
            nextState,
            now,
            cancellationToken);
        await providerOperations.CompleteAsync(
            effect.OperationId,
            cancellationToken);
    }

    public async Task<ProviderOperationResult> StartAsync(
        HostId hostId,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null) =>
        await ApplyAsync(
            hostId,
            ProviderCapability.Start,
            force: false,
            cancellationToken,
            expectedIncarnation);

    public async Task<HostView> DrainAsync(
        HostId hostId,
        bool force,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null)
    {
        var host = (await ListHostsAsync(cancellationToken: cancellationToken))
            .SingleOrDefault(x => x.HostId == hostId)
            ?? throw new KeyNotFoundException("Host is not registered.");
        EnsureIncarnation(host, expectedIncarnation);
        if (!force && await HasActiveWorkAsync(hostId, cancellationToken))
            throw new ApplicationContractException(
                ProblemCodes.LifecycleBlockedByActiveWork,
                "Host drain is blocked by active TaskAttempts.",
                ProblemDisposition.RequiresNewUserIntent);
        await coordinator.UpdateMemberAsync(
            host.PoolId, hostId, PoolMemberState.Draining, DateTimeOffset.UtcNow, cancellationToken);
        return host with { State = PoolMemberState.Draining };
    }

    public async Task<ProviderOperationResult> StopAsync(
        HostId hostId,
        bool force,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null) =>
        await ApplyAsync(
            hostId,
            ProviderCapability.Stop,
            force,
            cancellationToken,
            expectedIncarnation);

    public async Task<ProviderOperationResult> DeleteAsync(
        HostId hostId,
        bool force,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null) =>
        await ApplyAsync(
            hostId,
            ProviderCapability.Delete,
            force,
            cancellationToken,
            expectedIncarnation);

    public async Task<ProviderOperationResult> RecreateAsync(
        HostId hostId,
        bool force,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null)
    {
        var host = (await ListHostsAsync(cancellationToken: cancellationToken))
            .SingleOrDefault(x => x.HostId == hostId)
            ?? throw new KeyNotFoundException("Host is not registered.");
        EnsureIncarnation(host, expectedIncarnation);
        if (!force && await HasActiveWorkAsync(hostId, cancellationToken))
            throw new ApplicationContractException(
                ProblemCodes.LifecycleBlockedByActiveWork,
                "Host recreate is blocked by active work or incomplete portable state.");
        var pool = (await ListPoolsAsync(cancellationToken))
            .Single(x => x.Policy.PoolId == host.PoolId);
        if (recreateService is null)
        {
            var effect = await EffectAsync(
                hostId,
                ProviderCapability.Recreate,
                force,
                cancellationToken,
                expectedIncarnation);
            return ProviderOperationResult.CapabilityUnavailable(
                effect, ProviderCapability.Recreate,
                "Recreate is unavailable because no durable bootstrap/enrollment coordinator is configured.");
        }
        return await recreateService.RecreateAsync(host, pool, force, cancellationToken);
    }

    public async Task<ProviderResource?> InspectAsync(
        HostId hostId, CancellationToken cancellationToken = default)
    {
        var effect = await EffectAsync(hostId, ProviderCapability.Inspect, false, cancellationToken);
        if (!providers.TryResolve(effect.Binding.Provider, out var provider))
            throw new ApplicationContractException(
                ProblemCodes.CapabilityUnavailable, "The configured provider is unavailable.");
        return await provider.InspectAsync(
            effect.Binding, effect.ResourceName, cancellationToken);
    }

    public async Task<ProviderOperationResult> ReconcileOperationAsync(
        ReconcileProviderOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!providers.TryResolve(request.Handle.Provider, out var provider))
            throw new ApplicationContractException(
                ProblemCodes.CapabilityUnavailable, "The configured provider is unavailable.");
        return await provider.ReconcileAsync(request.Handle, cancellationToken);
    }

    private async Task<ProviderOperationResult> ApplyAsync(
        HostId hostId,
        ProviderCapability capability,
        bool force,
        CancellationToken cancellationToken,
        NodeIncarnationId? expectedIncarnation = null)
    {
        var effect = await EffectAsync(
            hostId,
            capability,
            force,
            cancellationToken,
            expectedIncarnation);
        if (!providers.TryResolve(effect.Binding.Provider, out var provider))
            return ProviderOperationResult.CapabilityUnavailable(
                effect, capability, "The configured provider is unavailable.");
        var result = capability switch
        {
            ProviderCapability.Start => await provider.StartAsync(effect, cancellationToken),
            ProviderCapability.Stop => await ApplyDestructiveAsync(
                provider, effect, capability, force, cancellationToken),
            ProviderCapability.Delete => await ApplyDestructiveAsync(
                provider, effect, capability, force, cancellationToken),
            _ => ProviderOperationResult.CapabilityUnavailable(
                effect, capability, "This lifecycle operation is unavailable.")
        };
        if (result.Status == ProviderOperationStatus.Succeeded)
            await coordinator.UpdateMemberAsync(
                (await ListHostsAsync(cancellationToken: cancellationToken))
                    .Single(x => x.HostId == hostId).PoolId,
                hostId,
                capability switch
                {
                    ProviderCapability.Start => PoolMemberState.Warm,
                    ProviderCapability.Stop => PoolMemberState.Stopped,
                    ProviderCapability.Delete => PoolMemberState.Deleted,
                    _ => PoolMemberState.Failed
                },
                DateTimeOffset.UtcNow,
                cancellationToken);
        return result;
    }

    private async Task<ProviderOperationResult> ApplyDestructiveAsync(
        IHostProvider provider,
        ProviderEffect effect,
        ProviderCapability capability,
        bool force,
        CancellationToken cancellationToken)
    {
        if (!force && await HasActiveWorkAsync(effect.HostId, cancellationToken))
            throw new ApplicationContractException(
                ProblemCodes.LifecycleBlockedByActiveWork,
                "Destructive Host lifecycle is blocked by active TaskAttempts.",
                ProblemDisposition.RequiresNewUserIntent);
        return capability == ProviderCapability.Delete
            ? await provider.DeleteAsync(effect, cancellationToken)
            : await provider.StopAsync(effect, cancellationToken);
    }

    private async Task<ProviderEffect> EffectAsync(
        HostId hostId,
        ProviderCapability capability,
        bool force,
        CancellationToken cancellationToken,
        NodeIncarnationId? expectedIncarnation = null)
    {
        var host = (await ListHostsAsync(cancellationToken: cancellationToken))
            .SingleOrDefault(x => x.HostId == hostId)
            ?? throw new KeyNotFoundException("Host is not registered.");
        EnsureIncarnation(host, expectedIncarnation);
        var pool = (await ListPoolsAsync(cancellationToken))
            .Single(x => x.Policy.PoolId == host.PoolId);
        return new(
            DeterministicOperation(hostId, capability),
            $"host:{hostId}:{capability}",
            pool.Provider,
            host.ProviderResourceName,
            host.HostId,
            host.NodeIncarnationId,
            new Dictionary<string, string> { ["force"] = force.ToString() });
    }

    private static void EnsureIncarnation(
        HostView host,
        NodeIncarnationId? expectedIncarnation)
    {
        if (expectedIncarnation is not null &&
            host.NodeIncarnationId != expectedIncarnation)
            throw new ApplicationContractException(
                ProblemCodes.StaleNodeIncarnation,
                "The Host Node incarnation changed after the operation view was loaded.",
                ProblemDisposition.RequiresReconciliation);
    }

    private async Task<bool> HasActiveWorkAsync(
        HostId hostId, CancellationToken cancellationToken)
    {
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
              (SELECT COUNT(*) FROM task_attempts
               WHERE json_extract(snapshot_json,'$.payload.hostId')=$host
                 AND state IN ('Reserved','Dispatched','Accepted','Preparing','Launching','Running','Recovering'))
              +
              (SELECT COUNT(*) FROM portable_objects p
               JOIN task_attempts a
                 ON json_extract(p.metadata_json,'$.taskAttemptId')=a.attempt_id
               WHERE json_extract(a.snapshot_json,'$.payload.hostId')=$host
                 AND p.complete=0)
            """;
        command.Parameters.AddWithValue("$host", hostId.ToString());
        if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) > 0) return true;
        return agentStore is not null &&
            await agentStore.HasActiveExecutionOnHostAsync(hostId, cancellationToken);
    }

    private static ProviderOperationId DeterministicOperation(
        PoolAction action, ProviderBinding binding) =>
        DeterministicOperation(action.Host.Id, action.Kind);

    private static ProviderOperationId DeterministicOperation(HostId hostId, object operation)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{hostId}:{operation}"));
        return new(new Guid(hash.AsSpan(0, 16)));
    }
}
