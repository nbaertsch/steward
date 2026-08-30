using System.Text.Json;
using Steward.Application;
using Steward.Contracts;
using Steward.Domain;
using Steward.Persistence.Sqlite;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;

namespace Steward.Stack.Local;

public sealed class DurableDevBoxRecreateService(
    SqliteControlStore store,
    IHostProviderRegistry providers,
    INodeBootstrapper bootstrapper,
    IEnrollmentClaimIssuer claims,
    SignedNodePackage package) : IHostRecreateService
{
    public async Task<ProviderOperationResult> RecreateAsync(
        HostView view,
        PoolRegistration pool,
        bool force,
        CancellationToken cancellationToken)
    {
        if (!providers.TryResolve(pool.Provider.Provider, out var provider))
            throw new InvalidOperationException("Configured Dev Box provider is unavailable.");
        var operationId = Deterministic(view.HostId);
        var state = await LoadAsync(operationId, cancellationToken);
        var host = RestoreHost(view);
        var coordinator = new DevBoxRecreateCoordinator(provider, bootstrapper);
        if (state is null)
        {
            state = coordinator.Begin(
                operationId, $"recreate:{view.HostId}", pool.Provider,
                view.ProviderResourceName,
                new(host, [], force, force ? ["forced recreate"] : null));
            await SaveAsync(state, cancellationToken);
        }
        var claim = await claims.IssueAsync(
            state.HostId, state.NewIncarnationId, view.ProviderResourceName, cancellationToken);
        state = await coordinator.AdvanceAsync(state, host, package, claim, cancellationToken);
        await SaveAsync(state, cancellationToken);
        return state.Phase switch
        {
            RecreatePhase.Completed => new(
                ProviderOperationStatus.Succeeded, null,
                new(view.ProviderResourceName, view.ProviderResourceName,
                    ProviderHostStatus.Running, new Dictionary<string, string>
                    {
                        ["nodeIncarnationId"] = state.NewIncarnationId.ToString()
                    })),
            RecreatePhase.Failed => new(
                ProviderOperationStatus.Failed, state.PendingHandle, null,
                "RecreateFailed", "Dev Box recreate failed in a durable phase."),
            _ => new(ProviderOperationStatus.Running, state.PendingHandle, null)
        };
    }

    private async Task<DevBoxRecreateState?> LoadAsync(
        ProviderOperationId id, CancellationToken cancellationToken)
    {
        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS devbox_recreate_operations(
              operation_id TEXT PRIMARY KEY,state_json TEXT NOT NULL,updated_at TEXT NOT NULL);
            SELECT state_json FROM devbox_recreate_operations WHERE operation_id=$id;
            """;
        command.Parameters.AddWithValue("$id", id.ToString());
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken);
        return json is null ? null :
            JsonSerializer.Deserialize<DevBoxRecreateState>(json, StewardJson.Options);
    }

    private async Task SaveAsync(DevBoxRecreateState state, CancellationToken cancellationToken)
    {
        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO devbox_recreate_operations(operation_id,state_json,updated_at)
            VALUES($id,$json,$now)
            ON CONFLICT(operation_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at;
            """;
        command.Parameters.AddWithValue("$id", state.OperationId.ToString());
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(state, StewardJson.Options));
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static Steward.Domain.Host RestoreHost(HostView view)
    {
        var host = new Steward.Domain.Host(view.HostId, view.PoolId, view.NodeIncarnationId);
        host.SetConnectionState(view.Connected ? HostConnectionState.Connected : HostConnectionState.Disconnected);
        return host;
    }

    private static ProviderOperationId Deterministic(HostId host)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"devbox-recreate:{host}"));
        return new(new Guid(hash.AsSpan(0, 16)));
    }
}
