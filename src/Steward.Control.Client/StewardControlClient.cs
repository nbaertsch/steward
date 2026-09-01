using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Application;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Providers.Abstractions;
using Steward.Terminal.Abstractions;

namespace Steward.Cli;

public sealed record ControlDoctorStatus(
    bool Healthy,
    int SchemaVersion,
    string JournalMode,
    bool ForeignKeys,
    string Integrity,
    string DatabasePath);

public sealed record ControlOrchestrationStatus(
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

public sealed record TerminalClientResponse(
    TerminalSessionSnapshot? Snapshot,
    IReadOnlyList<TerminalOutput> Output);

public interface IStewardControlClient
{
    ValueTask<bool> HasMutationTokenAsync(CancellationToken cancellationToken = default);
    Task<ControlDoctorStatus> DoctorAsync(CancellationToken cancellationToken = default);
    Task<ControlOrchestrationStatus> OrchestrationDoctorAsync(
        CancellationToken cancellationToken = default);
    Task<OperationsSnapshot> GetOperationsAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<PoolRegistration>> ListPoolsAsync(
        CancellationToken cancellationToken = default);
    Task<PoolRegistration> RegisterPoolAsync(
        PoolRegistration registration,
        CancellationToken cancellationToken = default);
    Task<PoolReconcileResult> ReconcilePoolAsync(
        PoolId poolId,
        ReconcilePoolRequest request,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<HostView>> ListHostsAsync(
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<NodeEndpointRegistration>> ListNodesAsync(
        CancellationToken cancellationToken = default);
    Task<ProviderResource?> InspectHostAsync(
        HostId hostId,
        CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> StartHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        CancellationToken cancellationToken = default);
    Task<HostView> DrainHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        bool force,
        CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> StopHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        bool force,
        CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> RecreateHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        bool force,
        CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> DeleteHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        bool force,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<PersistedNodeFact>> ReadTaskEventsAsync(
        TaskId taskId,
        long after,
        int limit,
        CancellationToken cancellationToken = default);
    Task<ArtifactDownloadResult> DownloadArtifactAsync(
        PortableObjectId id,
        string destinationPath,
        long maximumBytes = 256L * 1024 * 1024,
        CancellationToken cancellationToken = default);
    Task<TerminalPolicyStatus> GetTerminalPolicyAsync(
        CancellationToken cancellationToken = default);
    Task<TerminalAuthority> IssueTerminalAuthorityAsync(
        IssueTerminalAuthorityRequest request,
        CancellationToken cancellationToken = default);
    Task<TerminalClientResponse> OpenTerminalAsync(
        TerminalOpenRequest request,
        CancellationToken cancellationToken = default);
    Task<TerminalClientResponse> GetTerminalAsync(
        TerminalSessionId id,
        CancellationToken cancellationToken = default);
    Task<TerminalClientResponse> SendTerminalInputAsync(
        TerminalSessionId id,
        TerminalInputRequest request,
        CancellationToken cancellationToken = default);
    Task<TerminalClientResponse> ResizeTerminalAsync(
        TerminalSessionId id,
        TerminalResizeRequest request,
        CancellationToken cancellationToken = default);
    Task<TerminalClientResponse> ReadTerminalOutputAsync(
        TerminalSessionId id,
        TerminalOutputReadRequest request,
        CancellationToken cancellationToken = default);
    Task<TerminalClientResponse> CloseTerminalAsync(
        TerminalSessionId id,
        TerminalCloseRequest request,
        CancellationToken cancellationToken = default);
    Task RevokeTerminalAsync(
        TerminalSessionId id,
        CancellationToken cancellationToken = default);
}

internal sealed class StewardControlClient(ControlClient inner) : IStewardControlClient
{
    private static readonly JsonSerializerOptions HttpJson =
        CreateHttpJson();

    public ValueTask<bool> HasMutationTokenAsync(
        CancellationToken cancellationToken = default) =>
        inner.HasMutationTokenAsync(cancellationToken);

    public async Task<ControlDoctorStatus> DoctorAsync(
        CancellationToken cancellationToken = default) =>
        Read<ControlDoctorStatus>(
            await inner.DoctorAsync(cancellationToken));

    public async Task<ControlOrchestrationStatus> OrchestrationDoctorAsync(
        CancellationToken cancellationToken = default) =>
        Read<ControlOrchestrationStatus>(
            await inner.OrchestrationDoctorAsync(cancellationToken));

    public async Task<OperationsSnapshot> GetOperationsAsync(
        CancellationToken cancellationToken = default) =>
        Read<OperationsSnapshot>(
            await inner.GetOperationsAsync(cancellationToken));

    public async Task<IReadOnlyList<PoolRegistration>> ListPoolsAsync(
        CancellationToken cancellationToken = default) =>
        Read<IReadOnlyList<PoolRegistration>>(
            await inner.ListPoolsAsync(cancellationToken));

    public async Task<PoolRegistration> RegisterPoolAsync(
        PoolRegistration registration,
        CancellationToken cancellationToken = default) =>
        Read<PoolRegistration>(
            await inner.RegisterPoolAsync(registration, cancellationToken));

    public async Task<PoolReconcileResult> ReconcilePoolAsync(
        PoolId poolId,
        ReconcilePoolRequest request,
        CancellationToken cancellationToken = default) =>
        Read<PoolReconcileResult>(
            await inner.ReconcilePoolAsync(poolId, request, cancellationToken));

    public async Task<IReadOnlyList<HostView>> ListHostsAsync(
        CancellationToken cancellationToken = default) =>
        Read<IReadOnlyList<HostView>>(
            await inner.ListHostsAsync(cancellationToken));

    public async Task<IReadOnlyList<NodeEndpointRegistration>> ListNodesAsync(
        CancellationToken cancellationToken = default) =>
        Read<IReadOnlyList<NodeEndpointRegistration>>(
            await inner.ListNodesAsync(cancellationToken));

    public async Task<ProviderResource?> InspectHostAsync(
        HostId hostId,
        CancellationToken cancellationToken = default) =>
        ReadNullable<ProviderResource>(
            await inner.InspectHostAsync(hostId, cancellationToken));

    public async Task<ProviderOperationResult> StartHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        CancellationToken cancellationToken = default) =>
        Read<ProviderOperationResult>(
            await inner.StartHostAsync(
                hostId,
                cancellationToken,
                expectedIncarnation));

    public async Task<HostView> DrainHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        bool force,
        CancellationToken cancellationToken = default) =>
        Read<HostView>(
            await inner.DrainHostAsync(
                hostId,
                force,
                cancellationToken,
                expectedIncarnation));

    public async Task<ProviderOperationResult> StopHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        bool force,
        CancellationToken cancellationToken = default) =>
        Read<ProviderOperationResult>(
            await inner.StopHostAsync(
                hostId,
                force,
                cancellationToken,
                expectedIncarnation));

    public async Task<ProviderOperationResult> RecreateHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        bool force,
        CancellationToken cancellationToken = default) =>
        Read<ProviderOperationResult>(
            await inner.RecreateHostAsync(
                hostId,
                force,
                cancellationToken,
                expectedIncarnation));

    public async Task<ProviderOperationResult> DeleteHostAsync(
        HostId hostId,
        NodeIncarnationId expectedIncarnation,
        bool force,
        CancellationToken cancellationToken = default) =>
        Read<ProviderOperationResult>(
            await inner.DeleteHostAsync(
                hostId,
                force,
                cancellationToken,
                expectedIncarnation));

    public async Task<IReadOnlyList<PersistedNodeFact>> ReadTaskEventsAsync(
        TaskId taskId,
        long after,
        int limit,
        CancellationToken cancellationToken = default) =>
        Read<IReadOnlyList<PersistedNodeFact>>(
            await inner.ReadTaskEventsAsync(
                taskId,
                after,
                limit,
                cancellationToken));

    public Task<ArtifactDownloadResult> DownloadArtifactAsync(
        PortableObjectId id,
        string destinationPath,
        long maximumBytes = 256L * 1024 * 1024,
        CancellationToken cancellationToken = default) =>
        inner.DownloadArtifactAsync(
            id,
            destinationPath,
            maximumBytes,
            cancellationToken);

    public async Task<TerminalPolicyStatus> GetTerminalPolicyAsync(
        CancellationToken cancellationToken = default) =>
        Read<TerminalPolicyStatus>(
            await inner.GetTerminalPolicyAsync(cancellationToken));

    public async Task<TerminalAuthority> IssueTerminalAuthorityAsync(
        IssueTerminalAuthorityRequest request,
        CancellationToken cancellationToken = default) =>
        ReadHttp<TerminalAuthority>(
            await inner.IssueTerminalAuthorityAsync(request, cancellationToken));

    public async Task<TerminalClientResponse> OpenTerminalAsync(
        TerminalOpenRequest request,
        CancellationToken cancellationToken = default) =>
        ReadTerminal(
            await inner.OpenTerminalAsync(request, cancellationToken));

    public async Task<TerminalClientResponse> GetTerminalAsync(
        TerminalSessionId id,
        CancellationToken cancellationToken = default) =>
        ReadTerminal(
            await inner.GetTerminalAsync(id, cancellationToken));

    public async Task<TerminalClientResponse> SendTerminalInputAsync(
        TerminalSessionId id,
        TerminalInputRequest request,
        CancellationToken cancellationToken = default) =>
        ReadTerminal(
            await inner.SendTerminalInputAsync(id, request, cancellationToken));

    public async Task<TerminalClientResponse> ResizeTerminalAsync(
        TerminalSessionId id,
        TerminalResizeRequest request,
        CancellationToken cancellationToken = default) =>
        ReadTerminal(
            await inner.ResizeTerminalAsync(id, request, cancellationToken));

    public async Task<TerminalClientResponse> ReadTerminalOutputAsync(
        TerminalSessionId id,
        TerminalOutputReadRequest request,
        CancellationToken cancellationToken = default) =>
        ReadTerminal(
            await inner.ReadTerminalOutputAsync(id, request, cancellationToken));

    public async Task<TerminalClientResponse> CloseTerminalAsync(
        TerminalSessionId id,
        TerminalCloseRequest request,
        CancellationToken cancellationToken = default) =>
        ReadTerminal(
            await inner.CloseTerminalAsync(id, request, cancellationToken));

    public async Task RevokeTerminalAsync(
        TerminalSessionId id,
        CancellationToken cancellationToken = default) =>
        _ = await inner.RevokeTerminalAsync(id, cancellationToken);

    private static T Read<T>(JsonElement value) =>
        value.Deserialize<T>(HttpJson)
        ?? throw new InvalidDataException(
            $"Steward.Control returned an empty {typeof(T).Name} response.");

    private static T ReadHttp<T>(JsonElement value) =>
        value.Deserialize<T>(HttpJson)
        ?? throw new InvalidDataException(
            $"Steward.Control returned an empty {typeof(T).Name} response.");

    private static T? ReadNullable<T>(JsonElement value) where T : class =>
        value.ValueKind == JsonValueKind.Null
            ? null
            : Read<T>(value);

    private static TerminalClientResponse ReadTerminal(JsonElement value)
    {
        var response = value.Deserialize<TerminalWireResponse>(HttpJson)
            ?? throw new InvalidDataException(
                "Steward.Control returned an empty terminal response.");
        if (response.Problem is not null)
            throw new TerminalException(response.Problem);
        var snapshot = response.Snapshot;
        return new(snapshot, response.Output ?? []);
    }

    private static JsonSerializerOptions CreateHttpJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.CamelCase,
            allowIntegerValues: true));
        options.Converters.Add(new StewardIdJsonConverterFactory());
        options.Converters.Add(new TerminalSessionIdJsonConverter());
        return options;
    }
}
