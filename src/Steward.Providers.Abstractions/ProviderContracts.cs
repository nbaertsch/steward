using Steward.Domain;

namespace Steward.Providers.Abstractions;

[Flags]
public enum ProviderCapability
{
    None = 0,
    Discover = 1 << 0,
    Inspect = 1 << 1,
    Create = 1 << 2,
    Start = 1 << 3,
    Stop = 1 << 4,
    Repair = 1 << 5,
    Restore = 1 << 6,
    Recreate = 1 << 7,
    Delete = 1 << 8,
    BootstrapEnroll = 1 << 9
}

public enum ProviderHostStatus
{
    Unknown,
    Provisioning,
    Running,
    Stopped,
    Deleting,
    Deleted,
    Failed
}

public enum ProviderOperationStatus
{
    Accepted,
    Running,
    Succeeded,
    Failed,
    RequiresReconciliation,
    CapabilityUnavailable
}

public enum ProviderEffectAttempt
{
    New,
    RetryAfterUncertainOutcomeWithoutHandle
}

public sealed record ProviderBinding(string Provider, string Project, string Pool, string User = "me");

public sealed record ProviderResource(
    string ProviderResourceId,
    string Name,
    ProviderHostStatus Status,
    IReadOnlyDictionary<string, string> Metadata);

public sealed record ProviderCapabilities(
    ProviderCapability Supported,
    IReadOnlyDictionary<ProviderCapability, string> Evidence)
{
    public bool Supports(ProviderCapability capability) => Supported.HasFlag(capability);
}

public sealed record ProviderEffect(
    ProviderOperationId OperationId,
    string IdempotencyKey,
    ProviderBinding Binding,
    string ResourceName,
    HostId HostId,
    NodeIncarnationId IncarnationId,
    IReadOnlyDictionary<string, string>? Parameters = null,
    ProviderEffectAttempt Attempt = ProviderEffectAttempt.New);

public sealed record ProviderOperationHandle(
    ProviderOperationId OperationId,
    string IdempotencyKey,
    string Provider,
    string OpaqueHandle);

public sealed record ProviderOperationResult(
    ProviderOperationStatus Status,
    ProviderOperationHandle? Handle,
    ProviderResource? Resource,
    string? ProblemCode = null,
    string? Detail = null,
    IReadOnlyDictionary<string, string>? Metadata = null)
{
    public static ProviderOperationResult CapabilityUnavailable(ProviderEffect effect, ProviderCapability capability, string detail) =>
        new(ProviderOperationStatus.CapabilityUnavailable, null, null,
            nameof(DomainErrorCode.CapabilityUnavailable), detail,
            new Dictionary<string, string> { ["capability"] = capability.ToString(), ["operationId"] = effect.OperationId.ToString() });
}

public interface IHostProvider
{
    Task<ProviderCapabilities> DiscoverCapabilitiesAsync(ProviderBinding binding, CancellationToken cancellationToken = default);
    IAsyncEnumerable<ProviderResource> DiscoverAsync(ProviderBinding binding, CancellationToken cancellationToken = default);
    Task<ProviderResource?> InspectAsync(ProviderBinding binding, string resourceName, CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> CreateAsync(ProviderEffect effect, CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> StartAsync(ProviderEffect effect, CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> StopAsync(ProviderEffect effect, CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> RepairAsync(ProviderEffect effect, CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> RestoreAsync(ProviderEffect effect, CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> DeleteAsync(ProviderEffect effect, CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> ReconcileAsync(ProviderOperationHandle handle, CancellationToken cancellationToken = default);
}

public interface IDurableHostRecreator<TState>
{
    TState Begin(
        ProviderOperationId operationId,
        string idempotencyKey,
        ProviderBinding binding,
        string resourceName,
        DrainRequest drain);

    Task<TState> AdvanceAsync(
        TState state,
        Host host,
        SignedNodePackage package,
        EnrollmentClaim claim,
        CancellationToken cancellationToken = default);
}
