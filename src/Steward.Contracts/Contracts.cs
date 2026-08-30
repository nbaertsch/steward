using System.Text.Json;
using Steward.Domain;

namespace Steward.Contracts;

public sealed record ContractEnvelope<T>(
    string SchemaName,
    string SchemaVersion,
    IReadOnlyList<string> RequiredFeatures,
    IReadOnlyList<string> OptionalFeatures,
    DateTimeOffset CreatedAt,
    long Revision,
    T Payload);

public sealed record ExtensionMetadataDto(
    string Kind,
    string Version,
    JsonElement Data);

public sealed record ResourceRequirementsDto(
    decimal CpuCores,
    long MemoryBytes,
    long DiskBytes,
    int GpuCount,
    int ProcessCount,
    int ContainerCount,
    int VmCount,
    int ConcurrencyUnits);

public sealed record WorkloadDto(
    WorkloadId WorkloadId,
    PlanRevisionId PlanRevisionId,
    string WorkloadType,
    WorkloadDesiredState DesiredState,
    WorkloadObservedState ObservedState,
    IReadOnlyList<TaskId> TaskIds,
    IReadOnlyList<StewardAgentId> SupportingAgentIds,
    ExtensionMetadataDto Planner);

public sealed record TaskDto(
    TaskId TaskId,
    WorkloadId WorkloadId,
    PlanRevisionId PlanRevisionId,
    string TaskType,
    string TaskTypeVersion,
    TaskDesiredState DesiredState,
    TaskObservedState ObservedState,
    int AcceptedGeneration,
    InterruptionClass InterruptionClass,
    TaskCapabilities Capabilities,
    ResourceRequirementsDto Resources,
    IReadOnlyList<TaskId> Dependencies,
    ExtensionMetadataDto TaskMetadata);

public sealed record TaskAttemptDto(
    TaskAttemptId TaskAttemptId,
    TaskId TaskId,
    int Generation,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    TaskAttemptState State,
    RecoveryCertainty RecoveryCertainty,
    DelegationId DelegationId,
    CommandId CommandId,
    DateTimeOffset AuthorityExpiresAt,
    ExtensionMetadataDto RuntimeMetadata);

public sealed record AgentTurnDto(
    AgentTurnId AgentTurnId,
    AgentTurnState State,
    long? ResponseSequence,
    NotificationId? NotificationId);

public sealed record StewardAgentDto(
    StewardAgentId StewardAgentId,
    StewardAgentState State,
    long NotificationCursor,
    IReadOnlyList<AgentTurnDto> Turns,
    IReadOnlyList<PortableObjectId> CheckpointLineage,
    ExtensionMetadataDto RuntimeMetadata);

public sealed record HostDto(
    HostId HostId,
    PoolId PoolId,
    NodeIncarnationId NodeIncarnationId,
    HostLifecycleState LifecycleState,
    HostConnectionState ConnectionState,
    IReadOnlyList<string> Capabilities,
    IReadOnlyDictionary<string, string> Labels,
    ExtensionMetadataDto ProviderMetadata,
    ExtensionMetadataDto RuntimeMetadata);

public sealed record PoolDto(
    PoolId PoolId,
    int WarmMinimum,
    int HardMaximum,
    TimeSpan IdleTimeout,
    IReadOnlyList<string> AllowedTaskTypes,
    ResourceRequirementsDto DefaultResourceCeiling,
    ExtensionMetadataDto ProviderBinding);

public sealed record AttemptGenerationRangeDto(TaskId TaskId, int Minimum, int Maximum);
public sealed record RateLimitDto(string Scope, decimal MaximumAmount, DateTimeOffset ExpiresAt);
public sealed record TaskAuthorityBindingDto(
    TaskId TaskId,
    int Generation,
    IReadOnlyList<RateLimitDto> RateLimits,
    IReadOnlyList<IdentityGrantId> IdentityGrantIds);

public sealed record DelegationDto(
    DelegationId DelegationId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    PlanRevisionId PlanRevisionId,
    IReadOnlyList<AttemptGenerationRangeDto> AllowedGenerations,
    ResourceRequirementsDto ResourceLimit,
    int ConcurrencyLimit,
    long SpoolQuotaBytes,
    IReadOnlyList<RateLimitDto> RateLimits,
    IReadOnlyList<IdentityGrantId> IdentityGrantIds,
    DateTimeOffset AcceptedAt,
    DateTimeOffset NoNewStartsAfter,
    DateTimeOffset DrainAt,
    DateTimeOffset AuthorityExpiresAt,
    long RevocationRevision,
    IReadOnlyList<TaskAuthorityBindingDto>? TaskAuthorityBindings = null);

public sealed record IdentityGrantDto(
    IdentityGrantId IdentityGrantId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    WorkloadId WorkloadId,
    TaskId? TaskId,
    StewardAgentId? StewardAgentId,
    string Issuer,
    string Audience,
    IReadOnlyList<string> Scopes,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    int MaximumUses,
    IdentityRenewalMode RenewalMode,
    IdentityOfflineBehavior OfflineBehavior,
    ExtensionMetadataDto DeliveryMetadata);

public sealed record PortableObjectDto(
    PortableObjectId PortableObjectId,
    PortableObjectKind Kind,
    string MediaType,
    string ContentHash,
    long SizeBytes,
    TaskAttemptId? TaskAttemptId,
    StewardAgentId? StewardAgentId,
    bool Complete,
    string? StoreReceipt,
    DateTimeOffset CreatedAt,
    ExtensionMetadataDto StorageMetadata);

public sealed record CommandDto(
    CommandId CommandId,
    string IdempotencyKey,
    long ExpectedAggregateRevision,
    int? ExpectedAttemptGeneration,
    NodeIncarnationId? ExpectedNodeIncarnationId,
    DateTimeOffset Deadline,
    string Actor,
    string Capability,
    ExtensionMetadataDto Payload);

public sealed record NodeDelegationAcceptedEventDto(
    DelegationId DelegationId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    long NodeSequence,
    DateTimeOffset ObservedAt);

public sealed record NodeReconciliationEventDto(
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    long NodeSequence,
    string AggregateType,
    string AggregateId,
    int? AttemptGeneration,
    string FactType,
    DateTimeOffset ObservedAt,
    IReadOnlyList<PortableObjectId> EvidenceReferences,
    ExtensionMetadataDto Fact);

public enum ProblemDisposition
{
    RetrySafe,
    RequiresReconciliation,
    RequiresNewUserIntent,
    Terminal
}

public static class ProblemCodes
{
    public const string UnsupportedRequiredFeature = nameof(UnsupportedRequiredFeature);
    public const string RevisionConflict = nameof(RevisionConflict);
    public const string StaleNodeIncarnation = nameof(StaleNodeIncarnation);
    public const string StaleAttemptGeneration = nameof(StaleAttemptGeneration);
    public const string DelegationExpired = nameof(DelegationExpired);
    public const string DelegationLimitExceeded = nameof(DelegationLimitExceeded);
    public const string AmbiguousExecution = nameof(AmbiguousExecution);
    public const string CapabilityUnavailable = nameof(CapabilityUnavailable);
    public const string IdentityRenewalUnavailable = nameof(IdentityRenewalUnavailable);
    public const string SpoolAdmissionDenied = nameof(SpoolAdmissionDenied);
    public const string ExternalRateAllocationExhausted = nameof(ExternalRateAllocationExhausted);
    public const string PortableStateIncomplete = nameof(PortableStateIncomplete);
    public const string LifecycleBlockedByActiveWork = nameof(LifecycleBlockedByActiveWork);
    public const string UnmanagedMutationRequiresReconciliation = nameof(UnmanagedMutationRequiresReconciliation);
}

public sealed record ProblemDto(
    string Code,
    string Title,
    string Detail,
    ProblemDisposition Disposition,
    bool SideEffectMayHaveOccurred,
    IReadOnlyDictionary<string, string>? Extensions = null);
