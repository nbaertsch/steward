using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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

[JsonConverter(typeof(ExtensionMetadataDtoJsonConverter))]
public sealed class ExtensionMetadataDto : IEquatable<ExtensionMetadataDto>
{
    private const int MaximumDataBytes = 4 * 1024 * 1024;
    private readonly string dataJson;

    private ExtensionMetadataDto(string kind, string version, string dataJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kind);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        if (Encoding.UTF8.GetByteCount(dataJson) > MaximumDataBytes)
            throw new ArgumentException(
                "Extension metadata exceeds its size bound.",
                nameof(dataJson));
        using var document = JsonDocument.Parse(dataJson);
        Kind = kind;
        Version = version;
        this.dataJson = document.RootElement.GetRawText();
    }

    public string Kind { get; }
    public string Version { get; }
    public int DataByteCount => Encoding.UTF8.GetByteCount(dataJson);
    public bool HasData => dataJson != "null";
    public string DataHash => Convert.ToHexString(
        System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(dataJson)));

    public static ExtensionMetadataDto Create<T>(
        string kind,
        string version,
        T data,
        JsonSerializerOptions? options = null) =>
        new(kind, version, JsonSerializer.Serialize(data, options));

    public T? DeserializeData<T>(JsonSerializerOptions? options = null) =>
        JsonSerializer.Deserialize<T>(dataJson, options);

    public bool Equals(ExtensionMetadataDto? other) =>
        other is not null &&
        string.Equals(Kind, other.Kind, StringComparison.Ordinal) &&
        string.Equals(Version, other.Version, StringComparison.Ordinal) &&
        string.Equals(dataJson, other.dataJson, StringComparison.Ordinal);

    public override bool Equals(object? value) =>
        value is ExtensionMetadataDto other && Equals(other);

    public override int GetHashCode() =>
        HashCode.Combine(
            StringComparer.Ordinal.GetHashCode(Kind),
            StringComparer.Ordinal.GetHashCode(Version),
            StringComparer.Ordinal.GetHashCode(dataJson));

    internal string DataJson => dataJson;

    internal static ExtensionMetadataDto FromJson(
        string kind,
        string version,
        string dataJson) => new(kind, version, dataJson);
}

internal sealed class ExtensionMetadataDtoJsonConverter
    : JsonConverter<ExtensionMetadataDto>
{
    public override ExtensionMetadataDto Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;
        if (!TryGetProperty(root, "kind", out var kind) ||
            !TryGetProperty(root, "version", out var version) ||
            !TryGetProperty(root, "data", out var data) ||
            kind.ValueKind != JsonValueKind.String ||
            version.ValueKind != JsonValueKind.String)
            throw new JsonException("Extension metadata is invalid.");
        return ExtensionMetadataDto.FromJson(
            kind.GetString()!,
            version.GetString()!,
            data.GetRawText());
    }

    public override void Write(
        Utf8JsonWriter writer,
        ExtensionMetadataDto value,
        JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("kind", value.Kind);
        writer.WriteString("version", value.Version);
        writer.WritePropertyName("data");
        using var document = JsonDocument.Parse(value.DataJson);
        document.RootElement.WriteTo(writer);
        writer.WriteEndObject();
    }

    private static bool TryGetProperty(
        JsonElement value,
        string name,
        out JsonElement property)
    {
        foreach (var candidate in value.EnumerateObject())
        {
            if (candidate.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                property = candidate.Value;
                return true;
            }
        }
        property = default;
        return false;
    }
}
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
