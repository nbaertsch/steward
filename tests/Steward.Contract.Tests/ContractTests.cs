using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;

namespace Steward.Contract.Tests;

public sealed class ContractTests
{
    private static readonly DateTimeOffset Time = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Fact]
    public void ResourceFixturesRoundTripDeterministically()
    {
        var extension = Metadata("provider-neutral");
        var workloadId = WorkloadId.New();
        var planId = PlanRevisionId.New();
        var taskId = TaskId.New();
        var agentId = StewardAgentId.New();
        var hostId = HostId.New();
        var nodeId = NodeIncarnationId.New();
        var poolId = PoolId.New();
        var attemptId = TaskAttemptId.New();
        var delegationId = DelegationId.New();
        var grantId = IdentityGrantId.New();
        var portableId = PortableObjectId.New();
        var resources = new ResourceRequirementsDto(2, 1024, 2048, 0, 5, 1, 0, 1);

        RoundTrip(new WorkloadDto(workloadId, planId, "evaluation", WorkloadDesiredState.Active,
            WorkloadObservedState.Running, [taskId], [agentId], extension));
        RoundTrip(new TaskDto(taskId, workloadId, planId, "evaluate", "1.0.0", TaskDesiredState.Running,
            TaskObservedState.Running, 1, InterruptionClass.CheckpointResumable,
            TaskCapabilities.Execute | TaskCapabilities.Checkpoint, resources, [], extension));
        RoundTrip(new TaskAttemptDto(attemptId, taskId, 1, hostId, nodeId, TaskAttemptState.Running,
            RecoveryCertainty.Certain, delegationId, CommandId.New(), Time.AddHours(1), extension));
        RoundTrip(new StewardAgentDto(agentId, StewardAgentState.Ready, 4,
            [new(AgentTurnId.New(), AgentTurnState.Notified, 4, NotificationId.New())], [portableId], extension));
        RoundTrip(new HostDto(hostId, poolId, nodeId, HostLifecycleState.Ready, HostConnectionState.Connected,
            ["process"], new Dictionary<string, string> { ["os"] = "generic" }, extension, extension));
        RoundTrip(new PoolDto(poolId, 1, 4, TimeSpan.FromMinutes(20), ["evaluate"], resources, extension));
        RoundTrip(new DelegationDto(delegationId, hostId, nodeId, planId,
            [new(taskId, 1, 3)], resources, 2, 4096, [new("inference", 100, Time.AddMinutes(10))],
            [grantId], Time, Time.AddMinutes(5), Time.AddMinutes(10), Time.AddMinutes(15), 0,
            [new(taskId, 1, [new("inference", 100, Time.AddMinutes(10))], [grantId])]));
        RoundTrip(new IdentityGrantDto(grantId, hostId, nodeId, workloadId, taskId, null,
            "issuer", "audience", ["scope"], Time, Time.AddHours(1), 4,
            IdentityRenewalMode.LocalBroker, IdentityOfflineBehavior.CheckpointAndPause, extension));
        RoundTrip(new PortableObjectDto(portableId, PortableObjectKind.TaskCheckpoint, "application/octet-stream",
            "sha256:abc", 42, attemptId, null, true, "receipt", Time, extension));
    }

    [Fact]
    public void CommandAndNodeEventFixturesRoundTrip()
    {
        var hostId = HostId.New();
        var nodeId = NodeIncarnationId.New();
        var delegationId = DelegationId.New();
        RoundTrip(new CommandDto(CommandId.New(), "idempotent-1", 7, 2, nodeId, Time.AddMinutes(1),
            "control", "task.execute", Metadata("execute")));
        RoundTrip(new NodeDelegationAcceptedEventDto(delegationId, hostId, nodeId, 1, Time));
        RoundTrip(new NodeReconciliationEventDto(hostId, nodeId, 2, "taskAttempt", TaskAttemptId.New().ToString(),
            2, "processObserved", Time, [PortableObjectId.New()], Metadata("fact")));
    }

    [Fact]
    public void EnvelopeIncludesVersionAndFeatureDeclarations()
    {
        var envelope = Envelope(new NodeDelegationAcceptedEventDto(
            DelegationId.New(), HostId.New(), NodeIncarnationId.New(), 1, Time));
        var json = JsonSerializer.Serialize(envelope, StewardJson.Options);

        Assert.Contains("\"schemaName\":\"steward.node-event\"", json, StringComparison.Ordinal);
        Assert.Contains("\"schemaVersion\":\"1.1.0\"", json, StringComparison.Ordinal);
        Assert.Contains("\"requiredFeatures\":[\"generation-fencing\"]", json, StringComparison.Ordinal);
        RoundTrip(envelope);
    }

    [Fact]
    public void CompatibilityRejectsUnknownSchemaVersionAndRequiredFeature()
    {
        var compatibility = new ContractCompatibility(
            new Dictionary<string, Version> { ["steward.node-event"] = new(1, 1, 0) },
            ["generation-fencing"]);
        compatibility.Validate(Envelope("1.1.0", ["generation-fencing"]));

        var future = Assert.Throws<ContractValidationException>(() =>
            compatibility.Validate(Envelope("1.2.0", ["generation-fencing"])));
        Assert.Equal(ProblemCodes.UnsupportedRequiredFeature, future.Problem.Code);

        Assert.Throws<ContractValidationException>(() =>
            compatibility.Validate(Envelope("2.0.0", ["generation-fencing"])));
        Assert.Throws<ContractValidationException>(() =>
            compatibility.Validate(Envelope("1.1.0", ["unknown-required-feature"])));
    }

    [Fact]
    public void UnknownOptionalFeaturesAreAccepted()
    {
        var compatibility = new ContractCompatibility(
            new Dictionary<string, Version> { ["steward.node-event"] = new(1, 1, 0) },
            ["generation-fencing"]);
        var envelope = Envelope("1.1.0", ["generation-fencing"]) with
        {
            OptionalFeatures = ["future-observation"]
        };
        compatibility.Validate(envelope);
    }

    [Fact]
    public void StrongIdsUseStringsAndRejectEmptyOnTheWire()
    {
        var id = WorkloadId.New();
        var json = JsonSerializer.Serialize(id, StewardJson.Options);
        Assert.Equal($"\"{id}\"", json);
        Assert.Equal(id, JsonSerializer.Deserialize<WorkloadId>(json, StewardJson.Options));
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<WorkloadId>($"\"{Guid.Empty:D}\"", StewardJson.Options));
    }

    [Fact]
    public void ErrorCatalogHasStableDistinctCodes()
    {
        string[] codes =
        [
            ProblemCodes.UnsupportedRequiredFeature, ProblemCodes.RevisionConflict,
            ProblemCodes.StaleNodeIncarnation, ProblemCodes.StaleAttemptGeneration,
            ProblemCodes.DelegationExpired, ProblemCodes.DelegationLimitExceeded,
            ProblemCodes.AmbiguousExecution, ProblemCodes.CapabilityUnavailable,
            ProblemCodes.IdentityRenewalUnavailable, ProblemCodes.SpoolAdmissionDenied,
            ProblemCodes.ExternalRateAllocationExhausted, ProblemCodes.PortableStateIncomplete,
            ProblemCodes.LifecycleBlockedByActiveWork, ProblemCodes.UnmanagedMutationRequiresReconciliation
        ];
        Assert.Equal(codes.Length, codes.Distinct(StringComparer.Ordinal).Count());
        RoundTrip(new ProblemDto(codes[6], "Execution is ambiguous", "Reconcile Node evidence.",
            ProblemDisposition.RequiresReconciliation, true));
    }

    private static ContractEnvelope<NodeDelegationAcceptedEventDto> Envelope(
        string version,
        IReadOnlyList<string> required) =>
        new("steward.node-event", version, required, [], Time, 1,
            new(DelegationId.New(), HostId.New(), NodeIncarnationId.New(), 1, Time));

    private static ContractEnvelope<T> Envelope<T>(T value) =>
        new("steward.node-event", "1.1.0", ["generation-fencing"], [], Time, 1, value);

    private static ExtensionMetadataDto Metadata(string value)
    {
        using var document = JsonDocument.Parse($"{{\"name\":\"{value}\"}}");
        return ExtensionMetadataDto.Create(
            "neutral", "1.0.0", document.RootElement.Clone());
    }

    private static void RoundTrip<T>(T value)
    {
        var json = JsonSerializer.Serialize(value, StewardJson.Options);
        var restored = JsonSerializer.Deserialize<T>(json, StewardJson.Options);
        var second = JsonSerializer.Serialize(restored, StewardJson.Options);
        Assert.Equal(json, second);
    }
}
