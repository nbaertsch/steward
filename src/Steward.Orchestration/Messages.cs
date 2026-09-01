using Steward.Contracts;
using Steward.Domain;
using Steward.Maintenance.Windows;

namespace Steward.Orchestration;

public static class OrchestrationMessageKinds
{
    public const string Delegation = "control.delegation.v1";
    public const string ExecuteTask = "control.execute-task.v1";
    public const string CancelTask = "control.cancel-task.v1";
    public const string FactAcknowledgement = "control.fact-ack.v1";
    public const string DelegationAccepted = "node.delegation-accepted.v1";
    public const string TaskAccepted = "node.task-accepted.v1";
    public const string TaskRunning = "node.task-running.v1";
    public const string TaskProgress = "node.task-progress.v1";
    public const string TaskLogCursor = "node.task-log-cursor.v1";
    public const string TaskArtifact = "node.task-artifact.v1";
    public const string TaskCheckpoint = "node.task-checkpoint.v1";
    public const string TaskTerminal = "node.task-terminal.v1";
    public const string TaskRecovery = "node.task-recovery.v1";
    public const string CommandAcknowledged = "node.command-acknowledged.v1";
    public const string AgentActivity = "node.agent-activity.v1";
    public const string AgentFinal = "node.agent-final.v1";
    public const string RateFeedback = "node.rate-feedback.v1";
    public const string IdentityDeliveryRequest = "node.identity-delivery-request.v1";
    public const string IdentityDelivery = "control.identity-delivery.v1";
    public const string MaintenanceRequest = "control.local-maintenance.v1";
    public const string MaintenanceResult = "node.local-maintenance-result.v1";
}

internal sealed record OrchestrationEnvelope(
    string Schema,
    string Version,
    string Kind,
    DateTimeOffset CreatedAt,
    System.Text.Json.JsonElement Payload);

public sealed record DelegationMessage(DelegationDto Delegation);

public sealed record AttemptIdentity(
    WorkloadId WorkloadId,
    PlanRevisionId PlanRevisionId,
    TaskId TaskId,
    TaskAttemptId AttemptId,
    int Generation,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    DelegationId DelegationId,
    CommandId CommandId);

public sealed record ExecuteTaskMessage(
    CommandDto Command,
    AttemptIdentity Identity,
    string TaskType,
    string TaskTypeVersion,
    string InputMediaType,
    string InputSchemaVersion,
    string InputJson,
    ResourceRequirementsDto Resources,
    IReadOnlyDictionary<string, decimal> RateRequirements,
    IReadOnlyList<IdentityGrantId> IdentityGrantIds,
    string Workspace,
    IReadOnlyList<TaskIdentityGrantReference>? IdentityGrants = null);

public sealed record TaskIdentityGrantReference(
    IdentityGrantId IdentityGrantId,
    WorkloadId WorkloadId,
    TaskId TaskId,
    int Generation,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string Audience,
    IReadOnlyList<string> Scopes,
    DateTimeOffset ExpiresAt,
    IdentityRenewalMode RenewalMode,
    Guid UseId = default,
    IdentityOfflineBehavior OfflineBehavior = IdentityOfflineBehavior.Fail);

public sealed record DirectIdentityDeliveryRequest(
    Guid RequestId,
    AttemptIdentity Identity,
    TaskIdentityGrantReference Grant,
    byte[] RecipientPublicKey);

public sealed record EncryptedIdentityDelivery(
    Guid RequestId,
    Guid UseId,
    DateTimeOffset ExpiresAt,
    byte[] SenderPublicKey,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] AuthenticationTag);

public sealed record CancelTaskMessage(
    CommandDto Command,
    AttemptIdentity Identity,
    int GracePeriodMilliseconds);

public sealed record LocalMaintenanceRequestMessage(
    int Version,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    AuthenticatedMaintenanceRequest Request);

public sealed record LocalMaintenanceResultFact(
    int Version,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    MaintenanceResponse Result);

public sealed record FactAcknowledgementMessage(long ThroughCursor);

public sealed record DelegationAcceptedFact(
    DelegationId DelegationId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId);

public sealed record TaskAcceptedFact(AttemptIdentity Identity);
public sealed record TaskRunningFact(AttemptIdentity Identity);
public sealed record TaskProgressFact(AttemptIdentity Identity, double Fraction, string? Message);
public sealed record TaskLogCursorFact(
    AttemptIdentity Identity,
    string Stream,
    long Offset,
    long Length,
    string ContentHash,
    bool Truncated);
public sealed record TaskArtifactFact(
    AttemptIdentity Identity,
    PortableObjectId PortableObjectId,
    string Name,
    string MediaType,
    string Reference,
    long SizeBytes,
    string ContentHash,
    bool Portable = false);
public sealed record TaskCheckpointFact(
    AttemptIdentity Identity,
    PortableObjectId PortableObjectId,
    string Reference,
    long SizeBytes,
    string ContentHash,
    bool Portable = false);
public sealed record TaskTerminalFact(
    AttemptIdentity Identity,
    TaskAttemptState State,
    int? ExitCode,
    string Receipt,
    string? Detail);
public sealed record TaskRecoveryFact(AttemptIdentity Identity, string Code, string Detail);
public sealed record CommandAcknowledgedFact(
    AttemptIdentity Identity,
    CommandId AcknowledgedCommandId,
    string Operation);
public sealed record AgentActivityFact(AttemptIdentity Identity, string Text);
public sealed record AgentFinalFact(AttemptIdentity Identity, string Text, string Receipt);
public sealed record RateFeedbackFact(long FeedbackSequence, string Scope, DateTimeOffset RetryAfter);

internal sealed record DecodedOrchestrationMessage(string Kind, object Value);
