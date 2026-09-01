using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Contracts;
using Steward.Maintenance.Windows;

namespace Steward.Orchestration;

public sealed class OrchestrationMessageException(string message) : InvalidOperationException(message);

internal static class OrchestrationMessageCodec
{
    public const int MaximumPayloadBytes = 256 * 1024;
    public const int MaximumTextLength = 4096;
    public const int MaximumCollectionCount = 1000;
    private const string Schema = "steward.orchestration-message";
    private const string Version = "1.0";
    private static readonly JsonSerializerOptions Options = CreateOptions();

    public static ReadOnlyMemory<byte> Encode(object message, DateTimeOffset createdAt)
    {
        var kind = KindOf(message);
        Validate(kind, message);
        var payload = JsonSerializer.SerializeToElement(message, message.GetType(), Options);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new OrchestrationEnvelope(
            Schema, Version, kind, createdAt, payload), Options);
        if (bytes.Length > MaximumPayloadBytes)
            throw new OrchestrationMessageException("Orchestration message exceeds the payload limit.");
        return bytes;
    }

    public static DecodedOrchestrationMessage Decode(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.IsEmpty || bytes.Length > MaximumPayloadBytes)
            throw new OrchestrationMessageException("Orchestration message payload is empty or too large.");
        OrchestrationEnvelope envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<OrchestrationEnvelope>(bytes.Span, Options)
                ?? throw new OrchestrationMessageException("Orchestration envelope is null.");
        }
        catch (JsonException exception)
        {
            throw new OrchestrationMessageException($"Invalid orchestration JSON: {exception.Message}");
        }
        if (envelope.Schema != Schema || envelope.Version != Version)
            throw new OrchestrationMessageException("Unsupported orchestration message schema or version.");
        var value = DeserializePayload(envelope.Kind, envelope.Payload);
        Validate(envelope.Kind, value);
        return new(envelope.Kind, value);
    }

    public static object DecodeJournaledFact(string kind, string payloadJson)
    {
        if (kind is OrchestrationMessageKinds.IdentityDeliveryRequest or
            OrchestrationMessageKinds.IdentityDelivery)
            throw new OrchestrationMessageException(
                "Identity delivery messages are ephemeral and cannot be journaled.");
        if (Encoding.UTF8.GetByteCount(payloadJson) > MaximumPayloadBytes)
            throw new OrchestrationMessageException("Journaled fact exceeds the payload limit.");
        using var document = JsonDocument.Parse(payloadJson, new JsonDocumentOptions { MaxDepth = 64 });
        var value = DeserializePayload(kind, document.RootElement);
        Validate(kind, value);
        return value;
    }

    private static object DeserializePayload(string kind, JsonElement payload) => kind switch
    {
        OrchestrationMessageKinds.Delegation => Deserialize<DelegationMessage>(payload),
        OrchestrationMessageKinds.ExecuteTask => Deserialize<ExecuteTaskMessage>(payload),
        OrchestrationMessageKinds.CancelTask => Deserialize<CancelTaskMessage>(payload),
        OrchestrationMessageKinds.FactAcknowledgement => Deserialize<FactAcknowledgementMessage>(payload),
        OrchestrationMessageKinds.DelegationAccepted => Deserialize<DelegationAcceptedFact>(payload),
        OrchestrationMessageKinds.TaskAccepted => Deserialize<TaskAcceptedFact>(payload),
        OrchestrationMessageKinds.TaskRunning => Deserialize<TaskRunningFact>(payload),
        OrchestrationMessageKinds.TaskProgress => Deserialize<TaskProgressFact>(payload),
        OrchestrationMessageKinds.TaskLogCursor => Deserialize<TaskLogCursorFact>(payload),
        OrchestrationMessageKinds.TaskArtifact => Deserialize<TaskArtifactFact>(payload),
        OrchestrationMessageKinds.TaskCheckpoint => Deserialize<TaskCheckpointFact>(payload),
        OrchestrationMessageKinds.TaskTerminal => Deserialize<TaskTerminalFact>(payload),
        OrchestrationMessageKinds.TaskRecovery => Deserialize<TaskRecoveryFact>(payload),
        OrchestrationMessageKinds.CommandAcknowledged => Deserialize<CommandAcknowledgedFact>(payload),
        OrchestrationMessageKinds.AgentActivity => Deserialize<AgentActivityFact>(payload),
        OrchestrationMessageKinds.AgentFinal => Deserialize<AgentFinalFact>(payload),
        OrchestrationMessageKinds.RateFeedback => Deserialize<RateFeedbackFact>(payload),
        OrchestrationMessageKinds.IdentityDeliveryRequest => Deserialize<DirectIdentityDeliveryRequest>(payload),
        OrchestrationMessageKinds.IdentityDelivery => Deserialize<EncryptedIdentityDelivery>(payload),
        OrchestrationMessageKinds.MaintenanceRequest =>
            Deserialize<LocalMaintenanceRequestMessage>(payload),
        OrchestrationMessageKinds.MaintenanceResult =>
            Deserialize<LocalMaintenanceResultFact>(payload),
        _ => throw new OrchestrationMessageException($"Unknown message discriminator '{kind}'.")
    };

    private static T Deserialize<T>(JsonElement payload) =>
        payload.Deserialize<T>(Options) ?? throw new OrchestrationMessageException($"Message payload '{typeof(T).Name}' is null.");

    private static string KindOf(object value) => value switch
    {
        DelegationMessage => OrchestrationMessageKinds.Delegation,
        ExecuteTaskMessage => OrchestrationMessageKinds.ExecuteTask,
        CancelTaskMessage => OrchestrationMessageKinds.CancelTask,
        FactAcknowledgementMessage => OrchestrationMessageKinds.FactAcknowledgement,
        DelegationAcceptedFact => OrchestrationMessageKinds.DelegationAccepted,
        TaskAcceptedFact => OrchestrationMessageKinds.TaskAccepted,
        TaskRunningFact => OrchestrationMessageKinds.TaskRunning,
        TaskProgressFact => OrchestrationMessageKinds.TaskProgress,
        TaskLogCursorFact => OrchestrationMessageKinds.TaskLogCursor,
        TaskArtifactFact => OrchestrationMessageKinds.TaskArtifact,
        TaskCheckpointFact => OrchestrationMessageKinds.TaskCheckpoint,
        TaskTerminalFact => OrchestrationMessageKinds.TaskTerminal,
        TaskRecoveryFact => OrchestrationMessageKinds.TaskRecovery,
        CommandAcknowledgedFact => OrchestrationMessageKinds.CommandAcknowledged,
        AgentActivityFact => OrchestrationMessageKinds.AgentActivity,
        AgentFinalFact => OrchestrationMessageKinds.AgentFinal,
        RateFeedbackFact => OrchestrationMessageKinds.RateFeedback,
        DirectIdentityDeliveryRequest => OrchestrationMessageKinds.IdentityDeliveryRequest,
        EncryptedIdentityDelivery => OrchestrationMessageKinds.IdentityDelivery,
        LocalMaintenanceRequestMessage =>
            OrchestrationMessageKinds.MaintenanceRequest,
        LocalMaintenanceResultFact =>
            OrchestrationMessageKinds.MaintenanceResult,
        _ => throw new OrchestrationMessageException($"CLR type '{value.GetType().Name}' is not a registered wire message.")
    };

    private static void Validate(string kind, object value)
    {
        static void Text(string? text, string name, bool required = true)
        {
            if ((required && string.IsNullOrWhiteSpace(text)) || (text?.Length ?? 0) > MaximumTextLength)
                throw new OrchestrationMessageException($"{name} is missing or exceeds its bound.");
        }
        static void Identity(AttemptIdentity identity)
        {
            if (identity.Generation <= 0)
                throw new OrchestrationMessageException("Attempt generation must be positive.");
        }

        switch (value)
        {
            case DelegationMessage message:
                if (message.Delegation.AllowedGenerations.Count is 0 or > MaximumCollectionCount ||
                    message.Delegation.TaskAuthorityBindings is null ||
                    message.Delegation.TaskAuthorityBindings.Count != message.Delegation.AllowedGenerations.Count)
                    throw new OrchestrationMessageException("Delegation Task authority is missing or exceeds its bound.");
                break;
            case ExecuteTaskMessage message:
                Identity(message.Identity);
                Text(message.TaskType, nameof(message.TaskType));
                Text(message.TaskTypeVersion, nameof(message.TaskTypeVersion));
                Text(message.InputMediaType, nameof(message.InputMediaType));
                Text(message.InputSchemaVersion, nameof(message.InputSchemaVersion));
                Text(message.Workspace, nameof(message.Workspace));
                if (Encoding.UTF8.GetByteCount(message.InputJson) > Steward.Scheduling.TaskInput.MaximumUtf8Bytes ||
                    message.RateRequirements.Count > 32 || message.IdentityGrantIds.Count > 64 ||
                    (message.IdentityGrants?.Count ?? 0) > 64)
                    throw new OrchestrationMessageException("Execute Task input or authority declarations exceed their bound.");
                if ((message.IdentityGrants ?? []).Select(x => x.IdentityGrantId).ToHashSet()
                    .SetEquals(message.IdentityGrantIds) == false)
                    throw new OrchestrationMessageException(
                        "Identity delivery references do not exactly match delegated grant IDs.");
                foreach (var grant in message.IdentityGrants ?? [])
                {
                    if (grant.WorkloadId != message.Identity.WorkloadId ||
                        grant.TaskId != message.Identity.TaskId ||
                        grant.Generation != message.Identity.Generation ||
                        grant.HostId != message.Identity.HostId ||
                        grant.NodeIncarnationId != message.Identity.NodeIncarnationId ||
                        grant.ExpiresAt <= DateTimeOffset.UnixEpoch ||
                        string.IsNullOrWhiteSpace(grant.Audience) ||
                        grant.Scopes.Count is 0 or > 64 ||
                        grant.Scopes.Any(string.IsNullOrWhiteSpace))
                        throw new OrchestrationMessageException(
                            "Identity delivery reference is invalid or not bound to this Task generation.");
                }
                ValidateCommand(message.Command, message.Identity);
                break;
            case CancelTaskMessage message:
                Identity(message.Identity);
                if (message.GracePeriodMilliseconds is < 0 or > 300_000)
                    throw new OrchestrationMessageException("Cancellation grace period is outside its bound.");
                ValidateCommand(message.Command, message.Identity, requireCorrelationCommand: false);
                break;
            case FactAcknowledgementMessage message when message.ThroughCursor < 0:
                throw new OrchestrationMessageException("Acknowledgement cursor cannot be negative.");
            case TaskAcceptedFact message: Identity(message.Identity); break;
            case TaskRunningFact message: Identity(message.Identity); break;
            case TaskProgressFact message:
                Identity(message.Identity);
                if (!double.IsFinite(message.Fraction) || message.Fraction is < 0 or > 1)
                    throw new OrchestrationMessageException("Progress fraction must be finite and between zero and one.");
                Text(message.Message, nameof(message.Message), false);
                break;
            case TaskLogCursorFact message:
                Identity(message.Identity); Text(message.Stream, nameof(message.Stream)); Text(message.ContentHash, nameof(message.ContentHash));
                if (message.Offset < 0 || message.Length < 0) throw new OrchestrationMessageException("Log cursor values cannot be negative.");
                break;
            case TaskArtifactFact message:
                Identity(message.Identity); Text(message.Name, nameof(message.Name)); Text(message.MediaType, nameof(message.MediaType));
                Text(message.Reference, nameof(message.Reference)); Text(message.ContentHash, nameof(message.ContentHash));
                if (message.SizeBytes < 0) throw new OrchestrationMessageException("Artifact size cannot be negative.");
                break;
            case TaskCheckpointFact message:
                Identity(message.Identity); Text(message.Reference, nameof(message.Reference)); Text(message.ContentHash, nameof(message.ContentHash));
                if (message.SizeBytes < 0) throw new OrchestrationMessageException("Checkpoint size cannot be negative.");
                break;
            case TaskTerminalFact message:
                Identity(message.Identity); Text(message.Receipt, nameof(message.Receipt)); Text(message.Detail, nameof(message.Detail), false);
                if (message.State is not (Domain.TaskAttemptState.Succeeded or Domain.TaskAttemptState.Failed or
                    Domain.TaskAttemptState.Cancelled or Domain.TaskAttemptState.Interrupted or Domain.TaskAttemptState.Checkpointed))
                    throw new OrchestrationMessageException("Terminal fact has a nonterminal state.");
                break;
            case TaskRecoveryFact message:
                Identity(message.Identity); Text(message.Code, nameof(message.Code)); Text(message.Detail, nameof(message.Detail));
                break;
            case CommandAcknowledgedFact message:
                Identity(message.Identity); Text(message.Operation, nameof(message.Operation));
                break;
            case AgentActivityFact message:
                Identity(message.Identity); Text(message.Text, nameof(message.Text)); break;
            case AgentFinalFact message:
                Identity(message.Identity); Text(message.Text, nameof(message.Text));
                Text(message.Receipt, nameof(message.Receipt)); break;
            case RateFeedbackFact message:
                if (message.FeedbackSequence <= 0 || message.RetryAfter <= DateTimeOffset.UnixEpoch)
                    throw new OrchestrationMessageException("Rate feedback identity is invalid.");
                Text(message.Scope, nameof(message.Scope)); break;
            case DirectIdentityDeliveryRequest message:
                Identity(message.Identity);
                if (message.RequestId == Guid.Empty ||
                    message.Grant.UseId == Guid.Empty ||
                    message.RecipientPublicKey.Length is < 64 or > 512 ||
                    message.Grant.IdentityGrantId == default ||
                    message.Grant.WorkloadId != message.Identity.WorkloadId ||
                    message.Grant.TaskId != message.Identity.TaskId ||
                    message.Grant.Generation != message.Identity.Generation ||
                    message.Grant.HostId != message.Identity.HostId ||
                    message.Grant.NodeIncarnationId != message.Identity.NodeIncarnationId ||
                    message.Grant.ExpiresAt <= DateTimeOffset.UnixEpoch ||
                    string.IsNullOrWhiteSpace(message.Grant.Audience) ||
                    message.Grant.Scopes.Count is 0 or > 64 ||
                    message.Grant.Scopes.Any(string.IsNullOrWhiteSpace))
                    throw new OrchestrationMessageException(
                        "Identity delivery request is invalid or not exactly bound to its Task use.");
                break;
            case LocalMaintenanceRequestMessage message:
                if (message.Version != 1 ||
                    message.HostId == default ||
                    message.NodeIncarnationId == default)
                    throw new OrchestrationMessageException(
                        "Local maintenance request identity is invalid.");
                try
                {
                    MaintenanceContract.Validate(message.Request.Body);
                    _ = MaintenanceContract.Serialize(message.Request);
                }
                catch (Exception exception) when (exception is
                    MaintenanceProtocolException or InvalidDataException or
                    FormatException)
                {
                    throw new OrchestrationMessageException(
                        "Local maintenance request contract is invalid.");
                }
                break;
            case LocalMaintenanceResultFact message:
                if (message.Version != 1 ||
                    message.HostId == default ||
                    message.NodeIncarnationId == default ||
                    message.Result.ProtocolVersion !=
                        MaintenanceContract.ProtocolVersion ||
                    message.Result.RequestId == Guid.Empty ||
                    message.Result.OperationId == Guid.Empty ||
                    message.Result.OperationDigest is null ||
                    !Enum.IsDefined(message.Result.Status))
                    throw new OrchestrationMessageException(
                        "Local maintenance result identity is invalid.");
                break;
            case EncryptedIdentityDelivery message:
                if (message.RequestId == Guid.Empty ||
                    message.UseId == Guid.Empty ||
                    message.ExpiresAt <= DateTimeOffset.UnixEpoch ||
                    message.SenderPublicKey.Length is < 64 or > 512 ||
                    message.Nonce.Length != 12 ||
                    message.AuthenticationTag.Length != 16 ||
                    message.Ciphertext.Length is < 5 or > MaximumPayloadBytes)
                    throw new OrchestrationMessageException(
                        "Encrypted identity delivery has invalid bounds.");
                break;
        }
        _ = kind;
    }

    private static void ValidateCommand(
        CommandDto command,
        AttemptIdentity identity,
        bool requireCorrelationCommand = true)
    {
        if ((requireCorrelationCommand && command.CommandId != identity.CommandId) ||
            command.ExpectedAttemptGeneration != identity.Generation ||
            command.ExpectedNodeIncarnationId != identity.NodeIncarnationId)
            throw new OrchestrationMessageException("Command fences do not match its attempt identity.");
        if (string.IsNullOrWhiteSpace(command.IdempotencyKey) || command.IdempotencyKey.Length > 256 ||
            command.Deadline == default)
            throw new OrchestrationMessageException("Command idempotency identity or deadline is invalid.");
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(StewardJson.Options)
        {
            MaxDepth = 64,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };
        return options;
    }
}
