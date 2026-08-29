using System.Text.Json.Serialization;
using Steward.Rdp.Windows;

namespace Steward.DevBox.LiveAcceptance;

internal enum LiveRunPhase
{
    Planned,
    CreateStarted,
    BoxReady,
    GatewayGatePassed,
    DvcPending,
    DeleteStarted,
    Deleted
}

internal sealed record DurableRunState(
    int Version,
    string ConfigurationFingerprint,
    string EndpointOrigin,
    string Project,
    string Pool,
    string User,
    string BoxName,
    bool HarnessOwnsBox,
    LiveRunPhase Phase,
    string? CreateOperationId,
    string? CreateStatusUriSha256,
    string? DeleteOperationId,
    string? DeleteStatusUriSha256,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

internal enum GateOutcome
{
    Passed,
    Failed,
    Pending
}

internal sealed record GateEvidence(
    string Name,
    GateOutcome Outcome,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset FinishedAtUtc,
    string Code,
    IReadOnlyList<RdpDiagnosticEvent>? RdpEvents = null,
    int? DisconnectReason = null,
    int? ExtendedDisconnectReason = null,
    int? FatalErrorCode = null,
    int? LogonErrorCode = null,
    bool? GatewayUseObserved = null,
    string? GatewayRemoteEndpoint = null);

internal sealed record AcceptanceEvidence(
    int Version,
    string RunId,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset FinishedAtUtc,
    string EndpointOrigin,
    string Project,
    string Pool,
    string User,
    string BoxName,
    bool BillableCreateExplicitlyAllowed,
    bool CleanupExplicitlyRequested,
    string AzureDeveloperDevCenterVersion,
    string RdpActiveXProvenance,
    IReadOnlyList<GateEvidence> Gates,
    GateOutcome OverallOutcome);

[JsonSerializable(typeof(DurableRunState))]
[JsonSerializable(typeof(AcceptanceEvidence))]
[JsonSourceGenerationOptions(WriteIndented = true)]
internal sealed partial class HarnessJsonContext : JsonSerializerContext;
