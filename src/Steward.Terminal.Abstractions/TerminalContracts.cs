using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Domain;

namespace Steward.Terminal.Abstractions;

public readonly record struct TerminalSessionId
{
    public Guid Value { get; }

    public TerminalSessionId(Guid value) =>
        Value = value != Guid.Empty ? value : throw new ArgumentException("Terminal session ID cannot be empty.", nameof(value));

    public static TerminalSessionId New() => new(Guid.NewGuid());

    public static TerminalSessionId Parse(string value) =>
        Guid.TryParseExact(value, "D", out var parsed) && parsed != Guid.Empty
            ? new(parsed)
            : throw new FormatException("Terminal session ID must be a non-empty GUID in D format.");

    public static bool TryParse(string? value, out TerminalSessionId result)
    {
        if (Guid.TryParseExact(value, "D", out var parsed) && parsed != Guid.Empty)
        {
            result = new(parsed);
            return true;
        }

        result = default;
        return false;
    }

    public override string ToString() => Value.ToString("D");
}

public sealed class TerminalSessionIdJsonConverter
    : JsonConverter<TerminalSessionId>
{
    public override TerminalSessionId Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
            return TerminalSessionId.Parse(reader.GetString()!);
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException(
                "TerminalSessionId must be a GUID or value object.");
        using var document = JsonDocument.ParseValue(ref reader);
        if (!document.RootElement.TryGetProperty("value", out var value) ||
            !TerminalSessionId.TryParse(value.GetString(), out var parsed))
            throw new JsonException(
                "TerminalSessionId value object is invalid.");
        return parsed;
    }

    public override void Write(
        Utf8JsonWriter writer,
        TerminalSessionId value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToString());
}

public enum TerminalTranscriptMode
{
    None,
    Metadata,
    Full
}

[Flags]
public enum TerminalFileTransferCapabilities
{
    None = 0,
    Download = 1,
    Upload = 2
}

public enum TerminalSessionState
{
    Requested,
    Opening,
    Open,
    Closing,
    Closed,
    Interrupted,
    Recovering
}

public enum TerminalStream
{
    Output
}

public enum TerminalOutputContentAvailability
{
    Available,
    MetadataOnly,
    OmittedByReadLimit,
    NotRetained
}

public enum TerminalOperationStatus
{
    Accepted,
    Applied,
    SideEffectUncertain
}

public enum TerminalShellKind
{
    PowerShell,
    Pwsh,
    CommandPrompt
}

public enum TerminalProblemDisposition
{
    RetrySafe,
    RequiresReconciliation,
    RequiresNewUserIntent,
    Terminal
}

public enum TerminalProblemCode
{
    InvalidRequest,
    AuthorityMismatch,
    AuthorityNotYetValid,
    AuthorityExpired,
    AuthorityRevoked,
    ElevationUnavailable,
    CapabilityDenied,
    PathRejected,
    RevisionConflict,
    IdempotencyConflict,
    SessionNotFound,
    SessionLimitExceeded,
    InputLimitExceeded,
    OutputLimitExceeded,
    InvalidState,
    ProcessIdentityMismatch,
    RuntimeUnavailable,
    AmbiguousOpening,
    AmbiguousOperation,
    Interrupted,
    Cancelled
}

public sealed record TerminalProblem(
    TerminalProblemCode Code,
    string Detail,
    TerminalProblemDisposition Disposition,
    bool SideEffectMayHaveOccurred);

public sealed class TerminalException : Exception
{
    public TerminalException(TerminalProblem problem) : base(problem.Detail) => Problem = problem;
    public TerminalProblem Problem { get; }
}

public sealed record TerminalTaskBinding(TaskAttemptId TaskAttemptId, int Generation);

public sealed record TerminalAuthority(
    string SchemaVersion,
    TerminalSessionId SessionId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string Actor,
    string WorkspaceRoot,
    TerminalTaskBinding? Task,
    DateTimeOffset IssuedAt,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt,
    TimeSpan MaximumDuration,
    long MaximumInputBytes,
    long MaximumOutputBytes,
    TerminalTranscriptMode TranscriptMode,
    long MaximumTranscriptBytes,
    TerminalFileTransferCapabilities FileTransferCapabilities,
    bool ElevationRequested,
    bool ElevationGranted,
    long RevocationRevision,
    TimeSpan OperationalReplayDuration = default,
    long MaximumOperationalSpoolBytes = 0);

public sealed record TerminalOpenRequest(
    string SchemaVersion,
    string RequestId,
    TerminalAuthority Authority,
    TerminalShellKind ShellKind,
    string ShellExecutable,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    int Columns,
    int Rows,
    long ExpectedRevision = 0);

public sealed record TerminalOperationContext(
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string Actor,
    long CurrentRevocationRevision);

public sealed record TerminalInputRequest(
    TerminalSessionId SessionId,
    TerminalOperationContext Context,
    string RequestId,
    long ExpectedRevision,
    ReadOnlyMemory<byte> Data);

public sealed record TerminalResizeRequest(
    TerminalSessionId SessionId,
    TerminalOperationContext Context,
    string RequestId,
    long ExpectedRevision,
    int Columns,
    int Rows);

public sealed record TerminalCloseRequest(
    TerminalSessionId SessionId,
    TerminalOperationContext Context,
    string RequestId,
    long ExpectedRevision,
    TimeSpan GracePeriod);

public sealed record TerminalOutputReadRequest(
    TerminalSessionId SessionId,
    TerminalOperationContext Context,
    long AfterSequence,
    long AfterOffset,
    int MaximumItems,
    long MaximumBytes,
    bool Follow);

public sealed record TerminalOutput(
    TerminalSessionId SessionId,
    long Sequence,
    long Offset,
    int Length,
    ReadOnlyMemory<byte> Data,
    string Sha256,
    bool EndOfStream,
    bool Historical,
    bool GapBefore,
    TerminalOutputContentAvailability ContentAvailability);

public sealed record TerminalSessionSnapshot(
    TerminalSessionId SessionId,
    TerminalSessionState State,
    long Revision,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string Actor,
    string WorkspaceRoot,
    TerminalTaskBinding? Task,
    DateTimeOffset ExpiresAt,
    long InputBytes,
    long OutputBytes,
    long InputSequence,
    long OutputSequence,
    string InputHash,
    string OutputHash,
    TerminalTranscriptMode TranscriptMode,
    long TranscriptBytes,
    bool TranscriptTruncated,
    bool UnmanagedMutationSuspected,
    string? MutationEvidence,
    int? ProcessId,
    long? ProcessCreationTimeUtcTicks,
    bool ElevationGranted,
    string ExecutionIdentity,
    string? InterruptionReason);

public interface ITerminalSessionService
{
    ValueTask<TerminalSessionSnapshot> OpenAsync(
        TerminalOpenRequest request,
        TerminalOperationContext context,
        CancellationToken cancellationToken = default);

    ValueTask<TerminalSessionSnapshot> WriteInputAsync(
        TerminalInputRequest request,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<TerminalOutput> ReadOutputAsync(
        TerminalOutputReadRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<TerminalSessionSnapshot> ResizeAsync(
        TerminalResizeRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<TerminalSessionSnapshot> CloseAsync(
        TerminalCloseRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<TerminalSessionSnapshot> GetAsync(
        TerminalSessionId sessionId,
        TerminalOperationContext context,
        CancellationToken cancellationToken = default);
}

public static class TerminalContractLimits
{
    public const string SchemaVersion = "1.0";
    public const int MaximumActorCharacters = 256;
    public const int MaximumPathCharacters = 32_767;
    public const int MaximumArgumentCount = 128;
    public const int MaximumArgumentCharacters = 32_768;
    public const int MaximumRequestIdCharacters = 128;
    public const int MaximumOutputReadItems = 1_024;
    public const long MaximumOutputReadBytes = 4L * 1024 * 1024;
    public const int MinimumColumns = 1;
    public const int MaximumColumns = 1_000;
    public const int MinimumRows = 1;
    public const int MaximumRows = 1_000;
    public const long MaximumInputBytes = 64L * 1024 * 1024;
    public const long MaximumOutputBytes = 256L * 1024 * 1024;
    public const long MaximumTranscriptBytes = 256L * 1024 * 1024;
    public const long MaximumOperationalSpoolBytes = 64L * 1024 * 1024;
    public static readonly TimeSpan MaximumLeaseDuration = TimeSpan.FromHours(8);
    public static readonly TimeSpan MaximumOperationalReplayDuration = TimeSpan.FromHours(1);
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);

    public static void ValidateOpen(TerminalOpenRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateAuthorityShape(request.Authority);
        if (!StringComparer.Ordinal.Equals(request.SchemaVersion, SchemaVersion))
            ThrowInvalid("Unsupported terminal request schema.");
        if (string.IsNullOrWhiteSpace(request.RequestId) ||
            request.RequestId.Length > MaximumRequestIdCharacters ||
            request.RequestId.Any(char.IsControl))
            ThrowInvalid("Request ID is invalid.");
        if (!Enum.IsDefined(request.ShellKind))
            ThrowInvalid("Shell kind is invalid.");
        if (!Path.IsPathFullyQualified(request.ShellExecutable) ||
            request.ShellExecutable.Length > MaximumPathCharacters ||
            request.ShellExecutable.IndexOf('\0') >= 0)
            ThrowInvalid("Shell executable must be an absolute path.");
        if (!Path.IsPathFullyQualified(request.WorkingDirectory) ||
            request.WorkingDirectory.Length > MaximumPathCharacters ||
            request.WorkingDirectory.IndexOf('\0') >= 0)
            ThrowInvalid("Working directory must be an absolute path.");
        if (request.Arguments.Count > MaximumArgumentCount ||
            request.Arguments.Any(argument => argument is null || argument.Length > MaximumArgumentCharacters || argument.IndexOf('\0') >= 0))
            ThrowInvalid("Shell argument vector is invalid.");
        ValidateSize(request.Columns, request.Rows);
        if (request.ExpectedRevision != 0)
            ThrowInvalid("A new terminal session must expect revision zero.");
    }

    public static void ValidateAuthorityShape(TerminalAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (!StringComparer.Ordinal.Equals(authority.SchemaVersion, SchemaVersion))
            ThrowInvalid("Unsupported terminal authority schema.");
        if (authority.SessionId.Value == Guid.Empty ||
            authority.HostId.Value == Guid.Empty ||
            authority.NodeIncarnationId.Value == Guid.Empty)
            ThrowInvalid("Terminal authority identity is incomplete.");
        if (string.IsNullOrWhiteSpace(authority.Actor) ||
            authority.Actor.Length > MaximumActorCharacters ||
            authority.Actor.Any(char.IsControl) ||
            LooksCredentialBearing(authority.Actor))
            ThrowInvalid("Terminal actor is invalid.");
        if (!Path.IsPathFullyQualified(authority.WorkspaceRoot) ||
            authority.WorkspaceRoot.Length > MaximumPathCharacters ||
            authority.WorkspaceRoot.IndexOf('\0') >= 0 ||
            LooksCredentialBearing(authority.WorkspaceRoot))
            ThrowInvalid("Workspace root must be an absolute local path.");
        if (authority.Task is { Generation: <= 0 })
            ThrowInvalid("Task generation must be positive.");
        if (authority.NotBefore < authority.IssuedAt - MaximumClockSkew ||
            authority.ExpiresAt <= authority.NotBefore ||
            authority.MaximumDuration <= TimeSpan.Zero ||
            authority.MaximumDuration > MaximumLeaseDuration ||
            authority.ExpiresAt - authority.IssuedAt > MaximumLeaseDuration + MaximumClockSkew)
            ThrowInvalid("Terminal authority time bounds are invalid.");
        if (authority.MaximumInputBytes <= 0 || authority.MaximumInputBytes > MaximumInputBytes ||
            authority.MaximumOutputBytes <= 0 || authority.MaximumOutputBytes > MaximumOutputBytes ||
            authority.MaximumTranscriptBytes < 0 || authority.MaximumTranscriptBytes > MaximumTranscriptBytes ||
            authority.MaximumOperationalSpoolBytes < 0 ||
            authority.MaximumOperationalSpoolBytes > MaximumOperationalSpoolBytes)
            ThrowInvalid("Terminal authority byte bounds are invalid.");
        if (authority.OperationalReplayDuration < TimeSpan.Zero ||
            authority.OperationalReplayDuration > MaximumOperationalReplayDuration ||
            (authority.MaximumOperationalSpoolBytes == 0) != (authority.OperationalReplayDuration == TimeSpan.Zero))
            ThrowInvalid("Terminal operational replay policy is invalid.");
        if (!Enum.IsDefined(authority.TranscriptMode) ||
            authority.TranscriptMode == TerminalTranscriptMode.Full && authority.MaximumTranscriptBytes == 0)
            ThrowInvalid("Terminal transcript policy is invalid.");
        if ((authority.FileTransferCapabilities & ~(TerminalFileTransferCapabilities.Download | TerminalFileTransferCapabilities.Upload)) != 0)
            ThrowInvalid("Terminal file-transfer capabilities are invalid.");
        if (authority.ElevationGranted && !authority.ElevationRequested)
            ThrowInvalid("Elevation cannot be granted when it was not requested.");
        if (authority.RevocationRevision < 0)
            ThrowInvalid("Revocation revision cannot be negative.");
    }

    public static void ValidateSize(int columns, int rows)
    {
        if (columns is < MinimumColumns or > MaximumColumns ||
            rows is < MinimumRows or > MaximumRows)
            ThrowInvalid("Terminal dimensions are outside the supported range.");
    }

    public static void ValidateRequestId(string requestId)
    {
        if (string.IsNullOrWhiteSpace(requestId) ||
            requestId.Length > MaximumRequestIdCharacters ||
            requestId.Any(char.IsControl))
            ThrowInvalid("Request ID is invalid.");
    }

    public static void ValidateOutputRead(TerminalOutputReadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.AfterSequence < 0 || request.AfterOffset < 0 ||
            request.MaximumItems is <= 0 or > MaximumOutputReadItems ||
            request.MaximumBytes is <= 0 or > MaximumOutputReadBytes)
            ThrowInvalid("Terminal output read bounds are invalid.");
    }

    [DoesNotReturn]
    private static void ThrowInvalid(string detail) =>
        throw new TerminalException(new(TerminalProblemCode.InvalidRequest, detail, TerminalProblemDisposition.Terminal, false));

    private static bool LooksCredentialBearing(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.UserInfo);
}
