using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public enum ConnectionHostOperation
{
    Status,
    Resolve,
    Prepare,
    Connect,
    View,
    TakeControl,
    ReleaseControl,
    Disconnect
}

public sealed record DesiredConnectionTarget(
    Uri DevBoxEndpoint,
    string Project,
    string User,
    string DevBox,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId)
{
    public DesiredConnectionRecord ToRecord(string connectionId) =>
        new DesiredConnectionRecord(
            ConnectionHostProtocol.CurrentVersion,
            connectionId,
            DevBoxEndpoint,
            Project,
            User,
            DevBox,
            SessionId,
            HostId,
            NodeIncarnationId,
            true,
            DateTimeOffset.UtcNow).Validate();
}
public sealed record ConnectionHostCommand(
    int Version,
    string RequestId,
    ConnectionHostOperation Operation,
    string? ConnectionId = null,
    string? ProviderResource = null,
    string? AuthorizationToken = null,
    long? ConnectionGeneration = null,
    string? DvcEvidenceReference = null,
    DesiredConnectionTarget? DesiredConnection = null)
{
    public override string ToString() =>
        $"ConnectionHostCommand {{ Version = {Version}, " +
        $"Operation = {Operation}, Payload = [REDACTED] }}";
}

public sealed record ConnectionHostStatus(
    int Version,
    string ConnectionId,
    RdpDvcSessionState State,
    long? ConnectionGeneration,
    bool DvcConnected,
    bool ViewSupported,
    bool ControlSupported,
    string Code,
    DateTimeOffset UpdatedAtUtc);

public sealed record ConnectionHostResponse(
    int Version,
    string RequestId,
    bool Accepted,
    string Code,
    ConnectionHostStatus? Status = null,
    IReadOnlyList<ConnectionHostStatus>? Connections = null)
{
    public override string ToString() =>
        $"ConnectionHostResponse {{ Version = {Version}, " +
        $"Accepted = {Accepted}, Code = {Code} }}";
}

public static class ConnectionHostProtocol
{
    public const int CurrentVersion = 1;
    public const int MaximumMessageBytes = 64 * 1024;
    public const int MaximumConnections = 128;
    public const int MaximumConnectionIdCharacters = 128;
    public const int MaximumRequestIdCharacters = 128;
    public const int MaximumProviderResourceCharacters = 4096;
    public const int MaximumAuthorizationTokenCharacters = 2048;
    public const int MaximumEvidenceReferenceCharacters = 128;

    private static readonly JsonSerializerOptions JsonOptions = CreateOptions();

    public static async Task<ConnectionHostCommand> ReadCommandAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var payload = await ReadFrameAsync(stream, cancellationToken)
            .ConfigureAwait(false);
        var command = JsonSerializer.Deserialize<ConnectionHostCommand>(
            payload,
            JsonOptions) ?? throw new InvalidDataException(
            "The connection-host command was empty.");
        Validate(command);
        return command;
    }

    public static Task WriteResponseAsync(
        Stream stream,
        ConnectionHostResponse response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        return WriteFrameAsync(
            stream,
            JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions),
            cancellationToken);
    }

    public static async Task WriteCommandAsync(
        Stream stream,
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        Validate(command);
        await WriteFrameAsync(
                stream,
                JsonSerializer.SerializeToUtf8Bytes(command, JsonOptions),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public static async Task<ConnectionHostResponse> ReadResponseAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var payload = await ReadFrameAsync(stream, cancellationToken)
            .ConfigureAwait(false);
        return JsonSerializer.Deserialize<ConnectionHostResponse>(
            payload,
            JsonOptions) ?? throw new InvalidDataException(
            "The connection-host response was empty.");
    }

    public static void Validate(ConnectionHostCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Version != CurrentVersion)
            throw new InvalidDataException(
                "The connection-host protocol version is unsupported.");
        RequireBounded(command.RequestId, MaximumRequestIdCharacters, "request");
        if (command.Operation != ConnectionHostOperation.Status ||
            command.ConnectionId is not null)
            RequireBounded(
                command.ConnectionId,
                MaximumConnectionIdCharacters,
                "connection");
        if (command.ProviderResource is { } provider &&
            provider.Length > MaximumProviderResourceCharacters)
            throw new InvalidDataException(
                "The provider resource exceeds its bound.");
        if (command.AuthorizationToken is { } token &&
            token.Length > MaximumAuthorizationTokenCharacters)
            throw new InvalidDataException(
                "The authorization token exceeds its bound.");
        if (command.DvcEvidenceReference is { } evidenceReference)
            RequireBounded(
                evidenceReference,
                MaximumEvidenceReferenceCharacters,
                "DVC evidence reference");
        if (command.ConnectionGeneration is <= 0)
            throw new InvalidDataException(
                "The connection generation must be positive."); if (command.DesiredConnection is not null)
        {
            if (command.ConnectionId is null ||
                command.Operation != ConnectionHostOperation.Resolve)
                throw new InvalidDataException(
                    "Desired connection identity is valid only for Resolve.");
            _ = command.DesiredConnection.ToRecord(command.ConnectionId);
        }
    }

    private static async Task<byte[]> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken)
            .ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaximumMessageBytes)
            throw new InvalidDataException(
                "The connection-host message exceeds its bound.");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken)
            .ConfigureAwait(false);
        return payload;
    }

    private static async Task WriteFrameAsync(
        Stream stream,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        if (payload.Length is <= 0 or > MaximumMessageBytes)
            throw new InvalidDataException(
                "The connection-host message exceeds its bound.");
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken)
            .ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void RequireBounded(
        string? value,
        int maximum,
        string description)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximum ||
            value.Any(char.IsControl))
            throw new InvalidDataException(
                $"The {description} identifier is invalid.");
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
