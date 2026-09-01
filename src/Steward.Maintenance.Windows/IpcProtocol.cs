using System.Buffers.Binary;

namespace Steward.Maintenance.Windows;

internal sealed record MaintenanceIpcOptions
{
    public MaintenanceIpcOptions(
        string pipeName,
        int maximumFrameBytes,
        int maximumConcurrentConnections,
        TimeSpan requestTimeout)
    {
        if (string.IsNullOrWhiteSpace(pipeName) ||
            pipeName.Length > 128 ||
            pipeName.Any(character =>
                !(char.IsLetterOrDigit(character) ||
                  character is '-' or '_' or '.')))
            throw new ArgumentException(
                "Maintenance pipe name is invalid.",
                nameof(pipeName));
        if (maximumFrameBytes is < 1024 or
            > MaintenanceIpcProtocol.AbsoluteMaximumFrameBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumFrameBytes));
        if (maximumConcurrentConnections is < 1 or > 16)
            throw new ArgumentOutOfRangeException(
                nameof(maximumConcurrentConnections));
        if (requestTimeout < TimeSpan.FromMilliseconds(100) ||
            requestTimeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        PipeName = pipeName;
        MaximumFrameBytes = maximumFrameBytes;
        MaximumConcurrentConnections = maximumConcurrentConnections;
        RequestTimeout = requestTimeout;
    }

    public string PipeName { get; }
    public int MaximumFrameBytes { get; }
    public int MaximumConcurrentConnections { get; }
    public TimeSpan RequestTimeout { get; }
}

public static class MaintenanceIpcProtocol
{
    public const int AbsoluteMaximumFrameBytes = 64 * 1024;

    public static async ValueTask WriteRequestAsync(
        Stream stream,
        AuthenticatedMaintenanceRequest request,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ValidateMaximum(maximumBytes);
        var payload = MaintenanceContract.Serialize(request);
        if (payload.Length > maximumBytes)
            throw new InvalidDataException(
                "Maintenance request exceeds its configured bound.");
        var prefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix, cancellationToken)
            .ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<AuthenticatedMaintenanceRequest>
        ReadRequestAsync(
            Stream stream,
            int maximumBytes,
            CancellationToken cancellationToken)
    {
        ValidateMaximum(maximumBytes);
        var prefix = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(prefix, cancellationToken)
            .ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length <= 0 || length > maximumBytes ||
            length > AbsoluteMaximumFrameBytes)
            throw new InvalidDataException(
                "Maintenance frame length is invalid.");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken)
            .ConfigureAwait(false);
        return MaintenanceContract.Parse(payload);
    }

    public static async ValueTask<MaintenanceResponse> ReadResponseAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ValidateMaximum(maximumBytes);
        var prefix = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(prefix, cancellationToken)
            .ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length <= 0 || length > maximumBytes ||
            length > AbsoluteMaximumFrameBytes)
            throw new InvalidDataException(
                "Maintenance response length is invalid.");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<
                       MaintenanceResponse>(payload) ??
                   throw new InvalidDataException(
                       "Maintenance response is empty.");
        }
        catch (System.Text.Json.JsonException exception)
        {
            throw new InvalidDataException(
                "Maintenance response is malformed.",
                exception);
        }
    }

    public static async ValueTask WriteResponseAsync(
        Stream stream,
        MaintenanceResponse response,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ValidateMaximum(maximumBytes);
        var payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            response);
        if (payload.Length is <= 0 || payload.Length > maximumBytes ||
            payload.Length > AbsoluteMaximumFrameBytes)
            throw new InvalidDataException(
                "Maintenance response exceeds its configured bound.");
        var prefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix, cancellationToken)
            .ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask WriteChallengeAsync(
        Stream stream,
        MaintenanceSessionChallenge challenge,
        int maximumBytes,
        CancellationToken cancellationToken) =>
        await WriteJsonFrameAsync(
                stream,
                challenge,
                maximumBytes,
                cancellationToken)
            .ConfigureAwait(false);

    public static async ValueTask<MaintenanceSessionChallenge>
        ReadChallengeAsync(
            Stream stream,
            int maximumBytes,
            CancellationToken cancellationToken)
    {
        var payload = await ReadFrameAsync(
                stream,
                maximumBytes,
                cancellationToken)
            .ConfigureAwait(false);
        return Deserialize<MaintenanceSessionChallenge>(
            payload,
            "Maintenance challenge");
    }

    public static async ValueTask WriteSubmissionAsync(
        Stream stream,
        MaintenanceIpcSubmission submission,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(submission);
        _ = MaintenanceContract.Serialize(submission.Request);
        ArgumentNullException.ThrowIfNull(submission.Proof);
        await WriteJsonFrameAsync(
                stream,
                submission,
                maximumBytes,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public static async ValueTask<MaintenanceIpcSubmission>
        ReadSubmissionAsync(
            Stream stream,
            int maximumBytes,
            CancellationToken cancellationToken)
    {
        var payload = await ReadFrameAsync(
                stream,
                maximumBytes,
                cancellationToken)
            .ConfigureAwait(false);
        var submission = Deserialize<MaintenanceIpcSubmission>(
            payload,
            "Maintenance submission");
        _ = MaintenanceContract.Serialize(submission.Request);
        ArgumentNullException.ThrowIfNull(submission.Proof);
        return submission;
    }

    private static async ValueTask WriteJsonFrameAsync<T>(
        Stream stream,
        T value,
        int maximumBytes,
        CancellationToken cancellationToken)
        where T : notnull
    {
        ValidateMaximum(maximumBytes);
        var payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            value,
            MaintenanceIpcJson.Options);
        if (payload.Length is <= 0 || payload.Length > maximumBytes ||
            payload.Length > AbsoluteMaximumFrameBytes)
            throw new InvalidDataException(
                "Maintenance frame exceeds its configured bound.");
        var prefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix, cancellationToken)
            .ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> ReadFrameAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ValidateMaximum(maximumBytes);
        var prefix = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(prefix, cancellationToken)
            .ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length <= 0 || length > maximumBytes ||
            length > AbsoluteMaximumFrameBytes)
            throw new InvalidDataException(
                "Maintenance frame length is invalid.");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken)
            .ConfigureAwait(false);
        return payload;
    }

    private static T Deserialize<T>(byte[] payload, string name)
        where T : notnull
    {
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<T>(
                       payload,
                       MaintenanceIpcJson.Options) ??
                   throw new InvalidDataException($"{name} is empty.");
        }
        catch (System.Text.Json.JsonException exception)
        {
            throw new InvalidDataException(
                $"{name} is malformed.",
                exception);
        }
    }
    private static void ValidateMaximum(int maximumBytes)
    {
        if (maximumBytes is < 1024 or > AbsoluteMaximumFrameBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
    }
}


internal static class MaintenanceIpcJson
{
    internal static System.Text.Json.JsonSerializerOptions Options { get; } =
        new(System.Text.Json.JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling =
                System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
            MaxDepth = 32
        };
}
