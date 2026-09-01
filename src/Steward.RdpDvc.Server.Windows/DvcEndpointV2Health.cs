using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Contracts;

namespace Steward.RdpDvc.Server.Windows;

public sealed class DvcEndpointV2HealthStore
{
    private const int MaximumBytes = 64 * 1024;
    private static readonly JsonSerializerOptions Json = CreateJson();
    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.CamelCase,
            allowIntegerValues: false));
        return options;
    }
    private readonly string path;
    private readonly Guid sessionId;
    private readonly Guid hostId;
    private readonly Guid nodeIncarnationId;
    private readonly string nodeIdentity;
    private readonly string controlIdentity;
    private readonly byte[] authenticationKey;
    private readonly DateTimeOffset processStartedAtUtc;
    private readonly SemaphoreSlim gate = new(1, 1);

    public DvcEndpointV2HealthStore(
        string path,
        Guid sessionId,
        Guid hostId,
        Guid nodeIncarnationId,
        string nodeIdentity,
        string controlIdentity,
        ReadOnlySpan<byte> authenticationKey)
    {
        var identityProbe = new EndpointV2Health(
            EndpointV2HealthContract.Version,
            sessionId,
            hostId,
            nodeIncarnationId,
            nodeIdentity,
            controlIdentity,
            EndpointV2HealthState.WaitingForActiveRdpSession,
            0,
            null,
            null,
            DateTimeOffset.UtcNow,
            Environment.ProcessId,
            DateTimeOffset.UtcNow - TimeSpan.FromSeconds(1));
        EndpointV2HealthContract.Validate(identityProbe);
        if (!Path.IsPathFullyQualified(path) ||
            !string.Equals(
                Path.GetFileName(path),
                EndpointStateFiles.V2Health,
                StringComparison.Ordinal))
            throw new ArgumentException(
                "The v2 endpoint health path is invalid.",
                nameof(path));
        this.path = Path.GetFullPath(path);
        this.sessionId = sessionId;
        this.hostId = hostId;
        this.nodeIncarnationId = nodeIncarnationId;
        this.nodeIdentity = nodeIdentity;
        this.controlIdentity = controlIdentity;
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "Endpoint health authentication requires a 256-bit key.",
                nameof(authenticationKey));
        this.authenticationKey = authenticationKey.ToArray();
        processStartedAtUtc = Process.GetCurrentProcess()
            .StartTime.ToUniversalTime();
    }

    public async Task<AuthenticatedEndpointV2Health?> LoadAsync(
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await LoadCoreAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task WriteAsync(
        EndpointV2HealthState state,
        long generation,
        Guid? attemptId,
        int? wtsSessionId,
        CancellationToken cancellationToken)
    {
        var value = new EndpointV2Health(
            EndpointV2HealthContract.Version,
            sessionId,
            hostId,
            nodeIncarnationId,
            nodeIdentity,
            controlIdentity,
            state,
            generation,
            attemptId,
            wtsSessionId,
            DateTimeOffset.UtcNow,
            Environment.ProcessId,
            DateTimeOffset.UtcNow - TimeSpan.FromSeconds(1));
        EndpointV2HealthContract.Validate(value);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var prior = await LoadCoreAsync(cancellationToken)
                .ConfigureAwait(false);
            if (prior is not null &&
                (generation < prior.Observation.ReconnectGeneration ||
                 generation == prior.Observation.ReconnectGeneration &&
                 prior.Observation.AttemptId is { } priorAttempt &&
                 attemptId != priorAttempt))
                throw new InvalidOperationException(
                    "The v2 endpoint health generation cannot move backward or change attempt.");
            var authenticated = EndpointV2HealthAuthenticator.Authenticate(
                value,
                authenticationKey);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(
                authenticated,
                Json);
            if (bytes.Length > MaximumBytes)
                throw new InvalidDataException(
                    "The v2 endpoint health exceeds its bound.");
            var directory = Path.GetDirectoryName(path) ??
                throw new InvalidDataException(
                    "The v2 endpoint health path has no directory.");
            Directory.CreateDirectory(directory);
            var replacement = path + "." +
                Guid.NewGuid().ToString("N") + ".new";
            try
            {
                await using (var stream = new FileStream(
                                 replacement,
                                 FileMode.CreateNew,
                                 FileAccess.Write,
                                 FileShare.None,
                                 4096,
                                 FileOptions.Asynchronous |
                                 FileOptions.WriteThrough))
                {
                    await stream.WriteAsync(bytes, cancellationToken)
                        .ConfigureAwait(false);
                    await stream.FlushAsync(cancellationToken)
                        .ConfigureAwait(false);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(replacement, path, overwrite: true);
            }
            finally
            {
                if (File.Exists(replacement))
                    File.Delete(replacement);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<AuthenticatedEndpointV2Health?> LoadCoreAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return null;
        var attributes = File.GetAttributes(path);
        var information = new FileInfo(path);
        if (attributes.HasFlag(FileAttributes.Directory) ||
            attributes.HasFlag(FileAttributes.ReparsePoint) ||
            information.Length is <= 0 or > MaximumBytes)
            throw new InvalidDataException(
                "The v2 endpoint health file is unsafe or invalid.");
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var authenticated = await JsonSerializer.DeserializeAsync<
                AuthenticatedEndpointV2Health>(
                stream,
                Json,
                cancellationToken)
            .ConfigureAwait(false) ??
            throw new InvalidDataException(
                "The v2 endpoint health file is empty.");
        var value = EndpointV2HealthAuthenticator.Verify(
            authenticated,
            authenticationKey);
        if (value.SessionId != sessionId ||
            value.HostId != hostId ||
            value.NodeIncarnationId != nodeIncarnationId ||
            !string.Equals(value.NodeIdentity, nodeIdentity,
                StringComparison.Ordinal) ||
            !string.Equals(value.ControlIdentity, controlIdentity,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "The v2 endpoint health belongs to another identity.");
        return authenticated;
    }
}
