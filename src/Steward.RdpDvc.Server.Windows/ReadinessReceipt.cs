using System.Text.Json;
using System.Text.Json.Serialization;
namespace Steward.RdpDvc.Server.Windows;

public enum DvcEndpointReadinessState
{
    WaitingForActiveRdpSession,
    Handshaking,
    AuthenticatedGeneration,
    WaitingForReconnect,
    Completed,
    Exhausted
}

public sealed record DvcAuthenticatedGeneration(
    int Index,
    Guid Nonce,
    int WtsSessionId,
    long Sequence,
    DateTimeOffset AuthenticatedAtUtc);

public sealed record DvcEndpointReadinessReceipt(
    int Version,
    DvcEndpointReadinessState State,
    int ProcessId,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    int NextGeneration,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<DvcAuthenticatedGeneration> AuthenticatedGenerations);

public sealed class DvcEndpointReadinessStore(
    string path,
    Guid sessionId,
    Guid hostId,
    Guid incarnationId,
    IReadOnlyList<Guid>? expectedNonces = null)
{
    private static readonly JsonSerializerOptions Json = CreateJson();
    private readonly string _path = Path.GetFullPath(path);
    private readonly IReadOnlyList<Guid>? _expectedNonces =
        expectedNonces?.ToArray();
    private readonly int _maximumGenerations =
        expectedNonces?.Count is null
            ? 2
            : expectedNonces.Count is >= 2 and <= 256 &&
              expectedNonces.All(value => value != Guid.Empty) &&
              expectedNonces.Distinct().Count() == expectedNonces.Count
                ? expectedNonces.Count
                : throw new ArgumentException(
                    "Expected DVC nonces are invalid.",
                    nameof(expectedNonces));

    public async Task<DvcEndpointReadinessReceipt?> LoadAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
            return null;
        if (new FileInfo(_path).Length is <= 0 or > 256 * 1024)
            throw new InvalidDataException(
                "DVC endpoint readiness receipt exceeds its bound.");
        var receipt = JsonSerializer.Deserialize<
            DvcEndpointReadinessReceipt>(
            await File.ReadAllBytesAsync(_path, cancellationToken)
                .ConfigureAwait(false),
            Json) ?? throw new InvalidDataException(
            "DVC endpoint readiness receipt is empty.");
        if (receipt.Version != 1 ||
            receipt.SessionId != sessionId ||
            receipt.HostId != hostId ||
            receipt.NodeIncarnationId != incarnationId ||
            receipt.NextGeneration < 0 ||
            receipt.NextGeneration > _maximumGenerations ||
            receipt.AuthenticatedGenerations.Count > _maximumGenerations ||
            receipt.AuthenticatedGenerations.Any(value =>
                value.Index < 0 ||
                value.Index >= _maximumGenerations ||
                value.Nonce == Guid.Empty ||
                value.WtsSessionId <= 0 ||
                value.Sequence != 1) ||
            receipt.AuthenticatedGenerations
                .Select(value => value.Index)
                .Distinct()
                .Count() != receipt.AuthenticatedGenerations.Count ||
            !MatchesExpectedSequence(receipt.AuthenticatedGenerations))
            throw new InvalidDataException(
                "DVC endpoint readiness receipt is invalid.");
        return receipt;
    }

    public async Task WriteAsync(
        DvcEndpointReadinessState state,
        IReadOnlyList<DvcAuthenticatedGeneration> authenticated,
        int nextGeneration,
        CancellationToken cancellationToken)
    {
        if (authenticated.Count > _maximumGenerations ||
            authenticated.Select(value => value.Nonce).Distinct().Count() !=
            authenticated.Count ||
            !MatchesExpectedSequence(authenticated) ||
            nextGeneration < 0 ||
            nextGeneration > _maximumGenerations)
            throw new ArgumentException(
                "DVC endpoint readiness state is invalid.");
        var receipt = new DvcEndpointReadinessReceipt(
            1,
            state,
            Environment.ProcessId,
            sessionId,
            hostId,
            incarnationId,
            nextGeneration,
            DateTimeOffset.UtcNow,
            authenticated.ToArray());
        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException(
                "Readiness receipt path has no directory.");
        Directory.CreateDirectory(directory);
        var pending = _path + ".new";
        await using (var stream = new FileStream(
                         pending,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await JsonSerializer.SerializeAsync(
                    stream,
                    receipt,
                    Json,
                    cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        File.Move(pending, _path, overwrite: true);
    }

    private bool MatchesExpectedSequence(
        IReadOnlyList<DvcAuthenticatedGeneration> authenticated) =>
        authenticated.Select((value, index) =>
                value.Index == index &&
                (_expectedNonces is null ||
                 value.Nonce == _expectedNonces[index]))
            .All(value => value);

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(
            new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }
}
