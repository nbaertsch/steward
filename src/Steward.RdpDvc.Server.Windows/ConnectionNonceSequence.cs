using System.Text.Json;
namespace Steward.RdpDvc.Server.Windows;

public sealed record DvcConnectionNonceSequence(
    int Version,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    IReadOnlyList<Guid> Nonces,
    int NextIndex);

public sealed record DvcConnectionNonce(int Index, Guid Nonce);

public sealed class DvcConnectionNonceSequenceStore(string path)
{
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web);
    private readonly string _path = Path.GetFullPath(path);

    public async Task<DvcConnectionNonceSequence> InspectAsync(
        Guid sessionId,
        Guid hostId,
        Guid incarnationId,
        CancellationToken cancellationToken)
    {
        await using var lockStream = await AcquireLockAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var sequence = await ReadAsync(cancellationToken)
            .ConfigureAwait(false);
        Validate(sequence, sessionId, hostId, incarnationId);
        return sequence;
    }

    public async Task<DvcConnectionNonce> ConsumeNextAsync(
        Guid sessionId,
        Guid hostId,
        Guid incarnationId,
        CancellationToken cancellationToken)
    {
        await using var lockStream = await AcquireLockAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var sequence = await ReadAsync(cancellationToken)
            .ConfigureAwait(false);
        Validate(sequence, sessionId, hostId, incarnationId);
        if (sequence.NextIndex >= sequence.Nonces.Count)
            throw new InvalidOperationException(
                "The DVC nonce sequence is exhausted.");
        var result = new DvcConnectionNonce(
            sequence.NextIndex,
            sequence.Nonces[sequence.NextIndex]);
        await WriteAtomicAsync(
                sequence with { NextIndex = sequence.NextIndex + 1 },
                cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    private async Task<DvcConnectionNonceSequence> ReadAsync(
        CancellationToken cancellationToken)
    {
        if (new FileInfo(_path).Length is <= 0 or > 64 * 1024)
            throw new InvalidDataException(
                "The DVC nonce sequence exceeds its bound.");
        var bytes = await File.ReadAllBytesAsync(
                _path,
                cancellationToken)
            .ConfigureAwait(false);
        return JsonSerializer.Deserialize<
                   DvcConnectionNonceSequence>(bytes, Json)
               ?? throw new InvalidDataException(
                   "The DVC nonce sequence is empty.");
    }

    private static void Validate(
        DvcConnectionNonceSequence sequence,
        Guid sessionId,
        Guid hostId,
        Guid incarnationId)
    {
        if (sequence.Version != 1 ||
            sequence.SessionId != sessionId ||
            sequence.HostId != hostId ||
            sequence.NodeIncarnationId != incarnationId ||
            sequence.Nonces.Count != 2 ||
            sequence.Nonces.Any(nonce => nonce == Guid.Empty) ||
            sequence.Nonces.Distinct().Count() != 2 ||
            sequence.NextIndex is < 0 or > 2)
            throw new InvalidDataException(
                "The DVC nonce sequence is invalid or belongs to another endpoint.");
    }

    private async Task<FileStream> AcquireLockAsync(
        CancellationToken cancellationToken)
    {
        var lockPath = _path + ".lock";
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
            }
            catch (IOException) when (attempt < 100)
            {
                await Task.Delay(
                        TimeSpan.FromMilliseconds(50),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    private async Task WriteAtomicAsync(
        DvcConnectionNonceSequence sequence,
        CancellationToken cancellationToken)
    {
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
                    sequence,
                    Json,
                    cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        File.Move(pending, _path, overwrite: true);
    }
}
