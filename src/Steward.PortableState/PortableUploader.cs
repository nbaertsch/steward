using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Steward.PortableState;

public sealed record PortableUploadOptions
{
    public int BlockSizeBytes { get; init; } = 4 * 1024 * 1024;
    public TransportHashAlgorithm TransportHashAlgorithm { get; init; } = TransportHashAlgorithm.Md5;
    public TimeSpan MinimumAuthorityLifetime { get; init; } = TimeSpan.FromMinutes(5);

    public void Validate()
    {
        if (BlockSizeBytes is < 64 * 1024 or > 100 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(BlockSizeBytes));
        if (MinimumAuthorityLifetime < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(MinimumAuthorityLifetime));
    }
}

public sealed class PortableObjectUploader
{
    private readonly IPortableObjectStore _store;
    private readonly PortableUploadOptions _options;
    private readonly TimeProvider _timeProvider;

    public PortableObjectUploader(
        IPortableObjectStore store,
        PortableUploadOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options ?? new();
        _options.Validate();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public bool CanStartRemoteUpload =>
        _store.Authority.IsValidFor(
            _timeProvider.GetUtcNow() + _options.MinimumAuthorityLifetime,
            PortableStorePermission.Read | PortableStorePermission.Create | PortableStorePermission.Write);

    public async Task<PortableObjectReceipt> UploadAsync(
        string localPath,
        PortableObjectDescriptor descriptor,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(localPath);
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!CanStartRemoteUpload)
            throw new PortableStateException(
                "Remote upload cannot start because authority is expired or near expiry.",
                PortableFailureCode.RemoteAuthority);

        var existing = await _store.GetPropertiesAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
            return await VerifyCommittedAsync(descriptor, existing, cancellationToken).ConfigureAwait(false);

        await using var verifyLocal = OpenRead(localPath);
        var actualSha256 = await Hashing.Sha256HexAsync(verifyLocal, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(actualSha256, descriptor.Sha256, StringComparison.OrdinalIgnoreCase) ||
            verifyLocal.Length != descriptor.Length)
            throw new PortableStateException("Local portable object does not match its durable manifest.");

        var expected = BuildBlocks(descriptor.Length, _options.BlockSizeBytes);
        var remote = (await _store.GetUncommittedBlocksAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false))
            .ToDictionary(x => x.BlockId, StringComparer.Ordinal);

        await using var content = OpenRead(localPath);
        foreach (var block in expected)
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureUploadAuthority();
            if (remote.TryGetValue(block.Id, out var staged) && staged.Length == block.Length)
            {
                content.Position += block.Length;
                continue;
            }

            var bytes = new byte[block.Length];
            await content.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            var transactionHash = _options.TransportHashAlgorithm == TransportHashAlgorithm.Md5
                ? MD5.HashData(bytes)
                : Crc64.Compute(bytes);
            await using var blockContent = new MemoryStream(bytes, writable: false);
            await _store.StageBlockAsync(
                descriptor.ObjectName,
                block.Id,
                blockContent,
                block.Length,
                _options.TransportHashAlgorithm,
                transactionHash,
                cancellationToken).ConfigureAwait(false);
            EnsureUploadAuthority();
        }

        EnsureUploadAuthority();
        await _store.CommitBlockListAsync(
            descriptor,
            expected.Select(x => x.Id).ToArray(),
            cancellationToken).ConfigureAwait(false);
        var properties = await _store.GetPropertiesAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false)
            ?? throw new PortableStateException("Committed object properties were not visible.");
        return await VerifyCommittedAsync(descriptor, properties, cancellationToken).ConfigureAwait(false);
    }

    private async Task<PortableObjectReceipt> VerifyCommittedAsync(
        PortableObjectDescriptor descriptor,
        PortableObjectProperties properties,
        CancellationToken cancellationToken)
    {
        EnsureUploadAuthority();
        if (properties.Length != descriptor.Length ||
            !string.Equals(properties.Sha256, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Committed object properties failed integrity verification.");

        await using var downloaded = await _store.OpenReadAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false);
        var downloadedHash = await Hashing.Sha256HexAsync(downloaded, cancellationToken).ConfigureAwait(false);
        EnsureUploadAuthority();
        if (!string.Equals(downloadedHash, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Downloaded object failed whole-object SHA-256 verification.");

        return new(
            descriptor.ObjectName,
            descriptor.Sha256.ToLowerInvariant(),
            descriptor.Length,
            properties.ETag,
            _timeProvider.GetUtcNow());
    }

    private void EnsureUploadAuthority()
    {
        if (!_store.Authority.IsValidFor(
                _timeProvider.GetUtcNow(),
                PortableStorePermission.Read | PortableStorePermission.Create | PortableStorePermission.Write))
            throw new PortableStateException(
                "Portable-store authority expired during upload.",
                PortableFailureCode.RemoteAuthority);
    }

    public static string DeterministicBlockId(int index)
    {
        if (index < 0)
            throw new ArgumentOutOfRangeException(nameof(index));
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(bytes, index);
        return Convert.ToBase64String(bytes);
    }

    private static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static IReadOnlyList<(string Id, int Length)> BuildBlocks(long length, int blockSize)
    {
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));
        var result = new List<(string, int)>();
        long remaining = length;
        for (var index = 0; remaining > 0; index++)
        {
            var current = (int)Math.Min(blockSize, remaining);
            result.Add((DeterministicBlockId(index), current));
            remaining -= current;
        }
        if (length == 0)
            result.Add((DeterministicBlockId(0), 0));
        return result;
    }
}

internal static class Crc64
{
    private const ulong Polynomial = 0x42F0E1EBA9EA3693;

    public static byte[] Compute(ReadOnlySpan<byte> data)
    {
        ulong crc = 0;
        foreach (var value in data)
        {
            crc ^= (ulong)value << 56;
            for (var bit = 0; bit < 8; bit++)
                crc = (crc & 0x8000000000000000) != 0 ? (crc << 1) ^ Polynomial : crc << 1;
        }
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, crc);
        return result;
    }
}
