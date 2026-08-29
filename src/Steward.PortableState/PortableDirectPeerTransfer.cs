using System.Security.Cryptography;

namespace Steward.PortableState;

public sealed record PortableChunkRequest(
    int Index,
    long Offset,
    int MaximumLength);

public sealed record PortableChunkReceipt(
    string ObjectName,
    string ChunkId,
    long Length,
    string Sha256,
    DateTimeOffset ReceivedAt);

public sealed record PortableChunkReadReceipt(
    int Index,
    long Offset,
    int Length,
    string Sha256);

public sealed record PortableDirectPeerTransferReceipt(
    PortableObjectReceipt Object,
    IReadOnlyList<PortableChunkReceipt> Chunks,
    int ResumedChunkCount);

public sealed record PortableDirectPeerTransferOptions
{
    public int ChunkSizeBytes { get; init; } = 1024 * 1024;
    public long MaximumObjectBytes { get; init; } = 16L * 1024 * 1024 * 1024;

    public void Validate()
    {
        if (ChunkSizeBytes is < 64 * 1024 or > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(ChunkSizeBytes));
        if (MaximumObjectBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(MaximumObjectBytes));
    }
}

public interface IPortableChunkSource
{
    Task<PortableChunkReadReceipt> CopyChunkToAsync(
        PortableChunkRequest request,
        Stream destination,
        CancellationToken cancellationToken = default);
}

public interface IPortableChunkReceiptStore
{
    Task<IReadOnlyList<PortableChunkReceipt>> GetChunkReceiptsAsync(
        string objectName,
        CancellationToken cancellationToken = default);

    Task<PortableChunkReceipt> StageChunkAsync(
        string objectName,
        string chunkId,
        Stream content,
        long length,
        string sha256,
        CancellationToken cancellationToken = default);
}

public interface IPortableDirectPeerTransfer
{
    Task<PortableDirectPeerTransferReceipt> ReceiveAsync(
        PortableObjectDescriptor descriptor,
        IPortableChunkSource source,
        CancellationToken cancellationToken = default);
}

public sealed class PortableObjectStoreDirectPeerTransfer : IPortableDirectPeerTransfer
{
    private readonly IPortableObjectStore _store;
    private readonly PortableDirectPeerTransferOptions _options;
    private readonly TimeProvider _timeProvider;

    public PortableObjectStoreDirectPeerTransfer(
        IPortableObjectStore store,
        PortableDirectPeerTransferOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options ?? new();
        _options.Validate();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<PortableDirectPeerTransferReceipt> ReceiveAsync(
        PortableObjectDescriptor descriptor,
        IPortableChunkSource source,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(source);
        PortableObjectDescriptor.ValidateObjectName(descriptor.ObjectName);
        PortableObjectDescriptor.ValidateSha256(descriptor.Sha256);
        if (descriptor.Length < 0 || descriptor.Length > _options.MaximumObjectBytes)
            throw new PortableStateException("Direct-peer object exceeds the configured transfer bound.");

        var existing = await _store.GetPropertiesAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            var receipt = await VerifyCommittedAsync(descriptor, existing, cancellationToken).ConfigureAwait(false);
            return new(receipt, [], 0);
        }

        var chunks = BuildChunks(descriptor.Length, _options.ChunkSizeBytes);
        IReadOnlyList<PortableChunkReceipt> persisted = _store is IPortableChunkReceiptStore receipts
            ? await receipts.GetChunkReceiptsAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false)
            : (await _store.GetUncommittedBlocksAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false))
                .Select(x => new PortableChunkReceipt(
                    descriptor.ObjectName, x.BlockId, x.Length, string.Empty, DateTimeOffset.MinValue))
                .ToArray();
        var resumable = persisted.ToDictionary(x => x.ChunkId, StringComparer.Ordinal);
        var allReceipts = new List<PortableChunkReceipt>(chunks.Count);
        var resumed = 0;

        foreach (var chunk in chunks)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (resumable.TryGetValue(chunk.Id, out var saved) && saved.Length == chunk.Length)
            {
                allReceipts.Add(saved);
                resumed++;
                continue;
            }

            await using var buffer = new MemoryStream(chunk.Length);
            await using var bounded = new BoundedWriteStream(buffer, chunk.Length);
            var read = await source.CopyChunkToAsync(
                new(chunk.Index, chunk.Offset, chunk.Length),
                bounded,
                cancellationToken).ConfigureAwait(false);
            if (read.Index != chunk.Index ||
                read.Offset != chunk.Offset ||
                read.Length != chunk.Length ||
                buffer.Length != chunk.Length)
                throw new PortableStateException("Direct-peer source returned a mismatched chunk receipt.");
            PortableObjectDescriptor.ValidateSha256(read.Sha256);
            buffer.Position = 0;
            var actualSha256 = await Hashing.Sha256HexAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(actualSha256, read.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new PortableStateException("Direct-peer chunk failed SHA-256 verification.");
            buffer.Position = 0;

            PortableChunkReceipt received;
            if (_store is IPortableChunkReceiptStore receiptStore)
            {
                received = await receiptStore.StageChunkAsync(
                    descriptor.ObjectName,
                    chunk.Id,
                    buffer,
                    chunk.Length,
                    actualSha256,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                var md5 = MD5.HashData(buffer.GetBuffer().AsSpan(0, chunk.Length));
                await _store.StageBlockAsync(
                    descriptor.ObjectName,
                    chunk.Id,
                    buffer,
                    chunk.Length,
                    TransportHashAlgorithm.Md5,
                    md5,
                    cancellationToken).ConfigureAwait(false);
                received = new(
                    descriptor.ObjectName,
                    chunk.Id,
                    chunk.Length,
                    actualSha256,
                    _timeProvider.GetUtcNow());
            }
            allReceipts.Add(received);
        }

        await _store.CommitBlockListAsync(
            descriptor,
            chunks.Select(x => x.Id).ToArray(),
            cancellationToken).ConfigureAwait(false);
        var properties = await _store.GetPropertiesAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false)
            ?? throw new PortableStateException("Direct-peer commit was not visible.");
        var objectReceipt = await VerifyCommittedAsync(descriptor, properties, cancellationToken).ConfigureAwait(false);
        return new(objectReceipt, allReceipts, resumed);
    }

    private async Task<PortableObjectReceipt> VerifyCommittedAsync(
        PortableObjectDescriptor descriptor,
        PortableObjectProperties properties,
        CancellationToken cancellationToken)
    {
        if (properties.Length != descriptor.Length ||
            !string.Equals(properties.Sha256, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Direct-peer committed metadata failed integrity verification.");
        await using var content = await _store.OpenReadAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false);
        var actual = await Hashing.Sha256HexAsync(content, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(actual, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Direct-peer committed content failed integrity verification.");
        return new(
            descriptor.ObjectName,
            descriptor.Sha256.ToLowerInvariant(),
            descriptor.Length,
            properties.ETag,
            _timeProvider.GetUtcNow());
    }

    private static IReadOnlyList<Chunk> BuildChunks(long length, int chunkSize)
    {
        var chunks = new List<Chunk>();
        long remaining = length;
        long offset = 0;
        for (var index = 0; remaining > 0; index++)
        {
            var current = (int)Math.Min(chunkSize, remaining);
            chunks.Add(new(index, offset, current, PortableObjectUploader.DeterministicBlockId(index)));
            offset += current;
            remaining -= current;
        }
        if (length == 0)
            chunks.Add(new(0, 0, 0, PortableObjectUploader.DeterministicBlockId(0)));
        return chunks;
    }

    private sealed record Chunk(int Index, long Offset, int Length, string Id);

    private sealed class BoundedWriteStream(Stream inner, long maximumLength) : Stream
    {
        private long _written;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _written;
        public override long Position { get => _written; set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            EnsureBound(count);
            inner.Write(buffer, offset, count);
            _written += count;
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            EnsureBound(buffer.Length);
            await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            _written += buffer.Length;
        }

        protected override void Dispose(bool disposing)
        {
            // The caller owns the underlying bounded buffer.
            base.Dispose(disposing);
        }

        private void EnsureBound(int count)
        {
            if (count < 0 || count > maximumLength - _written)
                throw new PortableStateException("Direct-peer source exceeded the requested chunk bound.");
        }
    }
}
