using System.Security.Cryptography;
using Steward.PortableState;

namespace Steward.PortableState.Tests;

internal sealed class InMemoryBlockStore : IPortableObjectStore
{
    private readonly Dictionary<string, Dictionary<string, byte[]>> _staged = [];
    private readonly Dictionary<string, (byte[] Content, PortableObjectProperties Properties)> _committed = [];
    private readonly Dictionary<string, (byte[] Content, string ETag, string Sha256)> _manifests = [];
    private int _etag;

    public PortableStoreAuthority Authority { get; set; } = new(
        DateTimeOffset.MaxValue,
        PortableStorePermission.Read | PortableStorePermission.Create | PortableStorePermission.Write,
        "fake");

    public int StageCalls { get; private set; }
    public int CommitCalls { get; private set; }
    public int ManifestCalls { get; private set; }
    public bool CorruptCommittedDownload { get; set; }
    public bool FailPropertiesOnceAfterCommit { get; set; }
    public bool FailManifestOnce { get; set; }
    public bool TamperExistingManifestContent { get; set; }
    public Exception? PropertiesException { get; set; }
    public Action? AfterStage { get; set; }

    public void ExpireUncommitted() => _staged.Clear();

    public Task<IReadOnlyList<StagedBlock>> GetUncommittedBlocksAsync(
        string objectName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<StagedBlock> result = _staged.TryGetValue(objectName, out var blocks)
            ? blocks.Select(x => new StagedBlock(x.Key, x.Value.LongLength)).ToArray()
            : [];
        return Task.FromResult(result);
    }

    public async Task StageBlockAsync(
        string objectName,
        string blockId,
        Stream content,
        long length,
        TransportHashAlgorithm hashAlgorithm,
        ReadOnlyMemory<byte> transactionalHash,
        CancellationToken cancellationToken = default)
    {
        using var memory = new MemoryStream();
        await content.CopyToAsync(memory, cancellationToken);
        var bytes = memory.ToArray();
        if (bytes.LongLength != length)
            throw new PortableStateException("Transactional block length mismatch.");
        var actual = hashAlgorithm == TransportHashAlgorithm.Md5
            ? MD5.HashData(bytes)
            : TestCrc64(bytes);
        if (!actual.AsSpan().SequenceEqual(transactionalHash.Span))
            throw new PortableStateException("Transactional block hash mismatch.");
        if (!_staged.TryGetValue(objectName, out var blocks))
            _staged[objectName] = blocks = [];
        blocks[blockId] = bytes;
        StageCalls++;
        AfterStage?.Invoke();
    }

    public Task<string> CommitBlockListAsync(
        PortableObjectDescriptor descriptor,
        IReadOnlyList<string> orderedBlockIds,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (PropertiesException is { } propertiesException)
        {
            PropertiesException = null;
            throw propertiesException;
        }
        CommitCalls++;
        if (_committed.TryGetValue(descriptor.ObjectName, out var existing))
        {
            if (existing.Properties.Sha256 == descriptor.Sha256)
                return Task.FromResult(existing.Properties.ETag);
            throw new PortableStateException("Immutable object conflict.");
        }
        if (!_staged.TryGetValue(descriptor.ObjectName, out var blocks))
            throw new PortableStateException("No blocks staged.");
        using var content = new MemoryStream();
        foreach (var id in orderedBlockIds)
        {
            if (!blocks.TryGetValue(id, out var bytes))
                throw new PortableStateException($"Missing block '{id}'.");
            content.Write(bytes);
        }
        var body = content.ToArray();
        var hash = Convert.ToHexStringLower(SHA256.HashData(body));
        if (hash != descriptor.Sha256 || body.LongLength != descriptor.Length)
            throw new PortableStateException("Whole-object hash mismatch.");
        var etag = $"\"fake-{++_etag}\"";
        var metadata = new Dictionary<string, string>(descriptor.Lineage)
        {
            ["sha256"] = descriptor.Sha256,
            ["schemaVersion"] = descriptor.SchemaVersion,
            ["logicalObjectId"] = descriptor.LogicalObjectId
        };
        _committed[descriptor.ObjectName] = (
            body,
            new(body.LongLength, hash, etag, metadata));
        _staged.Remove(descriptor.ObjectName);
        return Task.FromResult(etag);
    }

    public Task<PortableObjectProperties?> GetPropertiesAsync(
        string objectName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (FailPropertiesOnceAfterCommit && _committed.ContainsKey(objectName))
        {
            FailPropertiesOnceAfterCommit = false;
            throw new IOException("Simulated crash after commit.");
        }
        return Task.FromResult(
            _committed.TryGetValue(objectName, out var value)
                ? value.Properties
                : null);
    }

    public Task<Stream> OpenReadAsync(string objectName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bytes = _committed[objectName].Content.ToArray();
        if (CorruptCommittedDownload && bytes.Length > 0)
            bytes[0] ^= 0xff;
        return Task.FromResult<Stream>(new MemoryStream(bytes, writable: false));
    }

    public Task<bool> DeleteAsync(string objectName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var removed = _committed.Remove(objectName) | _manifests.Remove(objectName);
        _staged.Remove(objectName);
        return Task.FromResult(removed);
    }

    public async Task<PortableObjectReceipt> PublishManifestAsync(
        string manifestName,
        Stream content,
        string contentSha256,
        CancellationToken cancellationToken = default)
    {
        ManifestCalls++;
        if (FailManifestOnce)
        {
            FailManifestOnce = false;
            throw new IOException("Simulated crash before manifest publication.");
        }
        using var memory = new MemoryStream();
        await content.CopyToAsync(memory, cancellationToken);
        var bytes = memory.ToArray();
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
        if (hash != contentSha256)
            throw new PortableStateException("Manifest hash mismatch.");
        if (_manifests.TryGetValue(manifestName, out var existing))
        {
            var actual = TamperExistingManifestContent
                ? Convert.ToHexStringLower(SHA256.HashData("tampered"u8.ToArray()))
                : Convert.ToHexStringLower(SHA256.HashData(existing.Content));
            if (existing.Sha256 == hash && actual == hash)
                return new(manifestName, hash, existing.Content.LongLength, existing.ETag, DateTimeOffset.UtcNow);
            throw new PortableStateException("Immutable manifest conflict.");
        }
        var etag = $"\"fake-{++_etag}\"";
        _manifests[manifestName] = (bytes, etag, hash);
        return new(manifestName, hash, bytes.LongLength, etag, DateTimeOffset.UtcNow);
    }

    private static byte[] TestCrc64(ReadOnlySpan<byte> data)
    {
        const ulong polynomial = 0x42F0E1EBA9EA3693;
        ulong crc = 0;
        foreach (var value in data)
        {
            crc ^= (ulong)value << 56;
            for (var bit = 0; bit < 8; bit++)
                crc = (crc & 0x8000000000000000) != 0 ? (crc << 1) ^ polynomial : crc << 1;
        }
        var result = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(result, crc);
        return result;
    }
}
