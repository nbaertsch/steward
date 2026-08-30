using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Steward.Contracts;

namespace Steward.PortableState;

public sealed class LocalStackObjectStoreConfiguration
{
    public const string MetadataKind = "content-addressed-filesystem";
    public const string MetadataVersion = "1.0";

    private LocalStackObjectStoreConfiguration(string approvedRoot) => ApprovedRoot = approvedRoot;

    public string ApprovedRoot { get; }

    public static LocalStackObjectStoreConfiguration FromCompositionMetadata(ExtensionMetadataDto metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (!string.Equals(metadata.Kind, MetadataKind, StringComparison.Ordinal) ||
            !string.Equals(metadata.Version, MetadataVersion, StringComparison.Ordinal))
            throw new PortableStateException("Local Stack portable-state metadata kind or version is unsupported.");
        if (metadata.Data.ValueKind != JsonValueKind.Object ||
            !TryGetProperty(metadata.Data, "rootPath", out var rootElement) ||
            rootElement.ValueKind != JsonValueKind.String)
            throw new PortableStateException("Local Stack portable-state metadata must contain rootPath.");

        var root = rootElement.GetString();
        if (string.IsNullOrWhiteSpace(root) ||
            root.Length > 32_767 ||
            root.IndexOf('\0') >= 0 ||
            root.Contains("://", StringComparison.Ordinal) ||
            root.Contains('?') ||
            root.Contains('#') ||
            !Path.IsPathFullyQualified(root))
            throw new PortableStateException("Local Stack portable-state root must be an absolute filesystem path, not a URI.");

        return new(Path.GetFullPath(root));
    }

    private static bool TryGetProperty(JsonElement value, string name, out JsonElement property)
    {
        foreach (var candidate in value.EnumerateObject())
        {
            if (string.Equals(candidate.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                property = candidate.Value;
                return true;
            }
        }
        property = default;
        return false;
    }
}

public sealed class LocalStackContentAddressedObjectStore : IPortableObjectStore, IPortableChunkReceiptStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TimeProvider _timeProvider;
    private readonly string _root;
    private readonly string _contentRoot;
    private readonly string _entryRoot;
    private readonly string _stagingRoot;

    public LocalStackContentAddressedObjectStore(
        ExtensionMetadataDto compositionMetadata,
        TimeProvider? timeProvider = null)
        : this(LocalStackObjectStoreConfiguration.FromCompositionMetadata(compositionMetadata), timeProvider)
    {
    }

    public LocalStackContentAddressedObjectStore(
        LocalStackObjectStoreConfiguration configuration,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        _root = configuration.ApprovedRoot;
        _contentRoot = Path.Combine(_root, "content");
        _entryRoot = Path.Combine(_root, "entries");
        _stagingRoot = Path.Combine(_root, "staging");
        _timeProvider = timeProvider ?? TimeProvider.System;
        EnsureSafeDirectory(_root);
        EnsureSafeDirectory(_contentRoot);
        EnsureSafeDirectory(_entryRoot);
        EnsureSafeDirectory(_stagingRoot);
        RemoveInterruptedWrites(_contentRoot);
        RemoveInterruptedWrites(_entryRoot);
        RemoveInterruptedWrites(_stagingRoot);
        RemoveOrphanedStagingFiles(_stagingRoot);
    }

    public PortableStoreAuthority Authority { get; } = new(
        DateTimeOffset.MaxValue,
        PortableStorePermission.Read | PortableStorePermission.Create |
        PortableStorePermission.Write | PortableStorePermission.Delete,
        "local-stack-filesystem");

    public async Task<IReadOnlyList<StagedBlock>> GetUncommittedBlocksAsync(
        string objectName,
        CancellationToken cancellationToken = default)
    {
        var receipts = await GetChunkReceiptsAsync(objectName, cancellationToken).ConfigureAwait(false);
        return receipts.Select(x => new StagedBlock(x.ChunkId, x.Length)).ToArray();
    }

    public async Task<IReadOnlyList<PortableChunkReceipt>> GetChunkReceiptsAsync(
        string objectName,
        CancellationToken cancellationToken = default)
    {
        ValidateName(objectName);
        var directory = StagingDirectory(objectName);
        if (!Directory.Exists(directory))
            return [];
        EnsureNoReparse(directory);

        var result = new List<PortableChunkReceipt>();
        foreach (var path in Directory.EnumerateFiles(directory, "*.receipt.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureNoReparse(path);
            try
            {
                var stored = JsonSerializer.Deserialize<StoredChunkReceipt>(
                    await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false),
                    JsonOptions) ?? throw new JsonException();
                if (!string.Equals(stored.ObjectName, objectName, StringComparison.Ordinal))
                    throw new PortableStateException("A staged chunk receipt belongs to another object.");
                var chunkPath = ChunkPath(directory, stored.ChunkId);
                EnsureRegularFile(chunkPath);
                var info = new FileInfo(chunkPath);
                if (info.Length != stored.Length)
                    throw new PortableStateException("A staged chunk receipt has an invalid length.");
                await using var chunk = OpenSafeRead(chunkPath);
                var actual = await Hashing.Sha256HexAsync(chunk, cancellationToken).ConfigureAwait(false);
                if (!string.Equals(actual, stored.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new PortableStateException("A staged chunk receipt failed SHA-256 verification.");
                result.Add(new(stored.ObjectName, stored.ChunkId, stored.Length, stored.Sha256, stored.ReceivedAt));
            }
            catch (Exception exception) when (exception is JsonException or IOException)
            {
                throw new PortableStateException("A staged chunk receipt is corrupt.", exception);
            }
        }
        return result;
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
        _ = await StageChunkCoreAsync(
            objectName,
            blockId,
            content,
            length,
            hashAlgorithm,
            transactionalHash,
            expectedSha256: null,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<PortableChunkReceipt> StageChunkAsync(
        string objectName,
        string chunkId,
        Stream content,
        long length,
        string sha256,
        CancellationToken cancellationToken = default)
    {
        PortableObjectDescriptor.ValidateSha256(sha256);
        return StageChunkCoreAsync(
            objectName,
            chunkId,
            content,
            length,
            TransportHashAlgorithm.Md5,
            ReadOnlyMemory<byte>.Empty,
            sha256,
            cancellationToken);
    }

    public async Task<string> CommitBlockListAsync(
        PortableObjectDescriptor descriptor,
        IReadOnlyList<string> orderedBlockIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(orderedBlockIds);
        ValidateName(descriptor.ObjectName);
        PortableObjectDescriptor.ValidateSha256(descriptor.Sha256);
        if (descriptor.Length < 0 || orderedBlockIds.Count == 0 || orderedBlockIds.Distinct(StringComparer.Ordinal).Count() != orderedBlockIds.Count)
            throw new PortableStateException("Portable object block list is invalid.");

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existing = await ReadEntryAsync(descriptor.ObjectName, cancellationToken).ConfigureAwait(false);
            if (existing is not null)
                return RequireMatching(existing, descriptor.Sha256, descriptor.Length).ETag;

            var staging = StagingDirectory(descriptor.ObjectName);
            EnsureSafeDirectory(staging);
            var contentPath = ContentPath(descriptor.Sha256);
            EnsureSafeDirectory(Path.GetDirectoryName(contentPath)!);
            var temporary = TemporaryPath(contentPath);
            try
            {
                var (length, sha256) = await AssembleAsync(
                    temporary, staging, orderedBlockIds, cancellationToken).ConfigureAwait(false);
                if (length != descriptor.Length ||
                    !string.Equals(sha256, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new PortableStateException("Committed content does not match its declared length and SHA-256.");
                PublishContent(temporary, contentPath, descriptor.Length, descriptor.Sha256);
            }
            finally
            {
                TryDelete(temporary);
            }

            var metadata = new Dictionary<string, string>(descriptor.Lineage, StringComparer.Ordinal)
            {
                ["sha256"] = descriptor.Sha256.ToLowerInvariant(),
                ["schemaVersion"] = descriptor.SchemaVersion,
                ["logicalObjectId"] = descriptor.LogicalObjectId,
                ["contentType"] = descriptor.ContentType
            };
            var entry = new StoredEntry(
                descriptor.ObjectName,
                descriptor.Sha256.ToLowerInvariant(),
                descriptor.Length,
                ETag(descriptor.Sha256),
                metadata);
            var published = await PublishEntryAsync(entry, cancellationToken).ConfigureAwait(false);
            TryDeleteDirectory(staging);
            return published.ETag;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<PortableObjectProperties?> GetPropertiesAsync(
        string objectName,
        CancellationToken cancellationToken = default)
    {
        ValidateName(objectName);
        var entry = await ReadEntryAsync(objectName, cancellationToken).ConfigureAwait(false);
        if (entry is null)
            return null;
        await VerifyContentAsync(entry, cancellationToken).ConfigureAwait(false);
        return new(entry.Length, entry.Sha256, entry.ETag, entry.Metadata);
    }

    public async Task<Stream> OpenReadAsync(
        string objectName,
        CancellationToken cancellationToken = default)
    {
        ValidateName(objectName);
        var entry = await ReadEntryAsync(objectName, cancellationToken).ConfigureAwait(false)
            ?? throw new FileNotFoundException("Portable object was not found.");
        await VerifyContentAsync(entry, cancellationToken).ConfigureAwait(false);
        return OpenSafeRead(ContentPath(entry.Sha256));
    }

    public async Task<bool> DeleteAsync(
        string objectName,
        CancellationToken cancellationToken = default)
    {
        ValidateName(objectName);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entry = await ReadEntryAsync(objectName, cancellationToken).ConfigureAwait(false);
            if (entry is null)
                return false;
            await VerifyContentAsync(entry, cancellationToken).ConfigureAwait(false);
            var entryPath = EntryPath(objectName);
            EnsureRegularFile(entryPath);
            File.Delete(entryPath);

            var stillReferenced = false;
            foreach (var path in Directory.EnumerateFiles(_entryRoot, "*.entry.json"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var candidate = await ReadStoredEntryAsync(path, cancellationToken).ConfigureAwait(false);
                if (string.Equals(candidate.Sha256, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    stillReferenced = true;
                    break;
                }
            }
            if (!stillReferenced)
                TryDelete(ContentPath(entry.Sha256));
            TryDeleteDirectory(StagingDirectory(objectName));
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<PortableObjectReceipt> PublishManifestAsync(
        string manifestName,
        Stream content,
        string contentSha256,
        CancellationToken cancellationToken = default)
    {
        ValidateName(manifestName);
        ArgumentNullException.ThrowIfNull(content);
        PortableObjectDescriptor.ValidateSha256(contentSha256);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existing = await ReadEntryAsync(manifestName, cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                var supplied = await HashAndCountAsync(content, cancellationToken).ConfigureAwait(false);
                if (!string.Equals(supplied.Sha256, contentSha256, StringComparison.OrdinalIgnoreCase))
                    throw new PortableStateException("Manifest content failed SHA-256 verification.");
                RequireMatching(existing, contentSha256, supplied.Length);
                await VerifyContentAsync(existing, cancellationToken).ConfigureAwait(false);
                return Receipt(existing);
            }

            var contentPath = ContentPath(contentSha256);
            EnsureSafeDirectory(Path.GetDirectoryName(contentPath)!);
            var temporary = TemporaryPath(contentPath);
            long length;
            string actualHash;
            try
            {
                (length, actualHash) = await WriteAndFlushAsync(
                    temporary, content, cancellationToken).ConfigureAwait(false);
                if (!string.Equals(actualHash, contentSha256, StringComparison.OrdinalIgnoreCase))
                    throw new PortableStateException("Manifest content failed SHA-256 verification.");
                PublishContent(temporary, contentPath, length, contentSha256);
            }
            finally
            {
                TryDelete(temporary);
            }
            var entry = new StoredEntry(
                manifestName,
                contentSha256.ToLowerInvariant(),
                length,
                ETag(contentSha256),
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["sha256"] = contentSha256.ToLowerInvariant(),
                    ["contentType"] = "application/json"
                });
            return Receipt(await PublishEntryAsync(entry, cancellationToken).ConfigureAwait(false));
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<PortableChunkReceipt> StageChunkCoreAsync(
        string objectName,
        string chunkId,
        Stream content,
        long length,
        TransportHashAlgorithm hashAlgorithm,
        ReadOnlyMemory<byte> transactionalHash,
        string? expectedSha256,
        CancellationToken cancellationToken)
    {
        ValidateName(objectName);
        ValidateChunkId(chunkId);
        ArgumentNullException.ThrowIfNull(content);
        if (!content.CanRead)
            throw new ArgumentException("Chunk content must be readable.", nameof(content));
        if (length < 0 || length > 100L * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(length));
        if (expectedSha256 is null &&
            transactionalHash.Length != (hashAlgorithm == TransportHashAlgorithm.Md5 ? 16 : 8))
            throw new PortableStateException("Transactional chunk hash has an invalid length.");

        var directory = StagingDirectory(objectName);
        EnsureSafeDirectory(directory);
        var chunkPath = ChunkPath(directory, chunkId);
        var temporary = TemporaryPath(chunkPath);
        string sha256;
        try
        {
            var written = await WriteChunkAndFlushAsync(
                temporary, content, hashAlgorithm, transactionalHash, expectedSha256, cancellationToken)
                .ConfigureAwait(false);
            if (written.Length != length)
                throw new PortableStateException("Transactional chunk length mismatch.");
            sha256 = written.Sha256;
            if (File.Exists(chunkPath))
                EnsureRegularFile(chunkPath);
            File.Move(temporary, chunkPath, overwrite: true);
        }
        finally
        {
            TryDelete(temporary);
        }

        var receipt = new StoredChunkReceipt(
            objectName,
            chunkId,
            length,
            sha256,
            _timeProvider.GetUtcNow());
        await AtomicWriteJsonAsync(
            ReceiptPath(directory, chunkId), receipt, overwrite: true, cancellationToken).ConfigureAwait(false);
        return new(objectName, chunkId, length, sha256, receipt.ReceivedAt);
    }

    private async Task<StoredEntry?> ReadEntryAsync(string objectName, CancellationToken cancellationToken)
    {
        var path = EntryPath(objectName);
        if (!File.Exists(path))
            return null;
        var entry = await ReadStoredEntryAsync(path, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(entry.ObjectName, objectName, StringComparison.Ordinal))
            throw new PortableStateException("Portable object entry does not match its logical name.");
        PortableObjectDescriptor.ValidateSha256(entry.Sha256);
        if (entry.Length < 0 || entry.Metadata is null)
            throw new PortableStateException("Portable object entry is invalid.");
        return entry;
    }

    private static StoredEntry RequireMatching(StoredEntry entry, string sha256, long length)
    {
        if (entry.Length != length ||
            !string.Equals(entry.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException(
                $"Immutable object '{entry.ObjectName}' already exists with different content.");
        return entry;
    }

    private async Task<StoredEntry> PublishEntryAsync(StoredEntry entry, CancellationToken cancellationToken)
    {
        var path = EntryPath(entry.ObjectName);
        try
        {
            await AtomicWriteJsonAsync(path, entry, overwrite: false, cancellationToken).ConfigureAwait(false);
            return entry;
        }
        catch (IOException) when (File.Exists(path))
        {
            var existing = await ReadStoredEntryAsync(path, cancellationToken).ConfigureAwait(false);
            return RequireMatching(existing, entry.Sha256, entry.Length);
        }
    }

    private async Task<StoredEntry> ReadStoredEntryAsync(string path, CancellationToken cancellationToken)
    {
        EnsureRegularFile(path);
        try
        {
            return JsonSerializer.Deserialize<StoredEntry>(
                await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false),
                JsonOptions) ?? throw new JsonException();
        }
        catch (JsonException exception)
        {
            throw new PortableStateException("Portable object entry is corrupt.", exception);
        }
    }

    private async Task VerifyContentAsync(StoredEntry entry, CancellationToken cancellationToken)
    {
        var path = ContentPath(entry.Sha256);
        EnsureRegularFile(path);
        var info = new FileInfo(path);
        if (info.Length != entry.Length)
            throw new PortableStateException("Portable object content length failed integrity verification.");
        await using var content = OpenSafeRead(path);
        var actual = await Hashing.Sha256HexAsync(content, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(actual, entry.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Portable object content failed SHA-256 integrity verification.");
    }

    private static async Task<(long Length, string Sha256)> AssembleAsync(
        string temporary,
        string staging,
        IReadOnlyList<string> blockIds,
        CancellationToken cancellationToken)
    {
        await using var destination = CreateWriteThrough(temporary);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long total = 0;
        foreach (var blockId in blockIds)
        {
            ValidateChunkId(blockId);
            var path = ChunkPath(staging, blockId);
            EnsureRegularFile(path);
            await using var source = OpenSafeRead(path);
            int read;
            while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                sha256.AppendData(buffer, 0, read);
                total += read;
            }
        }
        await FlushToDiskAsync(destination, cancellationToken).ConfigureAwait(false);
        return (total, Convert.ToHexStringLower(sha256.GetHashAndReset()));
    }

    private static async Task<(long Length, string Sha256)> WriteAndFlushAsync(
        string path,
        Stream source,
        CancellationToken cancellationToken)
    {
        await using var destination = CreateWriteThrough(path);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            sha256.AppendData(buffer, 0, read);
            total += read;
        }
        await FlushToDiskAsync(destination, cancellationToken).ConfigureAwait(false);
        return (total, Convert.ToHexStringLower(sha256.GetHashAndReset()));
    }

    private static async Task<(long Length, string Sha256)> HashAndCountAsync(
        Stream source,
        CancellationToken cancellationToken)
    {
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            sha256.AppendData(buffer, 0, read);
            total += read;
        }
        return (total, Convert.ToHexStringLower(sha256.GetHashAndReset()));
    }

    private static async Task<(long Length, string Sha256)> WriteChunkAndFlushAsync(
        string path,
        Stream source,
        TransportHashAlgorithm algorithm,
        ReadOnlyMemory<byte> expectedTransportHash,
        string? expectedSha256,
        CancellationToken cancellationToken)
    {
        await using var destination = CreateWriteThrough(path);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var md5 = algorithm == TransportHashAlgorithm.Md5
            ? IncrementalHash.CreateHash(HashAlgorithmName.MD5)
            : null;
        var crc64 = new Crc64Accumulator();
        var buffer = new byte[1024 * 1024];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            sha256.AppendData(buffer, 0, read);
            if (md5 is not null)
                md5.AppendData(buffer, 0, read);
            else
                crc64.Append(buffer.AsSpan(0, read));
            total += read;
        }
        await FlushToDiskAsync(destination, cancellationToken).ConfigureAwait(false);
        var actualSha256 = Convert.ToHexStringLower(sha256.GetHashAndReset());
        if (expectedSha256 is not null &&
            !string.Equals(expectedSha256, actualSha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Chunk SHA-256 verification failed.");
        if (!expectedTransportHash.IsEmpty)
        {
            var actualTransport = md5?.GetHashAndReset() ?? crc64.GetHash();
            if (!actualTransport.AsSpan().SequenceEqual(expectedTransportHash.Span))
                throw new PortableStateException("Transactional chunk hash verification failed.");
        }
        return (total, actualSha256);
    }

    private static async Task AtomicWriteJsonAsync<T>(
        string finalPath,
        T value,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        var temporary = TemporaryPath(finalPath);
        try
        {
            await using (var stream = CreateWriteThrough(temporary))
            {
                await JsonSerializer.SerializeAsync(stream, value, JsonOptions, cancellationToken).ConfigureAwait(false);
                await FlushToDiskAsync(stream, cancellationToken).ConfigureAwait(false);
            }
            File.Move(temporary, finalPath, overwrite);
        }
        finally
        {
            TryDelete(temporary);
        }
    }

    private static void PublishContent(
        string temporary,
        string finalPath,
        long expectedLength,
        string expectedSha256)
    {
        try
        {
            File.Move(temporary, finalPath, overwrite: false);
        }
        catch (IOException) when (File.Exists(finalPath))
        {
            EnsureRegularFile(finalPath);
            using var existing = OpenSafeRead(finalPath);
            var hash = Convert.ToHexStringLower(SHA256.HashData(existing));
            if (existing.Length != expectedLength ||
                !string.Equals(hash, expectedSha256, StringComparison.OrdinalIgnoreCase))
                throw new PortableStateException("Content-addressed object has an immutable conflict.");
        }
    }

    private string EntryPath(string objectName) =>
        Path.Combine(_entryRoot, $"{NameKey(objectName)}.entry.json");

    private string StagingDirectory(string objectName) =>
        Path.Combine(_stagingRoot, NameKey(objectName));

    private string ContentPath(string sha256)
    {
        PortableObjectDescriptor.ValidateSha256(sha256);
        sha256 = sha256.ToLowerInvariant();
        return Path.Combine(_contentRoot, sha256[..2], $"{sha256}.content");
    }

    private static string ChunkPath(string staging, string chunkId) =>
        Path.Combine(staging, $"{NameKey(chunkId)}.chunk");

    private static string ReceiptPath(string staging, string chunkId) =>
        Path.Combine(staging, $"{NameKey(chunkId)}.receipt.json");

    private static string NameKey(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string ETag(string sha256) => $"\"sha256-{sha256.ToLowerInvariant()}\"";

    private PortableObjectReceipt Receipt(StoredEntry entry) =>
        new(entry.ObjectName, entry.Sha256, entry.Length, entry.ETag, _timeProvider.GetUtcNow());

    private static FileStream CreateWriteThrough(string path) =>
        new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);

    private static FileStream OpenSafeRead(string path)
    {
        EnsureRegularFile(path);
        return new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
    }

    private static async Task FlushToDiskAsync(FileStream stream, CancellationToken cancellationToken)
    {
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
    }

    private static string TemporaryPath(string finalPath) =>
        $"{finalPath}.{Guid.NewGuid():N}.partial";

    private static void ValidateName(string name) => PortableObjectDescriptor.ValidateObjectName(name);

    private static void ValidateChunkId(string chunkId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(chunkId);
        if (chunkId.Length > 256 ||
            chunkId.Contains("://", StringComparison.Ordinal))
            throw new PortableStateException("Chunk identifiers must be bounded opaque values.");
    }

    private static void EnsureSafeDirectory(string path)
    {
        Directory.CreateDirectory(path);
        EnsureNoReparse(path);
    }

    private static void EnsureRegularFile(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Portable-state file was not found.");
        EnsureNoReparse(path);
        if ((File.GetAttributes(path) & FileAttributes.Directory) != 0)
            throw new PortableStateException("Portable-state content is not a regular file.");
    }

    private static void EnsureNoReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new PortableStateException("Reparse points are not permitted in Local Stack portable state.");
    }

    private static void RemoveInterruptedWrites(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            EnsureNoReparse(directory);
            foreach (var child in Directory.EnumerateDirectories(directory))
            {
                EnsureNoReparse(child);
                pending.Push(child);
            }
            foreach (var path in Directory.EnumerateFiles(directory, "*.partial"))
            {
                EnsureNoReparse(path);
                File.Delete(path);
            }
        }
    }

    private static void RemoveOrphanedStagingFiles(string stagingRoot)
    {
        foreach (var directory in Directory.EnumerateDirectories(stagingRoot))
        {
            EnsureNoReparse(directory);
            var chunks = Directory.EnumerateFiles(directory, "*.chunk")
                .ToDictionary(
                    path => Path.GetFileName(path)[..^".chunk".Length],
                    StringComparer.Ordinal);
            var receipts = Directory.EnumerateFiles(directory, "*.receipt.json")
                .ToDictionary(
                    path => Path.GetFileName(path)[..^".receipt.json".Length],
                    StringComparer.Ordinal);
            foreach (var orphan in chunks.Keys.Except(receipts.Keys, StringComparer.Ordinal))
            {
                EnsureNoReparse(chunks[orphan]);
                File.Delete(chunks[orphan]);
            }
            foreach (var orphan in receipts.Keys.Except(chunks.Keys, StringComparer.Ordinal))
            {
                EnsureNoReparse(receipts[orphan]);
                File.Delete(receipts[orphan]);
            }
            if (!Directory.EnumerateFileSystemEntries(directory).Any())
                Directory.Delete(directory);
        }
    }

    private static void TryDelete(string path)
    {
        if (File.Exists(path))
            File.Delete(path);
    }

    private static void TryDeleteDirectory(string path)
    {
        if (!Directory.Exists(path))
            return;
        EnsureNoReparse(path);
        foreach (var file in Directory.EnumerateFiles(path))
        {
            EnsureNoReparse(file);
            File.Delete(file);
        }
        Directory.Delete(path);
    }

    private sealed record StoredEntry(
        string ObjectName,
        string Sha256,
        long Length,
        string ETag,
        IReadOnlyDictionary<string, string> Metadata);

    private sealed record StoredChunkReceipt(
        string ObjectName,
        string ChunkId,
        long Length,
        string Sha256,
        DateTimeOffset ReceivedAt);

    private sealed class Crc64Accumulator
    {
        private const ulong Polynomial = 0x42F0E1EBA9EA3693;
        private ulong _crc;

        public void Append(ReadOnlySpan<byte> data)
        {
            foreach (var value in data)
            {
                _crc ^= (ulong)value << 56;
                for (var bit = 0; bit < 8; bit++)
                    _crc = (_crc & 0x8000000000000000) != 0
                        ? (_crc << 1) ^ Polynomial
                        : _crc << 1;
            }
        }

        public byte[] GetHash()
        {
            var result = new byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(result, _crc);
            return result;
        }
    }
}
