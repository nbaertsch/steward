using System.Security.Cryptography;
using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.PortableState;

namespace Steward.PortableState.Tests;

public sealed class LocalStackObjectStoreTests
{
    [Fact]
    public async Task Create_head_read_delete_and_restart_are_durable()
    {
        using var fixture = new LocalStoreFixture();
        var content = RandomNumberGenerator.GetBytes(90_000);
        var descriptor = fixture.Descriptor(content, "objects");
        var path = await fixture.WriteSourceAsync(content);

        var receipt = await fixture.Uploader.UploadAsync(path, descriptor);
        var restarted = fixture.Restart();
        var properties = await restarted.GetPropertiesAsync(descriptor.ObjectName);
        await using var read = await restarted.OpenReadAsync(descriptor.ObjectName);
        using var copy = new MemoryStream();
        await read.CopyToAsync(copy);

        Assert.Equal(descriptor.Sha256, receipt.Sha256);
        Assert.Equal(descriptor.Sha256, properties!.Sha256);
        Assert.Equal(content, copy.ToArray());
        Assert.True(await restarted.DeleteAsync(descriptor.ObjectName));
        Assert.False(await restarted.DeleteAsync(descriptor.ObjectName));
        Assert.Null(await fixture.Restart().GetPropertiesAsync(descriptor.ObjectName));
    }

    [Fact]
    public async Task Partial_chunks_survive_restart_and_resume()
    {
        using var fixture = new LocalStoreFixture();
        var content = RandomNumberGenerator.GetBytes(150_000);
        var descriptor = fixture.Descriptor(content, "checkpoints");
        var path = await fixture.WriteSourceAsync(content);
        var first = content[..65_536];
        await using (var stream = new MemoryStream(first, writable: false))
        {
            await fixture.Store.StageBlockAsync(
                descriptor.ObjectName,
                PortableObjectUploader.DeterministicBlockId(0),
                stream,
                first.Length,
                TransportHashAlgorithm.Md5,
                MD5.HashData(first));
        }

        var restarted = fixture.Restart();
        var staged = Assert.Single(await restarted.GetUncommittedBlocksAsync(descriptor.ObjectName));
        var uploader = fixture.CreateUploader(restarted);
        var receipt = await uploader.UploadAsync(path, descriptor);

        Assert.Equal(first.Length, staged.Length);
        Assert.Equal(descriptor.Sha256, receipt.Sha256);
        Assert.Empty(await restarted.GetUncommittedBlocksAsync(descriptor.ObjectName));
    }

    [Fact]
    public async Task Immutable_conflicts_and_on_disk_corruption_are_rejected()
    {
        using var fixture = new LocalStoreFixture();
        var original = RandomNumberGenerator.GetBytes(100);
        var first = fixture.Descriptor(original, "objects");
        await fixture.Uploader.UploadAsync(await fixture.WriteSourceAsync(original), first);

        var replacement = RandomNumberGenerator.GetBytes(100);
        var conflict = fixture.Descriptor(replacement, "objects") with { ObjectName = first.ObjectName };
        var replacementPath = await fixture.WriteSourceAsync(replacement);
        await Assert.ThrowsAsync<PortableStateException>(
            () => fixture.Uploader.UploadAsync(replacementPath, conflict));

        var contentPath = Assert.Single(Directory.EnumerateFiles(
            Path.Combine(fixture.Directory, "content"), "*.content", SearchOption.AllDirectories));
        var bytes = await File.ReadAllBytesAsync(contentPath);
        bytes[0] ^= 0xff;
        await File.WriteAllBytesAsync(contentPath, bytes);

        await Assert.ThrowsAsync<PortableStateException>(
            () => fixture.Store.GetPropertiesAsync(first.ObjectName));
        await Assert.ThrowsAsync<PortableStateException>(
            () => fixture.Store.OpenReadAsync(first.ObjectName));
    }

    [Fact]
    public async Task Content_address_is_shared_until_last_logical_reference_is_deleted()
    {
        using var fixture = new LocalStoreFixture();
        var content = "shared immutable manifest"u8.ToArray();
        var hash = Convert.ToHexStringLower(SHA256.HashData(content));
        await using (var first = new MemoryStream(content, writable: false))
            await fixture.Store.PublishManifestAsync("manifests/first", first, hash);
        await using (var second = new MemoryStream(content, writable: false))
            await fixture.Store.PublishManifestAsync("manifests/second", second, hash);

        Assert.Single(Directory.EnumerateFiles(
            Path.Combine(fixture.Directory, "content"), "*.content", SearchOption.AllDirectories));
        Assert.True(await fixture.Store.DeleteAsync("manifests/first"));
        await using var remaining = await fixture.Store.OpenReadAsync("manifests/second");
        Assert.Equal(hash, Convert.ToHexStringLower(await SHA256.HashDataAsync(remaining)));
        Assert.True(await fixture.Store.DeleteAsync("manifests/second"));
        Assert.Empty(Directory.EnumerateFiles(
            Path.Combine(fixture.Directory, "content"), "*.content", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Existing_manifest_still_validates_supplied_content()
    {
        using var fixture = new LocalStoreFixture();
        var content = "original manifest"u8.ToArray();
        var hash = Convert.ToHexStringLower(SHA256.HashData(content));
        await using (var original = new MemoryStream(content, writable: false))
            await fixture.Store.PublishManifestAsync("manifests/immutable", original, hash);
        await using var conflicting = new MemoryStream("different content"u8.ToArray(), writable: false);

        await Assert.ThrowsAsync<PortableStateException>(() =>
            fixture.Store.PublishManifestAsync("manifests/immutable", conflicting, hash));
    }

    [Fact]
    public void Restart_removes_interrupted_and_orphaned_staging_files()
    {
        using var fixture = new LocalStoreFixture();
        var stage = Path.Combine(fixture.Directory, "staging", "interrupted");
        Directory.CreateDirectory(stage);
        File.WriteAllText(Path.Combine(stage, "write.partial"), "partial");
        File.WriteAllText(Path.Combine(stage, "orphan.chunk"), "orphan");

        _ = fixture.Restart();

        Assert.False(Directory.Exists(stage));
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("objects/../../escape")]
    [InlineData("https://host/container?sig=secret")]
    [InlineData("objects/%2e%2e/escape")]
    [InlineData(@"C:\outside")]
    public void Traversal_paths_and_credential_uris_are_rejected(string objectName)
    {
        Assert.Throws<ArgumentException>(() => PortableObjectDescriptor.ValidateObjectName(objectName));
    }

    [Fact]
    public void Composition_metadata_requires_approved_absolute_non_uri_root()
    {
        var relative = Metadata("relative/root");
        var credentialUri = Metadata("https://host/container?sig=secret");
        var wrongKind = ExtensionMetadataDto.Create(
            "azure-blob",
            LocalStackObjectStoreConfiguration.MetadataVersion,
            new { rootPath = Path.GetFullPath("objects") });

        Assert.Throws<PortableStateException>(
            () => LocalStackObjectStoreConfiguration.FromCompositionMetadata(relative));
        Assert.Throws<PortableStateException>(
            () => LocalStackObjectStoreConfiguration.FromCompositionMetadata(credentialUri));
        Assert.Throws<PortableStateException>(
            () => LocalStackObjectStoreConfiguration.FromCompositionMetadata(wrongKind));
    }

    [Fact]
    public void Reparse_point_root_is_rejected_when_platform_supports_links()
    {
        var parent = Path.Combine(
            AppContext.BaseDirectory,
            "local-object-store-link-tests",
            Guid.NewGuid().ToString("N"));
        var target = Path.Combine(parent, "target");
        var link = Path.Combine(parent, "link");
        Directory.CreateDirectory(target);
        try
        {
            try
            {
                Directory.CreateSymbolicLink(link, target);
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
            {
                return;
            }

            Assert.Throws<PortableStateException>(
                () => new LocalStackContentAddressedObjectStore(Metadata(link)));
        }
        finally
        {
            if (Directory.Exists(link))
                Directory.Delete(link);
            if (Directory.Exists(parent))
                Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public async Task Direct_peer_transfer_is_bounded_and_resumes_from_chunk_receipts()
    {
        using var fixture = new LocalStoreFixture();
        var content = RandomNumberGenerator.GetBytes(150_000);
        var descriptor = fixture.Descriptor(content, "agents");
        var first = content[..65_536];
        var firstHash = Convert.ToHexStringLower(SHA256.HashData(first));
        await using (var stream = new MemoryStream(first, writable: false))
        {
            await fixture.Store.StageChunkAsync(
                descriptor.ObjectName,
                PortableObjectUploader.DeterministicBlockId(0),
                stream,
                first.Length,
                firstHash);
        }

        var restarted = fixture.Restart();
        var source = new ByteArrayChunkSource(content);
        var transfer = new PortableObjectStoreDirectPeerTransfer(
            restarted,
            new() { ChunkSizeBytes = 65_536, MaximumObjectBytes = 1_000_000 });
        var result = await transfer.ReceiveAsync(descriptor, source);

        Assert.Equal(1, result.ResumedChunkCount);
        Assert.Equal(2, source.Calls);
        Assert.Equal(3, result.Chunks.Count);
        Assert.Equal(descriptor.Sha256, result.Object.Sha256);
    }

    [Fact]
    public async Task Direct_peer_source_cannot_exceed_requested_chunk()
    {
        using var fixture = new LocalStoreFixture();
        var content = RandomNumberGenerator.GetBytes(65_536);
        var descriptor = fixture.Descriptor(content, "agents");
        var transfer = new PortableObjectStoreDirectPeerTransfer(
            fixture.Store,
            new() { ChunkSizeBytes = 65_536, MaximumObjectBytes = 100_000 });

        await Assert.ThrowsAsync<PortableStateException>(
            () => transfer.ReceiveAsync(descriptor, new OverwritingChunkSource(content)));
    }

    private static ExtensionMetadataDto Metadata(string root) =>
        ExtensionMetadataDto.Create(
            LocalStackObjectStoreConfiguration.MetadataKind,
            LocalStackObjectStoreConfiguration.MetadataVersion,
            new { rootPath = root });

    private sealed class LocalStoreFixture : IDisposable
    {
        private int _source;

        public LocalStoreFixture()
        {
            Directory = Path.Combine(
                AppContext.BaseDirectory,
                "local-object-store-tests",
                Guid.NewGuid().ToString("N"));
            Store = new LocalStackContentAddressedObjectStore(Metadata(Directory));
            Uploader = CreateUploader(Store);
        }

        public string Directory { get; }
        public LocalStackContentAddressedObjectStore Store { get; }
        public PortableObjectUploader Uploader { get; }

        public LocalStackContentAddressedObjectStore Restart() =>
            new(Metadata(Directory));

        public PortableObjectUploader CreateUploader(IPortableObjectStore store) =>
            new(store, new()
            {
                BlockSizeBytes = 65_536,
                MinimumAuthorityLifetime = TimeSpan.Zero
            });

        public PortableObjectDescriptor Descriptor(byte[] content, string category)
        {
            var hash = Convert.ToHexStringLower(SHA256.HashData(content));
            return new(
                PortableObjectDescriptor.ContentAddressedName(category, hash),
                PortableObjectId.New().ToString(),
                "1",
                "application/octet-stream",
                hash,
                content.LongLength,
                new Dictionary<string, string>());
        }

        public async Task<string> WriteSourceAsync(byte[] content)
        {
            var path = Path.Combine(Directory, $"source-{++_source}");
            await File.WriteAllBytesAsync(path, content);
            return path;
        }

        public void Dispose()
        {
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
    }

    private sealed class ByteArrayChunkSource(byte[] content) : IPortableChunkSource
    {
        public int Calls { get; private set; }

        public async Task<PortableChunkReadReceipt> CopyChunkToAsync(
            PortableChunkRequest request,
            Stream destination,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            var length = (int)Math.Min(request.MaximumLength, content.LongLength - request.Offset);
            await destination.WriteAsync(
                content.AsMemory((int)request.Offset, length),
                cancellationToken);
            var hash = Convert.ToHexStringLower(
                SHA256.HashData(content.AsSpan((int)request.Offset, length)));
            return new(request.Index, request.Offset, length, hash);
        }
    }

    private sealed class OverwritingChunkSource(byte[] content) : IPortableChunkSource
    {
        public async Task<PortableChunkReadReceipt> CopyChunkToAsync(
            PortableChunkRequest request,
            Stream destination,
            CancellationToken cancellationToken = default)
        {
            await destination.WriteAsync(content, cancellationToken);
            await destination.WriteAsync(new byte[1], cancellationToken);
            return new(
                request.Index,
                request.Offset,
                content.Length + 1,
                new string('0', 64));
        }
    }
}
