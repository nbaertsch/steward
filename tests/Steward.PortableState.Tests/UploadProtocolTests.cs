using System.Security.Cryptography;
using Steward.Domain;
using Steward.PortableState;

namespace Steward.PortableState.Tests;

public sealed class UploadProtocolTests
{
    [Fact]
    public async Task Partial_stage_resumes_only_missing_blocks()
    {
        var fixture = await UploadFixture.CreateAsync(150_000);
        await using var first = new MemoryStream(fixture.Content[..65_536], writable: false);
        await fixture.Store.StageBlockAsync(
            fixture.Descriptor.ObjectName,
            PortableObjectUploader.DeterministicBlockId(0),
            first,
            first.Length,
            TransportHashAlgorithm.Md5,
            MD5.HashData(fixture.Content[..65_536]));

        var receipt = await fixture.Uploader.UploadAsync(fixture.Path, fixture.Descriptor);

        Assert.Equal(fixture.Descriptor.Sha256, receipt.Sha256);
        Assert.Equal(3, fixture.Store.StageCalls);
        fixture.Dispose();
    }

    [Fact]
    public async Task Expired_or_wrong_length_blocks_are_restaged()
    {
        var fixture = await UploadFixture.CreateAsync(100_000);
        await using (var first = new MemoryStream(fixture.Content[..65_536], writable: false))
        {
            await fixture.Store.StageBlockAsync(
                fixture.Descriptor.ObjectName,
                PortableObjectUploader.DeterministicBlockId(0),
                first,
                first.Length,
                TransportHashAlgorithm.Md5,
                MD5.HashData(fixture.Content[..65_536]));
        }
        fixture.Store.ExpireUncommitted();
        var callsBefore = fixture.Store.StageCalls;

        await fixture.Uploader.UploadAsync(fixture.Path, fixture.Descriptor);

        Assert.Equal(2, fixture.Store.StageCalls - callsBefore);
        fixture.Dispose();
    }

    [Fact]
    public async Task Transaction_and_whole_object_corruption_are_rejected()
    {
        var store = new InMemoryBlockStore();
        var bytes = "integrity"u8.ToArray();
        await using var content = new MemoryStream(bytes, writable: false);
        await Assert.ThrowsAsync<PortableStateException>(() => store.StageBlockAsync(
            "object",
            PortableObjectUploader.DeterministicBlockId(0),
            content,
            bytes.Length,
            TransportHashAlgorithm.Md5,
            new byte[16]));

        var fixture = await UploadFixture.CreateAsync(80_000);
        fixture.Store.CorruptCommittedDownload = true;
        await Assert.ThrowsAsync<PortableStateException>(
            () => fixture.Uploader.UploadAsync(fixture.Path, fixture.Descriptor));
        fixture.Dispose();
    }

    [Fact]
    public async Task Crash_after_commit_resumes_without_restaging()
    {
        var fixture = await UploadFixture.CreateAsync(80_000);
        fixture.Store.FailPropertiesOnceAfterCommit = true;
        await Assert.ThrowsAsync<IOException>(
            () => fixture.Uploader.UploadAsync(fixture.Path, fixture.Descriptor));
        var stageCalls = fixture.Store.StageCalls;

        var receipt = await fixture.Uploader.UploadAsync(fixture.Path, fixture.Descriptor);

        Assert.Equal(stageCalls, fixture.Store.StageCalls);
        Assert.Equal(fixture.Descriptor.Sha256, receipt.Sha256);
        fixture.Dispose();
    }

    [Fact]
    public async Task Manifest_is_published_only_with_receipts_and_retry_is_idempotent()
    {
        var fixture = await UploadFixture.CreateAsync(10);
        var publisher = new PortableManifestPublisher(fixture.Store);
        var missing = new PortableManifest(
            "1",
            "task",
            [new(fixture.Descriptor.ObjectName, fixture.Descriptor.Sha256, fixture.Descriptor.Length, null)],
            DateTimeOffset.UtcNow);
        await Assert.ThrowsAsync<PortableStateException>(() => publisher.PublishAsync("manifests/task", missing));
        Assert.Equal(0, fixture.Store.ManifestCalls);

        var receipt = await fixture.Uploader.UploadAsync(fixture.Path, fixture.Descriptor);
        var complete = missing with
        {
            Objects = [missing.Objects[0] with { Receipt = receipt }]
        };
        fixture.Store.FailManifestOnce = true;
        await Assert.ThrowsAsync<IOException>(() => publisher.PublishAsync("manifests/task", complete));
        var published = await publisher.PublishAsync("manifests/task", complete);
        var again = await publisher.PublishAsync("manifests/task", complete);

        Assert.Equal(published.ETag, again.ETag);
        Assert.Equal(64, published.Sha256.Length);
        Assert.True(published.Length > 0);
        fixture.Dispose();
    }

    [Fact]
    public async Task Tampered_existing_manifest_is_rejected_despite_matching_metadata()
    {
        var fixture = await UploadFixture.CreateAsync(10);
        var publisher = new PortableManifestPublisher(fixture.Store);
        var receipt = await fixture.Uploader.UploadAsync(fixture.Path, fixture.Descriptor);
        var manifest = new PortableManifest(
            "1",
            "task",
            [new(fixture.Descriptor.ObjectName, fixture.Descriptor.Sha256, fixture.Descriptor.Length, receipt)],
            DateTimeOffset.UtcNow);
        await publisher.PublishAsync("manifests/tamper", manifest);
        fixture.Store.TamperExistingManifestContent = true;

        await Assert.ThrowsAsync<PortableStateException>(
            () => publisher.PublishAsync("manifests/tamper", manifest));
        fixture.Dispose();
    }

    [Fact]
    public async Task Authority_expiry_during_block_loop_stops_remote_work()
    {
        var fixture = await UploadFixture.CreateAsync(150_000);
        var clock = new MutableTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        fixture.Store.Authority = new(
            clock.GetUtcNow().AddMinutes(1),
            PortableStorePermission.Read | PortableStorePermission.Create | PortableStorePermission.Write,
            "sas");
        fixture.Store.AfterStage = () => clock.Advance(TimeSpan.FromMinutes(2));
        var uploader = new PortableObjectUploader(
            fixture.Store,
            new PortableUploadOptions { BlockSizeBytes = 65_536, MinimumAuthorityLifetime = TimeSpan.Zero },
            clock);

        await Assert.ThrowsAsync<PortableStateException>(
            () => uploader.UploadAsync(fixture.Path, fixture.Descriptor));

        Assert.Equal(1, fixture.Store.StageCalls);
        Assert.Equal(0, fixture.Store.CommitCalls);
        fixture.Dispose();
    }

    private sealed class UploadFixture : IDisposable
    {
        private UploadFixture(
            string directory,
            string path,
            byte[] content,
            PortableObjectDescriptor descriptor,
            InMemoryBlockStore store,
            PortableObjectUploader uploader)
        {
            Directory = directory;
            Path = path;
            Content = content;
            Descriptor = descriptor;
            Store = store;
            Uploader = uploader;
        }

        public string Directory { get; }
        public string Path { get; }
        public byte[] Content { get; }
        public PortableObjectDescriptor Descriptor { get; }
        public InMemoryBlockStore Store { get; }
        public PortableObjectUploader Uploader { get; }

        public static async Task<UploadFixture> CreateAsync(int length)
        {
            var directory = System.IO.Path.Combine(AppContext.BaseDirectory, "upload-tests", Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(directory);
            var path = System.IO.Path.Combine(directory, "content");
            var content = RandomNumberGenerator.GetBytes(length);
            await File.WriteAllBytesAsync(path, content);
            var hash = Convert.ToHexStringLower(SHA256.HashData(content));
            var descriptor = new PortableObjectDescriptor(
                PortableObjectDescriptor.ContentAddressedName("checkpoints", hash),
                PortableObjectId.New().ToString(),
                "1",
                "application/octet-stream",
                hash,
                length,
                new Dictionary<string, string> { ["taskAttemptId"] = TaskAttemptId.New().ToString() });
            var store = new InMemoryBlockStore();
            var uploader = new PortableObjectUploader(
                store,
                new PortableUploadOptions
                {
                    BlockSizeBytes = 65_536,
                    MinimumAuthorityLifetime = TimeSpan.Zero
                });
            return new(directory, path, content, descriptor, store, uploader);
        }

        public void Dispose() => System.IO.Directory.Delete(Directory, recursive: true);
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}
