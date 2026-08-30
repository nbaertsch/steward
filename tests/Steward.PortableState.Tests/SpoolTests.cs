using System.Security.Cryptography;
using Steward.Domain;
using Steward.PortableState;

namespace Steward.PortableState.Tests;

public sealed class SpoolTests
{
    [Fact]
    public async Task Expired_authority_keeps_output_queued_locally()
    {
        using var fixture = new SpoolFixture(1_000, 2_000, 500, 10_000);
        var admitted = await fixture.AdmitAsync(200, required: true);
        var store = new InMemoryBlockStore
        {
            Authority = new(
                DateTimeOffset.UtcNow.AddMinutes(-1),
                PortableStorePermission.Read | PortableStorePermission.Create | PortableStorePermission.Write,
                "expired-sas")
        };
        var uploader = new PortableObjectUploader(store, new PortableUploadOptions
        {
            BlockSizeBytes = 65_536,
            MinimumAuthorityLifetime = TimeSpan.Zero
        });

        var result = await fixture.Spool.UploadNextAsync(uploader);

        Assert.Null(result);
        Assert.Equal(SpoolItemState.Queued, Assert.Single(fixture.Spool.GetItems()).State);
        Assert.True(admitted.Admitted);
    }

    [Theory]
    [InlineData(1_500, 10_000, SpoolAdmissionDecision.HardLimitExceeded)]
    [InlineData(200, 600, SpoolAdmissionDecision.OsReserveThreatened)]
    public async Task Admission_enforces_hard_limit_and_os_reserve(
        int length,
        long available,
        SpoolAdmissionDecision expected)
    {
        using var fixture = new SpoolFixture(500, 1_000, 500, available);

        var result = await fixture.AdmitAsync(length, required: true);

        Assert.Equal(expected, result.Decision);
        Assert.Empty(fixture.Spool.GetItems());
    }

    [Fact]
    public async Task Required_checkpoint_is_never_silently_evicted()
    {
        using var fixture = new SpoolFixture(100, 1_000, 100, 10_000);
        var result = await fixture.AdmitAsync(200, required: true);
        var item = Assert.Single(fixture.Spool.GetItems());

        await Assert.ThrowsAsync<PortableStateException>(() => fixture.Spool.ReleaseAsync(item.SpoolId));

        Assert.Equal(SpoolAdmissionDecision.AdmittedAboveHighLimit, result.Decision);
        Assert.True(File.Exists(System.IO.Path.Combine(fixture.Directory, item.ContentFileName)));
    }

    [Fact]
    public async Task Admission_stream_cannot_exceed_declared_spool_bound()
    {
        using var fixture = new SpoolFixture(1_000, 2_000, 100, 10_000);
        var content = RandomNumberGenerator.GetBytes(201);
        var declared = content[..200];
        var hash = Convert.ToHexStringLower(SHA256.HashData(declared));
        var descriptor = new PortableObjectDescriptor(
            PortableObjectDescriptor.ContentAddressedName("logs", hash),
            PortableObjectId.New().ToString(),
            "1",
            "application/octet-stream",
            hash,
            declared.Length,
            new Dictionary<string, string>());
        await using var source = new MemoryStream(content, writable: false);

        await Assert.ThrowsAsync<PortableStateException>(() =>
            fixture.Spool.AdmitAsync(PortableObjectId.New(), descriptor, source, requiredCheckpoint: true));

        Assert.Empty(fixture.Spool.GetItems());
        Assert.Empty(System.IO.Directory.EnumerateFiles(fixture.Directory, "*.partial"));
    }

    [Fact]
    public async Task Credential_bearing_remote_error_is_never_persisted()
    {
        using var fixture = new SpoolFixture(1_000, 2_000, 100, 10_000);
        await fixture.AdmitAsync(200, required: true);
        var store = new InMemoryBlockStore
        {
            PropertiesException = new IOException(
                "request failed https://account.blob.core.windows.net/c/o?sig=top-secret&sp=rcw")
        };
        var uploader = new PortableObjectUploader(
            store,
            new PortableUploadOptions { BlockSizeBytes = 65_536, MinimumAuthorityLifetime = TimeSpan.Zero });

        await Assert.ThrowsAsync<IOException>(() => fixture.Spool.UploadNextAsync(uploader));

        var item = Assert.Single(fixture.Spool.GetItems());
        var persisted = await File.ReadAllTextAsync(
            System.IO.Path.Combine(fixture.Directory, $"{item.SpoolId:N}.manifest.json"));
        Assert.Equal(PortableFailureCode.RemoteUnavailable, item.ErrorCode);
        Assert.DoesNotContain("top-secret", persisted, StringComparison.Ordinal);
        Assert.DoesNotContain("sig=", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", item.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Restart_removes_partials_and_quarantines_tampered_content_without_blocking_spool()
    {
        using var fixture = new SpoolFixture(1_000, 4_000, 100, 10_000);
        var admitted = await fixture.AdmitAsync(200, required: true);
        var item = admitted.Manifest!;
        await File.WriteAllTextAsync(System.IO.Path.Combine(fixture.Directory, "orphan.content.partial"), "partial");
        await File.WriteAllTextAsync(
            System.IO.Path.Combine(fixture.Directory, item.ContentFileName),
            "tampered");

        var restarted = fixture.Restart();

        Assert.Empty(restarted.GetItems());
        Assert.Contains(restarted.Diagnostics, x => x.Code == "orphan-partial-removed");
        Assert.Contains(restarted.Diagnostics, x => x.Code == "corrupt-manifest");
        Assert.Contains(restarted.Diagnostics, x => x.Code == "orphan-content");
        var fresh = await fixture.AdmitAsyncOn(restarted, 100, required: false);
        Assert.True(fresh.Admitted);
    }

    [Fact]
    public async Task Restart_quarantines_path_escape_and_duplicate_portable_id()
    {
        using var fixture = new SpoolFixture(1_000, 4_000, 100, 10_000);
        var admitted = await fixture.AdmitAsync(100, required: true);
        var item = admitted.Manifest!;
        var original = await File.ReadAllTextAsync(
            System.IO.Path.Combine(fixture.Directory, $"{item.SpoolId:N}.manifest.json"));
        var duplicateId = Guid.NewGuid();
        var duplicateContent = $"{duplicateId:N}.content";
        File.Copy(
            System.IO.Path.Combine(fixture.Directory, item.ContentFileName),
            System.IO.Path.Combine(fixture.Directory, duplicateContent));
        var duplicateJson = original
            .Replace(item.SpoolId.ToString(), duplicateId.ToString(), StringComparison.OrdinalIgnoreCase)
            .Replace(item.SpoolId.ToString("N"), duplicateId.ToString("N"), StringComparison.OrdinalIgnoreCase);
        await File.WriteAllTextAsync(
            System.IO.Path.Combine(fixture.Directory, $"{duplicateId:N}.manifest.json"),
            duplicateJson);
        var escapeId = Guid.NewGuid();
        var escapedJson = duplicateJson
            .Replace(duplicateId.ToString(), escapeId.ToString(), StringComparison.OrdinalIgnoreCase)
            .Replace(duplicateId.ToString("N"), escapeId.ToString("N"), StringComparison.OrdinalIgnoreCase)
            .Replace(duplicateContent, "../outside.content", StringComparison.Ordinal);
        await File.WriteAllTextAsync(
            System.IO.Path.Combine(fixture.Directory, $"{escapeId:N}.manifest.json"),
            escapedJson);

        var restarted = fixture.Restart();

        Assert.Single(restarted.GetItems());
        Assert.True(restarted.Diagnostics.Count(x => x.Code == "corrupt-manifest") >= 2);
    }

    private sealed class SpoolFixture : IDisposable
    {
        private readonly long _available;

        public SpoolFixture(long high, long hard, long reserve, long available)
        {
            _available = available;
            Directory = System.IO.Path.Combine(AppContext.BaseDirectory, "spool-tests", Guid.NewGuid().ToString("N"));
            Spool = new DiskSpool(
                new SpoolOptions
                {
                    RootPath = Directory,
                    HighLimitBytes = high,
                    HardLimitBytes = hard,
                    OsReserveBytes = reserve
                },
                new Probe(() => _available));
        }

        public string Directory { get; }
        public DiskSpool Spool { get; }

        public async Task<SpoolAdmissionResult> AdmitAsync(int length, bool required)
            => await AdmitAsyncOn(Spool, length, required);

        public async Task<SpoolAdmissionResult> AdmitAsyncOn(DiskSpool spool, int length, bool required)
        {
            var bytes = RandomNumberGenerator.GetBytes(length);
            var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            var descriptor = new PortableObjectDescriptor(
                PortableObjectDescriptor.ContentAddressedName("logs", hash),
                PortableObjectId.New().ToString(),
                "1",
                "application/octet-stream",
                hash,
                length,
                new Dictionary<string, string>());
            await using var content = new MemoryStream(bytes, writable: false);
            return await spool.AdmitAsync(PortableObjectId.New(), descriptor, content, required);
        }

        public DiskSpool Restart() => new(
            new SpoolOptions
            {
                RootPath = Directory,
                HighLimitBytes = 1_000,
                HardLimitBytes = 4_000,
                OsReserveBytes = 100
            },
            new Probe(() => _available));

        public void Dispose()
        {
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }

        private sealed class Probe(Func<long> available) : IDiskSpaceProbe
        {
            public long GetAvailableBytes(string path) => available();
        }
    }
}
