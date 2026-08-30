using System.Security.Cryptography;
using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;

namespace Steward.PortableState;

public enum SpoolItemState
{
    Admission,
    Queued,
    Uploading,
    Committed,
    Failed
}

public enum SpoolAdmissionDecision
{
    Admitted,
    AdmittedAboveHighLimit,
    HardLimitExceeded,
    OsReserveThreatened
}

public sealed record SpoolOptions
{
    public required string RootPath { get; init; }
    public long HighLimitBytes { get; init; }
    public long HardLimitBytes { get; init; }
    public long OsReserveBytes { get; init; }

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(RootPath);
        if (!Path.IsPathFullyQualified(RootPath) ||
            RootPath.Contains("://", StringComparison.Ordinal) ||
            RootPath.Contains('?') ||
            RootPath.Contains('#'))
            throw new ArgumentException("Spool root must be an absolute filesystem path, not a URI.", nameof(RootPath));
        if (HighLimitBytes < 0 || HardLimitBytes <= 0 || HighLimitBytes > HardLimitBytes)
            throw new ArgumentOutOfRangeException(nameof(HighLimitBytes));
        if (OsReserveBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(OsReserveBytes));
    }
}

public interface IDiskSpaceProbe
{
    long GetAvailableBytes(string path);
}

public sealed class DriveDiskSpaceProbe : IDiskSpaceProbe
{
    public long GetAvailableBytes(string path)
    {
        var root = Path.GetPathRoot(Path.GetFullPath(path))
            ?? throw new PortableStateException("The spool path has no drive root.");
        return new DriveInfo(root).AvailableFreeSpace;
    }
}

public sealed record SpoolManifest(
    Guid SpoolId,
    PortableObjectId PortableObjectId,
    PortableObjectDescriptor Object,
    string ContentFileName,
    SpoolItemState State,
    bool RequiredCheckpoint,
    DateTimeOffset CreatedAt,
    PortableObjectReceipt? Receipt = null,
    PortableFailureCode? ErrorCode = null,
    string? Error = null);

public sealed record SpoolAdmissionResult(
    SpoolAdmissionDecision Decision,
    SpoolManifest? Manifest,
    long UsedBytes,
    long AvailableBytes)
{
    public bool Admitted => Manifest is not null;
}

public sealed record SpoolDiagnostic(string Code, string FileName, string Detail);

public sealed class DiskSpool
{
    private static readonly JsonSerializerOptions JsonOptions = new(StewardJson.Options);

    private readonly SpoolOptions _options;
    private readonly IDiskSpaceProbe _disk;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<SpoolDiagnostic> _diagnostics = [];
    private readonly string _root;
    private readonly string _quarantine;

    public DiskSpool(SpoolOptions options, IDiskSpaceProbe? disk = null, TimeProvider? timeProvider = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        _disk = disk ?? new DriveDiskSpaceProbe();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _root = Path.GetFullPath(_options.RootPath);
        _quarantine = Path.Combine(_root, "quarantine");
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(_quarantine);
        EnsureNoReparse(_root);
        EnsureNoReparse(_quarantine);
        Recover();
    }

    public IReadOnlyList<SpoolDiagnostic> Diagnostics
    {
        get
        {
            lock (_diagnostics)
                return _diagnostics.ToArray();
        }
    }

    public async Task<SpoolAdmissionResult> AdmitAsync(
        PortableObjectId portableObjectId,
        PortableObjectDescriptor descriptor,
        Stream content,
        bool requiredCheckpoint,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(content);
        if (!content.CanRead)
            throw new ArgumentException("Content must be readable.", nameof(content));

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var items = ReadAllManifests();
            if (items.Any(x => x.PortableObjectId == portableObjectId))
                throw new PortableStateException("A spool item with this PortableObjectId already exists.");
            var used = items.Aggregate(0L, (total, item) => checked(total + item.Object.Length));
            var available = _disk.GetAvailableBytes(_root);
            if (descriptor.Length > _options.HardLimitBytes - used)
                return new(SpoolAdmissionDecision.HardLimitExceeded, null, used, available);
            if (descriptor.Length > available - _options.OsReserveBytes)
                return new(SpoolAdmissionDecision.OsReserveThreatened, null, used, available);

            var id = Guid.NewGuid();
            var contentName = $"{id:N}.content";
            var contentPath = ContainedPath(contentName);
            var partialPath = contentPath + ".partial";
            long written;
            string hash;
            try
            {
                (written, hash) = await WriteAndFlushAsync(
                    partialPath, content, descriptor.Length, cancellationToken).ConfigureAwait(false);
                if (written != descriptor.Length || !string.Equals(hash, descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new PortableStateException("Spool content does not match its declared length and SHA-256.");
                File.Move(partialPath, contentPath);
            }
            catch
            {
                File.Delete(partialPath);
                File.Delete(contentPath);
                throw;
            }

            var manifest = new SpoolManifest(
                id,
                portableObjectId,
                descriptor,
                contentName,
                SpoolItemState.Queued,
                requiredCheckpoint,
                _timeProvider.GetUtcNow());
            try
            {
                WriteManifest(manifest);
            }
            catch
            {
                File.Delete(contentPath);
                throw;
            }

            var decision = used + descriptor.Length > _options.HighLimitBytes
                ? SpoolAdmissionDecision.AdmittedAboveHighLimit
                : SpoolAdmissionDecision.Admitted;
            return new(decision, manifest, used + descriptor.Length, available - descriptor.Length);
        }
        finally
        {
            _gate.Release();
        }
    }

    public IReadOnlyList<SpoolManifest> GetItems() =>
        ReadAllManifests().OrderBy(x => x.CreatedAt).ToArray();

    public async Task<PortableObjectReceipt?> UploadNextAsync(
        PortableObjectUploader uploader,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uploader);
        SpoolManifest? item;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            item = ReadAllManifests()
                .Where(x => x.State is SpoolItemState.Queued or SpoolItemState.Uploading or SpoolItemState.Failed)
                .OrderByDescending(x => x.RequiredCheckpoint)
                .ThenBy(x => x.CreatedAt)
                .FirstOrDefault();
            if (item is null || !uploader.CanStartRemoteUpload)
                return null;
            item = item with { State = SpoolItemState.Uploading, ErrorCode = null, Error = null };
            WriteManifest(item);
        }
        finally
        {
            _gate.Release();
        }

        try
        {
            var receipt = await uploader.UploadAsync(
                ContainedPath(item.ContentFileName),
                item.Object,
                cancellationToken).ConfigureAwait(false);
            await UpdateAsync(item with { State = SpoolItemState.Committed, Receipt = receipt }).ConfigureAwait(false);
            return receipt;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var safe = PortableErrorSanitizer.Sanitize(exception);
            await UpdateAsync(item with
            {
                State = SpoolItemState.Failed,
                ErrorCode = safe.Code,
                Error = safe.Detail
            }).ConfigureAwait(false);
            throw;
        }
    }

    public async Task ReleaseAsync(Guid spoolId, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var item = ReadManifest(spoolId);
            if (item.State != SpoolItemState.Committed || item.Receipt is null)
                throw new PortableStateException("Only a committed spool item with a durable receipt can be released.");
            File.Delete(ContainedPath(item.ContentFileName));
            File.Delete(ManifestPath(spoolId));
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task UpdateAsync(SpoolManifest manifest)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            WriteManifest(manifest);
        }
        finally
        {
            _gate.Release();
        }
    }

    private static async Task<(long Length, string Sha256)> WriteAndFlushAsync(
        string path,
        Stream source,
        long maximumLength,
        CancellationToken cancellationToken)
    {
        await using var destination = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long written = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (read > maximumLength - written)
                throw new PortableStateException("Spool content exceeded its declared bounded length.");
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            hasher.AppendData(buffer, 0, read);
            written += read;
        }
        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        destination.Flush(flushToDisk: true);
        return (written, Convert.ToHexStringLower(hasher.GetHashAndReset()));
    }

    private void WriteManifest(SpoolManifest manifest)
    {
        var finalPath = ManifestPath(manifest.SpoolId);
        var partialPath = finalPath + ".partial";
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
        using (var stream = new FileStream(
            partialPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        if (File.Exists(finalPath))
            EnsureNoReparse(finalPath);
        File.Move(partialPath, finalPath, overwrite: true);
    }

    private IReadOnlyList<SpoolManifest> ReadAllManifests()
    {
        var result = new List<SpoolManifest>();
        var portableIds = new HashSet<PortableObjectId>();
        foreach (var path in Directory.EnumerateFiles(_root, "*.manifest.json").ToArray())
        {
            try
            {
                EnsureNoReparse(path);
                var manifest = JsonSerializer.Deserialize<SpoolManifest>(File.ReadAllBytes(path), JsonOptions)
                    ?? throw new PortableStateException("Manifest JSON is empty.");
                ValidateManifest(path, manifest);
                if (!portableIds.Add(manifest.PortableObjectId))
                    throw new PortableStateException("Duplicate PortableObjectId.");
                result.Add(manifest);
            }
            catch (Exception exception) when (IsRecoverableCorruption(exception))
            {
                Quarantine(path, "corrupt-manifest", "Manifest or referenced content failed validation.");
            }
        }
        var referenced = result.Select(x => x.ContentFileName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var content in Directory.EnumerateFiles(_root, "*.content").ToArray())
        {
            if (!referenced.Contains(Path.GetFileName(content)))
                Quarantine(content, "orphan-content", "Content has no valid manifest.");
        }
        return result;
    }

    private SpoolManifest ReadManifest(Guid id) =>
        ReadAllManifests().SingleOrDefault(x => x.SpoolId == id)
        ?? throw new PortableStateException($"Spool manifest '{id}' is unavailable or corrupt.");

    private string ManifestPath(Guid id) => ContainedPath($"{id:N}.manifest.json");

    private void Recover()
    {
        foreach (var partial in Directory.EnumerateFiles(_root, "*.partial").ToArray())
        {
            EnsureNoReparse(partial);
            File.Delete(partial);
            AddDiagnostic("orphan-partial-removed", Path.GetFileName(partial), "Incomplete spool write removed.");
        }

        _ = ReadAllManifests();
    }

    private void ValidateManifest(string manifestPath, SpoolManifest manifest)
    {
        if (manifest.SpoolId == Guid.Empty || manifest.PortableObjectId.Value == Guid.Empty)
            throw new PortableStateException("Manifest identifiers cannot be empty.");
        if (!Path.GetFileName(manifestPath).Equals($"{manifest.SpoolId:N}.manifest.json", StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Manifest filename does not match its spool ID.");
        if (manifest.Object is null ||
            string.IsNullOrWhiteSpace(manifest.Object.ObjectName) ||
            string.IsNullOrWhiteSpace(manifest.Object.LogicalObjectId) ||
            manifest.Object.Length < 0)
            throw new PortableStateException("Portable object descriptor is invalid.");
        PortableObjectDescriptor.ValidateSha256(manifest.Object.Sha256);
        if (string.IsNullOrWhiteSpace(manifest.ContentFileName) ||
            !manifest.ContentFileName.Equals($"{manifest.SpoolId:N}.content", StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Manifest content filename is invalid.");
        var contentPath = ContainedPath(manifest.ContentFileName);
        if (File.Exists(contentPath))
            EnsureNoReparse(contentPath);
        var info = new FileInfo(contentPath);
        if (!info.Exists || info.Length != manifest.Object.Length)
            throw new PortableStateException("Spool content length does not match its manifest.");
        using var content = new FileStream(contentPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actualHash = Convert.ToHexStringLower(SHA256.HashData(content));
        if (!string.Equals(actualHash, manifest.Object.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Spool content SHA-256 does not match its manifest.");
    }

    private string ContainedPath(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName) || Path.GetFileName(fileName) != fileName)
            throw new PortableStateException("Spool paths must be simple filenames.");
        var path = Path.GetFullPath(Path.Combine(_root, fileName));
        var prefix = _root.EndsWith(Path.DirectorySeparatorChar)
            ? _root
            : _root + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Spool path escapes its root.");
        return path;
    }

    private void Quarantine(string path, string code, string detail)
    {
        if (!File.Exists(path))
            return;
        EnsureNoReparse(path);
        var destination = Path.Combine(
            _quarantine,
            $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}-{Path.GetFileName(path)}");
        File.Move(path, destination);
        AddDiagnostic(code, Path.GetFileName(path), SecretRedactor.Redact(detail));
    }

    private void AddDiagnostic(string code, string fileName, string detail)
    {
        lock (_diagnostics)
            _diagnostics.Add(new(code, fileName, detail));
    }

    private static bool IsRecoverableCorruption(Exception exception) =>
        exception is not OutOfMemoryException and
        not StackOverflowException and
        not AccessViolationException;

    private static void EnsureNoReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new PortableStateException("Reparse points are not permitted in the portable-state spool.");
    }
}
