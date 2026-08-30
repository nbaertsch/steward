using System.Text.Json;
using System.Runtime.Versioning;
using Azure.Identity;

namespace Steward.DevBox.Windows;

[SupportedOSPlatform("windows")]
public sealed class DevBoxIdentityStore
{
    private const string ContextFileName = "context.v1.json";
    private const string RecordFileName = "authentication-record.v1.json";
    private readonly string _directory;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public DevBoxIdentityStore(string? directory = null)
    {
        var selected = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Steward", "identity", "devbox", "default");
        if (!Path.IsPathFullyQualified(selected))
            throw new ArgumentException(
                "The Dev Box identity path must be absolute.",
                nameof(directory));
        _directory = Path.GetFullPath(selected);
        DevBoxIdentityStorageSecurity.PrepareDirectory(_directory);
    }

    public async Task SaveAsync(
        DevBoxIdentityContext context,
        AuthenticationRecord record,
        CancellationToken cancellationToken)
    {
        Validate(context);
        DevBoxIdentityStorageSecurity.EnsureSafeDirectory(_directory);
        var recordBytes = await SerializeRecordAsync(record, cancellationToken).ConfigureAwait(false);
        var contextBytes = JsonSerializer.SerializeToUtf8Bytes(context, _json);

        // The context is the commit marker. Readers never accept a record without it.
        await AtomicWriteAsync(RecordPath, recordBytes, cancellationToken).ConfigureAwait(false);
        await AtomicWriteAsync(ContextPath, contextBytes, cancellationToken).ConfigureAwait(false);
    }

    public async Task<(DevBoxIdentityContext Context, AuthenticationRecord Record)> LoadAsync(
        CancellationToken cancellationToken)
    {
        byte[] contextBytes;
        byte[] recordBytes;
        try
        {
            DevBoxIdentityStorageSecurity.EnsureSafeDirectory(_directory);
            if (!DevBoxIdentityStorageSecurity.IsSafeRegularFile(ContextPath) ||
                !DevBoxIdentityStorageSecurity.IsSafeRegularFile(RecordPath))
                throw new InvalidDataException(
                    "The devbox/default identity context is missing or unsafe.");
            contextBytes = await File.ReadAllBytesAsync(ContextPath, cancellationToken).ConfigureAwait(false);
            recordBytes = await File.ReadAllBytesAsync(RecordPath, cancellationToken).ConfigureAwait(false);
        }
        catch (FileNotFoundException exception)
        {
            throw new InvalidDataException("The devbox/default identity context is missing.", exception);
        }
        catch (DirectoryNotFoundException exception)
        {
            throw new InvalidDataException("The devbox/default identity context is missing.", exception);
        }

        try
        {
            var context = JsonSerializer.Deserialize<DevBoxIdentityContext>(contextBytes, _json)
                ?? throw new InvalidDataException("The Dev Box identity context is empty.");
            Validate(context);
            await using var stream = new MemoryStream(recordBytes, writable: false);
            var record = await AuthenticationRecord.DeserializeAsync(stream, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(record.TenantId, context.TenantId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(record.ClientId, context.ClientId, StringComparison.Ordinal) ||
                !string.Equals(record.HomeAccountId, context.HomeAccountId, StringComparison.Ordinal) ||
                !string.Equals(record.Authority, context.Authority, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(record.Username, context.Username, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The Dev Box authentication record does not match its context.");
            return (context, record);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The Dev Box identity context is corrupt.", exception);
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidDataException("The Dev Box authentication record is unsupported.", exception);
        }
    }

    public bool Exists => File.Exists(ContextPath);

    public void Delete()
    {
        DevBoxIdentityStorageSecurity.EnsureSafeDirectory(_directory);
        foreach (var path in new[] { ContextPath, RecordPath })
        {
            if (File.Exists(path))
            {
                if (!DevBoxIdentityStorageSecurity.IsSafeRegularFile(path))
                    throw new IOException(
                        "The Dev Box identity context contains an unsafe file.");
                File.Delete(path);
            }
        }
        foreach (var pending in Directory.EnumerateFiles(
                     _directory,
                     "*.new",
                     SearchOption.TopDirectoryOnly))
        {
            if (!DevBoxIdentityStorageSecurity.IsSafeRegularFile(pending))
                throw new IOException(
                    "The Dev Box identity context contains an unsafe file.");
            File.Delete(pending);
        }
        if (Directory.EnumerateFileSystemEntries(_directory).Any())
            throw new IOException(
                "The Dev Box identity context contains unexpected files.");
        Directory.Delete(_directory);
    }

    private string ContextPath => Path.Combine(_directory, ContextFileName);
    private string RecordPath => Path.Combine(_directory, RecordFileName);

    private static void Validate(DevBoxIdentityContext context)
    {
        if (context.Version != DevBoxIdentityConstants.CurrentVersion ||
            context.Name != DevBoxIdentityConstants.ContextName ||
            context.CacheName != DevBoxIdentityConstants.CacheName ||
            !Guid.TryParse(context.TenantId, out _) ||
            !IsPublicCloudAuthority(context.Authority) ||
            string.IsNullOrWhiteSpace(context.ClientId) ||
            string.IsNullOrWhiteSpace(context.HomeAccountId) ||
            string.IsNullOrWhiteSpace(context.Username))
            throw new InvalidDataException("The Dev Box identity context is invalid or unsupported.");
    }

    private static bool IsPublicCloudAuthority(string authority)
    {
        if (string.Equals(authority, "login.microsoftonline.com", StringComparison.OrdinalIgnoreCase))
            return true;
        return Uri.TryCreate(authority, UriKind.Absolute, out var uri) &&
            uri.Scheme == Uri.UriSchemeHttps &&
            uri.Port == 443 &&
            uri.UserInfo.Length == 0 &&
            string.Equals(uri.IdnHost, "login.microsoftonline.com", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<byte[]> SerializeRecordAsync(
        AuthenticationRecord record,
        CancellationToken cancellationToken)
    {
        await using var stream = new MemoryStream();
        await record.SerializeAsync(stream, cancellationToken).ConfigureAwait(false);
        return stream.ToArray();
    }

    private static async Task AtomicWriteAsync(
        string path,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            await using (var stream = new FileStream(
                temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            DevBoxIdentityStorageSecurity.RestrictFile(temporary);
            if (File.Exists(path))
            {
                if (!DevBoxIdentityStorageSecurity.IsSafeRegularFile(path))
                    throw new IOException(
                        "The Dev Box identity destination is unsafe.");
                File.Replace(temporary, path, null);
            }
            else
                File.Move(temporary, path);
            DevBoxIdentityStorageSecurity.RestrictFile(path);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}
