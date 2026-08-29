using System.Security.Cryptography;

namespace Steward.PortableState;

[Flags]
public enum PortableStorePermission
{
    None = 0,
    Read = 1,
    Create = 2,
    Write = 4,
    Delete = 8
}

public enum TransportHashAlgorithm
{
    Md5,
    Crc64
}

public sealed record PortableStoreAuthority(
    DateTimeOffset ExpiresAt,
    PortableStorePermission Permissions,
    string Kind)
{
    public bool IsValidFor(DateTimeOffset now, PortableStorePermission required) =>
        now < ExpiresAt && (Permissions & required) == required;
}

public sealed record PortableObjectDescriptor(
    string ObjectName,
    string LogicalObjectId,
    string SchemaVersion,
    string ContentType,
    string Sha256,
    long Length,
    IReadOnlyDictionary<string, string> Lineage)
{
    public static string ContentAddressedName(string category, string sha256)
    {
        ValidateSha256(sha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(category);
        var normalizedCategory = category.Trim('/');
        ValidateObjectName(normalizedCategory);
        return $"{normalizedCategory}/{sha256.ToLowerInvariant()}";
    }

    public static void ValidateSha256(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != 64 || !value.All(Uri.IsHexDigit))
            throw new ArgumentException("SHA-256 must be 64 hexadecimal characters.", nameof(value));
    }

    public static void ValidateObjectName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 1024 ||
            value.Contains('\\') ||
            value.Contains('%') ||
            value.Contains('?') ||
            value.Contains('#') ||
            value.Contains("://", StringComparison.Ordinal) ||
            Path.IsPathFullyQualified(value))
            throw new ArgumentException("Portable object names must be bounded logical names, not paths or URIs.", nameof(value));
        var segments = value.Split('/');
        if (segments.Any(segment =>
                string.IsNullOrWhiteSpace(segment) ||
                segment is "." or ".." ||
                segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
            throw new ArgumentException("Portable object names contain an invalid or traversing segment.", nameof(value));
    }
}

public sealed record StagedBlock(string BlockId, long Length);

public sealed record PortableObjectProperties(
    long Length,
    string Sha256,
    string ETag,
    IReadOnlyDictionary<string, string> Metadata);

public sealed record PortableObjectReceipt(
    string ObjectName,
    string Sha256,
    long Length,
    string ETag,
    DateTimeOffset CommittedAt);

public sealed record ManifestReceipt(
    string ManifestName,
    string Sha256,
    long Length,
    string ETag,
    DateTimeOffset PublishedAt);

public interface IPortableObjectStore
{
    PortableStoreAuthority Authority { get; }

    Task<IReadOnlyList<StagedBlock>> GetUncommittedBlocksAsync(
        string objectName,
        CancellationToken cancellationToken = default);

    Task StageBlockAsync(
        string objectName,
        string blockId,
        Stream content,
        long length,
        TransportHashAlgorithm hashAlgorithm,
        ReadOnlyMemory<byte> transactionalHash,
        CancellationToken cancellationToken = default);

    Task<string> CommitBlockListAsync(
        PortableObjectDescriptor descriptor,
        IReadOnlyList<string> orderedBlockIds,
        CancellationToken cancellationToken = default);

    Task<PortableObjectProperties?> GetPropertiesAsync(
        string objectName,
        CancellationToken cancellationToken = default);

    Task<Stream> OpenReadAsync(string objectName, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(string objectName, CancellationToken cancellationToken = default);

    Task<PortableObjectReceipt> PublishManifestAsync(
        string manifestName,
        Stream content,
        string contentSha256,
        CancellationToken cancellationToken = default);
}

public sealed class PortableStateException : InvalidOperationException
{
    public PortableStateException(
        string message,
        PortableFailureCode code = PortableFailureCode.Unknown) : base(message) =>
        Code = code;

    public PortableStateException(
        string message,
        Exception innerException,
        PortableFailureCode code = PortableFailureCode.Unknown) : base(message, innerException) =>
        Code = code;

    public PortableFailureCode Code { get; }
}

internal static class Hashing
{
    public static async Task<string> Sha256HexAsync(Stream stream, CancellationToken cancellationToken)
    {
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexStringLower(hash);
    }
}
