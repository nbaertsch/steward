using System.Text.Json;

namespace Steward.PortableState;

public sealed record PortableManifestReference(
    string ObjectName,
    string Sha256,
    long Length,
    PortableObjectReceipt? Receipt);

public sealed record PortableManifest(
    string SchemaVersion,
    string LogicalId,
    IReadOnlyList<PortableManifestReference> Objects,
    DateTimeOffset CreatedAt);

public sealed class PortableManifestPublisher
{
    private readonly IPortableObjectStore _store;
    private readonly TimeProvider _timeProvider;

    public PortableManifestPublisher(IPortableObjectStore store, TimeProvider? timeProvider = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<ManifestReceipt> PublishAsync(
        string name,
        PortableManifest manifest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (manifest.Objects.Count == 0)
            throw new PortableStateException("A portable manifest must reference at least one object.");
        foreach (var reference in manifest.Objects)
        {
            var objectReceipt = reference.Receipt
                ?? throw new PortableStateException("All manifest references require committed receipts.");
            if (!string.Equals(objectReceipt.ObjectName, reference.ObjectName, StringComparison.Ordinal) ||
                !string.Equals(objectReceipt.Sha256, reference.Sha256, StringComparison.OrdinalIgnoreCase) ||
                objectReceipt.Length != reference.Length)
                throw new PortableStateException("A manifest reference does not match its committed receipt.");
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest);
        var sha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
        await using var content = new MemoryStream(bytes, writable: false);
        var receipt = await _store.PublishManifestAsync(name, content, sha256, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(receipt.Sha256, sha256, StringComparison.OrdinalIgnoreCase) ||
            receipt.Length != bytes.LongLength)
            throw new PortableStateException("Published manifest receipt failed integrity verification.");
        return new(name, sha256, bytes.LongLength, receipt.ETag, _timeProvider.GetUtcNow());
    }
}
