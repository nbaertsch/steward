using Steward.Domain;
using Steward.Persistence.Sqlite;
using Steward.PortableState;

namespace Steward.Control;

public sealed class ControlPortableDownloadService(
    SqliteControlStore catalog,
    IPortableObjectStore store)
{
    public async Task<(Stream Content, string MediaType, long Length)> OpenAsync(
        PortableObjectId id,
        CancellationToken cancellationToken = default)
    {
        var receipt = await catalog.GetPortableObjectAsync(id, cancellationToken)
            ?? throw new KeyNotFoundException("Portable object does not exist.");
        if (!receipt.Complete || string.IsNullOrWhiteSpace(receipt.StoreReceipt))
            throw new InvalidOperationException("Portable object has no complete replicated receipt.");
        var reference = new Uri(receipt.StoreReceipt, UriKind.Absolute);
        if (reference.Scheme != "portable")
            throw new InvalidDataException("Portable store receipt is invalid.");
        var objectName = $"{reference.Host}{reference.AbsolutePath}".Trim('/');
        var content = await store.OpenReadAsync(objectName, cancellationToken);
        return (content, "application/octet-stream", receipt.SizeBytes);
    }
}
