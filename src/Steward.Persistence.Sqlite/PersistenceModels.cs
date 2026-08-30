using Steward.Domain;

namespace Steward.Persistence.Sqlite;

public enum AggregateKind { Workload, Task, TaskAttempt }

public enum PersistenceErrorCode
{
    RevisionConflict,
    IdempotencyConflict,
    NotFound,
    InvalidBackup,
    SchemaVersionMismatch
}

public sealed class PersistenceException : InvalidOperationException
{
    public PersistenceErrorCode Code { get; }

    public PersistenceException(PersistenceErrorCode code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;
}

public sealed record AggregateSnapshot(
    AggregateKind Kind,
    string Id,
    long Revision,
    string SnapshotJson,
    string? ParentId = null,
    int? Generation = null,
    string? State = null);

public sealed record OutboxMessage(
    string MessageId,
    string Kind,
    string PayloadJson,
    string? IdempotencyKey = null,
    DateTimeOffset? AvailableAt = null);

public sealed record AggregateOutboxItem(
    long Sequence,
    string MessageId,
    string Kind,
    string PayloadJson,
    DateTimeOffset CreatedAt,
    DateTimeOffset AvailableAt,
    DateTimeOffset? AcknowledgedAt);

public sealed record CommandOutboxItem(
    long Sequence,
    CommandId CommandId,
    string IdempotencyKey,
    string PayloadJson,
    DateTimeOffset CreatedAt,
    DateTimeOffset AvailableAt,
    DateTimeOffset? AcknowledgedAt);

public sealed record NotificationOutboxItem(
    long Cursor,
    NotificationId NotificationId,
    string Stream,
    string PayloadJson,
    DateTimeOffset CreatedAt,
    DateTimeOffset? AcknowledgedAt);

public sealed record PortableObjectReceipt(
    PortableObjectId PortableObjectId,
    PortableObjectKind Kind,
    string ContentHash,
    long SizeBytes,
    bool Complete,
    string? StoreReceipt,
    string MetadataJson,
    DateTimeOffset CreatedAt);

public sealed record BackupManifest(
    int ManifestVersion,
    int SchemaVersion,
    DateTimeOffset CreatedAt,
    string DatabaseFile,
    string DatabaseSha256,
    IReadOnlyList<PortableObjectReference> ReferencedPortableObjects);

public sealed record PortableObjectReference(
    PortableObjectId PortableObjectId,
    string ContentHash,
    long SizeBytes,
    string? StoreReceipt);

public sealed record BackupExport(string DatabasePath, string ManifestPath, BackupManifest Manifest);
