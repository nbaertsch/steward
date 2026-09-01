using System.Security.Cryptography;
using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.Persistence.Sqlite;

namespace Steward.Application;

internal record CreateWorkloadRequest(
    string WorkloadType,
    string PlannerKind,
    string PlannerVersion,
    JsonElement PlannerData,
    WorkloadId? WorkloadId = null,
    PlanRevisionId? PlanRevisionId = null,
    string? IdempotencyKey = null);

internal class WorkloadApplicationService(SqliteControlStore store)
{
    public async Task<ContractEnvelope<WorkloadDto>> CreateAsync(
        CreateWorkloadRequest request, CancellationToken cancellationToken = default)
    {
        Validate(request);
        if (request.PlannerKind is "harbor" or "saber" or "process" or "compose")
            throw new ApplicationContractException(
                "DraftOnlyEndpoint",
                "Executable workload kinds must use ExecutableWorkloadApplicationService.SubmitAsync.");
        var id = request.WorkloadId ?? WorkloadId.New();
        var payload = new WorkloadDto(
            id,
            request.PlanRevisionId ?? PlanRevisionId.New(),
            request.WorkloadType,
            WorkloadDesiredState.Active,
            WorkloadObservedState.Planning,
            [],
            [],
            ExtensionMetadataDto.Create(
                request.PlannerKind,
                request.PlannerVersion,
                request.PlannerData.Clone(),
                StewardJson.Options));
        var snapshot = new ContractEnvelope<WorkloadDto>(
            "steward.workload", "1.0.0", [], [], DateTimeOffset.UtcNow, 0, payload);
        if (request.IdempotencyKey is { } key)
            return await store.CreateWorkloadIdempotentAsync(
                snapshot,
                key,
                ComputeNormalizedHash(request),
                cancellationToken: cancellationToken);

        await store.SaveWorkloadAsync(snapshot, null, cancellationToken: cancellationToken);
        return snapshot;
    }

    public Task<ContractEnvelope<WorkloadDto>?> GetAsync(
        WorkloadId id, CancellationToken cancellationToken = default) =>
        store.GetWorkloadAsync(id, cancellationToken);

    public static string ComputeNormalizedHash(CreateWorkloadRequest request)
    {
        Validate(request);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("plannerKind", request.PlannerKind);
            writer.WritePropertyName("plannerData");
            WriteCanonical(writer, request.PlannerData);
            writer.WriteString("plannerVersion", request.PlannerVersion);
            if (request.PlanRevisionId is { } revision)
                writer.WriteString("planRevisionId", revision.ToString());
            if (request.WorkloadId is { } workload)
                writer.WriteString("workloadId", workload.ToString());
            writer.WriteString("workloadType", request.WorkloadType);
            writer.WriteEndObject();
        }
        return Convert.ToHexString(SHA256.HashData(stream.ToArray()));
    }

    private static void Validate(CreateWorkloadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateName(request.WorkloadType, nameof(request.WorkloadType));
        ValidateName(request.PlannerKind, nameof(request.PlannerKind));
        ValidateName(request.PlannerVersion, nameof(request.PlannerVersion));
        if (request.IdempotencyKey is { } key &&
            (string.IsNullOrWhiteSpace(key) || key.Length > ApplicationLimits.IdempotencyKeyLength))
            throw Invalid(nameof(request.IdempotencyKey));
        if (request.PlannerData.ValueKind == JsonValueKind.Undefined ||
            request.PlannerData.GetRawText().Length > ApplicationLimits.PlannerDataLength ||
            Depth(request.PlannerData) > ApplicationLimits.PlannerDataDepth)
            throw Invalid(nameof(request.PlannerData));
    }

    private static void ValidateName(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > ApplicationLimits.NameLength)
            throw Invalid(name);
    }

    private static ApplicationContractException Invalid(string name) =>
        new("InvalidArgument", $"{name} exceeds Steward's bounded input contract.");

    private static int Depth(JsonElement value) =>
        value.ValueKind switch
        {
            JsonValueKind.Array => 1 + value.EnumerateArray().Select(Depth).DefaultIfEmpty(0).Max(),
            JsonValueKind.Object => 1 + value.EnumerateObject().Select(x => Depth(x.Value)).DefaultIfEmpty(0).Max(),
            _ => 1
        };

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            writer.WriteStartObject();
            foreach (var property in value.EnumerateObject().OrderBy(x => x.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(property.Name);
                WriteCanonical(writer, property.Value);
            }
            writer.WriteEndObject();
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            writer.WriteStartArray();
            foreach (var item in value.EnumerateArray())
                WriteCanonical(writer, item);
            writer.WriteEndArray();
        }
        else
        {
            value.WriteTo(writer);
        }
    }
}

public class OutboxApplicationService(SqliteControlStore store)
{
    public Task<IReadOnlyList<AggregateOutboxItem>> ReadAsync(
        int limit, CancellationToken cancellationToken = default) =>
        store.ReadOutboxAsync(limit, cancellationToken: cancellationToken);

    public Task AcknowledgeAsync(long sequence, CancellationToken cancellationToken = default) =>
        store.AcknowledgeOutboxAsync(sequence, cancellationToken);
}

public class NotificationApplicationService(SqliteControlStore store)
{
    public Task<IReadOnlyList<NotificationOutboxItem>> ReadAsync(
        string stream, long afterCursor, int limit, CancellationToken cancellationToken = default)
    {
        Validate(stream, afterCursor);
        if (limit is < 1 or > ApplicationLimits.NotificationLimit)
            throw new ApplicationContractException("InvalidArgument", "limit must be between 1 and 50.");
        return store.ReadNotificationsAsync(stream, afterCursor, limit, cancellationToken);
    }

    public Task AcknowledgeAsync(
        string stream, long throughCursor, CancellationToken cancellationToken = default)
    {
        Validate(stream, throughCursor);
        return store.AcknowledgeNotificationsAsync(stream, throughCursor, cancellationToken);
    }

    private static void Validate(string stream, long cursor)
    {
        if (string.IsNullOrWhiteSpace(stream) ||
            stream.Length > ApplicationLimits.NotificationStreamLength ||
            cursor < 0)
            throw new ApplicationContractException("InvalidArgument", "Notification stream or cursor is outside the bounded contract.");
    }
}

public record DoctorResult(
    bool Healthy,
    int SchemaVersion,
    string JournalMode,
    bool ForeignKeys,
    string Integrity,
    string DatabasePath);

public class DoctorApplicationService(SqliteControlStore store)
{
    public async Task<DoctorResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        static async Task<string> ScalarAsync(
            Microsoft.Data.Sqlite.SqliteConnection connection, string sql, CancellationToken token)
        {
            var command = connection.CreateCommand();
            command.CommandText = sql;
            return Convert.ToString(await command.ExecuteScalarAsync(token)) ?? string.Empty;
        }

        var journal = await ScalarAsync(connection, "PRAGMA journal_mode;", cancellationToken);
        var foreignKeys = await ScalarAsync(connection, "PRAGMA foreign_keys;", cancellationToken) == "1";
        var integrity = await ScalarAsync(connection, "PRAGMA integrity_check;", cancellationToken);
        var version = await store.GetSchemaVersionAsync(cancellationToken);
        return new(
            version == SchemaMigrator.CurrentVersion &&
            string.Equals(journal, "wal", StringComparison.OrdinalIgnoreCase) &&
            foreignKeys &&
            string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase),
            version, journal, foreignKeys, integrity, store.DatabasePath);
    }
}
