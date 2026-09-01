using System.Text.Json;
using Steward.Domain;
using Steward.Persistence.Sqlite;

namespace Steward.Control;

// Compatibility types preserve the original Control API while implementations live in Steward.Application.
internal sealed record CreateWorkloadRequest(
    string WorkloadType,
    string PlannerKind,
    string PlannerVersion,
    JsonElement PlannerData,
    WorkloadId? WorkloadId = null,
    PlanRevisionId? PlanRevisionId = null,
    string? IdempotencyKey = null)
    : Steward.Application.CreateWorkloadRequest(
        WorkloadType, PlannerKind, PlannerVersion, PlannerData, WorkloadId, PlanRevisionId, IdempotencyKey);

internal sealed class WorkloadApplicationService(SqliteControlStore store)
    : Steward.Application.WorkloadApplicationService(store);

public sealed class OutboxApplicationService(SqliteControlStore store)
    : Steward.Application.OutboxApplicationService(store);

public sealed class NotificationApplicationService(SqliteControlStore store)
    : Steward.Application.NotificationApplicationService(store);

public sealed record DoctorResult(
    bool Healthy,
    int SchemaVersion,
    string JournalMode,
    bool ForeignKeys,
    string Integrity,
    string DatabasePath);

public sealed class DoctorApplicationService(SqliteControlStore store)
    : Steward.Application.DoctorApplicationService(store)
{
    public new async Task<DoctorResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        var result = await base.CheckAsync(cancellationToken);
        return new(
            result.Healthy,
            result.SchemaVersion,
            result.JournalMode,
            result.ForeignKeys,
            result.Integrity,
            result.DatabasePath);
    }
}
