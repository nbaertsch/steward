using Steward.Agents;
using Steward.Contracts;
using Steward.Domain;
using Steward.Persistence.Sqlite;
using Steward.Terminal.Abstractions;

namespace Steward.Application;

public sealed record NodeEvidenceSummary(
    NodeIncarnationId NodeIncarnationId,
    long ContiguousCursor,
    string? LastFactKind,
    DateTimeOffset? LastFactAt,
    int ActiveAttemptCount,
    IReadOnlyList<TaskAttemptId> ActiveAttemptIds,
    bool ActiveAttemptsTruncated,
    int IncompletePortableObjects,
    int CheckpointObjects);

public sealed record ArtifactOperationsView(
    PortableObjectId PortableObjectId,
    PortableObjectKind Kind,
    string ContentHash,
    long SizeBytes,
    bool Complete,
    DateTimeOffset CreatedAt);

public sealed record OperationsSnapshot(
    DateTimeOffset CapturedAt,
    IReadOnlyList<ContractEnvelope<WorkloadDto>> Workloads,
    IReadOnlyList<ContractEnvelope<TaskDto>> Tasks,
    IReadOnlyList<ContractEnvelope<TaskAttemptDto>> Attempts,
    IReadOnlyList<ArtifactOperationsView> Artifacts,
    IReadOnlyList<AgentDescriptor> Agents,
    IReadOnlyList<AgentNotification> AgentNotifications,
    IReadOnlyList<NodeEvidenceSummary> NodeEvidence);

public sealed record TerminalPolicyStatus(
    bool Enabled,
    string Actor,
    IReadOnlyList<HostId> AllowedHosts,
    IReadOnlyList<string> AllowedWorkspaceRoots,
    IReadOnlyList<HostId> ElevatedHosts,
    TimeSpan MaximumDuration,
    long MaximumInputBytes,
    long MaximumOutputBytes);

public sealed class OperationsApplicationService(
    SqliteControlStore store,
    IAgentStore agents)
{
    public async Task<OperationsSnapshot> GetAsync(
        int limit = 1000,
        CancellationToken cancellationToken = default)
    {
        if (limit is <= 0 or > 5000)
            throw new ArgumentOutOfRangeException(nameof(limit));
        var workloads = await store.ListWorkloadsAsync(limit, cancellationToken);
        var tasks = await store.ListTasksAsync(limit, cancellationToken);
        var attempts = await store.ListTaskAttemptsAsync(limit, cancellationToken);
        var persistedArtifacts =
            await store.ListPortableObjectsAsync(limit, cancellationToken);
        var agentValues = await agents.ListAsync(cancellationToken);
        var notifications = new List<AgentNotification>();
        foreach (var agent in agentValues.Take(limit))
        {
            if (notifications.Count >= limit)
                break;
            notifications.AddRange(await agents.ReadAsync(
                agent.AgentId,
                0,
                Math.Min(100, limit - notifications.Count),
                cancellationToken));
        }
        var evidence = await ReadNodeEvidenceAsync(cancellationToken);
        var artifacts = persistedArtifacts.Select(value =>
            new ArtifactOperationsView(
                value.PortableObjectId,
                value.Kind,
                value.ContentHash,
                value.SizeBytes,
                value.Complete,
                value.CreatedAt)).ToArray();
        return new(
            DateTimeOffset.UtcNow,
            workloads,
            tasks,
            attempts,
            artifacts,
            agentValues.Take(limit).ToArray(),
            notifications,
            evidence);
    }

    private async Task<IReadOnlyList<NodeEvidenceSummary>> ReadNodeEvidenceAsync(
        CancellationToken cancellationToken)
    {
        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        var cursors = new Dictionary<NodeIncarnationId, long>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT node_incarnation_id,contiguous_cursor
                FROM orchestration_node_cursors
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                cursors[NodeIncarnationId.Parse(reader.GetString(0))] =
                    reader.GetInt64(1);
        }

        var latest = new Dictionary<NodeIncarnationId, (string Kind, DateTimeOffset At)>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT f.node_incarnation_id,f.kind,f.processed_at
                FROM orchestration_node_facts f
                INNER JOIN (
                  SELECT node_incarnation_id,MAX(sequence) sequence
                  FROM orchestration_node_facts GROUP BY node_incarnation_id
                ) last
                ON last.node_incarnation_id=f.node_incarnation_id
                   AND last.sequence=f.sequence
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                latest[NodeIncarnationId.Parse(reader.GetString(0))] =
                    (reader.GetString(1), DateTimeOffset.Parse(reader.GetString(2)));
        }

        var activeAttempts =
            new Dictionary<NodeIncarnationId, List<TaskAttemptId>>();
        var activeAttemptCounts = new Dictionary<NodeIncarnationId, int>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT
                  json_extract(snapshot_json,'$.payload.nodeIncarnationId'),
                  attempt_id
                FROM task_attempts
                WHERE state IN (
                  'Reserved','Dispatched','Accepted','Preparing',
                  'Launching','Running','Recovering')
                ORDER BY updated_at DESC,attempt_id
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var node = NodeIncarnationId.Parse(reader.GetString(0));
                activeAttemptCounts[node] =
                    activeAttemptCounts.GetValueOrDefault(node) + 1;
                var ids = activeAttempts.GetValueOrDefault(node);
                if (ids is null)
                {
                    ids = [];
                    activeAttempts[node] = ids;
                }
                if (ids.Count < 100)
                    ids.Add(TaskAttemptId.Parse(reader.GetString(1)));
            }
        }

        var incomplete = new Dictionary<NodeIncarnationId, int>();
        var checkpoints = new Dictionary<NodeIncarnationId, int>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT
                  json_extract(a.snapshot_json,'$.payload.nodeIncarnationId'),
                  SUM(CASE WHEN p.complete=0 THEN 1 ELSE 0 END),
                  SUM(CASE WHEN p.kind='TaskCheckpoint' THEN 1 ELSE 0 END)
                FROM portable_objects p
                INNER JOIN task_attempts a
                  ON json_extract(p.metadata_json,'$.taskAttemptId')=a.attempt_id
                GROUP BY
                  json_extract(a.snapshot_json,'$.payload.nodeIncarnationId')
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var node = NodeIncarnationId.Parse(reader.GetString(0));
                incomplete[node] = checked((int)reader.GetInt64(1));
                checkpoints[node] = checked((int)reader.GetInt64(2));
            }
        }

        return cursors.Keys
            .Concat(latest.Keys)
            .Concat(activeAttemptCounts.Keys)
            .Concat(incomplete.Keys)
            .Concat(checkpoints.Keys)
            .Distinct()
            .OrderBy(value => value.ToString(), StringComparer.Ordinal)
            .Select(node =>
            {
                var hasLatest = latest.TryGetValue(node, out var value);
                return new NodeEvidenceSummary(
                    node,
                    cursors.GetValueOrDefault(node),
                    hasLatest ? value.Kind : null,
                    hasLatest ? value.At : null,
                    activeAttemptCounts.GetValueOrDefault(node),
                    activeAttempts.GetValueOrDefault(node)?.ToArray() ?? [],
                    activeAttemptCounts.GetValueOrDefault(node) >
                        (activeAttempts.GetValueOrDefault(node)?.Count ?? 0),
                    incomplete.GetValueOrDefault(node),
                    checkpoints.GetValueOrDefault(node));
            })
            .ToArray();
    }

}

public sealed class TerminalPolicyStatusService(
    TerminalControlPolicy policy,
    ILocalActorContext actor)
{
    public TerminalPolicyStatus Get() =>
        new(
            policy.AllowedActors.Contains(actor.Actor) &&
            policy.AllowedHosts.Count > 0 &&
            policy.AllowedWorkspaceRoots.Count > 0,
            actor.Actor,
            policy.AllowedHosts.OrderBy(value => value.ToString(), StringComparer.Ordinal).ToArray(),
            policy.AllowedWorkspaceRoots.ToArray(),
            policy.ElevatedActors.Contains(actor.Actor)
                ? policy.ElevatedHosts.OrderBy(
                    value => value.ToString(),
                    StringComparer.Ordinal).ToArray()
                : [],
            policy.MaximumDuration,
            policy.MaximumInputBytes,
            policy.MaximumOutputBytes);
}
