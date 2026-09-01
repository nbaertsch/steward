using System.Collections.Concurrent;
using Steward.Domain;

namespace Steward.Orchestration;

public sealed class ControlNodeLivenessRegistry
{
    private readonly ConcurrentDictionary<
        (HostId HostId, NodeIncarnationId IncarnationId),
        Observation> observations = new();

    public Guid MarkOnline(
        HostId hostId,
        NodeIncarnationId incarnationId,
        DateTimeOffset observedAt)
    {
        var leaseId = Guid.NewGuid();
        var key = (hostId, incarnationId);
        var normalized = observedAt.ToUniversalTime();
        observations.AddOrUpdate(
            key,
            _ => new(leaseId, normalized),
            (_, current) => new(
                leaseId,
                current.ObservedAt >= normalized
                    ? current.ObservedAt
                    : normalized));
        return leaseId;
    }

    public void Refresh(
        HostId hostId,
        NodeIncarnationId incarnationId,
        Guid leaseId,
        DateTimeOffset observedAt)
    {
        var key = (hostId, incarnationId);
        var normalized = observedAt.ToUniversalTime();
        while (observations.TryGetValue(key, out var current))
        {
            if (current.LeaseId != leaseId || current.ObservedAt >= normalized)
                return;
            if (observations.TryUpdate(
                    key,
                    current with { ObservedAt = normalized },
                    current))
                return;
        }
    }

    public bool MarkOffline(
        HostId hostId,
        NodeIncarnationId incarnationId,
        Guid leaseId)
    {
        var key = (hostId, incarnationId);
        if (observations.TryGetValue(key, out var current) &&
            current.LeaseId == leaseId)
            return observations.TryRemove(
                new KeyValuePair<
                    (HostId HostId, NodeIncarnationId IncarnationId),
                    Observation>(key, current));
        return false;
    }

    public bool TryGetOnline(
        HostId hostId,
        NodeIncarnationId incarnationId,
        out DateTimeOffset observedAt)
    {
        if (observations.TryGetValue(
                (hostId, incarnationId),
                out var observation))
        {
            observedAt = observation.ObservedAt;
            return true;
        }
        observedAt = default;
        return false;
    }

    private sealed record Observation(
        Guid LeaseId,
        DateTimeOffset ObservedAt);
}
