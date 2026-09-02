using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Domain;

namespace Steward.Providers.Abstractions;

public sealed record PoolPolicy(
    PoolId PoolId,
    int WarmMinimum,
    int HardMaximum,
    TimeSpan IdleTimeout,
    TimeSpan? StoppedRetention = null)
{
    public PoolPolicy Validate()
    {
        if (WarmMinimum < 0 ||
            HardMaximum < 1 ||
            WarmMinimum > HardMaximum ||
            IdleTimeout < TimeSpan.Zero ||
            StoppedRetention < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(WarmMinimum), "Invalid pool policy.");
        return this;
    }
}

public enum PoolMemberState
{
    Creating,
    Warm,
    Assigned,
    Draining,
    Stopped,
    Deleted,
    Failed
}
public enum PoolDemandClaimState { Claimed, Completed }
public enum PoolDemandClaimKind { Create, Assign }

public sealed record PoolMember(
    [property: JsonConverter(typeof(HostIdJsonConverter))]
    HostId HostId,
    [property: JsonConverter(typeof(PoolIdJsonConverter))]
    PoolId PoolId,
    [property: JsonConverter(typeof(NodeIncarnationIdJsonConverter))]
    NodeIncarnationId IncarnationId,
    string ProviderResourceName,
    PoolMemberState State,
    DateTimeOffset LastActiveAt,
    string? AffinityKey = null,
    string? DemandId = null,
    string? ProviderResourceId = null)
{
    [JsonIgnore]
    public Host Host => new(HostId, PoolId, IncarnationId);

    public static PoolMember FromHost(
        Host host, string providerResourceName, PoolMemberState state, DateTimeOffset lastActiveAt,
        string? affinityKey = null, string? demandId = null) =>
        new(host.Id, host.PoolId, host.NodeIncarnationId, providerResourceName, state, lastActiveAt, affinityKey, demandId);
}

public sealed record PoolDemandClaim(
    string DemandId,
    [property: JsonConverter(typeof(HostIdJsonConverter))]
    HostId HostId,
    PoolDemandClaimKind Kind,
    PoolDemandClaimState State,
    DateTimeOffset ClaimedAt,
    DateTimeOffset? CompletedAt = null,
    string? PreviousAffinityKey = null);

public sealed record PoolState(
    [property: JsonConverter(typeof(PoolIdJsonConverter))]
    PoolId PoolId,
    long Revision,
    IReadOnlyList<PoolMember> Members,
    IReadOnlyList<PoolDemandClaim> DemandClaims)
{
    public static PoolState Empty(PoolId poolId) => new(poolId, 0, [], []);
    [JsonIgnore]
    public IReadOnlyList<string> CompletedDemandIds =>
        DemandClaims.Where(x => x.State == PoolDemandClaimState.Completed).Select(x => x.DemandId).ToArray();
}

public interface IPoolStateStore
{
    Task<PoolState> LoadAsync(PoolId poolId, CancellationToken cancellationToken = default);
    Task<bool> TrySaveAsync(PoolState state, long expectedRevision, CancellationToken cancellationToken = default);
}

public sealed class InMemoryPoolStateStore : IPoolStateStore
{
    private readonly ConcurrentDictionary<PoolId, PoolState> _states = [];

    public Task<PoolState> LoadAsync(PoolId poolId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_states.TryGetValue(poolId, out var state) ? Snapshot(state) : PoolState.Empty(poolId));

    public Task<bool> TrySaveAsync(PoolState state, long expectedRevision, CancellationToken cancellationToken = default)
    {
        if (state.PoolId == default || state.Revision != expectedRevision + 1)
            throw new ArgumentException("Pool state identity or revision is invalid.", nameof(state));

        while (true)
        {
            if (!_states.TryGetValue(state.PoolId, out var current))
            {
                if (expectedRevision != 0)
                    return Task.FromResult(false);
                if (_states.TryAdd(state.PoolId, Snapshot(state)))
                    return Task.FromResult(true);
                continue;
            }

            if (current.Revision != expectedRevision)
                return Task.FromResult(false);
            return Task.FromResult(_states.TryUpdate(state.PoolId, Snapshot(state), current));
        }
    }

    private static PoolState Snapshot(PoolState state) =>
        state with { Members = state.Members.ToArray(), DemandClaims = state.DemandClaims.ToArray() };
}

public sealed record PoolDemand(string DemandId, string? AffinityKey = null);
public sealed record DemandRetention(IReadOnlySet<string> RetainedDemandIds, DateTimeOffset RetainCompletedAfter);
public enum PoolActionKind { Create, Start, Assign, Drain, Delete }
public sealed record PoolAction(PoolActionKind Kind, Host Host, string? DemandId = null, string? AffinityKey = null);
public sealed record PoolReconcileResult(IReadOnlyList<PoolAction> Actions, PoolState State)
{
    public IReadOnlyList<PoolMember> Members => State.Members;
}

public sealed class PoolCoordinator(IPoolStateStore store)
{
    public async Task<PoolReconcileResult> ReconcileAsync(
        PoolPolicy policy,
        IReadOnlyList<PoolDemand> demand,
        DateTimeOffset now,
        Func<Host> hostFactory,
        DemandRetention? retention = null,
        CancellationToken cancellationToken = default)
    {
        policy.Validate();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await store.LoadAsync(policy.PoolId, cancellationToken).ConfigureAwait(false);
            var (next, actions) = Plan(current, policy, demand, now, hostFactory, retention);
            if (await store.TrySaveAsync(next, current.Revision, cancellationToken).ConfigureAwait(false))
                return new(actions, next);
        }
    }

    public async Task UpdateMemberAsync(
        PoolId poolId,
        HostId hostId,
        PoolMemberState state,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await store.LoadAsync(poolId, cancellationToken).ConfigureAwait(false);
            var members = current.Members.ToList();
            var index = members.FindIndex(x => x.HostId == hostId);
            if (index < 0)
                throw new InvalidOperationException("Pool member does not exist.");
            members[index] = members[index] with { State = state, LastActiveAt = now };
            var next = current with { Revision = current.Revision + 1, Members = members };
            if (await store.TrySaveAsync(next, current.Revision, cancellationToken).ConfigureAwait(false))
                return;
        }
    }

    public async Task BindProviderResourceAsync(
        PoolId poolId,
        HostId hostId,
        string resourceName,
        string providerResourceId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerResourceId);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await store.LoadAsync(
                poolId,
                cancellationToken).ConfigureAwait(false);
            var members = current.Members.ToList();
            var index = members.FindIndex(x => x.HostId == hostId);
            if (index < 0)
                throw new InvalidOperationException(
                    "Pool member does not exist.");
            var member = members[index];
            if (member.ProviderResourceId is not null &&
                (!string.Equals(
                    member.ProviderResourceId,
                    providerResourceId,
                    StringComparison.Ordinal) ||
                 !string.Equals(
                    member.ProviderResourceName,
                    resourceName,
                    StringComparison.Ordinal)))
                throw new InvalidDataException(
                    "Pool member is already bound to another provider resource.");
            members[index] = member with
            {
                ProviderResourceName = resourceName,
                ProviderResourceId = providerResourceId,
                LastActiveAt = now
            };
            var next = current with
            {
                Revision = current.Revision + 1,
                Members = members
            };
            if (await store.TrySaveAsync(
                    next,
                    current.Revision,
                    cancellationToken).ConfigureAwait(false))
                return;
        }
    }

    public Task ConfirmDemandAsync(
        PoolId poolId,
        string demandId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default) =>
        MutateClaimAsync(poolId, demandId, (members, claims, index) =>
        {
            var claim = claims[index];
            claims[index] = claim with { State = PoolDemandClaimState.Completed, CompletedAt = now };
        }, cancellationToken);

    public Task ReleaseDemandAsync(
        PoolId poolId,
        string demandId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default) =>
        MutateClaimAsync(poolId, demandId, (members, claims, index) =>
        {
            var claim = claims[index];
            var memberIndex = members.FindIndex(x => x.HostId == claim.HostId && x.DemandId == demandId);
            if (memberIndex >= 0)
            {
                var member = members[memberIndex];
                members[memberIndex] = claim.Kind == PoolDemandClaimKind.Create
                    ? member with { State = PoolMemberState.Deleted, DemandId = null, LastActiveAt = now }
                    : member with
                    {
                        State = PoolMemberState.Warm,
                        DemandId = null,
                        AffinityKey = claim.PreviousAffinityKey,
                        LastActiveAt = now
                    };
            }
            claims.RemoveAt(index);
        }, cancellationToken);

    private async Task MutateClaimAsync(
        PoolId poolId,
        string demandId,
        Action<List<PoolMember>, List<PoolDemandClaim>, int> mutation,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await store.LoadAsync(poolId, cancellationToken).ConfigureAwait(false);
            var claims = current.DemandClaims.ToList();
            var index = claims.FindIndex(x => x.DemandId == demandId);
            if (index < 0)
                throw new InvalidOperationException("Demand claim does not exist.");
            var members = current.Members.ToList();
            mutation(members, claims, index);
            var next = current with { Revision = current.Revision + 1, Members = members, DemandClaims = claims };
            if (await store.TrySaveAsync(next, current.Revision, cancellationToken).ConfigureAwait(false))
                return;
        }
    }

    private static (PoolState State, IReadOnlyList<PoolAction> Actions) Plan(
        PoolState current,
        PoolPolicy policy,
        IReadOnlyList<PoolDemand> demand,
        DateTimeOffset now,
        Func<Host> hostFactory,
        DemandRetention? retention)
    {
        var members = current.Members.ToList();
        var claims = current.DemandClaims.ToList();
        if (retention is not null)
        {
            var removed = claims
                .Where(x => x.State == PoolDemandClaimState.Completed &&
                            x.CompletedAt < retention.RetainCompletedAfter &&
                            !retention.RetainedDemandIds.Contains(x.DemandId))
                .Select(x => x.DemandId)
                .ToHashSet(StringComparer.Ordinal);
            claims.RemoveAll(x => removed.Contains(x.DemandId));
            for (var i = 0; i < members.Count; i++)
                if (members[i].DemandId is { } id && removed.Contains(id))
                    members[i] = members[i] with { DemandId = null };
        }
        var actions = new List<PoolAction>();

        if (policy.StoppedRetention is { } retentionPeriod)
        {
            foreach (var stopped in members
                         .Where(x =>
                             x.State == PoolMemberState.Stopped &&
                             x.DemandId is null &&
                             now - x.LastActiveAt >= retentionPeriod)
                         .ToArray())
            {
                var index = members.IndexOf(stopped);
                members[index] = stopped with
                {
                    State = PoolMemberState.Draining,
                    LastActiveAt = now
                };
                actions.Add(new(PoolActionKind.Delete, stopped.Host));
            }
        }

        foreach (var item in demand.Where(x => claims.All(c => c.DemandId != x.DemandId)))
        {
            var index = members.FindIndex(x => x.State == PoolMemberState.Warm &&
                (item.AffinityKey is null || x.AffinityKey is null || x.AffinityKey == item.AffinityKey));
            if (index >= 0)
            {
                var candidate = members[index];
                members[index] = candidate with
                {
                    State = PoolMemberState.Assigned,
                    AffinityKey = item.AffinityKey,
                    LastActiveAt = now,
                    DemandId = item.DemandId
                };
                actions.Add(new(PoolActionKind.Assign, candidate.Host, item.DemandId, item.AffinityKey));
                claims.Add(new(item.DemandId, candidate.HostId, PoolDemandClaimKind.Assign,
                    PoolDemandClaimState.Claimed, now, PreviousAffinityKey: candidate.AffinityKey));
            }
            else if ((index = members.FindIndex(x =>
                         x.State == PoolMemberState.Stopped &&
                         (item.AffinityKey is null ||
                          x.AffinityKey is null ||
                          x.AffinityKey == item.AffinityKey))) >= 0)
            {
                var candidate = members[index];
                members[index] = candidate with
                {
                    State = PoolMemberState.Assigned,
                    AffinityKey = item.AffinityKey,
                    LastActiveAt = now,
                    DemandId = item.DemandId
                };
                actions.Add(new(
                    PoolActionKind.Start,
                    candidate.Host,
                    item.DemandId,
                    item.AffinityKey));
                claims.Add(new(
                    item.DemandId,
                    candidate.HostId,
                    PoolDemandClaimKind.Assign,
                    PoolDemandClaimState.Claimed,
                    now,
                    PreviousAffinityKey: candidate.AffinityKey));
            }
            else if (CountCapacity(members) < policy.HardMaximum)
            {
                var host = RequirePool(hostFactory(), policy.PoolId);
                members.Add(PoolMember.FromHost(
                    host, host.Id.ToString(), PoolMemberState.Creating, now, item.AffinityKey, item.DemandId));
                actions.Add(new(PoolActionKind.Create, host, item.DemandId, item.AffinityKey));
                claims.Add(new(item.DemandId, host.Id, PoolDemandClaimKind.Create, PoolDemandClaimState.Claimed, now));
            }
        }

        while (members.Count(x => x.State == PoolMemberState.Warm ||
                                  (x.State == PoolMemberState.Creating &&
                                   x.AffinityKey is null)) <
               policy.WarmMinimum &&
               (members.Any(x =>
                    x.State == PoolMemberState.Stopped &&
                    x.DemandId is null) ||
                CountCapacity(members) < policy.HardMaximum))
        {
            var stoppedIndex = members.FindIndex(x =>
                x.State == PoolMemberState.Stopped &&
                x.DemandId is null);
            if (stoppedIndex >= 0)
            {
                var stopped = members[stoppedIndex];
                members[stoppedIndex] = stopped with
                {
                    State = PoolMemberState.Warm,
                    LastActiveAt = now
                };
                actions.Add(new(PoolActionKind.Start, stopped.Host));
                continue;
            }
            var host = RequirePool(hostFactory(), policy.PoolId);
            members.Add(PoolMember.FromHost(host, host.Id.ToString(), PoolMemberState.Creating, now));
            actions.Add(new(PoolActionKind.Create, host));
        }

        var removable = Math.Max(0, members.Count(x => x.State == PoolMemberState.Warm) - policy.WarmMinimum);
        foreach (var idle in members
                     .Where(x => x.State == PoolMemberState.Warm && now - x.LastActiveAt >= policy.IdleTimeout)
                     .OrderBy(x => x.LastActiveAt)
                     .Take(removable)
                     .ToArray())
        {
            var index = members.IndexOf(idle);
            members[index] = idle with { State = PoolMemberState.Draining };
            actions.Add(new(PoolActionKind.Drain, idle.Host));
        }

        return (new(current.PoolId, current.Revision + 1, members,
            claims.OrderBy(x => x.DemandId, StringComparer.Ordinal).ToArray()), actions);
    }

    private static int CountCapacity(IEnumerable<PoolMember> members) =>
        members.Count(x => x.State is not PoolMemberState.Deleted);

    private static Host RequirePool(Host host, PoolId poolId) =>
        host.PoolId == poolId ? host : throw new InvalidOperationException("Host factory returned a Host for another Pool.");
}

public sealed class HostIdJsonConverter : JsonConverter<HostId>
{
    public override HostId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        HostId.Parse(reader.GetString() ?? "");
    public override void Write(Utf8JsonWriter writer, HostId value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToString());
}

public sealed class PoolIdJsonConverter : JsonConverter<PoolId>
{
    public override PoolId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        PoolId.Parse(reader.GetString() ?? "");
    public override void Write(Utf8JsonWriter writer, PoolId value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToString());
}

public sealed class NodeIncarnationIdJsonConverter : JsonConverter<NodeIncarnationId>
{
    public override NodeIncarnationId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        NodeIncarnationId.Parse(reader.GetString() ?? "");
    public override void Write(Utf8JsonWriter writer, NodeIncarnationId value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToString());
}
