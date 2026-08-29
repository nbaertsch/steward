using Steward.Domain;

namespace Steward.PortableState;

public sealed record DestinationRestoreReceipt(
    StewardAgentId AgentId,
    HostId DestinationHostId,
    string BundleSha256,
    bool HashesVerified,
    bool ReadinessPassed,
    DateTimeOffset RestoredAt);

public sealed record DestinationActivationReceipt(
    StewardAgentId AgentId,
    HostId DestinationHostId,
    long PlacementGeneration,
    string ActivationReceiptId,
    bool CredentialsRebrokered,
    DateTimeOffset ActivatedAt);

public enum MigrationResumeAction
{
    ActivateDestination,
    ReleaseSource,
    Complete
}

public sealed record MigrationHandoffRecord(
    StewardAgentId AgentId,
    HostId SourceHostId,
    HostId DestinationHostId,
    long ExpectedPlacementGeneration,
    long CommittedPlacementGeneration,
    PortableObjectReceipt SourceReceipt,
    DestinationRestoreReceipt DestinationReceipt,
    DestinationActivationReceipt? ActivationReceipt,
    bool SourceReleased,
    DateTimeOffset CommittedAt)
{
    public MigrationResumeAction ResumeAction => SourceReleased
        ? MigrationResumeAction.Complete
        : ActivationReceipt is null
            ? MigrationResumeAction.ActivateDestination
            : MigrationResumeAction.ReleaseSource;
}

public interface IAgentPlacementStore
{
    Task<long> GetGenerationAsync(StewardAgentId agentId, CancellationToken cancellationToken = default);

    Task<bool> TryCommitHandoffAsync(
        MigrationHandoffRecord handoff,
        long expectedGeneration,
        CancellationToken cancellationToken = default);

    Task<bool> TryRecordDestinationActiveAsync(
        DestinationActivationReceipt receipt,
        CancellationToken cancellationToken = default);

    Task MarkSourceReleasedAsync(
        StewardAgentId agentId,
        long committedGeneration,
        CancellationToken cancellationToken = default);

    Task<MigrationHandoffRecord?> GetHandoffAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken = default);
}

public interface ISourceWorkspaceReleaser
{
    Task ReleaseAsync(
        HostId sourceHostId,
        StewardAgentId agentId,
        long committedPlacementGeneration,
        CancellationToken cancellationToken = default);
}

public sealed class MigrationCoordinator
{
    private readonly IAgentPlacementStore _placements;
    private readonly ISourceWorkspaceReleaser _releaser;
    private readonly TimeProvider _timeProvider;

    public MigrationCoordinator(
        IAgentPlacementStore placements,
        ISourceWorkspaceReleaser releaser,
        TimeProvider? timeProvider = null)
    {
        _placements = placements ?? throw new ArgumentNullException(nameof(placements));
        _releaser = releaser ?? throw new ArgumentNullException(nameof(releaser));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<MigrationHandoffRecord?> TryCommitPlacementAsync(
        StewardAgentId agentId,
        HostId sourceHostId,
        HostId destinationHostId,
        long expectedGeneration,
        PortableObjectReceipt sourceReceipt,
        DestinationRestoreReceipt destinationReceipt,
        CancellationToken cancellationToken = default)
    {
        ValidateRestore(agentId, destinationHostId, sourceReceipt, destinationReceipt);
        if (expectedGeneration < 0)
            throw new ArgumentOutOfRangeException(nameof(expectedGeneration));

        var handoff = new MigrationHandoffRecord(
            agentId,
            sourceHostId,
            destinationHostId,
            expectedGeneration,
            checked(expectedGeneration + 1),
            sourceReceipt,
            destinationReceipt,
            null,
            false,
            _timeProvider.GetUtcNow());
        return await _placements.TryCommitHandoffAsync(handoff, expectedGeneration, cancellationToken)
            .ConfigureAwait(false)
            ? handoff
            : null;
    }

    public async Task<MigrationHandoffRecord> RecordDestinationActiveAsync(
        DestinationActivationReceipt activationReceipt,
        CancellationToken cancellationToken = default)
    {
        ValidateActivation(activationReceipt);
        var handoff = await RequireHandoffAsync(activationReceipt.AgentId, cancellationToken).ConfigureAwait(false);
        EnsureActivationMatches(handoff, activationReceipt);
        if (handoff.ActivationReceipt is not null)
        {
            if (handoff.ActivationReceipt != activationReceipt)
                throw new PortableStateException("A different destination activation receipt is already committed.");
            return handoff;
        }
        if (!await _placements.TryRecordDestinationActiveAsync(activationReceipt, cancellationToken).ConfigureAwait(false))
            throw new PortableStateException("Destination activation receipt conflicted with the committed handoff.");
        return handoff with { ActivationReceipt = activationReceipt };
    }

    public async Task<MigrationHandoffRecord> ReleaseSourceAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken = default)
    {
        var handoff = await RequireHandoffAsync(agentId, cancellationToken).ConfigureAwait(false);
        if (handoff.SourceReleased)
            return handoff;
        if (handoff.ActivationReceipt is null)
            throw new PortableStateException("Source release requires a durable destination-active receipt.");

        await _releaser.ReleaseAsync(
            handoff.SourceHostId,
            handoff.AgentId,
            handoff.CommittedPlacementGeneration,
            cancellationToken).ConfigureAwait(false);
        await _placements.MarkSourceReleasedAsync(
            handoff.AgentId,
            handoff.CommittedPlacementGeneration,
            cancellationToken).ConfigureAwait(false);
        return handoff with { SourceReleased = true };
    }

    public async Task<MigrationHandoffRecord> InspectAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken = default) =>
        await RequireHandoffAsync(agentId, cancellationToken).ConfigureAwait(false);

    private async Task<MigrationHandoffRecord> RequireHandoffAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken) =>
        await _placements.GetHandoffAsync(agentId, cancellationToken).ConfigureAwait(false)
        ?? throw new PortableStateException("No committed migration handoff exists.");

    private static void ValidateRestore(
        StewardAgentId agentId,
        HostId destinationHostId,
        PortableObjectReceipt sourceReceipt,
        DestinationRestoreReceipt destinationReceipt)
    {
        if (!destinationReceipt.HashesVerified || !destinationReceipt.ReadinessPassed)
            throw new PortableStateException("Destination must verify bundle hashes and readiness before placement.");
        if (destinationReceipt.AgentId != agentId || destinationReceipt.DestinationHostId != destinationHostId)
            throw new PortableStateException("Destination restore receipt does not match the migration.");
        if (!string.Equals(destinationReceipt.BundleSha256, sourceReceipt.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new PortableStateException("Destination restored a different source bundle.");
    }

    private static void ValidateActivation(DestinationActivationReceipt receipt)
    {
        if (receipt.PlacementGeneration <= 0 ||
            string.IsNullOrWhiteSpace(receipt.ActivationReceiptId) ||
            !receipt.CredentialsRebrokered)
            throw new PortableStateException(
                "Destination activation must prove active placement and credential rebroker.");
    }

    private static void EnsureActivationMatches(
        MigrationHandoffRecord handoff,
        DestinationActivationReceipt receipt)
    {
        if (receipt.AgentId != handoff.AgentId ||
            receipt.DestinationHostId != handoff.DestinationHostId ||
            receipt.PlacementGeneration != handoff.CommittedPlacementGeneration)
            throw new PortableStateException("Destination activation does not match the winning placement.");
    }
}

public sealed class InMemoryAgentPlacementStore : IAgentPlacementStore
{
    private readonly object _gate = new();
    private readonly Dictionary<StewardAgentId, long> _generations = [];
    private readonly Dictionary<StewardAgentId, MigrationHandoffRecord> _handoffs = [];

    public Task<long> GetGenerationAsync(StewardAgentId agentId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
            return Task.FromResult(_generations.GetValueOrDefault(agentId));
    }

    public Task<bool> TryCommitHandoffAsync(
        MigrationHandoffRecord handoff,
        long expectedGeneration,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (handoff.ActivationReceipt is not null || handoff.SourceReleased)
                throw new PortableStateException("A new handoff must begin before destination activation.");
            var current = _generations.GetValueOrDefault(handoff.AgentId);
            if (current != expectedGeneration)
                return Task.FromResult(false);
            _generations[handoff.AgentId] = handoff.CommittedPlacementGeneration;
            _handoffs[handoff.AgentId] = handoff;
            return Task.FromResult(true);
        }
    }

    public Task<bool> TryRecordDestinationActiveAsync(
        DestinationActivationReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (receipt.PlacementGeneration <= 0 ||
                string.IsNullOrWhiteSpace(receipt.ActivationReceiptId) ||
                !receipt.CredentialsRebrokered)
                throw new PortableStateException("Destination-active receipt is invalid.");
            if (!_handoffs.TryGetValue(receipt.AgentId, out var handoff) ||
                handoff.CommittedPlacementGeneration != receipt.PlacementGeneration)
                return Task.FromResult(false);
            if (handoff.ActivationReceipt is not null)
                return Task.FromResult(handoff.ActivationReceipt == receipt);
            _handoffs[receipt.AgentId] = handoff with { ActivationReceipt = receipt };
            return Task.FromResult(true);
        }
    }

    public Task MarkSourceReleasedAsync(
        StewardAgentId agentId,
        long committedGeneration,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (!_handoffs.TryGetValue(agentId, out var handoff) ||
                handoff.CommittedPlacementGeneration != committedGeneration ||
                handoff.ActivationReceipt is null)
                throw new PortableStateException(
                    "Source release requires the winning handoff and destination-active receipt.");
            _handoffs[agentId] = handoff with { SourceReleased = true };
            return Task.CompletedTask;
        }
    }

    public Task<MigrationHandoffRecord?> GetHandoffAsync(
        StewardAgentId agentId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
            return Task.FromResult(_handoffs.GetValueOrDefault(agentId));
    }
}
