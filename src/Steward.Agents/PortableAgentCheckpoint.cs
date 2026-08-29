using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Steward.Domain;
using Steward.PortableState;

namespace Steward.Agents;

public enum EnvironmentReferenceKind { OperatingSystem, Sdk, Package, Tool }

public sealed record DeclaredEnvironmentReference(
    string Name,
    string Version,
    string Fingerprint,
    EnvironmentReferenceKind Kind)
{
    public void Validate()
    {
        ValidateToken(Name, nameof(Name), 128);
        ValidateToken(Version, nameof(Version), 128);
        if (!Fingerprint.StartsWith("sha256:", StringComparison.Ordinal) ||
            Fingerprint.Length != 71 || !Fingerprint[7..].All(Uri.IsHexDigit))
            throw new ArgumentException("Fingerprint must be a SHA-256 reference.", nameof(Fingerprint));
        if (!Enum.IsDefined(Kind)) throw new ArgumentOutOfRangeException(nameof(Kind));
    }

    private static void ValidateToken(string value, string name, int maximum)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > maximum ||
            value.Any(x => !(char.IsAsciiLetterOrDigit(x) || x is '.' or '-' or '_' or ':' or '/' or '+')))
            throw new ArgumentException($"{name} is not a declared reference token.", name);
    }
}

public sealed record AgentEnvironmentManifest(
    IReadOnlyList<DeclaredEnvironmentReference> Environment,
    IReadOnlyList<DeclaredEnvironmentReference> Tools)
{
    public void Validate()
    {
        if (Environment.Count + Tools.Count > AgentLimits.MaximumEnvironmentEntries)
            throw new ArgumentException("Environment manifest has too many declared references.");
        foreach (var reference in Environment.Concat(Tools)) reference.Validate();
        if (Environment.Any(x => x.Kind == EnvironmentReferenceKind.Tool) ||
            Tools.Any(x => x.Kind != EnvironmentReferenceKind.Tool))
            throw new ArgumentException("Tool references must be declared only in the tools collection.");
        if (Environment.Concat(Tools).GroupBy(x => (x.Kind, x.Name), StringTupleComparer.Instance).Any(x => x.Count() > 1))
            throw new ArgumentException("Environment manifest contains duplicate references.");
    }

    private sealed class StringTupleComparer : IEqualityComparer<(EnvironmentReferenceKind Kind, string Name)>
    {
        public static StringTupleComparer Instance { get; } = new();
        public bool Equals(
            (EnvironmentReferenceKind Kind, string Name) x,
            (EnvironmentReferenceKind Kind, string Name) y) =>
            x.Kind == y.Kind && string.Equals(x.Name, y.Name, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((EnvironmentReferenceKind Kind, string Name) value) =>
            HashCode.Combine(value.Kind, StringComparer.OrdinalIgnoreCase.GetHashCode(value.Name));
    }
}

public sealed record AgentCheckpointPayload(
    StewardAgentBundle Bundle,
    IReadOnlyDictionary<string, byte[]> Entries)
{
    public void ZeroPlaintext()
    {
        foreach (var bytes in Entries.Values) CryptographicOperations.ZeroMemory(bytes);
    }
}

public sealed record StagedAgentRestore(
    Guid StageId,
    StewardAgentId AgentId,
    HostId DestinationHostId,
    DestinationRestoreReceipt Receipt);

public interface IAgentIdentityRebroker
{
    Task RebrokerAsync(
        StewardAgentId agentId,
        IReadOnlyList<ProtectedCredentialReference> protectedReferences,
        CancellationToken cancellationToken);
    Task RevokeStagingAsync(Guid stageId, CancellationToken cancellationToken);
}

public interface IAgentRestoreReadiness
{
    Task<bool> IsReadyAsync(StewardAgentId agentId, CancellationToken cancellationToken);
}

public sealed class PortableAgentCheckpointBuilder
{
    private sealed record PendingTurnDto(
        string TurnId,
        string Text,
        TextProvenance Provenance,
        string? ClientRequestId,
        long QueueSequence,
        string WorkloadId,
        string TaskId);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IAgentStore _store;

    public PortableAgentCheckpointBuilder(IAgentStore store) => _store = store;

    public async Task<AgentCheckpointPayload> BuildAsync(
        StewardAgentId agentId,
        GitArtifact gitBundle,
        GitArtifact dirtyPatch,
        AgentEnvironmentManifest environment,
        IReadOnlyList<PortableObjectId> lineage,
        CancellationToken cancellationToken = default)
    {
        if (lineage.Count == 0) throw new ArgumentException("Checkpoint lineage is required.", nameof(lineage));
        environment.Validate();
        var context = JsonSerializer.SerializeToUtf8Bytes(
            await _store.ReadContextAsync(agentId, cancellationToken).ConfigureAwait(false), JsonOptions);
        var records = await _store.ReadPendingTurnsAsync(agentId, cancellationToken).ConfigureAwait(false);
        var pending = JsonSerializer.SerializeToUtf8Bytes(records.Select(x => new PendingTurnDto(
            x.TurnId.ToString(), x.Text, x.Provenance, x.ClientRequestId, x.QueueSequence,
            x.WorkloadId!.Value.ToString(), x.TaskId!.Value.ToString())), JsonOptions);
        var manifest = JsonSerializer.SerializeToUtf8Bytes(environment, JsonOptions);
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["context.json"] = context,
            ["repository.bundle"] = gitBundle.Content.ToArray(),
            ["dirty.patch"] = dirtyPatch.Content.ToArray(),
            ["environment.json"] = manifest,
            ["pending-turns.json"] = pending
        };
        var bundle = new StewardAgentBundle(agentId, lineage,
            Entry("context.json", entries["context.json"]),
            Entry("repository.bundle", entries["repository.bundle"]),
            Entry("dirty.patch", entries["dirty.patch"]),
            Entry("environment.json", entries["environment.json"]),
            Entry("pending-turns.json", entries["pending-turns.json"]));
        bundle.Validate();
        return new(bundle, entries);
    }

    public async Task<StagedAgentRestore> StageRestoreAsync(
        AgentCheckpointPayload payload,
        HostId destinationHostId,
        IAgentRestoreReadiness readiness,
        CancellationToken cancellationToken = default)
    {
        Validate(payload);
        var stageId = Guid.NewGuid();
        await _store.StageCheckpointAsync(stageId, payload.Bundle.AgentId,
            payload.Entries["context.json"], payload.Entries["pending-turns.json"], cancellationToken)
            .ConfigureAwait(false);
        if (!await readiness.IsReadyAsync(payload.Bundle.AgentId, cancellationToken).ConfigureAwait(false))
        {
            await _store.RemoveCheckpointStageAsync(stageId, payload.Bundle.AgentId, cancellationToken)
                .ConfigureAwait(false);
            throw new PortableStateException("Staged agent failed credential-free readiness.");
        }
        var receipt = new DestinationRestoreReceipt(
            payload.Bundle.AgentId, destinationHostId, BundleHash(payload.Bundle), true, true,
            DateTimeOffset.UtcNow);
        return new(stageId, payload.Bundle.AgentId, destinationHostId, receipt);
    }

    public async Task CommitStageAsync(
        StagedAgentRestore stage,
        IAgentIdentityRebroker identity,
        IReadOnlyList<ProtectedCredentialReference> protectedReferences,
        CancellationToken cancellationToken = default)
    {
        var bytes = await _store.ReadCheckpointStageAsync(stage.StageId, stage.AgentId, cancellationToken)
            .ConfigureAwait(false) ?? throw new PortableStateException("Checkpoint stage does not exist.");
        var (context, pending) = DeserializeState(stage.AgentId, bytes.ContextJson, bytes.PendingTurnsJson);
        await identity.RebrokerAsync(stage.AgentId, protectedReferences, cancellationToken).ConfigureAwait(false);
        try
        {
            await _store.ImportCheckpointAsync(stage.AgentId, context, pending, cancellationToken).ConfigureAwait(false);
            await _store.RemoveCheckpointStageAsync(stage.StageId, stage.AgentId, cancellationToken)
                .ConfigureAwait(false);
            await UnfreezeAsync(stage.AgentId, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await identity.RevokeStagingAsync(stage.StageId, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public async Task RollbackStageAsync(
        StagedAgentRestore stage,
        IAgentIdentityRebroker identity,
        CancellationToken cancellationToken = default)
    {
        await _store.RemoveCheckpointStageAsync(stage.StageId, stage.AgentId, cancellationToken).ConfigureAwait(false);
        await identity.RevokeStagingAsync(stage.StageId, cancellationToken).ConfigureAwait(false);
        await UnfreezeAsync(stage.AgentId, cancellationToken).ConfigureAwait(false);
    }

    public static string BundleHash(StewardAgentBundle bundle)
    {
        var canonical = string.Join("\n", new[]
        {
            bundle.CompactedContext, bundle.GitBundle, bundle.DirtyStatePatch,
            bundle.EnvironmentManifest, bundle.PendingTurns
        }.Select(x => $"{x.Name}:{x.Sha256}:{x.Length}"));
        return Sha(Encoding.UTF8.GetBytes(canonical));
    }

    public static void Validate(AgentCheckpointPayload payload)
    {
        payload.Bundle.Validate();
        var expected = new[]
        {
            payload.Bundle.CompactedContext, payload.Bundle.GitBundle, payload.Bundle.DirtyStatePatch,
            payload.Bundle.EnvironmentManifest, payload.Bundle.PendingTurns
        };
        if (payload.Entries.Count != expected.Length ||
            !payload.Entries.Keys.ToHashSet(StringComparer.Ordinal)
                .SetEquals(expected.Select(x => x.Name)))
            throw new PortableStateException("Agent checkpoint contains undeclared entries.");
        if (!expected.All(entry => payload.Entries.TryGetValue(entry.Name, out var bytes) &&
            bytes.LongLength == entry.Length && string.Equals(Sha(bytes), entry.Sha256, StringComparison.Ordinal)))
            throw new PortableStateException("Agent checkpoint entry hash verification failed.");
        var environment = JsonSerializer.Deserialize<AgentEnvironmentManifest>(
            payload.Entries["environment.json"], JsonOptions)
            ?? throw new PortableStateException("Environment manifest is invalid.");
        environment.Validate();
    }

    private static (IReadOnlyList<ContextRecord>, IReadOnlyList<AgentTurnRecord>) DeserializeState(
        StewardAgentId agentId,
        byte[] contextJson,
        byte[] pendingJson)
    {
        var context = JsonSerializer.Deserialize<List<ContextRecord>>(contextJson, JsonOptions)
            ?? throw new PortableStateException("Agent context checkpoint is invalid.");
        var dtos = JsonSerializer.Deserialize<List<PendingTurnDto>>(pendingJson, JsonOptions)
            ?? throw new PortableStateException("Pending-turn checkpoint is invalid.");
        var pending = dtos.Select(x => new AgentTurnRecord(
            agentId, AgentTurnId.Parse(x.TurnId), x.Text, x.Provenance, x.ClientRequestId,
            AgentTurnStatus.Queued, x.QueueSequence, null, null, null, null,
            WorkloadId.Parse(x.WorkloadId), TaskId.Parse(x.TaskId), null)).ToArray();
        return (context, pending);
    }

    private static AgentBundleEntry Entry(string name, byte[] content) => new(name, Sha(content), content.LongLength);
    private static string Sha(byte[] content) => Convert.ToHexStringLower(SHA256.HashData(content));

    private async Task UnfreezeAsync(StewardAgentId agentId, CancellationToken cancellationToken)
    {
        var agent = await _store.GetAsync(agentId, cancellationToken).ConfigureAwait(false)
            ?? throw new KeyNotFoundException("Agent does not exist.");
        if (agent.Frozen &&
            !await _store.TrySetFrozenAsync(agentId, false, agent.Revision, cancellationToken).ConfigureAwait(false))
            throw new AgentConflictException("Agent stage activation revision conflicted.");
    }
}

public sealed record EncryptedAgentCheckpoint(
    HostId DestinationHostId,
    string Algorithm,
    byte[] WrappedKey,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] Tag,
    string PlaintextBundleSha256,
    string CiphertextSha256);

public interface IDestinationKeyEnvelope
{
    byte[] WrapKey(HostId destinationHostId, ReadOnlySpan<byte> key);
    byte[] UnwrapKey(HostId destinationHostId, ReadOnlySpan<byte> wrappedKey);
}

public interface IAgentCheckpointEncryption
{
    ValueTask<EncryptedAgentCheckpoint> EncryptAsync(
        AgentCheckpointPayload payload, HostId destinationHostId, CancellationToken cancellationToken);
    ValueTask<AgentCheckpointPayload> DecryptAsync(
        EncryptedAgentCheckpoint envelope, HostId destinationHostId, CancellationToken cancellationToken);
}

public sealed class AesGcmAgentCheckpointEncryption : IAgentCheckpointEncryption
{
    private sealed record WireEntry(string Name, string Sha256, long Length);
    private sealed record WireCheckpoint(
        string AgentId,
        string[] Lineage,
        WireEntry[] Metadata,
        Dictionary<string, byte[]> Entries);
    private readonly IDestinationKeyEnvelope _keys;

    public AesGcmAgentCheckpointEncryption(IDestinationKeyEnvelope keys) => _keys = keys;

    public ValueTask<EncryptedAgentCheckpoint> EncryptAsync(
        AgentCheckpointPayload payload,
        HostId destinationHostId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        PortableAgentCheckpointBuilder.Validate(payload);
        var metadata = new[]
        {
            payload.Bundle.CompactedContext, payload.Bundle.GitBundle, payload.Bundle.DirtyStatePatch,
            payload.Bundle.EnvironmentManifest, payload.Bundle.PendingTurns
        }.Select(x => new WireEntry(x.Name, x.Sha256, x.Length)).ToArray();
        var wire = new WireCheckpoint(payload.Bundle.AgentId.ToString(),
            payload.Bundle.CheckpointLineage.Select(x => x.ToString()).ToArray(),
            metadata, payload.Entries.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal));
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(wire);
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        var aad = Encoding.UTF8.GetBytes(destinationHostId.ToString());
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            var wrapped = _keys.WrapKey(destinationHostId, key);
            return ValueTask.FromResult(new EncryptedAgentCheckpoint(
                destinationHostId, "AES-256-GCM", wrapped, nonce, ciphertext, tag,
                PortableAgentCheckpointBuilder.BundleHash(payload.Bundle),
                Convert.ToHexStringLower(SHA256.HashData(ciphertext))));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public ValueTask<AgentCheckpointPayload> DecryptAsync(
        EncryptedAgentCheckpoint envelope,
        HostId destinationHostId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (envelope.DestinationHostId != destinationHostId)
            throw new CryptographicException("Checkpoint is bound to a different destination.");
        if (!string.Equals(envelope.CiphertextSha256,
            Convert.ToHexStringLower(SHA256.HashData(envelope.Ciphertext)), StringComparison.Ordinal))
            throw new CryptographicException("Encrypted checkpoint integrity hash is invalid.");
        var key = _keys.UnwrapKey(destinationHostId, envelope.WrappedKey);
        var plaintext = new byte[envelope.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, envelope.Tag.Length);
            aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext,
                Encoding.UTF8.GetBytes(destinationHostId.ToString()));
            var wire = JsonSerializer.Deserialize<WireCheckpoint>(plaintext)
                ?? throw new CryptographicException("Checkpoint envelope payload is invalid.");
            if (wire.Metadata.Length != 5) throw new CryptographicException("Checkpoint metadata is incomplete.");
            AgentBundleEntry Entry(int index) => new(
                wire.Metadata[index].Name, wire.Metadata[index].Sha256, wire.Metadata[index].Length);
            var bundle = new StewardAgentBundle(
                StewardAgentId.Parse(wire.AgentId), wire.Lineage.Select(PortableObjectId.Parse).ToArray(),
                Entry(0), Entry(1), Entry(2), Entry(3), Entry(4));
            if (!string.Equals(PortableAgentCheckpointBuilder.BundleHash(bundle),
                envelope.PlaintextBundleSha256, StringComparison.Ordinal))
                throw new CryptographicException("Checkpoint bundle identity is invalid.");
            return ValueTask.FromResult(new AgentCheckpointPayload(bundle, wire.Entries));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

public interface IAgentMigrationTransport
{
    Task<PortableObjectReceipt> UploadAsync(
        EncryptedAgentCheckpoint checkpoint, CancellationToken cancellationToken);
    Task<StagedAgentRestore> StageAtDestinationAsync(
        HostId destinationHostId, EncryptedAgentCheckpoint checkpoint, CancellationToken cancellationToken);
    Task<StagedAgentRestore> FindStagedAsync(
        StewardAgentId agentId, HostId destinationHostId, string bundleSha256,
        CancellationToken cancellationToken);
    Task<DestinationActivationReceipt> CommitStagedAsync(
        StagedAgentRestore stage,
        long placementGeneration,
        IReadOnlyList<ProtectedCredentialReference> protectedReferences,
        CancellationToken cancellationToken);
    Task RollbackStagedAsync(StagedAgentRestore stage, CancellationToken cancellationToken);
    Task ReplayPendingNotificationsAsync(
        StewardAgentId agentId, HostId destinationHostId, CancellationToken cancellationToken);
}

public sealed class AgentMigrationOrchestrator
{
    private readonly IAgentStore _store;
    private readonly PortableAgentCheckpointBuilder _checkpoints;
    private readonly IAgentCheckpointEncryption _encryption;
    private readonly IAgentMigrationTransport _transport;
    private readonly MigrationCoordinator _coordinator;

    public AgentMigrationOrchestrator(
        IAgentStore store,
        PortableAgentCheckpointBuilder checkpoints,
        IAgentCheckpointEncryption encryption,
        IAgentMigrationTransport transport,
        MigrationCoordinator coordinator)
    {
        _store = store;
        _checkpoints = checkpoints;
        _encryption = encryption;
        _transport = transport;
        _coordinator = coordinator;
    }

    public async Task<MigrationHandoffRecord?> MigrateAsync(
        StewardAgentId agentId,
        HostId sourceHostId,
        HostId destinationHostId,
        GitArtifact gitBundle,
        GitArtifact dirtyPatch,
        AgentEnvironmentManifest environment,
        IReadOnlyList<PortableObjectId> lineage,
        IReadOnlyList<ProtectedCredentialReference>? protectedReferences = null,
        CancellationToken cancellationToken = default)
    {
        var agent = await _store.GetAsync(agentId, cancellationToken).ConfigureAwait(false)
            ?? throw new KeyNotFoundException("Agent does not exist.");
        var migration = await _store.BeginMigrationAsync(
            agentId, destinationHostId, agent.Revision, cancellationToken).ConfigureAwait(false);
        if (migration is null)
            return null;
        StagedAgentRestore? stage = null;
        var committed = false;
        try
        {
            var checkpoint = await _checkpoints.BuildAsync(
                agentId, gitBundle, dirtyPatch, environment, lineage, cancellationToken).ConfigureAwait(false);
            EncryptedAgentCheckpoint encrypted;
            try
            {
                encrypted = await _encryption.EncryptAsync(checkpoint, destinationHostId, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                checkpoint.ZeroPlaintext();
            }
            var source = await _transport.UploadAsync(encrypted, cancellationToken).ConfigureAwait(false);
            stage = await _transport.StageAtDestinationAsync(
                destinationHostId, encrypted, cancellationToken).ConfigureAwait(false);
            var handoff = await _coordinator.TryCommitPlacementAsync(
                agentId, sourceHostId, destinationHostId, agent.PlacementGeneration,
                source, stage.Receipt, cancellationToken).ConfigureAwait(false);
            if (handoff is null)
            {
                await _transport.RollbackStagedAsync(stage, cancellationToken).ConfigureAwait(false);
                try
                {
                    var winner = await _coordinator.InspectAsync(agentId, cancellationToken).ConfigureAwait(false);
                    if (winner.AgentId != agentId)
                        throw new PortableStateException("Authoritative handoff belongs to another Agent.");
                    await _store.FinishMigrationAsync(
                        migration.MigrationId, agentId, "lost", false, cancellationToken).ConfigureAwait(false);
                }
                catch (PortableStateException)
                {
                    await _store.FinishMigrationAsync(
                        migration.MigrationId, agentId, "aborted", true, cancellationToken).ConfigureAwait(false);
                }
                return null;
            }
            committed = true;
            await _store.FinishMigrationAsync(
                migration.MigrationId, agentId, "placement-committed", false, cancellationToken).ConfigureAwait(false);
            var activation = await _transport.CommitStagedAsync(
                stage, handoff.CommittedPlacementGeneration, protectedReferences ?? [], cancellationToken)
                .ConfigureAwait(false);
            await _coordinator.RecordDestinationActiveAsync(activation, cancellationToken).ConfigureAwait(false);
            await _store.FinishMigrationAsync(
                migration.MigrationId, agentId, "destination-active", false, cancellationToken).ConfigureAwait(false);
            await _transport.ReplayPendingNotificationsAsync(agentId, destinationHostId, cancellationToken)
                .ConfigureAwait(false);
            var released = await _coordinator.ReleaseSourceAsync(agentId, cancellationToken).ConfigureAwait(false);
            await _store.FinishMigrationAsync(
                migration.MigrationId, agentId, "completed", false, cancellationToken).ConfigureAwait(false);
            return released;
        }
        catch
        {
            if (stage is not null && !committed)
                await _transport.RollbackStagedAsync(stage, CancellationToken.None).ConfigureAwait(false);
            if (!committed)
                await _store.FinishMigrationAsync(
                    migration.MigrationId, agentId, "aborted", true, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public async Task<MigrationHandoffRecord> ResumeAsync(
        StewardAgentId agentId,
        IReadOnlyList<ProtectedCredentialReference>? protectedReferences = null,
        CancellationToken cancellationToken = default)
    {
        var handoff = await _coordinator.InspectAsync(agentId, cancellationToken).ConfigureAwait(false);
        var migration = await _store.GetMigrationAsync(agentId, cancellationToken).ConfigureAwait(false)
            ?? throw new PortableStateException("Durable Agent migration state is missing.");
        if (handoff.ResumeAction == MigrationResumeAction.Complete)
        {
            if (migration.State != "completed")
                await _store.FinishMigrationAsync(
                    migration.MigrationId, agentId, "completed", false, cancellationToken).ConfigureAwait(false);
            return handoff;
        }
        if (handoff.ResumeAction == MigrationResumeAction.ActivateDestination)
        {
            var stage = await _transport.FindStagedAsync(
                agentId, handoff.DestinationHostId, handoff.DestinationReceipt.BundleSha256, cancellationToken)
                .ConfigureAwait(false);
            var activation = await _transport.CommitStagedAsync(
                stage, handoff.CommittedPlacementGeneration, protectedReferences ?? [], cancellationToken)
                .ConfigureAwait(false);
            handoff = await _coordinator.RecordDestinationActiveAsync(activation, cancellationToken)
                .ConfigureAwait(false);
            await _store.FinishMigrationAsync(
                migration.MigrationId, agentId, "destination-active", false, cancellationToken).ConfigureAwait(false);
        }
        if (handoff.ResumeAction == MigrationResumeAction.ReleaseSource)
        {
            await _transport.ReplayPendingNotificationsAsync(
                agentId, handoff.DestinationHostId, cancellationToken).ConfigureAwait(false);
            handoff = await _coordinator.ReleaseSourceAsync(agentId, cancellationToken).ConfigureAwait(false);
        }
        await _store.FinishMigrationAsync(
            migration.MigrationId, agentId, "completed", false, cancellationToken).ConfigureAwait(false);
        return handoff;
    }
}
