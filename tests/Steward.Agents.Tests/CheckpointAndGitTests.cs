using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Steward.Agents;
using Steward.Domain;
using Steward.PortableState;

namespace Steward.Agents.Tests;

public sealed class CheckpointAndGitTests
{
    [Fact]
    public async Task CheckpointExcludesSecretsAndRestoreIncludesPendingTurn()
    {
        var sourcePath = NewPath();
        var destinationPath = NewPath();
        var agent = StewardAgentId.New();
        var turn = AgentTurnId.New();
        AgentCheckpointPayload checkpoint;
        await using (var source = new SqliteAgentStore(sourcePath))
        {
            await source.CreateAsync(agent, new("runtime", "1"));
            await source.AppendContextAsync(agent, "retained", TextProvenance.User);
            await source.SubmitTurnAsync(agent, new(turn, "pending"));
            var builder = new PortableAgentCheckpointBuilder(source);
            var artifact = Artifact("git");
            checkpoint = await builder.BuildAsync(agent, artifact, Artifact("patch"),
                Manifest(), [PortableObjectId.New()]);
            Assert.DoesNotContain("credential", string.Join("", checkpoint.Entries.Values.Select(Encoding.UTF8.GetString)),
                StringComparison.OrdinalIgnoreCase);
            await Assert.ThrowsAsync<ArgumentException>(() => builder.BuildAsync(agent, artifact, artifact,
                new AgentEnvironmentManifest(
                    [new("password=raw-secret", "1", Fingerprint('a'), EnvironmentReferenceKind.Sdk)], []),
                [PortableObjectId.New()]));
        }
        await using (var destination = new SqliteAgentStore(destinationPath))
        {
            await destination.CreateAsync(agent, new("runtime", "1"));
            var builder = new PortableAgentCheckpointBuilder(destination);
            var stage = await builder.StageRestoreAsync(checkpoint, HostId.New(), new Ready());
            Assert.Null(await destination.GetTurnAsync(agent, turn));
            await builder.CommitStageAsync(stage, new FakeIdentity(), []);
            Assert.True(stage.Receipt.HashesVerified);
            Assert.Equal("pending", (await destination.GetTurnAsync(agent, turn))!.Text);
            Assert.Equal("retained", Assert.Single(await destination.ReadContextAsync(agent)).Text);
        }
        Cleanup(sourcePath);
        Cleanup(destinationPath);
    }

    [Fact]
    public async Task WorktreeUsesArgumentVectorsRatherThanShellConcatenation()
    {
        var process = new FakeGitProcess();
        var manager = new GitCliWorktreeManager(process);
        var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "worktree"));
        var repository = Path.GetFullPath(AppContext.BaseDirectory);
        await using var worktree = await manager.CreateAsync(
            new(new("https://example.invalid/repo", "repo"), repository, repository,
                "refs/heads/main", new string('a', 40), path),
            CancellationToken.None);
        Assert.Equal(["worktree", "add", "--detach", "--", path, new string('a', 40)], process.Requests[2].Arguments);
        Assert.All(process.Requests, request => Assert.Equal("git", request.Executable));
    }

    [Fact]
    public async Task WorktreeRejectsEscapesAndGitFailures()
    {
        var repository = Path.GetFullPath(AppContext.BaseDirectory);
        var manager = new GitCliWorktreeManager(new FakeGitProcess());
        await Assert.ThrowsAsync<ArgumentException>(() => manager.CreateAsync(
            new(new("https://example.invalid/repo", "repo"), repository, repository,
                "refs/heads/main", new string('a', 40), Path.GetFullPath(Path.Combine(repository, "..", "escape"))),
            CancellationToken.None));
        var failed = new FakeGitProcess { Result = new(1, [], "failed") };
        await Assert.ThrowsAsync<InvalidOperationException>(() => new GitCliWorktreeManager(failed).CreateAsync(
            new(new("https://example.invalid/repo", "repo"), repository, repository,
                "refs/heads/main", new string('a', 40), Path.Combine(repository, "safe-worktree")),
            CancellationToken.None));
        var wrongRepository = new FakeGitProcess
        {
            Handler = request => request.Arguments.FirstOrDefault() == "remote"
                ? new(0, Encoding.UTF8.GetBytes("https://example.invalid/other\n"), "")
                : new(0, Encoding.ASCII.GetBytes(new string('a', 40)), "")
        };
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new GitCliWorktreeManager(wrongRepository).CreateAsync(
                new(new("https://example.invalid/repo", "repo"), repository, repository,
                    "refs/heads/main", new string('a', 40), Path.Combine(repository, "safe-worktree")),
                CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new GitCliWorktreeManager(new FakeGitProcess()).CreateAsync(
                new(new("https://user:secret@example.invalid/repo?token=x", "repo"),
                    repository, repository, "refs/heads/main", new string('a', 40),
                    Path.Combine(repository, "safe-worktree")), CancellationToken.None));
    }

    [Fact]
    public async Task WorktreeRejectsReparseParentEscape()
    {
        var repository = Path.GetFullPath(AppContext.BaseDirectory);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new GitCliWorktreeManager(
                new FakeGitProcess(), new FakeGitProcess.JunctionRejectingValidator()).CreateAsync(
                new(new("https://example.invalid/repo", "repo"), repository, repository,
                    "refs/heads/main", new string('a', 40), Path.Combine(repository, "junction", "worktree")),
                CancellationToken.None));
    }

    [Fact]
    public async Task MigrationCasHasExactlyOneWinner()
    {
        var placements = new InMemoryAgentPlacementStore();
        var releaser = new Releaser();
        var coordinator = new MigrationCoordinator(placements, releaser);
        var agent = StewardAgentId.New();
        var source = HostId.New();
        var firstHost = HostId.New();
        var secondHost = HostId.New();
        var receipt = new PortableObjectReceipt("bundle", new string('a', 64), 1, "etag", DateTimeOffset.UtcNow);
        DestinationRestoreReceipt Destination(HostId host) =>
            new(agent, host, receipt.Sha256, true, true, DateTimeOffset.UtcNow);
        var attempts = await Task.WhenAll(
            coordinator.TryCommitPlacementAsync(agent, source, firstHost, 0, receipt, Destination(firstHost)),
            coordinator.TryCommitPlacementAsync(agent, source, secondHost, 0, receipt, Destination(secondHost)));
        var winner = Assert.Single(attempts, x => x is not null)!;
        Assert.Equal(0, releaser.Count);
        await coordinator.RecordDestinationActiveAsync(new(
            agent, winner.DestinationHostId, winner.CommittedPlacementGeneration,
            "active", true, DateTimeOffset.UtcNow));
        await coordinator.ReleaseSourceAsync(agent);
        Assert.Equal(1, releaser.Count);
    }

    [Fact]
    public async Task CheckpointEncryptionHidesPlaintextAndBindsDestination()
    {
        var path = NewPath();
        await using var store = new SqliteAgentStore(path);
        var agent = StewardAgentId.New();
        await store.CreateAsync(agent, new("runtime", "1"));
        await store.AppendContextAsync(agent, "sensitive-conversation-marker", TextProvenance.User);
        var builder = new PortableAgentCheckpointBuilder(store);
        var payload = await builder.BuildAsync(agent, Artifact("bundle"), Artifact("sensitive-patch-marker"),
            Manifest(), [PortableObjectId.New()]);
        var encryption = new AesGcmAgentCheckpointEncryption(new TestKeyEnvelope());
        var destination = HostId.New();
        var injectedEntries = payload.Entries.ToDictionary(x => x.Key, x => x.Value);
        injectedEntries["secret.txt"] = Encoding.UTF8.GetBytes("raw-secret");
        await Assert.ThrowsAsync<PortableStateException>(async () =>
            await encryption.EncryptAsync(payload with { Entries = injectedEntries }, destination, CancellationToken.None));
        var encrypted = await encryption.EncryptAsync(payload, destination, CancellationToken.None);
        var ciphertext = Encoding.UTF8.GetString(encrypted.Ciphertext);
        Assert.DoesNotContain("sensitive-conversation-marker", ciphertext, StringComparison.Ordinal);
        Assert.DoesNotContain("sensitive-patch-marker", ciphertext, StringComparison.Ordinal);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await encryption.DecryptAsync(encrypted, HostId.New(), CancellationToken.None));
        var decrypted = await encryption.DecryptAsync(encrypted, destination, CancellationToken.None);
        Assert.Contains("sensitive-conversation-marker",
            Encoding.UTF8.GetString(decrypted.Entries["context.json"]), StringComparison.Ordinal);
        await store.DisposeAsync();
        Cleanup(path);
    }

    [Fact]
    public void RsaDestinationEnvelopeWrapsWithPublicKeyAndRequiresMatchingPrivateHostKey()
    {
        var firstHost = HostId.New();
        var secondHost = HostId.New();
        using var first = CreateEncryptionCertificate(3072);
        using var second = CreateEncryptionCertificate(3072);
        using var firstPublic = X509CertificateLoader.LoadCertificate(first.Export(X509ContentType.Cert));
        using var secondPublic = X509CertificateLoader.LoadCertificate(second.Export(X509ContentType.Cert));
        var registry = new TestKeyEnvelope.CertificateRegistry();
        registry.Add(firstHost, firstPublic, first);
        registry.Add(secondHost, secondPublic, second);
        var envelope = new RsaOaepDestinationKeyEnvelope(registry);
        var cek = RandomNumberGenerator.GetBytes(32);
        try
        {
            var wrapped = envelope.WrapKey(firstHost, cek);
            Assert.Equal(cek, envelope.UnwrapKey(firstHost, wrapped));
            Assert.Throws<CryptographicException>(() => envelope.UnwrapKey(secondHost, wrapped));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }

        using var weak = CreateEncryptionCertificate(2048);
        using var weakPublic = X509CertificateLoader.LoadCertificate(weak.Export(X509ContentType.Cert));
        var weakHost = HostId.New();
        registry.Add(weakHost, weakPublic, weak);
        Assert.Throws<CryptographicException>(() => envelope.WrapKey(weakHost, new byte[32]));
    }

    [Fact]
    public async Task CrashAfterPlacementCasRetriesActivationBeforeSourceRelease()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        await using var store = new SqliteAgentStore(path);
        await store.CreateAsync(agent, new("runtime", "1"));
        var releaser = new Releaser();
        var transport = new FakeMigrationTransport(agent) { CommitFailuresRemaining = 1 };
        var orchestrator = CreateOrchestrator(store, transport, releaser);
        await Assert.ThrowsAsync<InvalidOperationException>(() => orchestrator.MigrateAsync(
            agent, HostId.New(), HostId.New(), Artifact("git"), Artifact("patch"),
            Manifest(), [PortableObjectId.New()]));
        Assert.Equal("placement-committed", (await store.GetMigrationAsync(agent))!.State);
        Assert.Equal(0, releaser.Count);
        Assert.Equal(0, transport.Rollbacks);
        var resumed = await orchestrator.ResumeAsync(agent);
        Assert.True(resumed.SourceReleased);
        Assert.Equal(1, releaser.Count);
        Assert.Equal("completed", (await store.GetMigrationAsync(agent))!.State);
        await store.DisposeAsync();
        Cleanup(path);
    }

    [Fact]
    public async Task CrashAfterDestinationActivationRetriesOnlySourceRelease()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        await using var store = new SqliteAgentStore(path);
        await store.CreateAsync(agent, new("runtime", "1"));
        var releaser = new Releaser { FailuresRemaining = 1 };
        var transport = new FakeMigrationTransport(agent);
        var orchestrator = CreateOrchestrator(store, transport, releaser);
        await Assert.ThrowsAsync<InvalidOperationException>(() => orchestrator.MigrateAsync(
            agent, HostId.New(), HostId.New(), Artifact("git"), Artifact("patch"),
            Manifest(), [PortableObjectId.New()]));
        Assert.Equal("destination-active", (await store.GetMigrationAsync(agent))!.State);
        Assert.Equal(1, transport.Commits);
        await orchestrator.ResumeAsync(agent);
        Assert.Equal(1, transport.Commits);
        Assert.Equal(1, releaser.Count);
        await store.DisposeAsync();
        Cleanup(path);
    }

    [Fact]
    public async Task CrashAfterSourceReleaseOnlyMarksMigrationComplete()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        var destination = HostId.New();
        var source = HostId.New();
        await using var store = new SqliteAgentStore(path);
        var descriptor = await store.CreateAsync(agent, new("runtime", "1"));
        var migration = (await store.BeginMigrationAsync(agent, destination, descriptor.Revision))!;
        var placements = new InMemoryAgentPlacementStore();
        var releaser = new Releaser();
        var coordinator = new MigrationCoordinator(placements, releaser);
        var sha = new string('a', 64);
        var sourceReceipt = new PortableObjectReceipt("bundle", sha, 1, "etag", DateTimeOffset.UtcNow);
        var restore = new DestinationRestoreReceipt(agent, destination, sha, true, true, DateTimeOffset.UtcNow);
        var handoff = (await coordinator.TryCommitPlacementAsync(
            agent, source, destination, 0, sourceReceipt, restore))!;
        await store.FinishMigrationAsync(migration.MigrationId, agent, "placement-committed", false);
        await coordinator.RecordDestinationActiveAsync(new(
            agent, destination, handoff.CommittedPlacementGeneration, "active", true, DateTimeOffset.UtcNow));
        await store.FinishMigrationAsync(migration.MigrationId, agent, "destination-active", false);
        await coordinator.ReleaseSourceAsync(agent);
        var transport = new FakeMigrationTransport(agent);
        var orchestrator = new AgentMigrationOrchestrator(store,
            new PortableAgentCheckpointBuilder(store),
            new AesGcmAgentCheckpointEncryption(new TestKeyEnvelope()), transport, coordinator);
        var resumed = await orchestrator.ResumeAsync(agent);
        Assert.True(resumed.SourceReleased);
        Assert.Equal(0, transport.Commits);
        Assert.Equal("completed", (await store.GetMigrationAsync(agent))!.State);
        await store.DisposeAsync();
        Cleanup(path);
    }

    [Fact]
    public async Task StagedRestoreIsNonExecutableAndRollbackScrubsGrant()
    {
        var sourcePath = NewPath();
        var destinationPath = NewPath();
        var agent = StewardAgentId.New();
        AgentCheckpointPayload payload;
        await using (var source = new SqliteAgentStore(sourcePath))
        {
            await source.CreateAsync(agent, new("runtime", "1"));
            await source.SubmitTurnAsync(agent, new(AgentTurnId.New(), "pending"));
            payload = await new PortableAgentCheckpointBuilder(source).BuildAsync(
                agent, Artifact("git"), Artifact("patch"), Manifest(), [PortableObjectId.New()]);
        }
        await using (var destination = new SqliteAgentStore(destinationPath))
        {
            await destination.CreateAsync(agent, new("runtime", "1"));
            var builder = new PortableAgentCheckpointBuilder(destination);
            var stage = await builder.StageRestoreAsync(payload, HostId.New(), new Ready());
            Assert.True((await destination.GetAsync(agent))!.Frozen);
            Assert.Empty(await destination.ReadPendingTurnsAsync(agent));
            var identity = new FakeIdentity();
            await builder.RollbackStageAsync(stage, identity);
            Assert.False((await destination.GetAsync(agent))!.Frozen);
            Assert.Contains(stage.StageId, identity.Revoked);
        }
        Cleanup(sourcePath);
        Cleanup(destinationPath);
    }

    [Fact]
    public async Task TwoDestinationMigrationRaceCommitsOneAndRollsBackLoser()
    {
        var firstPath = NewPath();
        var secondPath = NewPath();
        var agent = StewardAgentId.New();
        await using var firstStore = new SqliteAgentStore(firstPath);
        await using var secondStore = new SqliteAgentStore(secondPath);
        await firstStore.CreateAsync(agent, new("runtime", "1"));
        await secondStore.CreateAsync(agent, new("runtime", "1"));
        var placement = new InMemoryAgentPlacementStore();
        var coordinator = new MigrationCoordinator(placement, new Releaser());
        var encryption = new AesGcmAgentCheckpointEncryption(new TestKeyEnvelope());
        var firstTransport = new FakeMigrationTransport(agent);
        var secondTransport = new FakeMigrationTransport(agent);
        var first = new AgentMigrationOrchestrator(firstStore,
            new PortableAgentCheckpointBuilder(firstStore), encryption, firstTransport, coordinator);
        var second = new AgentMigrationOrchestrator(secondStore,
            new PortableAgentCheckpointBuilder(secondStore), encryption, secondTransport, coordinator);
        var sourceHost = HostId.New();
        var results = await Task.WhenAll(
            first.MigrateAsync(agent, sourceHost, HostId.New(), Artifact("git"), Artifact("patch"),
                Manifest(), [PortableObjectId.New()]),
            second.MigrateAsync(agent, sourceHost, HostId.New(), Artifact("git"), Artifact("patch"),
                Manifest(), [PortableObjectId.New()]));
        Assert.Single(results, x => x is not null);
        Assert.Equal(1, firstTransport.Commits + secondTransport.Commits);
        Assert.Equal(1, firstTransport.Rollbacks + secondTransport.Rollbacks);
        var states = new[] { await firstStore.GetMigrationAsync(agent), await secondStore.GetMigrationAsync(agent) };
        Assert.Single(states, x => x!.State == "lost");
        await firstStore.DisposeAsync();
        await secondStore.DisposeAsync();
        Cleanup(firstPath);
        Cleanup(secondPath);
    }

    [Fact]
    public async Task PreCommitMigrationFailureUnfreezesSource()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        await using var store = new SqliteAgentStore(path);
        await store.CreateAsync(agent, new("runtime", "1"));
        var transport = new FakeMigrationTransport(agent) { FailUpload = true };
        var orchestrator = new AgentMigrationOrchestrator(store,
            new PortableAgentCheckpointBuilder(store),
            new AesGcmAgentCheckpointEncryption(new TestKeyEnvelope()), transport,
            new MigrationCoordinator(new InMemoryAgentPlacementStore(), new Releaser()));
        await Assert.ThrowsAsync<InvalidOperationException>(() => orchestrator.MigrateAsync(
            agent, HostId.New(), HostId.New(), Artifact("git"), Artifact("patch"),
            Manifest(), [PortableObjectId.New()]));
        Assert.False((await store.GetAsync(agent))!.Frozen);
        Assert.Equal("aborted", (await store.GetMigrationAsync(agent))!.State);
        await store.DisposeAsync();
        Cleanup(path);
    }

    [Fact]
    public async Task StalePlacementWithoutAuthoritativeWinnerAbortsAndUnfreezes()
    {
        var path = NewPath();
        var agent = StewardAgentId.New();
        await using var store = new SqliteAgentStore(path);
        await store.CreateAsync(agent, new("runtime", "1"));
        var transport = new FakeMigrationTransport(agent);
        var orchestrator = new AgentMigrationOrchestrator(store,
            new PortableAgentCheckpointBuilder(store),
            new AesGcmAgentCheckpointEncryption(new TestKeyEnvelope()), transport,
            new MigrationCoordinator(new FakeMigrationTransport.StalePlacementStore(), new Releaser()));
        Assert.Null(await orchestrator.MigrateAsync(
            agent, HostId.New(), HostId.New(), Artifact("git"), Artifact("patch"),
            Manifest(), [PortableObjectId.New()]));
        Assert.False((await store.GetAsync(agent))!.Frozen);
        Assert.Equal("aborted", (await store.GetMigrationAsync(agent))!.State);
        Assert.Equal(1, transport.Rollbacks);
        await store.DisposeAsync();
        Cleanup(path);
    }

    private static GitArtifact Artifact(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        return new("application/octet-stream", bytes,
            Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)));
    }

    private sealed class FakeGitProcess : IGitProcess
    {
        public List<GitProcessRequest> Requests { get; } = [];
        public GitProcessResult Result { get; init; } = new(0, [], "");
        public Func<GitProcessRequest, GitProcessResult>? Handler { get; init; }
        public Task<GitProcessResult> RunAsync(GitProcessRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (Handler is not null) return Task.FromResult(Handler(request));
            if (Result.ExitCode != 0) return Task.FromResult(Result);
            if (request.Arguments.FirstOrDefault() == "remote")
                return Task.FromResult(new GitProcessResult(
                    0, Encoding.UTF8.GetBytes("https://example.invalid/repo\n"), ""));
            if (request.Arguments.FirstOrDefault() == "rev-parse")
                return Task.FromResult(new GitProcessResult(
                    0, Encoding.ASCII.GetBytes(new string('a', 40)), ""));
            return Task.FromResult(Result);
        }
        public sealed class JunctionRejectingValidator : IWorktreePathValidator
        {
            public void ValidateContainedPath(string workspaceRoot, string worktreePath) =>
                throw new ArgumentException("Worktree path traverses a junction.", nameof(worktreePath));
        }
    }

    private sealed class FakeIdentity : IAgentIdentityRebroker
    {
        public List<Guid> Revoked { get; } = [];
        public Task RebrokerAsync(StewardAgentId agentId,
            IReadOnlyList<ProtectedCredentialReference> protectedReferences,
            CancellationToken cancellationToken) => Task.CompletedTask;
        public Task RevokeStagingAsync(Guid stageId, CancellationToken cancellationToken)
        {
            Revoked.Add(stageId);
            return Task.CompletedTask;
        }
    }
    private sealed class TestKeyEnvelope : IDestinationKeyEnvelope
    {
        public byte[] WrapKey(HostId destinationHostId, ReadOnlySpan<byte> key) =>
            destinationHostId.Value.ToByteArray().Concat(key.ToArray()).ToArray();
        public byte[] UnwrapKey(HostId destinationHostId, ReadOnlySpan<byte> wrappedKey)
        {
            if (wrappedKey.Length != 48 ||
                !CryptographicOperations.FixedTimeEquals(
                    wrappedKey[..16], destinationHostId.Value.ToByteArray()))
                throw new CryptographicException("Wrong destination.");
            return wrappedKey[16..].ToArray();
        }
        public sealed class CertificateRegistry : IDestinationCertificateRegistry
        {
            private readonly Dictionary<HostId, (X509Certificate2 Public, X509Certificate2 Private)> _certificates = [];
            public void Add(HostId hostId, X509Certificate2 publicCertificate, X509Certificate2 privateCertificate) =>
                _certificates.Add(hostId, (publicCertificate, privateCertificate));
            public X509Certificate2 GetEncryptionCertificate(HostId destinationHostId) =>
                _certificates[destinationHostId].Public;
            public X509Certificate2 GetDecryptionCertificate(HostId destinationHostId) =>
                _certificates[destinationHostId].Private;
        }
    }
    private sealed class FakeMigrationTransport(StewardAgentId agentId) : IAgentMigrationTransport
    {
        public bool FailUpload { get; init; }
        public int Commits { get; private set; }
        public int Rollbacks { get; private set; }
        public int CommitFailuresRemaining { get; set; }
        private StagedAgentRestore? _stage;
        public Task<PortableObjectReceipt> UploadAsync(
            EncryptedAgentCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            if (FailUpload) throw new InvalidOperationException("injected upload failure");
            return Task.FromResult(new PortableObjectReceipt(
                "encrypted", checkpoint.PlaintextBundleSha256, checkpoint.Ciphertext.LongLength,
                "etag", DateTimeOffset.UtcNow));
        }
        public sealed class StalePlacementStore : IAgentPlacementStore
        {
            public Task<long> GetGenerationAsync(
                StewardAgentId agentId, CancellationToken cancellationToken = default) => Task.FromResult(1L);
            public Task<bool> TryCommitHandoffAsync(
                MigrationHandoffRecord handoff, long expectedGeneration,
                CancellationToken cancellationToken = default) => Task.FromResult(false);
            public Task<bool> TryRecordDestinationActiveAsync(
                DestinationActivationReceipt receipt,
                CancellationToken cancellationToken = default) => Task.FromResult(false);
            public Task MarkSourceReleasedAsync(
                StewardAgentId agentId, long committedGeneration,
                CancellationToken cancellationToken = default) => Task.CompletedTask;
            public Task<MigrationHandoffRecord?> GetHandoffAsync(
                StewardAgentId agentId, CancellationToken cancellationToken = default) =>
                Task.FromResult<MigrationHandoffRecord?>(null);
        }
        public Task<StagedAgentRestore> StageAtDestinationAsync(
            HostId destinationHostId, EncryptedAgentCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            var receipt = new DestinationRestoreReceipt(agentId, destinationHostId,
                checkpoint.PlaintextBundleSha256, true, true, DateTimeOffset.UtcNow);
            _stage = new StagedAgentRestore(Guid.NewGuid(), agentId, destinationHostId, receipt);
            return Task.FromResult(_stage);
        }
        public Task<StagedAgentRestore> FindStagedAsync(
            StewardAgentId id, HostId destinationHostId, string bundleSha256,
            CancellationToken cancellationToken) =>
            Task.FromResult(_stage is not null && _stage.AgentId == id &&
                _stage.DestinationHostId == destinationHostId &&
                _stage.Receipt.BundleSha256 == bundleSha256
                    ? _stage
                    : throw new InvalidOperationException("stage missing"));
        public Task<DestinationActivationReceipt> CommitStagedAsync(
            StagedAgentRestore stage,
            long placementGeneration,
            IReadOnlyList<ProtectedCredentialReference> protectedReferences,
            CancellationToken cancellationToken)
        {
            Commits++;
            if (CommitFailuresRemaining-- > 0)
                throw new InvalidOperationException("injected activation failure");
            return Task.FromResult(new DestinationActivationReceipt(
                stage.AgentId, stage.DestinationHostId, placementGeneration,
                $"active-{stage.StageId:D}", true, DateTimeOffset.UtcNow));
        }
        public Task RollbackStagedAsync(StagedAgentRestore stage, CancellationToken cancellationToken)
        {
            Rollbacks++;
            return Task.CompletedTask;
        }
        public Task ReplayPendingNotificationsAsync(
            StewardAgentId id, HostId destinationHostId, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
    private sealed class Ready : IAgentRestoreReadiness
    {
        public Task<bool> IsReadyAsync(StewardAgentId agentId, CancellationToken cancellationToken) =>
            Task.FromResult(true);
    }
    private sealed class Releaser : ISourceWorkspaceReleaser
    {
        public int Count { get; private set; }
        public int FailuresRemaining { get; set; }
        public Task ReleaseAsync(
            HostId sourceHostId, StewardAgentId agentId, long committedPlacementGeneration,
            CancellationToken cancellationToken)
        {
            if (FailuresRemaining-- > 0) throw new InvalidOperationException("injected release failure");
            Count++;
            return Task.CompletedTask;
        }
    }

    private static string NewPath() =>
        Path.Combine(AppContext.BaseDirectory, $"checkpoint-{Guid.NewGuid():N}.db");
    private static AgentEnvironmentManifest Manifest() =>
        new([new("dotnet", "10.0", Fingerprint('a'), EnvironmentReferenceKind.Sdk)],
            [new("git", "2.0", Fingerprint('b'), EnvironmentReferenceKind.Tool)]);
    private static string Fingerprint(char value) => $"sha256:{new string(value, 64)}";
    private static X509Certificate2 CreateEncryptionCertificate(int keySize)
    {
        using var rsa = RSA.Create(keySize);
        var request = new CertificateRequest(
            "CN=Steward Agent Destination", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    }
    private static AgentMigrationOrchestrator CreateOrchestrator(
        SqliteAgentStore store,
        IAgentMigrationTransport transport,
        ISourceWorkspaceReleaser releaser) =>
        new(store, new PortableAgentCheckpointBuilder(store),
            new AesGcmAgentCheckpointEncryption(new TestKeyEnvelope()), transport,
            new MigrationCoordinator(new InMemoryAgentPlacementStore(), releaser));
    private static void Cleanup(string path)
    {
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            if (File.Exists(path + suffix)) File.Delete(path + suffix);
    }
}
