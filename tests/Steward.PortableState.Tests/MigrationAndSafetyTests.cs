using Steward.Domain;
using Steward.PortableState;
using Microsoft.Data.Sqlite;

namespace Steward.PortableState.Tests;

public sealed class MigrationAndSafetyTests
{
    [Fact]
    public async Task Two_destinations_racing_have_one_placement_winner()
    {
        var agentId = StewardAgentId.New();
        var source = HostId.New();
        var store = new InMemoryAgentPlacementStore();
        var releaser = new RecordingReleaser();
        var coordinator = new MigrationCoordinator(store, releaser);
        var receipt = new PortableObjectReceipt(
            "agents/bundle",
            new string('a', 64),
            12,
            "\"etag\"",
            DateTimeOffset.UtcNow);

        Task<MigrationHandoffRecord?> Race(HostId destination) =>
            coordinator.TryCommitPlacementAsync(
                agentId,
                source,
                destination,
                0,
                receipt,
                new(agentId, destination, receipt.Sha256, true, true, DateTimeOffset.UtcNow));

        var results = await Task.WhenAll(Race(HostId.New()), Race(HostId.New()));

        Assert.Single(results, x => x is not null);
        Assert.Equal(1, await store.GetGenerationAsync(agentId));
        Assert.Equal(0, releaser.ReleaseCount);
        var winner = Assert.Single(results, x => x is not null)!;
        Assert.Equal(MigrationResumeAction.ActivateDestination, winner.ResumeAction);

        var activation = Activation(winner);
        await coordinator.RecordDestinationActiveAsync(activation);
        await coordinator.RecordDestinationActiveAsync(activation);
        await Assert.ThrowsAsync<PortableStateException>(() =>
            coordinator.RecordDestinationActiveAsync(
                activation with { ActivationReceiptId = "conflicting-activation" }));
        var released = await coordinator.ReleaseSourceAsync(agentId);

        Assert.Equal(1, releaser.ReleaseCount);
        Assert.True(released.SourceReleased);
        Assert.Equal(MigrationResumeAction.Complete, (await store.GetHandoffAsync(agentId))!.ResumeAction);
    }

    [Fact]
    public void Lifecycle_is_blocked_without_portable_receipt()
    {
        var host = new Host(HostId.New(), PoolId.New(), NodeIncarnationId.New());
        host.TransitionTo(HostLifecycleState.Provisioning);
        host.TransitionTo(HostLifecycleState.Bootstrapping);
        host.TransitionTo(HostLifecycleState.Enrolling);
        host.TransitionTo(HostLifecycleState.Ready);

        var exception = Assert.Throws<DomainRuleViolationException>(() => host.BeginDrain(
            [new DrainObligation(InterruptionClass.CheckpointResumable, CheckpointComplete: true, PortableReceiptPresent: false)]));

        Assert.Equal(DomainErrorCode.LifecycleBlockedByActiveWork, exception.Code);
    }

    [Fact]
    public async Task Doctor_surfaces_immutable_create_and_atomic_commit_as_prerequisites()
    {
        var doctor = new PortableStateDoctor(new DeploymentInspector(
            new(false, false, null)));

        var findings = await doctor.CheckAsync();

        Assert.Equal(2, findings.Count);
        Assert.All(findings, x => Assert.False(x.Passed));
        Assert.DoesNotContain(findings, x => x.Code.Contains("worm", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Durable_phases_survive_race_and_crashes_without_early_source_release()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "placement-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var database = Path.Combine(directory, "placement.db");
            var agent = StewardAgentId.New();
            var source = HostId.New();
            var receipt = new PortableObjectReceipt(
                "agents/bundle",
                new string('b', 64),
                42,
                "\"etag\"",
                DateTimeOffset.UtcNow);
            var failing = new FailingOnceReleaser();
            var destination1 = HostId.New();
            var destination2 = HostId.New();
            var coordinator1 = new MigrationCoordinator(new SqliteAgentPlacementStore(database), failing);
            var coordinator2 = new MigrationCoordinator(new SqliteAgentPlacementStore(database), failing);

            Task<MigrationHandoffRecord?> Race(MigrationCoordinator coordinator, HostId destination) =>
                coordinator.TryCommitPlacementAsync(
                    agent,
                    source,
                    destination,
                    0,
                    receipt,
                    new(agent, destination, receipt.Sha256, true, true, DateTimeOffset.UtcNow));

            var attempts = await Task.WhenAll(Race(coordinator1, destination1), Race(coordinator2, destination2));
            var winner = Assert.Single(attempts, x => x is not null)!;
            Assert.Single(attempts, x => x is null);
            Assert.Equal(0, failing.Calls);

            // Restart after placement CAS: source remains intact and activation is retryable.
            var restartedStore = new SqliteAgentPlacementStore(database);
            Assert.Equal(1, await restartedStore.GetGenerationAsync(agent));
            var restarted = new MigrationCoordinator(restartedStore, failing);
            Assert.Equal(MigrationResumeAction.ActivateDestination, (await restarted.InspectAsync(agent)).ResumeAction);
            await Assert.ThrowsAsync<PortableStateException>(() => restarted.ReleaseSourceAsync(agent));
            Assert.Equal(0, failing.Calls);

            var activation = Activation(winner);
            await restarted.RecordDestinationActiveAsync(activation);
            await restarted.RecordDestinationActiveAsync(activation);

            // Restart after destination activation receipt: source release is now retryable.
            var afterActivation = new MigrationCoordinator(new SqliteAgentPlacementStore(database), failing);
            Assert.Equal(MigrationResumeAction.ReleaseSource, (await afterActivation.InspectAsync(agent)).ResumeAction);
            await Assert.ThrowsAsync<InvalidOperationException>(() => afterActivation.ReleaseSourceAsync(agent));
            Assert.Equal(MigrationResumeAction.ReleaseSource, (await afterActivation.InspectAsync(agent)).ResumeAction);

            var resumed = await new MigrationCoordinator(
                new SqliteAgentPlacementStore(database),
                failing).ReleaseSourceAsync(agent);
            Assert.True(resumed.SourceReleased);
            Assert.True((await restartedStore.GetHandoffAsync(agent))!.SourceReleased);
            Assert.Equal(2, failing.Calls);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Sqlite_v1_handoffs_are_migrated_to_activation_aware_schema()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "placement-migration-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var database = Path.Combine(directory, "placement.db");
            await using (var connection = new SqliteConnection($"Data Source={database};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText =
                    """
                    CREATE TABLE portable_state_schema(
                        id INTEGER PRIMARY KEY CHECK(id = 1),
                        version INTEGER NOT NULL);
                    INSERT INTO portable_state_schema(id, version) VALUES(1, 1);
                    CREATE TABLE agent_placements(
                        agent_id TEXT PRIMARY KEY,
                        generation INTEGER NOT NULL);
                    CREATE TABLE migration_handoffs(
                        agent_id TEXT PRIMARY KEY,
                        source_host_id TEXT NOT NULL,
                        destination_host_id TEXT NOT NULL,
                        expected_generation INTEGER NOT NULL,
                        committed_generation INTEGER NOT NULL,
                        source_name TEXT NOT NULL,
                        source_sha256 TEXT NOT NULL,
                        source_length INTEGER NOT NULL,
                        source_etag TEXT NOT NULL,
                        source_committed_at TEXT NOT NULL,
                        bundle_sha256 TEXT NOT NULL,
                        hashes_verified INTEGER NOT NULL,
                        readiness_passed INTEGER NOT NULL,
                        restored_at TEXT NOT NULL,
                        source_released INTEGER NOT NULL,
                        committed_at TEXT NOT NULL);
                    """;
                await command.ExecuteNonQueryAsync();
            }

            _ = new SqliteAgentPlacementStore(database);

            await using var verify = new SqliteConnection($"Data Source={database};Pooling=False");
            await verify.OpenAsync();
            await using var versionCommand = verify.CreateCommand();
            versionCommand.CommandText = "SELECT version FROM portable_state_schema WHERE id = 1;";
            Assert.Equal(2L, (long)(await versionCommand.ExecuteScalarAsync())!);
            await using var columnCommand = verify.CreateCommand();
            columnCommand.CommandText =
                "SELECT COUNT(*) FROM pragma_table_info('migration_handoffs') WHERE name = 'activation_receipt_id';";
            Assert.Equal(1L, (long)(await columnCommand.ExecuteScalarAsync())!);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class RecordingReleaser : ISourceWorkspaceReleaser
    {
        private int _releaseCount;
        public int ReleaseCount => _releaseCount;

        public Task ReleaseAsync(
            HostId sourceHostId,
            StewardAgentId agentId,
            long committedPlacementGeneration,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _releaseCount);
            return Task.CompletedTask;
        }
    }

    private sealed class FailingOnceReleaser : ISourceWorkspaceReleaser
    {
        private int _calls;
        public int Calls => _calls;

        public Task ReleaseAsync(
            HostId sourceHostId,
            StewardAgentId agentId,
            long committedPlacementGeneration,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _calls) == 1)
                throw new InvalidOperationException("simulated release crash");
            return Task.CompletedTask;
        }
    }

    private sealed class DeploymentInspector(PortableStateDeploymentSettings settings)
        : IPortableStateDeploymentInspector
    {
        public Task<PortableStateDeploymentSettings> InspectAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(settings);
    }

    private static DestinationActivationReceipt Activation(MigrationHandoffRecord handoff) =>
        new(
            handoff.AgentId,
            handoff.DestinationHostId,
            handoff.CommittedPlacementGeneration,
            $"active-{handoff.CommittedPlacementGeneration}",
            true,
            DateTimeOffset.UtcNow);
}
