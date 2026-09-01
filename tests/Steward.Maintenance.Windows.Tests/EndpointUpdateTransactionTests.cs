using System.Security.Cryptography;
using Steward.Contracts;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class EndpointUpdateTransactionTests
{
    [Fact]
    public void Health_gate_rejects_stale_authenticated_observation()
    {
        var fixture = new HealthFixture();
        var stale = fixture.Authenticate(fixture.Observation with
        {
            UpdatedAtUtc = fixture.Now - TimeSpan.FromMinutes(2)
        });

        Assert.Equal(
            EndpointHealthStatus.ControlUnavailable,
            fixture.Evaluate(stale).Status);
    }

    [Fact]
    public void Health_gate_rejects_wrong_identity_and_generation()
    {
        var fixture = new HealthFixture();
        var identity = fixture.Authenticate(fixture.Observation with
        {
            HostId = Guid.NewGuid()
        });
        var generation = fixture.Authenticate(fixture.Observation with
        {
            ReconnectGeneration = 91
        });

        Assert.Equal(
            EndpointHealthStatus.IdentityMismatch,
            fixture.Evaluate(identity).Status);
        Assert.Equal(
            EndpointHealthStatus.ControlUnavailable,
            fixture.Evaluate(generation).Status);
    }

    [Fact]
    public void Health_gate_rejects_wrong_PID_and_WTS_session()
    {
        var fixture = new HealthFixture();
        var wrongProcess = new FakeEndpointProcessEvidenceSource(
            fixture.Process with { ProcessId = fixture.Process.ProcessId + 1 });
        var wrongSession = new FakeEndpointProcessEvidenceSource(
            fixture.Process with { WtsSessionId = fixture.Process.WtsSessionId + 1 });
        var authenticated = fixture.Authenticate(fixture.Observation);

        Assert.Equal(
            EndpointHealthStatus.Unhealthy,
            fixture.Evaluate(authenticated, wrongProcess).Status);
        Assert.Equal(
            EndpointHealthStatus.Unhealthy,
            fixture.Evaluate(authenticated, wrongSession).Status);
    }

    [Fact]
    public void Health_gate_rejects_wrong_authenticator()
    {
        var fixture = new HealthFixture();
        var authenticated = fixture.Authenticate(fixture.Observation);

        var result = EndpointUpdateHealthGate.Evaluate(
            authenticated,
            RandomNumberGenerator.GetBytes(32),
            fixture.SessionId,
            fixture.HostId,
            fixture.IncarnationId,
            fixture.NodeIdentity,
            fixture.ControlIdentity,
            generationHighWater: 91,
            fixture.Now,
            TimeSpan.FromSeconds(30),
            new FakeEndpointProcessEvidenceSource(fixture.Process));

        Assert.Equal(EndpointHealthStatus.Unhealthy, result.Status);
    }

    [Fact]
    public void Health_gate_accepts_fresh_authentic_identity_generation_process_and_WTS_session()
    {
        var fixture = new HealthFixture();

        var result = fixture.Evaluate(
            fixture.Authenticate(fixture.Observation));

        Assert.Equal(EndpointHealthStatus.Healthy, result.Status);
    }
    [Fact]
    public async Task Good_update_commits_known_good_without_changing_preserved_authority()
    {
        var fixture = new UpdateFixture();

        var result = await fixture.Coordinator.ExecuteAsync(
            fixture.Operation("1.1.0"),
            default);

        Assert.Equal(EndpointUpdateDisposition.Activated, result.Disposition);
        Assert.Equal(EndpointUpdateTransactionState.Succeeded, result.State);
        Assert.Equal("1.1.0", fixture.Store.History.ActiveVersion);
        Assert.Equal("1.1.0", fixture.Store.History.HighestSignedVersion);
        Assert.Equal((ulong)1, fixture.Store.History.LastUpdateSequence);
        Assert.Equal(fixture.Preserved, fixture.Platform.PreservedAfterActivation);
        Assert.Equal(1, fixture.Platform.CleanupEffects);
        Assert.Equal(1, fixture.Platform.HandoffIntentEffects);
        Assert.Equal(1, fixture.Platform.HandoffTriggerEffects);
        Assert.Equal(1, fixture.Platform.ReceiptObservations);
        Assert.Equal(
            [
                EndpointUpdateTransactionState.Requested,
                EndpointUpdateTransactionState.ReleaseVerified,
                EndpointUpdateTransactionState.Staged,
                EndpointUpdateTransactionState.CompatibilityExpanded,
                EndpointUpdateTransactionState.InstallerHandoffIntentCommitted,
                EndpointUpdateTransactionState.InstallerHandoffTriggered,
                EndpointUpdateTransactionState.InstallerCommitted,
                EndpointUpdateTransactionState.HealthGateRunning,
                EndpointUpdateTransactionState.KnownGoodCommitted,
                EndpointUpdateTransactionState.MigrationContracted,
                EndpointUpdateTransactionState.Succeeded
            ],
            fixture.Store.States);
    }

    [Theory]
    [InlineData((int)EndpointUpdateBoundary.ReleaseVerified)]
    [InlineData((int)EndpointUpdateBoundary.Staged)]
    [InlineData((int)EndpointUpdateBoundary.CompatibilityExpanded)]
    [InlineData((int)EndpointUpdateBoundary.InstallerHandoffIntentCommitted)]
    [InlineData((int)EndpointUpdateBoundary.InstallerHandoffTriggered)]
    [InlineData((int)EndpointUpdateBoundary.InstallerCommitted)]
    [InlineData((int)EndpointUpdateBoundary.HealthGateStarted)]
    [InlineData((int)EndpointUpdateBoundary.KnownGoodCommitted)]
    [InlineData((int)EndpointUpdateBoundary.MigrationContracted)]
    public async Task Every_durable_crash_boundary_continues_without_duplicate_activation(
        int boundaryValue)
    {
        var fixture = new UpdateFixture((EndpointUpdateBoundary)boundaryValue);
        var operation = fixture.Operation("1.1.0");

        await Assert.ThrowsAsync<EndpointUpdateInterruptedException>(() =>
            fixture.Coordinator.ExecuteAsync(operation, default));
        fixture.Observer.Disable();
        var restarted = fixture.CreateCoordinator();
        var result = await restarted.ExecuteAsync(operation, default);

        Assert.Equal(EndpointUpdateDisposition.Activated, result.Disposition);
        Assert.Equal(1, fixture.Platform.HandoffTriggerEffects);
        Assert.Equal(1, fixture.Platform.KnownGoodEffects);
        Assert.Equal(EndpointUpdateTransactionState.Succeeded, fixture.Store.Current?.State);
    }

    [Theory]
    [InlineData((int)EndpointUpdateBoundary.RollbackIntentCommitted)]
    [InlineData((int)EndpointUpdateBoundary.RolledBack)]
    public async Task Rollback_crash_boundaries_continue_without_reusing_state(
        int boundaryValue)
    {
        var fixture = new UpdateFixture(
            (EndpointUpdateBoundary)boundaryValue);
        fixture.Platform.Health = EndpointHealthStatus.CrashLoop;
        var operation = fixture.Operation("1.1.0");

        await Assert.ThrowsAsync<EndpointUpdateInterruptedException>(() =>
            fixture.Coordinator.ExecuteAsync(operation, default));
        fixture.Observer.Disable();
        var restarted = fixture.CreateCoordinator();
        var error = await Assert.ThrowsAsync<EndpointUpdateException>(() =>
            restarted.ExecuteAsync(operation, default));

        Assert.Equal("activation_crash_loop", error.Code);
        Assert.Equal(EndpointUpdateTransactionState.RolledBack,
            fixture.Store.Current?.State);
        Assert.Equal(1, fixture.Platform.RollbackEffects);
        Assert.Equal((ulong)1, fixture.Store.History.LastUpdateSequence);
    }
    [Fact]
    public async Task Rolled_back_installer_receipt_is_terminal_and_never_enters_health_gate()
    {
        var fixture = new UpdateFixture();
        fixture.Platform.InstallerOutcome =
            EndpointInstallerReceiptOutcome.RolledBack;

        var error = await Assert.ThrowsAsync<EndpointUpdateException>(() =>
            fixture.Coordinator.ExecuteAsync(fixture.Operation("1.1.0"), default));

        Assert.Equal("installer_rolled_back", error.Code);
        Assert.Equal(EndpointUpdateTransactionState.RolledBack,
            fixture.Store.Current?.State);
        Assert.Equal(1, fixture.Platform.HandoffIntentEffects);
        Assert.Equal(1, fixture.Platform.HandoffTriggerEffects);
        Assert.Equal(1, fixture.Platform.ReceiptObservations);
        Assert.Equal(0, fixture.Platform.HealthObservations);
        Assert.Equal(0, fixture.Platform.ActivationEffects);
    }
    [Theory]
    [InlineData((int)EndpointHealthStatus.ControlUnavailable, "health_timeout")]
    [InlineData((int)EndpointHealthStatus.CrashLoop, "activation_crash_loop")]
    [InlineData((int)EndpointHealthStatus.IdentityMismatch, "health_identity_mismatch")]
    public async Task Failed_health_gate_rolls_back_and_keeps_monotonic_history(
        int healthValue,
        string expectedCode)
    {
        var fixture = new UpdateFixture();
        fixture.Platform.Health = (EndpointHealthStatus)healthValue;

        var error = await Assert.ThrowsAsync<EndpointUpdateException>(() =>
            fixture.Coordinator.ExecuteAsync(fixture.Operation("1.1.0"), default));

        Assert.Equal(expectedCode, error.Code);
        Assert.Equal(EndpointUpdateTransactionState.RolledBack, fixture.Store.Current?.State);
        Assert.Equal("1.0.23", fixture.Store.History.ActiveVersion);
        Assert.Equal("1.1.0", fixture.Store.History.HighestSignedVersion);
        Assert.Equal((ulong)1, fixture.Store.History.LastUpdateSequence);
        Assert.Equal(1, fixture.Platform.RollbackEffects);
        Assert.Equal(1, fixture.Platform.CleanupEffects);
        Assert.Equal(fixture.Preserved, fixture.Platform.PreservedAfterRollback);
    }

    [Theory]
    [InlineData(EndpointUpdateFailure.ReleaseSignature, "signature_mismatch")]
    [InlineData(EndpointUpdateFailure.Attestation, "attestation_missing")]
    [InlineData(EndpointUpdateFailure.Provenance, "provenance_mismatch")]
    [InlineData(EndpointUpdateFailure.Hash, "hash_mismatch")]
    [InlineData(EndpointUpdateFailure.Size, "artifact_size_mismatch")]
    [InlineData(EndpointUpdateFailure.CorruptMsi, "corrupt_msi")]
    [InlineData(EndpointUpdateFailure.ReparsePoint, "staging_reparse")]
    [InlineData(EndpointUpdateFailure.HardLink, "staging_hardlink")]
    [InlineData(EndpointUpdateFailure.StagingMutation, "staging_mutated")]
    public async Task Verification_and_staging_fail_closed_before_activation(
        EndpointUpdateFailure failure,
        string expectedCode)
    {
        var fixture = new UpdateFixture();
        fixture.Platform.Failure = failure;

        var error = await Assert.ThrowsAsync<EndpointUpdateException>(() =>
            fixture.Coordinator.ExecuteAsync(fixture.Operation("1.1.0"), default));

        Assert.Equal(expectedCode, error.Code);
        Assert.Equal(EndpointUpdateTransactionState.Failed, fixture.Store.Current?.State);
        Assert.Equal(0, fixture.Platform.ActivationEffects);
        Assert.Equal(0, fixture.Platform.RollbackEffects);
        Assert.Equal(1, fixture.Platform.CleanupEffects);
        Assert.Equal("1.0.23", fixture.Store.History.ActiveVersion);
    }

    [Fact]
    public async Task Migration_failure_before_activation_fails_without_switching()
    {
        var fixture = new UpdateFixture();
        fixture.Platform.Failure = EndpointUpdateFailure.Migration;

        var error = await Assert.ThrowsAsync<EndpointUpdateException>(() =>
            fixture.Coordinator.ExecuteAsync(fixture.Operation("1.1.0"), default));

        Assert.Equal("migration_expand_failed", error.Code);
        Assert.Equal(0, fixture.Platform.ActivationEffects);
        Assert.Equal(EndpointUpdateTransactionState.Failed, fixture.Store.Current?.State);
    }

    [Fact]
    public async Task Downgrade_and_same_version_substitution_are_signed_version_rollback_attacks()
    {
        var fixture = new UpdateFixture();
        await fixture.Coordinator.ExecuteAsync(fixture.Operation("1.1.0"), default);
        fixture.BeginNextOperation();

        var downgrade = await Assert.ThrowsAsync<EndpointUpdateException>(() =>
            fixture.Coordinator.ExecuteAsync(fixture.Operation("1.0.23"), default));
        var substitution = await Assert.ThrowsAsync<EndpointUpdateException>(() =>
            fixture.Coordinator.ExecuteAsync(
                fixture.Operation("1.1.0") with
                {
                    Release = fixture.Release("1.1.0") with
                    {
                        MsiSha256 = new string('F', 64)
                    },
                    Package = fixture.Operation("1.1.0").Package with
                    {
                        Sha256 = new string('F', 64)
                    }
                },
                default));

        Assert.Equal("signed_version_rollback", downgrade.Code);
        Assert.Equal("signed_version_substitution", substitution.Code);
    }

    [Fact]
    public async Task Upgrade_rollback_and_second_upgrade_preserve_exact_state_and_never_reuse_sequence()
    {
        var fixture = new UpdateFixture();
        fixture.Platform.Health = EndpointHealthStatus.ControlUnavailable;
        await Assert.ThrowsAsync<EndpointUpdateException>(() =>
            fixture.Coordinator.ExecuteAsync(fixture.Operation("1.1.0"), default));

        fixture.BeginNextOperation();
        fixture.Platform.Health = EndpointHealthStatus.Healthy;
        var second = await fixture.Coordinator.ExecuteAsync(
            fixture.Operation("1.1.0"),
            default);

        Assert.Equal(EndpointUpdateDisposition.Activated, second.Disposition);
        Assert.Equal((ulong)2, fixture.Store.History.LastUpdateSequence);
        Assert.Equal(fixture.Preserved, fixture.Platform.PreservedAfterActivation);
        Assert.Equal((ulong)91, fixture.Platform.PreservedAfterActivation.ReconnectGeneration);
        Assert.Equal((ulong)44, fixture.Platform.PreservedAfterActivation.ApplicationCursor);
        Assert.Equal((ulong)12, fixture.Platform.PreservedAfterActivation.UpdateVersion);
        Assert.Equal("1.1.0", fixture.Store.History.ActiveVersion);

        fixture.BeginNextOperation();
        var repair = await fixture.Coordinator.ExecuteAsync(
            fixture.Operation("1.1.0"),
            default);
        Assert.Equal(EndpointUpdateDisposition.Activated, repair.Disposition);
        Assert.Equal((ulong)3, fixture.Store.History.LastUpdateSequence);
        Assert.Equal(fixture.Preserved, fixture.Platform.PreservedAfterActivation);
    }

    private sealed class HealthFixture
    {
        internal readonly DateTimeOffset Now =
            DateTimeOffset.Parse("2026-09-01T17:00:00Z");
        internal readonly Guid SessionId =
            Guid.Parse("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA");
        internal readonly Guid HostId =
            Guid.Parse("11111111-1111-1111-1111-111111111111");
        internal readonly Guid IncarnationId =
            Guid.Parse("22222222-2222-2222-2222-222222222222");
        internal readonly string NodeIdentity =
            "node/11111111111111111111111111111111";
        internal readonly string ControlIdentity = "control";
        internal readonly byte[] Key = RandomNumberGenerator.GetBytes(32);
        internal EndpointProcessEvidence Process { get; }
        internal EndpointV2Health Observation { get; }

        internal HealthFixture()
        {
            var started = Now - TimeSpan.FromMinutes(5);
            Process = new EndpointProcessEvidence(401, 3, started, true);
            Observation = new EndpointV2Health(
                EndpointV2HealthContract.Version,
                SessionId,
                HostId,
                IncarnationId,
                NodeIdentity,
                ControlIdentity,
                EndpointV2HealthState.Authenticated,
                92,
                Guid.Parse("33333333-3333-3333-3333-333333333333"),
                3,
                Now,
                401,
                started);
        }

        internal AuthenticatedEndpointV2Health Authenticate(
            EndpointV2Health value) =>
            EndpointV2HealthAuthenticator.Authenticate(value, Key);

        internal EndpointHealthObservation Evaluate(
            AuthenticatedEndpointV2Health value,
            IEndpointProcessEvidenceSource? source = null) =>
            EndpointUpdateHealthGate.Evaluate(
                value,
                Key,
                SessionId,
                HostId,
                IncarnationId,
                NodeIdentity,
                ControlIdentity,
                generationHighWater: 91,
                Now,
                TimeSpan.FromSeconds(30),
                source ?? new FakeEndpointProcessEvidenceSource(Process));
    }

    private sealed class FakeEndpointProcessEvidenceSource(
        EndpointProcessEvidence evidence) : IEndpointProcessEvidenceSource
    {
        public EndpointProcessEvidence Observe(int processId) => evidence;
    }
    private sealed class UpdateFixture
    {
        internal readonly EndpointPreservationSnapshot Preserved = new(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            Hash('1'),
            Hash('2'),
            Hash('3'),
            Hash('4'),
            Hash('5'),
            Hash('6'),
            Hash('7'),
            Hash('8'),
            Hash('9'),
            Hash('A'),
            91,
            12,
            44,
            "tasks-v1");

        internal InMemoryEndpointUpdateTransactionStore Store { get; private set; }
        internal FakeUpdatePlatform Platform { get; }
        internal CrashObserver Observer { get; }
        internal EndpointUpdateCoordinator Coordinator { get; private set; }

        internal UpdateFixture(EndpointUpdateBoundary? crashAt = null)
        {
            Store = new InMemoryEndpointUpdateTransactionStore("1.0.23");
            Platform = new FakeUpdatePlatform(Preserved);
            Observer = new CrashObserver(crashAt);
            Coordinator = CreateCoordinator();
        }

        internal EndpointUpdateCoordinator CreateCoordinator() =>
            new(Store, Platform, Observer, maximumHealthObservations: 3);

        internal void BeginNextOperation()
        {
            Store = Store.ForNextOperation();
            Coordinator = CreateCoordinator();
        }

        internal ActivateEndpointUpdateOperation Operation(string version) =>
            new(
                1,
                MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointMsi),
                MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
                MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointAttestation),
                Release(version),
                MaintenanceContractTests.Provenance());

        internal EndpointReleaseIdentity Release(string version) => new(
            1,
            $"steward-endpoint/{version}/123456789",
            version,
            Hash('A'),
            1024,
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            Guid.Parse("37C34E0A-E245-48A4-B07C-78E2955A7E65"));

        private static string Hash(char value) => new(value, 64);
    }

    private sealed class CrashObserver(EndpointUpdateBoundary? boundary) : IEndpointUpdateBoundaryObserver
    {
        private EndpointUpdateBoundary? boundary = boundary;

        public void Reached(EndpointUpdateBoundary reached)
        {
            if (boundary == reached)
                throw new EndpointUpdateInterruptedException(reached);
        }

        internal void Disable() => boundary = null;
    }

    public enum EndpointUpdateFailure
    {
        None,
        ReleaseSignature,
        Attestation,
        Provenance,
        Hash,
        Size,
        CorruptMsi,
        ReparsePoint,
        HardLink,
        StagingMutation,
        Migration
    }

    private sealed class FakeUpdatePlatform(EndpointPreservationSnapshot preserved) : IEndpointUpdatePlatform
    {
        internal EndpointUpdateFailure Failure { get; set; }
        internal EndpointHealthStatus Health { get; set; } = EndpointHealthStatus.Healthy;
        internal EndpointInstallerReceiptOutcome InstallerOutcome
        {
            get; set;
        } = EndpointInstallerReceiptOutcome.Committed;
        internal int ActivationEffects { get; private set; }
        internal int HandoffIntentEffects { get; private set; }
        internal int HandoffTriggerEffects { get; private set; }
        internal int ReceiptObservations { get; private set; }
        internal int HealthObservations { get; private set; }
        internal int RollbackEffects { get; private set; }
        internal int KnownGoodEffects { get; private set; }
        internal int CleanupEffects { get; private set; }
        internal EndpointPreservationSnapshot PreservedAfterActivation { get; private set; } = null!;
        internal EndpointPreservationSnapshot PreservedAfterRollback { get; private set; } = null!;
        private bool handoffIntentPersisted;
        private bool handoffTriggered;
        private bool receiptObserved;
        private bool rolledBack;
        private bool knownGood;

        public Task<EndpointPreservationSnapshot> CapturePreservedStateAsync(
            Guid transactionId,
            ActivateEndpointUpdateOperation operation,
            CancellationToken cancellationToken) => Task.FromResult(preserved);

        public Task<VerifiedEndpointRelease> VerifyReleaseAsync(
            ActivateEndpointUpdateOperation operation,
            CancellationToken cancellationToken)
        {
            ThrowFailure(
                (EndpointUpdateFailure.ReleaseSignature, "signature_mismatch"),
                (EndpointUpdateFailure.Attestation, "attestation_missing"),
                (EndpointUpdateFailure.Provenance, "provenance_mismatch"),
                (EndpointUpdateFailure.Hash, "hash_mismatch"),
                (EndpointUpdateFailure.Size, "artifact_size_mismatch"),
                (EndpointUpdateFailure.CorruptMsi, "corrupt_msi"));
            return Task.FromResult(new VerifiedEndpointRelease(
                operation.Release,
                "manifest",
                "package",
                "attestation"));
        }

        public Task<StagedEndpointRelease> StageImmutableAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            ThrowFailure(
                (EndpointUpdateFailure.ReparsePoint, "staging_reparse"),
                (EndpointUpdateFailure.HardLink, "staging_hardlink"),
                (EndpointUpdateFailure.StagingMutation, "staging_mutated"));
            return Task.FromResult(new StagedEndpointRelease(
                transaction.VerifiedRelease!.Release,
                "version-root",
                "package",
                "manifest",
                "attestation",
                Hash('C')));
        }

        public Task ExpandCompatibilityAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            ThrowFailure((EndpointUpdateFailure.Migration, "migration_expand_failed"));
            return Task.CompletedTask;
        }

        public Task PersistInstallerHandoffAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            if (!handoffIntentPersisted)
            {
                handoffIntentPersisted = true;
                HandoffIntentEffects++;
            }
            return Task.CompletedTask;
        }

        public Task TriggerInstallerHandoffAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            if (!handoffTriggered)
            {
                handoffTriggered = true;
                HandoffTriggerEffects++;
            }
            return Task.CompletedTask;
        }

        public Task<EndpointInstallerReceiptOutcome>
            ObserveInstallerReceiptAsync(
                EndpointUpdateTransaction transaction,
                CancellationToken cancellationToken)
        {
            if (!receiptObserved)
            {
                receiptObserved = true;
                ReceiptObservations++;
            }
            return Task.FromResult(InstallerOutcome);
        }

        public Task<EndpointHealthObservation> ObserveHealthAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            HealthObservations++;
            return Task.FromResult(new EndpointHealthObservation(
                Health,
                Health.ToString()));
        }

        public Task CommitKnownGoodAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            if (!knownGood)
            {
                knownGood = true;
                KnownGoodEffects++;
            }
            PreservedAfterActivation = preserved;
            return Task.CompletedTask;
        }

        public Task ContractCompatibilityAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RollbackAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            if (!rolledBack)
            {
                rolledBack = true;
                RollbackEffects++;
            }
            PreservedAfterRollback = preserved;
            return Task.CompletedTask;
        }

        public Task CleanupPreservationAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            CleanupEffects++;
            return Task.CompletedTask;
        }

        public Task AssertPreservedAsync(
            EndpointUpdateTransaction transaction,
            CancellationToken cancellationToken)
        {
            Assert.Equal(preserved, transaction.PreservedState);
            return Task.CompletedTask;
        }

        private void ThrowFailure(params (EndpointUpdateFailure Failure, string Code)[] failures)
        {
            var match = failures.SingleOrDefault(value => value.Failure == Failure);
            if (match.Failure != EndpointUpdateFailure.None)
                throw new EndpointUpdateException(match.Code, "Injected update failure.");
        }

        private static string Hash(char value) => new(value, 64);
    }
}

