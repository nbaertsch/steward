using System.Security.Cryptography;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class MaintenanceDurabilityTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "steward-maintenance-journal-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Completed_operation_is_idempotent_across_coordinator_restart()
    {
        Directory.CreateDirectory(root);
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = RandomNumberGenerator.GetBytes(32);
        var journalPath = Path.Combine(root, "operations.journal");
        var operationId = Guid.NewGuid();
        var executor = new RecordingExecutor();
        var first = Coordinator(journalPath, key, signingKey, executor, new EmptyLeaseProbe());
        var operation = new RepairEndpointOperation(1, RepairTarget.RdpDvcEndpointTask);

        var request = Sign(operation, signingKey, operationId);
        var firstResult = await first.ExecuteAsync(request, default);
        var second = Coordinator(journalPath, key, signingKey, executor, new EmptyLeaseProbe());
        var secondResult = await second.ExecuteAsync(request, default);
        Assert.Equal(MaintenanceOperationStatus.Succeeded, firstResult.Status);
        Assert.Equal(MaintenanceOperationStatus.Succeeded, secondResult.Status);
        Assert.True(secondResult.IsIdempotentReplay);
        Assert.Equal(1, executor.ExecutionCount);
        Assert.DoesNotContain("token", File.ReadAllText(journalPath), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Exact_request_and_operation_digest_replay_returns_prior_terminal_result()
    {
        Directory.CreateDirectory(root);
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var executor = new RecordingExecutor();
        var coordinator = Coordinator(
            Path.Combine(root, "operations.journal"),
            RandomNumberGenerator.GetBytes(32),
            signingKey,
            executor,
            new EmptyLeaseProbe());
        var request = Sign(
            new RepairEndpointOperation(
                1,
                RepairTarget.RdpDvcEndpointTask),
            signingKey);

        var accepted = await coordinator.ExecuteAsync(request, default);
        var replay = await coordinator.ExecuteAsync(request, default);

        Assert.Equal(MaintenanceOperationStatus.Succeeded, accepted.Status);
        Assert.Equal(MaintenanceOperationStatus.Succeeded, replay.Status);
        Assert.True(replay.IsIdempotentReplay);
        Assert.Equal(1, executor.ExecutionCount);
    }
    [Fact]
    public void Journal_rejects_conflicting_request_or_operation_identity_reuse()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "operations.journal");
        var journal = new FileMaintenanceJournal(
            path,
            RandomNumberGenerator.GetBytes(32));
        var first = MaintenanceContractTests.Request(
            new RepairEndpointOperation(
                1,
                RepairTarget.RdpDvcEndpointTask),
            issuedAtUtc: DateTimeOffset.UtcNow).Body;
        journal.Begin(first);

        var requestConflict = first with
        {
            OperationId = Guid.NewGuid()
        };
        var requestError = Assert.Throws<MaintenanceProtocolException>(() =>
            journal.Begin(requestConflict));
        Assert.Equal("request_id_conflict", requestError.Code);

        var operationConflict = first with
        {
            RequestId = Guid.NewGuid(),
            Operation = new RepairEndpointOperation(
                1,
                RepairTarget.HandleKeeperTask)
        };
        var operationError = Assert.Throws<MaintenanceProtocolException>(() =>
            journal.Begin(operationConflict));
        Assert.Equal("operation_id_conflict", operationError.Code);
    }
    [Fact]
    public async Task Running_operation_recovers_once_after_crash_and_tampering_fails_closed()
    {
        Directory.CreateDirectory(root);
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = RandomNumberGenerator.GetBytes(32);
        var path = Path.Combine(root, "operations.journal");
        var operationId = Guid.NewGuid();
        var body = Sign(
            new CollectDiagnosticsOperation(1, DiagnosticKind.MaintenanceAndEndpointHealth, 8192),
            signingKey,
            operationId).Body;
        var journal = new FileMaintenanceJournal(path, key);
        journal.Begin(body);
        journal.Transition(operationId, MaintenanceOperationStatus.Running);
        var executor = new RecordingExecutor();
        var coordinator = Coordinator(path, key, signingKey, executor, new EmptyLeaseProbe());

        await coordinator.RecoverAsync(default);
        await coordinator.RecoverAsync(default);

        Assert.Equal(1, executor.ExecutionCount);
        Assert.Equal(
            MaintenanceOperationStatus.Succeeded,
            new FileMaintenanceJournal(path, key).Get(operationId)?.Status);

        var bytes = File.ReadAllBytes(path);
        bytes[^1] ^= 0x5A;
        File.WriteAllBytes(path, bytes);
        Assert.Throws<InvalidDataException>(() =>
            new FileMaintenanceJournal(path, key).Get(operationId));
    }

    [Fact]
    public async Task Awaiting_reboot_exact_replay_returns_prior_in_progress_result()
    {
        Directory.CreateDirectory(root);
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coordinator = Coordinator(
            Path.Combine(root, "awaiting-reboot.journal"),
            RandomNumberGenerator.GetBytes(32),
            signingKey,
            new AwaitThenDeferRebootExecutor(),
            new EmptyLeaseProbe());
        var request = Sign(
            new ContinueAfterRebootOperation(
                1,
                RebootReason.EndpointUpdate),
            signingKey);

        var awaiting = await coordinator.ExecuteAsync(request, default);
        var replay = await coordinator.ExecuteAsync(request, default);

        Assert.Equal(
            MaintenanceOperationStatus.AwaitingReboot,
            awaiting.Status);
        Assert.Equal(
            MaintenanceOperationStatus.AwaitingReboot,
            replay.Status);
        Assert.True(replay.IsIdempotentReplay);
    }
    [Fact]
    public async Task Reboot_continuation_stays_pending_until_a_new_boot_is_observed()
    {
        Directory.CreateDirectory(root);
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = RandomNumberGenerator.GetBytes(32);
        var path = Path.Combine(root, "operations.journal");
        var operationId = Guid.NewGuid();
        var body = Sign(
            new ContinueAfterRebootOperation(1, RebootReason.WslFeatureEnablement),
            signingKey,
            operationId).Body;
        var journal = new FileMaintenanceJournal(path, key);
        journal.Begin(body);
        journal.Transition(operationId, MaintenanceOperationStatus.Running);
        journal.Transition(
            operationId,
            MaintenanceOperationStatus.AwaitingReboot,
            "same-boot");
        var coordinator = Coordinator(
            path,
            key,
            signingKey,
            new RebootDeferredExecutor(),
            new EmptyLeaseProbe());

        var summary = await coordinator.RecoverAsync(default);

        Assert.Equal(1, summary.Deferred);
        Assert.Equal(
            MaintenanceOperationStatus.AwaitingReboot,
            new FileMaintenanceJournal(path, key).Get(operationId)?.Status);
    }

    [Fact]
    public async Task Update_refuses_live_HandleKeeper_leases_before_any_effect()
    {
        Directory.CreateDirectory(root);
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var executor = new RecordingExecutor();
        var coordinator = Coordinator(
            Path.Combine(root, "operations.journal"),
            RandomNumberGenerator.GetBytes(32),
            signingKey,
            executor,
            new LiveLeaseProbe());
        var operation = new ActivateEndpointUpdateOperation(
            1,
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointMsi),
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointAttestation),
            MaintenanceContractTests.Release("2.0.0"),
            MaintenanceContractTests.Provenance());

        var error = await Assert.ThrowsAsync<MaintenanceProtocolException>(() =>
            coordinator.ExecuteAsync(Sign(operation, signingKey), default));

        Assert.Equal("live_leases", error.Code);
        Assert.Equal(0, executor.ExecutionCount);
    }

    [Fact]
    public async Task Update_releases_drain_fence_when_execution_fails()
    {
        Directory.CreateDirectory(root);
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fence = new RecordingDrainFence();
        var coordinator = Coordinator(
            Path.Combine(root, "operations.journal"),
            RandomNumberGenerator.GetBytes(32),
            signingKey,
            new ThrowingExecutor(),
            fence);
        var operation = new ActivateEndpointUpdateOperation(
            1,
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointMsi),
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointReleaseManifest),
            MaintenanceContractTests.Artifact(ApprovedArtifactKind.EndpointAttestation),
            MaintenanceContractTests.Release("2.0.0"),
            MaintenanceContractTests.Provenance());

        await Assert.ThrowsAsync<MaintenanceProtocolException>(() =>
            coordinator.ExecuteAsync(Sign(operation, signingKey), default));

        Assert.Equal(1, fence.Acquisitions);
        Assert.Equal(1, fence.Releases);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private static MaintenanceCoordinator Coordinator(
        string path,
        byte[] journalKey,
        ECDsa signingKey,
        IMaintenanceOperationExecutor executor,
        IHandleKeeperDrainFence drainFence) =>
        new(
            new MaintenanceRequestAuthenticator(
                signingKey.ExportSubjectPublicKeyInfo(),
                TimeProvider.System,
                TimeSpan.FromMinutes(5)),
            new InMemoryMaintenanceReplayStore(64),
            new FileMaintenanceJournal(path, journalKey),
            executor,
            drainFence);

    private static AuthenticatedMaintenanceRequest Sign(
        MaintenanceOperation operation,
        ECDsa key,
        Guid? operationId = null)
    {
        var request = MaintenanceContractTests.Request(
            operation,
            operationId: operationId,
            issuedAtUtc: DateTimeOffset.UtcNow);
        return MaintenanceAuthenticationTests.Sign(request.Body, key);
    }

    private sealed class RecordingDrainFence : IHandleKeeperDrainFence
    {
        internal int Acquisitions { get; private set; }
        internal int Releases { get; private set; }

        public ValueTask<IAsyncDisposable> AcquireAsync(
            HandleKeeperDrainRequest request,
            CancellationToken cancellationToken)
        {
            Acquisitions++;
            return ValueTask.FromResult<IAsyncDisposable>(
                new RecordingScope(this));
        }

        private sealed class RecordingScope(RecordingDrainFence owner) :
            IAsyncDisposable
        {
            public ValueTask DisposeAsync()
            {
                owner.Releases++;
                return ValueTask.CompletedTask;
            }
        }
    }

    private sealed class ThrowingExecutor : IMaintenanceOperationExecutor
    {
        public Task<MaintenanceExecutionResult> ExecuteAsync(
            MaintenanceOperation operation,
            MaintenanceExecutionContext context,
            CancellationToken cancellationToken) =>
            throw new IOException("injected failure");
    }

    private sealed class RecordingExecutor : IMaintenanceOperationExecutor
    {
        public int ExecutionCount { get; private set; }

        public Task<MaintenanceExecutionResult> ExecuteAsync(
            MaintenanceOperation operation,
            MaintenanceExecutionContext context,
            CancellationToken cancellationToken)
        {
            ExecutionCount++;
            return Task.FromResult(MaintenanceExecutionResult.Succeeded());
        }
    }

    private sealed class AwaitThenDeferRebootExecutor :
        IMaintenanceOperationExecutor
    {
        private int calls;

        public Task<MaintenanceExecutionResult> ExecuteAsync(
            MaintenanceOperation operation,
            MaintenanceExecutionContext context,
            CancellationToken cancellationToken)
        {
            calls++;
            if (calls == 1)
                return Task.FromResult(
                    MaintenanceExecutionResult.AwaitingReboot("boot-1"));
            throw new MaintenanceProtocolException(
                "reboot_not_observed",
                "Required reboot has not occurred.");
        }
    }
    private sealed class RebootDeferredExecutor : IMaintenanceOperationExecutor
    {
        public Task<MaintenanceExecutionResult> ExecuteAsync(
            MaintenanceOperation operation,
            MaintenanceExecutionContext context,
            CancellationToken cancellationToken) =>
            throw new MaintenanceProtocolException(
                "reboot_not_observed",
                "Required reboot has not occurred.");
    }

    private sealed class EmptyLeaseProbe : IHandleKeeperDrainFence
    {
        public ValueTask<IAsyncDisposable> AcquireAsync(
            HandleKeeperDrainRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<IAsyncDisposable>(new EmptyFenceScope());
    }

    private sealed class LiveLeaseProbe : IHandleKeeperDrainFence
    {
        public ValueTask<IAsyncDisposable> AcquireAsync(
            HandleKeeperDrainRequest request,
            CancellationToken cancellationToken) =>
            throw new MaintenanceProtocolException(
                "live_leases",
                "HandleKeeper has live leases.");
    }

    private sealed class EmptyFenceScope : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}



