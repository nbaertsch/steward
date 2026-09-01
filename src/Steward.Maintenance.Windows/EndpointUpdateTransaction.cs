namespace Steward.Maintenance.Windows;

internal enum EndpointUpdateTransactionState
{
    Requested,
    ReleaseVerified,
    Staged,
    CompatibilityExpanded,
    InstallerHandoffIntentCommitted,
    InstallerHandoffTriggered,
    InstallerCommitted,
    HealthGateRunning,
    KnownGoodCommitted,
    MigrationContracted,
    Succeeded,
    RollbackIntentCommitted,
    RolledBack,
    Failed
}

internal enum EndpointUpdateDisposition
{
    Activated,
    RolledBack
}

internal enum EndpointHealthStatus
{
    Healthy,
    ControlUnavailable,
    CrashLoop,
    IdentityMismatch,
    Unhealthy
}

internal enum EndpointUpdateBoundary
{
    ReleaseVerified,
    Staged,
    CompatibilityExpanded,
    InstallerHandoffIntentCommitted,
    InstallerHandoffTriggered,
    InstallerCommitted,
    HealthGateStarted,
    KnownGoodCommitted,
    MigrationContracted,
    RollbackIntentCommitted,
    RolledBack
}

internal sealed record EndpointPreservationSnapshot(
    Guid HostId,
    Guid NodeIncarnationId,
    string NodePrivateKeySha256,
    string ControlTrustSha256,
    string MaintenanceTrustSha256,
    string NodeJournalSha256,
    string ExecutionJournalSha256,
    string WorkspaceTreeSha256,
    string SpoolTreeSha256,
    string ReceiptTreeSha256,
    string TerminalJournalSha256,
    string EvaluationJournalSha256,
    ulong ReconnectGeneration,
    ulong UpdateVersion,
    ulong ApplicationCursor,
    string ScheduledTaskSemantics)
{
    internal Guid SessionId { get; init; }
    internal string NodeIdentity { get; init; } = string.Empty;
    internal string ControlIdentity { get; init; } = string.Empty;
    internal string PortableTreeSha256 { get; init; } = new('0', 64);
    internal string? BackupRoot { get; init; }
    internal IReadOnlyList<EndpointSqliteSnapshot> SqliteDatabases
    {
        get; init;
    } = [];
}

internal sealed record VerifiedEndpointRelease(
    EndpointReleaseIdentity Release,
    string ManifestPath,
    string PackagePath,
    string AttestationPath);

internal sealed record StagedEndpointRelease(
    EndpointReleaseIdentity Release,
    string VersionRoot,
    string PackagePath,
    string ManifestPath,
    string AttestationPath,
    string TreeSha256);

internal sealed record EndpointHealthObservation(
    EndpointHealthStatus Status,
    string Detail);

internal sealed record EndpointKnownGoodVersion(
    string ProductVersion,
    string ReleaseSha256,
    ulong UpdateSequence);

internal sealed record EndpointUpdateVersionHistory(
    int Version,
    string ActiveVersion,
    string HighestSignedVersion,
    string? HighestSignedReleaseSha256,
    ulong LastUpdateSequence,
    IReadOnlyList<EndpointKnownGoodVersion> KnownGoodVersions);

internal sealed record EndpointUpdateTransaction(
    int Version,
    Guid TransactionId,
    ulong UpdateSequence,
    string PriorVersion,
    ActivateEndpointUpdateOperation Operation,
    EndpointUpdateTransactionState State,
    EndpointPreservationSnapshot PreservedState,
    VerifiedEndpointRelease? VerifiedRelease,
    StagedEndpointRelease? StagedRelease,
    int HealthObservations,
    string? ErrorCode);

internal sealed record EndpointUpdateResult(
    EndpointUpdateDisposition Disposition,
    EndpointUpdateTransactionState State,
    string ActiveVersion,
    ulong UpdateSequence);

internal sealed class EndpointUpdateException(
    string code,
    string safeMessage) : Exception(safeMessage)
{
    internal string Code { get; } = code;
}

internal sealed class EndpointUpdateInterruptedException(
    EndpointUpdateBoundary boundary) :
    Exception($"Injected endpoint update interruption at {boundary}.")
{
    internal EndpointUpdateBoundary Boundary { get; } = boundary;
}

internal interface IEndpointUpdateBoundaryObserver
{
    void Reached(EndpointUpdateBoundary boundary);
}

internal sealed class NullEndpointUpdateBoundaryObserver :
    IEndpointUpdateBoundaryObserver
{
    internal static NullEndpointUpdateBoundaryObserver Instance { get; } = new();

    private NullEndpointUpdateBoundaryObserver()
    {
    }

    public void Reached(EndpointUpdateBoundary boundary)
    {
    }
}

internal interface IEndpointUpdatePlatform
{
    Task<EndpointPreservationSnapshot> CapturePreservedStateAsync(
        Guid transactionId,
        ActivateEndpointUpdateOperation operation,
        CancellationToken cancellationToken);

    Task<VerifiedEndpointRelease> VerifyReleaseAsync(
        ActivateEndpointUpdateOperation operation,
        CancellationToken cancellationToken);

    Task<StagedEndpointRelease> StageImmutableAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task ExpandCompatibilityAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task PersistInstallerHandoffAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task TriggerInstallerHandoffAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task<EndpointInstallerReceiptOutcome> ObserveInstallerReceiptAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task<EndpointHealthObservation> ObserveHealthAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task CommitKnownGoodAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task ContractCompatibilityAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task RollbackAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task AssertPreservedAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);

    Task CleanupPreservationAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken);
}

internal interface IEndpointUpdateTransactionStore
{
    EndpointUpdateTransaction? Current { get; }
    EndpointUpdateVersionHistory History { get; }

    void Prepare(Guid transactionId);

    EndpointUpdateTransaction Begin(
        Guid transactionId,
        ActivateEndpointUpdateOperation operation,
        EndpointPreservationSnapshot preservedState);

    EndpointUpdateTransaction Transition(
        EndpointUpdateTransactionState state,
        VerifiedEndpointRelease? verifiedRelease = null,
        StagedEndpointRelease? stagedRelease = null,
        string? errorCode = null);

    EndpointUpdateTransaction RecordHealthObservation();
    EndpointUpdateTransaction CommitKnownGood();
    EndpointUpdateTransaction CommitRollback(string errorCode);
}

internal sealed class InMemoryEndpointUpdateTransactionStore :
    IEndpointUpdateTransactionStore
{
    private EndpointUpdateVersionHistory history;
    private readonly List<EndpointUpdateTransactionState> states = [];

    internal InMemoryEndpointUpdateTransactionStore(string activeVersion) :
        this(new EndpointUpdateVersionHistory(
            1,
            NormalizeVersion(activeVersion),
            NormalizeVersion(activeVersion),
            null,
            0,
            []))
    {
    }

    private InMemoryEndpointUpdateTransactionStore(
        EndpointUpdateVersionHistory history)
    {
        this.history = history;
    }

    internal static InMemoryEndpointUpdateTransactionStore Restore(
        EndpointUpdateVersionHistory history,
        EndpointUpdateTransaction? current)
    {
        var store = new InMemoryEndpointUpdateTransactionStore(history)
        {
            Current = current
        };
        if (current is not null)
            store.states.Add(current.State);
        return store;
    }

    public EndpointUpdateTransaction? Current { get; private set; }
    public EndpointUpdateVersionHistory History => history;
    internal IReadOnlyList<EndpointUpdateTransactionState> States => states;

    internal InMemoryEndpointUpdateTransactionStore ForNextOperation()
    {
        if (Current is not null && Current.State is not (
                EndpointUpdateTransactionState.Succeeded or
                EndpointUpdateTransactionState.RolledBack or
                EndpointUpdateTransactionState.Failed))
            throw new InvalidOperationException(
                "A pending endpoint update cannot be replaced.");
        return new InMemoryEndpointUpdateTransactionStore(history);
    }

    public void Prepare(Guid transactionId)
    {
        if (transactionId == Guid.Empty)
            throw new ArgumentException(
                "Endpoint update transaction ID is required.",
                nameof(transactionId));
        if (Current is null || Current.TransactionId == transactionId)
            return;
        if (Current.State is not (
                EndpointUpdateTransactionState.Succeeded or
                EndpointUpdateTransactionState.RolledBack or
                EndpointUpdateTransactionState.Failed))
            throw new EndpointUpdateException(
                "update_in_progress",
                "A different endpoint update is already pending.");
        Current = null;
        states.Clear();
    }

    public EndpointUpdateTransaction Begin(
        ActivateEndpointUpdateOperation operation,
        EndpointPreservationSnapshot preservedState) =>
        Begin(Guid.NewGuid(), operation, preservedState);

    public EndpointUpdateTransaction Begin(
        Guid transactionId,
        ActivateEndpointUpdateOperation operation,
        EndpointPreservationSnapshot preservedState)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(preservedState);
        MaintenanceContract.ValidateOperation(operation);
        if (Current is not null)
        {
            if (Current.Operation != operation)
                throw new EndpointUpdateException(
                    "update_in_progress",
                    "A different endpoint update is already pending.");
            return Current;
        }

        var requested = Version.Parse(operation.ProductVersion);
        var active = Version.Parse(history.ActiveVersion);
        var highest = Version.Parse(history.HighestSignedVersion);
        if (requested < highest)
            throw new EndpointUpdateException(
                "signed_version_rollback",
                "Endpoint signed version rollback is refused.");
        if (requested == highest &&
            history.HighestSignedReleaseSha256 is { } acceptedRelease &&
            !string.Equals(
                acceptedRelease,
                operation.Release.MsiSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new EndpointUpdateException(
                "signed_version_substitution",
                "A signed endpoint version cannot be rebound to another release.");
        if (requested < active)
            throw new EndpointUpdateException(
                "downgrade_refused",
                "Endpoint update downgrade is refused.");
        if (history.LastUpdateSequence == ulong.MaxValue)
            throw new EndpointUpdateException(
                "update_sequence_exhausted",
                "Endpoint update sequence is exhausted.");

        var sequence = history.LastUpdateSequence + 1;
        history = history with
        {
            HighestSignedVersion = requested > highest
                ? operation.ProductVersion
                : history.HighestSignedVersion,
            HighestSignedReleaseSha256 = requested >= highest
                ? operation.Release.MsiSha256
                : history.HighestSignedReleaseSha256,
            LastUpdateSequence = sequence
        };
        Current = new EndpointUpdateTransaction(
            1,
            transactionId,
            sequence,
            history.ActiveVersion,
            operation,
            EndpointUpdateTransactionState.Requested,
            preservedState,
            null,
            null,
            0,
            null);
        states.Add(Current.State);
        return Current;
    }

    public EndpointUpdateTransaction Transition(
        EndpointUpdateTransactionState state,
        VerifiedEndpointRelease? verifiedRelease = null,
        StagedEndpointRelease? stagedRelease = null,
        string? errorCode = null)
    {
        var current = Current ?? throw new InvalidOperationException(
            "No endpoint update transaction exists.");
        if (!Allowed(current.State, state))
            throw new InvalidOperationException(
                $"Endpoint update transition {current.State} -> {state} is invalid.");
        Current = current with
        {
            State = state,
            VerifiedRelease = verifiedRelease ?? current.VerifiedRelease,
            StagedRelease = stagedRelease ?? current.StagedRelease,
            ErrorCode = errorCode
        };
        states.Add(state);
        return Current;
    }

    public EndpointUpdateTransaction RecordHealthObservation()
    {
        var current = Current ?? throw new InvalidOperationException(
            "No endpoint update transaction exists.");
        if (current.State != EndpointUpdateTransactionState.HealthGateRunning ||
            current.HealthObservations == int.MaxValue)
            throw new InvalidOperationException(
                "Endpoint health observation cannot be recorded.");
        Current = current with
        {
            HealthObservations = current.HealthObservations + 1
        };
        return Current;
    }

    public EndpointUpdateTransaction CommitKnownGood()
    {
        var current = Current ?? throw new InvalidOperationException(
            "No endpoint update transaction exists.");
        if (current.State != EndpointUpdateTransactionState.HealthGateRunning)
            throw new InvalidOperationException(
                "Known-good history requires a running health gate.");
        Current = current with
        {
            State = EndpointUpdateTransactionState.KnownGoodCommitted,
            ErrorCode = null
        };
        states.Add(Current.State);
        var knownGood = history.KnownGoodVersions
            .Where(value => !string.Equals(
                value.ProductVersion,
                current.Operation.ProductVersion,
                StringComparison.Ordinal))
            .Append(new EndpointKnownGoodVersion(
                current.Operation.ProductVersion,
                current.Operation.Release.MsiSha256,
                current.UpdateSequence))
            .OrderBy(value => value.UpdateSequence)
            .ToArray();
        history = history with
        {
            ActiveVersion = current.Operation.ProductVersion,
            KnownGoodVersions = knownGood
        };
        return Current;
    }

    public EndpointUpdateTransaction CommitRollback(string errorCode)
    {
        var current = Current ?? throw new InvalidOperationException(
            "No endpoint update transaction exists.");
        if (current.State !=
            EndpointUpdateTransactionState.RollbackIntentCommitted ||
            string.IsNullOrWhiteSpace(errorCode) ||
            errorCode.Length > 64)
            throw new InvalidOperationException(
                "Rollback history requires a durable rollback intent.");
        Current = current with
        {
            State = EndpointUpdateTransactionState.RolledBack,
            ErrorCode = errorCode
        };
        states.Add(Current.State);
        history = history with { ActiveVersion = current.PriorVersion };
        return Current;
    }
    private static bool Allowed(
        EndpointUpdateTransactionState current,
        EndpointUpdateTransactionState next) =>
        current == next || (current, next) switch
        {
            (EndpointUpdateTransactionState.Requested,
                EndpointUpdateTransactionState.ReleaseVerified or
                EndpointUpdateTransactionState.Failed) => true,
            (EndpointUpdateTransactionState.ReleaseVerified,
                EndpointUpdateTransactionState.Staged or
                EndpointUpdateTransactionState.Failed) => true,
            (EndpointUpdateTransactionState.Staged,
                EndpointUpdateTransactionState.CompatibilityExpanded or
                EndpointUpdateTransactionState.Failed) => true,
            (EndpointUpdateTransactionState.CompatibilityExpanded,
                EndpointUpdateTransactionState.
                    InstallerHandoffIntentCommitted or
                EndpointUpdateTransactionState.Failed) => true,
            (EndpointUpdateTransactionState.InstallerHandoffIntentCommitted,
                EndpointUpdateTransactionState.InstallerHandoffTriggered or
                EndpointUpdateTransactionState.RollbackIntentCommitted) => true,
            (EndpointUpdateTransactionState.InstallerHandoffTriggered,
                EndpointUpdateTransactionState.InstallerCommitted or
                EndpointUpdateTransactionState.RollbackIntentCommitted) => true,
            (EndpointUpdateTransactionState.InstallerCommitted,
                EndpointUpdateTransactionState.HealthGateRunning or
                EndpointUpdateTransactionState.RollbackIntentCommitted) => true,
            (EndpointUpdateTransactionState.HealthGateRunning,
                EndpointUpdateTransactionState.KnownGoodCommitted or
                EndpointUpdateTransactionState.RollbackIntentCommitted) => true,
            (EndpointUpdateTransactionState.KnownGoodCommitted,
                EndpointUpdateTransactionState.MigrationContracted or
                EndpointUpdateTransactionState.RollbackIntentCommitted) => true,
            (EndpointUpdateTransactionState.MigrationContracted,
                EndpointUpdateTransactionState.Succeeded) => true,
            (EndpointUpdateTransactionState.RollbackIntentCommitted,
                EndpointUpdateTransactionState.RolledBack) => true,
            _ => false
        };

    private static string NormalizeVersion(string value) =>
        Version.TryParse(value, out var version) &&
        version.Build >= 0 && version.Revision < 0
            ? version.ToString(3)
            : throw new ArgumentException(
                "Endpoint active version must have three components.",
                nameof(value));
}

internal sealed class EndpointUpdateCoordinator(
    IEndpointUpdateTransactionStore store,
    IEndpointUpdatePlatform platform,
    IEndpointUpdateBoundaryObserver? boundaryObserver = null,
    int maximumHealthObservations = 6,
    Guid? transactionId = null)
{
    private readonly IEndpointUpdateBoundaryObserver observer =
        boundaryObserver ?? NullEndpointUpdateBoundaryObserver.Instance;
    private readonly Guid? transactionId = transactionId is null
        ? null
        : transactionId != Guid.Empty
            ? transactionId
            : throw new ArgumentException(
                "Endpoint update transaction ID cannot be empty.",
                nameof(transactionId)); private readonly int maximumHealthObservations =
        maximumHealthObservations is >= 1 and <= 120
            ? maximumHealthObservations
            : throw new ArgumentOutOfRangeException(
                nameof(maximumHealthObservations));

    internal async Task<EndpointUpdateResult> ExecuteAsync(
        ActivateEndpointUpdateOperation operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        MaintenanceContract.ValidateOperation(operation);
        if (transactionId is { } requestedTransactionId)
            store.Prepare(requestedTransactionId);
        var transaction = store.Current;
        if (transaction is null)
        {
            var newTransactionId = transactionId ?? Guid.NewGuid();
            var preserved = await platform.CapturePreservedStateAsync(
                    newTransactionId,
                    operation,
                    cancellationToken)
                .ConfigureAwait(false);
            transaction = store.Begin(
                newTransactionId,
                operation,
                preserved);
        }
        else if (transaction.Operation != operation)
        {
            throw new EndpointUpdateException(
                "update_in_progress",
                "A different endpoint update is already pending.");
        }

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            transaction = store.Current ?? throw new InvalidOperationException(
                "Endpoint update transaction disappeared.");
            try
            {
                switch (transaction.State)
                {
                    case EndpointUpdateTransactionState.Requested:
                        {
                            var verified = await platform.VerifyReleaseAsync(
                                    operation,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            transaction = store.Transition(
                                EndpointUpdateTransactionState.ReleaseVerified,
                                verifiedRelease: verified);
                            observer.Reached(EndpointUpdateBoundary.ReleaseVerified);
                            break;
                        }
                    case EndpointUpdateTransactionState.ReleaseVerified:
                        {
                            var staged = await platform.StageImmutableAsync(
                                    transaction,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            transaction = store.Transition(
                                EndpointUpdateTransactionState.Staged,
                                stagedRelease: staged);
                            observer.Reached(EndpointUpdateBoundary.Staged);
                            break;
                        }
                    case EndpointUpdateTransactionState.Staged:
                        await platform.ExpandCompatibilityAsync(
                                transaction,
                                cancellationToken)
                            .ConfigureAwait(false);
                        transaction = store.Transition(
                            EndpointUpdateTransactionState.CompatibilityExpanded);
                        observer.Reached(
                            EndpointUpdateBoundary.CompatibilityExpanded);
                        break;
                    case EndpointUpdateTransactionState.CompatibilityExpanded:
                        await platform.PersistInstallerHandoffAsync(
                                transaction,
                                cancellationToken)
                            .ConfigureAwait(false);
                        transaction = store.Transition(
                            EndpointUpdateTransactionState.
                                InstallerHandoffIntentCommitted);
                        observer.Reached(
                            EndpointUpdateBoundary.
                                InstallerHandoffIntentCommitted);
                        break;
                    case EndpointUpdateTransactionState.
                        InstallerHandoffIntentCommitted:
                        await platform.TriggerInstallerHandoffAsync(
                                transaction,
                                cancellationToken)
                            .ConfigureAwait(false);
                        transaction = store.Transition(
                            EndpointUpdateTransactionState.
                                InstallerHandoffTriggered);
                        observer.Reached(
                            EndpointUpdateBoundary.InstallerHandoffTriggered);
                        break;
                    case EndpointUpdateTransactionState.
                        InstallerHandoffTriggered:
                        var installerOutcome =
                            await platform.ObserveInstallerReceiptAsync(
                                    transaction,
                                    cancellationToken)
                                .ConfigureAwait(false);
                        if (installerOutcome ==
                            EndpointInstallerReceiptOutcome.RolledBack)
                        {
                            transaction = store.Transition(
                                EndpointUpdateTransactionState.
                                    RollbackIntentCommitted,
                                errorCode: "installer_rolled_back");
                            observer.Reached(
                                EndpointUpdateBoundary.RollbackIntentCommitted);
                            await CompleteRollbackAsync(
                                    transaction,
                                    cancellationToken,
                                    installerAlreadyRolledBack: true)
                                .ConfigureAwait(false);
                            throw TerminalError();
                        }
                        transaction = store.Transition(
                            EndpointUpdateTransactionState.InstallerCommitted);
                        observer.Reached(
                            EndpointUpdateBoundary.InstallerCommitted);
                        break;
                    case EndpointUpdateTransactionState.InstallerCommitted:
                        transaction = store.Transition(
                            EndpointUpdateTransactionState.HealthGateRunning);
                        observer.Reached(EndpointUpdateBoundary.HealthGateStarted);
                        break;
                    case EndpointUpdateTransactionState.HealthGateRunning:
                        transaction = await RunHealthGateAsync(
                                transaction,
                                cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    case EndpointUpdateTransactionState.KnownGoodCommitted:
                        await platform.ContractCompatibilityAsync(
                                transaction,
                                cancellationToken)
                            .ConfigureAwait(false);
                        await platform.CleanupPreservationAsync(
                                transaction,
                                cancellationToken)
                            .ConfigureAwait(false);
                        transaction = store.Transition(
                            EndpointUpdateTransactionState.MigrationContracted);
                        observer.Reached(
                            EndpointUpdateBoundary.MigrationContracted);
                        break;
                    case EndpointUpdateTransactionState.MigrationContracted:
                        await platform.AssertPreservedAsync(
                                transaction,
                                cancellationToken)
                            .ConfigureAwait(false);
                        transaction = store.Transition(
                            EndpointUpdateTransactionState.Succeeded);
                        return new EndpointUpdateResult(
                            EndpointUpdateDisposition.Activated,
                            transaction.State,
                            store.History.ActiveVersion,
                            transaction.UpdateSequence);
                    case EndpointUpdateTransactionState.Succeeded:
                        return new EndpointUpdateResult(
                            EndpointUpdateDisposition.Activated,
                            transaction.State,
                            store.History.ActiveVersion,
                            transaction.UpdateSequence);
                    case EndpointUpdateTransactionState.RollbackIntentCommitted:
                        await CompleteRollbackAsync(
                                transaction,
                                cancellationToken,
                                installerAlreadyRolledBack:
                                    transaction.ErrorCode ==
                                    "installer_rolled_back")
                            .ConfigureAwait(false);
                        throw TerminalError();
                    case EndpointUpdateTransactionState.RolledBack:
                    case EndpointUpdateTransactionState.Failed:
                        throw TerminalError();
                    default:
                        throw new InvalidOperationException(
                            "Endpoint update state is unsupported.");
                }
            }
            catch (EndpointUpdateInterruptedException)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (EndpointUpdateException exception)
            {
                await FailOrRollbackAsync(exception, cancellationToken)
                    .ConfigureAwait(false);
                throw;
            }
            catch (Exception exception) when (
                exception is IOException or InvalidDataException or
                InvalidOperationException or UnauthorizedAccessException or
                System.Security.Cryptography.CryptographicException)
            {
                var failure = new EndpointUpdateException(
                    "update_platform_failed",
                    $"Endpoint update platform failed: {exception.GetType().Name}.");
                await FailOrRollbackAsync(failure, cancellationToken)
                    .ConfigureAwait(false);
                throw failure;
            }
        }
    }

    private async Task<EndpointUpdateTransaction> RunHealthGateAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var observation = await platform.ObserveHealthAsync(
                transaction,
                cancellationToken)
            .ConfigureAwait(false);
        transaction = store.RecordHealthObservation();
        switch (observation.Status)
        {
            case EndpointHealthStatus.Healthy:
                await platform.AssertPreservedAsync(
                        transaction,
                        cancellationToken)
                    .ConfigureAwait(false);
                await platform.CommitKnownGoodAsync(
                        transaction,
                        cancellationToken)
                    .ConfigureAwait(false);
                transaction = store.CommitKnownGood();
                observer.Reached(EndpointUpdateBoundary.KnownGoodCommitted);
                return transaction;
            case EndpointHealthStatus.ControlUnavailable
                when transaction.HealthObservations < maximumHealthObservations:
                return transaction;
            case EndpointHealthStatus.ControlUnavailable:
                throw new EndpointUpdateException(
                    "health_timeout",
                    "Control did not authenticate the updated endpoint in time.");
            case EndpointHealthStatus.CrashLoop:
                throw new EndpointUpdateException(
                    "activation_crash_loop",
                    "Updated endpoint entered a crash loop.");
            case EndpointHealthStatus.IdentityMismatch:
                throw new EndpointUpdateException(
                    "health_identity_mismatch",
                    "Updated endpoint reported a different identity.");
            case EndpointHealthStatus.Unhealthy:
                throw new EndpointUpdateException(
                    "health_failed",
                    "Updated endpoint did not pass its bounded health gate.");
            default:
                throw new InvalidOperationException(
                    "Endpoint health status is unsupported.");
        }
    }

    private async Task FailOrRollbackAsync(
        EndpointUpdateException exception,
        CancellationToken cancellationToken)
    {
        var transaction = store.Current ?? throw new InvalidOperationException(
            "Endpoint update transaction disappeared.");
        if (transaction.State is
            EndpointUpdateTransactionState.InstallerHandoffIntentCommitted or
            EndpointUpdateTransactionState.InstallerHandoffTriggered or
            EndpointUpdateTransactionState.InstallerCommitted or
            EndpointUpdateTransactionState.HealthGateRunning or
            EndpointUpdateTransactionState.KnownGoodCommitted or
            EndpointUpdateTransactionState.RollbackIntentCommitted)
        {
            if (transaction.State !=
                EndpointUpdateTransactionState.RollbackIntentCommitted)
                transaction = store.Transition(
                    EndpointUpdateTransactionState.RollbackIntentCommitted,
                    errorCode: exception.Code);
            observer.Reached(EndpointUpdateBoundary.RollbackIntentCommitted);
            await CompleteRollbackAsync(transaction, cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        if (transaction.State is not (
                EndpointUpdateTransactionState.Failed or
                EndpointUpdateTransactionState.RolledBack))
        {
            store.Transition(
                EndpointUpdateTransactionState.Failed,
                errorCode: exception.Code);
            await platform.CleanupPreservationAsync(
                    transaction,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task CompleteRollbackAsync(
        EndpointUpdateTransaction transaction,
        CancellationToken cancellationToken,
        bool installerAlreadyRolledBack = false)
    {
        if (!installerAlreadyRolledBack)
            await platform.RollbackAsync(transaction, cancellationToken)
                .ConfigureAwait(false);
        await platform.AssertPreservedAsync(transaction, cancellationToken)
            .ConfigureAwait(false);
        await platform.CleanupPreservationAsync(
                transaction,
                cancellationToken)
            .ConfigureAwait(false);
        transaction = store.CommitRollback(
            transaction.ErrorCode ?? "update_rolled_back");
        observer.Reached(EndpointUpdateBoundary.RolledBack);
    }

    private EndpointUpdateException TerminalError()
    {
        var transaction = store.Current ?? throw new InvalidOperationException(
            "Endpoint update transaction disappeared.");
        return new EndpointUpdateException(
            transaction.ErrorCode ?? "update_failed",
            transaction.State == EndpointUpdateTransactionState.RolledBack
                ? "Endpoint update failed and the known-good version was restored."
                : "Endpoint update failed before activation.");
    }
}
