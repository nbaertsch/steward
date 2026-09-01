namespace Steward.Maintenance.Windows;

internal sealed record MaintenanceExecutionContext(
    Guid OperationId,
    bool IsRecovery,
    string? Continuation);

internal sealed record MaintenanceExecutionResult(
    MaintenanceOperationStatus Status,
    string? Continuation)
{
    public static MaintenanceExecutionResult Succeeded() =>
        new(MaintenanceOperationStatus.Succeeded, null);

    public static MaintenanceExecutionResult AwaitingReboot(
        string bootIdentity) =>
        new(MaintenanceOperationStatus.AwaitingReboot, bootIdentity);
}

internal interface IMaintenanceOperationExecutor
{
    Task<MaintenanceExecutionResult> ExecuteAsync(
        MaintenanceOperation operation,
        MaintenanceExecutionContext context,
        CancellationToken cancellationToken);
}

internal sealed record HandleKeeperDrainRequest(
    Guid TransactionId,
    Guid ScopeId);

internal interface IHandleKeeperDrainFence
{
    ValueTask<IAsyncDisposable> AcquireAsync(
        HandleKeeperDrainRequest request,
        CancellationToken cancellationToken);
}

internal sealed record MaintenanceRecoverySummary(
    int Attempted,
    int Recovered,
    int Deferred,
    int Failed);
internal sealed class MaintenanceCoordinator(
    MaintenanceRequestAuthenticator authenticator,
    IMaintenanceReplayStore replayStore,
    FileMaintenanceJournal journal,
    IMaintenanceOperationExecutor executor,
    IHandleKeeperDrainFence drainFence)
{
    private readonly SemaphoreSlim executionGate = new(1, 1);

    public Task<MaintenanceResponse> ExecuteAsync(
        AuthenticatedMaintenanceRequest request,
        CancellationToken cancellationToken) =>
        ExecuteCoreAsync(
            request,
            authenticatedSession: false,
            cancellationToken);

    internal Task<MaintenanceResponse> ExecuteSessionAsync(
        AuthenticatedMaintenanceRequest request,
        CancellationToken cancellationToken) =>
        ExecuteCoreAsync(
            request,
            authenticatedSession: true,
            cancellationToken);

    private async Task<MaintenanceResponse> ExecuteCoreAsync(
        AuthenticatedMaintenanceRequest request,
        bool authenticatedSession,
        CancellationToken cancellationToken)
    {
        var authentication = authenticatedSession
            ? authenticator.AuthenticateForSession(request, replayStore)
            : authenticator.Authenticate(request, replayStore);
        await executionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var prior = journal.Get(request.Body.OperationId);
            var entry = journal.Begin(request.Body);
            var isReplay = prior is not null || authentication.IsReplay;
            if (entry.Status is MaintenanceOperationStatus.Succeeded or
                MaintenanceOperationStatus.Failed)
                return Response(request.Body, entry, isIdempotentReplay: true);
            try
            {
                entry = await ExecuteEntryAsync(
                        entry,
                        entry.Status != MaintenanceOperationStatus.Accepted,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (MaintenanceProtocolException exception)
                when (exception.Code is "reboot_not_observed" or
                    "reboot_identity_unverified")
            {
                entry = journal.Get(request.Body.OperationId) ??
                    throw new InvalidOperationException(
                        "Deferred maintenance operation disappeared.");
                return Response(
                    request.Body,
                    entry,
                    isIdempotentReplay: true);
            }
            return Response(request.Body, entry, isReplay);
        }
        finally
        {
            executionGate.Release();
        }
    }

    public async Task<MaintenanceRecoverySummary> RecoverAsync(
        CancellationToken cancellationToken)
    {
        await executionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var attempted = 0;
            var recovered = 0;
            var deferred = 0;
            var failed = 0;
            foreach (var entry in journal.Pending())
            {
                cancellationToken.ThrowIfCancellationRequested();
                attempted++;
                try
                {
                    var result = await ExecuteEntryAsync(
                            entry,
                            isRecovery: true,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (result.Status == MaintenanceOperationStatus.Succeeded)
                        recovered++;
                    else
                        deferred++;
                }
                catch (MaintenanceProtocolException exception)
                    when (exception.Code is "reboot_not_observed" or
                      "reboot_identity_unverified")
                {
                    deferred++;
                }
                catch (MaintenanceProtocolException)
                {
                    failed++;
                }
            }
            return new MaintenanceRecoverySummary(
                attempted,
                recovered,
                deferred,
                failed);
        }
        finally
        {
            executionGate.Release();
        }
    }
    private async Task<MaintenanceJournalEntry> ExecuteEntryAsync(
        MaintenanceJournalEntry entry,
        bool isRecovery,
        CancellationToken cancellationToken)
    {
        var wasAwaitingReboot = entry.Status ==
            MaintenanceOperationStatus.AwaitingReboot;
        IAsyncDisposable? fence = null;
        try
        {
            if (RequiresHandleKeeperDrain(entry.Operation))
                fence = await drainFence.AcquireAsync(
                        new HandleKeeperDrainRequest(
                            entry.OperationId,
                            entry.OperationId),
                        cancellationToken)
                    .ConfigureAwait(false);
            entry = journal.Transition(
                entry.OperationId,
                MaintenanceOperationStatus.Running,
                entry.Continuation);
            var result = await executor.ExecuteAsync(
                    entry.Operation,
                    new MaintenanceExecutionContext(
                        entry.OperationId,
                        isRecovery,
                        entry.Continuation),
                    cancellationToken)
                .ConfigureAwait(false);
            if (result.Status is not (
                    MaintenanceOperationStatus.Succeeded or
                    MaintenanceOperationStatus.AwaitingReboot))
                throw new InvalidOperationException(
                    "Maintenance executor returned an invalid state.");
            return journal.Transition(
                entry.OperationId,
                result.Status,
                result.Continuation);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (MaintenanceProtocolException exception)
            when (wasAwaitingReboot &&
                  exception.Code is "reboot_not_observed" or
                      "reboot_identity_unverified")
        {
            journal.Transition(
                entry.OperationId,
                MaintenanceOperationStatus.AwaitingReboot,
                entry.Continuation);
            throw;
        }
        catch (MaintenanceProtocolException exception)
        {
            journal.Transition(
                entry.OperationId,
                MaintenanceOperationStatus.Failed,
                errorCode: exception.Code);
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or InvalidDataException or
            InvalidOperationException or UnauthorizedAccessException)
        {
            journal.Transition(
                entry.OperationId,
                MaintenanceOperationStatus.Failed,
                errorCode: "operation_failed");
            throw new MaintenanceProtocolException(
                "operation_failed",
                "Maintenance operation failed.");
        }
        finally
        {
            if (fence is not null)
                await fence.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static bool RequiresHandleKeeperDrain(
        MaintenanceOperation operation) =>
        operation is ActivateEndpointUpdateOperation ||
        operation is RepairEndpointOperation
        {
            Target: RepairTarget.HandleKeeperTask
        };

    private static MaintenanceResponse Response(
        MaintenanceRequestBody request,
        MaintenanceJournalEntry entry,
        bool isIdempotentReplay) =>
        new(
            MaintenanceContract.ProtocolVersion,
            request.RequestId,
            request.OperationId,
            entry.Status,
            isIdempotentReplay,
            entry.ErrorCode,
            entry.ErrorCode is null ? null :
                "Maintenance operation did not complete.",
            MaintenanceOperationDigest.Create(request.Operation));
}



