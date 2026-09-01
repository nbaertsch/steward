using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.Maintenance.Windows;
using Steward.Node;
using Steward.Orchestration;
using Steward.Transport;

namespace Steward.Orchestration.Tests;

public sealed class MaintenanceDeliveryTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "steward-maintenance-delivery-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Crash_before_launch_recovers_durable_inbox_after_control_cursor_acceptance()
    {
        var path = Path.Combine(root, "node.db");
        var host = HostId.New();
        var incarnation = NodeIncarnationId.New();
        var request = Request();
        var key = MaintenanceDeliveryKey.Create(request.Body);
        await using (var journal = await OpenAsync(path, incarnation))
        {
            var accepted = await journal.AcceptMaintenanceAsync(
                host,
                incarnation,
                request,
                controlCursor: 17);
            Assert.True(accepted.IsNew);
            Assert.Equal(MaintenanceDeliveryState.Accepted,
                accepted.Delivery.State);
        }

        await using var restarted = await OpenAsync(path, incarnation);
        var pending = Assert.Single(
            await restarted.ReadPendingMaintenanceAsync());
        Assert.Equal(key, pending.Key);
        Assert.Equal(MaintenanceDeliveryState.Accepted, pending.State);
        Assert.Equal(
            17,
            (await restarted.GetStreamCursorsAsync())[StreamKind.Control]);
    }

    [Fact]
    public async Task Crash_after_acceptance_and_reboot_recovers_in_progress_delivery_to_terminal_outbox()
    {
        var path = Path.Combine(root, "node.db");
        var host = HostId.New();
        var incarnation = NodeIncarnationId.New();
        var request = Request();
        var key = MaintenanceDeliveryKey.Create(request.Body);
        await using (var journal = await OpenAsync(path, incarnation))
        {
            await journal.AcceptMaintenanceAsync(
                host, incarnation, request, controlCursor: 1);
            await journal.MarkMaintenanceInProgressAsync(key);
        }

        await using (var rebooted = await OpenAsync(path, incarnation))
        {
            var pending = Assert.Single(
                await rebooted.ReadPendingMaintenanceAsync());
            Assert.Equal(MaintenanceDeliveryState.InProgress, pending.State);
            var replay = await rebooted.AcceptMaintenanceAsync(
                host,
                incarnation,
                request,
                controlCursor: 2);
            Assert.False(replay.IsNew);
            Assert.Equal(
                MaintenanceDeliveryState.InProgress,
                replay.Delivery.State);
            var awaiting = Response(
                key,
                MaintenanceOperationStatus.AwaitingReboot);
            await RecordResultAsync(rebooted, host, incarnation, awaiting);
        }

        await using (var afterReboot = await OpenAsync(path, incarnation))
        {
            Assert.Single(await afterReboot.ReadPendingMaintenanceAsync());
            var succeeded = Response(
                key,
                MaintenanceOperationStatus.Succeeded);
            await RecordResultAsync(
                afterReboot,
                host,
                incarnation,
                succeeded);
        }

        await using var reconnected = await OpenAsync(path, incarnation);
        Assert.Empty(await reconnected.ReadPendingMaintenanceAsync());
        var results = await reconnected.ReadFactsAfterAsync(0);
        Assert.Equal(2, results.Count(fact =>
            fact.FactType == OrchestrationMessageKinds.MaintenanceResult));
    }

    [Fact]
    public async Task Offline_terminal_completion_is_published_exactly_once_after_reconnect()
    {
        var path = Path.Combine(root, "node.db");
        var host = HostId.New();
        var incarnation = NodeIncarnationId.New();
        var request = Request();
        var key = MaintenanceDeliveryKey.Create(request.Body);
        await using var journal = await OpenAsync(path, incarnation);
        await journal.AcceptMaintenanceAsync(
            host, incarnation, request, controlCursor: 4);
        var response = Response(key, MaintenanceOperationStatus.Succeeded);

        var first = await RecordResultAsync(
            journal, host, incarnation, response);
        var replay = await RecordResultAsync(
            journal, host, incarnation, response);

        Assert.True(first);
        Assert.False(replay);
        var terminalReplay = await journal.AcceptMaintenanceAsync(
            host,
            incarnation,
            request,
            controlCursor: 5);
        Assert.False(terminalReplay.IsNew);
        Assert.Equal(
            MaintenanceDeliveryState.Terminal,
            terminalReplay.Delivery.State);
        Assert.Equal(response, terminalReplay.Delivery.LastResult);
        Assert.Single(await journal.ReadFactsAfterAsync(0));
    }

    [Fact]
    public async Task Exact_digest_replay_returns_prior_and_conflicting_request_or_operation_reuse_rejects()
    {
        var path = Path.Combine(root, "node.db");
        var host = HostId.New();
        var incarnation = NodeIncarnationId.New();
        var request = Request();
        await using var journal = await OpenAsync(path, incarnation);

        var accepted = await journal.AcceptMaintenanceAsync(
            host, incarnation, request, controlCursor: 1);
        var replay = await journal.AcceptMaintenanceAsync(
            host, incarnation, request, controlCursor: 2);
        Assert.True(accepted.IsNew);
        Assert.False(replay.IsNew);
        Assert.Equal(accepted.Delivery.Key, replay.Delivery.Key);
        Assert.Equal(
            MaintenanceDeliveryState.Accepted,
            replay.Delivery.State);

        var requestConflict = Request(
            requestId: request.Body.RequestId,
            operationId: Guid.NewGuid(),
            target: RepairTarget.HandleKeeperTask);
        await Assert.ThrowsAsync<IdempotencyConflictException>(() =>
            journal.AcceptMaintenanceAsync(
                host, incarnation, requestConflict, controlCursor: 3));

        var operationConflict = Request(
            requestId: Guid.NewGuid(),
            operationId: request.Body.OperationId,
            target: RepairTarget.HandleKeeperTask);
        await Assert.ThrowsAsync<IdempotencyConflictException>(() =>
            journal.AcceptMaintenanceAsync(
                host, incarnation, operationConflict, controlCursor: 3));
        Assert.Equal(
            2,
            (await journal.GetStreamCursorsAsync())[StreamKind.Control]);
    }

    [Fact]
    public async Task Service_failure_is_correlated_with_request_and_operation_IDs()
    {
        var host = HostId.New();
        var incarnation = NodeIncarnationId.New();
        var request = Request();
        var handler = new NodeMaintenanceCommandHandler(
            host,
            incarnation,
            new FailingForwarder());

        var result = await handler.HandleAsync(
            new LocalMaintenanceRequestMessage(
                1,
                host,
                incarnation,
                request),
            default);

        Assert.Equal(request.Body.RequestId, result.Result.RequestId);
        Assert.Equal(request.Body.OperationId, result.Result.OperationId);
        Assert.Equal(MaintenanceOperationStatus.Failed, result.Result.Status);
        Assert.Equal("local_forward_failed", result.Result.ErrorCode);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private static async Task<NodeJournal> OpenAsync(
        string path,
        NodeIncarnationId incarnation)
    {
        var journal = new NodeJournal(path);
        await journal.InitializeAsync(incarnation, Guid.NewGuid());
        return journal;
    }

    private static AuthenticatedMaintenanceRequest Request(
        Guid? requestId = null,
        Guid? operationId = null,
        RepairTarget target = RepairTarget.RdpDvcEndpointTask) =>
        new(
            new MaintenanceRequestBody(
                MaintenanceContract.ProtocolVersion,
                requestId ?? Guid.NewGuid(),
                operationId ?? Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                new RepairEndpointOperation(1, target)),
            "AA==");

    private static MaintenanceResponse Response(
        MaintenanceDeliveryKey key,
        MaintenanceOperationStatus status) =>
        new(
            MaintenanceContract.ProtocolVersion,
            key.RequestId,
            key.OperationId,
            status,
            false,
            OperationDigest: key.OperationDigest);

    private static Task<bool> RecordResultAsync(
        NodeJournal journal,
        HostId host,
        NodeIncarnationId incarnation,
        MaintenanceResponse response)
    {
        var fact = new LocalMaintenanceResultFact(
            1,
            host,
            incarnation,
            response);
        return journal.RecordMaintenanceResultAsync(
            MaintenanceDeliveryKey.FromResponse(response),
            response,
            OrchestrationMessageKinds.MaintenanceResult,
            JsonSerializer.Serialize(fact, StewardJson.Options),
            DateTimeOffset.UtcNow);
    }

    private sealed class FailingForwarder : ILocalMaintenanceForwarder
    {
        public Task<MaintenanceResponse> ForwardAsync(
            AuthenticatedMaintenanceRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new MaintenanceResponse(
                MaintenanceContract.ProtocolVersion,
                request.Body.RequestId,
                request.Body.OperationId,
                MaintenanceOperationStatus.Failed,
                false,
                "local_forward_failed",
                "Maintenance service rejected the operation.",
                MaintenanceOperationDigest.Create(request.Body.Operation)));
    }
}
