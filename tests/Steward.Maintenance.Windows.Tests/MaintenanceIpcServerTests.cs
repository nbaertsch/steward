using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class MaintenanceIpcServerTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "steward-maintenance-ipc-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Disconnected_malformed_client_does_not_consume_the_listener()
    {
        if (!OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(root);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var journalKey = RandomNumberGenerator.GetBytes(32);
        var sessionKey = RandomNumberGenerator.GetBytes(32);
        var coordinator = new MaintenanceCoordinator(
            new MaintenanceRequestAuthenticator(
                signer.ExportSubjectPublicKeyInfo(),
                TimeProvider.System,
                TimeSpan.FromMinutes(5)),
            new InMemoryMaintenanceReplayStore(32),
            new FileMaintenanceJournal(
                Path.Combine(root, "operations.journal"),
                journalKey),
            new SucceedingExecutor(),
            new EmptyDrainFence());
        var pipeName = $"steward-maintenance-{Guid.NewGuid():N}";
        var server = new MaintenancePipeServer(
            new MaintenanceIpcOptions(
                pipeName,
                16 * 1024,
                1,
                TimeSpan.FromSeconds(2)),
            WindowsIdentity.GetCurrent().User!.Value,
            new MaintenanceSessionAuthenticator(
                sessionKey,
                TimeProvider.System,
                TimeSpan.FromSeconds(15)),
            coordinator);
        using var stop = new CancellationTokenSource();
        var running = server.RunAsync(stop.Token);

        await using (var disconnected = new NamedPipeClientStream(
                         ".",
                         pipeName,
                         PipeDirection.InOut,
                         PipeOptions.Asynchronous))
        {
            await disconnected.ConnectAsync(2_000);
            var prefix = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(prefix, 128);
            await disconnected.WriteAsync(prefix);
            await disconnected.FlushAsync();
        }

        var body = new MaintenanceRequestBody(
            MaintenanceContract.ProtocolVersion,
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            new CollectDiagnosticsOperation(
                1,
                DiagnosticKind.MaintenanceAndEndpointHealth,
                4096));
        var request = MaintenanceAuthenticationTests.Sign(body, signer);
        MaintenanceResponse response;
        await using (var client = new NamedPipeClientStream(
                         ".",
                         pipeName,
                         PipeDirection.InOut,
                         PipeOptions.Asynchronous))
        {
            await client.ConnectAsync(2_000);
            var challenge = await MaintenanceIpcProtocol.ReadChallengeAsync(
                client,
                16 * 1024,
                default);
            var proof = MaintenanceSessionAuthenticator.CreateProof(
                challenge,
                request,
                sessionKey,
                Environment.ProcessId,
                Process.GetCurrentProcess().SessionId);
            await MaintenanceIpcProtocol.WriteSubmissionAsync(
                client,
                new MaintenanceIpcSubmission(request, proof),
                16 * 1024,
                default);
            var responsePrefix = new byte[sizeof(int)];
            await client.ReadExactlyAsync(responsePrefix);
            var length = BinaryPrimitives.ReadInt32LittleEndian(responsePrefix);
            var responseBytes = new byte[length];
            await client.ReadExactlyAsync(responseBytes);
            response = JsonSerializer.Deserialize<MaintenanceResponse>(
                responseBytes) ?? throw new InvalidDataException();
        }

        Assert.Equal(MaintenanceOperationStatus.Succeeded, response.Status);
        stop.Cancel();
        await running;
    }

    [Fact]
    public async Task Protocol_failure_response_preserves_request_and_operation_IDs()
    {
        if (!OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(root);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var sessionKey = RandomNumberGenerator.GetBytes(32);
        var coordinator = new MaintenanceCoordinator(
            new MaintenanceRequestAuthenticator(
                signer.ExportSubjectPublicKeyInfo(),
                TimeProvider.System,
                TimeSpan.FromMinutes(5)),
            new InMemoryMaintenanceReplayStore(32),
            new FileMaintenanceJournal(
                Path.Combine(root, "correlated-operations.journal"),
                RandomNumberGenerator.GetBytes(32)),
            new FailingExecutor(),
            new EmptyDrainFence());
        var pipeName = $"steward-maintenance-{Guid.NewGuid():N}";
        var server = new MaintenancePipeServer(
            new MaintenanceIpcOptions(
                pipeName,
                16 * 1024,
                1,
                TimeSpan.FromSeconds(2)),
            WindowsIdentity.GetCurrent().User!.Value,
            new MaintenanceSessionAuthenticator(
                sessionKey,
                TimeProvider.System,
                TimeSpan.FromSeconds(15)),
            coordinator);
        using var stop = new CancellationTokenSource();
        var running = server.RunAsync(stop.Token);
        var body = new MaintenanceRequestBody(
            MaintenanceContract.ProtocolVersion,
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            new CollectDiagnosticsOperation(
                1,
                DiagnosticKind.MaintenanceAndEndpointHealth,
                4096));
        var request = MaintenanceAuthenticationTests.Sign(body, signer);

        MaintenanceResponse response;
        await using (var client = new NamedPipeClientStream(
                         ".",
                         pipeName,
                         PipeDirection.InOut,
                         PipeOptions.Asynchronous))
        {
            await client.ConnectAsync(2_000);
            var challenge = await MaintenanceIpcProtocol.ReadChallengeAsync(
                client,
                16 * 1024,
                default);
            var proof = MaintenanceSessionAuthenticator.CreateProof(
                challenge,
                request,
                sessionKey,
                Environment.ProcessId,
                Process.GetCurrentProcess().SessionId);
            await MaintenanceIpcProtocol.WriteSubmissionAsync(
                client,
                new MaintenanceIpcSubmission(request, proof),
                16 * 1024,
                default);
            response = await MaintenanceIpcProtocol.ReadResponseAsync(
                client,
                16 * 1024,
                default);
        }

        Assert.Equal(body.RequestId, response.RequestId);
        Assert.Equal(body.OperationId, response.OperationId);
        Assert.Equal(MaintenanceOperationStatus.Failed, response.Status);
        Assert.Equal("operation_denied", response.ErrorCode);
        stop.Cancel();
        await running;
    }
    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private sealed class FailingExecutor : IMaintenanceOperationExecutor
    {
        public Task<MaintenanceExecutionResult> ExecuteAsync(
            MaintenanceOperation operation,
            MaintenanceExecutionContext context,
            CancellationToken cancellationToken) =>
            throw new MaintenanceProtocolException(
                "operation_denied",
                "Maintenance operation was denied.");
    }
    private sealed class SucceedingExecutor : IMaintenanceOperationExecutor
    {
        public Task<MaintenanceExecutionResult> ExecuteAsync(
            MaintenanceOperation operation,
            MaintenanceExecutionContext context,
            CancellationToken cancellationToken) =>
            Task.FromResult(MaintenanceExecutionResult.Succeeded());
    }

    private sealed class EmptyDrainFence : IHandleKeeperDrainFence
    {
        public ValueTask<IAsyncDisposable> AcquireAsync(
            HandleKeeperDrainRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<IAsyncDisposable>(new Scope());

        private sealed class Scope : IAsyncDisposable
        {
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}
