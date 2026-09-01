using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;

namespace Steward.ConnectionHost.Windows;

public sealed class ConnectionHostPipeServer(
    ConnectionHostOptions options,
    ConnectionHostOrchestrator orchestrator)
{
    private const int MaximumConcurrentClients = 8;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var listeners = Enumerable.Range(0, MaximumConcurrentClients)
            .Select(_ => RunListenerAsync(cancellationToken))
            .ToArray();
        await Task.WhenAll(listeners).ConfigureAwait(false);
    }

    private async Task RunListenerAsync(
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using var pipe = new NamedPipeServerStream(
                options.PipeName,
                PipeDirection.InOut,
                MaximumConcurrentClients,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                ConnectionHostProtocol.MaximumMessageBytes,
                ConnectionHostProtocol.MaximumMessageBytes);
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (!IsCurrentUser(pipe))
                {
                    await TryWriteDiagnosticAsync(
                            pipe,
                            "CONNECTION_HOST_CLIENT_AUTHENTICATION_FAILED",
                            cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }
                using var timeout =
                    CancellationTokenSource.CreateLinkedTokenSource(
                        cancellationToken);
                timeout.CancelAfter(options.CommandTimeout);
                var command = await ConnectionHostProtocol.ReadCommandAsync(
                        pipe,
                        timeout.Token)
                    .ConfigureAwait(false);
                var response = await orchestrator.ExecuteAsync(
                        command,
                        timeout.Token)
                    .ConfigureAwait(false);
                await ConnectionHostProtocol.WriteResponseAsync(
                        pipe,
                        response,
                        timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
                when (exception is InvalidDataException or JsonException)
            {
                await TryWriteDiagnosticAsync(
                        pipe,
                        "CONNECTION_HOST_PROTOCOL_INVALID",
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                await TryWriteDiagnosticAsync(
                        pipe,
                        "CONNECTION_HOST_CLIENT_AUTHENTICATION_FAILED",
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await TryWriteDiagnosticAsync(
                        pipe,
                        "CONNECTION_HOST_COMMAND_TIMEOUT",
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (IOException)
            {
            }
        }
    }

    private static bool IsCurrentUser(NamedPipeServerStream pipe)
    {
        var serverSid = WindowsIdentity.GetCurrent().User?.Value;
        string? clientSid = null;
        pipe.RunAsClient(
            () => clientSid =
                WindowsIdentity.GetCurrent(true)?.User?.Value);
        return serverSid is not null &&
            string.Equals(
                serverSid,
                clientSid,
                StringComparison.Ordinal);
    }

    private static async Task TryWriteDiagnosticAsync(
        NamedPipeServerStream pipe,
        string code,
        CancellationToken hostCancellation)
    {
        if (!pipe.IsConnected || hostCancellation.IsCancellationRequested)
            return;
        using var timeout = new CancellationTokenSource(
            TimeSpan.FromSeconds(1));
        try
        {
            await ConnectionHostProtocol.WriteResponseAsync(
                    pipe,
                    new(
                        ConnectionHostProtocol.CurrentVersion,
                        "invalid",
                        false,
                        code),
                    timeout.Token)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
            when (exception is IOException or OperationCanceledException)
        {
        }
    }
}

public sealed class ConnectionHostPipeClient(
    string pipeName,
    TimeSpan connectTimeout)
{
    public async Task<ConnectionHostResponse> SendAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken = default)
    {
        using var timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(connectTimeout);
        await using var pipe = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        await ConnectionHostProtocol.WriteCommandAsync(
                pipe,
                command,
                timeout.Token)
            .ConfigureAwait(false);
        return await ConnectionHostProtocol.ReadResponseAsync(
                pipe,
                timeout.Token)
            .ConfigureAwait(false);
    }
}
