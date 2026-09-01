using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using Steward.Maintenance.Windows;
using Steward.Orchestration;

namespace Steward.Node.Host;

internal sealed class NamedPipeLocalMaintenanceForwarder(
    string pipeName,
    TimeSpan timeout,
    string authenticationKeyPath) : ILocalMaintenanceForwarder
{
    public async Task<MaintenanceResponse> ForwardAsync(
        AuthenticatedMaintenanceRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(pipeName) || pipeName.Length > 128 ||
            timeout < TimeSpan.FromSeconds(1) ||
            timeout > TimeSpan.FromMinutes(2) ||
            !Path.IsPathFullyQualified(authenticationKeyPath))
            throw new InvalidOperationException(
                "Local maintenance forwarding configuration is invalid.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        deadline.CancelAfter(timeout);
        await using var pipe = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(
                checked((int)timeout.TotalMilliseconds),
                deadline.Token)
            .ConfigureAwait(false);
        var challenge = await MaintenanceIpcProtocol.ReadChallengeAsync(
                pipe,
                MaintenanceIpcProtocol.AbsoluteMaximumFrameBytes,
                deadline.Token)
            .ConfigureAwait(false);
        var authenticationPath = Path.GetFullPath(authenticationKeyPath);
        if (!File.Exists(authenticationPath) ||
            File.GetAttributes(authenticationPath).HasFlag(
                FileAttributes.ReparsePoint) ||
            new FileInfo(authenticationPath).Length != 32)
            throw new InvalidDataException(
                "Maintenance session authenticator is unavailable.");
        var key = await File.ReadAllBytesAsync(
                authenticationPath,
                deadline.Token)
            .ConfigureAwait(false);
        try
        {
            var proof = MaintenanceSessionAuthenticator.CreateProof(
                challenge,
                request,
                key,
                Environment.ProcessId,
                Process.GetCurrentProcess().SessionId);
            await MaintenanceIpcProtocol.WriteSubmissionAsync(
                    pipe,
                    new MaintenanceIpcSubmission(request, proof),
                    MaintenanceIpcProtocol.AbsoluteMaximumFrameBytes,
                    deadline.Token)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        var response = await MaintenanceIpcProtocol.ReadResponseAsync(
                pipe,
                MaintenanceIpcProtocol.AbsoluteMaximumFrameBytes,
                deadline.Token)
            .ConfigureAwait(false);
        var expectedKey = MaintenanceDeliveryKey.Create(request.Body);
        if (response.RequestId != request.Body.RequestId ||
            response.OperationId != request.Body.OperationId ||
            response.OperationDigest != expectedKey.OperationDigest)
            throw new InvalidDataException(
                "Local maintenance response identity mismatched its request.");
        return response;
    }
}
