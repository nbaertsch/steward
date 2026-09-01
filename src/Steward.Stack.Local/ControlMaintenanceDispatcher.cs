using System.Security.Cryptography;
using System.Text;
using Steward.Domain;
using Steward.Maintenance.Windows;
using Steward.Orchestration;

namespace Steward.Stack.Local;

public sealed record LocalMaintenanceSubmission(
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    Guid RequestId,
    Guid OperationId,
    MaintenanceOperation Operation);

public sealed class ControlMaintenanceDispatcher(
    ValidatedLocalStackOptions options,
    ControlNodeRegistrationStore registrations,
    ControlOrchestrator orchestrator,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider timeProvider =
        timeProvider ?? TimeProvider.System;

    public async Task<LocalMaintenanceRequestMessage> DispatchAsync(
        LocalMaintenanceSubmission submission,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(submission);
        if (submission.HostId == default ||
            submission.NodeIncarnationId == default ||
            submission.RequestId == Guid.Empty ||
            submission.OperationId == Guid.Empty)
            throw new ArgumentException(
                "Local maintenance submission identity is invalid.");
        MaintenanceContract.ValidateOperation(submission.Operation);
        var endpoint = (await registrations.ListAsync(cancellationToken)
                .ConfigureAwait(false))
            .SingleOrDefault(value =>
                value.Enabled &&
                value.HostId == submission.HostId &&
                value.NodeIncarnationId == submission.NodeIncarnationId)
            ?? throw new KeyNotFoundException(
                "The target Node endpoint is not enabled.");
        _ = endpoint;
        var keyPath = options.TransportPrivateKeyPemPath ??
            throw new InvalidOperationException(
                "Control signing authority is unavailable.");
        var body = new MaintenanceRequestBody(
            MaintenanceContract.ProtocolVersion,
            submission.RequestId,
            submission.OperationId,
            timeProvider.GetUtcNow(),
            submission.Operation);
        var canonical = MaintenanceContract.Canonicalize(body);
        var keyBytes = await File.ReadAllBytesAsync(
                keyPath,
                cancellationToken)
            .ConfigureAwait(false);
        var keyCharacters = Encoding.UTF8.GetChars(keyBytes);
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(keyCharacters);
            var signature = key.SignData(
                canonical,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            try
            {
                var request = new AuthenticatedMaintenanceRequest(
                    body,
                    Convert.ToBase64String(signature));
                var message = new LocalMaintenanceRequestMessage(
                    1,
                    submission.HostId,
                    submission.NodeIncarnationId,
                    request);
                await orchestrator.QueueMaintenanceAsync(
                        message,
                        cancellationToken)
                    .ConfigureAwait(false);
                return message;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
            CryptographicOperations.ZeroMemory(keyBytes);
            Array.Clear(keyCharacters);
        }
    }
}
