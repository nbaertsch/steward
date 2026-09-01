using System.Security.Cryptography;
using System.Text;

namespace Steward.Maintenance.Windows;

internal interface IMaintenanceReplayStore
{
    bool TryAccept(
        Guid requestId,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset nowUtc);
}

internal sealed class InMemoryMaintenanceReplayStore : IMaintenanceReplayStore
{
    private readonly int capacity;
    private readonly List<AcceptedReplay> accepted = [];
    private readonly object gate = new();

    private sealed record AcceptedReplay(
        Guid RequestId,
        DateTimeOffset ExpiresAtUtc);

    public InMemoryMaintenanceReplayStore(int capacity)
    {
        if (capacity is < 1 or > 65_536)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        this.capacity = capacity;
    }

    public bool TryAccept(
        Guid requestId,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset nowUtc)
    {
        lock (gate)
        {
            accepted.RemoveAll(entry => entry.ExpiresAtUtc < nowUtc);
            if (accepted.Any(entry => entry.RequestId == requestId))
                return false;
            if (accepted.Count >= capacity)
                throw new MaintenanceProtocolException(
                    "replay_capacity",
                    "Maintenance replay capacity is exhausted.");
            accepted.Add(new AcceptedReplay(requestId, expiresAtUtc));
            return true;
        }
    }
}

internal sealed record MaintenanceAuthenticationResult(bool IsReplay);

internal sealed class MaintenanceRequestAuthenticator
{
    private readonly byte[] publicKey;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan maximumClockSkew;

    public MaintenanceRequestAuthenticator(
        ReadOnlySpan<byte> controlSigningPublicKey,
        TimeProvider timeProvider,
        TimeSpan maximumClockSkew)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (controlSigningPublicKey.Length is < 64 or > 512)
            throw new ArgumentException(
                "Control signing public key size is invalid.",
                nameof(controlSigningPublicKey));
        if (maximumClockSkew < TimeSpan.FromSeconds(30) ||
            maximumClockSkew > TimeSpan.FromMinutes(15))
            throw new ArgumentOutOfRangeException(nameof(maximumClockSkew));
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(controlSigningPublicKey, out var read);
        if (read != controlSigningPublicKey.Length)
            throw new CryptographicException(
                "Control signing public key contains trailing data.");
        publicKey = controlSigningPublicKey.ToArray();
        this.timeProvider = timeProvider;
        this.maximumClockSkew = maximumClockSkew;
    }

    public MaintenanceAuthenticationResult Authenticate(
        AuthenticatedMaintenanceRequest request,
        IMaintenanceReplayStore replayStore) =>
        AuthenticateCore(request, replayStore, requireFreshTimestamp: true);

    public MaintenanceAuthenticationResult AuthenticateForSession(
        AuthenticatedMaintenanceRequest request,
        IMaintenanceReplayStore replayStore) =>
        AuthenticateCore(request, replayStore, requireFreshTimestamp: false);

    private MaintenanceAuthenticationResult AuthenticateCore(
        AuthenticatedMaintenanceRequest request,
        IMaintenanceReplayStore replayStore,
        bool requireFreshTimestamp)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(replayStore);
        MaintenanceContract.Validate(request.Body);
        var now = timeProvider.GetUtcNow();
        if (requireFreshTimestamp &&
            (request.Body.IssuedAtUtc < now - maximumClockSkew ||
             request.Body.IssuedAtUtc > now + maximumClockSkew))
            throw new MaintenanceProtocolException(
                "request_expired",
                "Maintenance request time is outside the accepted window.");

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(request.Signature);
        }
        catch (FormatException)
        {
            throw new MaintenanceProtocolException(
                "authentication_failed",
                "Maintenance request authentication failed.");
        }
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            var canonical = MaintenanceContract.Canonicalize(request.Body);
            try
            {
                if (!key.VerifyData(
                        canonical,
                        signature,
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.Rfc3279DerSequence))
                    throw new MaintenanceProtocolException(
                        "authentication_failed",
                        "Maintenance request authentication failed.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonical);
            }
        }
        catch (CryptographicException)
        {
            throw new MaintenanceProtocolException(
                "authentication_failed",
                "Maintenance request authentication failed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }

        var expiry = requireFreshTimestamp
            ? request.Body.IssuedAtUtc + maximumClockSkew
            : now + maximumClockSkew;
        var accepted = replayStore.TryAccept(
            request.Body.RequestId,
            expiry,
            now);
        return new MaintenanceAuthenticationResult(!accepted);
    }
}
