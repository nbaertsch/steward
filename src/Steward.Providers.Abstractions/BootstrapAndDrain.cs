using Steward.Domain;

namespace Steward.Providers.Abstractions;

public sealed record SignedNodePackage(Uri Source, string ContentSha256, string Signature, string Signer);

public sealed record EnrollmentClaim(
    string Token,
    DateTimeOffset ExpiresAt,
    string ExpectedProviderResourceId,
    HostId HostId,
    NodeIncarnationId IncarnationId)
{
    public void Validate(DateTimeOffset now)
    {
        if (ExpiresAt <= now || ExpiresAt > now.AddMinutes(15))
            throw new ArgumentException("Enrollment claim must be short-lived and unexpired.", nameof(now));
        if (string.IsNullOrWhiteSpace(Token) || string.IsNullOrWhiteSpace(ExpectedProviderResourceId))
            throw new ArgumentException("Enrollment claim is incomplete.");
    }
}

public sealed record BootstrapRequest(
    ProviderOperationId OperationId,
    string IdempotencyKey,
    ProviderResource Resource,
    Host Host,
    SignedNodePackage Package,
    EnrollmentClaim Claim)
{
    public void Validate(DateTimeOffset now)
    {
        Claim.Validate(now);
        if (Claim.HostId != Host.Id || Claim.IncarnationId != Host.NodeIncarnationId ||
            !string.Equals(Claim.ExpectedProviderResourceId, Resource.ProviderResourceId, StringComparison.Ordinal))
            throw new ArgumentException("Enrollment claim binding does not match the provider resource and Host incarnation.");
        if (!Package.Source.IsAbsoluteUri || Package.Source.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrWhiteSpace(Package.ContentSha256) ||
            string.IsNullOrWhiteSpace(Package.Signature) ||
            string.IsNullOrWhiteSpace(Package.Signer))
            throw new ArgumentException("A signed HTTPS node package is required.");
    }
}

public interface INodeBootstrapper
{
    Task<ProviderOperationResult> BootstrapAndEnrollAsync(BootstrapRequest request, CancellationToken cancellationToken = default);
    Task<ProviderOperationResult> ReconcileAsync(ProviderOperationHandle handle, CancellationToken cancellationToken = default);
}

public sealed record DrainRequest(
    Host Host,
    IReadOnlyList<DrainObligation> TaskAndAgentObligations,
    bool Force = false,
    IReadOnlyList<string>? ExactLossManifest = null);

public static class LifecycleInterlock
{
    public static void BeginDrain(DrainRequest request) =>
        request.Host.BeginDrain(request.TaskAndAgentObligations, request.Force, request.ExactLossManifest);
}
