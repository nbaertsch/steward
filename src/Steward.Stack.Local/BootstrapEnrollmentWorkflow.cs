using Steward.Application;
using Steward.Orchestration;
using Steward.Providers.Abstractions;

namespace Steward.Stack.Local;

public sealed class BootstrapEnrollmentWorkflow(
    INodeBootstrapper bootstrapper,
    IEnrollmentClaimIssuer claims,
    IRoutableNodeEndpointIssuer endpoints,
    SignedNodePackage package) : IProvisionedNodeEnrollmentWorkflow
{
    public async Task<NodeEndpointRegistration> BootstrapAndEnrollAsync(
        PoolRegistration pool,
        PoolMember member,
        ProviderResource resource,
        CancellationToken cancellationToken)
    {
        var host = member.Host;
        var claim = await claims.IssueAsync(
            host.Id, host.NodeIncarnationId, resource.ProviderResourceId, cancellationToken);
        var operation = Deterministic(member.HostId, "bootstrap");
        var request = new BootstrapRequest(
            operation, $"bootstrap:{member.HostId}:{member.IncarnationId}",
            resource, host, package, claim);
        request.Validate(DateTimeOffset.UtcNow);
        var result = await bootstrapper.BootstrapAndEnrollAsync(request, cancellationToken);
        while (result.Status is ProviderOperationStatus.Accepted or ProviderOperationStatus.Running)
        {
            if (result.Handle is null)
                throw new InvalidDataException("Bootstrap operation did not return a durable handle.");
            result = await bootstrapper.ReconcileAsync(result.Handle, cancellationToken);
        }
        if (result.Status != ProviderOperationStatus.Succeeded)
            throw new InvalidOperationException("bootstrap.enrollment-failed");
        var endpoint = await endpoints.IssueAsync(pool, member, resource, cancellationToken);
        return endpoint.Validate();
    }

    private static Steward.Domain.ProviderOperationId Deterministic(
        Steward.Domain.HostId host, string operation)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{host}:{operation}"));
        return new(new Guid(hash.AsSpan(0, 16)));
    }
}
