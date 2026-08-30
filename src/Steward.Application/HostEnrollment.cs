using Steward.Domain;
using Steward.Orchestration;
using Steward.Providers.Abstractions;

namespace Steward.Application;

public interface IEnrollmentClaimIssuer
{
    ValueTask<EnrollmentClaim> IssueAsync(
        HostId hostId,
        NodeIncarnationId incarnationId,
        string providerResourceId,
        CancellationToken cancellationToken);
}

public interface IRoutableNodeEndpointIssuer
{
    ValueTask<NodeEndpointRegistration> IssueAsync(
        PoolRegistration pool,
        PoolMember member,
        ProviderResource resource,
        CancellationToken cancellationToken);
}
