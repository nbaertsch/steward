using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Steward.Orchestration;

namespace Steward.Node.Host;

public sealed class HttpTaskIdentityResolver : ITaskIdentityResolver, IDisposable
{
    private readonly HttpClient client;
    private readonly IProtectedIdentityVault vault;
    private readonly TimeProvider timeProvider;

    public HttpTaskIdentityResolver(
        Uri endpoint,
        X509Certificate2 clientCertificate,
        IProtectedIdentityVault vault,
        TimeProvider? timeProvider = null)
    {
        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(clientCertificate);
        client = new(handler) { BaseAddress = endpoint };
        this.vault = vault;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<TaskIdentityLease> ResolveAsync(
        AttemptIdentity identity,
        IReadOnlyList<TaskIdentityGrantReference> grants,
        CancellationToken cancellationToken)
    {
        var handles = new List<Steward.Tasks.Abstractions.ProtectedIdentityHandle>();
        try
        {
            foreach (var grant in grants)
            {
                ValidateBinding(identity, grant);
                using var response = await client.PostAsJsonAsync(
                    $"api/v1/grants/{grant.IdentityGrantId}/redeem",
                    new { grant.Audience, grant.Scopes },
                    cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                    throw new IdentityResolutionException(
                        ProblemCode(response.StatusCode),
                        "The identity broker denied the task-bound grant.");
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
                var root = document.RootElement;
                var token = root.GetProperty("accessToken").GetString();
                var expires = root.GetProperty("expiresAt").GetDateTimeOffset();
                if (string.IsNullOrWhiteSpace(token) || expires <= timeProvider.GetUtcNow() ||
                    expires > grant.ExpiresAt)
                    throw new IdentityResolutionException(
                        "identity.invalid-material",
                        "The identity broker returned invalid or overlong-lived material.");
                handles.Add(vault.Store("identity-broker", token, expires));
            }
            return new(handles, () =>
            {
                foreach (var handle in handles) vault.Remove(handle);
                return ValueTask.CompletedTask;
            });
        }
        catch
        {
            foreach (var handle in handles) vault.Remove(handle);
            throw;
        }
    }

    private static void ValidateBinding(AttemptIdentity identity, TaskIdentityGrantReference grant)
    {
        if (grant.WorkloadId != identity.WorkloadId ||
            grant.TaskId != identity.TaskId ||
            grant.Generation != identity.Generation ||
            grant.HostId != identity.HostId ||
            grant.NodeIncarnationId != identity.NodeIncarnationId)
            throw new IdentityResolutionException(
                "identity.binding-invalid", "Identity grant binding does not match the TaskAttempt.");
    }

    private static string ProblemCode(System.Net.HttpStatusCode status) => status switch
    {
        System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden =>
            "identity.client-denied",
        System.Net.HttpStatusCode.Gone => "identity.expired",
        _ => "identity.renewal-unavailable"
    };

    public void Dispose() => client.Dispose();
}
