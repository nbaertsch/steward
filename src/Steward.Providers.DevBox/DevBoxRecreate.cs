using System.Security.Cryptography;
using System.Text;
using Steward.Domain;
using Steward.Providers.Abstractions;

namespace Steward.Providers.DevBox;

public enum RecreatePhase
{
    Deleting,
    Creating,
    BootstrappingAndEnrolling,
    Completed,
    Failed
}

public sealed record DevBoxRecreateState(
    ProviderOperationId OperationId,
    string IdempotencyKey,
    ProviderBinding Binding,
    string ResourceName,
    string ProviderResourceId,
    HostId HostId,
    NodeIncarnationId PreviousIncarnationId,
    NodeIncarnationId NewIncarnationId,
    RecreatePhase Phase,
    ProviderOperationHandle? PendingHandle = null,
    string? FailedPhase = null,
    string? FailureDetail = null);

public sealed class DevBoxRecreateCoordinator(IHostProvider provider, INodeBootstrapper bootstrapper)
    : IDurableHostRecreator<DevBoxRecreateState>
{
    public DevBoxRecreateState Begin(
        ProviderOperationId operationId,
        string idempotencyKey,
        ProviderBinding binding,
        string resourceName,
        string providerResourceId,
        DrainRequest drain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerResourceId);
        LifecycleInterlock.BeginDrain(drain);
        drain.Host.TransitionTo(HostLifecycleState.Reimaging);
        return new(operationId, idempotencyKey, binding, resourceName,
            providerResourceId, drain.Host.Id,
            drain.Host.NodeIncarnationId, NodeIncarnationId.New(), RecreatePhase.Deleting);
    }

    public async Task<DevBoxRecreateState> AdvanceAsync(
        DevBoxRecreateState state,
        Host host,
        SignedNodePackage package,
        EnrollmentClaim claim,
        CancellationToken cancellationToken = default)
    {
        Validate(state, host, claim);
        if (state.Phase is RecreatePhase.Completed or RecreatePhase.Failed)
            return state;

        return state.Phase switch
        {
            RecreatePhase.Deleting => await AdvanceProviderPhase(
                state, "delete", RecreatePhase.Creating,
                effect => provider.DeleteAsync(effect, cancellationToken),
                handle => provider.ReconcileAsync(handle, cancellationToken)).ConfigureAwait(false),
            RecreatePhase.Creating => await AdvanceCreateAsync(state, host, cancellationToken).ConfigureAwait(false),
            RecreatePhase.BootstrappingAndEnrolling => await AdvanceBootstrapAsync(state, host, package, claim, cancellationToken).ConfigureAwait(false),
            _ => state
        };
    }

    private async Task<DevBoxRecreateState> AdvanceCreateAsync(
        DevBoxRecreateState state, Host host, CancellationToken cancellationToken)
    {
        var advanced = await AdvanceProviderPhase(
            state, "create", RecreatePhase.BootstrappingAndEnrolling,
            effect => provider.CreateAsync(effect, cancellationToken),
            handle => provider.ReconcileAsync(handle, cancellationToken)).ConfigureAwait(false);
        if (advanced.Phase == RecreatePhase.BootstrappingAndEnrolling && state.Phase != advanced.Phase)
        {
            host.TransitionTo(HostLifecycleState.Bootstrapping);
            host.ReplaceIncarnation(state.NewIncarnationId);
        }
        return advanced;
    }

    private async Task<DevBoxRecreateState> AdvanceBootstrapAsync(
        DevBoxRecreateState state,
        Host host,
        SignedNodePackage package,
        EnrollmentClaim claim,
        CancellationToken cancellationToken)
    {
        ProviderOperationResult result;
        if (state.PendingHandle is null)
        {
            var resource = await provider.InspectAsync(state.Binding, state.ResourceName, cancellationToken).ConfigureAwait(false);
            if (resource is null)
                return Fail(state, "bootstrap/enroll", "Created provider resource cannot be inspected.");
            var request = new BootstrapRequest(
                PhaseId(state.OperationId, "bootstrap"), $"{state.IdempotencyKey}:bootstrap",
                resource, host, package, claim);
            request.Validate(DateTimeOffset.UtcNow);
            result = await bootstrapper.BootstrapAndEnrollAsync(request, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            result = await bootstrapper.ReconcileAsync(state.PendingHandle, cancellationToken).ConfigureAwait(false);
        }

        if (result.Status is ProviderOperationStatus.Failed or ProviderOperationStatus.CapabilityUnavailable)
            return Fail(state, "bootstrap/enroll", result.Detail ?? result.ProblemCode ?? "Bootstrap/enrollment failed.");
        if (result.Status is ProviderOperationStatus.Accepted or ProviderOperationStatus.Running)
            return state with { PendingHandle = result.Handle ?? state.PendingHandle };

        host.TransitionTo(HostLifecycleState.Enrolling);
        host.TransitionTo(HostLifecycleState.Ready);
        return state with { Phase = RecreatePhase.Completed, PendingHandle = null };
    }

    private async Task<DevBoxRecreateState> AdvanceProviderPhase(
        DevBoxRecreateState state,
        string phaseName,
        RecreatePhase next,
        Func<ProviderEffect, Task<ProviderOperationResult>> start,
        Func<ProviderOperationHandle, Task<ProviderOperationResult>> reconcile)
    {
        var result = state.PendingHandle is null
            ? await start(Effect(state, phaseName)).ConfigureAwait(false)
            : await reconcile(state.PendingHandle).ConfigureAwait(false);

        if (result.Status is ProviderOperationStatus.Failed or ProviderOperationStatus.CapabilityUnavailable)
            return Fail(state, phaseName, result.Detail ?? result.ProblemCode ?? $"{phaseName} failed.");
        if (result.Status is ProviderOperationStatus.Accepted or ProviderOperationStatus.Running)
            return state with { PendingHandle = result.Handle ?? state.PendingHandle };
        return state with { Phase = next, PendingHandle = null };
    }

    private static ProviderEffect Effect(DevBoxRecreateState state, string phase) =>
        new(PhaseId(state.OperationId, phase), $"{state.IdempotencyKey}:{phase}", state.Binding,
            state.ResourceName, state.HostId, state.NewIncarnationId);

    private static ProviderOperationId PhaseId(ProviderOperationId root, string phase)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{root}:{phase}"));
        return new ProviderOperationId(new Guid(bytes.AsSpan(0, 16)));
    }

    private static DevBoxRecreateState Fail(DevBoxRecreateState state, string phase, string detail) =>
        state with { Phase = RecreatePhase.Failed, FailedPhase = phase, FailureDetail = detail };

    private static void Validate(DevBoxRecreateState state, Host host, EnrollmentClaim claim)
    {
        if (host.Id != state.HostId)
            throw new InvalidOperationException("Recreate state belongs to a different Host.");
        if (claim.HostId != state.HostId || claim.IncarnationId != state.NewIncarnationId)
            throw new InvalidOperationException("Enrollment claim is not bound to this Host incarnation.");
        if (!string.Equals(
                claim.ExpectedProviderResourceId,
                state.ProviderResourceId,
                StringComparison.Ordinal))
            throw new InvalidOperationException(
                "Enrollment claim is not bound to this provider resource.");
        claim.Validate(DateTimeOffset.UtcNow);
    }
}
