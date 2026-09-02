using System.Collections.Concurrent;
using System.Text.Json;
using Azure;
using Steward.Domain;
using Steward.Providers.Abstractions;

namespace Steward.Providers.DevBox;

public sealed record MappedDevBoxState(ProviderHostStatus Status, IReadOnlyDictionary<string, string> Metadata);

public static class DevBoxStateMapper
{
    public static MappedDevBoxState Map(string? provisioning, string? power)
    {
        var metadata = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(provisioning)) metadata["rawProvisioningState"] = provisioning;
        if (!string.IsNullOrWhiteSpace(power)) metadata["rawPowerState"] = power;

        var status = provisioning?.ToLowerInvariant() switch
        {
            "failed" or "canceled" => ProviderHostStatus.Failed,
            "deleting" => ProviderHostStatus.Deleting,
            "creating" or "updating" or "provisioning" or "starting" or "stopping" => ProviderHostStatus.Provisioning,
            "succeeded" or "provisionedwithwarning" => power?.ToLowerInvariant() switch
            {
                "running" => ProviderHostStatus.Running,
                "stopped" or "deallocated" or "poweredoff" or "hibernated" => ProviderHostStatus.Stopped,
                _ => ProviderHostStatus.Unknown
            },
            "notprovisioned" => ProviderHostStatus.Deleted,
            _ => ProviderHostStatus.Unknown
        };
        return new(status, metadata);
    }
}

public sealed class DevBoxProvider(
    IDevBoxClient client,
    IDevBoxOperationHandleProtector handleProtector) : IHostProvider
{
    private readonly ConcurrentDictionary<string, Lazy<Task<ProviderOperationResult>>> _effects = new(StringComparer.Ordinal);

    public Task<ProviderCapabilities> DiscoverCapabilitiesAsync(ProviderBinding binding, CancellationToken cancellationToken = default) =>
        client.DiscoverCapabilitiesAsync(binding, cancellationToken);

    public async IAsyncEnumerable<ProviderResource> DiscoverAsync(
        ProviderBinding binding,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var box in client.ListAsync(binding, cancellationToken).ConfigureAwait(false))
            yield return Convert(box);
    }

    public async Task<ProviderResource?> InspectAsync(ProviderBinding binding, string resourceName, CancellationToken cancellationToken = default)
    {
        var value = await client.GetAsync(binding, resourceName, cancellationToken).ConfigureAwait(false);
        return value is null ? null : Convert(value);
    }

    public Task<ProviderOperationResult> CreateAsync(ProviderEffect effect, CancellationToken cancellationToken = default) =>
        ExecuteAsync(effect, ProviderCapability.Create, "create", (c, e, ct) => c.CreateAsync(e.Binding, e.ResourceName, ct), cancellationToken);

    public Task<ProviderOperationResult> StartAsync(ProviderEffect effect, CancellationToken cancellationToken = default) =>
        ExecuteAsync(effect, ProviderCapability.Start, "start", (c, e, ct) => c.StartAsync(e.Binding, e.ResourceName, ct), cancellationToken);

    public Task<ProviderOperationResult> StopAsync(ProviderEffect effect, CancellationToken cancellationToken = default) =>
        ExecuteAsync(effect, ProviderCapability.Stop, "stop", (c, e, ct) => c.StopAsync(e.Binding, e.ResourceName, ct), cancellationToken);

    public Task<ProviderOperationResult> RepairAsync(ProviderEffect effect, CancellationToken cancellationToken = default) =>
        ExecuteAsync(effect, ProviderCapability.Repair, "repair", (c, e, ct) => c.RepairAsync(e.Binding, e.ResourceName, ct), cancellationToken);

    public Task<ProviderOperationResult> RestoreAsync(ProviderEffect effect, CancellationToken cancellationToken = default) =>
        ExecuteAsync(effect, ProviderCapability.Restore, "restore", (c, e, ct) => c.RestoreAsync(e.Binding, e.ResourceName, e.Parameters, ct), cancellationToken);

    public Task<ProviderOperationResult> DeleteAsync(ProviderEffect effect, CancellationToken cancellationToken = default) =>
        ExecuteAsync(effect, ProviderCapability.Delete, "delete", (c, e, ct) => c.DeleteAsync(e.Binding, e.ResourceName, ct), cancellationToken);

    public async Task<ProviderOperationResult> ReconcileAsync(ProviderOperationHandle handle, CancellationToken cancellationToken = default)
    {
        var payload = DecodeAndValidate(handle);
        var operation = await client.ReconcileAsync(
            payload.AzureOperationId, payload.StatusUri, payload.Binding, payload.Name, payload.Kind, cancellationToken).ConfigureAwait(false);
        return Result(handle, operation);
    }

    private async Task<ProviderOperationResult> ExecuteAsync(
        ProviderEffect effect,
        ProviderCapability capability,
        string kind,
        Func<IDevBoxClient, ProviderEffect, CancellationToken, Task<DevBoxLongRunningOperation>> action,
        CancellationToken cancellationToken)
    {
        var key = $"{effect.OperationId}:{effect.IdempotencyKey}";
        var lazy = _effects.GetOrAdd(key, _ => new Lazy<Task<ProviderOperationResult>>(
            () => ExecuteCoreAsync(effect, capability, kind, action, cancellationToken),
            LazyThreadSafetyMode.ExecutionAndPublication));
        try
        {
            return await lazy.Value.ConfigureAwait(false);
        }
        catch
        {
            _effects.TryRemove(new KeyValuePair<string, Lazy<Task<ProviderOperationResult>>>(key, lazy));
            throw;
        }
    }

    private async Task<ProviderOperationResult> ExecuteCoreAsync(
        ProviderEffect effect,
        ProviderCapability capability,
        string kind,
        Func<IDevBoxClient, ProviderEffect, CancellationToken, Task<DevBoxLongRunningOperation>> action,
        CancellationToken cancellationToken)
    {
        if (effect.Attempt == ProviderEffectAttempt.RetryAfterUncertainOutcomeWithoutHandle &&
            kind is not ("create" or "delete"))
        {
            return new ProviderOperationResult(
                ProviderOperationStatus.RequiresReconciliation,
                null,
                null,
                "RequiresReconciliation",
                $"{kind} cannot be reissued after an uncertain outcome without its persisted operation handle.",
                new Dictionary<string, string> { ["operationId"] = effect.OperationId.ToString(), ["operation"] = kind });
        }

        var capabilities = await client.DiscoverCapabilitiesAsync(effect.Binding, cancellationToken).ConfigureAwait(false);
        if (!capabilities.Supports(capability))
            return ProviderOperationResult.CapabilityUnavailable(effect, capability, $"Dev Box binding does not grant {capability}.");
        try
        {
            var operation = await action(client, effect, cancellationToken).ConfigureAwait(false);
            var payload = new HandlePayload(
                effect.OperationId.ToString(),
                effect.IdempotencyKey,
                "azure-dev-box",
                operation.Id,
                operation.StatusUri,
                effect.Binding,
                effect.ResourceName,
                kind);
            var opaque = handleProtector.Protect(
                JsonSerializer.Serialize(payload), effect.OperationId, effect.IdempotencyKey, "azure-dev-box");
            var handle = new ProviderOperationHandle(effect.OperationId, effect.IdempotencyKey, "azure-dev-box", opaque);
            return Result(handle, operation);
        }
        catch (RequestFailedException exception) when (exception.Status is 401 or 403)
        {
            return ProviderOperationResult.CapabilityUnavailable(effect, capability, "Current identity lacks mutation authority.");
        }
        catch (RequestFailedException exception)
            when (exception.Status == 409 &&
                  string.Equals(
                      exception.ErrorCode,
                      "DevBoxUsageExceeded",
                      StringComparison.Ordinal))
        {
            return new(
                ProviderOperationStatus.Failed,
                null,
                null,
                "ProviderCapacityExceeded",
                "The Dev Box project user capacity limit is exhausted.",
                new Dictionary<string, string>
                {
                    ["operationId"] = effect.OperationId.ToString(),
                    ["operation"] = kind
                });
        }
        catch (NotSupportedException exception)
        {
            return ProviderOperationResult.CapabilityUnavailable(effect, capability, exception.Message);
        }
    }

    private static ProviderOperationResult Result(ProviderOperationHandle handle, DevBoxLongRunningOperation operation) =>
        new(operation.Completed
                ? operation.Succeeded ? ProviderOperationStatus.Succeeded : ProviderOperationStatus.Failed
                : ProviderOperationStatus.Running,
            handle,
            operation.Resource is null ? null : Convert(operation.Resource),
            operation.Succeeded
                ? null
                : operation.Error is null
                    ? null
                    : "ProviderOperationFailed",
            operation.Error,
            new Dictionary<string, string>
            {
                ["providerOperationId"] = operation.Id,
                ["reconciliationSource"] = operation.ReconciliationSource
            });

    private static ProviderResource Convert(DevBoxResource value)
    {
        var mapped = DevBoxStateMapper.Map(value.ProvisioningState, value.PowerState);
        var metadata = mapped.Metadata.ToDictionary();
        if (!string.IsNullOrWhiteSpace(value.Error))
            metadata["providerError"] = value.Error;
        return new(value.Id, value.Name, mapped.Status, metadata);
    }

    private HandlePayload DecodeAndValidate(ProviderOperationHandle handle)
    {
        if (handle.OpaqueHandle.Length is 0 or > 32_768)
            throw new ArgumentException("Malformed Dev Box operation handle.", nameof(handle));
        if (handle.OperationId.Value == Guid.Empty)
            throw new ArgumentException("Dev Box operation handle has an empty Steward operation ID.", nameof(handle));

        HandlePayload payload;
        try
        {
            payload = JsonSerializer.Deserialize<HandlePayload>(
                handleProtector.Unprotect(
                    handle.OpaqueHandle, handle.OperationId, handle.IdempotencyKey, handle.Provider))
                ?? throw new FormatException("Payload is empty.");
        }
        catch (Exception exception) when (exception is FormatException or JsonException or NotSupportedException)
        {
            throw new ArgumentException("Malformed Dev Box operation handle.", nameof(handle), exception);
        }

        if (handle.Provider != "azure-dev-box" ||
            payload.Provider != handle.Provider ||
            !string.Equals(payload.StewardOperationId, handle.OperationId.ToString(), StringComparison.Ordinal) ||
            !string.Equals(payload.IdempotencyKey, handle.IdempotencyKey, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(handle.IdempotencyKey) ||
            string.IsNullOrWhiteSpace(payload.AzureOperationId) ||
            string.IsNullOrWhiteSpace(payload.Name) ||
            payload.Binding is null ||
            payload.Binding.Provider != "azure-dev-box" ||
            string.IsNullOrWhiteSpace(payload.Binding.Project) ||
            string.IsNullOrWhiteSpace(payload.Binding.Pool) ||
            string.IsNullOrWhiteSpace(payload.Binding.User) ||
            (payload.StatusUri is not null &&
             (!Uri.TryCreate(payload.StatusUri, UriKind.Absolute, out var statusUri) ||
              statusUri.Scheme != Uri.UriSchemeHttps)) ||
            payload.Kind is not ("create" or "start" or "stop" or "delete" or "repair" or "restore"))
            throw new ArgumentException("Dev Box operation handle identity does not match its outer envelope.", nameof(handle));

        return payload;
    }

    private sealed record HandlePayload(
        string StewardOperationId,
        string IdempotencyKey,
        string Provider,
        string AzureOperationId,
        string? StatusUri,
        ProviderBinding Binding,
        string Name,
        string Kind);
}
