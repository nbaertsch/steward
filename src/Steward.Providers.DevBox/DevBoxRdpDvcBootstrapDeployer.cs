using System.Collections.Concurrent;
using System.Text.Json;
using Azure;
using Steward.Domain;
using Steward.Providers.Abstractions;

namespace Steward.Providers.DevBox;

public sealed record DevBoxRdpDvcBootstrapCheckpoint(
    DevBoxRdpDvcBootstrapOperation Operation,
    ProviderOperationHandle Handle,
    int GroupIndex,
    bool Completed);

public interface ISecureDurableDevBoxRdpDvcBootstrapStore
{
    // Implementations must atomically persist and encrypt sensitive task parameters before returning.
    Task<DevBoxRdpDvcBootstrapCheckpoint?> LoadAsync(
        ProviderOperationId operationId,
        string idempotencyKey,
        CancellationToken cancellationToken);

    Task RecordBeforeEffectAsync(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint,
        CancellationToken cancellationToken);

    Task RecordCompletedAsync(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint,
        CancellationToken cancellationToken);
}

public sealed class DevBoxRdpDvcBootstrapDeployer(
    DevBoxCustomizationClient client,
    ISecureDurableDevBoxRdpDvcBootstrapStore store,
    IDevBoxOperationHandleProtector handleProtector)
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates =
        new(StringComparer.Ordinal);

    public async Task<ProviderOperationResult> DeployAsync(
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle,
        CancellationToken cancellationToken = default)
    {
        var operation = DevBoxRdpDvcBootstrapPlan.Create(request, bundle);
        return await LockedAsync(
            request.OperationId,
            request.IdempotencyKey,
            async () =>
            {
                var checkpoint = await store.LoadAsync(
                        request.OperationId,
                        request.IdempotencyKey,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (checkpoint is null)
                {
                    checkpoint = Checkpoint(operation, 0, completed: false);
                    await store.RecordBeforeEffectAsync(
                            checkpoint,
                            cancellationToken)
                        .ConfigureAwait(false);
                    return await AdvanceAsync(
                            checkpoint,
                            probeBeforePut: false,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                ValidateSameIntent(checkpoint.Operation.Intent, operation.Intent);
                return checkpoint.Completed
                    ? Succeeded(checkpoint)
                    : await AdvanceAsync(
                            checkpoint,
                            probeBeforePut: true,
                            cancellationToken)
                        .ConfigureAwait(false);
            }).ConfigureAwait(false);
    }

    public async Task<ProviderOperationResult> ReconcileAsync(
        ProviderOperationHandle handle,
        CancellationToken cancellationToken = default)
    {
        var payload = Decode(handle);
        return await LockedAsync(
            handle.OperationId,
            handle.IdempotencyKey,
            async () =>
            {
                var checkpoint = await store.LoadAsync(
                        handle.OperationId,
                        handle.IdempotencyKey,
                        cancellationToken)
                    .ConfigureAwait(false)
                    ?? throw new InvalidOperationException(
                        "Durable RDP DVC bootstrap intent is unavailable.");
                ValidatePayload(payload, checkpoint);
                return checkpoint.Completed
                    ? Succeeded(checkpoint)
                    : await AdvanceAsync(
                            checkpoint,
                            probeBeforePut: true,
                            cancellationToken)
                        .ConfigureAwait(false);
            }).ConfigureAwait(false);
    }

    private async Task<ProviderOperationResult> AdvanceAsync(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint,
        bool probeBeforePut,
        CancellationToken cancellationToken)
    {
        while (checkpoint.GroupIndex < checkpoint.Operation.Groups.Count)
        {
            var group = checkpoint.Operation.Groups[checkpoint.GroupIndex];
            DevBoxCustomizationGroupResult result;
            if (probeBeforePut)
            {
                try
                {
                    result = await client.GetAsync(
                            checkpoint.Operation.Intent.Project,
                            checkpoint.Operation.Intent.User,
                            checkpoint.Operation.Intent.DevBox,
                            group.Name,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (RequestFailedException exception)
                    when (exception.Status == 404)
                {
                    var applied = await TryApplyAsync(
                            checkpoint.Operation,
                            group,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (applied is null)
                        return Running(checkpoint);
                    return IsFailed(applied.Status)
                        ? Failed(checkpoint)
                        : Running(checkpoint);
                }
            }
            else
            {
                var applied = await TryApplyAsync(
                        checkpoint.Operation,
                        group,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (applied is null)
                    return Running(checkpoint);
                return IsFailed(applied.Status)
                    ? Failed(checkpoint)
                    : Running(checkpoint);
            }

            if (IsFailed(result.Status))
                return Failed(checkpoint);
            if (!IsSucceeded(result.Status))
                return new(
                    ProviderOperationStatus.Running,
                    checkpoint.Handle,
                    null,
                    Metadata: SafeMetadata(checkpoint));

            var nextIndex = checkpoint.GroupIndex + 1;
            if (nextIndex == checkpoint.Operation.Groups.Count)
            {
                checkpoint = Checkpoint(
                    checkpoint.Operation,
                    nextIndex,
                    completed: true);
                await store.RecordCompletedAsync(
                        checkpoint,
                        cancellationToken)
                    .ConfigureAwait(false);
                return Succeeded(checkpoint);
            }

            checkpoint = Checkpoint(
                checkpoint.Operation,
                nextIndex,
                completed: false);
            await store.RecordBeforeEffectAsync(
                    checkpoint,
                    cancellationToken)
                .ConfigureAwait(false);
            probeBeforePut = false;
        }
        throw new InvalidDataException(
            "RDP DVC bootstrap checkpoint is inconsistent.");
    }

    private async Task<DevBoxCustomizationGroupResult?> TryApplyAsync(
        DevBoxRdpDvcBootstrapOperation operation,
        DevBoxRdpDvcBootstrapGroup group,
        CancellationToken cancellationToken)
    {
        try
        {
            return await client.ApplyAsync(
                    operation.Intent.Project,
                    operation.Intent.User,
                    operation.Intent.DevBox,
                    group.Name,
                    group.Tasks,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (RequestFailedException exception)
            when (exception.Status == 409)
        {
            return null;
        }
    }

    private DevBoxRdpDvcBootstrapCheckpoint Checkpoint(
        DevBoxRdpDvcBootstrapOperation operation,
        int groupIndex,
        bool completed)
    {
        var payload = new HandlePayload(
            operation.Intent.OperationId.ToString(),
            operation.Intent.IdempotencyKey,
            DevBoxRdpDvcBootstrapPlan.ProviderName,
            operation.Intent.Fingerprint,
            operation.Intent.Project,
            operation.Intent.User,
            operation.Intent.DevBox,
            operation.Intent.Version,
            operation.Intent.ArchiveSha256,
            groupIndex,
            operation.Groups.Count,
            completed);
        var opaque = handleProtector.Protect(
            JsonSerializer.Serialize(payload),
            operation.Intent.OperationId,
            operation.Intent.IdempotencyKey,
            DevBoxRdpDvcBootstrapPlan.ProviderName);
        return new(
            operation,
            new(
                operation.Intent.OperationId,
                operation.Intent.IdempotencyKey,
                DevBoxRdpDvcBootstrapPlan.ProviderName,
                opaque),
            groupIndex,
            completed);
    }

    private HandlePayload Decode(ProviderOperationHandle handle)
    {
        if (handle.Provider != DevBoxRdpDvcBootstrapPlan.ProviderName ||
            handle.OperationId.Value == Guid.Empty ||
            string.IsNullOrWhiteSpace(handle.IdempotencyKey) ||
            handle.OpaqueHandle.Length is 0 or > 32_768)
            throw new ArgumentException(
                "RDP DVC bootstrap handle is malformed.",
                nameof(handle));
        try
        {
            return JsonSerializer.Deserialize<HandlePayload>(
                       handleProtector.Unprotect(
                           handle.OpaqueHandle,
                           handle.OperationId,
                           handle.IdempotencyKey,
                           handle.Provider))
                   ?? throw new FormatException();
        }
        catch (Exception exception)
            when (exception is JsonException or FormatException)
        {
            throw new ArgumentException(
                "RDP DVC bootstrap handle is malformed.",
                nameof(handle),
                exception);
        }
    }

    private static void ValidatePayload(
        HandlePayload payload,
        DevBoxRdpDvcBootstrapCheckpoint checkpoint)
    {
        var intent = checkpoint.Operation.Intent;
        if (payload.Provider != DevBoxRdpDvcBootstrapPlan.ProviderName ||
            payload.StewardOperationId != intent.OperationId.ToString() ||
            payload.IdempotencyKey != intent.IdempotencyKey ||
            payload.Fingerprint != intent.Fingerprint ||
            payload.Project != intent.Project ||
            payload.User != intent.User ||
            payload.DevBox != intent.DevBox ||
            payload.Version != intent.Version ||
            payload.ArchiveSha256 != intent.ArchiveSha256 ||
            payload.GroupCount != checkpoint.Operation.Groups.Count ||
            payload.GroupIndex > checkpoint.GroupIndex ||
            payload.GroupIndex < 0)
            throw new ArgumentException(
                "RDP DVC bootstrap handle identity does not match durable intent.");
    }

    private static void ValidateSameIntent(
        DevBoxRdpDvcBootstrapIntent durable,
        DevBoxRdpDvcBootstrapIntent requested)
    {
        if (durable.OperationId != requested.OperationId ||
            durable.IdempotencyKey != requested.IdempotencyKey ||
            durable.Fingerprint != requested.Fingerprint)
            throw new InvalidOperationException(
                "RDP DVC bootstrap idempotency key was reused with different intent.");
    }

    private static bool IsSucceeded(string status) =>
        status.Equals("Succeeded", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("Completed", StringComparison.OrdinalIgnoreCase);

    private static bool IsFailed(string status) =>
        status.Equals("Failed", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("Canceled", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("Cancelled", StringComparison.OrdinalIgnoreCase);

    private static bool IsNotStarted(string status) =>
        status.Equals(
            "NotStarted",
            StringComparison.OrdinalIgnoreCase);

    private static ProviderOperationResult Succeeded(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint) =>
        new(
            ProviderOperationStatus.Succeeded,
            checkpoint.Handle,
            null,
            Metadata: SafeMetadata(checkpoint));

    private static ProviderOperationResult Running(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint) =>
        new(
            ProviderOperationStatus.Running,
            checkpoint.Handle,
            null,
            Metadata: SafeMetadata(checkpoint));

    private static ProviderOperationResult Failed(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint) =>
        new(
            ProviderOperationStatus.Failed,
            checkpoint.Handle,
            null,
            "DevBoxCustomizationFailed",
            "Dev Box rejected an RDP DVC bootstrap customization group.",
            SafeMetadata(checkpoint));

    private static IReadOnlyDictionary<string, string> SafeMetadata(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["version"] = checkpoint.Operation.Intent.Version,
            ["archiveSha256"] = checkpoint.Operation.Intent.ArchiveSha256,
            ["groupIndex"] = checkpoint.GroupIndex.ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            ["groupCount"] = checkpoint.Operation.Groups.Count.ToString(
                System.Globalization.CultureInfo.InvariantCulture)
        };

    private async Task<T> LockedAsync<T>(
        ProviderOperationId operationId,
        string idempotencyKey,
        Func<Task<T>> action)
    {
        var key = $"{operationId}:{idempotencyKey}";
        var gate = _gates.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await action().ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private sealed record HandlePayload(
        string StewardOperationId,
        string IdempotencyKey,
        string Provider,
        string Fingerprint,
        string Project,
        string User,
        string DevBox,
        string Version,
        string ArchiveSha256,
        int GroupIndex,
        int GroupCount,
        bool Completed);
}
