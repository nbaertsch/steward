using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Developer.DevCenter;
using Azure.Developer.DevCenter.Models;
using Steward.Providers.Abstractions;

namespace Steward.Providers.DevBox;

public sealed record DevBoxResource(
    string Id,
    string Name,
    string? ProvisioningState,
    string? PowerState,
    string? Error = null);
public sealed record DevBoxLongRunningOperation(
    string Id,
    bool Completed,
    bool Succeeded,
    string? Error = null,
    string? StatusUri = null,
    string ReconciliationSource = "provider-operation",
    DevBoxResource? Resource = null);

public interface IDevBoxOperationStatusClient
{
    Task<DevBoxLongRunningOperation> GetStatusAsync(
        string azureOperationId,
        string statusUri,
        CancellationToken cancellationToken);
}

public interface IDevBoxClient
{
    Task<ProviderCapabilities> DiscoverCapabilitiesAsync(ProviderBinding binding, CancellationToken cancellationToken);
    IAsyncEnumerable<DevBoxResource> ListAsync(ProviderBinding binding, CancellationToken cancellationToken);
    Task<DevBoxResource?> GetAsync(ProviderBinding binding, string name, CancellationToken cancellationToken);
    Task<DevBoxLongRunningOperation> CreateAsync(ProviderBinding binding, string name, CancellationToken cancellationToken);
    Task<DevBoxLongRunningOperation> StartAsync(ProviderBinding binding, string name, CancellationToken cancellationToken);
    Task<DevBoxLongRunningOperation> StopAsync(ProviderBinding binding, string name, CancellationToken cancellationToken);
    Task<DevBoxLongRunningOperation> DeleteAsync(ProviderBinding binding, string name, CancellationToken cancellationToken);
    Task<DevBoxLongRunningOperation> RepairAsync(ProviderBinding binding, string name, CancellationToken cancellationToken);
    Task<DevBoxLongRunningOperation> RestoreAsync(ProviderBinding binding, string name, IReadOnlyDictionary<string, string>? parameters, CancellationToken cancellationToken);
    Task<DevBoxLongRunningOperation> ReconcileAsync(string operationId, string? statusUri, ProviderBinding binding, string name, string operation, CancellationToken cancellationToken);
}

public sealed class AzureSdkDevBoxClient : IDevBoxClient
{
    private readonly DevBoxesClient _client;
    private readonly ProviderCapabilities _capabilities;
    private readonly IDevBoxOperationStatusClient _operationStatusClient;

    public AzureSdkDevBoxClient(
        DevBoxesClient client,
        Uri devCenterEndpoint,
        ProviderCapabilities capabilities,
        string? allowedOperationPathBase = null,
        IDevBoxOperationStatusClient? operationStatusClient = null)
    {
        _client = client;
        _capabilities = capabilities;
        _operationStatusClient = operationStatusClient ??
            new AzurePipelineDevBoxOperationStatusClient(
                new AzurePipelineDevBoxOperationTransport(client.Pipeline),
                devCenterEndpoint,
                allowedOperationPathBase ?? devCenterEndpoint.AbsolutePath);
    }

    public Task<ProviderCapabilities> DiscoverCapabilitiesAsync(ProviderBinding binding, CancellationToken cancellationToken) =>
        Task.FromResult(_capabilities);

    public async IAsyncEnumerable<DevBoxResource> ListAsync(
        ProviderBinding binding,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var box in _client.GetDevBoxesAsync(binding.Project, binding.User, cancellationToken).ConfigureAwait(false))
            yield return Convert(box, binding);
    }

    public async Task<DevBoxResource?> GetAsync(ProviderBinding binding, string name, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _client.GetDevBoxAsync(binding.Project, binding.User, name, cancellationToken).ConfigureAwait(false);
            return Convert(response.Value, binding);
        }
        catch (RequestFailedException exception) when (exception.Status == 404)
        {
            return null;
        }
    }

    public async Task<DevBoxLongRunningOperation> CreateAsync(ProviderBinding binding, string name, CancellationToken cancellationToken)
    {
        var box = new Azure.Developer.DevCenter.Models.DevBox(name, binding.Project) { PoolName = binding.Pool };
        var operation = await _client.CreateDevBoxAsync(WaitUntil.Started, binding.Project, binding.User, box, cancellationToken).ConfigureAwait(false);
        return new(operation.Id, operation.HasCompleted, operation.HasCompleted && operation.HasValue,
            StatusUri: GetStatusUri(operation.GetRawResponse()),
            Resource: operation.HasCompleted && operation.HasValue
                ? Convert(operation.Value, binding)
                : null);
    }

    public async Task<DevBoxLongRunningOperation> StartAsync(ProviderBinding binding, string name, CancellationToken cancellationToken)
    {
        var operation = await _client.StartDevBoxAsync(WaitUntil.Started, binding.Project, binding.User, name, Context(cancellationToken)).ConfigureAwait(false);
        return From(operation);
    }

    public async Task<DevBoxLongRunningOperation> StopAsync(ProviderBinding binding, string name, CancellationToken cancellationToken)
    {
        var operation = await _client.StopDevBoxAsync(WaitUntil.Started, binding.Project, binding.User, name, false, Context(cancellationToken)).ConfigureAwait(false);
        return From(operation);
    }

    public async Task<DevBoxLongRunningOperation> DeleteAsync(ProviderBinding binding, string name, CancellationToken cancellationToken)
    {
        var operation = await _client.DeleteDevBoxAsync(WaitUntil.Started, binding.Project, binding.User, name, Context(cancellationToken)).ConfigureAwait(false);
        return From(operation);
    }

    public Task<DevBoxLongRunningOperation> RepairAsync(ProviderBinding binding, string name, CancellationToken cancellationToken) =>
        throw new NotSupportedException("The 1.0.0 typed client has no repair method.");

    public Task<DevBoxLongRunningOperation> RestoreAsync(ProviderBinding binding, string name, IReadOnlyDictionary<string, string>? parameters, CancellationToken cancellationToken) =>
        throw new NotSupportedException("The 1.0.0 typed client has no restore method.");

    public async Task<DevBoxLongRunningOperation> ReconcileAsync(
        string operationId, string? statusUri, ProviderBinding binding, string name, string operation, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(statusUri))
        {
            var status = await _operationStatusClient.GetStatusAsync(
                operationId,
                statusUri,
                cancellationToken).ConfigureAwait(false);
            if (!status.Completed ||
                !status.Succeeded ||
                operation == "delete")
                return status;
            var completedResource = await GetAsync(
                binding,
                name,
                cancellationToken).ConfigureAwait(false);
            return status with
            {
                Resource = completedResource
                    ?? throw new InvalidDataException(
                        "A successful Dev Box operation has no inspectable resource.")
            };
        }

        // Azure.Developer.DevCenter 1.0.0 has no public operation rehydration API. Resource
        // polling is used only when the initial response supplied no operation-status URI.
        var resource = await GetAsync(binding, name, cancellationToken).ConfigureAwait(false);
        var state = DevBoxStateMapper.Map(resource?.ProvisioningState, resource?.PowerState);
        var completed = operation switch
        {
            "delete" => resource is null,
            "start" => state.Status == ProviderHostStatus.Running,
            "stop" => state.Status == ProviderHostStatus.Stopped,
            "create" => state.Status is ProviderHostStatus.Running or ProviderHostStatus.Stopped,
            _ => false
        };
        var failed = state.Status == ProviderHostStatus.Failed;
        return new(operationId, completed || failed, completed && !failed,
            failed
                ? resource?.Error ?? "Provider resource reports Failed; no operation-status URI was available."
                : null,
            ReconciliationSource: "resource-state-fallback",
            Resource: completed && operation != "delete"
                ? resource
                : null);
    }

    private static DevBoxLongRunningOperation From(Operation operation) =>
        new(operation.Id, operation.HasCompleted, operation.HasCompleted,
            StatusUri: GetStatusUri(operation.GetRawResponse()));

    private static string? GetStatusUri(Response response)
    {
        if (response.Headers.TryGetValue("Operation-Location", out var operationLocation))
            return operationLocation;
        return response.Headers.TryGetValue("Azure-AsyncOperation", out var asyncOperation)
            ? asyncOperation
            : null;
    }

    private static RequestContext Context(CancellationToken cancellationToken) =>
        new() { CancellationToken = cancellationToken };

    private static DevBoxResource Convert(Azure.Developer.DevCenter.Models.DevBox box, ProviderBinding binding) =>
        new($"{binding.Project}/{binding.User}/{box.Name}", box.Name, box.ProvisioningState?.ToString(), box.PowerState?.ToString(),
            box.Error is null ? null : $"{box.Error.Code}: {box.Error.Message}");
}

public sealed record DevBoxOperationHttpResponse(int Status, string ReasonPhrase, bool IsError, string Content);

public interface IDevBoxOperationTransport
{
    Task<DevBoxOperationHttpResponse> GetAsync(Uri uri, CancellationToken cancellationToken);
}

public sealed class AzurePipelineDevBoxOperationTransport(Azure.Core.Pipeline.HttpPipeline pipeline)
    : IDevBoxOperationTransport
{
    public async Task<DevBoxOperationHttpResponse> GetAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var message = pipeline.CreateMessage(new RequestContext { CancellationToken = cancellationToken });
        message.Request.Method = RequestMethod.Get;
        message.Request.Uri.Reset(uri);
        await pipeline.SendAsync(message, cancellationToken).ConfigureAwait(false);
        var response = message.Response;
        return new(response.Status, response.ReasonPhrase, response.IsError, response.Content?.ToString() ?? "");
    }
}

public sealed class AzurePipelineDevBoxOperationStatusClient : IDevBoxOperationStatusClient
{
    private readonly IDevBoxOperationTransport _transport;
    private readonly Uri _allowedOrigin;
    private readonly string _allowedPathBase;

    public AzurePipelineDevBoxOperationStatusClient(
        IDevBoxOperationTransport transport,
        Uri allowedOperationOrigin,
        string allowedOperationPathBase)
    {
        if (!allowedOperationOrigin.IsAbsoluteUri || allowedOperationOrigin.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Allowed Dev Center operation origin must be absolute HTTPS.", nameof(allowedOperationOrigin));
        _transport = transport;
        _allowedOrigin = allowedOperationOrigin;
        _allowedPathBase = NormalizePathBase(allowedOperationPathBase);
    }

    public async Task<DevBoxLongRunningOperation> GetStatusAsync(
        string azureOperationId,
        string statusUri,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(statusUri, UriKind.Absolute, out var uri) ||
            uri.Scheme != _allowedOrigin.Scheme ||
            !string.Equals(uri.IdnHost, _allowedOrigin.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            uri.Port != _allowedOrigin.Port ||
            !uri.AbsolutePath.StartsWith(_allowedPathBase, StringComparison.Ordinal))
            throw new InvalidOperationException("Dev Box operation-status URI is outside the configured Dev Center operation origin.");

        var response = await _transport.GetAsync(uri, cancellationToken).ConfigureAwait(false);
        var content = response.Content;

        if (response.IsError)
        {
            var transient = response.Status is 408 or 429 || response.Status >= 500;
            return new(azureOperationId, !transient, false,
                $"Operation endpoint returned HTTP {response.Status} {response.ReasonPhrase}. {content}",
                statusUri);
        }

        try
        {
            using var document = JsonDocument.Parse(content);
            var root = document.RootElement;
            var status = root.TryGetProperty("status", out var statusValue) ? statusValue.GetString() : null;
            var error = root.TryGetProperty("error", out var errorValue) ? errorValue.GetRawText() : null;
            return status?.ToLowerInvariant() switch
            {
                "succeeded" => new(azureOperationId, true, true, StatusUri: statusUri),
                "failed" or "canceled" or "cancelled" =>
                    new(azureOperationId, true, false, error ?? $"Provider operation ended as {status}.", statusUri),
                _ => new(azureOperationId, false, false, error, statusUri)
            };
        }
        catch (JsonException exception)
        {
            return new(azureOperationId, false, false,
                $"Operation endpoint returned unrecognized status JSON: {exception.Message}", statusUri);
        }
    }

    private static string NormalizePathBase(string path)
    {
        var normalized = string.IsNullOrWhiteSpace(path) ? "/" : path;
        if (!normalized.StartsWith('/'))
            normalized = "/" + normalized;
        return normalized.EndsWith('/') ? normalized : normalized + "/";
    }
}
