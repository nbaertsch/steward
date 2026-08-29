using Steward.Domain;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;

namespace Steward.DevBox.Tests;

internal static class TestProvider
{
    private static readonly byte[] Key = Enumerable.Range(1, 32).Select(x => (byte)x).ToArray();

    public static DevBoxProvider Create(IDevBoxClient client) =>
        new(client, new HmacDevBoxOperationHandleProtector(Key));

    public static IDevBoxOperationHandleProtector Protector() =>
        new HmacDevBoxOperationHandleProtector(Key);
}

internal sealed class FakeDevBoxClient : IDevBoxClient
{
    private readonly Dictionary<string, DevBoxResource> _resources = [];
    private readonly Dictionary<string, (string Kind, string Name, bool Complete, bool Succeed, string StatusUri)> _operations = [];
    private int _sequence;

    public ProviderCapability Capabilities { get; set; } =
        ProviderCapability.Discover | ProviderCapability.Inspect | ProviderCapability.Create |
        ProviderCapability.Start | ProviderCapability.Stop | ProviderCapability.Delete |
        ProviderCapability.Recreate | ProviderCapability.BootstrapEnroll;
    public bool CompleteImmediately { get; set; }
    public Dictionary<string, int> Calls { get; } = [];
    public string LastOperationId { get; private set; } = "";

    public void Add(DevBoxResource resource) => _resources[resource.Name] = resource;
    public void Complete(string operationId, bool succeed = true)
    {
        var operation = _operations[operationId];
        _operations[operationId] = (operation.Kind, operation.Name, true, succeed, operation.StatusUri);
        if (!succeed) return;
        if (operation.Kind == "delete") _resources.Remove(operation.Name);
        else if (operation.Kind == "create") _resources[operation.Name] = new(operation.Name, operation.Name, "Succeeded", "Stopped");
        else if (_resources.TryGetValue(operation.Name, out var resource))
            _resources[operation.Name] = resource with { PowerState = operation.Kind == "start" ? "Running" : "Stopped" };
    }

    public Task<ProviderCapabilities> DiscoverCapabilitiesAsync(ProviderBinding binding, CancellationToken cancellationToken) =>
        Task.FromResult(new ProviderCapabilities(Capabilities, new Dictionary<ProviderCapability, string>()));

    public async IAsyncEnumerable<DevBoxResource> ListAsync(ProviderBinding binding, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();
        foreach (var resource in _resources.Values) yield return resource;
    }

    public Task<DevBoxResource?> GetAsync(ProviderBinding binding, string name, CancellationToken cancellationToken) =>
        Task.FromResult(_resources.GetValueOrDefault(name));

    public Task<DevBoxLongRunningOperation> CreateAsync(ProviderBinding binding, string name, CancellationToken cancellationToken) => Start("create", name);
    public Task<DevBoxLongRunningOperation> StartAsync(ProviderBinding binding, string name, CancellationToken cancellationToken) => Start("start", name);
    public Task<DevBoxLongRunningOperation> StopAsync(ProviderBinding binding, string name, CancellationToken cancellationToken) => Start("stop", name);
    public Task<DevBoxLongRunningOperation> DeleteAsync(ProviderBinding binding, string name, CancellationToken cancellationToken) => Start("delete", name);
    public Task<DevBoxLongRunningOperation> RepairAsync(ProviderBinding binding, string name, CancellationToken cancellationToken) => Start("repair", name);
    public Task<DevBoxLongRunningOperation> RestoreAsync(ProviderBinding binding, string name, IReadOnlyDictionary<string, string>? parameters, CancellationToken cancellationToken) => Start("restore", name);

    public Task<DevBoxLongRunningOperation> ReconcileAsync(string operationId, string? statusUri, ProviderBinding binding, string name, string operation, CancellationToken cancellationToken)
    {
        Increment("reconcile");
        var value = _operations[operationId];
        if (statusUri != value.StatusUri)
            throw new InvalidOperationException("Persisted status URI did not round-trip.");
        return Task.FromResult(new DevBoxLongRunningOperation(operationId, value.Complete, value.Complete && value.Succeed,
            value.Complete && !value.Succeed ? "injected provider LRO failure details" : null,
            value.StatusUri,
            Resource: value.Complete &&
                value.Succeed &&
                value.Kind != "delete"
                ? _resources.GetValueOrDefault(value.Name)
                : null));
    }

    private Task<DevBoxLongRunningOperation> Start(string kind, string name)
    {
        Increment(kind);
        LastOperationId = $"{kind}-{++_sequence}";
        var statusUri = $"https://devcenter.invalid/operations/{LastOperationId}";
        _operations[LastOperationId] = (kind, name, CompleteImmediately, true, statusUri);
        if (CompleteImmediately) Complete(LastOperationId);
        return Task.FromResult(new DevBoxLongRunningOperation(
            LastOperationId,
            CompleteImmediately,
            CompleteImmediately,
            StatusUri: statusUri,
            Resource: CompleteImmediately && kind != "delete"
                ? _resources.GetValueOrDefault(name)
                : null));
    }

    private void Increment(string name) => Calls[name] = Calls.GetValueOrDefault(name) + 1;
}

internal sealed class FakeOperationTransport : IDevBoxOperationTransport
{
    public int Calls { get; private set; }
    public DevBoxOperationHttpResponse Response { get; set; } =
        new(200, "OK", false, """{"status":"Succeeded"}""");

    public Task<DevBoxOperationHttpResponse> GetAsync(Uri uri, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(Response);
    }
}

internal sealed class FakeBootstrapper : INodeBootstrapper
{
    public bool Fail { get; set; }
    public int Calls { get; private set; }

    public Task<ProviderOperationResult> BootstrapAndEnrollAsync(BootstrapRequest request, CancellationToken cancellationToken = default)
    {
        Calls++;
        return Task.FromResult(Fail
            ? new ProviderOperationResult(ProviderOperationStatus.Failed, null, request.Resource, "BootstrapFailed", "injected bootstrap failure")
            : new ProviderOperationResult(ProviderOperationStatus.Succeeded, null, request.Resource));
    }

    public Task<ProviderOperationResult> ReconcileAsync(ProviderOperationHandle handle, CancellationToken cancellationToken = default) =>
        Task.FromResult(new ProviderOperationResult(ProviderOperationStatus.Succeeded, handle, null));
}
