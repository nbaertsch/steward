using Steward.Domain;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;

namespace Steward.DevBox.Tests;

public sealed class DevBoxProviderTests
{
    private static readonly ProviderBinding Binding = new("azure-dev-box", "project", "pool");

    [Fact]
    public async Task DiscoversAndMapsKnownAndUnknownStatesWithoutGuessing()
    {
        var client = new FakeDevBoxClient();
        client.Add(new("one", "one", "Succeeded", "Running"));
        client.Add(new("two", "two", "FutureProvisioning", "FuturePower"));
        var provider = TestProvider.Create(client);

        var values = new List<ProviderResource>();
        await foreach (var value in provider.DiscoverAsync(Binding)) values.Add(value);

        Assert.Equal(ProviderHostStatus.Running, values.Single(x => x.Name == "one").Status);
        var unknown = values.Single(x => x.Name == "two");
        Assert.Equal(ProviderHostStatus.Unknown, unknown.Status);
        Assert.Equal("FutureProvisioning", unknown.Metadata["rawProvisioningState"]);
        Assert.Equal("FuturePower", unknown.Metadata["rawPowerState"]);
    }

    [Fact]
    public async Task EffectsAreIdempotentAndPersistedHandleResumesAfterRestart()
    {
        var client = new FakeDevBoxClient();
        var provider = TestProvider.Create(client);
        var effect = Effect("box");

        var first = await provider.CreateAsync(effect);
        var duplicate = await provider.CreateAsync(effect);
        Assert.Equal(first.Handle, duplicate.Handle);
        Assert.Equal(1, client.Calls["create"]);

        client.Complete(client.LastOperationId);
        var restartedProvider = TestProvider.Create(client);
        var completed = await restartedProvider.ReconcileAsync(first.Handle!);
        Assert.Equal(ProviderOperationStatus.Succeeded, completed.Status);
        Assert.NotNull(completed.Resource);
        Assert.Equal("box", completed.Resource.Name);
        Assert.NotNull(await restartedProvider.InspectAsync(Binding, "box"));
    }

    [Fact]
    public async Task StartStopAndDeleteAreIdempotent()
    {
        var client = new FakeDevBoxClient { CompleteImmediately = true };
        client.Add(new("box", "box", "Succeeded", "Stopped"));
        var provider = TestProvider.Create(client);

        await Twice(provider.StartAsync, Effect("box"));
        await Twice(provider.StopAsync, Effect("box", "stop"));
        await Twice(provider.DeleteAsync, Effect("box", "delete"));

        Assert.Equal(1, client.Calls["start"]);
        Assert.Equal(1, client.Calls["stop"]);
        Assert.Equal(1, client.Calls["delete"]);
    }

    [Fact]
    public async Task ListingAuthorityDoesNotImplyMutationAuthority()
    {
        var client = new FakeDevBoxClient { Capabilities = ProviderCapability.Discover | ProviderCapability.Inspect };
        var result = await TestProvider.Create(client).DeleteAsync(Effect("box"));
        Assert.Equal(ProviderOperationStatus.CapabilityUnavailable, result.Status);
        Assert.Equal(nameof(DomainErrorCode.CapabilityUnavailable), result.ProblemCode);
        Assert.False(client.Calls.ContainsKey("delete"));
    }

    [Fact]
    public async Task RejectsMalformedOrEnvelopeMismatchedHandlesBeforeProviderCall()
    {
        var client = new FakeDevBoxClient();
        var result = await TestProvider.Create(client).CreateAsync(Effect("box"));
        var handle = result.Handle!;
        var payload = TestProvider.Protector().Unprotect(
            handle.OpaqueHandle, handle.OperationId, handle.IdempotencyKey, handle.Provider);
        var attackerProtector = new HmacDevBoxOperationHandleProtector(
            Enumerable.Repeat((byte)0xA5, 32).ToArray());
        var invalid = new[]
        {
            handle with { OperationId = ProviderOperationId.New() },
            handle with { IdempotencyKey = "tampered" },
            handle with { Provider = "other-provider" },
            handle with { OpaqueHandle = handle.OpaqueHandle[..^2] + "!!" },
            handle with
            {
                OpaqueHandle = attackerProtector.Protect(
                    payload.Replace(handle.OperationId.ToString(), ProviderOperationId.New().ToString(), StringComparison.Ordinal),
                    handle.OperationId, handle.IdempotencyKey, handle.Provider)
            },
            handle with
            {
                OpaqueHandle = attackerProtector.Protect(
                    payload.Replace("https://devcenter.invalid", "https://attacker.invalid", StringComparison.Ordinal),
                    handle.OperationId, handle.IdempotencyKey, handle.Provider)
            }
        };

        var restarted = TestProvider.Create(client);
        foreach (var tampered in invalid)
            await Assert.ThrowsAsync<ArgumentException>(() => restarted.ReconcileAsync(tampered));
        Assert.False(client.Calls.ContainsKey("reconcile"));
    }

    [Fact]
    public async Task FailedProviderOperationPreservesLroFailureDetails()
    {
        var client = new FakeDevBoxClient();
        var started = await TestProvider.Create(client).DeleteAsync(Effect("box", "delete"));
        client.Complete(client.LastOperationId, succeed: false);

        var failed = await TestProvider.Create(client).ReconcileAsync(started.Handle!);

        Assert.Equal(ProviderOperationStatus.Failed, failed.Status);
        Assert.Contains("injected provider LRO failure details", failed.Detail);
        Assert.Equal("provider-operation", failed.Metadata!["reconciliationSource"]);
    }

    [Fact]
    public async Task RestartWithoutHandleReissuesOnlyProviderIdempotentEffects()
    {
        var client = new FakeDevBoxClient();
        var create = Effect("box");
        await TestProvider.Create(client).CreateAsync(create);
        await TestProvider.Create(client).CreateAsync(create with
        {
            Attempt = ProviderEffectAttempt.RetryAfterUncertainOutcomeWithoutHandle
        });
        Assert.Equal(2, client.Calls["create"]);

        var start = Effect("box", "start");
        await TestProvider.Create(client).StartAsync(start);
        var rejected = await TestProvider.Create(client).StartAsync(start with
        {
            Attempt = ProviderEffectAttempt.RetryAfterUncertainOutcomeWithoutHandle
        });
        Assert.Equal(ProviderOperationStatus.RequiresReconciliation, rejected.Status);
        Assert.Equal(1, client.Calls["start"]);
    }

    [Fact]
    public async Task OperationStatusRejectsCrossOriginBeforeTransportSend()
    {
        var transport = new FakeOperationTransport();
        var statusClient = new AzurePipelineDevBoxOperationStatusClient(
            transport,
            new Uri("https://tenant.devcenter.azure.com/api/"),
            "/api/operations/");

        await Assert.ThrowsAsync<InvalidOperationException>(() => statusClient.GetStatusAsync(
            "operation-1", "https://attacker.invalid/api/operations/1", default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => statusClient.GetStatusAsync(
            "operation-1", "https://tenant.devcenter.azure.com/other/1", default));
        Assert.Equal(0, transport.Calls);

        var completed = await statusClient.GetStatusAsync(
            "operation-1", "https://tenant.devcenter.azure.com/api/operations/1", default);
        Assert.True(completed.Succeeded);
        Assert.Equal(1, transport.Calls);
    }

    private static async Task Twice(
        Func<ProviderEffect, CancellationToken, Task<ProviderOperationResult>> action,
        ProviderEffect effect)
    {
        await Task.WhenAll(action(effect, default), action(effect, default));
    }

    private static ProviderEffect Effect(string name, string suffix = "create") =>
        new(ProviderOperationId.New(), $"key-{suffix}", Binding, name, HostId.New(), NodeIncarnationId.New());
}
