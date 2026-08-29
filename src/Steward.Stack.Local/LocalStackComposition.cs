using System.Runtime.Versioning;
using Azure.Core;
using Azure.Developer.DevCenter;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Steward.Application;
using Steward.Orchestration;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;
using Steward.PortableState;
using Steward.Transport;

namespace Steward.Stack.Local;

public static class LocalStackComposition
{
    public static IServiceCollection AddStewardLocalStack(
        this IServiceCollection services,
        IConfiguration configuration,
        TokenCredential? devBoxCredential = null)
    {
        var options = new LocalStackOptions();
        configuration.GetSection("Steward:LocalStack").Bind(options);
        var validated = options.Validate();
        services.AddSingleton(validated);
        services.AddSingleton<ILocalTransportFactory, LocalDirectTransportFactory>();
        services.AddSingleton<ITransportDeploymentStatus, LocalTransportDeploymentStatus>();
        var portableMetadata = LocalStackOptions.PortableStateBinding(new
        {
            rootPath = validated.PortableStateRoot
        });
        services.AddSingleton<IPortableObjectStore>(
            new LocalStackContentAddressedObjectStore(portableMetadata));
        services.AddSingleton<PortableObjectUploader>();
        services.AddSingleton<IPortableDirectPeerTransfer>(provider =>
            new PortableObjectStoreDirectPeerTransfer(
                provider.GetRequiredService<IPortableObjectStore>()));

        var devBox = new LocalDevBoxProviderOptions();
        configuration.GetSection("Steward:LocalStack:DevBox").Bind(devBox);
        services.AddSingleton<IHostProviderRegistry>(
            devBox.CreateRegistry(devBoxCredential));
        if (services.Any(x => x.ServiceType == typeof(INodeBootstrapper)) &&
            services.Any(x => x.ServiceType == typeof(IEnrollmentClaimIssuer)) &&
            services.Any(x => x.ServiceType == typeof(SignedNodePackage)))
            services.AddSingleton<IHostRecreateService, DurableDevBoxRecreateService>();
        if (services.Any(x => x.ServiceType == typeof(INodeBootstrapper)) &&
            services.Any(x => x.ServiceType == typeof(IEnrollmentClaimIssuer)) &&
            services.Any(x => x.ServiceType == typeof(IRoutableNodeEndpointIssuer)) &&
            services.Any(x => x.ServiceType == typeof(SignedNodePackage)))
            services.AddSingleton<IProvisionedNodeEnrollmentWorkflow, BootstrapEnrollmentWorkflow>();
        return services;
    }

    [SupportedOSPlatform("windows")]
    public static IServiceCollection AddStewardLocalControlTransport(
        this IServiceCollection services)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "The Local Stack credential vault requires Windows.");
        services.AddSingleton(provider =>
        {
            var options = provider.GetRequiredService<ValidatedLocalStackOptions>();
            return new LocalIdentityGrantStore(
                Path.Combine(options.DataRoot, "identity.db"));
        });
        services.AddSingleton<IProtectedIdentityVault>(provider =>
        {
            var options = provider.GetRequiredService<ValidatedLocalStackOptions>();
            return new DpapiProtectedIdentityVault(
                Path.Combine(options.CredentialVaultRoot, "control"));
        });
        services.AddSingleton<LocalControlIdentityGrantCatalog>();
        services.AddSingleton<IControlIdentityGrantCatalog>(provider =>
            provider.GetRequiredService<LocalControlIdentityGrantCatalog>());
        services.AddSingleton<DirectSessionControlIdentityHandler>();
        services.AddSingleton<LocalPortableReceiveHandler>();
        services.AddSingleton<IAuxiliaryTransportStreamHandler>(provider =>
            provider.GetRequiredService<LocalPortableReceiveHandler>());
        services.AddHostedService<LocalControlSessionWorker>();
        return services;
    }

    public static IServiceCollection AddStewardLocalNodeTransport(
        this IServiceCollection services)
    {
        services.AddSingleton<LocalPortableTransferClient>();
        services.AddSingleton<IAuxiliaryTransportStreamHandler>(provider =>
            provider.GetRequiredService<LocalPortableTransferClient>());
        return services;
    }
}

public sealed class LocalDevBoxProviderOptions
{
    public bool Enabled { get; set; }
    public string Endpoint { get; set; } = string.Empty;
    public string OperationHandleHmacKeyEnvironmentVariable { get; set; } = string.Empty;

    public IHostProviderRegistry CreateRegistry(TokenCredential? injectedCredential = null)
    {
        if (!Enabled) return new HostProviderRegistry([]);
        if (!Uri.TryCreate(Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException(
                "The Local Stack Dev Box endpoint must use HTTPS.");
        var credential = injectedCredential ?? throw new InvalidOperationException(
            "Enabled Dev Box provider composition requires the devbox/default silent WAM credential.");
        var hmacText = Environment.GetEnvironmentVariable(
            OperationHandleHmacKeyEnvironmentVariable);
        byte[] hmac;
        try { hmac = Convert.FromBase64String(hmacText ?? string.Empty); }
        catch (FormatException)
        {
            throw new InvalidOperationException(
                "The Dev Box operation-handle key is invalid.");
        }
        if (hmac.Length < 32)
            throw new InvalidOperationException(
                "The Dev Box operation-handle key must be at least 256 bits.");
        try
        {
            var capabilities = new ProviderCapabilities(
                ProviderCapability.Discover | ProviderCapability.Inspect |
                ProviderCapability.Create | ProviderCapability.Start |
                ProviderCapability.Stop | ProviderCapability.Repair |
                ProviderCapability.Restore | ProviderCapability.Delete |
                ProviderCapability.BootstrapEnroll,
                new Dictionary<ProviderCapability, string>());
            var sdk = new DevBoxesClient(endpoint, credential);
            var client = new AzureSdkDevBoxClient(sdk, endpoint, capabilities);
            var provider = new DevBoxProvider(
                client, new HmacDevBoxOperationHandleProtector(hmac));
            return new HostProviderRegistry([
                new KeyValuePair<string, IHostProvider>("devbox", provider),
                new KeyValuePair<string, IHostProvider>("azure-dev-box", provider)
            ]);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(hmac);
        }
    }

}
