using System.Runtime.Versioning;
using Azure.Core;
using Azure.Identity;
using Azure.Identity.Broker;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensions.Msal;

namespace Steward.DevBox.Windows;

public interface IDevBoxAccountRemover
{
    Task RemoveAsync(DevBoxIdentityContext context, CancellationToken cancellationToken);
}

[SupportedOSPlatform("windows")]
public sealed class MsalWamDevBoxAccountRemover : IDevBoxAccountRemover
{
    public async Task RemoveAsync(DevBoxIdentityContext context, CancellationToken cancellationToken)
    {
        var cacheDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            ".IdentityService");
        Directory.CreateDirectory(cacheDirectory);
        var storage = new StorageCreationPropertiesBuilder(context.CacheName, cacheDirectory).Build();
        var helper = await MsalCacheHelper.CreateAsync(storage).ConfigureAwait(false);
        var app = PublicClientApplicationBuilder
            .Create(context.ClientId)
            .WithAuthority(Authority(context))
            .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows))
            .Build();
        helper.RegisterCache(app.UserTokenCache);
        try
        {
            var accounts = await app.GetAccountsAsync().ConfigureAwait(false);
            foreach (var account in accounts.Where(x =>
                         string.Equals(
                             x.HomeAccountId.Identifier,
                             context.HomeAccountId,
                             StringComparison.Ordinal)))
                await app.RemoveAsync(account).ConfigureAwait(false);

            var remaining = await app.GetAccountsAsync().ConfigureAwait(false);
            if (remaining.Any(x => string.Equals(
                    x.HomeAccountId.Identifier,
                    context.HomeAccountId,
                    StringComparison.Ordinal)))
                throw new InvalidOperationException("WAM did not remove the Steward Dev Box account.");
        }
        finally
        {
            helper.UnregisterCache(app.UserTokenCache);
        }

        var cachePath = Path.Combine(cacheDirectory, context.CacheName);
        if (File.Exists(cachePath))
            File.Delete(cachePath);
        if (File.Exists(cachePath + ".lockfile"))
            File.Delete(cachePath + ".lockfile");
        if (File.Exists(cachePath))
            throw new IOException("The isolated Steward Dev Box token cache could not be removed.");
    }

    private static string Authority(DevBoxIdentityContext context) =>
        Uri.TryCreate(context.Authority, UriKind.Absolute, out _)
            ? context.Authority
            : $"https://{context.Authority}/{context.TenantId}";
}

[SupportedOSPlatform("windows")]
public sealed class DevBoxIdentityService : IDevBoxSilentCredentialSource
{
    private static readonly string[] Scopes = [DevBoxIdentityConstants.Scope];
    private readonly DevBoxIdentityStore _store;
    private readonly IDevBoxAccountRemover _accountRemover;

    public DevBoxIdentityService(
        DevBoxIdentityStore store,
        IDevBoxAccountRemover? accountRemover = null)
    {
        _store = store;
        _accountRemover = accountRemover ?? new MsalWamDevBoxAccountRemover();
    }

    public async Task<DevBoxIdentityStatus> LoginAsync(
        IntPtr parentWindowHandle,
        CancellationToken cancellationToken)
    {
        if (_store.Exists)
            await LogoutAsync(cancellationToken).ConfigureAwait(false);

        var options = new InteractiveBrowserCredentialBrokerOptions(parentWindowHandle)
        {
            UseDefaultBrokerAccount = false,
            TokenCachePersistenceOptions = CacheOptions()
        };
        var credential = new InteractiveBrowserCredential(options);
        var record = await credential.AuthenticateAsync(
            new TokenRequestContext(Scopes), cancellationToken).ConfigureAwait(false);
        if (!Guid.TryParse(record.TenantId, out _))
            throw new AuthenticationFailedException(
                "WAM returned an account without a valid tenant binding.");
        var context = new DevBoxIdentityContext(
            DevBoxIdentityConstants.CurrentVersion,
            DevBoxIdentityConstants.ContextName,
            record.TenantId,
            record.Authority,
            record.ClientId,
            record.HomeAccountId,
            record.Username,
            DevBoxIdentityConstants.CacheName,
            DateTimeOffset.UtcNow);
        await _store.SaveAsync(context, record, cancellationToken).ConfigureAwait(false);
        var token = await credential.GetTokenAsync(
            new TokenRequestContext(Scopes), cancellationToken).ConfigureAwait(false);
        return Status(context, token);
    }

    public async Task<DevBoxIdentityStatus> StatusAsync(CancellationToken cancellationToken)
    {
        try
        {
            var (context, _, token) = await OpenAsync(cancellationToken).ConfigureAwait(false);
            return Status(context, token);
        }
        catch (Exception exception) when (
            exception is InvalidDataException or AuthenticationFailedException or
            CredentialUnavailableException)
        {
            return new(
                DevBoxIdentityConstants.CurrentVersion,
                DevBoxIdentityConstants.ContextName,
                false, null, null, null,
                "Silent authentication failed. Run " +
                "'steward identity devbox login'.");
        }
    }

    public async Task<DevBoxIdentityStatus> LogoutAsync(CancellationToken cancellationToken)
    {
        if (!_store.Exists)
            return new(
                DevBoxIdentityConstants.CurrentVersion,
                DevBoxIdentityConstants.ContextName,
                false, null, null, null, null);

        var (context, _) = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
        await _accountRemover.RemoveAsync(context, cancellationToken).ConfigureAwait(false);
        _store.Delete();
        return new(
            DevBoxIdentityConstants.CurrentVersion,
            DevBoxIdentityConstants.ContextName,
            false, null, null, null, null);
    }

    public async Task<(DevBoxIdentityContext Context, TokenCredential Credential, AccessToken Token)> OpenAsync(
        CancellationToken cancellationToken)
    {
        var (context, record) = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
        var options = new InteractiveBrowserCredentialBrokerOptions(IntPtr.Zero)
        {
            TenantId = context.TenantId,
            ClientId = context.ClientId,
            AuthenticationRecord = record,
            DisableAutomaticAuthentication = true,
            UseDefaultBrokerAccount = false,
            TokenCachePersistenceOptions = CacheOptions()
        };
        var credential = new InteractiveBrowserCredential(options);
        var token = await credential.GetTokenAsync(
            new TokenRequestContext(Scopes), cancellationToken).ConfigureAwait(false);
        return (context, credential, token);
    }

    private static TokenCachePersistenceOptions CacheOptions() =>
        new() { Name = DevBoxIdentityConstants.CacheName };

    private static DevBoxIdentityStatus Status(DevBoxIdentityContext context, AccessToken token) =>
        new(
            DevBoxIdentityConstants.CurrentVersion,
            DevBoxIdentityConstants.ContextName,
            true,
            context.TenantId,
            context.Username,
            token.ExpiresOn,
            null);
}

[SupportedOSPlatform("windows")]
public sealed class DevBoxSilentTokenCredential(IDevBoxSilentCredentialSource source)
    : TokenCredential
{
    public override AccessToken GetToken(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken) =>
        GetTokenAsync(requestContext, cancellationToken).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        if (requestContext.Scopes.Length != 1 ||
            !string.Equals(
                requestContext.Scopes[0],
                DevBoxIdentityConstants.Scope,
                StringComparison.Ordinal))
            throw new AuthenticationFailedException(
                "The devbox/default credential is restricted to the Dev Center audience.");
        var (_, _, token) = await source.OpenAsync(cancellationToken).ConfigureAwait(false);
        return token;
    }
}
