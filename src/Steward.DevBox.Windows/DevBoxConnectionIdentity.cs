using System.Runtime.Versioning;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Azure.Identity.Broker;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensions.Msal;

namespace Steward.DevBox.Windows;

public enum DevBoxConnectionAudience
{
    Windows365EndUser,
    AzureVirtualDesktop
}

public enum DevBoxConnectionIdentityOutcome
{
    Ready,
    InteractionRequired,
    AccountMismatch
}

public static class DevBoxConnectionIdentityConstants
{
    public const int CurrentVersion = 1;
    public const string ContextName = "devbox/connection";
    public const string CacheName = "steward.devbox.connection.msal.cache";
    public const string WindowsAppClientId =
        "4fb5cc57-dbbc-4cdc-9595-748adff5f414";
    public const string WindowsAppBrokerRedirectUri =
        "ms-appx-web://microsoft.aad.brokerplugin/" +
        WindowsAppClientId;
    public const string Windows365EndUserScope =
        "7c0a6aea-533c-458c-9f81-15568f10f6e4/EndUser.Access";
    public const string AzureVirtualDesktopScope =
        "https://www.wvd.microsoft.com/.default";
    public const string AzureVirtualDesktopRedirectUri =
        "https://www.wvd.microsoft.com/webclient";
    public const string WindowsCloudLoginRedirectUri =
        "https://login.microsoftonline.com/common/oauth2/nativeclient";
    public const string WindowsCloudLoginClientId =
        "81ec77fa-8ec7-4901-bf69-f1130545991d";
    public const string AvdClaimsClientId =
        "a85cf173-4192-42f8-81fa-777a763e6e2c";
    public const string AvdClaimsBrokerRedirectUri =
        "ms-appx-web://Microsoft.AAD.BrokerPlugin/" +
        AvdClaimsClientId;

    public static string Scope(DevBoxConnectionAudience audience) =>
        audience switch
        {
            DevBoxConnectionAudience.Windows365EndUser =>
                Windows365EndUserScope,
            DevBoxConnectionAudience.AzureVirtualDesktop =>
                AzureVirtualDesktopScope,
            _ => throw new ArgumentOutOfRangeException(
                nameof(audience),
                audience,
                "The connection audience is unsupported.")
        };
}

public sealed record DevBoxConnectionIdentityContext(
    int Version,
    string Name,
    string TenantId,
    string Authority,
    string ClientId,
    string RedirectUri,
    string HomeAccountId,
    string Username,
    string CacheName,
    IReadOnlyList<string> Scopes,
    DateTimeOffset CreatedAtUtc);

public sealed record DevBoxConnectionIdentityStatus(
    int Version,
    string Name,
    DevBoxConnectionIdentityOutcome Outcome,
    bool Enrolled,
    string? TenantId,
    string? Username,
    DateTimeOffset? TokenExpiresOn,
    string? Problem);

public sealed class DevBoxConnectionIdentityException(
    DevBoxConnectionIdentityOutcome outcome,
    string message,
    Exception? innerException = null)
    : InvalidOperationException(message, innerException)
{
    public DevBoxConnectionIdentityOutcome Outcome { get; } = outcome;
}

public interface IDevBoxConnectionIdentityGate
{
    Task<DevBoxConnectionIdentityStatus> StatusAsync(
        CancellationToken cancellationToken);
}

public sealed record DevBoxConnectionIdentityBinding(
    string TenantId,
    string HomeAccountId,
    string Username,
    string ClientId)
{
    public override string ToString() =>
        "DevBoxConnectionIdentityBinding { Values = [REDACTED] }";
}

public interface IDevBoxConnectionTokenSource
{
    Task<DevBoxConnectionIdentityBinding> GetBindingAsync(
        CancellationToken cancellationToken);

    Task<AccessToken> AcquireTokenAsync(
        DevBoxConnectionAudience audience,
        CancellationToken cancellationToken,
        string? claims = null);

}

internal sealed record DevBoxConnectionBrokerEnrollment(
    AuthenticationRecord Record,
    DateTimeOffset TokenExpiresOn);

internal interface IDevBoxConnectionBroker
{
    Task<DevBoxConnectionBrokerEnrollment> EnrollAsync(
        IntPtr parentWindowHandle,
        DevBoxIdentityContext expectedIdentity,
        IReadOnlyList<DevBoxConnectionAudience> audiences,
        CancellationToken cancellationToken);

    Task<AccessToken> AcquireSilentAsync(
        DevBoxConnectionIdentityContext context,
        AuthenticationRecord record,
        DevBoxConnectionAudience audience,
        string? claims,
        CancellationToken cancellationToken);

}

[SupportedOSPlatform("windows")]
internal sealed class NativeWamDevBoxConnectionAccountRemover :
    IDevBoxAccountRemover
{
    public async Task RemoveAsync(
        DevBoxIdentityContext context,
        CancellationToken cancellationToken)
    {
        var cacheDirectory = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            ".IdentityService");
        Directory.CreateDirectory(cacheDirectory);
        var storage = new StorageCreationPropertiesBuilder(
            context.CacheName,
            cacheDirectory).Build();
        var helper = await MsalCacheHelper.CreateAsync(
            storage).ConfigureAwait(false);
        var app = PublicClientApplicationBuilder
            .Create(DevBoxConnectionIdentityConstants.WindowsAppClientId)
            .WithAuthority(Authority(context))
            .WithRedirectUri(
                DevBoxConnectionIdentityConstants.WindowsAppBrokerRedirectUri)
            .WithBroker(
                new BrokerOptions(BrokerOptions.OperatingSystems.Windows))
            .Build();
        helper.RegisterCache(app.UserTokenCache);
        try
        {
            var accounts = await app.GetAccountsAsync().ConfigureAwait(false);
            foreach (var account in accounts.Where(account =>
                         string.Equals(
                             account.HomeAccountId.Identifier,
                             context.HomeAccountId,
                             StringComparison.Ordinal)))
                await app.RemoveAsync(account).ConfigureAwait(false);
            var remaining = await app.GetAccountsAsync().ConfigureAwait(false);
            if (remaining.Any(account =>
                    string.Equals(
                        account.HomeAccountId.Identifier,
                        context.HomeAccountId,
                        StringComparison.Ordinal)))
                throw new InvalidOperationException(
                    "WAM did not remove the Steward connection account.");
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
            throw new IOException(
                "The isolated Steward connection token cache could not be removed.");
    }

    private static string Authority(DevBoxIdentityContext context) =>
        Uri.TryCreate(context.Authority, UriKind.Absolute, out _)
            ? context.Authority
            : $"https://{context.Authority}/{context.TenantId}";
}

[SupportedOSPlatform("windows")]
internal sealed class NativeWamDevBoxConnectionBroker :
    IDevBoxConnectionBroker
{
    public async Task<DevBoxConnectionBrokerEnrollment> EnrollAsync(
        IntPtr parentWindowHandle,
        DevBoxIdentityContext expectedIdentity,
        IReadOnlyList<DevBoxConnectionAudience> audiences,
        CancellationToken cancellationToken)
    {
        if (audiences.Count == 0)
            throw new ArgumentException(
                "At least one connection audience is required.",
                nameof(audiences));
        var credential = new InteractiveBrowserCredential(
            Options(
                parentWindowHandle,
                expectedIdentity.TenantId,
                authenticationRecord: null,
                disableAutomaticAuthentication: false));
        var first = audiences[0];
        var record = await credential.AuthenticateAsync(
            Request(first),
            cancellationToken).ConfigureAwait(false);
        var expiresOn = (await credential.GetTokenAsync(
            Request(first),
            cancellationToken).ConfigureAwait(false)).ExpiresOn;
        foreach (var audience in audiences.Skip(1))
        {
            var token = await credential.GetTokenAsync(
                Request(audience),
                cancellationToken).ConfigureAwait(false);
            if (token.ExpiresOn < expiresOn)
                expiresOn = token.ExpiresOn;
        }
        return new(record, expiresOn);
    }

    public async Task<AccessToken> AcquireSilentAsync(
        DevBoxConnectionIdentityContext context,
        AuthenticationRecord record,
        DevBoxConnectionAudience audience,
        string? claims,
        CancellationToken cancellationToken)
    {
        var credential = new InteractiveBrowserCredential(
            Options(
                IntPtr.Zero,
                context.TenantId,
                record,
                disableAutomaticAuthentication: true));
        return await credential.GetTokenAsync(
            Request(audience, claims),
            cancellationToken).ConfigureAwait(false);
    }

    private static InteractiveBrowserCredentialBrokerOptions Options(
        IntPtr parentWindowHandle,
        string tenantId,
        AuthenticationRecord? authenticationRecord,
        bool disableAutomaticAuthentication) =>
        new(parentWindowHandle)
        {
            TenantId = tenantId,
            ClientId = DevBoxConnectionIdentityConstants.WindowsAppClientId,
            RedirectUri = new Uri(
                DevBoxConnectionIdentityConstants.WindowsAppBrokerRedirectUri),
            AuthenticationRecord = authenticationRecord,
            DisableAutomaticAuthentication = disableAutomaticAuthentication,
            UseDefaultBrokerAccount = false,
            TokenCachePersistenceOptions = new()
            {
                Name = DevBoxConnectionIdentityConstants.CacheName
            }
        };

    private static TokenRequestContext Request(
        DevBoxConnectionAudience audience,
        string? claims = null) =>
        new(
            [DevBoxConnectionIdentityConstants.Scope(audience)],
            claims: claims);
}

[SupportedOSPlatform("windows")]
public sealed class DevBoxConnectionIdentityService :
    IDevBoxConnectionIdentityGate,
    IDevBoxConnectionTokenSource
{
    private readonly DevBoxIdentityStore defaultStore;
    private readonly DevBoxConnectionIdentityStore connectionStore;
    private readonly IDevBoxConnectionBroker broker;
    private readonly IDevBoxAccountRemover accountRemover;

    public DevBoxConnectionIdentityService(
        DevBoxIdentityStore defaultStore,
        DevBoxConnectionIdentityStore connectionStore)
        : this(
            defaultStore,
            connectionStore,
            new NativeWamDevBoxConnectionBroker(),
            new NativeWamDevBoxConnectionAccountRemover())
    {
    }

    public DevBoxConnectionIdentityService(
        DevBoxConnectionIdentityStore connectionStore)
        : this(new DevBoxIdentityStore(), connectionStore)
    {
    }

    internal DevBoxConnectionIdentityService(
        DevBoxIdentityStore defaultStore,
        DevBoxConnectionIdentityStore connectionStore,
        IDevBoxConnectionBroker broker,
        IDevBoxAccountRemover accountRemover)
    {
        this.defaultStore = defaultStore;
        this.connectionStore = connectionStore;
        this.broker = broker;
        this.accountRemover = accountRemover;
    }

    public Task<DevBoxConnectionIdentityStatus> EnrollAsync(
        IntPtr parentWindowHandle,
        CancellationToken cancellationToken) =>
        EnrollAsync(
            parentWindowHandle,
            includeWindows365EndUser: false,
            cancellationToken);

    public async Task<DevBoxConnectionIdentityStatus> EnrollAsync(
        IntPtr parentWindowHandle,
        bool includeWindows365EndUser,
        CancellationToken cancellationToken)
    {
        var expected = await LoadDefaultAsync(
            cancellationToken).ConfigureAwait(false);
        if (expected is null)
            return Outcome(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "The devbox/default identity must be enrolled first.");

        if (connectionStore.Exists)
            await ClearStoredConnectionAsync(
                cancellationToken).ConfigureAwait(false);

        DevBoxConnectionBrokerEnrollment enrollment;
        try
        {
            var audiences = includeWindows365EndUser
                ? new[]
                {
                    DevBoxConnectionAudience.AzureVirtualDesktop,
                    DevBoxConnectionAudience.Windows365EndUser
                }
                : [DevBoxConnectionAudience.AzureVirtualDesktop];
            enrollment = await broker.EnrollAsync(
                parentWindowHandle,
                expected.Value.Context,
                audiences,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is AuthenticationFailedException or
                CredentialUnavailableException)
        {
            return Outcome(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "Native WAM connection enrollment did not complete.");
        }

        if (enrollment.Record.ClientId !=
            DevBoxConnectionIdentityConstants.WindowsAppClientId)
        {
            await RemoveRecordAsync(
                enrollment.Record,
                cancellationToken).ConfigureAwait(false);
            return Outcome(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "WAM did not use the installed Windows App registration.");
        }
        if (!MatchesDefault(expected.Value.Context, enrollment.Record))
        {
            await RemoveRecordAsync(
                enrollment.Record,
                cancellationToken).ConfigureAwait(false);
            return Outcome(
                DevBoxConnectionIdentityOutcome.AccountMismatch,
                "The Windows App account does not match devbox/default.");
        }

        var scopes = includeWindows365EndUser
            ? new[]
            {
                DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope,
                DevBoxConnectionIdentityConstants.Windows365EndUserScope
            }
            : [DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope];
        var record = enrollment.Record;
        var context = new DevBoxConnectionIdentityContext(
            DevBoxConnectionIdentityConstants.CurrentVersion,
            DevBoxConnectionIdentityConstants.ContextName,
            record.TenantId,
            record.Authority,
            DevBoxConnectionIdentityConstants.WindowsAppClientId,
            DevBoxConnectionIdentityConstants.WindowsAppBrokerRedirectUri,
            record.HomeAccountId,
            record.Username,
            DevBoxConnectionIdentityConstants.CacheName,
            scopes,
            DateTimeOffset.UtcNow);
        await connectionStore.SaveAsync(
            context,
            record,
            cancellationToken).ConfigureAwait(false);
        return Ready(context, enrollment.TokenExpiresOn);
    }

    public async Task<DevBoxConnectionIdentityStatus> StatusAsync(
        CancellationToken cancellationToken)
    {
        var expected = await LoadDefaultAsync(
            cancellationToken).ConfigureAwait(false);
        if (expected is null || !connectionStore.Exists)
            return Outcome(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "Explicit native WAM connection enrollment is required.");

        DevBoxConnectionIdentityContext context;
        AuthenticationRecord record;
        try
        {
            (context, record) = await connectionStore.LoadAsync(
                cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidDataException)
        {
            return Outcome(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "The connection identity context is missing or invalid.");
        }
        if (!MatchesDefault(expected.Value.Context, context) ||
            !MatchesDefault(expected.Value.Context, record))
            return Outcome(
                DevBoxConnectionIdentityOutcome.AccountMismatch,
                "The Windows App account does not match devbox/default.");

        try
        {
            var token = await broker.AcquireSilentAsync(
                context,
                record,
                DevBoxConnectionAudience.AzureVirtualDesktop,
                claims: null,
                cancellationToken).ConfigureAwait(false);
            return Ready(context, token.ExpiresOn);
        }
        catch (Exception exception) when (
            exception is AuthenticationFailedException or
                CredentialUnavailableException)
        {
            return Outcome(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "Silent native WAM authentication requires explicit enrollment.");
        }
    }

    public async Task<DevBoxConnectionIdentityStatus> ClearAsync(
        CancellationToken cancellationToken)
    {
        if (connectionStore.Exists)
            await ClearStoredConnectionAsync(
                cancellationToken).ConfigureAwait(false);
        return Outcome(
            DevBoxConnectionIdentityOutcome.InteractionRequired,
            null);
    }

    public async Task<DevBoxConnectionIdentityBinding> GetBindingAsync(
        CancellationToken cancellationToken)
    {
        var expected = await LoadDefaultAsync(
            cancellationToken).ConfigureAwait(false);
        if (expected is null || !connectionStore.Exists)
            throw new DevBoxConnectionIdentityException(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "Explicit native WAM connection enrollment is required.");
        var (context, record) = await connectionStore.LoadAsync(
            cancellationToken).ConfigureAwait(false);
        if (!MatchesDefault(expected.Value.Context, context) ||
            !MatchesDefault(expected.Value.Context, record))
            throw new DevBoxConnectionIdentityException(
                DevBoxConnectionIdentityOutcome.AccountMismatch,
                "The Windows App account does not match devbox/default.");
        return new(
            context.TenantId,
            context.HomeAccountId,
            context.Username,
            context.ClientId);
    }

    public async Task<AccessToken> AcquireTokenAsync(
        DevBoxConnectionAudience audience,
        CancellationToken cancellationToken,
        string? claims = null)
    {
        var expected = await LoadDefaultAsync(
            cancellationToken).ConfigureAwait(false);
        if (expected is null || !connectionStore.Exists)
            throw new DevBoxConnectionIdentityException(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "Explicit native WAM connection enrollment is required.");
        var (context, record) = await connectionStore.LoadAsync(
            cancellationToken).ConfigureAwait(false);
        if (!MatchesDefault(expected.Value.Context, context) ||
            !MatchesDefault(expected.Value.Context, record))
            throw new DevBoxConnectionIdentityException(
                DevBoxConnectionIdentityOutcome.AccountMismatch,
                "The Windows App account does not match devbox/default.");
        var scope = DevBoxConnectionIdentityConstants.Scope(audience);
        try
        {
            var token = await broker.AcquireSilentAsync(
                context,
                record,
                audience,
                claims,
                cancellationToken).ConfigureAwait(false);
            if (!context.Scopes.Contains(scope, StringComparer.Ordinal))
            {
                context = context with
                {
                    Scopes = context.Scopes
                        .Append(scope)
                        .Distinct(StringComparer.Ordinal)
                        .ToArray()
                };
                await connectionStore.SaveAsync(
                        context,
                        record,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            return token;
        }
        catch (Exception exception) when (
            exception is AuthenticationFailedException or
                CredentialUnavailableException)
        {
            throw new DevBoxConnectionIdentityException(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "Silent native WAM authentication requires explicit enrollment.",
                exception);
        }
    }

    private async Task ClearStoredConnectionAsync(
        CancellationToken cancellationToken)
    {
        var (context, _) = await connectionStore.LoadAsync(
            cancellationToken).ConfigureAwait(false);
        await accountRemover.RemoveAsync(
            AsRemovalContext(context),
            cancellationToken).ConfigureAwait(false);
        connectionStore.Delete();
    }

    private async Task RemoveRecordAsync(
        AuthenticationRecord record,
        CancellationToken cancellationToken)
    {
        var context = new DevBoxConnectionIdentityContext(
            DevBoxConnectionIdentityConstants.CurrentVersion,
            DevBoxConnectionIdentityConstants.ContextName,
            record.TenantId,
            record.Authority,
            record.ClientId,
            DevBoxConnectionIdentityConstants.WindowsAppBrokerRedirectUri,
            record.HomeAccountId,
            record.Username,
            DevBoxConnectionIdentityConstants.CacheName,
            [DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope],
            DateTimeOffset.UtcNow);
        await accountRemover.RemoveAsync(
            AsRemovalContext(context),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<(
        DevBoxIdentityContext Context,
        AuthenticationRecord Record)?> LoadDefaultAsync(
        CancellationToken cancellationToken)
    {
        if (!defaultStore.Exists)
            return null;
        try
        {
            return await defaultStore.LoadAsync(
                cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    private static bool MatchesDefault(
        DevBoxIdentityContext expected,
        DevBoxConnectionIdentityContext actual) =>
        string.Equals(
            expected.TenantId,
            actual.TenantId,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            expected.HomeAccountId,
            actual.HomeAccountId,
            StringComparison.Ordinal);

    private static bool MatchesDefault(
        DevBoxIdentityContext expected,
        AuthenticationRecord actual) =>
        string.Equals(
            expected.TenantId,
            actual.TenantId,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            expected.HomeAccountId,
            actual.HomeAccountId,
            StringComparison.Ordinal);

    private static DevBoxIdentityContext AsRemovalContext(
        DevBoxConnectionIdentityContext context) =>
        new(
            DevBoxIdentityConstants.CurrentVersion,
            context.Name,
            context.TenantId,
            context.Authority,
            context.ClientId,
            context.HomeAccountId,
            context.Username,
            context.CacheName,
            context.CreatedAtUtc);

    private static DevBoxConnectionIdentityStatus Ready(
        DevBoxConnectionIdentityContext context,
        DateTimeOffset expiresOn) =>
        new(
            DevBoxConnectionIdentityConstants.CurrentVersion,
            DevBoxConnectionIdentityConstants.ContextName,
            DevBoxConnectionIdentityOutcome.Ready,
            true,
            context.TenantId,
            context.Username,
            expiresOn,
            null);

    private static DevBoxConnectionIdentityStatus Outcome(
        DevBoxConnectionIdentityOutcome outcome,
        string? problem) =>
        new(
            DevBoxConnectionIdentityConstants.CurrentVersion,
            DevBoxConnectionIdentityConstants.ContextName,
            outcome,
            false,
            null,
            null,
            null,
            problem);
}

[SupportedOSPlatform("windows")]
public sealed class DevBoxConnectionIdentityStore
{
    private const string ContextFileName = "context.v1.json";
    private const string RecordFileName = "authentication-record.v1.json";
    private readonly string directory;
    private readonly JsonSerializerOptions json =
        new(JsonSerializerDefaults.Web);

    public DevBoxConnectionIdentityStore(string? directory = null)
    {
        var selected = directory ?? Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "Steward",
            "identity",
            "devbox",
            "connection");
        if (!Path.IsPathFullyQualified(selected))
            throw new ArgumentException(
                "The Dev Box connection identity path must be absolute.",
                nameof(directory));
        this.directory = Path.GetFullPath(selected);
        DevBoxIdentityStorageSecurity.PrepareDirectory(this.directory);
    }

    public bool Exists => File.Exists(ContextPath);

    public async Task SaveAsync(
        DevBoxConnectionIdentityContext context,
        AuthenticationRecord record,
        CancellationToken cancellationToken)
    {
        Validate(context);
        ValidateRecord(context, record);
        DevBoxIdentityStorageSecurity.EnsureSafeDirectory(directory);
        var recordBytes = await SerializeRecordAsync(
            record,
            cancellationToken).ConfigureAwait(false);
        var contextBytes = JsonSerializer.SerializeToUtf8Bytes(context, json);
        await AtomicWriteAsync(
            RecordPath,
            recordBytes,
            cancellationToken).ConfigureAwait(false);
        await AtomicWriteAsync(
            ContextPath,
            contextBytes,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<(
        DevBoxConnectionIdentityContext Context,
        AuthenticationRecord Record)> LoadAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            DevBoxIdentityStorageSecurity.EnsureSafeDirectory(directory);
            if (!DevBoxIdentityStorageSecurity.IsSafeRegularFile(ContextPath) ||
                !DevBoxIdentityStorageSecurity.IsSafeRegularFile(RecordPath))
                throw new InvalidDataException(
                    "The devbox/connection identity context is missing or unsafe.");
            var contextBytes = await File.ReadAllBytesAsync(
                ContextPath,
                cancellationToken).ConfigureAwait(false);
            var recordBytes = await File.ReadAllBytesAsync(
                RecordPath,
                cancellationToken).ConfigureAwait(false);
            var context =
                JsonSerializer.Deserialize<DevBoxConnectionIdentityContext>(
                    contextBytes,
                    json)
                ?? throw new InvalidDataException(
                    "The Dev Box connection identity context is empty.");
            Validate(context);
            await using var stream = new MemoryStream(
                recordBytes,
                writable: false);
            var record = await AuthenticationRecord.DeserializeAsync(
                stream,
                cancellationToken).ConfigureAwait(false);
            ValidateRecord(context, record);
            return (context, record);
        }
        catch (FileNotFoundException exception)
        {
            throw new InvalidDataException(
                "The devbox/connection identity context is missing.",
                exception);
        }
        catch (DirectoryNotFoundException exception)
        {
            throw new InvalidDataException(
                "The devbox/connection identity context is missing.",
                exception);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "The Dev Box connection identity context is corrupt.",
                exception);
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidDataException(
                "The Dev Box connection authentication record is unsupported.",
                exception);
        }
    }

    public void Delete()
    {
        DevBoxIdentityStorageSecurity.EnsureSafeDirectory(directory);
        foreach (var path in new[] { ContextPath, RecordPath })
        {
            if (!File.Exists(path))
                continue;
            if (!DevBoxIdentityStorageSecurity.IsSafeRegularFile(path))
                throw new IOException(
                    "The Dev Box connection identity contains an unsafe file.");
            File.Delete(path);
        }
        foreach (var pending in Directory.EnumerateFiles(
                     directory,
                     "*.new",
                     SearchOption.TopDirectoryOnly))
        {
            if (!DevBoxIdentityStorageSecurity.IsSafeRegularFile(pending))
                throw new IOException(
                    "The Dev Box connection identity contains an unsafe file.");
            File.Delete(pending);
        }
        if (Directory.EnumerateFileSystemEntries(directory).Any())
            throw new IOException(
                "The Dev Box connection identity contains unexpected files.");
        Directory.Delete(directory);
    }

    private string ContextPath =>
        Path.Combine(directory, ContextFileName);

    private string RecordPath =>
        Path.Combine(directory, RecordFileName);

    private static void Validate(
        DevBoxConnectionIdentityContext context)
    {
        var scopes = context.Scopes.ToHashSet(StringComparer.Ordinal);
        if (context.Version !=
                DevBoxConnectionIdentityConstants.CurrentVersion ||
            context.Name !=
                DevBoxConnectionIdentityConstants.ContextName ||
            context.CacheName !=
                DevBoxConnectionIdentityConstants.CacheName ||
            context.ClientId !=
                DevBoxConnectionIdentityConstants.WindowsAppClientId ||
            context.RedirectUri !=
                DevBoxConnectionIdentityConstants.WindowsAppBrokerRedirectUri ||
            !Guid.TryParse(context.TenantId, out _) ||
            !IsPublicCloudAuthority(context.Authority) ||
            string.IsNullOrWhiteSpace(context.HomeAccountId) ||
            string.IsNullOrWhiteSpace(context.Username) ||
            scopes.Count != context.Scopes.Count ||
            !scopes.Contains(
                DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope) ||
            scopes.Any(scope =>
                scope !=
                    DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope &&
                scope !=
                    DevBoxConnectionIdentityConstants.Windows365EndUserScope))
            throw new InvalidDataException(
                "The Dev Box connection identity context is invalid or unsupported.");
    }

    private static void ValidateRecord(
        DevBoxConnectionIdentityContext context,
        AuthenticationRecord record)
    {
        if (!string.Equals(
                record.TenantId,
                context.TenantId,
                StringComparison.OrdinalIgnoreCase) ||
            record.ClientId != context.ClientId ||
            !string.Equals(
                record.HomeAccountId,
                context.HomeAccountId,
                StringComparison.Ordinal) ||
            !string.Equals(
                record.Authority,
                context.Authority,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                record.Username,
                context.Username,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "The Dev Box connection authentication record does not match its context.");
    }

    private static bool IsPublicCloudAuthority(string authority)
    {
        if (string.Equals(
                authority,
                "login.microsoftonline.com",
                StringComparison.OrdinalIgnoreCase))
            return true;
        return Uri.TryCreate(authority, UriKind.Absolute, out var uri) &&
            uri.Scheme == Uri.UriSchemeHttps &&
            uri.Port == 443 &&
            uri.UserInfo.Length == 0 &&
            string.Equals(
                uri.IdnHost,
                "login.microsoftonline.com",
                StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<byte[]> SerializeRecordAsync(
        AuthenticationRecord record,
        CancellationToken cancellationToken)
    {
        await using var stream = new MemoryStream();
        await record.SerializeAsync(
            stream,
            cancellationToken).ConfigureAwait(false);
        return stream.ToArray();
    }

    private static async Task AtomicWriteAsync(
        string path,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        var temporary =
            path + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough |
                    FileOptions.Asynchronous))
            {
                await stream.WriteAsync(
                    bytes,
                    cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(
                    cancellationToken).ConfigureAwait(false);
            }
            DevBoxIdentityStorageSecurity.RestrictFile(temporary);
            if (File.Exists(path))
            {
                if (!DevBoxIdentityStorageSecurity.IsSafeRegularFile(path))
                    throw new IOException(
                        "The Dev Box connection identity destination is unsafe.");
                File.Replace(temporary, path, null);
            }
            else
            {
                File.Move(temporary, path);
            }
            DevBoxIdentityStorageSecurity.RestrictFile(path);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}
