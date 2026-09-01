using System.Text.Json;
using Azure.Identity;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;

namespace Steward.ConnectionHost.Windows;

public sealed class DevBoxRdCoreCredentialCallback(
    IDevBoxConnectionTokenSource tokenSource,
    Action<string>? diagnosticSink = null,
    IWindowsCloudLoginTokenProvider? cloudLoginTokenProvider = null) :
    IRdCoreCredentialCallback
{
    private const string AvdResource = "https://www.wvd.microsoft.com/";
    private const string AvdClaimsClientId =
        DevBoxConnectionIdentityConstants.AvdClaimsClientId;
    private readonly IWindowsCloudLoginTokenProvider cloudLogin =
        cloudLoginTokenProvider ?? new WindowsCloudLoginTokenProvider();

    public async ValueTask<RdCoreClaimsToken> AcquireTokenAsync(
        RdCoreClaimsTokenRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var before = await tokenSource.GetBindingAsync(cancellationToken)
            .ConfigureAwait(false);
        _ = Uri.TryCreate(
            request.ResourceUri,
            UriKind.Absolute,
            out var resourceUri);
        _ = Uri.TryCreate(
            request.Scope,
            UriKind.Absolute,
            out var scopeUri);
        _ = Uri.TryCreate(
            request.RedirectUri,
            UriKind.Absolute,
            out var redirectUri);
        diagnosticSink?.Invoke(
            $"client-known={request.ClientId == AvdClaimsClientId};" +
            $"authority-known={AuthorityMatchesTenant(request.AuthorityUri, before.TenantId)};" +
            $"hint-empty={string.IsNullOrWhiteSpace(request.UserNameHint)};" +
            $"hint-exact={string.Equals(request.UserNameHint, before.Username, StringComparison.OrdinalIgnoreCase)};" +
            $"resource-known={IsAvdResource(request.ResourceUri)};" +
            $"resource-scheme={resourceUri?.Scheme ?? "none"};" +
            $"resource-shape={resourceUri?.IdnHost ?? "none"}{resourceUri?.AbsolutePath ?? string.Empty};" +
            $"scope-empty={string.IsNullOrWhiteSpace(request.Scope)};" +
            $"scope-exact={string.Equals(request.Scope, DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope, StringComparison.Ordinal)};" +
            $"scope-shape={scopeUri?.IdnHost ?? "none"}{scopeUri?.AbsolutePath ?? string.Empty};" +
            $"scope-label={SafeLabel(request.Scope)};" +
            $"redirect-shape={redirectUri?.Scheme ?? "none"}:{redirectUri?.IdnHost ?? "none"}{redirectUri?.AbsolutePath ?? string.Empty};" +
            $"claims-shape={ClaimsShape(request.Claims)}");
        var isCloudLogin = IsWindowsCloudLogin(request);
        ValidateRequest(request, before, isCloudLogin);
        WindowsCloudLoginToken? cloudToken;
        try
        {
            cloudToken = isCloudLogin
                ? await cloudLogin
                    .AcquireSilentAsync(
                        request,
                        before,
                        cancellationToken)
                    .ConfigureAwait(false)
                : null;
        }
        catch (Exception exception)
            when (exception is
                AuthenticationFailedException or
                CredentialUnavailableException)
        {
            throw new DevBoxConnectionIdentityException(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                exception.Message,
                exception);
        }
        var token = cloudToken?.AccessToken ??
            await tokenSource.AcquireTokenAsync(
                    DevBoxConnectionAudience.AzureVirtualDesktop,
                    cancellationToken,
                    request.Claims)
                .ConfigureAwait(false);
        if (cloudToken is not null)
            diagnosticSink?.Invoke(
                "cloud-login-metadata=" +
                string.Join(',', cloudToken.MetadataKeys));
        var after = await tokenSource.GetBindingAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!SameBinding(before, after))
            throw new InvalidOperationException(
                "The Dev Box connection identity changed during token acquisition.");
        return new(
            token.Token,
            cloudToken?.TokenAuthority ?? request.AuthorityUri,
            cloudToken?.UserName ?? before.Username,
            AcquiredSilently: true,
            cloudToken?.AadResourceTenantId ?? before.TenantId,
            AadDeviceId: cloudToken?.AadDeviceId ?? string.Empty,
            AadP2PRootCertificates:
                cloudToken?.AadP2PRootCertificates ?? string.Empty);
    }

    private static void ValidateRequest(
        RdCoreClaimsTokenRequest request,
        DevBoxConnectionIdentityBinding binding,
        bool cloudLogin)
    {
        if (!string.Equals(
                request.ClientId,
                AvdClaimsClientId,
                StringComparison.Ordinal) ||
            !string.Equals(
                binding.ClientId,
                DevBoxConnectionIdentityConstants.WindowsAppClientId,
                StringComparison.Ordinal))
            throw new InvalidOperationException(
                "RDCore requested a token for an unexpected client.");
        if (string.IsNullOrWhiteSpace(binding.TenantId) ||
            string.IsNullOrWhiteSpace(binding.HomeAccountId) ||
            string.IsNullOrWhiteSpace(binding.Username) ||
            !AuthorityMatchesTenant(
                request.AuthorityUri,
                binding.TenantId))
            throw new InvalidOperationException(
                "RDCore requested a token for an unexpected tenant.");
        if (!string.IsNullOrWhiteSpace(request.UserNameHint) &&
            !string.Equals(
                request.UserNameHint,
                binding.Username,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "RDCore requested a token for an unexpected account.");
        if (!cloudLogin &&
            (!IsAvdResource(request.ResourceUri) ||
            !string.IsNullOrWhiteSpace(request.Scope) &&
            !string.Equals(
                request.Scope,
                DevBoxConnectionIdentityConstants.AzureVirtualDesktopScope,
                StringComparison.Ordinal)))
            throw new InvalidOperationException(
                "RDCore requested a token outside the AVD audience.");
    }

    private static bool IsWindowsCloudLogin(
        RdCoreClaimsTokenRequest request) =>
        Uri.TryCreate(
            request.ResourceUri,
            UriKind.Absolute,
            out var resource) &&
        resource.Scheme == "ms-device-service" &&
        string.Equals(
            resource.IdnHost,
            "270efc09-cd0d-444b-a71f-39af4910ec45",
            StringComparison.OrdinalIgnoreCase) &&
        resource.Query.Length == 0 &&
        resource.Fragment.Length == 0 &&
        resource.AbsolutePath.Split(
            '/',
            StringSplitOptions.RemoveEmptyEntries) is
            ["id", var deviceId] &&
        Guid.TryParse(deviceId, out _) &&
        request.Scope == "user_impersonation";

    private static bool AuthorityMatchesTenant(
        string authorityValue,
        string tenantId)
    {
        if (!Uri.TryCreate(
                authorityValue,
                UriKind.Absolute,
                out var authority) ||
            authority.Scheme != Uri.UriSchemeHttps ||
            authority.Port != 443 ||
            authority.UserInfo.Length != 0 ||
            authority.Query.Length != 0 ||
            authority.Fragment.Length != 0 ||
            !(string.Equals(
                  authority.IdnHost,
                  "login.microsoftonline.com",
                  StringComparison.OrdinalIgnoreCase) ||
              string.Equals(
                  authority.IdnHost,
                  "login.windows.net",
                  StringComparison.OrdinalIgnoreCase)))
            return false;
        var authorityTenant = authority.AbsolutePath.Trim('/');
        return string.Equals(
                authorityTenant,
                tenantId,
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                authorityTenant,
                "common",
                StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAvdResource(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var resource) ||
            resource.Scheme != Uri.UriSchemeHttps ||
            resource.Port != 443 ||
            resource.UserInfo.Length != 0 ||
            resource.Query.Length != 0 ||
            resource.Fragment.Length != 0)
            return false;
        return string.Equals(
            resource.AbsoluteUri.TrimEnd('/') + "/",
            AvdResource,
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameBinding(
        DevBoxConnectionIdentityBinding left,
        DevBoxConnectionIdentityBinding right) =>
        string.Equals(
            left.TenantId,
            right.TenantId,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            left.HomeAccountId,
            right.HomeAccountId,
            StringComparison.Ordinal) &&
        string.Equals(
            left.Username,
            right.Username,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            left.ClientId,
            right.ClientId,
            StringComparison.Ordinal);

    private static string SafeLabel(string value) =>
        value.Length <= 128 &&
        value.All(character =>
            char.IsAsciiLetterOrDigit(character) ||
            character is '.' or ':' or '/' or '-' or '_')
            ? value
            : "other";

    private static string ClaimsShape(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "empty";
        try
        {
            using var document = JsonDocument.Parse(value);
            var names = new HashSet<string>(StringComparer.Ordinal);
            CollectNames(document.RootElement, names, 0);
            return $"{value.Length}:{string.Join(',', names.Order())}";
        }
        catch (JsonException)
        {
            return $"{value.Length}:non-json";
        }
    }

    private static void CollectNames(
        JsonElement element,
        HashSet<string> names,
        int depth)
    {
        if (depth > 4 || names.Count >= 32)
            return;
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.Name.Length <= 64 &&
                    property.Name.All(character =>
                        char.IsAsciiLetterOrDigit(character) ||
                        character is '-' or '_'))
                    names.Add(property.Name);
                CollectNames(property.Value, names, depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray().Take(1))
                CollectNames(item, names, depth + 1);
        }
    }
}
