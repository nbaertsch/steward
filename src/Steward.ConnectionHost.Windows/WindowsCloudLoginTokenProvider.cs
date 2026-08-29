using Azure.Core;
using Azure.Identity;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Windows.Security.Authentication.Web.Core;

namespace Steward.ConnectionHost.Windows;

public sealed record WindowsCloudLoginToken(
    AccessToken AccessToken,
    string TokenAuthority,
    string UserName,
    string AadDeviceId,
    string AadResourceTenantId,
    string AadP2PRootCertificates,
    IReadOnlyList<string> MetadataKeys);

public interface IWindowsCloudLoginTokenProvider
{
    Task<WindowsCloudLoginToken> AcquireSilentAsync(
        RdCoreClaimsTokenRequest request,
        DevBoxConnectionIdentityBinding binding,
        CancellationToken cancellationToken);
}

public sealed class WindowsCloudLoginTokenProvider :
    IWindowsCloudLoginTokenProvider
{
    private readonly RSA popKey = RSA.Create(2048);

    public async Task<WindowsCloudLoginToken> AcquireSilentAsync(
        RdCoreClaimsTokenRequest request,
        DevBoxConnectionIdentityBinding binding,
        CancellationToken cancellationToken)
    {
        var (resource, deviceId) = Validate(request);
        cancellationToken.ThrowIfCancellationRequested();
        var authority =
            $"https://login.microsoftonline.com/{binding.TenantId}";
        var provider =
            await WebAuthenticationCoreManager.FindAccountProviderAsync(
                "https://login.microsoft.com",
                authority);
        if (provider is null)
            throw new CredentialUnavailableException(
                "The Windows Cloud Login account provider is unavailable.");
        var tokenRequest = new WebTokenRequest(
            provider,
            "user_impersonation",
            DevBoxConnectionIdentityConstants.AvdClaimsClientId);
        tokenRequest.Properties.Add("authority", authority);
        tokenRequest.Properties.Add("resource", resource);
        tokenRequest.Properties.Add("token_type", "pop");
        tokenRequest.Properties.Add("enclave", "kg");
        tokenRequest.Properties.Add("req_cnf", CreateReqCnf(popKey));
        tokenRequest.Properties.Add("LoginHint", binding.Username);
        if (!string.IsNullOrWhiteSpace(request.Claims))
            tokenRequest.Properties.Add("claims", request.Claims);

        var result =
            await WebAuthenticationCoreManager.GetTokenSilentlyAsync(
                tokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        if (result.ResponseStatus ==
            WebTokenRequestStatus.UserInteractionRequired)
            throw new CredentialUnavailableException(
                "Windows Cloud Login requires interaction.");
        if (result.ResponseStatus != WebTokenRequestStatus.Success ||
            result.ResponseData.Count != 1)
            throw new AuthenticationFailedException(
                $"Windows Cloud Login failed with status " +
                $"{result.ResponseStatus} and provider code " +
                $"{result.ResponseError?.ErrorCode ?? 0}: " +
                Sanitize(result.ResponseError?.ErrorMessage) +
                ".");
        var response = result.ResponseData[0];
        if (string.IsNullOrWhiteSpace(response.Token) ||
            !string.Equals(
                response.WebAccount?.UserName,
                binding.Username,
                StringComparison.OrdinalIgnoreCase))
            throw new AuthenticationFailedException(
                "Windows Cloud Login returned an invalid account response.");
        var returnedDeviceId = Property(
            response,
            "target_deviceid");
        var resourceTenantId = Property(
            response,
            "DeviceTenantId");
        var rootsProperty = Property(response, "x5c_ca");
        var roots = NormalizeCertificates(rootsProperty);
        var tokenAuthority = Property(response, "DeviceAuthority");
        var userName = response.WebAccount?.UserName ?? string.Empty;
        if (!Guid.TryParse(returnedDeviceId, out var parsedDeviceId) ||
            !Guid.TryParse(deviceId, out var expectedDeviceId) ||
            parsedDeviceId != expectedDeviceId ||
            !Guid.TryParse(resourceTenantId, out _) ||
            string.IsNullOrWhiteSpace(roots) ||
            roots.Length > 256 * 1024 ||
            !IsMicrosoftAuthority(tokenAuthority, resourceTenantId) ||
            string.IsNullOrWhiteSpace(userName))
            throw new AuthenticationFailedException(
                "Windows Cloud Login returned invalid RDP PoP metadata.");
        return new(
            new(
                response.Token,
                DateTimeOffset.UtcNow.AddMinutes(5)),
            tokenAuthority,
            userName,
            deviceId,
            resourceTenantId,
            roots,
            response.Properties.Keys
                .Where(key =>
                    key.Length <= 64 &&
                    key.All(character =>
                        char.IsAsciiLetterOrDigit(character) ||
                        character is '-' or '_'))
                .Order(StringComparer.Ordinal)
                .Append("x5c-shape-" + CertificateShape(rootsProperty))
                .ToArray());
    }

    private static string Property(
        WebTokenResponse response,
        string name) =>
        response.Properties.FirstOrDefault(property =>
            string.Equals(
                property.Key,
                name,
                StringComparison.OrdinalIgnoreCase)).Value ??
        string.Empty;

    private static bool IsMicrosoftAuthority(
        string value,
        string tenantId) =>
        Uri.TryCreate(value, UriKind.Absolute, out var authority) &&
        authority.Scheme == Uri.UriSchemeHttps &&
        authority.Port == 443 &&
        authority.UserInfo.Length == 0 &&
        authority.Query.Length == 0 &&
        authority.Fragment.Length == 0 &&
        (authority.IdnHost.Equals(
             "login.microsoftonline.com",
             StringComparison.OrdinalIgnoreCase) ||
         authority.IdnHost.Equals(
             "login.windows.net",
             StringComparison.OrdinalIgnoreCase)) &&
        (authority.AbsolutePath.Trim('/').Equals(
             tenantId,
             StringComparison.OrdinalIgnoreCase) ||
         authority.AbsolutePath.Trim('/').Equals(
             "common",
             StringComparison.OrdinalIgnoreCase));

    private static (string Resource, string DeviceId) Validate(
        RdCoreClaimsTokenRequest request)
    {
        if (request.ClientId !=
                DevBoxConnectionIdentityConstants.AvdClaimsClientId ||
            !string.IsNullOrWhiteSpace(request.RedirectUri) &&
            request.RedirectUri !=
                DevBoxConnectionIdentityConstants
                    .AvdClaimsBrokerRedirectUri ||
            request.Scope != "user_impersonation" ||
            !Uri.TryCreate(
                request.ResourceUri,
                UriKind.Absolute,
                out var resource) ||
            resource.Scheme != "ms-device-service" ||
            !string.Equals(
                resource.IdnHost,
                "270efc09-cd0d-444b-a71f-39af4910ec45",
                StringComparison.OrdinalIgnoreCase) ||
            resource.Query.Length != 0 ||
            resource.Fragment.Length != 0 ||
            resource.AbsolutePath.Split(
                '/',
                StringSplitOptions.RemoveEmptyEntries) is not
                ["id", var deviceId] ||
            !Guid.TryParse(deviceId, out _))
            throw new ArgumentException(
                "The Windows Cloud Login token request is invalid.");
        return (request.ResourceUri, deviceId);
    }

    private static string Sanitize(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? "no-detail"
            : new string(value
                    .Take(160)
                    .Select(character =>
                        char.IsAsciiLetterOrDigit(character) ||
                        character is ' ' or '.' or '-' or '_' or ':'
                            ? character
                            : '_')
                    .ToArray())
                .Replace(' ', '_');

    private static string CreateReqCnf(RSA key)
    {
        var parameters = key.ExportParameters(false);
        var exponent = Base64Url(parameters.Exponent!);
        var modulus = Base64Url(parameters.Modulus!);
        var canonical = Encoding.UTF8.GetBytes(
            $"{{\"e\":\"{exponent}\",\"kty\":\"RSA\",\"n\":\"{modulus}\"}}");
        var kid = Base64Url(SHA256.HashData(canonical));
        return Base64Url(Encoding.UTF8.GetBytes(
            $"{{\"kid\":\"{kid}\"}}"));
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string CertificateShape(string value)
    {
        try
        {
            using var document = JsonDocument.Parse(value);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                return document.RootElement.ValueKind.ToString();
            var lengths = document.RootElement
                .EnumerateArray()
                .Take(8)
                .Select(element =>
                {
                    if (element.ValueKind != JsonValueKind.String)
                        return -1;
                    try
                    {
                        return Convert.FromBase64String(
                            element.GetString()!).Length;
                    }
                    catch (FormatException)
                    {
                        return -2;
                    }
                });
            return "Array-" + string.Join('-', lengths);
        }
        catch (JsonException)
        {
            return $"NonJson-{value.Length}";
        }

    }

    private static string NormalizeCertificates(string value)
    {
        using var document = JsonDocument.Parse(value);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new AuthenticationFailedException(
                "Windows Cloud Login returned an invalid certificate chain.");
        var certificates = document.RootElement
            .EnumerateArray()
            .Select(element =>
                element.ValueKind == JsonValueKind.String
                    ? element.GetString()
                    : null)
            .ToArray();
        if (certificates.Length is 0 or > 8 ||
            certificates.Any(string.IsNullOrWhiteSpace))
            throw new AuthenticationFailedException(
                "Windows Cloud Login returned an invalid certificate chain.");
        var pem = new StringBuilder();
        foreach (var encoded in certificates)
        {
            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(encoded!);
                using var certificate =
                    X509CertificateLoader.LoadCertificate(bytes);
                if (certificate.RawData.Length != bytes.Length)
                    throw new CryptographicException();
                pem.Append(certificate.ExportCertificatePem());
            }
            catch (Exception exception)
                when (exception is
                    FormatException or
                    CryptographicException)
            {
                throw new AuthenticationFailedException(
                    "Windows Cloud Login returned an invalid certificate chain.",
                    exception);
            }
        }
        return pem.ToString();
    }
}
