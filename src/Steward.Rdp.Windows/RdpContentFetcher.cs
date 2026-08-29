using System.Net;
using System.Net.Http.Headers;
using Azure.Core;

namespace Steward.Rdp.Windows;

public sealed class RdpContentFetcher
{
    private const int MaximumRedirects = 3;
    private readonly HttpMessageInvoker _http;

    public RdpContentFetcher(HttpMessageInvoker http)
    {
        _http = http;
    }

    public async Task<byte[]> FetchAsync(
        Uri rdpConnectionUri,
        Uri devCenterEndpoint,
        AccessToken devCenterToken,
        CancellationToken cancellationToken)
    {
        ValidateInitialUri(rdpConnectionUri);
        ValidateDevCenterEndpoint(devCenterEndpoint);
        var initialOrigin = Origin(rdpConnectionUri);
        var current = rdpConnectionUri;
        for (var redirects = 0; ; redirects++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                "application/x-rdp"));
            if (SameOrigin(current, devCenterEndpoint))
                request.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer", devCenterToken.Token);

            using var response = await _http.SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
            if (IsRedirect(response.StatusCode))
            {
                if (redirects == MaximumRedirects)
                    throw new InvalidDataException(
                        $"RDP download exceeds {MaximumRedirects} redirects.");
                var location = response.Headers.Location ??
                    throw new InvalidDataException("RDP download redirect has no Location.");
                var next = location.IsAbsoluteUri ? location : new Uri(current, location);
                ValidateRedirect(next, initialOrigin);
                current = next;
                continue;
            }

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new InvalidOperationException(
                    "The devbox/default identity cannot retrieve the RDP profile.");
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is > RdpFileParser.MaximumBytes)
                throw new InvalidDataException("RDP download exceeds the response limit.");
            await using var stream = await response.Content
                .ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            return await ReadBoundedAsync(stream, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return output.ToArray();
            if (output.Length + read > RdpFileParser.MaximumBytes)
                throw new InvalidDataException("RDP download exceeds the response limit.");
            output.Write(buffer, 0, read);
        }
    }

    private static void ValidateInitialUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.Port != 443 ||
            uri.UserInfo.Length != 0 ||
            uri.Fragment.Length != 0)
            throw new InvalidDataException(
                "The RDP connection URL must be absolute HTTPS on port 443 without user info or fragment.");
    }

    private static void ValidateDevCenterEndpoint(Uri endpoint)
    {
        if (!endpoint.IsAbsoluteUri ||
            endpoint.Scheme != Uri.UriSchemeHttps ||
            endpoint.Port != 443 ||
            endpoint.UserInfo.Length != 0)
            throw new ArgumentException(
                "The Dev Center endpoint must be absolute HTTPS on port 443.",
                nameof(endpoint));
    }

    private static void ValidateRedirect(Uri candidate, Uri allowedOrigin)
    {
        ValidateInitialUri(candidate);
        if (!SameOrigin(candidate, allowedOrigin))
            throw new InvalidDataException(
                "RDP download redirect leaves the original HTTPS origin.");
    }

    private static Uri Origin(Uri uri) =>
        new(uri.GetLeftPart(UriPartial.Authority), UriKind.Absolute);

    private static bool SameOrigin(Uri left, Uri right) =>
        left.Scheme == right.Scheme &&
        left.Port == right.Port &&
        string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase);

    private static bool IsRedirect(HttpStatusCode status) =>
        status is HttpStatusCode.Moved or
            HttpStatusCode.Redirect or
            HttpStatusCode.RedirectMethod or
            HttpStatusCode.TemporaryRedirect or
            HttpStatusCode.PermanentRedirect;
}
