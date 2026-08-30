using System.Text.RegularExpressions;

namespace Steward.PortableState;

public static partial class SecretRedactor
{
    public const string Redacted = "[REDACTED]";

    public static string RedactUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return new UriBuilder(uri) { Query = string.Empty, Fragment = string.Empty }.Uri.AbsoluteUri;
    }

    public static string Redact(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return CredentialUriRegex().Replace(value, match =>
        {
            var text = match.Value.TrimEnd('.', ',', ';', ')', ']', '}');
            return Uri.TryCreate(text, UriKind.Absolute, out var uri)
                ? RedactUri(uri) + Redacted
                : Redacted;
        });
    }

    [GeneratedRegex(@"https?://[^\s""'<>]+?\?[^\s""'<>]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CredentialUriRegex();
}
