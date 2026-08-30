using System.Text.Json;

namespace Steward.ConnectionHost.Windows;

public sealed record ConnectionHostAutoConnectOptions(
    int Version,
    Uri DevBoxEndpoint,
    string Project,
    string User,
    string DevBox,
    string ConnectionId,
    string AuthorizationToken,
    string EvidenceReference,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    Guid ConnectionNonce)
{
    public static async Task<ConnectionHostAutoConnectOptions?> LoadAsync(
        string? path,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor path must be absolute.");
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath) ||
            File.GetAttributes(fullPath).HasFlag(
                FileAttributes.ReparsePoint) ||
            new FileInfo(fullPath).Length is <= 0 or > 64 * 1024)
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor is unavailable.");
        await using var stream = File.OpenRead(fullPath);
        var options = await JsonSerializer.DeserializeAsync<
                ConnectionHostAutoConnectOptions>(
                stream,
                new JsonSerializerOptions(
                    JsonSerializerDefaults.Web),
                cancellationToken)
            .ConfigureAwait(false) ??
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor is empty.");
        return options.Validate();
    }

    public ConnectionHostAutoConnectOptions Validate()
    {
        if (Version != 1)
            throw new InvalidDataException(
                "The ConnectionHost auto-connect version is unsupported.");
        Steward.DevBox.Windows.DevBoxDiscoveryService
            .ValidateProjectEndpoint(DevBoxEndpoint);
        ValidateIdentifier(Project, nameof(Project));
        if (!string.Equals(User, "me", StringComparison.Ordinal) &&
            !Guid.TryParse(User, out _))
            throw new InvalidDataException(
                "The auto-connect Dev Box user is invalid.");
        ValidateIdentifier(DevBox, nameof(DevBox));
        ValidateBounded(ConnectionId, 128, nameof(ConnectionId));
        ValidateBounded(
            AuthorizationToken,
            ConnectionHostProtocol.MaximumAuthorizationTokenCharacters,
            nameof(AuthorizationToken));
        ValidateBounded(
            EvidenceReference,
            ConnectionHostProtocol.MaximumEvidenceReferenceCharacters,
            nameof(EvidenceReference));
        if (SessionId == Guid.Empty ||
            HostId == Guid.Empty ||
            NodeIncarnationId == Guid.Empty ||
            ConnectionNonce == Guid.Empty)
            throw new InvalidDataException(
                "The auto-connect transport identity is invalid.");
        return this;
    }

    private static void ValidateIdentifier(
        string value,
        string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length is < 3 or > 63 ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.'))
            throw new InvalidDataException(
                $"The auto-connect identifier '{name}' is invalid.");
    }

    private static void ValidateBounded(
        string value,
        int maximum,
        string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximum ||
            value.Any(char.IsControl))
            throw new InvalidDataException(
                $"The auto-connect value '{name}' is invalid.");
    }
}
