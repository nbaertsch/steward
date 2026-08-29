using System.Collections.ObjectModel;
using System.Text;

namespace Steward.Rdp.Windows;

public sealed record RdpConnectionProfile(
    string FullAddress,
    string GatewayHostname,
    int GatewayUsageMethod,
    int GatewayProfileUsageMethod,
    int GatewayCredentialsSource,
    uint GatewayBrokeringType,
    string LoadBalanceInfo,
    bool EnableRdsAadAuth,
    bool EnableCredSspSupport,
    bool AutoReconnect,
    int MaxReconnectAttempts,
    IReadOnlyDictionary<string, RdpSetting> Settings);

public sealed record RdpSetting(string Name, RdpSettingType Type, string Value);

public enum RdpSettingType
{
    Integer,
    String,
    Binary
}

public static class RdpFileParser
{
    public const int MaximumBytes = 64 * 1024;
    private const int MaximumLines = 128;
    private const int MaximumLineCharacters = 16 * 1024;

    private static readonly IReadOnlyDictionary<string, RdpSettingType> Allowed =
        new ReadOnlyDictionary<string, RdpSettingType>(
            new Dictionary<string, RdpSettingType>(StringComparer.OrdinalIgnoreCase)
            {
                ["full address"] = RdpSettingType.String,
                ["alternate full address"] = RdpSettingType.String,
                ["administrative session"] = RdpSettingType.Integer,
                ["alternate shell"] = RdpSettingType.String,
                ["bitmapcachepersistenable"] = RdpSettingType.Integer,
                ["compression"] = RdpSettingType.Integer,
                ["connect to console"] = RdpSettingType.Integer,
                ["gatewayhostname"] = RdpSettingType.String,
                ["gatewayusagemethod"] = RdpSettingType.Integer,
                ["gatewayprofileusagemethod"] = RdpSettingType.Integer,
                ["gatewaycredentialssource"] = RdpSettingType.Integer,
                ["gatewaybrokeringtype"] = RdpSettingType.Integer,
                ["promptcredentialonce"] = RdpSettingType.Integer,
                ["use redirection server name"] = RdpSettingType.Integer,
                ["loadbalanceinfo"] = RdpSettingType.String,
                ["pcb"] = RdpSettingType.String,
                ["authentication level"] = RdpSettingType.Integer,
                ["negotiate security layer"] = RdpSettingType.Integer,
                ["prompt for credentials"] = RdpSettingType.Integer,
                ["enablecredsspsupport"] = RdpSettingType.Integer,
                ["enablerdsaadauth"] = RdpSettingType.Integer,
                ["autoreconnection enabled"] = RdpSettingType.Integer,
                ["redirectclipboard"] = RdpSettingType.Integer,
                ["redirectprinters"] = RdpSettingType.Integer,
                ["redirectcomports"] = RdpSettingType.Integer,
                ["redirectsmartcards"] = RdpSettingType.Integer,
                ["redirectwebauthn"] = RdpSettingType.Integer,
                ["drivestoredirect"] = RdpSettingType.String,
                ["devicestoredirect"] = RdpSettingType.String,
                ["audiomode"] = RdpSettingType.Integer,
                ["audiocapturemode"] = RdpSettingType.Integer,
                ["videoplaybackmode"] = RdpSettingType.Integer,
                ["connection type"] = RdpSettingType.Integer,
                ["networkautodetect"] = RdpSettingType.Integer,
                ["bandwidthautodetect"] = RdpSettingType.Integer,
                ["desktopwidth"] = RdpSettingType.Integer,
                ["desktopheight"] = RdpSettingType.Integer,
                ["desktop size id"] = RdpSettingType.Integer,
                ["session bpp"] = RdpSettingType.Integer,
                ["dynamic resolution"] = RdpSettingType.Integer,
                ["smart sizing"] = RdpSettingType.Integer,
                ["screen mode id"] = RdpSettingType.Integer,
                ["keyboardhook"] = RdpSettingType.Integer,
                ["use multimon"] = RdpSettingType.Integer,
                ["displayconnectionbar"] = RdpSettingType.Integer,
                ["remoteapplicationmode"] = RdpSettingType.Integer,
                ["shell working directory"] = RdpSettingType.String,
                ["winposstr"] = RdpSettingType.String,
                ["disable wallpaper"] = RdpSettingType.Integer,
                ["disable full window drag"] = RdpSettingType.Integer,
                ["disable menu anims"] = RdpSettingType.Integer,
                ["disable themes"] = RdpSettingType.Integer,
                ["disable cursor setting"] = RdpSettingType.Integer,
                ["allow font smoothing"] = RdpSettingType.Integer,
                ["allow desktop composition"] = RdpSettingType.Integer,
                ["signature"] = RdpSettingType.String,
                ["signscope"] = RdpSettingType.String
            });

    public static RdpConnectionProfile Parse(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0 || content.Length > MaximumBytes)
            throw new InvalidDataException(
                $"RDP content must contain between 1 and {MaximumBytes} bytes.");

        var text = Decode(content);
        if (text.IndexOf('\0') >= 0)
            throw new InvalidDataException("RDP content contains a NUL character.");

        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines.Length > MaximumLines)
            throw new InvalidDataException($"RDP content exceeds {MaximumLines} lines.");

        var settings = new Dictionary<string, RdpSetting>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in lines)
        {
            var line = rawLine.EndsWith('\r') ? rawLine[..^1] : rawLine;
            if (line.Length == 0)
                continue;
            if (line.Length > MaximumLineCharacters)
                throw new InvalidDataException(
                    $"An RDP setting exceeds {MaximumLineCharacters} characters.");
            if (line.Any(char.IsControl))
                throw new InvalidDataException("RDP content contains a control character.");

            var first = line.IndexOf(':');
            var second = first < 0 ? -1 : line.IndexOf(':', first + 1);
            if (first <= 0 || second != first + 2)
                throw new InvalidDataException("An RDP setting has invalid name:type:value syntax.");

            var name = line[..first];
            if (name != name.Trim() || !Allowed.TryGetValue(name, out var allowedType))
                throw new InvalidDataException($"RDP setting '{name}' is not allowed.");
            var type = ParseType(line[first + 1]);
            if (type != allowedType)
                throw new InvalidDataException($"RDP setting '{name}' has an unexpected type.");
            var value = line[(second + 1)..];
            ValidateValue(name, type, value);
            if (!settings.TryAdd(name, new(name, type, value)))
                throw new InvalidDataException($"RDP setting '{name}' is duplicated.");
        }

        RequireSigned(settings);
        var fullAddress = RequiredString(settings, "full address");
        var gatewayHostname = RequiredString(settings, "gatewayhostname");
        ValidateEndpoint(fullAddress, "full address", "rdp", 3389);
        ValidateEndpoint(gatewayHostname, "gatewayhostname", Uri.UriSchemeHttps, 443);
        var usage = RequiredInteger(settings, "gatewayusagemethod", 0, 4);
        if (usage is 0 or 2 or 4)
            throw new InvalidDataException(
                "The live gate requires an RDP profile that mandates RD Gateway use.");
        var loadBalanceName = settings.ContainsKey("loadbalanceinfo")
            ? "loadbalanceinfo"
            : "pcb";
        return new(
            fullAddress,
            gatewayHostname,
            usage,
            OptionalInteger(settings, "gatewayprofileusagemethod", 0, 1, 1),
            OptionalInteger(settings, "gatewaycredentialssource", 0, 5, 5),
            checked((uint)OptionalInteger(settings, "gatewaybrokeringtype", 0, 2, 0)),
            RequiredString(settings, loadBalanceName),
            RequiredBoolean(settings, "enablerdsaadauth", true),
            OptionalBoolean(settings, "enablecredsspsupport", true),
            OptionalBoolean(settings, "autoreconnection enabled", true),
            3,
            new ReadOnlyDictionary<string, RdpSetting>(settings));
    }

    private static string Decode(ReadOnlySpan<byte> content)
    {
        try
        {
            if (content.Length >= 2 &&
                content[0] == 0xff &&
                content[1] == 0xfe)
                return new UnicodeEncoding(false, true, true).GetString(content[2..]);
            if (content.Length >= 3 &&
                content[0] == 0xef &&
                content[1] == 0xbb &&
                content[2] == 0xbf)
                content = content[3..];
            return new UTF8Encoding(false, true).GetString(content);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("RDP content is not strict UTF-8 or UTF-16LE.", exception);
        }
    }

    private static RdpSettingType ParseType(char value) => value switch
    {
        'i' => RdpSettingType.Integer,
        's' => RdpSettingType.String,
        'b' => RdpSettingType.Binary,
        _ => throw new InvalidDataException($"RDP setting type '{value}' is not allowed.")
    };

    private static void ValidateValue(string name, RdpSettingType type, string value)
    {
        if (value.Length == 0 &&
            !EmptyStringAllowed.Contains(name))
            throw new InvalidDataException($"RDP setting '{name}' is empty.");
        if (type == RdpSettingType.Integer &&
            (!int.TryParse(
                value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out _) ||
             value.Length > 10))
            throw new InvalidDataException($"RDP setting '{name}' is not a valid integer.");
        if (type == RdpSettingType.Binary &&
            (value.Length % 2 != 0 || value.Any(x => !Uri.IsHexDigit(x))))
            throw new InvalidDataException($"RDP setting '{name}' is not valid hexadecimal.");
    }

    private static void RequireSigned(IReadOnlyDictionary<string, RdpSetting> settings)
    {
        var signature = RequiredString(settings, "signature");
        if (signature.Length < 32 || signature.Length > MaximumLineCharacters)
            throw new InvalidDataException("The RDP signature has an invalid length.");
        var decodedSignature = new byte[signature.Length];
        if (!Convert.TryFromBase64String(
                signature,
                decodedSignature,
                out var signatureBytes) ||
            signatureBytes < 24)
            throw new InvalidDataException("The RDP signature is not valid bounded base64.");
        var scope = RequiredString(settings, "signscope");
        var signedNames = scope.Split(',', StringSplitOptions.TrimEntries);
        if (signedNames.Length == 0 ||
            signedNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() != signedNames.Length ||
            signedNames.Any(x => !settings.ContainsKey(x) ||
                                 string.Equals(x, "signature", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("The RDP signscope references an absent or invalid setting.");
        var loadBalanceName = settings.ContainsKey("loadbalanceinfo")
            ? "loadbalanceinfo"
            : "pcb";
        foreach (var required in new[] { "full address", "gatewayhostname", loadBalanceName })
            if (!signedNames.Contains(required, StringComparer.OrdinalIgnoreCase))
                throw new InvalidDataException($"The RDP signscope does not cover '{required}'.");
    }

    private static void ValidateEndpoint(
        string value,
        string settingName,
        string scheme,
        int defaultPort)
    {
        if (!Uri.TryCreate($"{scheme}://{value}", UriKind.Absolute, out var uri) ||
            string.IsNullOrWhiteSpace(uri.IdnHost) ||
            uri.UserInfo.Length != 0 ||
            uri.AbsolutePath != "/" ||
            uri.Query.Length != 0 ||
            uri.Fragment.Length != 0 ||
            (!uri.IsDefaultPort && uri.Port is <= 0 or > 65535))
            throw new InvalidDataException($"RDP setting '{settingName}' is not a valid endpoint.");
        _ = uri.IsDefaultPort ? defaultPort : uri.Port;
    }

    private static readonly HashSet<string> EmptyStringAllowed =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "alternate shell",
            "shell working directory",
            "drivestoredirect",
            "devicestoredirect"
        };

    private static string RequiredString(
        IReadOnlyDictionary<string, RdpSetting> settings,
        string name) =>
        settings.TryGetValue(name, out var setting) && !string.IsNullOrWhiteSpace(setting.Value)
            ? setting.Value
            : throw new InvalidDataException($"RDP setting '{name}' is required.");

    private static int RequiredInteger(
        IReadOnlyDictionary<string, RdpSetting> settings,
        string name,
        int minimum,
        int maximum)
    {
        if (!settings.TryGetValue(name, out var setting) ||
            !int.TryParse(
                setting.Value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var value) ||
            value < minimum ||
            value > maximum)
            throw new InvalidDataException(
                $"RDP setting '{name}' must be between {minimum} and {maximum}.");
        return value;
    }

    private static int OptionalInteger(
        IReadOnlyDictionary<string, RdpSetting> settings,
        string name,
        int minimum,
        int maximum,
        int defaultValue) =>
        settings.ContainsKey(name)
            ? RequiredInteger(settings, name, minimum, maximum)
            : defaultValue;

    private static bool RequiredBoolean(
        IReadOnlyDictionary<string, RdpSetting> settings,
        string name,
        bool requiredValue)
    {
        var value = RequiredInteger(settings, name, 0, 1) == 1;
        if (value != requiredValue)
            throw new InvalidDataException($"RDP setting '{name}' must be {(requiredValue ? 1 : 0)}.");
        return value;
    }

    private static bool OptionalBoolean(
        IReadOnlyDictionary<string, RdpSetting> settings,
        string name,
        bool defaultValue) =>
        settings.ContainsKey(name)
            ? RequiredInteger(settings, name, 0, 1) == 1
            : defaultValue;
}
