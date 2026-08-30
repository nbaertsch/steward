namespace Steward.DevBox.LiveAcceptance;

internal sealed record LiveHarnessConfiguration(
    Uri Endpoint,
    string Project,
    string Pool,
    string User,
    string BoxName,
    string EvidenceDirectory,
    bool AllowBillableCreate,
    bool CreateOnly,
    bool DeleteEvidenceBox,
    bool RecoverAcceptedCreate,
    TimeSpan CreateTimeout,
    TimeSpan RdpConnectionTimeout,
    TimeSpan RdpLoginTimeout)
{
    private const string BillableConsent = "I_UNDERSTAND_THIS_CREATES_A_BILLABLE_DEV_BOX";

    public static LiveHarnessConfiguration Parse(
        string[] arguments,
        IReadOnlyDictionary<string, string?> environment)
    {
        var values = ParseArguments(arguments);
        var endpoint = Required(values, environment, "endpoint", "STEWARD_DEVBOX_ENDPOINT");
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri) ||
            endpointUri.Scheme != Uri.UriSchemeHttps ||
            endpointUri.Port != 443 ||
            endpointUri.UserInfo.Length != 0)
            throw new ArgumentException(
                "Dev Center endpoint must be absolute HTTPS on port 443.");

        var evidenceDirectory = Optional(
            values,
            environment,
            "evidence-directory",
            "STEWARD_DEVBOX_EVIDENCE_DIRECTORY",
            Path.Combine("artifacts", "devbox-live-acceptance"));
        if (!Path.IsPathFullyQualified(evidenceDirectory))
            evidenceDirectory = Path.GetFullPath(evidenceDirectory);

        var allowCreate =
            values.ContainsKey("allow-billable-create") ||
            string.Equals(
                EnvironmentValue(environment, "STEWARD_DEVBOX_LIVE_ACCEPTANCE"),
                BillableConsent,
                StringComparison.Ordinal);
        var delete =
            values.ContainsKey("delete-evidence-box") ||
            string.Equals(
                EnvironmentValue(environment, "STEWARD_DEVBOX_DELETE_EVIDENCE_BOX"),
                "true",
                StringComparison.OrdinalIgnoreCase);
        var recoverAcceptedCreate =
            values.ContainsKey("recover-accepted-create");
        var createOnly = values.ContainsKey("create-only");
        return new(
            NormalizeEndpoint(endpointUri),
            Required(values, environment, "project", "STEWARD_DEVBOX_PROJECT"),
            Required(values, environment, "pool", "STEWARD_DEVBOX_POOL"),
            Required(values, environment, "user", "STEWARD_DEVBOX_USER"),
            Required(values, environment, "box-name", "STEWARD_DEVBOX_BOX_NAME"),
            evidenceDirectory,
            allowCreate,
            createOnly,
            delete,
            recoverAcceptedCreate,
            TimeSpan.FromMinutes(ParsePositiveMinutes(
                values,
                environment,
                "create-timeout-minutes",
                "STEWARD_DEVBOX_CREATE_TIMEOUT_MINUTES",
                45)),
            TimeSpan.FromMinutes(ParsePositiveMinutes(
                values,
                environment,
                "rdp-connect-timeout-minutes",
                "STEWARD_DEVBOX_RDP_CONNECT_TIMEOUT_MINUTES",
                3)),
            TimeSpan.FromMinutes(ParsePositiveMinutes(
                values,
                environment,
                "rdp-login-timeout-minutes",
                "STEWARD_DEVBOX_RDP_LOGIN_TIMEOUT_MINUTES",
                3)));
    }

    public string Fingerprint()
    {
        var value = string.Join(
            '\n',
            Endpoint.AbsoluteUri,
            Project,
            Pool,
            User,
            BoxName);
        return Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(value)));
    }

    private static Dictionary<string, string?> ParseArguments(string[] arguments)
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Length; index++)
        {
            var argument = arguments[index];
            if (!argument.StartsWith("--", StringComparison.Ordinal) ||
                argument.Length == 2)
                throw new ArgumentException($"Unknown argument syntax at position {index + 1}.");
            var name = argument[2..];
            if (name is
                "allow-billable-create" or
                "create-only" or
                "delete-evidence-box" or
                "recover-accepted-create")
            {
                if (!values.TryAdd(name, null))
                    throw new ArgumentException($"Argument '--{name}' is duplicated.");
                continue;
            }
            if (index + 1 >= arguments.Length ||
                arguments[index + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException($"Argument '--{name}' requires a value.");
            if (!KnownValueArguments.Contains(name) ||
                !values.TryAdd(name, arguments[++index]))
                throw new ArgumentException($"Argument '--{name}' is unknown or duplicated.");
        }
        return values;
    }

    private static readonly HashSet<string> KnownValueArguments =
    [
        "endpoint",
        "project",
        "pool",
        "user",
        "box-name",
        "evidence-directory",
        "create-timeout-minutes",
        "rdp-connect-timeout-minutes",
        "rdp-login-timeout-minutes"
    ];

    private static string Required(
        IReadOnlyDictionary<string, string?> arguments,
        IReadOnlyDictionary<string, string?> environment,
        string argumentName,
        string environmentName)
    {
        var value = Optional(
            arguments,
            environment,
            argumentName,
            environmentName,
            "");
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 256 ||
            value.Any(char.IsControl))
            throw new ArgumentException(
                $"Provide a valid '--{argumentName}' or '{environmentName}'.");
        return value;
    }

    private static string Optional(
        IReadOnlyDictionary<string, string?> arguments,
        IReadOnlyDictionary<string, string?> environment,
        string argumentName,
        string environmentName,
        string defaultValue) =>
        arguments.TryGetValue(argumentName, out var argumentValue)
            ? argumentValue!
            : EnvironmentValue(environment, environmentName) ?? defaultValue;

    private static string? EnvironmentValue(
        IReadOnlyDictionary<string, string?> environment,
        string name) =>
        environment.TryGetValue(name, out var value) ? value : null;

    private static double ParsePositiveMinutes(
        IReadOnlyDictionary<string, string?> arguments,
        IReadOnlyDictionary<string, string?> environment,
        string argumentName,
        string environmentName,
        double defaultValue)
    {
        var text = Optional(
            arguments,
            environment,
            argumentName,
            environmentName,
            defaultValue.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
        if (!double.TryParse(
                text,
                System.Globalization.NumberStyles.AllowDecimalPoint,
                System.Globalization.CultureInfo.InvariantCulture,
                out var value) ||
            value <= 0 ||
            value > 120)
            throw new ArgumentException(
                $"Timeout '--{argumentName}' must be greater than 0 and at most 120 minutes.");
        return value;
    }

    private static Uri NormalizeEndpoint(Uri endpoint) =>
        new(endpoint.GetLeftPart(UriPartial.Authority).TrimEnd('/') + "/");

    public static IReadOnlyDictionary<string, string?> ReadEnvironment()
    {
        var names = new[]
        {
            "STEWARD_DEVBOX_ENDPOINT",
            "STEWARD_DEVBOX_PROJECT",
            "STEWARD_DEVBOX_POOL",
            "STEWARD_DEVBOX_USER",
            "STEWARD_DEVBOX_BOX_NAME",
            "STEWARD_DEVBOX_EVIDENCE_DIRECTORY",
            "STEWARD_DEVBOX_LIVE_ACCEPTANCE",
            "STEWARD_DEVBOX_DELETE_EVIDENCE_BOX",
            "STEWARD_DEVBOX_CREATE_TIMEOUT_MINUTES",
            "STEWARD_DEVBOX_RDP_CONNECT_TIMEOUT_MINUTES",
            "STEWARD_DEVBOX_RDP_LOGIN_TIMEOUT_MINUTES"
        };
        return names.ToDictionary(
            x => x,
            Environment.GetEnvironmentVariable,
            StringComparer.Ordinal);
    }
}
