using Steward.Domain;

namespace Steward.RdpDvc.LiveAcceptance;

internal sealed record LiveAcceptanceOptions(
    Uri DevBoxEndpoint,
    string Project,
    string User,
    string DevBox,
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string EvidencePipeName,
    string EvidenceKeyFile,
    string DvcAuthenticationKeyFile,
    string EvidenceTicketDirectory,
    string ControlSigningPrivateKeyFile,
    string ControlSigningPublicKeyFile,
    string ControlIdentity,
    string NodeSigningPublicKeyFile,
    string NodeTransportSigningPublicKeyFile,
    string NodeIdentity,
    string BootstrapReceiptFile,
    Guid BootstrapOperationId,
    string BootstrapBundleVersion,
    string BootstrapArchiveSha256,
    string? BootstrapDeployExecutable,
    string? BootstrapDeployArgumentsFile,
    string? BootstrapDeployToolSha256,
    string BootstrapDeployConsent,
    TimeSpan BootstrapDeployTimeout,
    string EvidenceDirectory,
    string ConnectConsent,
    string CloudReadConsent,
    TimeSpan Timeout)
{
    internal const string RequiredConnectConsent =
        "I_UNDERSTAND_RDCORE_LIVE_ACCEPTANCE_CONNECTS_WITHOUT_VIEW";
    internal const string RequiredCloudReadConsent =
        "I_UNDERSTAND_RDCORE_LIVE_ACCEPTANCE_READS_EXISTING_CONNECTION_METADATA";
    internal const string RequiredBootstrapDeployConsent =
        "I_UNDERSTAND_BOOTSTRAP_DEPLOY_MUTATES_THE_RETAINED_DEV_BOX_CUSTOMIZATION";

    internal bool HasRequiredConsent =>
        string.Equals(
            ConnectConsent,
            RequiredConnectConsent,
            StringComparison.Ordinal) &&
        string.Equals(
            CloudReadConsent,
            RequiredCloudReadConsent,
            StringComparison.Ordinal);

    internal bool InvokeBootstrapDeploy =>
        BootstrapDeployExecutable is not null;

    internal static bool HasRequiredConsentValue(
        string[] arguments,
        IReadOnlyDictionary<string, string?> environment)
    {
        string? connect = EnvironmentValue(
            environment,
            "STEWARD_RDCORE_LIVE_ACCEPTANCE");
        string? cloudRead = EnvironmentValue(
            environment,
            "STEWARD_RDCORE_LIVE_CLOUD_READ");
        for (var index = 0; index + 1 < arguments.Length; index++)
        {
            if (arguments[index] == "--consent")
                connect = arguments[index + 1];
            else if (arguments[index] == "--cloud-read-consent")
                cloudRead = arguments[index + 1];
        }
        return string.Equals(
                connect,
                RequiredConnectConsent,
                StringComparison.Ordinal) &&
            string.Equals(
                cloudRead,
                RequiredCloudReadConsent,
                StringComparison.Ordinal);
    }

    internal static LiveAcceptanceOptions Parse(
        string[] arguments,
        IReadOnlyDictionary<string, string?> environment)
    {
        var values = ParseArguments(arguments);
        var endpointText = Required(
            values,
            environment,
            "endpoint",
            "STEWARD_DEVBOX_ENDPOINT");
        if (!Uri.TryCreate(
                endpointText,
                UriKind.Absolute,
                out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps ||
            endpoint.Port != 443 ||
            endpoint.UserInfo.Length != 0 ||
            endpoint.Fragment.Length != 0)
            throw new ArgumentException(
                "The Dev Box endpoint must be absolute HTTPS on port 443.");

        var timeoutText = Optional(
            values,
            environment,
            "timeout-seconds",
            "STEWARD_RDCORE_LIVE_TIMEOUT_SECONDS",
            "120");
        if (!int.TryParse(timeoutText, out var timeout) ||
            timeout is < 10 or > 300)
            throw new ArgumentException(
                "The timeout must be between 10 and 300 seconds.");
        var evidencePipeName = Required(
            values,
            environment,
            "evidence-pipe-name",
            "STEWARD_DVC_EVIDENCE_PIPE_NAME");
        if (evidencePipeName.Length > 128 ||
            evidencePipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new ArgumentException(
                "The DVC evidence pipe name is invalid.");

        var deployExecutable = OptionalNull(
            values,
            environment,
            "bootstrap-deploy-executable",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_EXECUTABLE");
        var deployArguments = OptionalNull(
            values,
            environment,
            "bootstrap-deploy-arguments-file",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_ARGUMENTS_FILE");
        var deployToolSha256 = OptionalNull(
            values,
            environment,
            "bootstrap-deploy-tool-sha256",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_TOOL_SHA256");
        var deployConsent = Optional(
            values,
            environment,
            "bootstrap-deploy-consent",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_CONSENT",
            "");
        if (new[]
            {
                deployExecutable,
                deployArguments,
                deployToolSha256
            }.Count(static value => value is not null) is not (0 or 3))
            throw new ArgumentException(
                "Bootstrap deploy executable, arguments file, and tool SHA-256 must be supplied together.");
        if (deployExecutable is not null &&
            !string.Equals(
                deployConsent,
                RequiredBootstrapDeployConsent,
                StringComparison.Ordinal))
            throw new ArgumentException(
                "Invoking bootstrap deployment requires its exact independent mutation consent.");
        var deployTimeoutText = Optional(
            values,
            environment,
            "bootstrap-deploy-timeout-seconds",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_TIMEOUT_SECONDS",
            "1800");
        if (!int.TryParse(deployTimeoutText, out var deployTimeout) ||
            deployTimeout is < 30 or > 7200)
            throw new ArgumentException(
                "Bootstrap deployment timeout must be between 30 and 7200 seconds.");

        return new(
            NormalizeEndpoint(endpoint),
            Identifier(values, environment, "project", "STEWARD_DEVBOX_PROJECT"),
            Identifier(values, environment, "user", "STEWARD_DEVBOX_USER"),
            Identifier(values, environment, "box", "STEWARD_DEVBOX_BOX_NAME"),
            RequiredGuid(
                values,
                environment,
                "session-id",
                "STEWARD_RDCORE_SESSION_ID"),
            new HostId(RequiredGuid(
                values,
                environment,
                "host-id",
                "STEWARD_RDCORE_HOST_ID")),
            new NodeIncarnationId(RequiredGuid(
                values,
                environment,
                "incarnation-id",
                "STEWARD_RDCORE_NODE_INCARNATION_ID")),
            evidencePipeName,
            FullPath(Required(
                values,
                environment,
                "evidence-key-file",
                "STEWARD_DVC_EVIDENCE_KEY_FILE")),
            FullPath(Required(
                values,
                environment,
                "dvc-auth-key-file",
                "STEWARD_DVC_AUTH_KEY_FILE")),
            FullPath(Required(
                values,
                environment,
                "evidence-ticket-directory",
                "STEWARD_DVC_EVIDENCE_TICKET_DIRECTORY")),
            FullPath(Required(
                values,
                environment,
                "control-signing-private-key-file",
                "STEWARD_RDCORE_CONTROL_SIGNING_PRIVATE_KEY_FILE")),
            FullPath(Required(
                values,
                environment,
                "control-signing-public-key-file",
                "STEWARD_RDCORE_CONTROL_SIGNING_PUBLIC_KEY_FILE")),
            Identity(
                values,
                environment,
                "control-identity",
                "STEWARD_RDCORE_CONTROL_IDENTITY"),
            FullPath(Required(
                values,
                environment,
                "node-signing-public-key-file",
                "STEWARD_RDCORE_NODE_SIGNING_PUBLIC_KEY_FILE")),
            FullPath(Required(
                values,
                environment,
                "node-transport-signing-public-key-file",
                "STEWARD_RDCORE_NODE_TRANSPORT_SIGNING_PUBLIC_KEY_FILE")),
            Identity(
                values,
                environment,
                "node-identity",
                "STEWARD_RDCORE_NODE_IDENTITY"),
            FullPath(Required(
                values,
                environment,
                "bootstrap-receipt",
                "STEWARD_RDCORE_BOOTSTRAP_RECEIPT")),
            RequiredGuid(
                values,
                environment,
                "bootstrap-operation-id",
                "STEWARD_RDCORE_BOOTSTRAP_OPERATION_ID"),
            Identifier(
                values,
                environment,
                "bootstrap-bundle-version",
                "STEWARD_RDCORE_BOOTSTRAP_BUNDLE_VERSION"),
            Sha256(
                values,
                environment,
                "bootstrap-archive-sha256",
                "STEWARD_RDCORE_BOOTSTRAP_ARCHIVE_SHA256"),
            deployExecutable is null ? null : FullPath(deployExecutable),
            deployArguments is null ? null : FullPath(deployArguments),
            deployToolSha256 is null
                ? null
                : RequireSha256(deployToolSha256, "bootstrap-deploy-tool-sha256"),
            deployConsent,
            TimeSpan.FromSeconds(deployTimeout),
            FullPath(Optional(
                values,
                environment,
                "evidence-directory",
                "STEWARD_RDCORE_LIVE_EVIDENCE_DIRECTORY",
                Path.Combine("artifacts", "rdcore-live-acceptance"))),
            Optional(
                values,
                environment,
                "consent",
                "STEWARD_RDCORE_LIVE_ACCEPTANCE",
                ""),
            Optional(
                values,
                environment,
                "cloud-read-consent",
                "STEWARD_RDCORE_LIVE_CLOUD_READ",
                ""),
            TimeSpan.FromSeconds(timeout));
    }

    internal static IReadOnlyDictionary<string, string?> ReadEnvironment()
    {
        string[] names =
        [
            "STEWARD_DEVBOX_ENDPOINT",
            "STEWARD_DEVBOX_PROJECT",
            "STEWARD_DEVBOX_USER",
            "STEWARD_DEVBOX_BOX_NAME",
            "STEWARD_RDCORE_SESSION_ID",
            "STEWARD_RDCORE_HOST_ID",
            "STEWARD_RDCORE_NODE_INCARNATION_ID",
            "STEWARD_DVC_EVIDENCE_PIPE_NAME",
            "STEWARD_DVC_EVIDENCE_KEY_FILE",
            "STEWARD_DVC_AUTH_KEY_FILE",
            "STEWARD_DVC_EVIDENCE_TICKET_DIRECTORY",
            "STEWARD_RDCORE_CONTROL_SIGNING_PRIVATE_KEY_FILE",
            "STEWARD_RDCORE_CONTROL_SIGNING_PUBLIC_KEY_FILE",
            "STEWARD_RDCORE_CONTROL_IDENTITY",
            "STEWARD_RDCORE_NODE_SIGNING_PUBLIC_KEY_FILE",
            "STEWARD_RDCORE_NODE_TRANSPORT_SIGNING_PUBLIC_KEY_FILE",
            "STEWARD_RDCORE_NODE_IDENTITY",
            "STEWARD_RDCORE_BOOTSTRAP_RECEIPT",
            "STEWARD_RDCORE_BOOTSTRAP_OPERATION_ID",
            "STEWARD_RDCORE_BOOTSTRAP_BUNDLE_VERSION",
            "STEWARD_RDCORE_BOOTSTRAP_ARCHIVE_SHA256",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_EXECUTABLE",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_ARGUMENTS_FILE",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_TOOL_SHA256",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_CONSENT",
            "STEWARD_RDCORE_BOOTSTRAP_DEPLOY_TIMEOUT_SECONDS",
            "STEWARD_RDCORE_LIVE_EVIDENCE_DIRECTORY",
            "STEWARD_RDCORE_LIVE_ACCEPTANCE",
            "STEWARD_RDCORE_LIVE_CLOUD_READ",
            "STEWARD_RDCORE_LIVE_TIMEOUT_SECONDS"
        ];
        return names.ToDictionary(
            static name => name,
            Environment.GetEnvironmentVariable,
            StringComparer.Ordinal);
    }

    private static Dictionary<string, string> ParseArguments(
        string[] arguments)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Length; index++)
        {
            var argument = arguments[index];
            if (!argument.StartsWith("--", StringComparison.Ordinal) ||
                argument.Length == 2 ||
                index + 1 >= arguments.Length ||
                arguments[index + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException(
                    $"Unknown or incomplete argument at position {index + 1}.");
            var name = argument[2..];
            if (!KnownArguments.Contains(name) ||
                !result.TryAdd(name, arguments[++index]))
                throw new ArgumentException(
                    $"Argument '--{name}' is unknown or duplicated.");
        }
        return result;
    }

    private static readonly HashSet<string> KnownArguments =
    [
        "endpoint",
        "project",
        "user",
        "box",
        "session-id",
        "host-id",
        "incarnation-id",
        "evidence-pipe-name",
        "evidence-key-file",
        "dvc-auth-key-file",
        "evidence-ticket-directory",
        "control-signing-private-key-file",
        "control-signing-public-key-file",
        "control-identity",
        "node-signing-public-key-file",
        "node-transport-signing-public-key-file",
        "node-identity",
        "bootstrap-receipt",
        "bootstrap-operation-id",
        "bootstrap-bundle-version",
        "bootstrap-archive-sha256",
        "bootstrap-deploy-executable",
        "bootstrap-deploy-arguments-file",
        "bootstrap-deploy-tool-sha256",
        "bootstrap-deploy-consent",
        "bootstrap-deploy-timeout-seconds",
        "evidence-directory",
        "consent",
        "cloud-read-consent",
        "timeout-seconds"
    ];

    private static Guid RequiredGuid(
        IReadOnlyDictionary<string, string> arguments,
        IReadOnlyDictionary<string, string?> environment,
        string argumentName,
        string environmentName)
    {
        var text = Required(
            arguments,
            environment,
            argumentName,
            environmentName);
        return Guid.TryParse(text, out var value) && value != Guid.Empty
            ? value
            : throw new ArgumentException(
                $"'{argumentName}' must be a nonempty GUID.");
    }

    private static string Identifier(
        IReadOnlyDictionary<string, string> arguments,
        IReadOnlyDictionary<string, string?> environment,
        string argumentName,
        string environmentName)
    {
        var value = Required(
            arguments,
            environment,
            argumentName,
            environmentName);
        if (value.Length > 256)
            throw new ArgumentException(
                $"'{argumentName}' exceeds its bound.");
        return value;
    }

    private static string Identity(
        IReadOnlyDictionary<string, string> arguments,
        IReadOnlyDictionary<string, string?> environment,
        string argumentName,
        string environmentName) =>
        Identifier(
            arguments,
            environment,
            argumentName,
            environmentName);

    private static string Sha256(
        IReadOnlyDictionary<string, string> arguments,
        IReadOnlyDictionary<string, string?> environment,
        string argumentName,
        string environmentName)
    {
        var value = Required(
            arguments,
            environment,
            argumentName,
            environmentName);
        if (value.Length != 64 ||
            value.Any(static character => !Uri.IsHexDigit(character)))
            throw new ArgumentException(
                $"'{argumentName}' must be a SHA-256 hex digest.");
        return value.ToLowerInvariant();
    }

    private static string RequireSha256(string value, string name)
    {
        if (value.Length != 64 ||
            value.Any(static character => !Uri.IsHexDigit(character)))
            throw new ArgumentException(
                $"'{name}' must be a SHA-256 hex digest.");
        return value.ToLowerInvariant();
    }

    private static string Required(
        IReadOnlyDictionary<string, string> arguments,
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
            value.Length > 4096 ||
            value.Any(char.IsControl))
            throw new ArgumentException(
                $"Provide a valid '--{argumentName}' or '{environmentName}'.");
        return value;
    }

    private static string Optional(
        IReadOnlyDictionary<string, string> arguments,
        IReadOnlyDictionary<string, string?> environment,
        string argumentName,
        string environmentName,
        string defaultValue) =>
        arguments.TryGetValue(argumentName, out var value)
            ? value
            : EnvironmentValue(environment, environmentName) ?? defaultValue;

    private static string? OptionalNull(
        IReadOnlyDictionary<string, string> arguments,
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
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static string? EnvironmentValue(
        IReadOnlyDictionary<string, string?> environment,
        string name) =>
        environment.TryGetValue(name, out var value) ? value : null;

    private static Uri NormalizeEndpoint(Uri value) =>
        new(value.GetLeftPart(UriPartial.Authority).TrimEnd('/') + "/");

    private static string FullPath(string value) => Path.GetFullPath(value);
}
