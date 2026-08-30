namespace Steward.RdpDvc.Server.Windows;

public sealed record ServerOptions(
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    string AuthenticationKeyFile,
    string NonceSequenceFile,
    string ReadinessReceiptFile,
    string? NodeSigningKeyFile,
    string? NodeIdentity,
    string? ControlSigningKeyFile,
    string? ControlIdentity,
    bool Once,
    TimeSpan Timeout,
    string? NodeHostConfigFile,
    string? PortableStateRoot,
    string? CredentialVaultRoot)
{
    public static ServerOptions Parse(string[] arguments)
    {
        var values = new Dictionary<string, string>(
            StringComparer.Ordinal);
        var once = false;
        for (var index = 0; index < arguments.Length; index++)
        {
            var argument = arguments[index];
            if (argument == "--once")
            {
                if (once)
                    throw new ArgumentException(
                        "'--once' was specified more than once.");
                once = true;
                continue;
            }
            if (argument is not (
                    "--session-id" or
                    "--host-id" or
                    "--incarnation-id" or
                    "--auth-key-file" or
                    "--nonce-sequence-file" or
                    "--readiness-receipt-file" or
                    "--node-signing-key-file" or
                    "--node-identity" or
                    "--control-signing-key-file" or
                    "--control-identity" or
                    "--timeout-seconds" or
                    "--node-host-config" or
                    "--portable-state-root" or
                    "--credential-vault-root") ||
                index + 1 >= arguments.Length ||
                !values.TryAdd(
                    argument,
                    arguments[++index]))
                throw new ArgumentException(
                    $"Unknown, duplicated, or incomplete argument '{argument}'.");
        }
        if (!Guid.TryParse(
                Required(values, "--session-id"),
                out var sessionId) ||
            sessionId == Guid.Empty ||
            !Guid.TryParse(
                Required(values, "--host-id"),
                out var hostId) ||
            hostId == Guid.Empty ||
            !Guid.TryParse(
                Required(values, "--incarnation-id"),
                out var incarnationId) ||
            incarnationId == Guid.Empty)
            throw new ArgumentException(
                "Session, Host, and incarnation IDs must be nonempty GUIDs.");
        var keyFile = RegularFile(
            Required(values, "--auth-key-file"),
            "authentication key");
        var nonceFile = RegularFile(
            Required(values, "--nonce-sequence-file"),
            "nonce sequence");
        var receiptFile = Path.GetFullPath(
            Required(values, "--readiness-receipt-file"));
        if (!Path.IsPathFullyQualified(receiptFile) ||
            (File.Exists(receiptFile) &&
             (File.GetAttributes(receiptFile) &
              FileAttributes.ReparsePoint) != 0))
            throw new ArgumentException(
                "The readiness receipt path must be absolute and regular.");
        var nodeSigning = Optional(values, "--node-signing-key-file");
        var nodeIdentity = Optional(values, "--node-identity");
        var controlSigning = Optional(values, "--control-signing-key-file");
        var controlIdentity = Optional(values, "--control-identity");
        if (new[]
            {
                nodeSigning,
                nodeIdentity,
                controlSigning,
                controlIdentity
            }.Count(value => value is not null) is not (0 or 4))
            throw new ArgumentException(
                "Secure transport signing options must be supplied together.");
        var seconds = 30;
        if (values.TryGetValue(
                "--timeout-seconds",
                out var timeoutText) &&
            (!int.TryParse(timeoutText, out seconds) ||
             seconds is < 1 or > 300))
            throw new ArgumentException(
                "The timeout must be between 1 and 300 seconds.");
        var nodeHostConfig = Optional(values, "--node-host-config");
        var portableStateRoot = Optional(values, "--portable-state-root");
        var credentialVaultRoot = Optional(values, "--credential-vault-root");
        if (nodeHostConfig is not null)
        {
            if (nodeSigning is null)
                throw new ArgumentException(
                    "--node-host-config requires signed secure transport options.");
            nodeHostConfig = RegularFile(nodeHostConfig, "node host config");
            if (portableStateRoot is null || credentialVaultRoot is null)
                throw new ArgumentException(
                    "--node-host-config requires --portable-state-root and --credential-vault-root.");
            if (!Path.IsPathFullyQualified(Path.GetFullPath(portableStateRoot)))
                throw new ArgumentException(
                    "--portable-state-root must be fully qualified.");
            if (!Path.IsPathFullyQualified(Path.GetFullPath(credentialVaultRoot)))
                throw new ArgumentException(
                    "--credential-vault-root must be fully qualified.");
            portableStateRoot = Path.GetFullPath(portableStateRoot);
            credentialVaultRoot = Path.GetFullPath(credentialVaultRoot);
        }
        return new(
            sessionId,
            hostId,
            incarnationId,
            keyFile,
            nonceFile,
            receiptFile,
            nodeSigning is null
                ? null
                : RegularFile(nodeSigning, "node signing key"),
            nodeIdentity,
            controlSigning is null
                ? null
                : RegularFile(controlSigning, "control signing key"),
            controlIdentity,
            once,
            TimeSpan.FromSeconds(seconds),
            nodeHostConfig,
            portableStateRoot,
            credentialVaultRoot);
    }

    private static string RegularFile(string value, string description)
    {
        var path = Path.GetFullPath(value);
        if (!Path.IsPathFullyQualified(path) ||
            !File.Exists(path) ||
            (File.GetAttributes(path) &
             FileAttributes.ReparsePoint) != 0)
            throw new ArgumentException(
                $"The {description} file must be an absolute, regular file.");
        return path;
    }

    private static string Required(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var value) &&
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException(
                $"Required argument '{name}' is missing.");

    private static string? Optional(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var value) &&
        !string.IsNullOrWhiteSpace(value)
            ? value
            : null;
}
