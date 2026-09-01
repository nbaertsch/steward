using System.Security.Cryptography;
using System.Text.Json;
using Steward.Transport;

namespace Steward.RdpDvc.Server.Windows;

public sealed record ServerOptions(
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    string AuthenticationKeyFile,
    string? NonceSequenceFile,
    string? ReconnectLedgerFile,
    string? V1MigrationAuthorizationFile,
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
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web);

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
                    "--reconnect-ledger-file" or
                    "--v1-migration-authorization-file" or
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
        var nonceValue = Optional(values, "--nonce-sequence-file");
        var ledgerValue = Optional(values, "--reconnect-ledger-file");
        var migrationValue = Optional(
            values,
            "--v1-migration-authorization-file");
        if ((nonceValue is null) == (ledgerValue is null))
            throw new ArgumentException(
                "Exactly one v1 nonce sequence or v2 reconnect ledger must be supplied.");
        var nonceFile = nonceValue is null
            ? null
            : RegularFile(nonceValue, "nonce sequence");
        var reconnectLedgerFile = ledgerValue is null
            ? null
            : WritableStatePath(ledgerValue, "reconnect ledger");
        var migrationFile = migrationValue is null
            ? null
            : RegularFile(
                migrationValue,
                "v1 migration authorization");
        if (nonceFile is null && migrationFile is not null)
            throw new ArgumentException(
                "V1 migration authorization is only valid with retained nonce state.");
        if (nonceFile is not null && migrationFile is null)
            throw new ArgumentException(
                "Retained v1 nonce state requires signed migration authorization.");
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
        if ((reconnectLedgerFile is not null || nonceFile is not null) &&
            nodeSigning is null)
            throw new ArgumentException(
                "Reconnect lanes require the full signed secure transport configuration.");
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
        var result = new ServerOptions(
            sessionId,
            hostId,
            incarnationId,
            keyFile,
            nonceFile,
            reconnectLedgerFile,
            migrationFile,
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
        result.ValidateProtocolState();
        return result;
    }

    internal void ValidateProtocolState()
    {
        if (NonceSequenceFile is null)
            return;
        try
        {
            var nonceBytes = File.ReadAllBytes(NonceSequenceFile);
            var sequence = JsonSerializer.Deserialize<
                DvcConnectionNonceSequence>(nonceBytes, Json) ??
                throw new InvalidDataException(
                    "The retained v1 nonce inventory is empty.");
            var authorizationBytes = File.ReadAllBytes(
                V1MigrationAuthorizationFile ??
                throw new InvalidDataException(
                    "The retained v1 migration authorization is missing."));
            var authorization =
                RetainedV1MigrationAuthorizationCodec.Decode(
                    authorizationBytes);
            var keyBytes = File.ReadAllBytes(
                NodeSigningKeyFile ??
                throw new InvalidDataException(
                    "The Node signing key is missing."));
            try
            {
                using var signer = ECDsa.Create();
                signer.ImportPkcs8PrivateKey(keyBytes, out var read);
                if (read != keyBytes.Length)
                    throw new CryptographicException(
                        "The Node signing key contains trailing data.");
                try
                {
                    _ = RetainedV1MigrationAuthorizationCodec.Validate(
                        authorization,
                        signer,
                        nonceBytes,
                        SessionId,
                        HostId,
                        NodeIncarnationId,
                        sequence.Nonces.Count,
                        sequence.NextIndex);
                }
                catch (Exception exception)
                    when (exception is
                        InvalidDataException or
                        CryptographicException &&
                        sequence.NextIndex > 0 &&
                        authorization.Body.NextIndex ==
                            sequence.NextIndex - 1)
                {
                    var priorBytes = JsonSerializer.SerializeToUtf8Bytes(
                        sequence with
                        {
                            NextIndex = authorization.Body.NextIndex
                        },
                        Json);
                    try
                    {
                        _ = RetainedV1MigrationAuthorizationCodec.Validate(
                            authorization,
                            signer,
                            priorBytes,
                            SessionId,
                            HostId,
                            NodeIncarnationId,
                            sequence.Nonces.Count,
                            authorization.Body.NextIndex);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(priorBytes);
                    }
                    RefreshV1MigrationAuthorization(
                        sequence,
                        nonceBytes,
                        authorization.Body.RetainedEndpointVersion,
                        signer);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }
        catch (Exception exception)
            when (exception is
                IOException or
                InvalidDataException or
                JsonException or
                FormatException or
                CryptographicException)
        {
            throw new ArgumentException(
                "The retained v1 migration authorization is invalid.",
                exception);
        }
    }

    internal void RefreshV1MigrationAuthorization()
    {
        if (NonceSequenceFile is null)
            return;
        var nonceBytes = File.ReadAllBytes(NonceSequenceFile);
        var sequence = JsonSerializer.Deserialize<
            DvcConnectionNonceSequence>(nonceBytes, Json) ??
            throw new InvalidDataException(
                "The retained v1 nonce inventory is empty.");
        var authorization = RetainedV1MigrationAuthorizationCodec.Decode(
            File.ReadAllBytes(V1MigrationAuthorizationFile!));
        var keyBytes = File.ReadAllBytes(NodeSigningKeyFile!);
        try
        {
            using var signer = ECDsa.Create();
            signer.ImportPkcs8PrivateKey(keyBytes, out var read);
            if (read != keyBytes.Length)
                throw new CryptographicException(
                    "The Node signing key contains trailing data.");
            RefreshV1MigrationAuthorization(
                sequence,
                nonceBytes,
                authorization.Body.RetainedEndpointVersion,
                signer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonceBytes);
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    private void RefreshV1MigrationAuthorization(
        DvcConnectionNonceSequence sequence,
        ReadOnlySpan<byte> nonceBytes,
        string retainedEndpointVersion,
        ECDsa signer)
    {
        var updated = RetainedV1MigrationAuthorizationCodec.Create(
            new(
                1,
                retainedEndpointVersion,
                SessionId,
                HostId,
                NodeIncarnationId,
                sequence.Nonces.Count,
                sequence.NextIndex,
                Convert.ToHexString(SHA256.HashData(nonceBytes))),
            signer);
        var encoded = RetainedV1MigrationAuthorizationCodec.Encode(updated);
        var pending = V1MigrationAuthorizationFile! + ".new";
        try
        {
            File.WriteAllBytes(pending, encoded);
            File.Move(
                pending,
                V1MigrationAuthorizationFile!,
                overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }

    private static string WritableStatePath(
        string value,
        string description)
    {
        if (!Path.IsPathFullyQualified(value))
            throw new ArgumentException(
                $"The {description} path must be absolute.");
        var path = Path.GetFullPath(value);
        if (File.Exists(path) &&
            File.GetAttributes(path).HasFlag(
                FileAttributes.ReparsePoint))
            throw new ArgumentException(
                $"The {description} path must be regular.");
        var directory = Path.GetDirectoryName(path) ??
            throw new ArgumentException(
                $"The {description} path has no directory.");
        if (Directory.Exists(directory) &&
            File.GetAttributes(directory).HasFlag(
                FileAttributes.ReparsePoint))
            throw new ArgumentException(
                $"The {description} directory must be regular.");
        return path;
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
