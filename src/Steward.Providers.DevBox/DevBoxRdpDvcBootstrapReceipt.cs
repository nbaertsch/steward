using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Domain;
using Steward.Providers.Abstractions;

namespace Steward.Providers.DevBox;

public sealed record DevBoxRdpDvcPreConnectReadiness(
    int Version,
    string ScheduledTaskState,
    bool EndpointProcessRunning,
    string RemoteState,
    int ProcessId,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    int NextGeneration,
    DateTimeOffset UpdatedAtUtc);

public sealed record DevBoxRdpDvcBootstrapReceipt(
    int Version,
    ProviderOperationId OperationId,
    string BundleVersion,
    string ArchiveSha256,
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    IReadOnlyList<Guid> ConnectionNonces,
    DateTimeOffset ObservedAtUtc,
    DevBoxRdpDvcPreConnectReadiness RemoteReadiness,
    bool PreConnectReady,
    bool SecretsExcluded);

public sealed record DevBoxRdpDvcReceiptSignature(
    string Identity,
    string PublicKeySha256,
    string Signature);

public sealed record AttestedDevBoxRdpDvcBootstrapReceipt(
    int Version,
    DevBoxRdpDvcBootstrapReceipt Receipt,
    DevBoxRdpDvcReceiptSignature? Node,
    DevBoxRdpDvcReceiptSignature Control);

public sealed record DevBoxRdpDvcBootstrapReceiptExpectation(
    ProviderOperationId OperationId,
    string BundleVersion,
    string ArchiveSha256,
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    IReadOnlyList<Guid> ConnectionNonces)
{
    public static DevBoxRdpDvcBootstrapReceiptExpectation From(
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle)
    {
        request.Validate();
        bundle.Validate();
        return new(
            request.OperationId,
            bundle.Manifest.Version,
            bundle.ArchiveSha256,
            request.SessionId,
            request.HostId,
            request.IncarnationId,
            request.ConnectionNonces.ToArray());
    }
}

public static class DevBoxRdpDvcBootstrapReceipts
{
    private static readonly JsonSerializerOptions CanonicalJson =
        CreateJson(indented: false);
    private static readonly JsonSerializerOptions Json =
        CreateJson(indented: true);

    public static DevBoxRdpDvcBootstrapReceipt Create(
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle,
        ProviderOperationResult result,
        DevBoxRdpDvcReadinessObservation readiness)
    {
        request.Validate();
        bundle.Validate();
        readiness.Validate(request);
        if (result.Status is not (
                ProviderOperationStatus.Succeeded or
                ProviderOperationStatus.Running) ||
            result.Handle?.OperationId != request.OperationId ||
            result.Handle.IdempotencyKey != request.IdempotencyKey)
            throw new InvalidOperationException(
                "A successful exact bootstrap operation is required.");
        if (!IsPreConnectReady(readiness))
            throw new InvalidOperationException(
                "The scheduled RDP DVC endpoint is not in exact pre-connect readiness.");
        return new(
            1,
            request.OperationId,
            bundle.Manifest.Version,
            bundle.ArchiveSha256,
            request.SessionId,
            request.HostId,
            request.IncarnationId,
            request.ConnectionNonces.ToArray(),
            DateTimeOffset.UtcNow,
            new(
                1,
                readiness.ScheduledTaskState,
                readiness.EndpointProcessRunning,
                readiness.Receipt.State,
                readiness.Receipt.ProcessId,
                readiness.Receipt.SessionId,
                readiness.Receipt.HostId,
                readiness.Receipt.NodeIncarnationId,
                readiness.Receipt.NextGeneration,
                readiness.Receipt.UpdatedAtUtc),
            true,
            true);
    }

    public static DevBoxRdpDvcBootstrapReceipt CreateDeploymentPending(
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle,
        ProviderOperationResult result)
    {
        request.Validate();
        bundle.Validate();
        if (result.Status != ProviderOperationStatus.Running ||
            result.Handle?.OperationId != request.OperationId ||
            result.Handle.IdempotencyKey != request.IdempotencyKey)
            throw new InvalidOperationException(
                "An exact running bootstrap operation is required.");
        var observed = DateTimeOffset.UtcNow;
        return new(
            1,
            request.OperationId,
            bundle.Manifest.Version,
            bundle.ArchiveSha256,
            request.SessionId,
            request.HostId,
            request.IncarnationId,
            request.ConnectionNonces.ToArray(),
            observed,
            new(
                1,
                "Running",
                false,
                "deploymentPending",
                0,
                request.SessionId,
                request.HostId.Value,
                request.IncarnationId.Value,
                0,
                observed),
            false,
            true);
    }

    public static AttestedDevBoxRdpDvcBootstrapReceipt Attest(
        DevBoxRdpDvcBootstrapReceipt receipt,
        string nodeIdentity,
        ECDsa nodeKey,
        string controlIdentity,
        ECDsa controlKey)
    {
        ValidateIdentity(nodeIdentity, nameof(nodeIdentity));
        ValidateIdentity(controlIdentity, nameof(controlIdentity));
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            receipt,
            CanonicalJson);
        try
        {
            return new(
                1,
                receipt,
                Sign(nodeIdentity, nodeKey, canonical),
                Sign(controlIdentity, controlKey, canonical));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static AttestedDevBoxRdpDvcBootstrapReceipt AttestPending(
        DevBoxRdpDvcBootstrapReceipt receipt,
        string controlIdentity,
        ECDsa controlKey)
    {
        if (receipt.PreConnectReady ||
            receipt.RemoteReadiness.RemoteState != "deploymentPending")
            throw new InvalidOperationException(
                "Only deployment-pending receipts may omit node attestation.");
        ValidateIdentity(controlIdentity, nameof(controlIdentity));
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            receipt,
            CanonicalJson);
        try
        {
            return new(
                1,
                receipt,
                null,
                Sign(controlIdentity, controlKey, canonical));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static DevBoxRdpDvcBootstrapReceipt Verify(
        AttestedDevBoxRdpDvcBootstrapReceipt attested,
        DevBoxRdpDvcBootstrapReceiptExpectation expected,
        string expectedNodeIdentity,
        ReadOnlySpan<byte> nodePublicKey,
        string expectedControlIdentity,
        ReadOnlySpan<byte> controlPublicKey)
    {
        ValidateIdentity(expectedNodeIdentity, nameof(expectedNodeIdentity));
        ValidateIdentity(
            expectedControlIdentity,
            nameof(expectedControlIdentity));
        var receipt = attested.Receipt;
        if (attested.Version != 1 ||
            receipt.Version != 1 ||
            receipt.OperationId != expected.OperationId ||
            receipt.BundleVersion != expected.BundleVersion ||
            !FixedHexEquals(
                receipt.ArchiveSha256,
                expected.ArchiveSha256) ||
            receipt.SessionId != expected.SessionId ||
            receipt.HostId != expected.HostId ||
            receipt.NodeIncarnationId != expected.NodeIncarnationId ||
            !receipt.ConnectionNonces.SequenceEqual(
                expected.ConnectionNonces) ||
            !receipt.SecretsExcluded ||
            !(receipt.PreConnectReady
                ? IsPreConnectReady(receipt.RemoteReadiness)
                : IsDeploymentPending(receipt.RemoteReadiness)) ||
            receipt.RemoteReadiness.SessionId != expected.SessionId ||
            receipt.RemoteReadiness.HostId != expected.HostId.Value ||
            receipt.RemoteReadiness.NodeIncarnationId !=
                expected.NodeIncarnationId.Value ||
            receipt.PreConnectReady &&
            (attested.Node is null ||
             !string.Equals(
                 attested.Node.Identity,
                 expectedNodeIdentity,
                 StringComparison.Ordinal)) ||
            !receipt.PreConnectReady &&
            attested.Node is not null ||
            !string.Equals(
                attested.Control.Identity,
                expectedControlIdentity,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Attested RDP DVC bootstrap receipt does not match its expected identity.");
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            receipt,
            CanonicalJson);
        try
        {
            if (attested.Node is not null)
                VerifySignature(
                    attested.Node,
                    nodePublicKey,
                    canonical);
            VerifySignature(
                attested.Control,
                controlPublicKey,
                canonical);
            return receipt;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static async Task<AttestedDevBoxRdpDvcBootstrapReceipt>
        LoadAttestedAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath) ||
            (File.GetAttributes(fullPath) &
             FileAttributes.ReparsePoint) != 0 ||
            new FileInfo(fullPath).Length is <= 0 or > 4 * 1024 * 1024)
            throw new InvalidDataException(
                "Attested RDP DVC bootstrap receipt file is invalid.");
        await using var stream = File.OpenRead(fullPath);
        try
        {
            return await JsonSerializer.DeserializeAsync<
                       AttestedDevBoxRdpDvcBootstrapReceipt>(
                       stream,
                       CanonicalJson,
                       cancellationToken)
                       .ConfigureAwait(false)
                   ?? throw new InvalidDataException(
                       "Attested RDP DVC bootstrap receipt is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Attested RDP DVC bootstrap receipt is malformed.",
                exception);
        }
    }

    public static Task SaveAsync(
        string path,
        DevBoxRdpDvcBootstrapReceipt receipt,
        CancellationToken cancellationToken) =>
        SaveCoreAsync(path, receipt, cancellationToken);

    public static Task SaveAsync(
        string path,
        AttestedDevBoxRdpDvcBootstrapReceipt receipt,
        CancellationToken cancellationToken) =>
        SaveCoreAsync(path, receipt, cancellationToken);

    private static DevBoxRdpDvcReceiptSignature Sign(
        string identity,
        ECDsa key,
        ReadOnlySpan<byte> canonical)
    {
        var publicKey = key.ExportSubjectPublicKeyInfo();
        try
        {
            return new(
                identity,
                Convert.ToHexString(SHA256.HashData(publicKey))
                    .ToLowerInvariant(),
                Convert.ToBase64String(
                    key.SignData(
                        canonical,
                        HashAlgorithmName.SHA256)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static void VerifySignature(
        DevBoxRdpDvcReceiptSignature signature,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> canonical)
    {
        if (publicKey.Length is 0 or > 2048 ||
            string.IsNullOrWhiteSpace(signature.PublicKeySha256) ||
            string.IsNullOrWhiteSpace(signature.Signature) ||
            signature.Signature.Length > 512)
            throw new InvalidDataException(
                "Bootstrap receipt signature is invalid.");
        if (!FixedHexEquals(
                signature.PublicKeySha256,
                Convert.ToHexString(SHA256.HashData(publicKey))))
            throw new InvalidDataException(
                "Bootstrap receipt signing key does not match.");
        byte[]? decoded = null;
        try
        {
            decoded = Convert.FromBase64String(signature.Signature);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length ||
                !verifier.VerifyData(
                    canonical,
                    decoded,
                    HashAlgorithmName.SHA256))
                throw new InvalidDataException(
                    "Bootstrap receipt signature is invalid.");
        }
        catch (Exception exception)
            when (exception is
                FormatException or
                CryptographicException)
        {
            throw new InvalidDataException(
                "Bootstrap receipt signature is invalid.",
                exception);
        }
        finally
        {
            if (decoded is not null)
                CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static bool FixedHexEquals(string? value, string expected)
    {
        if (value is null || value.Length != expected.Length)
            return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(value),
                Convert.FromHexString(expected));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsPreConnectReady(
        DevBoxRdpDvcReadinessObservation readiness) =>
        readiness.ScheduledTaskState.Equals(
            "Queued",
            StringComparison.OrdinalIgnoreCase) &&
        !readiness.EndpointProcessRunning &&
        !readiness.DvcEndpointReady &&
        readiness.Receipt.State == "waitingForActiveRdpSession" &&
        readiness.Receipt.NextGeneration == 0 &&
        readiness.Receipt.AuthenticatedGenerations.Count == 0;

    private static bool IsPreConnectReady(
        DevBoxRdpDvcPreConnectReadiness readiness) =>
        readiness.Version == 1 &&
        readiness.ScheduledTaskState.Equals(
            "Queued",
            StringComparison.OrdinalIgnoreCase) &&
        !readiness.EndpointProcessRunning &&
        readiness.RemoteState == "waitingForActiveRdpSession" &&
        readiness.ProcessId == 0 &&
        readiness.NextGeneration == 0 &&
        readiness.UpdatedAtUtc <= DateTimeOffset.UtcNow.AddMinutes(5) &&
        readiness.UpdatedAtUtc >=
            DateTimeOffset.UtcNow.Subtract(TimeSpan.FromHours(24));

    private static bool IsDeploymentPending(
        DevBoxRdpDvcPreConnectReadiness readiness) =>
        readiness.Version == 1 &&
        readiness.ScheduledTaskState.Equals(
            "Running",
            StringComparison.OrdinalIgnoreCase) &&
        !readiness.EndpointProcessRunning &&
        readiness.RemoteState == "deploymentPending" &&
        readiness.ProcessId == 0 &&
        readiness.NextGeneration == 0 &&
        readiness.UpdatedAtUtc <= DateTimeOffset.UtcNow.AddMinutes(5) &&
        readiness.UpdatedAtUtc >=
            DateTimeOffset.UtcNow.Subtract(TimeSpan.FromHours(24));

    private static async Task SaveCoreAsync<T>(
        string path,
        T receipt,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException(
                "Receipt path has no directory.",
                nameof(path));
        Directory.CreateDirectory(directory);
        var pending = fullPath + ".new";
        await using (var stream = new FileStream(
                         pending,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await JsonSerializer.SerializeAsync(
                    stream,
                    receipt,
                    Json,
                    cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        File.Move(pending, fullPath, overwrite: true);
    }

    private static void ValidateIdentity(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 256 ||
            value.Any(char.IsControl))
            throw new ArgumentException(
                "Receipt signing identity is invalid.",
                name);
    }

    private static JsonSerializerOptions CreateJson(bool indented)
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = indented
        };
        options.Converters.Add(new ProviderOperationIdConverter());
        options.Converters.Add(new HostIdConverter());
        options.Converters.Add(new NodeIncarnationIdConverter());
        return options;
    }

    private sealed class ProviderOperationIdConverter :
        JsonConverter<ProviderOperationId>
    {
        public override ProviderOperationId Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options) =>
            ProviderOperationId.Parse(
                reader.GetString()
                ?? throw new JsonException(
                    "Provider operation ID is missing."));

        public override void Write(
            Utf8JsonWriter writer,
            ProviderOperationId value,
            JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString());
    }

    private sealed class HostIdConverter : JsonConverter<HostId>
    {
        public override HostId Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options) =>
            HostId.Parse(
                reader.GetString()
                ?? throw new JsonException("Host ID is missing."));

        public override void Write(
            Utf8JsonWriter writer,
            HostId value,
            JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString());
    }

    private sealed class NodeIncarnationIdConverter :
        JsonConverter<NodeIncarnationId>
    {
        public override NodeIncarnationId Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options) =>
            NodeIncarnationId.Parse(
                reader.GetString()
                ?? throw new JsonException(
                    "Node incarnation ID is missing."));

        public override void Write(
            Utf8JsonWriter writer,
            NodeIncarnationId value,
            JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString());
    }
}
