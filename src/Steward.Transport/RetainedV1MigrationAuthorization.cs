using System.Security.Cryptography;
using System.Text.Json;

namespace Steward.Transport;

public sealed record RetainedV1MigrationAuthorizationBody(
    int Version,
    string RetainedEndpointVersion,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    int NonceCount,
    int NextIndex,
    string InventorySha256)
{
    public const string SupportedEndpointVersion = "1.0.23";

    public RetainedV1MigrationAuthorizationBody Validate()
    {
        if (Version != 1 ||
            !string.Equals(
                RetainedEndpointVersion,
                SupportedEndpointVersion,
                StringComparison.Ordinal) ||
            SessionId == Guid.Empty ||
            HostId == Guid.Empty ||
            NodeIncarnationId == Guid.Empty ||
            NonceCount is < 2 or > 256 ||
            NextIndex < 0 ||
            NextIndex > NonceCount ||
            InventorySha256.Length != 64 ||
            !InventorySha256.All(Uri.IsHexDigit))
            throw new InvalidDataException(
                "The retained v1 migration authorization is invalid.");
        return this;
    }
}

public sealed record RetainedV1MigrationAuthorization(
    RetainedV1MigrationAuthorizationBody Body,
    string Signature);

public static class RetainedV1MigrationAuthorizationCodec
{
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web);

    public static RetainedV1MigrationAuthorization Create(
        RetainedV1MigrationAuthorizationBody body,
        ECDsa signingKey)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        _ = body.Validate();
        var canonical = JsonSerializer.SerializeToUtf8Bytes(body, Json);
        try
        {
            var signature = signingKey.SignData(
                canonical,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            try
            {
                return new(body, Convert.ToBase64String(signature));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static byte[] Encode(
        RetainedV1MigrationAuthorization authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        _ = authorization.Body.Validate();
        if (string.IsNullOrWhiteSpace(authorization.Signature))
            throw new InvalidDataException(
                "The retained v1 migration signature is missing.");
        return JsonSerializer.SerializeToUtf8Bytes(authorization, Json);
    }

    public static RetainedV1MigrationAuthorization Decode(
        ReadOnlySpan<byte> content)
    {
        if (content.Length is <= 0 or > 16 * 1024)
            throw new InvalidDataException(
                "The retained v1 migration authorization exceeds its bound.");
        var authorization = JsonSerializer.Deserialize<
            RetainedV1MigrationAuthorization>(content, Json) ??
            throw new InvalidDataException(
                "The retained v1 migration authorization is empty.");
        _ = authorization.Body.Validate();
        if (string.IsNullOrWhiteSpace(authorization.Signature))
            throw new InvalidDataException(
                "The retained v1 migration signature is missing.");
        return authorization;
    }

    public static RetainedV1MigrationAuthorization Validate(
        RetainedV1MigrationAuthorization authorization,
        ECDsa signingKey,
        ReadOnlySpan<byte> nonceInventory,
        Guid sessionId,
        Guid hostId,
        Guid nodeIncarnationId,
        int nonceCount,
        int nextIndex)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(signingKey);
        var body = authorization.Body.Validate();
        if (body.SessionId != sessionId ||
            body.HostId != hostId ||
            body.NodeIncarnationId != nodeIncarnationId ||
            body.NonceCount != nonceCount ||
            body.NextIndex != nextIndex ||
            !string.Equals(
                body.InventorySha256,
                Convert.ToHexString(SHA256.HashData(nonceInventory)),
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "The retained v1 migration authorization does not match the nonce inventory.");
        var signature = Convert.FromBase64String(authorization.Signature);
        var canonical = JsonSerializer.SerializeToUtf8Bytes(body, Json);
        try
        {
            if (!signingKey.VerifyData(
                    canonical,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence))
                throw new CryptographicException(
                    "The retained v1 migration authorization signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(canonical);
        }
        return authorization;
    }
}
