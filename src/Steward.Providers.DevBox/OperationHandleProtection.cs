using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Steward.Domain;

namespace Steward.Providers.DevBox;

public interface IDevBoxOperationHandleProtector
{
    string Protect(
        string canonicalPayload,
        ProviderOperationId operationId,
        string idempotencyKey,
        string provider);

    string Unprotect(
        string protectedPayload,
        ProviderOperationId operationId,
        string idempotencyKey,
        string provider);
}

public sealed class HmacDevBoxOperationHandleProtector : IDevBoxOperationHandleProtector
{
    private readonly byte[] _key;

    public HmacDevBoxOperationHandleProtector(ReadOnlySpan<byte> key)
    {
        if (key.Length < 32)
            throw new ArgumentException("Dev Box operation handle HMAC key must be at least 256 bits.", nameof(key));
        _key = key.ToArray();
    }

    public string Protect(
        string canonicalPayload,
        ProviderOperationId operationId,
        string idempotencyKey,
        string provider)
    {
        var payloadBytes = Encoding.UTF8.GetBytes(canonicalPayload);
        var signature = HMACSHA256.HashData(_key, SignedBytes(payloadBytes, operationId, idempotencyKey, provider));
        return $"{Convert.ToBase64String(payloadBytes)}.{Convert.ToBase64String(signature)}";
    }

    public string Unprotect(
        string protectedPayload,
        ProviderOperationId operationId,
        string idempotencyKey,
        string provider)
    {
        try
        {
            var parts = protectedPayload.Split('.');
            if (parts.Length != 2)
                throw new FormatException();
            var payload = Convert.FromBase64String(parts[0]);
            var supplied = Convert.FromBase64String(parts[1]);
            var expected = HMACSHA256.HashData(_key, SignedBytes(payload, operationId, idempotencyKey, provider));
            if (supplied.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(supplied, expected))
                throw new CryptographicException();
            return Encoding.UTF8.GetString(payload);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            throw new ArgumentException("Dev Box operation handle authentication failed.", nameof(protectedPayload), exception);
        }
    }

    private static byte[] SignedBytes(
        byte[] payload,
        ProviderOperationId operationId,
        string idempotencyKey,
        string provider)
    {
        using var stream = new MemoryStream();
        Write(stream, operationId.ToString());
        Write(stream, idempotencyKey);
        Write(stream, provider);
        stream.Write(payload);
        return stream.ToArray();
    }

    private static void Write(Stream stream, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        stream.Write(length);
        stream.Write(bytes);
    }
}
