using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Steward.Transport;

public sealed record RdpDvcBootstrapEnvelopePayload(
    Guid OperationId,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    byte[] AuthenticationKey,
    byte[] NodeSigningPublicKey);

public static class RdpDvcBootstrapEnvelope
{
    private const int HeaderBytes = 1 + 16 * 4 + 32 + 2;
    private const byte Version = 1;

    public static byte[] Encrypt(
        RSA publicKey,
        RdpDvcBootstrapEnvelopePayload payload)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        Validate(payload);
        var encoded = new byte[
            HeaderBytes + payload.NodeSigningPublicKey.Length];
        try
        {
            encoded[0] = Version;
            payload.OperationId.TryWriteBytes(encoded.AsSpan(1, 16));
            payload.SessionId.TryWriteBytes(encoded.AsSpan(17, 16));
            payload.HostId.TryWriteBytes(encoded.AsSpan(33, 16));
            payload.NodeIncarnationId.TryWriteBytes(
                encoded.AsSpan(49, 16));
            payload.AuthenticationKey.CopyTo(encoded, 65);
            BinaryPrimitives.WriteUInt16BigEndian(
                encoded.AsSpan(97, 2),
                checked((ushort)payload.NodeSigningPublicKey.Length));
            payload.NodeSigningPublicKey.CopyTo(encoded, HeaderBytes);
            return publicKey.Encrypt(
                encoded,
                RSAEncryptionPadding.OaepSHA256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    public static RdpDvcBootstrapEnvelopePayload Decrypt(
        RSA privateKey,
        ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        if (ciphertext.IsEmpty || ciphertext.Length > 1024)
            throw new ArgumentException(
                "The bootstrap envelope ciphertext is invalid.",
                nameof(ciphertext));
        var cleartext = privateKey.Decrypt(
            ciphertext,
            RSAEncryptionPadding.OaepSHA256);
        try
        {
            if (cleartext.Length < HeaderBytes ||
                cleartext[0] != Version)
                throw new InvalidDataException(
                    "The bootstrap envelope is malformed.");
            var publicKeyBytes = BinaryPrimitives.ReadUInt16BigEndian(
                cleartext.AsSpan(97, 2));
            if (publicKeyBytes is < 64 or > 512 ||
                cleartext.Length != HeaderBytes + publicKeyBytes)
                throw new InvalidDataException(
                    "The bootstrap envelope key is malformed.");
            var payload = new RdpDvcBootstrapEnvelopePayload(
                new(cleartext.AsSpan(1, 16)),
                new(cleartext.AsSpan(17, 16)),
                new(cleartext.AsSpan(33, 16)),
                new(cleartext.AsSpan(49, 16)),
                cleartext.AsSpan(65, 32).ToArray(),
                cleartext.AsSpan(HeaderBytes, publicKeyBytes).ToArray());
            Validate(payload);
            return payload;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
        }
    }

    private static void Validate(RdpDvcBootstrapEnvelopePayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (payload.OperationId == Guid.Empty ||
            payload.SessionId == Guid.Empty ||
            payload.HostId == Guid.Empty ||
            payload.NodeIncarnationId == Guid.Empty ||
            payload.AuthenticationKey.Length != 32 ||
            payload.NodeSigningPublicKey.Length is < 64 or > 512)
            throw new ArgumentException(
                "The bootstrap envelope payload is invalid.",
                nameof(payload));
    }
}
