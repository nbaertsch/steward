using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Domain;

namespace Steward.Transport;

public enum TransportEndpointRole : byte { Control = 1, Node = 2 }

public enum SecureHandshakeError
{
    Malformed,
    BoundsExceeded,
    UnsupportedKey,
    IdentityMismatch,
    InvalidSignature,
    SessionBindingMismatch
}

public sealed class SecureHandshakeException(
    SecureHandshakeError error,
    string message,
    Exception? innerException = null) : CryptographicException(message, innerException)
{
    public SecureHandshakeError Error { get; } = error;
}

public static class EndpointKeyFingerprint
{
    public static string Compute(ReadOnlySpan<byte> subjectPublicKeyInfo) =>
        Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo));
}

public interface IEndpointSigningKey
{
    string Identity { get; }
    ReadOnlyMemory<byte> ExportPublicKey();
    byte[] Sign(ReadOnlySpan<byte> data);
}

public sealed class EcdsaEndpointSigningKey(string identity, ECDsa key) : IEndpointSigningKey, IDisposable
{
    public string Identity { get; } = string.IsNullOrWhiteSpace(identity)
        ? throw new ArgumentException("An identity is required.", nameof(identity))
        : identity;

    public ReadOnlyMemory<byte> ExportPublicKey() => key.ExportSubjectPublicKeyInfo();
    public byte[] Sign(ReadOnlySpan<byte> data) => key.SignData(data, HashAlgorithmName.SHA256);
    public void Dispose() => key.Dispose();

    public static EcdsaEndpointSigningKey Create(string identity) =>
        new(identity, ECDsa.Create(ECCurve.NamedCurves.nistP256));
}

public sealed record ExpectedPeerIdentity(string Identity, ReadOnlyMemory<byte> SigningPublicKey)
{
    public ExpectedPeerIdentity Validate()
    {
        if (string.IsNullOrWhiteSpace(Identity) || SigningPublicKey.IsEmpty)
            throw new ArgumentException("The expected peer identity and public key are required.");
        return this;
    }
}

internal sealed record ReconnectBindingWire(
    int Version,
    Guid RouteId,
    Guid HostId,
    Guid NodeIncarnationId,
    long ReconnectGeneration,
    Guid AttemptId,
    int RdpSessionId,
    string CarrierTranscriptSha256);

internal sealed record HelloWire(
    Guid SessionId,
    Guid NodeIncarnationId,
    int ProtocolMajor,
    int ProtocolMinor,
    string[] SupportedFeatures,
    string[] RequiredFeatures,
    Dictionary<StreamKind, long> ResumeCursors,
    TransportLimits Limits,
    ReconnectBindingWire? ReconnectBinding);

internal sealed record HandshakeWire(
    int Version,
    TransportEndpointRole Role,
    string Identity,
    byte[] SigningPublicKey,
    byte[] EphemeralPublicKey,
    HelloWire Hello,
    byte[] Signature);

internal static class SecureTransportProtocol
{
    internal const byte HandshakeRecord = 1;
    internal const byte CiphertextRecord = 2;
    internal const int TagSize = 16;
    internal const int MaximumHandshakeBytes = 16 * 1024;
    private const int MaximumIdentityCharacters = 256;
    private const int MaximumFeatures = 64;
    private const int MaximumFeatureCharacters = 128;
    private const int MaximumPublicKeyBytes = 512;
    private const int MaximumSignatureBytes = 256;
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal static HelloWire ToWire(SessionHello hello) => new(
        hello.SessionId,
        hello.NodeIncarnationId.Value,
        hello.ProtocolMajor,
        hello.ProtocolMinor,
        [.. hello.SupportedFeatures.Order(StringComparer.Ordinal)],
        [.. hello.RequiredFeatures.Order(StringComparer.Ordinal)],
        hello.ResumeCursors.ToDictionary(),
        hello.Limits,
        hello.ReconnectBinding is { } binding
            ? new(
                binding.Version,
                binding.RouteId,
                binding.HostId.Value,
                binding.NodeIncarnationId.Value,
                binding.ReconnectGeneration,
                binding.AttemptId,
                binding.RdpSessionId,
                binding.CarrierTranscriptSha256)
            : null);

    internal static SessionHello FromWire(HelloWire hello) => new(
        hello.SessionId,
        new NodeIncarnationId(hello.NodeIncarnationId),
        hello.ProtocolMajor,
        hello.ProtocolMinor,
        hello.SupportedFeatures.ToHashSet(StringComparer.Ordinal),
        hello.RequiredFeatures.ToHashSet(StringComparer.Ordinal),
        hello.ResumeCursors,
        hello.Limits,
        hello.ReconnectBinding is { } binding
            ? new(
                binding.Version,
                new HostId(binding.HostId),
                new NodeIncarnationId(binding.NodeIncarnationId),
                binding.ReconnectGeneration,
                binding.AttemptId,
                binding.RdpSessionId,
                binding.CarrierTranscriptSha256)
            {
                RouteId = binding.RouteId
            }
            : null);

    internal static byte[] CreateHandshake(
        TransportEndpointRole role,
        IEndpointSigningKey signingKey,
        SessionHello hello,
        ECDiffieHellman ephemeral)
    {
        ValidateHello(ToWire(hello));
        var publicKey = signingKey.ExportPublicKey().ToArray();
        if (signingKey.Identity.Length > MaximumIdentityCharacters ||
            publicKey.Length is < 64 or > MaximumPublicKeyBytes)
            throw new SecureHandshakeException(SecureHandshakeError.BoundsExceeded, "Local handshake identity or key exceeds protocol bounds.");
        var unsigned = new HandshakeWire(
            1, role, signingKey.Identity, publicKey,
            ephemeral.ExportSubjectPublicKeyInfo(), ToWire(hello), []);
        var signature = signingKey.Sign(SerializeUnsigned(unsigned));
        var payload = JsonSerializer.SerializeToUtf8Bytes(unsigned with { Signature = signature });
        var result = new byte[payload.Length + 1];
        result[0] = HandshakeRecord;
        payload.CopyTo(result.AsSpan(1));
        if (result.Length > MaximumHandshakeBytes)
            throw new SecureHandshakeException(SecureHandshakeError.BoundsExceeded, "Local handshake exceeds the protocol bound.");
        return result;
    }

    internal static HandshakeWire ParseAndVerifyHandshake(
        ReadOnlySpan<byte> record,
        TransportEndpointRole localRole,
        ExpectedPeerIdentity expectedPeer,
        SessionHello localHello)
    {
        var handshake = ParseBoundedHandshake(record);
        if (handshake.Version != 1 || !Enum.IsDefined(handshake.Role) || handshake.Role == localRole ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(Encoding.UTF8.GetBytes(handshake.Identity)),
                SHA256.HashData(Encoding.UTF8.GetBytes(expectedPeer.Identity))) ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(handshake.SigningPublicKey),
                SHA256.HashData(expectedPeer.SigningPublicKey.Span)))
            throw new SecureHandshakeException(SecureHandshakeError.IdentityMismatch, "The peer identity does not match the enrolled identity.");
        VerifySignature(handshake);
        var localWire = ToWire(localHello);
        ValidateHello(localWire);
        if (handshake.Hello.SessionId != localWire.SessionId ||
            handshake.Hello.NodeIncarnationId != localWire.NodeIncarnationId ||
            handshake.Hello.ReconnectBinding != localWire.ReconnectBinding)
            throw new SecureHandshakeException(
                SecureHandshakeError.SessionBindingMismatch,
                "The signed session, Node incarnation, or reconnect binding differs.");
        return handshake;
    }

    internal static (byte[] Send, byte[] Receive, string Binding) DeriveKeys(
        ECDiffieHellman localEphemeral,
        HandshakeWire remote,
        ReadOnlySpan<byte> localHandshake,
        ReadOnlySpan<byte> remoteHandshake,
        TransportEndpointRole localRole)
    {
        byte[] secret;
        try
        {
            using var remoteKey = ECDiffieHellman.Create();
            remoteKey.ImportSubjectPublicKeyInfo(remote.EphemeralPublicKey, out var read);
            if (read != remote.EphemeralPublicKey.Length || remoteKey.KeySize != 256)
                throw new CryptographicException("Trailing ECDH key data.");
            secret = localEphemeral.DeriveRawSecretAgreement(remoteKey.PublicKey);
        }
        catch (CryptographicException ex)
        {
            throw new SecureHandshakeException(SecureHandshakeError.UnsupportedKey, "The peer ECDH key is invalid.", ex);
        }
        var transcriptHash = ComputeTranscriptHash(localHandshake, remoteHandshake, localRole);
        var info = new byte[
            "steward-direct-transport-v1"u8.Length + transcriptHash.Length];
        "steward-direct-transport-v1"u8.CopyTo(info);
        transcriptHash.CopyTo(
            info.AsSpan("steward-direct-transport-v1"u8.Length));
        var keys = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 64, transcriptHash, info);
        CryptographicOperations.ZeroMemory(secret);
        CryptographicOperations.ZeroMemory(info);
        var controlToNode = keys[..32];
        var nodeToControl = keys[32..];
        var binding = Convert.ToHexString(transcriptHash);
        CryptographicOperations.ZeroMemory(keys);
        return localRole == TransportEndpointRole.Control
            ? (controlToNode, nodeToControl, binding)
            : (nodeToControl, controlToNode, binding);
    }

    internal static byte[] Encrypt(
        ReadOnlySpan<byte> key,
        TransportEndpointRole sender,
        Guid sessionId,
        long sequence,
        ReadOnlySpan<byte> plaintext)
    {
        var result = new byte[1 + 8 + plaintext.Length + TagSize];
        result[0] = CiphertextRecord;
        BinaryPrimitives.WriteInt64BigEndian(result.AsSpan(1, 8), sequence);
        Span<byte> nonce = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(nonce, (uint)sender);
        BinaryPrimitives.WriteInt64BigEndian(nonce[4..], sequence);
        var aad = CreateAad(sessionId, sender, sequence);
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, result.AsSpan(9, plaintext.Length), result.AsSpan(9 + plaintext.Length), aad);
        return result;
    }

    internal static byte[] Decrypt(
        ReadOnlySpan<byte> key,
        TransportEndpointRole sender,
        Guid sessionId,
        long expectedSequence,
        ReadOnlySpan<byte> record)
    {
        if (record.Length < 1 + 8 + TagSize || record[0] != CiphertextRecord)
            throw new CryptographicException("Invalid encrypted record.");
        var sequence = BinaryPrimitives.ReadInt64BigEndian(record.Slice(1, 8));
        if (sequence != expectedSequence)
            throw new TransportProtocolException(TransportError.InvalidSequence, "Encrypted records must be contiguous.");
        var ciphertextLength = record.Length - 9 - TagSize;
        var plaintext = new byte[ciphertextLength];
        Span<byte> nonce = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(nonce, (uint)sender);
        BinaryPrimitives.WriteInt64BigEndian(nonce[4..], sequence);
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, record.Slice(9, ciphertextLength), record[^TagSize..], plaintext,
            CreateAad(sessionId, sender, sequence));
        return plaintext;
    }

    internal static byte[] SerializeFrame(TransportFrame frame)
    {
        var result = new byte[16 + 16 + 1 + 8 + 8 + 4 + frame.Payload.Length];
        frame.SessionId.TryWriteBytes(result);
        frame.NodeIncarnationId.Value.TryWriteBytes(result.AsSpan(16));
        result[32] = (byte)frame.Stream;
        BinaryPrimitives.WriteInt64BigEndian(result.AsSpan(33), frame.Sequence);
        BinaryPrimitives.WriteInt64BigEndian(result.AsSpan(41), frame.Cursor);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(49), frame.Payload.Length);
        frame.Payload.Span.CopyTo(result.AsSpan(53));
        return result;
    }

    internal static TransportFrame DeserializeFrame(ReadOnlySpan<byte> value)
    {
        if (value.Length < 53)
            throw new TransportProtocolException(TransportError.InvalidSequence, "The encrypted frame is malformed.");
        var length = BinaryPrimitives.ReadInt32BigEndian(value.Slice(49, 4));
        if (length < 0 || value.Length != 53 + length)
            throw new TransportProtocolException(TransportError.InvalidSequence, "The encrypted frame length is invalid.");
        var stream = (StreamKind)value[32];
        if (!Enum.IsDefined(stream))
            throw new TransportProtocolException(TransportError.InvalidSequence, "The encrypted frame stream kind is undefined.");
        return new TransportFrame(
            new Guid(value[..16]), new NodeIncarnationId(new Guid(value.Slice(16, 16))),
            stream, BinaryPrimitives.ReadInt64BigEndian(value.Slice(33, 8)),
            BinaryPrimitives.ReadInt64BigEndian(value.Slice(41, 8)), value[53..].ToArray());
    }

    private static byte[] SerializeUnsigned(HandshakeWire value) =>
        JsonSerializer.SerializeToUtf8Bytes(value with { Signature = [] });

    internal static string GetHandshakeSigningKeyFingerprint(ReadOnlySpan<byte> record) =>
        EndpointKeyFingerprint.Compute(ParseBoundedHandshake(record).SigningPublicKey);

    internal static void VerifySelfSignedHandshake(
        ReadOnlySpan<byte> record,
        TransportEndpointRole expectedRole,
        string expectedSigningKeyFingerprint)
    {
        var handshake = ParseBoundedHandshake(record);
        if (handshake.Role != expectedRole ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(handshake.SigningPublicKey),
                Convert.FromHexString(expectedSigningKeyFingerprint)))
            throw new SecureHandshakeException(
                SecureHandshakeError.IdentityMismatch,
                "The handshake role or signing key does not match the expected peer.");
        VerifySignature(handshake);
    }

    internal static byte[] ComputeTranscriptHash(
        ReadOnlySpan<byte> localHandshake,
        ReadOnlySpan<byte> remoteHandshake,
        TransportEndpointRole localRole)
    {
        _ = ParseBoundedHandshake(localHandshake);
        _ = ParseBoundedHandshake(remoteHandshake);
        var localCanonical = JsonSerializer.SerializeToUtf8Bytes(ParseBoundedHandshake(localHandshake), StrictJson);
        var remoteCanonical = JsonSerializer.SerializeToUtf8Bytes(ParseBoundedHandshake(remoteHandshake), StrictJson);
        var control = localRole == TransportEndpointRole.Control ? localCanonical : remoteCanonical;
        var node = localRole == TransportEndpointRole.Node ? localCanonical : remoteCanonical;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("steward-direct-transport-transcript-v1"u8);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, control.Length);
        hash.AppendData(length);
        hash.AppendData(control);
        BinaryPrimitives.WriteInt32BigEndian(length, node.Length);
        hash.AppendData(length);
        hash.AppendData(node);
        return hash.GetHashAndReset();
    }

    private static HandshakeWire ParseBoundedHandshake(ReadOnlySpan<byte> record)
    {
        if (record.Length < 2 || record.Length > MaximumHandshakeBytes || record[0] != HandshakeRecord)
            throw new SecureHandshakeException(
                record.Length > MaximumHandshakeBytes ? SecureHandshakeError.BoundsExceeded : SecureHandshakeError.Malformed,
                "The peer handshake record is invalid.");
        HandshakeWire handshake;
        try
        {
            handshake = JsonSerializer.Deserialize<HandshakeWire>(record[1..], StrictJson)
                ?? throw new JsonException("Null handshake.");
        }
        catch (JsonException ex)
        {
            throw new SecureHandshakeException(SecureHandshakeError.Malformed, "The peer handshake is malformed.", ex);
        }
        ValidateHello(handshake.Hello);
        if (string.IsNullOrWhiteSpace(handshake.Identity) ||
            handshake.Identity.Length > MaximumIdentityCharacters ||
            handshake.SigningPublicKey.Length is < 64 or > MaximumPublicKeyBytes ||
            handshake.EphemeralPublicKey.Length is < 64 or > MaximumPublicKeyBytes ||
            handshake.Signature.Length is < 48 or > MaximumSignatureBytes)
            throw new SecureHandshakeException(SecureHandshakeError.BoundsExceeded, "The peer handshake exceeds identity or cryptographic bounds.");
        return handshake;
    }

    private static void VerifySignature(HandshakeWire handshake)
    {
        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(handshake.SigningPublicKey, out var read);
            if (read != handshake.SigningPublicKey.Length || verifier.KeySize != 256 ||
                !verifier.VerifyData(SerializeUnsigned(handshake), handshake.Signature, HashAlgorithmName.SHA256))
                throw new SecureHandshakeException(SecureHandshakeError.InvalidSignature, "The peer handshake signature is invalid.");
        }
        catch (SecureHandshakeException) { throw; }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new SecureHandshakeException(SecureHandshakeError.UnsupportedKey, "The peer signing key is invalid.", ex);
        }
    }

    private static void ValidateHello(HelloWire hello)
    {
        if (hello.SessionId == Guid.Empty || hello.NodeIncarnationId == Guid.Empty ||
            hello.SupportedFeatures.Length > MaximumFeatures ||
            hello.RequiredFeatures.Length > MaximumFeatures ||
            hello.ResumeCursors.Count > Enum.GetValues<StreamKind>().Length ||
            hello.SupportedFeatures.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > MaximumFeatureCharacters) ||
            hello.RequiredFeatures.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > MaximumFeatureCharacters) ||
            hello.ResumeCursors.Any(value => !Enum.IsDefined(value.Key) || value.Value < 0))
            throw new SecureHandshakeException(SecureHandshakeError.BoundsExceeded, "The handshake hello exceeds protocol bounds.");
        hello.Limits.Validate();
        if (hello.ReconnectBinding is { } binding)
            _ = new ReconnectTransportBinding(
                    binding.Version,
                    new HostId(binding.HostId),
                    new NodeIncarnationId(binding.NodeIncarnationId),
                    binding.ReconnectGeneration,
                    binding.AttemptId,
                    binding.RdpSessionId,
                    binding.CarrierTranscriptSha256)
            {
                RouteId = binding.RouteId
            }
                .Validate(new NodeIncarnationId(hello.NodeIncarnationId));
    }

    private static byte[] CreateAad(Guid sessionId, TransportEndpointRole role, long sequence)
    {
        var aad = new byte[25];
        sessionId.TryWriteBytes(aad);
        aad[16] = (byte)role;
        BinaryPrimitives.WriteInt64BigEndian(aad.AsSpan(17), sequence);
        return aad;
    }
}
