using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Steward.Domain;

namespace Steward.Agents;

public interface IDestinationCertificateRegistry
{
    X509Certificate2 GetEncryptionCertificate(HostId destinationHostId);
    X509Certificate2 GetDecryptionCertificate(HostId destinationHostId);
}

public sealed class RsaOaepDestinationKeyEnvelope : IDestinationKeyEnvelope
{
    private readonly IDestinationCertificateRegistry _certificates;
    private readonly TimeProvider _timeProvider;

    public RsaOaepDestinationKeyEnvelope(
        IDestinationCertificateRegistry certificates,
        TimeProvider? timeProvider = null)
    {
        _certificates = certificates ?? throw new ArgumentNullException(nameof(certificates));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public byte[] WrapKey(HostId destinationHostId, ReadOnlySpan<byte> key)
    {
        if (key.Length != 32) throw new CryptographicException("Checkpoint CEK must be 256 bits.");
        var certificate = _certificates.GetEncryptionCertificate(destinationHostId)
            ?? throw new CryptographicException("Destination encryption certificate is unavailable.");
        ValidateCertificate(certificate, requirePrivateKey: false);
        using var rsa = certificate.GetRSAPublicKey()
            ?? throw new CryptographicException("Destination certificate has no RSA public key.");
        ValidateRsa(rsa);
        return rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
    }

    public byte[] UnwrapKey(HostId destinationHostId, ReadOnlySpan<byte> wrappedKey)
    {
        if (wrappedKey.IsEmpty) throw new CryptographicException("Wrapped checkpoint key is empty.");
        var certificate = _certificates.GetDecryptionCertificate(destinationHostId)
            ?? throw new CryptographicException("Destination decryption certificate is unavailable.");
        ValidateCertificate(certificate, requirePrivateKey: true);
        using var rsa = certificate.GetRSAPrivateKey()
            ?? throw new CryptographicException("Destination certificate has no RSA private key.");
        ValidateRsa(rsa);
        var key = rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
        if (key.Length != 32)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException("Unwrapped checkpoint CEK has an invalid length.");
        }
        return key;
    }

    private void ValidateCertificate(X509Certificate2 certificate, bool requirePrivateKey)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        if (now < certificate.NotBefore.ToUniversalTime() || now > certificate.NotAfter.ToUniversalTime())
            throw new CryptographicException("Destination encryption certificate is not currently valid.");
        if (requirePrivateKey && !certificate.HasPrivateKey)
            throw new CryptographicException("Destination decryption certificate requires a private key.");
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        if (usage is null || (usage.KeyUsages & X509KeyUsageFlags.KeyEncipherment) == 0)
            throw new CryptographicException("Destination certificate is not authorized for key encipherment.");
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        if (constraints?.CertificateAuthority == true)
            throw new CryptographicException("A certificate-authority certificate cannot wrap checkpoint keys.");
    }

    private static void ValidateRsa(RSA rsa)
    {
        if (rsa.KeySize < 3072)
            throw new CryptographicException("Destination RSA key must be at least 3072 bits.");
    }
}
