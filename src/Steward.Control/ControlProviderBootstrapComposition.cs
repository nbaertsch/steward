using System.Collections.Concurrent;
using System.Net;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Developer.DevCenter;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Steward.Application;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;
using Steward.Transport;

namespace Steward.Control;

public sealed class ControlProviderBootstrapOptions
{
    public bool Enabled { get; set; }
    public string StateRoot { get; set; } = string.Empty;
    public TimeSpan EnrollmentClaimLifetime { get; set; } =
        TimeSpan.FromMinutes(5);
    public string PackageSource { get; set; } = string.Empty;
    public string PackageContentSha256 { get; set; } = string.Empty;
    public string PackageSignature { get; set; } = string.Empty;
    public string PackageSigner { get; set; } = string.Empty;
    public string PackageSigningPublicKeyPemPath { get; set; } =
        string.Empty;
    public int MaximumPackageBytes { get; set; } =
        RdpDvcBootstrapBundle.MaximumArchiveBytes;
    public TimeSpan PackageDownloadTimeout { get; set; } =
        TimeSpan.FromMinutes(2);
    public decimal CpuCores { get; set; } = 2;
    public long MemoryBytes { get; set; } = 8L * 1024 * 1024 * 1024;
    public long DiskBytes { get; set; } = 64L * 1024 * 1024 * 1024;
    public int ProcessCount { get; set; } = 16;
    public int ContainerCount { get; set; }
    public int ConcurrencyUnits { get; set; } = 4;
    public List<string> Capabilities { get; set; } =
        ["process", "terminal"];
    public List<string> SetupFingerprints { get; set; } = [];

    public ValidatedControlProviderBootstrapOptions Validate(
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ValidateBounds();
        if (!Enabled)
            return ValidatedControlProviderBootstrapOptions.Unavailable(
                enabled: false,
                "disabled");

        var local = new LocalBootstrapConfiguration();
        configuration.GetSection("Steward:LocalStack").Bind(local);
        var devBox = new LocalDevBoxConfiguration();
        configuration.GetSection("Steward:LocalStack:DevBox").Bind(devBox);
        if (!devBox.Enabled ||
            !local.TransportEnabled ||
            !local.RdpDvcControlCarrierEnabled ||
            Missing(
                local.DataRoot,
                local.TransportIdentity,
                local.TransportPrivateKeyPemPath,
                local.RdpDvcControlCarrierPipeName,
                devBox.Endpoint,
                devBox.OperationHandleHmacKeyEnvironmentVariable,
                PackageSource,
                PackageContentSha256,
                PackageSignature,
                PackageSigner,
                PackageSigningPublicKeyPemPath))
            return ValidatedControlProviderBootstrapOptions.Unavailable(
                enabled: true,
                "incomplete");

        if (!Uri.TryCreate(
                PackageSource,
                UriKind.Absolute,
                out var packageSource) ||
            packageSource.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(packageSource.UserInfo) ||
            packageSource.AbsoluteUri.Length > 2048)
            throw new InvalidOperationException(
                "Control provider bootstrap package source must be bounded HTTPS without user information.");
        if (!Uri.TryCreate(
                devBox.Endpoint,
                UriKind.Absolute,
                out var devCenterEndpoint) ||
            devCenterEndpoint.Scheme != Uri.UriSchemeHttps ||
            devCenterEndpoint.Port != 443 ||
            !string.IsNullOrEmpty(devCenterEndpoint.UserInfo) ||
            devCenterEndpoint.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(devCenterEndpoint.Query) ||
            !string.IsNullOrEmpty(devCenterEndpoint.Fragment) ||
            devCenterEndpoint.AbsoluteUri.Length > 2048 ||
            !devCenterEndpoint.IdnHost.EndsWith(
                ".devcenter.azure.com",
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Control provider bootstrap Dev Center endpoint must be an approved bounded Microsoft Dev Center HTTPS origin.");

        var contentSha256 = NormalizeSha256(
            PackageContentSha256,
            "package content");
        var signature = DecodeBoundedBase64(
            PackageSignature,
            48,
            512,
            "package signature");
        var signingKeyPath = ExistingAbsoluteRegularFile(
            PackageSigningPublicKeyPemPath,
            "package signing public key");
        var controlKeyPath = ExistingAbsoluteRegularFile(
            local.TransportPrivateKeyPemPath,
            "Control signing private key");
        var stateRoot = string.IsNullOrWhiteSpace(StateRoot)
            ? Path.Combine(
                AbsolutePath(local.DataRoot, "Local Stack data root"),
                "provider-bootstrap")
            : AbsolutePath(StateRoot, "provider bootstrap state root");
        ValidateSimpleIdentity(
            local.TransportIdentity,
            128,
            "Control transport identity");
        ValidatePipeName(local.RdpDvcControlCarrierPipeName);
        ValidateEnvironmentVariableName(
            devBox.OperationHandleHmacKeyEnvironmentVariable);

        byte[]? signerPublic = null;
        byte[]? controlPublic = null;
        try
        {
            signerPublic = ReadPublicSigningKey(signingKeyPath);
            var signer = "sha256:" +
                Convert.ToHexStringLower(SHA256.HashData(signerPublic));
            if (!string.Equals(
                    PackageSigner,
                    signer,
                    StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "Control provider bootstrap package signer does not match its configured public key.");
            var signedIdentity = SignedPackageIdentity(
                packageSource,
                contentSha256,
                signer);
            try
            {
                using var verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(
                    signerPublic,
                    out var read);
                if (read != signerPublic.Length ||
                    !verifier.VerifyData(
                        signedIdentity,
                        signature,
                        HashAlgorithmName.SHA256))
                    throw new InvalidOperationException(
                        "Control provider bootstrap package signature is invalid.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signedIdentity);
            }
            controlPublic = ReadControlSigningPublicKey(controlKeyPath);
            var package = new SignedNodePackage(
                packageSource,
                contentSha256,
                PackageSignature,
                signer);
            return new(
                true,
                true,
                "available",
                stateRoot,
                EnrollmentClaimLifetime,
                package,
                devCenterEndpoint,
                devBox.OperationHandleHmacKeyEnvironmentVariable,
                local.TransportIdentity,
                controlKeyPath,
                controlPublic.ToArray(),
                local.RdpDvcControlCarrierPipeName,
                MaximumPackageBytes,
                PackageDownloadTimeout,
                new(
                    CpuCores,
                    MemoryBytes,
                    DiskBytes,
                    processCount: ProcessCount,
                    containerCount: ContainerCount,
                    concurrencyUnits: ConcurrencyUnits),
                Capabilities.ToArray(),
                SetupFingerprints.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
            if (signerPublic is not null)
                CryptographicOperations.ZeroMemory(signerPublic);
            if (controlPublic is not null)
                CryptographicOperations.ZeroMemory(controlPublic);
        }
    }

    internal static byte[] SignedPackageIdentity(
        Uri source,
        string contentSha256,
        string signer) =>
        Encoding.UTF8.GetBytes(
            "Steward.SignedNodePackage.v1\n" +
            source.AbsoluteUri + "\n" +
            contentSha256 + "\n" +
            signer);

    private void ValidateBounds()
    {
        if (EnrollmentClaimLifetime < TimeSpan.FromSeconds(30) ||
            EnrollmentClaimLifetime > TimeSpan.FromMinutes(15))
            throw new InvalidOperationException(
                "Control provider bootstrap claims must live for 30 seconds through 15 minutes.");
        if (MaximumPackageBytes is <= 0 or
            > RdpDvcBootstrapBundle.MaximumArchiveBytes)
            throw new InvalidOperationException(
                "Control provider bootstrap package byte bound is invalid.");
        if (PackageDownloadTimeout < TimeSpan.FromSeconds(5) ||
            PackageDownloadTimeout > TimeSpan.FromMinutes(10))
            throw new InvalidOperationException(
                "Control provider bootstrap package download timeout is invalid.");
        if (CpuCores is <= 0 or > 1024 ||
            MemoryBytes is <= 0 or > 16L * 1024 * 1024 * 1024 * 1024 ||
            DiskBytes is <= 0 or > 64L * 1024 * 1024 * 1024 * 1024 ||
            ProcessCount is <= 0 or > 65_536 ||
            ContainerCount is < 0 or > 65_536 ||
            ConcurrencyUnits is <= 0 or > 65_536)
            throw new InvalidOperationException(
                "Control provider bootstrap Node capacity is outside its bound.");
        ValidateStringSet(Capabilities, 1, 128, "capabilities");
        ValidateStringSet(SetupFingerprints, 0, 256, "setup fingerprints");
    }

    private static void ValidateStringSet(
        IReadOnlyList<string> values,
        int minimum,
        int maximum,
        string name)
    {
        if (values.Count < minimum ||
            values.Count > maximum ||
            values.Any(value =>
                string.IsNullOrWhiteSpace(value) ||
                value.Length > 256 ||
                value.Any(char.IsControl)) ||
            values.Distinct(StringComparer.Ordinal).Count() != values.Count)
            throw new InvalidOperationException(
                $"Control provider bootstrap {name} are invalid.");
    }

    private static bool Missing(params string?[] values) =>
        values.Any(string.IsNullOrWhiteSpace);

    private static string NormalizeSha256(string value, string description)
    {
        if (value.Length != 64 ||
            value.Any(character => !char.IsAsciiHexDigit(character)))
            throw new InvalidOperationException(
                $"Control provider bootstrap {description} SHA-256 is invalid.");
        return value.ToLowerInvariant();
    }

    private static byte[] DecodeBoundedBase64(
        string value,
        int minimumBytes,
        int maximumBytes,
        string description)
    {
        if (value.Length > 4096)
            throw new InvalidOperationException(
                $"Control provider bootstrap {description} exceeds its bound.");
        try
        {
            var decoded = Convert.FromBase64String(value);
            if (decoded.Length < minimumBytes ||
                decoded.Length > maximumBytes)
            {
                CryptographicOperations.ZeroMemory(decoded);
                throw new InvalidOperationException(
                    $"Control provider bootstrap {description} is invalid.");
            }
            return decoded;
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                $"Control provider bootstrap {description} is invalid.",
                exception);
        }
    }

    private static string AbsolutePath(string value, string description)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 32_767 ||
            value.IndexOf('\0') >= 0 ||
            !Path.IsPathFullyQualified(value))
            throw new InvalidOperationException(
                $"Control provider bootstrap {description} must be a bounded absolute path.");
        return Path.GetFullPath(value);
    }

    private static string ExistingAbsoluteRegularFile(
        string value,
        string description)
    {
        var path = AbsolutePath(value, description);
        if (!File.Exists(path) ||
            File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint) ||
            new FileInfo(path).Length is <= 0 or > 1024 * 1024)
            throw new InvalidOperationException(
                $"Control provider bootstrap {description} must be an existing bounded regular file.");
        return path;
    }

    private static byte[] ReadPublicSigningKey(string path)
    {
        using var key = ECDsa.Create();
        byte[]? privateKey = null;
        try
        {
            key.ImportFromPem(File.ReadAllText(path));
            if (key.KeySize != 256)
                throw new CryptographicException();
            try
            {
                privateKey = key.ExportPkcs8PrivateKey();
            }
            catch (CryptographicException)
            {
            }
            if (privateKey is not null)
                throw new InvalidOperationException(
                    "Control provider bootstrap package signer configuration must contain only a public key.");
            return key.ExportSubjectPublicKeyInfo();
        }
        catch (Exception exception)
            when (exception is
                CryptographicException or
                ArgumentException)
        {
            throw new InvalidOperationException(
                "Control provider bootstrap package signing key must be ECDSA P-256.",
                exception);
        }
        finally
        {
            if (privateKey is not null)
                CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private static byte[] ReadControlSigningPublicKey(string path)
    {
        using var key = ECDsa.Create();
        byte[]? privateKey = null;
        try
        {
            key.ImportFromPem(File.ReadAllText(path));
            if (key.KeySize != 256)
                throw new CryptographicException();
            privateKey = key.ExportPkcs8PrivateKey();
            return key.ExportSubjectPublicKeyInfo();
        }
        catch (Exception exception)
            when (exception is
                CryptographicException or
                ArgumentException)
        {
            throw new InvalidOperationException(
                "Control provider bootstrap Control signing key must be a private ECDSA P-256 key.",
                exception);
        }
        finally
        {
            if (privateKey is not null)
                CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private static void ValidateSimpleIdentity(
        string value,
        int maximum,
        string description)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximum ||
            value.Any(character =>
                char.IsControl(character) ||
                character == '"'))
            throw new InvalidOperationException(
                $"Control provider bootstrap {description} is invalid.");
    }

    private static void ValidatePipeName(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 80 ||
            value.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new InvalidOperationException(
                "Control provider bootstrap RDP DVC carrier pipe name is invalid.");
    }

    private static void ValidateEnvironmentVariableName(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 128 ||
            value.Any(character =>
                char.IsControl(character) ||
                character == '='))
            throw new InvalidOperationException(
                "Control provider bootstrap operation-handle environment variable name is invalid.");
    }

    private sealed class LocalBootstrapConfiguration
    {
        public string DataRoot { get; set; } = string.Empty;
        public bool TransportEnabled { get; set; }
        public string TransportIdentity { get; set; } = string.Empty;
        public string TransportPrivateKeyPemPath { get; set; } =
            string.Empty;
        public bool RdpDvcControlCarrierEnabled { get; set; }
        public string RdpDvcControlCarrierPipeName { get; set; } =
            string.Empty;
    }

    private sealed class LocalDevBoxConfiguration
    {
        public bool Enabled { get; set; }
        public string Endpoint { get; set; } = string.Empty;
        public string OperationHandleHmacKeyEnvironmentVariable { get; set; } =
            string.Empty;
    }
}

public sealed record ValidatedControlProviderBootstrapOptions(
    bool Enabled,
    bool Available,
    string Status,
    string? StateRoot,
    TimeSpan EnrollmentClaimLifetime,
    SignedNodePackage? Package,
    Uri? DevCenterEndpoint,
    string? OperationHandleHmacKeyEnvironmentVariable,
    string? ControlIdentity,
    string? ControlSigningPrivateKeyPemPath,
    byte[]? ControlSigningPublicKey,
    string? RdpDvcControlCarrierPipeName,
    int MaximumPackageBytes,
    TimeSpan PackageDownloadTimeout,
    ResourceRequirements? Capacity,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> SetupFingerprints)
{
    internal static ValidatedControlProviderBootstrapOptions Unavailable(
        bool enabled,
        string status) =>
        new(
            enabled,
            false,
            status,
            null,
            TimeSpan.Zero,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            0,
            TimeSpan.Zero,
            null,
            [],
            []);
}

public static class ControlProviderBootstrapComposition
{
    [SupportedOSPlatform("windows")]
    public static IServiceCollection AddStewardControlProviderBootstrap(
        this IServiceCollection services,
        IConfiguration configuration,
        TokenCredential? devBoxCredential = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Control provider bootstrap requires Windows DPAPI.");
        var configured = new ControlProviderBootstrapOptions();
        configuration.GetSection("Control:ProviderBootstrap")
            .Bind(configured);
        var options = configured.Validate(configuration);
        services.AddSingleton(options);
        if (!options.Available)
            return services;
        if (devBoxCredential is null)
            throw new InvalidOperationException(
                "Available Control provider bootstrap requires the Dev Box silent credential.");

        var hmac = ReadHmacKey(
            options.OperationHandleHmacKeyEnvironmentVariable!);
        try
        {
            services.AddSingleton(options.Package!);
            services.AddSingleton<ControlBootstrapProtectedStateStore>();
            services.AddSingleton<DurableEnrollmentClaimIssuer>();
            services.AddSingleton<IEnrollmentClaimIssuer>(provider =>
                provider.GetRequiredService<
                    DurableEnrollmentClaimIssuer>());
            services.AddSingleton<IEnrollmentClaimConsumer>(provider =>
                provider.GetRequiredService<
                    DurableEnrollmentClaimIssuer>());
            services.AddSingleton<
                IDevBoxRdpDvcBootstrapCheckpointProtector,
                DpapiDevBoxRdpDvcBootstrapCheckpointProtector>();
            services.AddSingleton<
                ISecureDurableDevBoxRdpDvcBootstrapStore>(provider =>
                new EncryptedFileDevBoxRdpDvcBootstrapStore(
                    Path.Combine(
                        options.StateRoot!,
                        "deployment-checkpoints"),
                    provider.GetRequiredService<
                        IDevBoxRdpDvcBootstrapCheckpointProtector>()));
            services.AddSingleton<IDevBoxOperationHandleProtector>(
                new HmacDevBoxOperationHandleProtector(hmac));
            services.AddSingleton(provider =>
            {
                var sdk = new DevBoxesClient(
                    options.DevCenterEndpoint!,
                    devBoxCredential);
                return new DevBoxCustomizationClient(
                    options.DevCenterEndpoint!,
                    new AzurePipelineDevBoxCustomizationTransport(
                        sdk.Pipeline));
            });
            services.AddSingleton<DevBoxRdpDvcBootstrapDeployer>();
            services.AddSingleton<
                IControlBootstrapPackageSource,
                HttpsSignedControlBootstrapPackageSource>();
            services.AddSingleton<
                IControlDevBoxBootstrapDeployment,
                ControlDevBoxRdpDvcBootstrapDeployment>();
            services.AddSingleton<
                INodeBootstrapper,
                ControlDevBoxNodeBootstrapper>();
            services.AddSingleton<
                IRoutableNodeEndpointIssuer,
                ControlRdpDvcNodeEndpointIssuer>();
            return services;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hmac);
        }
    }

    private static byte[] ReadHmacKey(string environmentVariable)
    {
        byte[] value;
        try
        {
            value = Convert.FromBase64String(
                Environment.GetEnvironmentVariable(
                    environmentVariable) ?? string.Empty);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                "Control provider bootstrap operation-handle key is invalid.",
                exception);
        }
        if (value.Length < 32 || value.Length > 128)
        {
            CryptographicOperations.ZeroMemory(value);
            throw new InvalidOperationException(
                "Control provider bootstrap operation-handle key must be 256 through 1024 bits.");
        }
        return value;
    }
}

public interface IEnrollmentClaimConsumer
{
    ValueTask ConsumeAsync(
        EnrollmentClaim claim,
        CancellationToken cancellationToken);
}

[SupportedOSPlatform("windows")]
internal sealed class DurableEnrollmentClaimIssuer(
    ValidatedControlProviderBootstrapOptions options) :
    IEnrollmentClaimIssuer,
    IEnrollmentClaimConsumer
{
    private readonly string directory = PrepareDirectory(options, "claims");
    private readonly ConcurrentDictionary<string, SemaphoreSlim> gates =
        new(StringComparer.Ordinal);

    public async ValueTask<EnrollmentClaim> IssueAsync(
        HostId hostId,
        NodeIncarnationId incarnationId,
        string providerResourceId,
        CancellationToken cancellationToken)
    {
        _ = DevBoxProviderResourceIdentity.Parse(providerResourceId);
        if (hostId.Value == Guid.Empty ||
            incarnationId.Value == Guid.Empty)
            throw new ArgumentException(
                "Enrollment claim identity is invalid.");
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(tokenBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        CryptographicOperations.ZeroMemory(tokenBytes);
        var expiresAt = DateTimeOffset.UtcNow +
            options.EnrollmentClaimLifetime;
        var claim = new EnrollmentClaim(
            token,
            expiresAt,
            providerResourceId,
            hostId,
            incarnationId);
        claim.Validate(DateTimeOffset.UtcNow);
        var hash = TokenHash(token);
        var record = new PersistedEnrollmentClaim(
            hash,
            expiresAt,
            providerResourceId,
            hostId.Value,
            incarnationId.Value);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(record);
        byte[]? protectedValue = null;
        try
        {
            protectedValue = ProtectedData.Protect(
                plaintext,
                Entropy("claim", hash),
                DataProtectionScope.CurrentUser);
            await ControlBootstrapStorage.WriteAsync(
                    Path.Combine(directory, hash + ".claim"),
                    protectedValue,
                    cancellationToken,
                    overwrite: false)
                .ConfigureAwait(false);
            return claim;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedValue is not null)
                CryptographicOperations.ZeroMemory(protectedValue);
        }
    }

    public async ValueTask ConsumeAsync(
        EnrollmentClaim claim,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        claim.Validate(DateTimeOffset.UtcNow);
        _ = DevBoxProviderResourceIdentity.Parse(
            claim.ExpectedProviderResourceId);
        var hash = TokenHash(claim.Token);
        var path = Path.Combine(directory, hash + ".claim");
        var gate = gates.GetOrAdd(
            hash,
            static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var protectedValue = await ControlBootstrapStorage.ReadAsync(
                    path,
                    16 * 1024,
                    cancellationToken)
                .ConfigureAwait(false);
            if (protectedValue is null)
                throw new UnauthorizedAccessException(
                    "Enrollment claim is unavailable or was already consumed.");
            byte[]? plaintext = null;
            try
            {
                plaintext = ProtectedData.Unprotect(
                    protectedValue,
                    Entropy("claim", hash),
                    DataProtectionScope.CurrentUser);
                var persisted = JsonSerializer.Deserialize<
                        PersistedEnrollmentClaim>(plaintext)
                    ?? throw new InvalidDataException(
                        "Enrollment claim state is empty.");
                if (!FixedHexEquals(persisted.TokenSha256, hash) ||
                    persisted.ExpiresAt != claim.ExpiresAt ||
                    persisted.ExpiresAt <= DateTimeOffset.UtcNow ||
                    persisted.HostId != claim.HostId.Value ||
                    persisted.NodeIncarnationId !=
                        claim.IncarnationId.Value ||
                    !string.Equals(
                        persisted.ProviderResourceId,
                        claim.ExpectedProviderResourceId,
                        StringComparison.Ordinal))
                    throw new UnauthorizedAccessException(
                        "Enrollment claim binding does not match its durable single-use record.");
                File.Delete(path);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedValue);
                if (plaintext is not null)
                    CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private static string PrepareDirectory(
        ValidatedControlProviderBootstrapOptions options,
        string child)
    {
        if (!options.Available)
            throw new InvalidOperationException(
                "Control provider bootstrap is unavailable.");
        var path = Path.Combine(options.StateRoot!, child);
        ControlBootstrapStorage.PrepareDirectory(path);
        return path;
    }

    private static string TokenHash(string token) =>
        Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static byte[] Entropy(string purpose, string identity) =>
        SHA256.HashData(
            Encoding.UTF8.GetBytes(
                "Steward.Control.ProviderBootstrap.v1\n" +
                purpose + "\n" + identity));

    private static bool FixedHexEquals(string left, string right)
    {
        if (left.Length != right.Length)
            return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(left),
                Convert.FromHexString(right));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private sealed record PersistedEnrollmentClaim(
        string TokenSha256,
        DateTimeOffset ExpiresAt,
        string ProviderResourceId,
        Guid HostId,
        Guid NodeIncarnationId);
}

internal sealed record DevBoxProviderResourceIdentity(
    string Project,
    string User,
    string DevBox)
{
    internal static DevBoxProviderResourceIdentity Parse(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 256 ||
            value.Any(char.IsControl))
            throw new ArgumentException(
                "Dev Box provider resource ID is invalid.",
                nameof(value));
        var parts = value.Split('/');
        if (parts.Length != 3 ||
            !ValidIdentifier(parts[0]) ||
            !ValidUser(parts[1]) ||
            !ValidIdentifier(parts[2]) ||
            !string.Equals(
                value,
                string.Join('/', parts),
                StringComparison.Ordinal))
            throw new ArgumentException(
                "Dev Box provider resource ID must be canonical project/user/name.",
                nameof(value));
        return new(parts[0], parts[1], parts[2]);
    }

    private static bool ValidIdentifier(string value) =>
        value.Length is >= 3 and <= 63 &&
        char.IsAsciiLetterOrDigit(value[0]) &&
        value.All(character =>
            char.IsAsciiLetterOrDigit(character) ||
            character is '-' or '_' or '.');

    private static bool ValidUser(string value) =>
        string.Equals(value, "me", StringComparison.Ordinal) ||
        Guid.TryParseExact(value, "D", out var parsed) &&
        parsed != Guid.Empty &&
        string.Equals(
            value,
            parsed.ToString("D"),
            StringComparison.Ordinal);
}

internal sealed record ControlBootstrapRemoteOutput(
    byte[] AuthenticationKey,
    byte[] NodeSigningPublicKey,
    DateTimeOffset ObservedAt);

internal sealed record PersistedControlBootstrapHandle(
    Guid OperationId,
    string IdempotencyKey,
    string Provider,
    string OpaqueHandle)
{
    internal ProviderOperationHandle ToHandle() =>
        new(
            new ProviderOperationId(OperationId),
            IdempotencyKey,
            Provider,
            OpaqueHandle);

    internal static PersistedControlBootstrapHandle From(
        ProviderOperationHandle handle) =>
        new(
            handle.OperationId.Value,
            handle.IdempotencyKey,
            handle.Provider,
            handle.OpaqueHandle);
}

internal sealed record ControlBootstrapState(
    Guid OperationId,
    string IdempotencyKey,
    string Project,
    string User,
    string DevBox,
    string ProviderResourceId,
    Guid HostId,
    Guid NodeIncarnationId,
    Guid SessionId,
    IReadOnlyList<Guid> ConnectionNonces,
    byte[] IntentAuthenticationKey,
    byte[] IntentNodeSigningPrivateKey,
    byte[] BootstrapEncryptionPrivateKey,
    string PackageSource,
    string PackageContentSha256,
    string PackageSignature,
    string PackageSigner,
    string NodeIdentity,
    string ControlIdentity,
    byte[] ControlSigningPublicKey,
    string ControlCarrierPipeName,
    decimal CpuCores,
    long MemoryBytes,
    long DiskBytes,
    int ProcessCount,
    int ContainerCount,
    int ConcurrencyUnits,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> SetupFingerprints,
    DateTimeOffset CreatedAt,
    PersistedControlBootstrapHandle? LastHandle = null,
    ControlBootstrapRemoteOutput? Output = null)
{
    internal ProviderOperationId StewardOperationId =>
        new(OperationId);

    internal SignedNodePackage Package =>
        new(
            new Uri(PackageSource, UriKind.Absolute),
            PackageContentSha256,
            PackageSignature,
            PackageSigner);

    internal ResourceRequirements Capacity =>
        new(
            CpuCores,
            MemoryBytes,
            DiskBytes,
            processCount: ProcessCount,
            containerCount: ContainerCount,
            concurrencyUnits: ConcurrencyUnits);

    internal static ControlBootstrapState Create(
        BootstrapRequest request,
        DevBoxProviderResourceIdentity identity,
        ValidatedControlProviderBootstrapOptions options)
    {
        var nodeIdentity =
            $"steward-node:{request.Host.Id.Value:N}:" +
            request.Host.NodeIncarnationId.Value.ToString("N");
        var intentAuthentication = RandomNumberGenerator.GetBytes(32);
        using var intentNode = ECDsa.Create(
            ECCurve.NamedCurves.nistP256);
        using var envelope = RSA.Create(2048);
        var fingerprints = options.SetupFingerprints
            .Append("rdp-dvc:" + options.Package!.ContentSha256)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return new(
            request.OperationId.Value,
            request.IdempotencyKey,
            identity.Project,
            identity.User,
            identity.DevBox,
            request.Resource.ProviderResourceId,
            request.Host.Id.Value,
            request.Host.NodeIncarnationId.Value,
            DeriveSessionId(
                request.Host.Id,
                request.Host.NodeIncarnationId),
            [Guid.NewGuid(), Guid.NewGuid()],
            intentAuthentication,
            intentNode.ExportPkcs8PrivateKey(),
            envelope.ExportPkcs8PrivateKey(),
            options.Package.Source.AbsoluteUri,
            options.Package.ContentSha256,
            options.Package.Signature,
            options.Package.Signer,
            nodeIdentity,
            options.ControlIdentity!,
            options.ControlSigningPublicKey!.ToArray(),
            options.RdpDvcControlCarrierPipeName!,
            options.Capacity!.CpuCores,
            options.Capacity.MemoryBytes,
            options.Capacity.DiskBytes,
            options.Capacity.ProcessCount,
            options.Capacity.ContainerCount,
            options.Capacity.ConcurrencyUnits,
            options.Capabilities.ToArray(),
            fingerprints,
            DateTimeOffset.UtcNow);
    }

    internal ControlBootstrapState Validate()
    {
        var identity = DevBoxProviderResourceIdentity.Parse(
            ProviderResourceId);
        if (OperationId == Guid.Empty ||
            string.IsNullOrWhiteSpace(IdempotencyKey) ||
            IdempotencyKey.Length > 256 ||
            identity.Project != Project ||
            identity.User != User ||
            identity.DevBox != DevBox ||
            HostId == Guid.Empty ||
            NodeIncarnationId == Guid.Empty ||
            SessionId != DeriveSessionId(
                new HostId(HostId),
                new NodeIncarnationId(NodeIncarnationId)) ||
            ConnectionNonces.Count != 2 ||
            ConnectionNonces.Any(value => value == Guid.Empty) ||
            ConnectionNonces.Distinct().Count() != 2 ||
            IntentAuthenticationKey.Length != 32 ||
            string.IsNullOrWhiteSpace(NodeIdentity) ||
            NodeIdentity.Length > 128 ||
            string.IsNullOrWhiteSpace(ControlIdentity) ||
            ControlIdentity.Length > 128 ||
            ControlSigningPublicKey.Length is < 64 or > 2048 ||
            string.IsNullOrWhiteSpace(ControlCarrierPipeName) ||
            ControlCarrierPipeName.Length > 80 ||
            CreatedAt > DateTimeOffset.UtcNow.AddMinutes(5) ||
            Capabilities.Count is 0 or > 128 ||
            Capabilities.Distinct(StringComparer.Ordinal).Count() !=
                Capabilities.Count ||
            SetupFingerprints.Count > 256 ||
            SetupFingerprints.Distinct(StringComparer.Ordinal).Count() !=
                SetupFingerprints.Count ||
            Output is not null && LastHandle is null)
            throw new InvalidDataException(
                "Durable Control bootstrap state is invalid.");
        ValidateKeys();
        _ = Package;
        _ = Capacity;
        if (LastHandle is not null &&
            (LastHandle.OperationId != OperationId ||
             LastHandle.IdempotencyKey != IdempotencyKey ||
             LastHandle.Provider !=
                 DevBoxRdpDvcBootstrapPlan.ProviderName ||
             string.IsNullOrWhiteSpace(LastHandle.OpaqueHandle) ||
             LastHandle.OpaqueHandle.Length > 32_768))
            throw new InvalidDataException(
                "Durable Control bootstrap handle identity is invalid.");
        if (Output is not null)
        {
            if (Output.AuthenticationKey.Length != 32 ||
                Output.NodeSigningPublicKey.Length is < 64 or > 512 ||
                Output.ObservedAt < CreatedAt.AddMinutes(-5) ||
                Output.ObservedAt >
                    DateTimeOffset.UtcNow.AddMinutes(5))
                throw new InvalidDataException(
                    "Durable Control bootstrap output is invalid.");
            using var node = ECDsa.Create();
            node.ImportSubjectPublicKeyInfo(
                Output.NodeSigningPublicKey,
                out var read);
            if (read != Output.NodeSigningPublicKey.Length ||
                node.KeySize != 256)
                throw new InvalidDataException(
                    "Durable Control bootstrap Node key is invalid.");
        }
        return this;
    }

    internal void ValidateIntent(
        BootstrapRequest request,
        ValidatedControlProviderBootstrapOptions options)
    {
        var identity = DevBoxProviderResourceIdentity.Parse(
            request.Resource.ProviderResourceId);
        var package = options.Package!;
        if (request.OperationId.Value != OperationId ||
            request.IdempotencyKey != IdempotencyKey ||
            request.Host.Id.Value != HostId ||
            request.Host.NodeIncarnationId.Value !=
                NodeIncarnationId ||
            request.Resource.Name != DevBox ||
            identity.Project != Project ||
            identity.User != User ||
            identity.DevBox != DevBox ||
            request.Resource.ProviderResourceId !=
                ProviderResourceId ||
            request.Package.Source.AbsoluteUri != PackageSource ||
            request.Package.ContentSha256 != PackageContentSha256 ||
            request.Package.Signature != PackageSignature ||
            request.Package.Signer != PackageSigner ||
            package.Source.AbsoluteUri != PackageSource ||
            package.ContentSha256 != PackageContentSha256 ||
            package.Signature != PackageSignature ||
            package.Signer != PackageSigner ||
            options.ControlIdentity != ControlIdentity ||
            options.RdpDvcControlCarrierPipeName !=
                ControlCarrierPipeName ||
            !CryptographicOperations.FixedTimeEquals(
                options.ControlSigningPublicKey!,
                ControlSigningPublicKey) ||
            options.Capacity != Capacity ||
            !options.Capabilities.SequenceEqual(
                Capabilities,
                StringComparer.Ordinal) ||
            !options.SetupFingerprints
                .Append(
                    "rdp-dvc:" +
                    package.ContentSha256)
                .Distinct(StringComparer.Ordinal)
                .SequenceEqual(
                    SetupFingerprints,
                    StringComparer.Ordinal))
            throw new InvalidOperationException(
                "Control bootstrap idempotency identity changed across reconciliation.");
    }

    internal DevBoxRdpDvcBootstrapRequest ToProviderRequest()
    {
        using var envelope = RSA.Create();
        envelope.ImportPkcs8PrivateKey(
            BootstrapEncryptionPrivateKey,
            out var read);
        if (read != BootstrapEncryptionPrivateKey.Length)
            throw new InvalidDataException(
                "Bootstrap encryption key contains trailing data.");
        return new DevBoxRdpDvcBootstrapRequest(
            StewardOperationId,
            IdempotencyKey,
            Project,
            User,
            DevBox,
            SessionId,
            new HostId(HostId),
            new NodeIncarnationId(NodeIncarnationId),
            ConnectionNonces,
            IntentAuthenticationKey,
            NodeIdentity,
            IntentNodeSigningPrivateKey,
            ControlIdentity,
            ControlSigningPublicKey,
            envelope.ExportSubjectPublicKeyInfo()).Validate();
    }

    internal void ZeroSensitive()
    {
        CryptographicOperations.ZeroMemory(
            IntentAuthenticationKey);
        CryptographicOperations.ZeroMemory(
            IntentNodeSigningPrivateKey);
        CryptographicOperations.ZeroMemory(
            BootstrapEncryptionPrivateKey);
        CryptographicOperations.ZeroMemory(
            ControlSigningPublicKey);
        if (Output is not null)
        {
            CryptographicOperations.ZeroMemory(
                Output.AuthenticationKey);
            CryptographicOperations.ZeroMemory(
                Output.NodeSigningPublicKey);
        }
    }

    internal static Guid DeriveSessionId(
        HostId hostId,
        NodeIncarnationId incarnationId)
    {
        var bytes = Encoding.UTF8.GetBytes(
            $"steward-direct:{hostId}:{incarnationId}");
        return new Guid(SHA256.HashData(bytes).AsSpan(0, 16));
    }

    private void ValidateKeys()
    {
        try
        {
            using var node = ECDsa.Create();
            node.ImportPkcs8PrivateKey(
                IntentNodeSigningPrivateKey,
                out var nodeRead);
            using var envelope = RSA.Create();
            envelope.ImportPkcs8PrivateKey(
                BootstrapEncryptionPrivateKey,
                out var envelopeRead);
            using var control = ECDsa.Create();
            control.ImportSubjectPublicKeyInfo(
                ControlSigningPublicKey,
                out var controlRead);
            if (nodeRead != IntentNodeSigningPrivateKey.Length ||
                node.KeySize != 256 ||
                envelopeRead !=
                    BootstrapEncryptionPrivateKey.Length ||
                envelope.KeySize < 2048 ||
                controlRead != ControlSigningPublicKey.Length ||
                control.KeySize != 256)
                throw new CryptographicException();
        }
        catch (Exception exception)
            when (exception is
                CryptographicException or
                ArgumentException)
        {
            throw new InvalidDataException(
                "Durable Control bootstrap key material is invalid.",
                exception);
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class ControlBootstrapProtectedStateStore
{
    private const int MaximumStateBytes = 256 * 1024;
    private readonly string operations;
    private readonly string indexes;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> gates =
        new(StringComparer.Ordinal);

    public ControlBootstrapProtectedStateStore(
        ValidatedControlProviderBootstrapOptions options)
    {
        if (!options.Available)
            throw new InvalidOperationException(
                "Control provider bootstrap is unavailable.");
        operations = Path.Combine(options.StateRoot!, "operations");
        indexes = Path.Combine(options.StateRoot!, "indexes");
        ControlBootstrapStorage.PrepareDirectory(operations);
        ControlBootstrapStorage.PrepareDirectory(indexes);
    }

    internal async Task<ControlBootstrapState?> LoadAsync(
        ProviderOperationId operationId,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        var identity = StateIdentity(operationId, idempotencyKey);
        var protectedValue = await ControlBootstrapStorage.ReadAsync(
                Path.Combine(operations, identity + ".state"),
                MaximumStateBytes,
                cancellationToken)
            .ConfigureAwait(false);
        if (protectedValue is null)
            return null;
        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedValue,
                Entropy("state", identity),
                DataProtectionScope.CurrentUser);
            return (JsonSerializer.Deserialize<ControlBootstrapState>(
                        plaintext)
                    ?? throw new InvalidDataException(
                        "Control bootstrap state is empty."))
                .Validate();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Control bootstrap state is malformed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedValue);
            if (plaintext is not null)
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal async Task SaveAsync(
        ControlBootstrapState state,
        CancellationToken cancellationToken)
    {
        state.Validate();
        var identity = StateIdentity(
            state.StewardOperationId,
            state.IdempotencyKey);
        var gate = gates.GetOrAdd(
            identity,
            static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteProtectedAsync(
                    Path.Combine(operations, identity + ".state"),
                    state,
                    "state",
                    identity,
                    cancellationToken)
                .ConfigureAwait(false);
            var indexIdentity = IndexIdentity(
                new HostId(state.HostId),
                new NodeIncarnationId(state.NodeIncarnationId),
                state.ProviderResourceId);
            await WriteProtectedAsync(
                    Path.Combine(indexes, indexIdentity + ".index"),
                    new ControlBootstrapIndex(
                        state.OperationId,
                        state.IdempotencyKey,
                        state.HostId,
                        state.NodeIncarnationId,
                        state.ProviderResourceId),
                    "index",
                    indexIdentity,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async Task<ControlBootstrapState?> FindAsync(
        HostId hostId,
        NodeIncarnationId incarnationId,
        string providerResourceId,
        CancellationToken cancellationToken)
    {
        var identity = IndexIdentity(
            hostId,
            incarnationId,
            providerResourceId);
        var protectedValue = await ControlBootstrapStorage.ReadAsync(
                Path.Combine(indexes, identity + ".index"),
                16 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        if (protectedValue is null)
            return null;
        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedValue,
                Entropy("index", identity),
                DataProtectionScope.CurrentUser);
            var index = JsonSerializer.Deserialize<
                    ControlBootstrapIndex>(plaintext)
                ?? throw new InvalidDataException(
                    "Control bootstrap index is empty.");
            if (index.HostId != hostId.Value ||
                index.NodeIncarnationId != incarnationId.Value ||
                index.ProviderResourceId != providerResourceId)
                throw new InvalidDataException(
                    "Control bootstrap index identity is invalid.");
            return await LoadAsync(
                    new ProviderOperationId(index.OperationId),
                    index.IdempotencyKey,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedValue);
            if (plaintext is not null)
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal string StatePath(
        ProviderOperationId operationId,
        string idempotencyKey) =>
        Path.Combine(
            operations,
            StateIdentity(operationId, idempotencyKey) + ".state");

    private static async Task WriteProtectedAsync<T>(
        string path,
        T value,
        string purpose,
        string identity,
        CancellationToken cancellationToken)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(value);
        if (plaintext.Length > MaximumStateBytes)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new InvalidDataException(
                "Control bootstrap protected state exceeds its bound.");
        }
        byte[]? protectedValue = null;
        try
        {
            protectedValue = ProtectedData.Protect(
                plaintext,
                Entropy(purpose, identity),
                DataProtectionScope.CurrentUser);
            await ControlBootstrapStorage.WriteAsync(
                    path,
                    protectedValue,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedValue is not null)
                CryptographicOperations.ZeroMemory(protectedValue);
        }
    }

    private static string StateIdentity(
        ProviderOperationId operationId,
        string idempotencyKey)
    {
        if (operationId.Value == Guid.Empty ||
            string.IsNullOrWhiteSpace(idempotencyKey) ||
            idempotencyKey.Length > 256)
            throw new ArgumentException(
                "Control bootstrap state identity is invalid.");
        var keyHash = Convert.ToHexStringLower(
            SHA256.HashData(
                Encoding.UTF8.GetBytes(idempotencyKey)));
        return operationId.Value.ToString("N") + "-" + keyHash;
    }

    private static string IndexIdentity(
        HostId hostId,
        NodeIncarnationId incarnationId,
        string providerResourceId)
    {
        _ = DevBoxProviderResourceIdentity.Parse(providerResourceId);
        var providerHash = Convert.ToHexStringLower(
            SHA256.HashData(
                Encoding.UTF8.GetBytes(providerResourceId)));
        return hostId.Value.ToString("N") + "-" +
            incarnationId.Value.ToString("N") + "-" +
            providerHash;
    }

    private static byte[] Entropy(string purpose, string identity) =>
        SHA256.HashData(
            Encoding.UTF8.GetBytes(
                "Steward.Control.ProviderBootstrap.v1\n" +
                purpose + "\n" + identity));

    private sealed record ControlBootstrapIndex(
        Guid OperationId,
        string IdempotencyKey,
        Guid HostId,
        Guid NodeIncarnationId,
        string ProviderResourceId);
}

[SupportedOSPlatform("windows")]
internal sealed class DpapiDevBoxRdpDvcBootstrapCheckpointProtector :
    IDevBoxRdpDvcBootstrapCheckpointProtector
{
    public byte[] Protect(
        ReadOnlySpan<byte> plaintext,
        ProviderOperationId operationId,
        string idempotencyKey)
    {
        var cleartext = plaintext.ToArray();
        try
        {
            return ProtectedData.Protect(
                cleartext,
                Entropy(operationId, idempotencyKey),
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
        }
    }

    public byte[] Unprotect(
        ReadOnlySpan<byte> protectedData,
        ProviderOperationId operationId,
        string idempotencyKey)
    {
        var ciphertext = protectedData.ToArray();
        try
        {
            return ProtectedData.Unprotect(
                ciphertext,
                Entropy(operationId, idempotencyKey),
                DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "RDP DVC bootstrap checkpoint authentication failed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private static byte[] Entropy(
        ProviderOperationId operationId,
        string idempotencyKey) =>
        SHA256.HashData(
            Encoding.UTF8.GetBytes(
                "Steward.Control.RdpDvcCheckpoint.v1\n" +
                operationId + "\n" + idempotencyKey));
}

internal interface IControlBootstrapPackageSource
{
    Task<RdpDvcBootstrapBundle> LoadAsync(
        CancellationToken cancellationToken);
}

[SupportedOSPlatform("windows")]
internal sealed class HttpsSignedControlBootstrapPackageSource(
    ValidatedControlProviderBootstrapOptions options) :
    IControlBootstrapPackageSource
{
    private readonly string cacheDirectory =
        PrepareCacheDirectory(options);

    public async Task<RdpDvcBootstrapBundle> LoadAsync(
        CancellationToken cancellationToken)
    {
        var package = options.Package!;
        var path = Path.Combine(
            cacheDirectory,
            package.ContentSha256 + ".zip");
        if (!ControlBootstrapStorage.IsSafeRegularFile(path))
        {
            var bytes = await DownloadAsync(
                    package.Source,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                ValidateHash(bytes, package.ContentSha256);
                await ControlBootstrapStorage.WriteAsync(
                        path,
                        bytes,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        var cached = await ControlBootstrapStorage.ReadAsync(
                path,
                options.MaximumPackageBytes,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "Signed bootstrap package cache is unavailable.");
        try
        {
            ValidateHash(cached, package.ContentSha256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cached);
        }
        var bundle = RdpDvcBootstrapBundle.Load(path);
        if (!string.Equals(
                bundle.ArchiveSha256,
                package.ContentSha256,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Signed bootstrap package identity does not match the RDP DVC bundle.");
        return bundle;
    }

    private async Task<byte[]> DownloadAsync(
        Uri source,
        CancellationToken cancellationToken)
    {
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression =
                DecompressionMethods.None
        };
        using var client = new HttpClient(handler);
        using var timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(options.PackageDownloadTimeout);
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            source);
        using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token)
            .ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException(
                "Signed bootstrap package download did not return HTTP 200.",
                null,
                response.StatusCode);
        var contentLength =
            response.Content.Headers.ContentLength;
        if (!contentLength.HasValue ||
            contentLength.Value <= 0 ||
            contentLength.Value > options.MaximumPackageBytes)
            throw new InvalidDataException(
                "Signed bootstrap package content length is unavailable or exceeds its bound.");
        await using var input = await response.Content.ReadAsStreamAsync(
                timeout.Token)
            .ConfigureAwait(false);
        using var output = new MemoryStream(
            checked((int)contentLength.Value));
        var buffer = new byte[64 * 1024];
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(
                        buffer,
                        timeout.Token)
                    .ConfigureAwait(false);
                if (read == 0)
                    break;
                if (output.Length + read >
                    options.MaximumPackageBytes)
                    throw new InvalidDataException(
                        "Signed bootstrap package exceeds its byte bound.");
                output.Write(buffer, 0, read);
            }
            if (output.Length == 0)
                throw new InvalidDataException(
                    "Signed bootstrap package is empty.");
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static void ValidateHash(
        ReadOnlySpan<byte> content,
        string expected)
    {
        var actual = SHA256.HashData(content);
        var expectedBytes = Convert.FromHexString(expected);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    actual,
                    expectedBytes))
                throw new InvalidDataException(
                    "Signed bootstrap package hash is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expectedBytes);
        }
    }

    private static string PrepareCacheDirectory(
        ValidatedControlProviderBootstrapOptions options)
    {
        var directory = Path.Combine(
            options.StateRoot!,
            "packages");
        ControlBootstrapStorage.PrepareDirectory(directory);
        return directory;
    }
}

internal sealed record ControlBootstrapDeploymentResult(
    ProviderOperationResult Result,
    ControlBootstrapRemoteOutput? Output = null);

internal interface IControlDevBoxBootstrapDeployment
{
    Task<ControlBootstrapDeploymentResult> DeployAsync(
        ControlBootstrapState state,
        CancellationToken cancellationToken);

    Task<ControlBootstrapDeploymentResult> ReconcileAsync(
        ControlBootstrapState state,
        ProviderOperationHandle handle,
        CancellationToken cancellationToken);
}

internal sealed class ControlDevBoxRdpDvcBootstrapDeployment(
    DevBoxRdpDvcBootstrapDeployer deployer,
    DevBoxCustomizationClient customization,
    IControlBootstrapPackageSource packages) :
    IControlDevBoxBootstrapDeployment
{
    private const string BootstrapEnvelopeMarker =
        "STEWARD_RDP_DVC_BOOTSTRAP_ENVELOPE:";

    public async Task<ControlBootstrapDeploymentResult> DeployAsync(
        ControlBootstrapState state,
        CancellationToken cancellationToken)
    {
        var bundle = await packages.LoadAsync(cancellationToken)
            .ConfigureAwait(false);
        var request = state.ToProviderRequest();
        var result = await deployer.DeployAsync(
                request,
                bundle,
                cancellationToken)
            .ConfigureAwait(false);
        return await CompleteAsync(
                state,
                request,
                bundle,
                result,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ControlBootstrapDeploymentResult> ReconcileAsync(
        ControlBootstrapState state,
        ProviderOperationHandle handle,
        CancellationToken cancellationToken)
    {
        var bundle = await packages.LoadAsync(cancellationToken)
            .ConfigureAwait(false);
        var request = state.ToProviderRequest();
        var result = await deployer.ReconcileAsync(
                handle,
                cancellationToken)
            .ConfigureAwait(false);
        return await CompleteAsync(
                state,
                request,
                bundle,
                result,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<ControlBootstrapDeploymentResult> CompleteAsync(
        ControlBootstrapState state,
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle,
        ProviderOperationResult result,
        CancellationToken cancellationToken)
    {
        if (result.Status != ProviderOperationStatus.Succeeded)
            return new(result);
        if (result.Handle is null)
            return new(new(
                ProviderOperationStatus.Failed,
                null,
                null,
                "BootstrapHandleMissing",
                "Completed RDP DVC bootstrap has no durable handle."));
        var plan = DevBoxRdpDvcBootstrapPlan.Create(
            request,
            bundle);
        DevBoxCustomizationGroupResult group;
        try
        {
            group = await customization.GetAsync(
                    state.Project,
                    state.User,
                    state.DevBox,
                    plan.Groups[^1].Name,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (RequestFailedException exception)
            when (exception.Status is 404 or 409)
        {
            return new(result with
            {
                Status = ProviderOperationStatus.Running
            });
        }
        if (!Succeeded(group.Status) ||
            group.Tasks.Count == 0 ||
            !Succeeded(group.Tasks[^1].Status))
            return new(result with
            {
                Status = ProviderOperationStatus.Running
            });
        var log = await customization.GetTaskLogAsync(
                group.Tasks[^1].LogUri,
                cancellationToken)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(log))
            return new(result with
            {
                Status = ProviderOperationStatus.Running
            });
        var marker = log.LastIndexOf(
            BootstrapEnvelopeMarker,
            StringComparison.Ordinal);
        if (marker < 0)
            return new(new(
                ProviderOperationStatus.Failed,
                result.Handle,
                null,
                "BootstrapEnvelopeMissing",
                "Completed RDP DVC bootstrap did not publish its encrypted output."));
        var encoded = log[
            (marker + BootstrapEnvelopeMarker.Length)..];
        var lineEnd = encoded.IndexOfAny(['\r', '\n']);
        if (lineEnd >= 0)
            encoded = encoded[..lineEnd];
        if (encoded.Length is <= 0 or > 2048)
            throw new InvalidDataException(
                "RDP DVC bootstrap output envelope exceeds its bound.");
        var ciphertext = Convert.FromBase64String(encoded.Trim());
        using var encryption = RSA.Create();
        encryption.ImportPkcs8PrivateKey(
            state.BootstrapEncryptionPrivateKey,
            out var read);
        if (read != state.BootstrapEncryptionPrivateKey.Length)
            throw new InvalidDataException(
                "RDP DVC bootstrap output key contains trailing data.");
        var payload = RdpDvcBootstrapEnvelope.Decrypt(
            encryption,
            ciphertext);
        try
        {
            if (payload.OperationId != state.OperationId ||
                payload.SessionId != state.SessionId ||
                payload.HostId != state.HostId ||
                payload.NodeIncarnationId !=
                    state.NodeIncarnationId)
                throw new InvalidDataException(
                    "RDP DVC bootstrap output identity does not match durable intent.");
            using var node = ECDsa.Create();
            node.ImportSubjectPublicKeyInfo(
                payload.NodeSigningPublicKey,
                out var nodeRead);
            if (nodeRead != payload.NodeSigningPublicKey.Length ||
                node.KeySize != 256)
                throw new InvalidDataException(
                    "RDP DVC bootstrap output Node key is invalid.");
            return new(
                result,
                new(
                    payload.AuthenticationKey.ToArray(),
                    payload.NodeSigningPublicKey.ToArray(),
                    DateTimeOffset.UtcNow));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(
                payload.AuthenticationKey);
            CryptographicOperations.ZeroMemory(
                payload.NodeSigningPublicKey);
        }
    }

    private static bool Succeeded(string status) =>
        status.Equals(
            "Succeeded",
            StringComparison.OrdinalIgnoreCase) ||
        status.Equals(
            "Completed",
            StringComparison.OrdinalIgnoreCase);
}

internal sealed class ControlDevBoxNodeBootstrapper(
    ValidatedControlProviderBootstrapOptions options,
    ControlBootstrapProtectedStateStore stateStore,
    IEnrollmentClaimConsumer claims,
    IControlDevBoxBootstrapDeployment deployment) :
    INodeBootstrapper
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> gates =
        new(StringComparer.Ordinal);

    public async Task<ProviderOperationResult> BootstrapAndEnrollAsync(
        BootstrapRequest request,
        CancellationToken cancellationToken = default)
    {
        request.Validate(DateTimeOffset.UtcNow);
        ValidatePackage(request.Package);
        var identity = DevBoxProviderResourceIdentity.Parse(
            request.Resource.ProviderResourceId);
        if (!string.Equals(
                request.Resource.Name,
                identity.DevBox,
                StringComparison.Ordinal) ||
            request.Resource.Status is
                ProviderHostStatus.Deleted or
                ProviderHostStatus.Deleting or
                ProviderHostStatus.Failed)
            throw new InvalidOperationException(
                "Bootstrap provider resource identity or state is invalid.");
        return await LockedAsync(
                request.OperationId,
                request.IdempotencyKey,
                async () =>
                {
                    var state = await stateStore.LoadAsync(
                            request.OperationId,
                            request.IdempotencyKey,
                            cancellationToken)
                        .ConfigureAwait(false);
                    try
                    {
                        state?.ValidateIntent(request, options);
                        await claims.ConsumeAsync(
                                request.Claim,
                                cancellationToken)
                            .ConfigureAwait(false);
                        if (state is null)
                        {
                            state = ControlBootstrapState.Create(
                                request,
                                identity,
                                options);
                            await stateStore.SaveAsync(
                                    state,
                                    cancellationToken)
                                .ConfigureAwait(false);
                        }
                        var result = await deployment.DeployAsync(
                                state,
                                cancellationToken)
                            .ConfigureAwait(false);
                        state = WithDeploymentResult(state, result);
                        await stateStore.SaveAsync(
                                state,
                                cancellationToken)
                            .ConfigureAwait(false);
                        return result.Result;
                    }
                    finally
                    {
                        state?.ZeroSensitive();
                    }
                })
            .ConfigureAwait(false);
    }

    public async Task<ProviderOperationResult> ReconcileAsync(
        ProviderOperationHandle handle,
        CancellationToken cancellationToken = default)
    {
        if (handle.OperationId.Value == Guid.Empty ||
            string.IsNullOrWhiteSpace(handle.IdempotencyKey) ||
            handle.Provider !=
                DevBoxRdpDvcBootstrapPlan.ProviderName ||
            string.IsNullOrWhiteSpace(handle.OpaqueHandle) ||
            handle.OpaqueHandle.Length > 32_768)
            throw new ArgumentException(
                "Control bootstrap handle is malformed.",
                nameof(handle));
        return await LockedAsync(
                handle.OperationId,
                handle.IdempotencyKey,
                async () =>
                {
                    var state = await stateStore.LoadAsync(
                            handle.OperationId,
                            handle.IdempotencyKey,
                            cancellationToken)
                        .ConfigureAwait(false)
                        ?? throw new InvalidOperationException(
                            "Durable Control bootstrap intent is unavailable.");
                    try
                    {
                        ValidateHandle(state, handle);
                        var result = await deployment.ReconcileAsync(
                                state,
                                handle,
                                cancellationToken)
                            .ConfigureAwait(false);
                        state = WithDeploymentResult(state, result);
                        await stateStore.SaveAsync(
                                state,
                                cancellationToken)
                            .ConfigureAwait(false);
                        return result.Result;
                    }
                    finally
                    {
                        state.ZeroSensitive();
                    }
                })
            .ConfigureAwait(false);
    }

    private void ValidatePackage(SignedNodePackage package)
    {
        var expected = options.Package!;
        if (package.Source.AbsoluteUri != expected.Source.AbsoluteUri ||
            package.ContentSha256 != expected.ContentSha256 ||
            package.Signature != expected.Signature ||
            package.Signer != expected.Signer)
            throw new InvalidOperationException(
                "Bootstrap request does not use the configured signed Node package identity.");
    }

    private static void ValidateHandle(
        ControlBootstrapState state,
        ProviderOperationHandle handle)
    {
        var expected = state.LastHandle?.ToHandle()
            ?? throw new InvalidOperationException(
                "Durable Control bootstrap has no reconcilable handle.");
        if (expected.OperationId != handle.OperationId ||
            expected.IdempotencyKey != handle.IdempotencyKey ||
            expected.Provider != handle.Provider ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected.OpaqueHandle),
                Encoding.UTF8.GetBytes(handle.OpaqueHandle)))
            throw new ArgumentException(
                "Control bootstrap handle does not match durable intent.",
                nameof(handle));
    }

    private static ControlBootstrapState WithDeploymentResult(
        ControlBootstrapState state,
        ControlBootstrapDeploymentResult deploymentResult)
    {
        if (deploymentResult.Result.Status is (
                ProviderOperationStatus.Accepted or
                ProviderOperationStatus.Running or
                ProviderOperationStatus.Succeeded) &&
            deploymentResult.Result.Handle is null)
            throw new InvalidDataException(
                "RDP DVC bootstrap did not return a durable reconcile handle.");
        if (deploymentResult.Result.Status ==
                ProviderOperationStatus.Succeeded &&
            deploymentResult.Output is null)
            throw new InvalidDataException(
                "Successful RDP DVC bootstrap has no verified output.");
        return state with
        {
            LastHandle = deploymentResult.Result.Handle is null
                ? state.LastHandle
                : PersistedControlBootstrapHandle.From(
                    deploymentResult.Result.Handle),
            Output = deploymentResult.Output ?? state.Output
        };
    }

    private async Task<T> LockedAsync<T>(
        ProviderOperationId operationId,
        string idempotencyKey,
        Func<Task<T>> action)
    {
        var key = operationId + ":" + idempotencyKey;
        var gate = gates.GetOrAdd(
            key,
            static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await action().ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }
}

public sealed record ControlRdpDvcEndpointBinding(
    int Version,
    Guid SessionId,
    Guid RouteId,
    string ControlCarrierPipeName,
    string ProviderResourceId,
    Guid BootstrapOperationId,
    string AuthenticationKeyReference,
    string NodeSigningPublicKeySha256)
{
    public const int CurrentVersion = 2;

    public ControlRdpDvcEndpointBinding Validate()
    {
        _ = DevBoxProviderResourceIdentity.Parse(
            ProviderResourceId);
        if (Version != CurrentVersion ||
            SessionId == Guid.Empty ||
            RouteId == Guid.Empty ||
            BootstrapOperationId == Guid.Empty ||
            string.IsNullOrWhiteSpace(ControlCarrierPipeName) ||
            ControlCarrierPipeName.Length > 80 ||
            ControlCarrierPipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/') ||
            string.IsNullOrWhiteSpace(AuthenticationKeyReference) ||
            AuthenticationKeyReference.Length > 32_767 ||
            !Path.IsPathFullyQualified(
                AuthenticationKeyReference) ||
            NodeSigningPublicKeySha256.Length != 64 ||
            NodeSigningPublicKeySha256.Any(
                character => !char.IsAsciiHexDigit(character)))
            throw new InvalidOperationException(
                "Control RDP DVC endpoint binding is invalid.");
        return this;
    }
}

[SupportedOSPlatform("windows")]
internal sealed class ControlRdpDvcNodeEndpointIssuer(
    ValidatedControlProviderBootstrapOptions options,
    ControlBootstrapProtectedStateStore stateStore) :
    IRoutableNodeEndpointIssuer
{
    internal const string TransportKind =
        "rdp-dvc-control-carrier";
    internal const string TransportVersion = "2.0";

    public async ValueTask<NodeEndpointRegistration> IssueAsync(
        PoolRegistration pool,
        PoolMember member,
        ProviderResource resource,
        CancellationToken cancellationToken)
    {
        var identity = DevBoxProviderResourceIdentity.Parse(
            resource.ProviderResourceId);
        if (pool.Policy.PoolId != member.PoolId ||
            pool.Provider.Provider is not (
                "devbox" or "azure-dev-box") ||
            pool.Provider.Project != identity.Project ||
            pool.Provider.User != identity.User ||
            resource.Name != identity.DevBox ||
            member.ProviderResourceName != resource.Name ||
            member.ProviderResourceId !=
                resource.ProviderResourceId)
            throw new InvalidOperationException(
                "RDP DVC endpoint provider, Pool, project, user, or Dev Box identity does not match.");
        var state = await stateStore.FindAsync(
                member.HostId,
                member.IncarnationId,
                resource.ProviderResourceId,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "Verified durable RDP DVC bootstrap output is unavailable.");
        try
        {
            if (state.Output is null ||
                state.Project != identity.Project ||
                state.User != identity.User ||
                state.DevBox != identity.DevBox ||
                state.ProviderResourceId !=
                    resource.ProviderResourceId ||
                state.HostId != member.HostId.Value ||
                state.NodeIncarnationId !=
                    member.IncarnationId.Value ||
                state.ControlCarrierPipeName !=
                    options.RdpDvcControlCarrierPipeName)
                throw new InvalidDataException(
                    "Durable RDP DVC bootstrap output identity does not match endpoint issuance.");
            var connectionDirectory = Path.Combine(
                options.StateRoot!,
                "connections",
                member.HostId.Value.ToString("N"),
                member.IncarnationId.Value.ToString("N"));
            ControlBootstrapStorage.PrepareDirectory(
                connectionDirectory);
            var authenticationPath = Path.Combine(
                connectionDirectory,
                "dvc-auth.key");
            var nodePublicPath = Path.Combine(
                connectionDirectory,
                "node-public.pem");
            await ControlBootstrapStorage.WriteAsync(
                    authenticationPath,
                    state.Output.AuthenticationKey,
                    cancellationToken)
                .ConfigureAwait(false);
            var nodePem = Encoding.ASCII.GetBytes(
                PemEncoding.WriteString(
                    "PUBLIC KEY",
                    state.Output.NodeSigningPublicKey));
            try
            {
                await ControlBootstrapStorage.WriteAsync(
                        nodePublicPath,
                        nodePem,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nodePem);
            }
            var publicKeyHash = Convert.ToHexStringLower(
                SHA256.HashData(
                    state.Output.NodeSigningPublicKey));
            var binding = new ControlRdpDvcEndpointBinding(
                ControlRdpDvcEndpointBinding.CurrentVersion,
                state.SessionId,
                member.HostId.Value,
                state.ControlCarrierPipeName,
                state.ProviderResourceId,
                state.OperationId,
                authenticationPath,
                publicKeyHash).Validate();
            return new NodeEndpointRegistration(
                    member.HostId,
                    member.IncarnationId,
                    member.PoolId,
                    ExtensionMetadataDto.Create(
                        TransportKind,
                        TransportVersion,
                        binding),
                    state.NodeIdentity,
                    nodePublicPath,
                    state.Capacity,
                    state.Capabilities.ToArray(),
                    state.SetupFingerprints.ToArray(),
                    state.Output.ObservedAt)
                .Validate();
        }
        finally
        {
            state.ZeroSensitive();
        }
    }
}

[SupportedOSPlatform("windows")]
internal static class ControlBootstrapStorage
{
    internal static void PrepareDirectory(string path)
    {
        EnsureNoReparseSegments(path, requireLeaf: false);
        Directory.CreateDirectory(path);
        EnsureNoReparseSegments(path, requireLeaf: true);
        var identity = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new DirectorySecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    internal static async Task<byte[]?> ReadAsync(
        string path,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return null;
        if (!IsSafeRegularFile(path))
            throw new IOException(
                "Control bootstrap storage requires a regular file.");
        var length = new FileInfo(path).Length;
        if (length is <= 0 || length > maximumBytes)
            throw new InvalidDataException(
                "Control bootstrap storage file exceeds its bound.");
        return await File.ReadAllBytesAsync(
                path,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal static async Task WriteAsync(
        string path,
        ReadOnlyMemory<byte> value,
        CancellationToken cancellationToken,
        bool overwrite = true)
    {
        if (value.IsEmpty)
            throw new ArgumentException(
                "Control bootstrap storage cannot write an empty value.",
                nameof(value));
        var directory = Path.GetDirectoryName(
            Path.GetFullPath(path))
            ?? throw new ArgumentException(
                "Control bootstrap storage path has no directory.",
                nameof(path));
        PrepareDirectory(directory);
        if (!overwrite && File.Exists(path))
            throw new IOException(
                "Control bootstrap storage identity already exists.");
        if (File.Exists(path) && !IsSafeRegularFile(path))
            throw new IOException(
                "Control bootstrap storage destination is unsafe.");
        var pending = path + "." +
            Guid.NewGuid().ToString("N") + ".new";
        try
        {
            await using (var stream = new FileStream(
                             pending,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous |
                             FileOptions.WriteThrough))
            {
                await stream.WriteAsync(
                        value,
                        cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            RestrictFile(pending);
            File.Move(pending, path, overwrite);
            RestrictFile(path);
        }
        finally
        {
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }

    internal static bool IsSafeRegularFile(string path)
    {
        if (!File.Exists(path))
            return false;
        var attributes = File.GetAttributes(path);
        return !attributes.HasFlag(FileAttributes.Directory) &&
            !attributes.HasFlag(FileAttributes.ReparsePoint);
    }

    private static void RestrictFile(string path)
    {
        if (!IsSafeRegularFile(path))
            throw new IOException(
                "Control bootstrap storage requires a regular file.");
        var identity = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new FileSecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static void EnsureNoReparseSegments(
        string path,
        bool requireLeaf)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full)
            ?? throw new IOException(
                "Control bootstrap storage path has no root.");
        var current = root;
        foreach (var segment in full[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (!Directory.Exists(current))
                continue;
            if (File.GetAttributes(current)
                .HasFlag(FileAttributes.ReparsePoint))
                throw new IOException(
                    "Control bootstrap storage cannot traverse reparse points.");
        }
        if (requireLeaf && !Directory.Exists(full))
            throw new IOException(
                "Control bootstrap storage directory is unavailable.");
    }
}
