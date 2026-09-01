using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Steward.Maintenance.Windows;

public enum ApprovedArtifactKind
{
    EndpointMsi,
    EndpointReleaseManifest,
    EndpointAttestation,
    WslPackage,
    WslDistribution,
    DockerEngine,
    DockerCompose
}

public enum WslFeatureSet
{
    WslAndVirtualMachinePlatform
}

public enum WslDistribution
{
    Ubuntu2404
}

public enum WslDistributionConfiguration
{
    RootlessDefaultUser
}

public enum DockerIsolation
{
    Process
}

public enum RepairTarget
{
    MaintenanceService,
    HandleKeeperTask,
    RdpDvcEndpointTask
}

public enum DiagnosticKind
{
    MaintenanceAndEndpointHealth
}

public enum RebootReason
{
    WslFeatureEnablement,
    DockerInstallation,
    EndpointUpdate
}

public enum MaintenanceOperationStatus
{
    Accepted,
    Running,
    AwaitingReboot,
    Succeeded,
    Failed
}

public enum MaintenanceDeliveryState
{
    Accepted,
    InProgress,
    Terminal
}

public sealed record MaintenanceOperationDigest
{
    public MaintenanceOperationDigest(string sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256) ||
            sha256.Length != 64 ||
            sha256.Any(character => !char.IsAsciiHexDigit(character)))
            throw new ArgumentException(
                "Maintenance operation digest is invalid.",
                nameof(sha256));
        Sha256 = sha256.ToUpperInvariant();
    }

    public string Sha256 { get; }

    public static MaintenanceOperationDigest Create(
        MaintenanceOperation operation)
    {
        var canonical = MaintenanceContract.CanonicalizeOperation(operation);
        try
        {
            return new MaintenanceOperationDigest(
                Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(canonical)));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(
                canonical);
        }
    }
}

public sealed record MaintenanceDeliveryKey
{
    public MaintenanceDeliveryKey(
        Guid requestId,
        Guid operationId,
        MaintenanceOperationDigest operationDigest)
    {
        if (requestId == Guid.Empty || operationId == Guid.Empty)
            throw new ArgumentException(
                "Maintenance delivery identity is invalid.");
        RequestId = requestId;
        OperationId = operationId;
        OperationDigest = operationDigest ??
            throw new ArgumentNullException(nameof(operationDigest));
    }

    public Guid RequestId { get; }
    public Guid OperationId { get; }
    public MaintenanceOperationDigest OperationDigest { get; }

    public static MaintenanceDeliveryKey Create(
        MaintenanceRequestBody body)
    {
        MaintenanceContract.Validate(body);
        return new MaintenanceDeliveryKey(
            body.RequestId,
            body.OperationId,
            MaintenanceOperationDigest.Create(body.Operation));
    }

    public static MaintenanceDeliveryKey FromResponse(
        MaintenanceResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return new MaintenanceDeliveryKey(
            response.RequestId,
            response.OperationId,
            response.OperationDigest ?? throw new InvalidDataException(
                "Maintenance response lacks its operation digest."));
    }
}

public static class MaintenanceArtifactCatalog
{
    public const string WslVersion = "2.7.12";
    public const string DockerEngineVersion = "28.3.1";
    public const string DockerComposeVersion = "5.4.0";

    public static ApprovedArtifact Wsl2712 { get; } = new(
        1,
        ApprovedArtifactKind.WslPackage,
        new Uri(
            "https://github.com/microsoft/WSL/releases/download/2.7.12/wsl.2.7.12.0.x64.msi"),
        "A460D4560215F2EFE003C136244B78EA3415D773824D7A688EA9DED36DBE9145",
        258_998_272);

    public static ApprovedArtifact DockerEngine2831 { get; } = new(
        1,
        ApprovedArtifactKind.DockerEngine,
        new Uri(
            "https://download.docker.com/win/static/stable/x86_64/docker-28.3.1.zip"),
        "8360CF63AC342B1ED29C9EC9CB816209E13B7CA381CCF1F7B602DD8284024382",
        43_508_880);

    public static ApprovedArtifact DockerCompose540 { get; } = new(
        1,
        ApprovedArtifactKind.DockerCompose,
        new Uri(
            "https://github.com/docker/compose/releases/download/v5.4.0/docker-compose-windows-x86_64.exe"),
        "D51BC731B3FF6F062A26E8FDFD391AE98AEAB516432F097C66D39C1C9D06680E",
        50_241_536);
}

public sealed record AssignedUserIdentity(
    int Version,
    string Sid,
    string Account);

public sealed record ApprovedArtifact(
    int Version,
    ApprovedArtifactKind Kind,
    Uri Uri,
    string Sha256,
    long Length);

public sealed record ArtifactProvenance(
    int Version,
    string SourceRepository,
    string SourceCommit,
    string SourceRef,
    string SignerWorkflow,
    string SourceRunId);
public readonly record struct EndpointCatalogIdentity
{
    private const string Prefix = "steward-endpoint/";

    private EndpointCatalogIdentity(
        string productVersion,
        string sourceRunId)
    {
        ProductVersion = productVersion;
        SourceRunId = sourceRunId;
    }

    public string ProductVersion { get; }
    public string SourceRunId { get; }

    public static EndpointCatalogIdentity Parse(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !value.StartsWith(Prefix, StringComparison.Ordinal))
            throw new FormatException(
                "Endpoint catalog identity is invalid.");
        var components = value[Prefix.Length..].Split('/');
        if (components.Length != 2 ||
            !System.Version.TryParse(components[0], out var version) ||
            version.Build < 0 ||
            version.Revision >= 0 ||
            version.ToString(3) != components[0] ||
            !ulong.TryParse(
                components[1],
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var run) ||
            run.ToString(
                System.Globalization.CultureInfo.InvariantCulture) !=
                components[1])
            throw new FormatException(
                "Endpoint catalog identity is invalid.");
        return new EndpointCatalogIdentity(
            components[0],
            components[1]);
    }

    public static EndpointCatalogIdentity Create(
        string productVersion,
        string sourceRunId) =>
        Parse($"{Prefix}{productVersion}/{sourceRunId}");

    public override string ToString() =>
        $"{Prefix}{ProductVersion}/{SourceRunId}";
}

public sealed record EndpointReleaseIdentity(
    int Version,
    string CatalogIdentity,
    string ProductVersion,
    string MsiSha256,
    long MsiLength,
    Guid ProductCode,
    Guid UpgradeCode);

public sealed record DockerTaskIdentity(
    int Version,
    string Sid);

public sealed record DockerDaemonConfiguration(
    int Version,
    DockerIsolation Isolation,
    bool Experimental,
    int ShutdownTimeoutSeconds,
    int MaximumConcurrentDownloads);

[JsonPolymorphic(
    TypeDiscriminatorPropertyName = "$operation",
    UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(ActivateEndpointUpdateOperation), "activate-endpoint-update")]
[JsonDerivedType(typeof(ConfigureWslOperation), "configure-wsl")]
[JsonDerivedType(typeof(ImportWslDistributionOperation), "import-wsl-distribution")]
[JsonDerivedType(typeof(ConfigureDockerOperation), "configure-docker")]
[JsonDerivedType(typeof(RepairEndpointOperation), "repair-endpoint")]
[JsonDerivedType(typeof(CollectDiagnosticsOperation), "collect-diagnostics")]
[JsonDerivedType(typeof(ContinueAfterRebootOperation), "continue-after-reboot")]
public abstract record MaintenanceOperation(int Version);

public sealed record ActivateEndpointUpdateOperation(
    int Version,
    ApprovedArtifact Package,
    ApprovedArtifact ReleaseManifest,
    ApprovedArtifact AttestationBundle,
    EndpointReleaseIdentity Release,
    ArtifactProvenance Provenance) : MaintenanceOperation(Version)
{
    public string ProductVersion => Release.ProductVersion;
}

public sealed record ConfigureWslOperation(
    int Version,
    WslFeatureSet Features,
    ApprovedArtifact Package) : MaintenanceOperation(Version);

public sealed record ImportWslDistributionOperation(
    int Version,
    WslDistribution Distribution,
    ApprovedArtifact Package,
    WslDistributionConfiguration Configuration,
    AssignedUserIdentity User) : MaintenanceOperation(Version);

public sealed record ConfigureDockerOperation(
    int Version,
    ApprovedArtifact EnginePackage,
    ApprovedArtifact ComposePackage,
    DockerDaemonConfiguration Configuration) : MaintenanceOperation(Version)
{
    public IReadOnlyList<DockerTaskIdentity> TaskIdentities { get; init; } = [];
}

public sealed record RepairEndpointOperation(
    int Version,
    RepairTarget Target) : MaintenanceOperation(Version);

public sealed record CollectDiagnosticsOperation(
    int Version,
    DiagnosticKind Kind,
    int MaximumBytes) : MaintenanceOperation(Version);

public sealed record ContinueAfterRebootOperation(
    int Version,
    RebootReason Reason) : MaintenanceOperation(Version);

public sealed record MaintenanceRequestBody(
    int ProtocolVersion,
    Guid RequestId,
    Guid OperationId,
    DateTimeOffset IssuedAtUtc,
    MaintenanceOperation Operation);

public sealed record AuthenticatedMaintenanceRequest(
    MaintenanceRequestBody Body,
    string Signature);

public sealed record MaintenanceSessionChallenge(
    int Version,
    Guid ChallengeId,
    string Nonce,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc);

public sealed record MaintenanceSessionProof(
    int Version,
    Guid ChallengeId,
    Guid RequestId,
    Guid OperationId,
    MaintenanceOperationDigest OperationDigest,
    int ClientProcessId,
    int WtsSessionId,
    string AuthenticationTag);

public sealed record MaintenanceIpcSubmission(
    AuthenticatedMaintenanceRequest Request,
    MaintenanceSessionProof Proof);

public sealed record MaintenanceResponse(
    int ProtocolVersion,
    Guid RequestId,
    Guid OperationId,
    MaintenanceOperationStatus Status,
    bool IsIdempotentReplay,
    string? ErrorCode = null,
    string? Message = null,
    MaintenanceOperationDigest? OperationDigest = null);

public sealed class MaintenanceProtocolException(
    string code,
    string safeMessage) : Exception(safeMessage)
{
    public string Code { get; } = code;
}

public static class MaintenanceContract
{
    public const int ProtocolVersion = 1;
    public const string LocalPipeName = "Steward.Maintenance.v1";
    public const int MaximumDiagnosticBytes = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = CreateJson();

    public static byte[] Serialize(AuthenticatedMaintenanceRequest request)
    {
        Validate(request.Body);
        ValidateSignatureEncoding(request.Signature);
        return JsonSerializer.SerializeToUtf8Bytes(request, Json);
    }

    public static AuthenticatedMaintenanceRequest Parse(
        ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty ||
            payload.Length > 64 * 1024)
            throw new InvalidDataException(
                "Maintenance request size is invalid.");
        try
        {
            var request = JsonSerializer.Deserialize<AuthenticatedMaintenanceRequest>(
                              payload,
                              Json)
                          ?? throw new InvalidDataException(
                              "Maintenance request is empty.");
            Validate(request.Body);
            ValidateSignatureEncoding(request.Signature);
            return request;
        }
        catch (MaintenanceProtocolException exception)
        {
            throw new InvalidDataException(
                "Maintenance request contract is unsupported.",
                exception);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Maintenance request is malformed or unsupported.",
                exception);
        }
        catch (NotSupportedException exception)
        {
            throw new InvalidDataException(
                "Maintenance request operation is unsupported.",
                exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Maintenance request authentication is malformed.",
                exception);
        }
    }

    public static byte[] Canonicalize(MaintenanceRequestBody body)
    {
        Validate(body);
        return JsonSerializer.SerializeToUtf8Bytes(body, Json);
    }

    public static byte[] CanonicalizeOperation(MaintenanceOperation operation)
    {
        ValidateOperation(operation);
        return JsonSerializer.SerializeToUtf8Bytes(operation, Json);
    }

    public static void Validate(MaintenanceRequestBody body)
    {
        if (body.ProtocolVersion != ProtocolVersion)
            throw new MaintenanceProtocolException(
                "unsupported_version",
                "Maintenance protocol version is unsupported.");
        if (body.RequestId == Guid.Empty || body.OperationId == Guid.Empty)
            throw new MaintenanceProtocolException(
                "invalid_identity",
                "Maintenance request identity is invalid.");
        if (body.IssuedAtUtc.Offset != TimeSpan.Zero)
            throw new MaintenanceProtocolException(
                "invalid_timestamp",
                "Maintenance request time must be UTC.");
        ArgumentNullException.ThrowIfNull(body.Operation);
        ValidateOperation(body.Operation);
    }

    public static void ValidateOperation(MaintenanceOperation operation)
    {
        if (operation.Version != 1)
            throw new MaintenanceProtocolException(
                "unsupported_operation_version",
                "Maintenance operation version is unsupported.");

        switch (operation)
        {
            case ActivateEndpointUpdateOperation update:
                ValidateArtifact(update.Package, ApprovedArtifactKind.EndpointMsi);
                ValidateArtifact(
                    update.ReleaseManifest,
                    ApprovedArtifactKind.EndpointReleaseManifest);
                ValidateArtifact(
                    update.AttestationBundle,
                    ApprovedArtifactKind.EndpointAttestation);
                ValidateRelease(update.Release);
                ValidateProvenance(update.Provenance);
                var catalog = EndpointCatalogIdentity.Parse(
                    update.Release.CatalogIdentity);
                if (!string.Equals(
                        catalog.ProductVersion,
                        update.Release.ProductVersion,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        catalog.SourceRunId,
                        update.Provenance.SourceRunId,
                        StringComparison.Ordinal))
                    throw new MaintenanceProtocolException(
                        "release_mismatch",
                        "Endpoint catalog identity does not match its release.");
                if (!string.Equals(
                        update.Package.Sha256,
                        update.Release.MsiSha256,
                        StringComparison.OrdinalIgnoreCase) ||
                    update.Package.Length != update.Release.MsiLength)
                    throw new MaintenanceProtocolException(
                        "release_mismatch",
                        "Endpoint release does not bind the requested MSI.");
                break;
            case ConfigureWslOperation wsl:
                if (wsl.Features != WslFeatureSet.WslAndVirtualMachinePlatform)
                    throw InvalidOperation();
                ValidateArtifact(wsl.Package, ApprovedArtifactKind.WslPackage);
                RequireExactArtifact(
                    wsl.Package,
                    MaintenanceArtifactCatalog.Wsl2712);
                break;
            case ImportWslDistributionOperation distribution:
                if (distribution.Distribution != WslDistribution.Ubuntu2404 ||
                    distribution.Configuration !=
                        WslDistributionConfiguration.RootlessDefaultUser)
                    throw InvalidOperation();
                ValidateArtifact(
                    distribution.Package,
                    ApprovedArtifactKind.WslDistribution);
                ValidateAssignedUser(distribution.User);
                break;
            case ConfigureDockerOperation docker:
                ValidateArtifact(
                    docker.EnginePackage,
                    ApprovedArtifactKind.DockerEngine);
                ValidateArtifact(
                    docker.ComposePackage,
                    ApprovedArtifactKind.DockerCompose);
                RequireExactArtifact(
                    docker.EnginePackage,
                    MaintenanceArtifactCatalog.DockerEngine2831);
                RequireExactArtifact(
                    docker.ComposePackage,
                    MaintenanceArtifactCatalog.DockerCompose540);
                if (docker.Configuration.Version != 1 ||
                    docker.Configuration.Isolation != DockerIsolation.Process ||
                    docker.Configuration.Experimental ||
                    docker.Configuration.ShutdownTimeoutSeconds is < 5 or > 120 ||
                    docker.Configuration.MaximumConcurrentDownloads is < 1 or > 16 ||
                    docker.TaskIdentities.Count > 256 ||
                    docker.TaskIdentities.Any(identity =>
                        identity.Version != 1 ||
                        identity.Sid.Length is < 10 or > 184 ||
                        !identity.Sid.StartsWith("S-1-", StringComparison.Ordinal)))
                    throw InvalidOperation();
                break;
            case RepairEndpointOperation repair:
                if (!Enum.IsDefined(repair.Target))
                    throw InvalidOperation();
                break;
            case CollectDiagnosticsOperation diagnostics:
                if (diagnostics.Kind !=
                        DiagnosticKind.MaintenanceAndEndpointHealth ||
                    diagnostics.MaximumBytes is < 1024 or > MaximumDiagnosticBytes)
                    throw InvalidOperation();
                break;
            case ContinueAfterRebootOperation reboot:
                if (!Enum.IsDefined(reboot.Reason))
                    throw InvalidOperation();
                break;
            default:
                throw new MaintenanceProtocolException(
                    "unknown_operation",
                    "Maintenance operation is unsupported.");
        }
    }

    public static void ValidateArtifact(ApprovedArtifact artifact)
    {
        if (!Enum.IsDefined(artifact.Kind))
            throw new MaintenanceProtocolException(
                "artifact_not_approved",
                "Maintenance artifact is outside the typed allowlist.");
        ValidateArtifact(artifact, artifact.Kind);
    }

    private static void ValidateArtifact(
        ApprovedArtifact artifact,
        ApprovedArtifactKind expectedKind)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (artifact.Version != 1 ||
            artifact.Kind != expectedKind ||
            artifact.Length is <= 0 or > 4L * 1024 * 1024 * 1024 ||
            artifact.Sha256.Length != 64 ||
            artifact.Sha256.Any(character => !char.IsAsciiHexDigit(character)) ||
            !artifact.Uri.IsAbsoluteUri ||
            !string.Equals(artifact.Uri.Scheme, Uri.UriSchemeHttps,
                StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(artifact.Uri.UserInfo) ||
            !string.IsNullOrEmpty(artifact.Uri.Query) ||
            !string.IsNullOrEmpty(artifact.Uri.Fragment) ||
            !AllowedHost(expectedKind, artifact.Uri.Host))
            throw new MaintenanceProtocolException(
                "artifact_not_approved",
                "Maintenance artifact is outside the typed allowlist.");
    }

    private static bool AllowedHost(
        ApprovedArtifactKind kind,
        string host) => kind switch
        {
            ApprovedArtifactKind.EndpointMsi or
            ApprovedArtifactKind.EndpointReleaseManifest or
            ApprovedArtifactKind.EndpointAttestation =>
                string.Equals(host, "github.com", StringComparison.OrdinalIgnoreCase),
            ApprovedArtifactKind.WslPackage =>
                string.Equals(host, "github.com", StringComparison.OrdinalIgnoreCase),
            ApprovedArtifactKind.WslDistribution =>
                string.Equals(host, "download.microsoft.com", StringComparison.OrdinalIgnoreCase),
            ApprovedArtifactKind.DockerEngine =>
                string.Equals(host, "download.docker.com", StringComparison.OrdinalIgnoreCase),
            ApprovedArtifactKind.DockerCompose =>
                string.Equals(host, "github.com", StringComparison.OrdinalIgnoreCase),
            _ => false
        };

    private static void RequireExactArtifact(
        ApprovedArtifact actual,
        ApprovedArtifact expected)
    {
        if (actual.Version != expected.Version ||
            actual.Kind != expected.Kind ||
            actual.Uri != expected.Uri ||
            !string.Equals(actual.Sha256, expected.Sha256,
                StringComparison.OrdinalIgnoreCase) ||
            actual.Length != expected.Length)
            throw new MaintenanceProtocolException(
                "artifact_not_approved",
                "Maintenance artifact does not match the immutable approved release.");
    }

    private static void ValidateAssignedUser(AssignedUserIdentity user)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (user.Version != 1 ||
            user.Sid.Length is < 20 or > 184 ||
            !System.Text.RegularExpressions.Regex.IsMatch(
                user.Sid,
                "^S-1-12-1-(\\d+-){2}\\d+-\\d+$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(1)) ||
            string.IsNullOrWhiteSpace(user.Account) ||
            user.Account.Length > 256 ||
            user.Account.Any(character => char.IsControl(character)))
            throw InvalidOperation();
    }

    private static void ValidateVersion(string value)
    {
        if (!Version.TryParse(value, out var version) ||
            version.Major < 0 || version.Build < 0 || version.Revision >= 0)
            throw InvalidOperation();
    }

    private static void ValidateRelease(EndpointReleaseIdentity release)
    {
        ArgumentNullException.ThrowIfNull(release);
        ValidateVersion(release.ProductVersion);
        if (release.Version != 1 ||
            string.IsNullOrWhiteSpace(release.CatalogIdentity) ||
            release.CatalogIdentity.Length > 128 ||
            !TryParseCatalogIdentity(release.CatalogIdentity) ||
            release.MsiSha256.Length != 64 ||
            release.MsiSha256.Any(character =>
                !char.IsAsciiHexDigit(character)) ||
            release.MsiLength is <= 0 or > 4L * 1024 * 1024 * 1024 ||
            release.ProductCode == Guid.Empty ||
            release.UpgradeCode == Guid.Empty)
            throw new MaintenanceProtocolException(
                "release_mismatch",
                "Endpoint release identity is invalid.");
    }
    private static bool TryParseCatalogIdentity(string value)
    {
        try
        {
            _ = EndpointCatalogIdentity.Parse(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static void ValidateProvenance(ArtifactProvenance provenance)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        if (provenance.Version != 1 ||
            string.IsNullOrWhiteSpace(provenance.SourceRepository) ||
            provenance.SourceRepository.Length > 200 ||
            provenance.SourceCommit.Length != 40 ||
            provenance.SourceCommit.Any(character => !char.IsAsciiHexDigit(character)) ||
            provenance.SourceRef != "refs/heads/main" ||
            provenance.SignerWorkflow !=
                provenance.SourceRepository +
                "/.github/workflows/release-endpoint.yml" ||
            string.IsNullOrWhiteSpace(provenance.SourceRunId) ||
            provenance.SourceRunId.Length > 32 ||
            provenance.SourceRunId.Any(character => !char.IsAsciiDigit(character)))
            throw new MaintenanceProtocolException(
                "provenance_mismatch",
                "Endpoint update provenance is not approved.");
    }

    private static void ValidateSignatureEncoding(string signature)
    {
        if (string.IsNullOrWhiteSpace(signature) || signature.Length > 256)
            throw new FormatException(
                "Maintenance request signature is invalid.");
        var bytes = Convert.FromBase64String(signature);
        if (bytes.Length is < 1 or > 128)
            throw new FormatException(
                "Maintenance request signature is invalid.");
    }

    private static MaintenanceProtocolException InvalidOperation() =>
        new(
            "operation_not_approved",
            "Maintenance operation is outside the typed allowlist.");

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            MaxDepth = 16,
            PropertyNameCaseInsensitive = false
        };
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.CamelCase,
            allowIntegerValues: false));
        return options;
    }
}

public sealed class MaintenanceSessionAuthenticator
{
    private readonly byte[] authenticationKey;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan lifetime;

    public MaintenanceSessionAuthenticator(
        ReadOnlySpan<byte> authenticationKey,
        TimeProvider timeProvider,
        TimeSpan lifetime)
    {
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "Maintenance session authentication requires a 256-bit key.",
                nameof(authenticationKey));
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (lifetime < TimeSpan.FromSeconds(5) ||
            lifetime > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        this.authenticationKey = authenticationKey.ToArray();
        this.timeProvider = timeProvider;
        this.lifetime = lifetime;
    }

    public MaintenanceSessionChallenge CreateChallenge()
    {
        var now = timeProvider.GetUtcNow();
        return new MaintenanceSessionChallenge(
            1,
            Guid.NewGuid(),
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            now,
            now + lifetime);
    }

    public static MaintenanceSessionProof CreateProof(
        MaintenanceSessionChallenge challenge,
        AuthenticatedMaintenanceRequest request,
        ReadOnlySpan<byte> authenticationKey,
        int clientProcessId,
        int wtsSessionId)
    {
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "Maintenance session authentication requires a 256-bit key.",
                nameof(authenticationKey));
        ValidateChallenge(challenge);
        MaintenanceContract.Validate(request.Body);
        if (clientProcessId <= 0 || wtsSessionId < 0)
            throw new ArgumentException(
                "Maintenance client process evidence is invalid.");
        var digest = MaintenanceOperationDigest.Create(
            request.Body.Operation);
        var canonical = Canonicalize(
            challenge,
            request.Body.RequestId,
            request.Body.OperationId,
            digest,
            clientProcessId,
            wtsSessionId);
        try
        {
            var tag = HMACSHA256.HashData(authenticationKey, canonical);
            try
            {
                return new MaintenanceSessionProof(
                    1,
                    challenge.ChallengeId,
                    request.Body.RequestId,
                    request.Body.OperationId,
                    digest,
                    clientProcessId,
                    wtsSessionId,
                    Convert.ToBase64String(tag));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(tag);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public void Verify(
        MaintenanceSessionChallenge challenge,
        AuthenticatedMaintenanceRequest request,
        MaintenanceSessionProof proof,
        int expectedClientProcessId,
        int expectedWtsSessionId)
    {
        ValidateChallenge(challenge);
        MaintenanceContract.Validate(request.Body);
        ArgumentNullException.ThrowIfNull(proof);
        var now = timeProvider.GetUtcNow();
        var digest = MaintenanceOperationDigest.Create(
            request.Body.Operation);
        if (challenge.ExpiresAtUtc - challenge.IssuedAtUtc != lifetime ||
            now < challenge.IssuedAtUtc ||
            now > challenge.ExpiresAtUtc ||
            proof.Version != 1 ||
            proof.ChallengeId != challenge.ChallengeId ||
            proof.RequestId != request.Body.RequestId ||
            proof.OperationId != request.Body.OperationId ||
            proof.OperationDigest != digest ||
            proof.ClientProcessId != expectedClientProcessId ||
            proof.WtsSessionId != expectedWtsSessionId ||
            proof.AuthenticationTag.Length > 64)
            throw AuthenticationFailed();
        byte[] actual;
        try
        {
            actual = Convert.FromBase64String(proof.AuthenticationTag);
        }
        catch (FormatException)
        {
            throw AuthenticationFailed();
        }
        var canonical = Canonicalize(
            challenge,
            proof.RequestId,
            proof.OperationId,
            proof.OperationDigest,
            proof.ClientProcessId,
            proof.WtsSessionId);
        try
        {
            var expected = HMACSHA256.HashData(
                authenticationKey,
                canonical);
            try
            {
                if (actual.Length != expected.Length ||
                    !CryptographicOperations.FixedTimeEquals(
                        actual,
                        expected))
                    throw AuthenticationFailed();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expected);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private static byte[] Canonicalize(
        MaintenanceSessionChallenge challenge,
        Guid requestId,
        Guid operationId,
        MaintenanceOperationDigest digest,
        int clientProcessId,
        int wtsSessionId) => Encoding.UTF8.GetBytes(string.Join(
            '\n',
            "steward-maintenance-session-v1",
            challenge.ChallengeId.ToString("D"),
            challenge.Nonce,
            challenge.IssuedAtUtc.ToString("O"),
            challenge.ExpiresAtUtc.ToString("O"),
            requestId.ToString("D"),
            operationId.ToString("D"),
            digest.Sha256,
            clientProcessId.ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            wtsSessionId.ToString(
                System.Globalization.CultureInfo.InvariantCulture)));

    private static void ValidateChallenge(
        MaintenanceSessionChallenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        byte[] nonce;
        try
        {
            nonce = Convert.FromBase64String(challenge.Nonce);
        }
        catch (FormatException)
        {
            throw AuthenticationFailed();
        }
        try
        {
            if (challenge.Version != 1 ||
                challenge.ChallengeId == Guid.Empty ||
                nonce.Length != 32 ||
                challenge.IssuedAtUtc.Offset != TimeSpan.Zero ||
                challenge.ExpiresAtUtc.Offset != TimeSpan.Zero ||
                challenge.ExpiresAtUtc <= challenge.IssuedAtUtc)
                throw AuthenticationFailed();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static MaintenanceProtocolException AuthenticationFailed() =>
        new(
            "session_authentication_failed",
            "Maintenance session authentication failed.");
}
