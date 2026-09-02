using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Scheduling;

namespace Steward.Stack.Local;

public sealed class LocalStackOptions
{
    public const string TransportKind = "direct-websocket";
    public const string TransportVersion = "1.0";
    public const string PortableStateKind = "content-addressed-filesystem";
    public const string PortableStateVersion = "1.0";
    public const string CredentialDeliveryKind = "direct-session-os-vault";
    public const string CredentialDeliveryVersion = "1.0";

    public string DataRoot { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Steward");
    public string PortableStateRoot { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Steward", "objects");
    public string CredentialVaultRoot { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Steward", "credentials");
    public bool TransportEnabled { get; set; }
    public string TransportIdentity { get; set; } = string.Empty;
    public string TransportPrivateKeyPemPath { get; set; } = string.Empty;
    public bool RdpDvcControlCarrierEnabled { get; set; }
    public string RdpDvcControlCarrierPipeName { get; set; } =
        "Steward.Control.RdpDvc.v2";
    public List<LocalNodeEndpointOptions> Nodes { get; set; } = [];
    public int MaximumTransportPayloadBytes { get; set; } = 256 * 1024;
    public int MaximumBufferedFrames { get; set; } = 256;

    public ValidatedLocalStackOptions Validate()
    {
        var dataRoot = RequireAbsolute(DataRoot, nameof(DataRoot));
        var portableRoot = RequireAbsolute(PortableStateRoot, nameof(PortableStateRoot));
        var credentialRoot = RequireAbsolute(CredentialVaultRoot, nameof(CredentialVaultRoot));
        string? privateKey = null;
        if (TransportEnabled)
        {
            if (string.IsNullOrWhiteSpace(TransportIdentity) ||
                TransportIdentity.Length > 256)
                throw new InvalidOperationException(
                    "Local Stack TransportIdentity is required and bounded.");
            privateKey = RequireExistingAbsolute(
                TransportPrivateKeyPemPath, nameof(TransportPrivateKeyPemPath));
            if (Nodes.Count > 256 ||
                Nodes.Count == 0 &&
                !RdpDvcControlCarrierEnabled)
                throw new InvalidOperationException(
                    "Local Stack transport requires direct Node endpoints or the RDP DVC Control carrier.");
        }
        if (RdpDvcControlCarrierEnabled && !TransportEnabled)
            throw new InvalidOperationException(
                "The RDP DVC Control carrier requires configured transport identity and Nodes.");
        if (string.IsNullOrWhiteSpace(RdpDvcControlCarrierPipeName) ||
            RdpDvcControlCarrierPipeName.Length > 80 ||
            RdpDvcControlCarrierPipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new InvalidOperationException(
                "The RDP DVC Control carrier pipe name is invalid.");
        var nodes = Nodes.Select(x => x.Validate()).ToArray();
        if (nodes.Select(x => x.HostId).Distinct().Count() != nodes.Length ||
            nodes.Select(x => x.NodeIncarnationId).Distinct().Count() != nodes.Length)
            throw new InvalidOperationException(
                "Local Stack Node Host and incarnation identities must be unique.");
        if (MaximumTransportPayloadBytes is <= 0 or > 1024 * 1024 ||
            MaximumBufferedFrames is <= 0 or > 4096)
            throw new InvalidOperationException("Local Stack transport bounds are invalid.");
        return new(
            dataRoot,
            portableRoot,
            credentialRoot,
            TransportEnabled,
            TransportIdentity,
            privateKey,
            nodes,
            MaximumTransportPayloadBytes,
            MaximumBufferedFrames,
            RdpDvcControlCarrierEnabled,
            RdpDvcControlCarrierPipeName);
    }

    public static ExtensionMetadataDto TransportBinding<T>(T configuration) =>
        ExtensionMetadataDto.Create(
            TransportKind, TransportVersion, configuration);

    public static ExtensionMetadataDto PortableStateBinding<T>(T configuration) =>
        ExtensionMetadataDto.Create(
            PortableStateKind, PortableStateVersion, configuration);

    public static ExtensionMetadataDto CredentialDeliveryBinding<T>(T configuration) =>
        ExtensionMetadataDto.Create(
            CredentialDeliveryKind, CredentialDeliveryVersion, configuration);

    private static string RequireAbsolute(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 32_767 ||
            value.IndexOf('\0') >= 0 ||
            !Path.IsPathFullyQualified(value))
            throw new InvalidOperationException(
                $"Local Stack {name} must be a bounded absolute path.");
        return Path.GetFullPath(value);
    }

    private static string RequireExistingAbsolute(string value, string name)
    {
        var full = RequireAbsolute(value, name);
        if (!File.Exists(full))
            throw new InvalidOperationException(
                $"Local Stack {name} must reference an existing file.");
        return full;
    }
}

public sealed record ValidatedLocalStackOptions(
    string DataRoot,
    string PortableStateRoot,
    string CredentialVaultRoot,
    bool TransportEnabled,
    string TransportIdentity,
    string? TransportPrivateKeyPemPath,
    IReadOnlyList<NodeEndpointRegistration> Nodes,
    int MaximumTransportPayloadBytes,
    int MaximumBufferedFrames,
    bool RdpDvcControlCarrierEnabled = false,
    string RdpDvcControlCarrierPipeName = "Steward.Control.RdpDvc.v2");

public enum LocalDirectDialDirection
{
    ControlDialsNode,
    NodeDialsControl
}

public sealed record LocalDirectTransportBinding(
    LocalDirectDialDirection DialDirection,
    Uri Endpoint,
    Guid? SessionId = null)
{
    public LocalDirectTransportBinding Validate()
    {
        if (!Enum.IsDefined(DialDirection) ||
            Endpoint is null ||
            !Endpoint.IsAbsoluteUri ||
            (Endpoint.Scheme != Uri.UriSchemeWss &&
             !(Endpoint.Scheme == Uri.UriSchemeWs && Endpoint.IsLoopback)) ||
            SessionId == Guid.Empty)
            throw new InvalidOperationException(
                "Local direct transport requires wss, except ws is allowed on loopback.");
        return this;
    }
}

public sealed class LocalNodeEndpointOptions
{
    public string HostId { get; set; } = string.Empty;
    public string NodeIncarnationId { get; set; } = string.Empty;
    public string PoolId { get; set; } = string.Empty;
    public LocalDirectDialDirection DialDirection { get; set; }
    public string Endpoint { get; set; } = string.Empty;
    public string? SessionId { get; set; }
    public string PeerIdentity { get; set; } = string.Empty;
    public string PeerPublicKeyPemPath { get; set; } = string.Empty;
    public decimal CpuCores { get; set; } = 1;
    public long MemoryBytes { get; set; } = 1024 * 1024 * 1024;
    public long DiskBytes { get; set; } = 1024 * 1024 * 1024;
    public int ProcessCount { get; set; } = 1;
    public int ContainerCount { get; set; }
    public int ConcurrencyUnits { get; set; } = 1;
    public List<string> Capabilities { get; set; } = [];
    public List<string> SetupFingerprints { get; set; } = [];

    public NodeEndpointRegistration Validate()
    {
        if (!Domain.HostId.TryParse(HostId, out var host) ||
            !Domain.NodeIncarnationId.TryParse(
                NodeIncarnationId, out var incarnation) ||
            !Domain.PoolId.TryParse(PoolId, out var pool))
            throw new InvalidOperationException(
                "Local Stack Node Host/incarnation/Pool identity is invalid.");
        if (!Uri.TryCreate(Endpoint, UriKind.Absolute, out var endpoint))
            throw new InvalidOperationException(
                "Local Stack Node endpoint URI is invalid.");
        Guid? sessionId = null;
        if (SessionId is not null)
        {
            if (!Guid.TryParse(SessionId, out var parsedSessionId) ||
                parsedSessionId == Guid.Empty)
                throw new InvalidOperationException(
                    "Local Stack Node session identity is invalid.");
            sessionId = parsedSessionId;
        }
        var binding = new LocalDirectTransportBinding(
            DialDirection, endpoint, sessionId).Validate();
        if (string.IsNullOrWhiteSpace(PeerIdentity) ||
            !Path.IsPathFullyQualified(PeerPublicKeyPemPath) ||
            !File.Exists(PeerPublicKeyPemPath))
            throw new InvalidOperationException(
                "Local Stack Node peer identity or public key is invalid.");
        return new(
            host,
            incarnation,
            pool,
            LocalStackOptions.TransportBinding(binding),
            PeerIdentity,
            Path.GetFullPath(PeerPublicKeyPemPath),
            new ResourceRequirements(
                CpuCores,
                MemoryBytes,
                DiskBytes,
                processCount: ProcessCount,
                containerCount: ContainerCount,
                concurrencyUnits: ConcurrencyUnits),
            Capabilities.ToArray(),
            SetupFingerprints.ToArray(),
            DateTimeOffset.UtcNow);
    }
}
