using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public sealed record ConnectionHostOptions
{
    public bool EnableLiveConnections { get; init; }
    public string PipeName { get; init; } = "Steward.ConnectionHost.v1";
    public TimeSpan CommandTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public Action<string>? DiagnosticSink { get; init; }
}

public interface IDevBoxRemoteConnectionProvider
{
    Task<Uri> GetRemoteConnectionAsync(
        DesiredConnectionRecord desired,
        CancellationToken cancellationToken);
}

public interface IDesiredDevBoxConnectionResolver
{
    Task<ISensitiveRdpConnectionMaterial> ResolveDesiredAsync(
        DesiredConnectionRecord desired,
        CancellationToken cancellationToken);
}

public sealed record ConnectionRecoveryMaterial(
    string AuthorizationToken,
    string EvidenceReference);

public interface IConnectionRecoveryMaterialIssuer
{
    ValueTask<ConnectionRecoveryMaterial> IssueAsync(
        DesiredConnectionRecord desired,
        CancellationToken cancellationToken);
}
public interface IDevBoxConnectionResolver
{
    Task<ISensitiveRdpConnectionMaterial> ResolveAsync(
        Uri providerResource,
        CancellationToken cancellationToken);
}

public interface ISensitiveRdpConnectionMaterial : IDisposable
{
    Uri ProviderResourceUri { get; }

    Stream OpenRdpContent();
}

public sealed class DevBoxConnectionResolver(
    DevBoxBrokerFeedResolver resolver,
    IDevBoxRemoteConnectionProvider? remoteConnections = null) :
    IDevBoxConnectionResolver,
    IDesiredDevBoxConnectionResolver
{
    public async Task<ISensitiveRdpConnectionMaterial> ResolveAsync(
        Uri providerResource,
        CancellationToken cancellationToken) =>
        new SensitiveRdpConnectionMaterial(
            providerResource,
            await resolver.ResolveAsync(
                    providerResource,
                    cancellationToken)
                .ConfigureAwait(false));

    public async Task<ISensitiveRdpConnectionMaterial> ResolveDesiredAsync(
        DesiredConnectionRecord desired,
        CancellationToken cancellationToken)
    {
        desired = desired.Validate();
        var provider = remoteConnections ??
            throw new DevBoxConnectionIdentityException(
                DevBoxConnectionIdentityOutcome.InteractionRequired,
                "Silent Dev Box connection refresh is unavailable.");
        return await ResolveAsync(
                await provider.GetRemoteConnectionAsync(
                        desired,
                        cancellationToken)
                    .ConfigureAwait(false),
                cancellationToken)
            .ConfigureAwait(false);
    }
}

internal sealed class SensitiveRdpConnectionMaterial(
    Uri providerResourceUri,
    SensitiveDevBoxBrokerResult value) : ISensitiveRdpConnectionMaterial
{
    public Uri ProviderResourceUri { get; } = providerResourceUri;

    public Stream OpenRdpContent() => value.OpenRdpContent();

    public void Dispose() => value.Dispose();

    public override string ToString() =>
        "SensitiveRdpConnectionMaterial { RdpContent = [REDACTED] }";
}

public sealed record RdCoreCompatibilitySnapshot(
    bool IsCompatible,
    string Code,
    RdCorePackageArtifacts? Artifacts);

public interface IRdCoreCompatibilityInspector
{
    RdCoreCompatibilitySnapshot Inspect();
}

public sealed class RdCoreCompatibilityInspector : IRdCoreCompatibilityInspector
{
    private readonly RdCoreCompatibilityProbe? probe;
    private readonly RdCoreCapabilityReport? fixedReport;

    public RdCoreCompatibilityInspector()
    {
        probe = new();
    }

    public RdCoreCompatibilityInspector(RdCoreCapabilityReport report)
    {
        fixedReport = report ??
            throw new ArgumentNullException(nameof(report));
    }

    public RdCoreCompatibilitySnapshot Inspect()
    {
        var result = fixedReport ?? probe!.Inspect();
        return new(
            result.IsCompatible,
            result.Code.ToString(),
            result.Artifacts);
    }
}

public sealed class DisabledDevBoxConnectionResolver :
    IDevBoxConnectionResolver
{
    public Task<ISensitiveRdpConnectionMaterial> ResolveAsync(
        Uri providerResource,
        CancellationToken cancellationToken) =>
        Task.FromException<ISensitiveRdpConnectionMaterial>(
            new InvalidOperationException(
                "The RDCore integration gate is disabled."));
}

public interface IDvcRegistrationSnapshotProvider
{
    DvcPluginRegistrationStatus GetStatus();
}

public sealed class DvcRegistrationSnapshotProvider(
    RdpDvcPluginRegistration registration) :
    IDvcRegistrationSnapshotProvider
{
    public DvcPluginRegistrationStatus GetStatus() =>
        registration.GetStatus();
}

public interface IControlConnectAuthorizationValidator
{
    ValueTask<bool> ConsumeAsync(
        string authorizationToken,
        string connectionId,
        CancellationToken cancellationToken);
}

public sealed class SingleUseControlConnectAuthorizationValidator :
    IControlConnectAuthorizationValidator
{
    private readonly ConcurrentDictionary<string, byte> tokenDigests =
        new(StringComparer.Ordinal);

    public void Register(string authorizationToken)
    {
        ValidateToken(authorizationToken);
        if (!tokenDigests.TryAdd(Digest(authorizationToken), 0))
            throw new InvalidOperationException(
                "The Control authorization token is already registered.");
    }

    public ValueTask<bool> ConsumeAsync(
        string authorizationToken,
        string connectionId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = connectionId;
        ValidateToken(authorizationToken);
        return ValueTask.FromResult(
            tokenDigests.TryRemove(Digest(authorizationToken), out _));
    }

    private static string Digest(string token) =>
        Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static void ValidateToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token) ||
            token.Length > ConnectionHostProtocol
                .MaximumAuthorizationTokenCharacters)
            throw new ArgumentException(
                "The Control authorization token is invalid.",
                nameof(token));
    }
}

public sealed class DpapiConnectionRecoveryMaterialIssuer(
    SingleUseControlConnectAuthorizationValidator authorization,
    DpapiRdpDvcEvidenceTicketStore evidenceTickets) :
    IConnectionRecoveryMaterialIssuer
{
    public ValueTask<ConnectionRecoveryMaterial> IssueAsync(
        DesiredConnectionRecord desired,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        desired = desired.Validate();
        var token = Convert.ToHexString(
            RandomNumberGenerator.GetBytes(32));
        var evidenceReference = "recovery-" +
            RandomNumberGenerator.GetHexString(24);
        evidenceTickets.Write(
            evidenceReference,
            new(
                desired.SessionId,
                desired.HostId,
                desired.NodeIncarnationId,
                0,
                Guid.NewGuid(),
                ProtocolVersion: 2));
        authorization.Register(token);
        return ValueTask.FromResult(
            new ConnectionRecoveryMaterial(token, evidenceReference));
    }
}
public sealed record RdCoreRuntimeEvidence(
    RdCoreDvcEvidenceEvent Event,
    string? PluginAddInName = null,
    Guid? PluginClsid = null,
    string? ChannelName = null);

public sealed record RdCorePresentationCapabilities(
    bool SameConnectionView,
    bool SameConnectionControl,
    string EvidenceCode)
{
    public const string VerifiedEvidenceCode =
        "RDCORE_SAME_CONNECTION_PRESENTATION_VERIFIED";

    public bool IsVerified =>
        string.Equals(
            EvidenceCode,
            VerifiedEvidenceCode,
            StringComparison.Ordinal);
}

public sealed class RdCoreConnectionStartRequest
{
    public RdCoreConnectionStartRequest(
        string connectionId,
        Uri providerResourceUri,
        Stream signedRdpContent,
        RdCorePackageArtifacts package,
        DvcPluginRegistrationStatus registration,
        string? dvcEvidenceReference = null)
    {
        ConnectionId = connectionId;
        ProviderResourceUri = providerResourceUri;
        SignedRdpContent = signedRdpContent;
        Package = package;
        Registration = registration;
        DvcEvidenceReference = dvcEvidenceReference;
    }

    public string ConnectionId { get; }
    public Uri ProviderResourceUri { get; }
    public Stream SignedRdpContent { get; }
    public RdCorePackageArtifacts Package { get; }
    public DvcPluginRegistrationStatus Registration { get; }
    public string? DvcEvidenceReference { get; }

    public override string ToString() =>
        "RdCoreConnectionStartRequest { ProviderResourceUri = [REDACTED], " +
        "SignedRdpContent = [REDACTED] }";
}

public sealed record RdCoreConnectionRuntimeResult(
    string RuntimeConnectionId,
    long ConnectionGeneration,
    IReadOnlyList<RdCoreRuntimeEvidence> Evidence,
    RdCorePresentationCapabilities PresentationCapabilities)
{
    public override string ToString() =>
        $"RdCoreConnectionRuntimeResult {{ Generation = " +
        $"{ConnectionGeneration}, EvidenceCount = {Evidence.Count} }}";
}

public sealed record RdCorePresentationProof(
    string RuntimeConnectionId,
    long ConnectionGeneration,
    string EvidenceCode);

public interface IRdCoreConnectionRuntime
{
    Task<RdCoreConnectionRuntimeResult> ConnectAsync(
        RdCoreConnectionStartRequest request,
        CancellationToken cancellationToken);

    Task<RdCoreConnectionRuntimeResult?> ReconcileAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);

    Task<RdCorePresentationProof> ViewExistingAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);

    Task<RdCorePresentationProof> TakeControlAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);

    Task ReleaseControlAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);

    Task DisconnectAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);
}

public sealed class DisabledRdCoreConnectionRuntime : IRdCoreConnectionRuntime
{
    private const string Message =
        "The production RDCore runtime adapter is not configured.";

    public Task<RdCoreConnectionRuntimeResult> ConnectAsync(
        RdCoreConnectionStartRequest request,
        CancellationToken cancellationToken) =>
        Task.FromException<RdCoreConnectionRuntimeResult>(
            new InvalidOperationException(Message));

    public Task<RdCoreConnectionRuntimeResult?> ReconcileAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken) =>
        Task.FromResult<RdCoreConnectionRuntimeResult?>(null);

    public Task<RdCorePresentationProof> ViewExistingAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken) =>
        Task.FromException<RdCorePresentationProof>(
            new InvalidOperationException(Message));

    public Task<RdCorePresentationProof> TakeControlAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken) =>
        Task.FromException<RdCorePresentationProof>(
            new InvalidOperationException(Message));

    public Task ReleaseControlAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken) =>
        Task.FromException(new InvalidOperationException(Message));

    public Task DisconnectAsync(
        string runtimeConnectionId,
        long connectionGeneration,
        CancellationToken cancellationToken) =>
        Task.FromException(new InvalidOperationException(Message));
}
