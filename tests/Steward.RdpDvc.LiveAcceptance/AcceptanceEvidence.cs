using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.LiveAcceptance;

internal sealed record RemoteBootstrapGeneration(
    string EvidenceReference,
    Guid ConnectionNonce);

internal sealed record LivePreflightEvidence(
    bool PackageCompatible,
    string PackageFullName,
    string PackageVersion,
    bool DevBoxDefaultIdentityReady,
    string IdentityContext,
    bool ExactDvcRegistration,
    string DvcRegistrationCode,
    bool BootstrapDeployInvoked,
    string BootstrapDeploymentReceiptSha256);

internal sealed record SurfaceObservationEvidence(
    DateTimeOffset ObservedAtUtc,
    int ProcessCount,
    int TopLevelWindowCount,
    string ProcessSetSha256,
    string TopLevelWindowSetSha256,
    long ForegroundWindow);

internal sealed record LiveGenerationEvidence(
    int Ordinal,
    long ConnectionGeneration,
    int RdpSessionId,
    string NonceSha256,
    long PingSequence,
    double? PingRoundTripMilliseconds,
    IReadOnlyList<RdCoreDvcEvidenceEvent> OrderedEvidence,
    string ConnectionStatusCode);

internal sealed record RdCoreLiveAcceptanceEvidence(
    int Version,
    string RunId,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset FinishedAtUtc,
    bool LiveConnectExplicitlyAllowed,
    bool CloudReadExplicitlyAllowed,
    bool CloudMutationAllowed,
    bool BillableMutationAllowed,
    bool MsAvdShellActivationUsed,
    bool ViewInvoked,
    string PluginClsid,
    string PluginAddInName,
    string ChannelName,
    LivePreflightEvidence Preflight,
    SurfaceObservationEvidence InitialSurface,
    SurfaceObservationEvidence FinalSurface,
    IReadOnlyList<LiveGenerationEvidence> Generations,
    bool NoVisibleSurfaceObserved,
    bool SecretsExcluded,
    bool Passed);

[JsonSerializable(typeof(RdCoreLiveAcceptanceEvidence))]
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
internal sealed partial class AcceptanceJsonContext : JsonSerializerContext;

internal static class RemoteBootstrapEvidenceLoader
{
    internal static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value));
}

internal static class AcceptanceEvidenceStore
{
    internal static async Task SaveAsync(
        string directory,
        RdCoreLiveAcceptanceEvidence evidence,
        IReadOnlyCollection<string> sensitiveValues,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(directory);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            evidence,
            AcceptanceJsonContext.Default.RdCoreLiveAcceptanceEvidence);
        AssertNoSecrets(bytes, sensitiveValues);
        var path = Path.Combine(
            directory,
            $"rdcore-evidence-{evidence.RunId}.json");
        var pending = path + ".new";
        await using (var stream = new FileStream(
                         pending,
                         FileMode.CreateNew,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.Asynchronous |
                         FileOptions.WriteThrough))
        {
            await stream.WriteAsync(bytes, cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        File.Move(pending, path);
    }

    internal static async Task TrySaveFailureAsync(
        string directory,
        string failureType,
        CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var runId = Guid.NewGuid().ToString("N");
            var text = JsonSerializer.Serialize(
                new
                {
                    version = 1,
                    runId,
                    finishedAtUtc = DateTimeOffset.UtcNow,
                    passed = false,
                    failureType
                });
            await File.WriteAllTextAsync(
                    Path.Combine(
                        directory,
                        $"rdcore-failure-{runId}.json"),
                    text,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
        }
    }

    internal static void AssertNoSecrets(
        ReadOnlySpan<byte> evidence,
        IReadOnlyCollection<string> sensitiveValues)
    {
        var text = Encoding.UTF8.GetString(evidence);
        foreach (var sensitive in sensitiveValues)
        {
            if (string.IsNullOrEmpty(sensitive))
                continue;
            if (text.Contains(sensitive, StringComparison.Ordinal) ||
                text.Contains(
                    Uri.EscapeDataString(sensitive),
                    StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Acceptance evidence contains a sensitive value.");
        }
    }
}
