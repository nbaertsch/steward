using System.Globalization;
using System.Text.RegularExpressions;

namespace Steward.Maintenance.Windows;

internal sealed record SignedEndpointReleaseManifest(
    int Version,
    string MsiFile,
    string ProductVersion,
    string MsiSha256,
    long MsiLength,
    Guid ProductCode,
    Guid UpgradeCode,
    string CatalogIdentity,
    string AttestationBundleFile,
    ArtifactProvenance Provenance);

internal static partial class EndpointReleaseManifestParser
{
    private const int MaximumManifestBytes = 32 * 1024;

    internal static SignedEndpointReleaseManifest Parse(string path)
    {
        EndpointUpdateFileValidator.EnsureRegularFile(path);
        var file = new FileInfo(path);
        if (file.Length is <= 0 or > MaximumManifestBytes)
            throw Invalid("Endpoint release manifest size is invalid.");
        var content = File.ReadAllText(path);
        var assignments = Assignment().Matches(content);
        if (!Header().IsMatch(content) ||
            assignments.Count != 14 ||
            assignments.Select(match => match.Groups[1].Value)
                .Distinct(StringComparer.Ordinal).Count() != assignments.Count)
            throw Invalid("Endpoint release manifest shape is invalid.");
        var version = Integer(content, "Version");
        var msiLength = Long(content, "MsiLength");
        var productCode = GuidValue(content, "ProductCode");
        var upgradeCode = GuidValue(content, "UpgradeCode");
        var provenance = new ArtifactProvenance(
            1,
            Text(content, "SourceRepository"),
            Text(content, "SourceCommit"),
            Text(content, "SourceRef"),
            Text(content, "SignerWorkflow"),
            Text(content, "SourceRunId"));
        return new SignedEndpointReleaseManifest(
            version,
            Text(content, "MsiFile"),
            Text(content, "ProductVersion"),
            Text(content, "MsiSha256"),
            msiLength,
            productCode,
            upgradeCode,
            Text(content, "CatalogIdentity"),
            Text(content, "AttestationBundleFile"),
            provenance);
    }

    internal static void ValidateBinding(
        SignedEndpointReleaseManifest manifest,
        ActivateEndpointUpdateOperation operation)
    {
        if (manifest.Version != 4 ||
            !string.Equals(
                manifest.MsiFile,
                "Steward.Endpoint.Msi.msi",
                StringComparison.Ordinal) ||
            !string.Equals(
                manifest.AttestationBundleFile,
                "Steward.Endpoint.Msi.sigstore.json",
                StringComparison.Ordinal) ||
            !string.Equals(
                manifest.ProductVersion,
                operation.Release.ProductVersion,
                StringComparison.Ordinal) ||
            !string.Equals(
                manifest.MsiSha256,
                operation.Release.MsiSha256,
                StringComparison.OrdinalIgnoreCase) ||
            manifest.MsiLength != operation.Release.MsiLength ||
            manifest.ProductCode != operation.Release.ProductCode ||
            manifest.UpgradeCode != operation.Release.UpgradeCode ||
            !string.Equals(
                manifest.CatalogIdentity,
                operation.Release.CatalogIdentity,
                StringComparison.Ordinal) ||
            manifest.Provenance != operation.Provenance)
            throw new EndpointUpdateException(
                "release_mismatch",
                "Signed endpoint release manifest does not match the request.");
    }

    private static string Text(string content, string name)
    {
        var match = Regex.Match(
            content,
            $@"(?m)^\s*{Regex.Escape(name)}\s*=\s*'([^'\r\n]*)'\s*$",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
        if (!match.Success)
            throw Invalid($"Endpoint release manifest {name} is missing.");
        return match.Groups[1].Value;
    }

    private static int Integer(string content, string name) =>
        int.TryParse(
            Number(content, name),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var value)
            ? value
            : throw Invalid($"Endpoint release manifest {name} is invalid.");

    private static long Long(string content, string name) =>
        long.TryParse(
            Number(content, name),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var value)
            ? value
            : throw Invalid($"Endpoint release manifest {name} is invalid.");

    private static string Number(string content, string name)
    {
        var match = Regex.Match(
            content,
            $@"(?m)^\s*{Regex.Escape(name)}\s*=\s*([0-9]+)\s*$",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
        if (!match.Success)
            throw Invalid($"Endpoint release manifest {name} is missing.");
        return match.Groups[1].Value;
    }

    private static Guid GuidValue(string content, string name) =>
        Guid.TryParse(Text(content, name), out var value) && value != Guid.Empty
            ? value
            : throw Invalid($"Endpoint release manifest {name} is invalid.");

    private static EndpointUpdateException Invalid(string message) =>
        new("release_manifest_invalid", message);

    [GeneratedRegex(
        @"(?m)^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(?:'[^'\r\n]*'|[0-9]+)\s*$",
        RegexOptions.CultureInvariant)]
    private static partial Regex Assignment();

    [GeneratedRegex(
        @"\A\s*@\{(?:.|\r|\n)*\}\s*\z",
        RegexOptions.CultureInvariant)]
    private static partial Regex Header();
}
