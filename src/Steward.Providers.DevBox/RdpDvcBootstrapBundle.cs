using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace Steward.Providers.DevBox;

public sealed record RdpDvcBootstrapManifestEntry(
    string RelativePath,
    long Length,
    string Sha256)
{
    public RdpDvcBootstrapManifestEntry Validate()
    {
        RdpDvcBootstrapBundle.ValidateRelativePath(RelativePath);
        if (Length < 0 ||
            Sha256.Length != 64 ||
            Sha256.Any(character => !char.IsAsciiHexDigit(character)))
            throw new ArgumentException("RDP DVC bundle manifest entry is invalid.");
        return this;
    }
}

public sealed record RdpDvcBootstrapManifest(
    int FormatVersion,
    string Version,
    IReadOnlyList<RdpDvcBootstrapManifestEntry> Files);

public sealed record RdpDvcBootstrapBundle(
    RdpDvcBootstrapManifest Manifest,
    BinaryData Archive,
    string ArchiveSha256)
{
    public const int MaximumArchiveBytes = 3 * 1024 * 1024;
    public const int MaximumPayloadFileBytes = 8 * 1024 * 1024;
    public const int MaximumExpandedArchiveBytes = 16 * 1024 * 1024;
    public const string ManifestPath = "manifest.json";

    private static readonly string[] RequiredFiles =
    [
        "Microsoft.RdpDvcSamples.LICENSE.txt",
        "Steward.HandleKeeper.deps.json",
        "Steward.HandleKeeper.dll",
        "Steward.HandleKeeper.runtimeconfig.json",
        "Steward.RdpDvc.Server.Windows.deps.json",
        "Steward.RdpDvc.Server.Windows.dll",
        "Steward.RdpDvc.Server.Windows.runtimeconfig.json"
    ];

    public static RdpDvcBootstrapBundle Load(string archivePath)
    {
        var path = Path.GetFullPath(archivePath);
        if (!File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new ArgumentException(
                "RDP DVC bootstrap archive must be an existing regular file.",
                nameof(archivePath));
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is 0 or > MaximumArchiveBytes)
            throw new InvalidDataException(
                "RDP DVC bootstrap archive exceeds its bound.");
        var archiveFiles = ReadArchive(bytes);
        if (!archiveFiles.TryGetValue(
                ManifestPath,
                out var manifestBytes))
            throw new InvalidDataException(
                "RDP DVC bootstrap manifest is missing.");
        if (manifestBytes.Length is <= 0 or > 256 * 1024)
            throw new InvalidDataException(
                "RDP DVC bootstrap manifest exceeds its bound.");
        RdpDvcBootstrapManifest manifest;
        manifest = JsonSerializer.Deserialize<RdpDvcBootstrapManifest>(
                       manifestBytes,
                       new JsonSerializerOptions(
                           JsonSerializerDefaults.Web))
                   ?? throw new InvalidDataException(
                       "RDP DVC bootstrap manifest is empty.");
        var expectedEntries = new HashSet<string>(
            manifest.Files.Select(file => $"payload/{file.RelativePath}"),
            StringComparer.Ordinal)
        {
            ManifestPath
        };
        if (archiveFiles.Count != expectedEntries.Count ||
            archiveFiles.Keys.Any(path =>
                !expectedEntries.Contains(path)))
            throw new InvalidDataException(
                "RDP DVC bootstrap archive contains unmanifested files.");
        foreach (var file in manifest.Files)
        {
            file.Validate();
            if (!archiveFiles.TryGetValue(
                    $"payload/{file.RelativePath}",
                    out var content))
                throw new InvalidDataException(
                    "RDP DVC bootstrap payload file is missing.");
            if (content.LongLength != file.Length ||
                content.Length > MaximumPayloadFileBytes)
                throw new InvalidDataException(
                    "RDP DVC bootstrap payload length is invalid.");
            var hash = Convert.ToHexString(
                    SHA256.HashData(content))
                .ToLowerInvariant();
            if (!string.Equals(
                    hash,
                    file.Sha256,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException(
                    "RDP DVC bootstrap payload hash is invalid.");
        }
        return new RdpDvcBootstrapBundle(
                manifest,
                BinaryData.FromBytes(bytes),
                Convert.ToHexString(SHA256.HashData(bytes))
                    .ToLowerInvariant())
            .Validate();
    }

    public static RdpDvcBootstrapBundle CreateFromPublishDirectory(
        string publishDirectory,
        string version)
    {
        ValidateVersion(version);
        var root = Path.GetFullPath(publishDirectory);
        if (!Directory.Exists(root) ||
            (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new ArgumentException(
                "RDP DVC publish directory must be an existing regular directory.",
                nameof(publishDirectory));

        var files = Directory.EnumerateFiles(
                root,
                "*",
                SearchOption.TopDirectoryOnly)
            .Where(IsRemoteBundleFile)
            .Select(path =>
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException(
                        "RDP DVC bundle files cannot be reparse points.");
                var relativePath = Path.GetRelativePath(root, path)
                    .Replace('\\', '/');
                ValidateRelativePath(relativePath);
                var content = File.ReadAllBytes(path);
                if (content.Length > MaximumPayloadFileBytes)
                    throw new InvalidDataException(
                        "RDP DVC bundle payload file exceeds its bound.");
                return new BundleFile(
                    relativePath,
                    content,
                    Convert.ToHexString(SHA256.HashData(content))
                        .ToLowerInvariant());
            })
            .OrderBy(file => file.RelativePath, StringComparer.Ordinal)
            .ToArray();

        var names = files.Select(file => file.RelativePath)
            .ToHashSet(StringComparer.Ordinal);
        if (RequiredFiles.Any(required => !names.Contains(required)))
            throw new InvalidDataException(
                "Framework-dependent RDP DVC publish output is incomplete.");
        if (files.Any(file =>
                file.RelativePath is "coreclr.dll" or "hostfxr.dll" or "hostpolicy.dll"))
            throw new InvalidDataException(
                "RDP DVC bundle must be framework-dependent, not self-contained.");

        var entries = files.Select(file =>
                new RdpDvcBootstrapManifestEntry(
                    file.RelativePath,
                    file.Content.LongLength,
                    file.Sha256))
            .ToArray();
        var manifest = new RdpDvcBootstrapManifest(1, version, entries);
        var manifestBytes = WriteManifest(manifest);
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(
                   output,
                   ZipArchiveMode.Create,
                   leaveOpen: true))
        {
            AddEntry(archive, ManifestPath, manifestBytes);
            foreach (var file in files)
                AddEntry(
                    archive,
                    $"payload/{file.RelativePath}",
                    file.Content);
        }
        if (output.Length > MaximumArchiveBytes)
            throw new InvalidDataException(
                "RDP DVC bootstrap archive exceeds its bound.");
        var bytes = output.ToArray();
        return new(
            manifest,
            BinaryData.FromBytes(bytes),
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
    }

    public RdpDvcBootstrapBundle Validate()
    {
        ValidateVersion(Manifest.Version);
        if (Manifest.FormatVersion != 1 ||
            Manifest.Files.Count is 0 or > 128 ||
            Archive.ToMemory().Length is 0 or > MaximumArchiveBytes ||
            ArchiveSha256.Length != 64 ||
            ArchiveSha256.Any(character => !char.IsAsciiHexDigit(character)))
            throw new ArgumentException("RDP DVC bootstrap bundle is invalid.");
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in Manifest.Files)
        {
            file.Validate();
            if (!paths.Add(file.RelativePath))
                throw new ArgumentException(
                    "RDP DVC bundle manifest contains duplicate paths.");
        }
        if (RequiredFiles.Any(required => !paths.Contains(required)))
            throw new ArgumentException(
                "RDP DVC bundle manifest is missing a required managed component.");
        var actual = Convert.ToHexString(
                SHA256.HashData(Archive.ToMemory().Span))
            .ToLowerInvariant();
        if (!string.Equals(
                actual,
                ArchiveSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                "RDP DVC bootstrap archive hash does not match.");
        return this;
    }

    public static void ValidateRelativePath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) ||
            relativePath.Length > 240 ||
            Path.IsPathRooted(relativePath) ||
            relativePath.Contains('\\') ||
            relativePath.Split('/').Any(segment =>
                segment.Length is 0 or > 128 ||
                segment is "." or ".." ||
                segment.Any(character =>
                    char.IsControl(character) ||
                    character is ':' or '*' or '?' or '"' or '<' or '>' or '|')))
            throw new ArgumentException(
                "RDP DVC bundle path is unsafe.",
                nameof(relativePath));
    }

    public static void ValidateVersion(string version)
    {
        if (string.IsNullOrWhiteSpace(version) ||
            version.Length > 64 ||
            version.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_'))
            throw new ArgumentException(
                "RDP DVC bundle version is invalid.",
                nameof(version));
    }

    private static bool IsRemoteBundleFile(string path)
    {
        var name = Path.GetFileName(path);
        return name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(
                   name,
                   "Microsoft.RdpDvcSamples.LICENSE.txt",
                   StringComparison.Ordinal);
    }

    private static byte[] WriteManifest(RdpDvcBootstrapManifest manifest)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
                   output,
                   new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("formatVersion", manifest.FormatVersion);
            writer.WriteString("version", manifest.Version);
            writer.WriteStartArray("files");
            foreach (var file in manifest.Files)
            {
                writer.WriteStartObject();
                writer.WriteString("relativePath", file.RelativePath);
                writer.WriteNumber("length", file.Length);
                writer.WriteString("sha256", file.Sha256);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return output.ToArray();
    }

    private static void AddEntry(
        ZipArchive archive,
        string path,
        ReadOnlySpan<byte> content)
    {
        var entry = archive.CreateEntry(
            path,
            CompressionLevel.SmallestSize);
        entry.LastWriteTime = new DateTimeOffset(
            1980,
            1,
            1,
            0,
            0,
            0,
            TimeSpan.Zero);
        using var stream = entry.Open();
        stream.Write(content);
    }

    private static Dictionary<string, byte[]> ReadArchive(
        ReadOnlySpan<byte> compressed)
    {
        using var source = new MemoryStream(
            compressed.ToArray(),
            writable: false);
        ZipArchive archive;
        try
        {
            archive = new ZipArchive(
                source,
                ZipArchiveMode.Read,
                leaveOpen: false);
        }
        catch (InvalidDataException exception)
        {
            throw new InvalidDataException(
                "RDP DVC bootstrap archive compression is invalid.",
                exception);
        }
        using (archive)
        {
        var files = new Dictionary<string, byte[]>(
            StringComparer.Ordinal);
            long expandedBytes = 0;
            foreach (var entry in archive.Entries)
        {
                if (string.IsNullOrEmpty(entry.Name) ||
                    entry.Length < 0 ||
                    (expandedBytes += entry.Length) >
                        MaximumExpandedArchiveBytes)
                    throw new InvalidDataException(
                        "RDP DVC bootstrap archive contains an invalid entry.");
                using var stream = entry.Open();
                if (
                    !files.TryAdd(
                        entry.FullName,
                        ReadBounded(
                            stream,
                            entry.FullName == ManifestPath
                                ? 256 * 1024
                                : MaximumPayloadFileBytes)))
                    throw new InvalidDataException(
                        "RDP DVC bootstrap archive contains an invalid entry.");
        }
        return files;
        }
    }

    private static byte[] ReadBounded(
        Stream stream,
        int maximumBytes)
    {
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = stream.Read(buffer);
            if (read == 0)
                return output.ToArray();
            if (output.Length + read > maximumBytes)
                throw new InvalidDataException(
                    "RDP DVC bootstrap entry exceeds its bound.");
            output.Write(buffer, 0, read);
        }
    }

    private sealed record BundleFile(
        string RelativePath,
        byte[] Content,
        string Sha256);
}
