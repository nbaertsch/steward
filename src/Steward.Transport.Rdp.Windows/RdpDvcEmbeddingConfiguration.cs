using System.Text.Json;

namespace Steward.Transport.Rdp.Windows;

public sealed record RdpDvcEmbeddingConfiguration(
    int Version,
    string EvidencePipeName,
    string EvidenceKeyFile,
    string DiagnosticLogFile);

public static class RdpDvcEmbeddingConfigurationStore
{
    public const int CurrentVersion = 2;
    public const string ConfigurationPathEnvironmentVariable =
        "STEWARD_RDP_DVC_EMBEDDING_CONFIGURATION_FILE";

    public static string CurrentPath
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable(
                ConfigurationPathEnvironmentVariable);
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException(
                    "The DVC embedding configuration path is required.");
            if (!Path.IsPathFullyQualified(configured))
                throw new InvalidDataException(
                    "The DVC embedding configuration path must be absolute.");
            return Path.GetFullPath(configured);
        }
    }

    public static void Write(
        string evidencePipeName,
        string evidenceKeyFile)
    {
        Validate(evidencePipeName, evidenceKeyFile);
        var path = CurrentPath;
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        if (File.GetAttributes(directory)
            .HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "The DVC embedding configuration directory is unsafe.");
        var temporary = path + "." +
            Guid.NewGuid().ToString("N") + ".tmp";
        var diagnosticLog = Path.Combine(
            directory,
            "embedding.log");
        if (File.Exists(diagnosticLog))
            File.Delete(diagnosticLog);
        try
        {
            File.WriteAllBytes(
                temporary,
                JsonSerializer.SerializeToUtf8Bytes(
                    new RdpDvcEmbeddingConfiguration(
                        CurrentVersion,
                        evidencePipeName,
                        Path.GetFullPath(evidenceKeyFile),
                        diagnosticLog)));
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    public static RdpDvcEmbeddingConfiguration Load()
    {
        var path = CurrentPath;
        if (!File.Exists(path) ||
            File.GetAttributes(path)
                .HasFlag(FileAttributes.ReparsePoint) ||
            new FileInfo(path).Length is <= 0 or > 16 * 1024)
            throw new InvalidDataException(
                "The DVC embedding configuration is unavailable.");
        var configuration =
            JsonSerializer.Deserialize<RdpDvcEmbeddingConfiguration>(
                File.ReadAllBytes(path)) ??
            throw new InvalidDataException(
                "The DVC embedding configuration is invalid.");
        if (configuration.Version != CurrentVersion)
            throw new InvalidDataException(
                "The DVC embedding configuration version is invalid.");
        Validate(
            configuration.EvidencePipeName,
            configuration.EvidenceKeyFile);
        if (!Path.IsPathFullyQualified(configuration.DiagnosticLogFile))
            throw new InvalidDataException(
                "The DVC diagnostic log path must be absolute.");
        return configuration;
    }

    public static void Delete()
    {
        var path = CurrentPath;
        if (File.Exists(path))
            File.Delete(path);
    }

    private static void Validate(
        string evidencePipeName,
        string evidenceKeyFile)
    {
        if (string.IsNullOrWhiteSpace(evidencePipeName) ||
            evidencePipeName.Length > 128 ||
            evidencePipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new InvalidDataException(
                "The DVC evidence pipe name is invalid.");
        if (!Path.IsPathFullyQualified(evidenceKeyFile))
            throw new InvalidDataException(
                "The DVC evidence key path must be absolute.");
        var path = Path.GetFullPath(evidenceKeyFile);
        if (!File.Exists(path) ||
            File.GetAttributes(path)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "The DVC evidence key file is unavailable.");
    }
}
