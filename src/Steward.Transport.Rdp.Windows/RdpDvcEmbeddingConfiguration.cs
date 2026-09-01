using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Steward.Transport.Rdp.Windows;

public sealed record RdpDvcEmbeddingConfiguration(
    int Version,
    string BrokerPipeName,
    string EvidencePipeName,
    string EvidenceKeyFile,
    string DiagnosticLogFile);

public static class RdpDvcEmbeddingConfigurationStore
{
    public const int CurrentVersion = 3;
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
        string brokerPipeName,
        string evidencePipeName,
        string evidenceKeyFile) =>
        Write(
            CurrentPath,
            brokerPipeName,
            evidencePipeName,
            evidenceKeyFile);

    public static void Write(
        string path,
        string brokerPipeName,
        string evidencePipeName,
        string evidenceKeyFile)
    {
        Validate(brokerPipeName, evidencePipeName, evidenceKeyFile);
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException(
                "The DVC embedding configuration path must be absolute.");
        path = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(path)!;
        PreparePrivateDirectory(directory);
        var temporary = path + "." +
            Guid.NewGuid().ToString("N") + ".tmp";
        var diagnosticLog = Path.ChangeExtension(path, ".log");
        if (File.Exists(diagnosticLog))
            DeletePrivateFile(diagnosticLog);
        try
        {
            File.WriteAllBytes(
                temporary,
                JsonSerializer.SerializeToUtf8Bytes(
                    new RdpDvcEmbeddingConfiguration(
                        CurrentVersion,
                        brokerPipeName,
                        evidencePipeName,
                        Path.GetFullPath(evidenceKeyFile),
                        diagnosticLog)));
            RestrictFile(temporary);
            File.Move(temporary, path, overwrite: true);
            RestrictFile(path);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    public static RdpDvcEmbeddingConfiguration Load() =>
        Load(CurrentPath);

    public static RdpDvcEmbeddingConfiguration Load(string path)
    {
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException(
                "The DVC embedding configuration path must be absolute.");
        path = Path.GetFullPath(path);
        EnsurePrivateDirectory(Path.GetDirectoryName(path)!);
        if (!File.Exists(path) ||
            File.GetAttributes(path)
                .HasFlag(FileAttributes.ReparsePoint) ||
            new FileInfo(path).Length is <= 0 or > 16 * 1024)
            throw new InvalidDataException(
                "The DVC embedding configuration is unavailable.");
        EnsurePrivateFile(path);
        var configuration =
            JsonSerializer.Deserialize<RdpDvcEmbeddingConfiguration>(
                File.ReadAllBytes(path)) ??
            throw new InvalidDataException(
                "The DVC embedding configuration is invalid.");
        if (configuration.Version != CurrentVersion)
            throw new InvalidDataException(
                "The DVC embedding configuration version is invalid.");
        Validate(
            configuration.BrokerPipeName,
            configuration.EvidencePipeName,
            configuration.EvidenceKeyFile);
        if (!Path.IsPathFullyQualified(configuration.DiagnosticLogFile))
            throw new InvalidDataException(
                "The DVC diagnostic log path must be absolute.");
        return configuration;
    }

    public static void Delete() => Delete(CurrentPath);

    public static void Delete(string path)
    {
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException(
                "The DVC embedding configuration path must be absolute.");
        path = Path.GetFullPath(path);
        if (File.Exists(path))
            DeletePrivateFile(path);
    }

    private static void Validate(
        string brokerPipeName,
        string evidencePipeName,
        string evidenceKeyFile)
    {
        ValidatePipeName(brokerPipeName, "DVC broker");
        ValidatePipeName(evidencePipeName, "DVC evidence");
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

    private static void ValidatePipeName(
        string pipeName,
        string description)
    {
        if (string.IsNullOrWhiteSpace(pipeName) ||
            pipeName.Length > 128 ||
            pipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new InvalidDataException(
                $"The {description} pipe name is invalid.");
    }

    private static void PreparePrivateDirectory(string directory)
    {
        EnsureNoReparseSegments(directory);
        Directory.CreateDirectory(directory);
        EnsureNoReparseSegments(directory);
        var current = CurrentUser();
        var security = new DirectorySecurity();
        security.SetOwner(current);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new(
            current,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    private static void EnsurePrivateDirectory(string directory)
    {
        EnsureNoReparseSegments(directory);
        var current = CurrentUser();
        var security = new DirectoryInfo(directory).GetAccessControl();
        if (!security.AreAccessRulesProtected ||
            !current.Equals(
                security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException(
                "The DVC embedding configuration directory is not private.");
        EnsureOnlyCurrentUserAllows(security, current);
    }

    private static void RestrictFile(string path)
    {
        var current = CurrentUser();
        var security = new FileSecurity();
        security.SetOwner(current);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static void EnsurePrivateFile(string path)
    {
        EnsureNoReparseSegments(path);
        var current = CurrentUser();
        var security = new FileInfo(path).GetAccessControl();
        if (!security.AreAccessRulesProtected ||
            !current.Equals(
                security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException(
                "The DVC embedding configuration file is not private.");
        EnsureOnlyCurrentUserAllows(security, current);
    }

    private static void DeletePrivateFile(string path)
    {
        EnsurePrivateFile(path);
        File.Delete(path);
    }

    private static void EnsureOnlyCurrentUserAllows(
        FileSystemSecurity security,
        SecurityIdentifier current)
    {
        var rules = security.GetAccessRules(
            true,
            true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType == AccessControlType.Allow &&
                !current.Equals(rule.IdentityReference))
                throw new UnauthorizedAccessException(
                    "The DVC embedding configuration grants unintended access.");
    }

    private static SecurityIdentifier CurrentUser() =>
        WindowsIdentity.GetCurrent().User ??
        throw new InvalidOperationException(
            "The current Windows identity has no SID.");

    private static void EnsureNoReparseSegments(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ??
            throw new InvalidDataException(
                "The DVC embedding configuration path has no root.");
        var current = root;
        foreach (var segment in full[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                File.GetAttributes(current).HasFlag(
                    FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "The DVC embedding configuration path cannot traverse reparse points.");
        }
    }
}
