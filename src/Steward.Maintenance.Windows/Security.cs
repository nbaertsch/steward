using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Steward.Maintenance.Windows;

internal static class MaintenanceStateSecurity
{
    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static void Protect(string stateRoot)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Maintenance state ACLs require Windows.");
        ArgumentException.ThrowIfNullOrWhiteSpace(stateRoot);
        var full = Path.GetFullPath(stateRoot);
        Directory.CreateDirectory(full);
        ValidatePath(full);
        var security = CreateDescriptor();
        new DirectoryInfo(full).SetAccessControl(security);
        ValidateTree(full);
        ValidateIsolation(full);
    }

    public static DirectorySecurity CreateDescriptor()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Maintenance state ACLs require Windows.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.SetOwner(SystemSid);
        AddFullControl(security, SystemSid);
        AddFullControl(security, AdministratorsSid);
        return security;
    }
    public static void ValidateTree(string stateRoot)
    {
        ValidatePath(stateRoot);
        foreach (var entry in Directory.EnumerateFileSystemEntries(
                     stateRoot,
                     "*",
                     SearchOption.AllDirectories))
            if (File.GetAttributes(entry).HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "Maintenance state cannot contain reparse points.");
    }

    public static void ValidateIsolation(string stateRoot)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Maintenance state ACLs require Windows.");
        var trusted = new HashSet<string>(StringComparer.Ordinal)
        {
            SystemSid.Value,
            AdministratorsSid.Value
        };
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     stateRoot,
                     "*",
                     SearchOption.AllDirectories).Prepend(stateRoot))
        {
            FileSystemSecurity security = Directory.Exists(path)
                ? new DirectoryInfo(path).GetAccessControl()
                : new FileInfo(path).GetAccessControl();
            if (string.Equals(path, stateRoot, StringComparison.OrdinalIgnoreCase) &&
                !security.AreAccessRulesProtected)
                throw new UnauthorizedAccessException(
                    "Maintenance state root inherits authority.");
            var owner = security.GetOwner(typeof(SecurityIdentifier));
            if (owner is not SecurityIdentifier ownerSid ||
                !trusted.Contains(ownerSid.Value))
                throw new UnauthorizedAccessException(
                    "Maintenance state owner is not trusted.");
            var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
                if (rule.AccessControlType == AccessControlType.Allow &&
                    !trusted.Contains(rule.IdentityReference.Value))
                    throw new UnauthorizedAccessException(
                        "Maintenance state grants unintended authority.");
        }
    }

    public static void ValidatePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ??
            throw new InvalidDataException(
                "Maintenance state has no path root.");
        var current = root;
        foreach (var segment in full[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((Directory.Exists(current) || File.Exists(current)) &&
                File.GetAttributes(current).HasFlag(
                    FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "Maintenance state path cannot traverse reparse points.");
        }
    }

    private static void AddFullControl(
        DirectorySecurity security,
        SecurityIdentifier sid) =>
        security.AddAccessRule(new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
}

internal sealed record MaintenanceServiceConfiguration(
    int Version,
    string PipeName,
    string NodeUserSid,
    string NodeUserAccount,
    string ControlIdentity,
    string KeeperPipeName,
    Guid HostId,
    string InstalledProductVersion,
    string ApprovedSourceRepository,
    string ApprovedSignerWorkflow,
    string EndpointStateRoot,
    string InstallRoot,
    string VersionedRoot,
    string EndpointUpgradeCode)
{
    public static MaintenanceServiceConfiguration Load(string stateRoot)
    {
        MaintenanceStateSecurity.ValidatePath(stateRoot);
        var path = Path.Combine(stateRoot, "service-config.json");
        if (!File.Exists(path) ||
            File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint) ||
            new FileInfo(path).Length is <= 0 or > 16 * 1024)
            throw new InvalidDataException(
                "Maintenance service configuration is unavailable.");
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            PropertyNameCaseInsensitive = false
        };
        MaintenanceServiceConfiguration configuration;
        try
        {
            configuration = JsonSerializer.Deserialize<
                                MaintenanceServiceConfiguration>(
                                File.ReadAllBytes(path),
                                options)
                            ?? throw new InvalidDataException(
                                "Maintenance service configuration is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Maintenance service configuration is malformed.",
                exception);
        }
        configuration.Validate();
        return configuration;
    }

    public void Validate()
    {
        _ = new MaintenanceIpcOptions(
            PipeName,
            64 * 1024,
            4,
            TimeSpan.FromSeconds(15));
        if (Version != 1 ||
            !NodeUserSid.StartsWith("S-1-", StringComparison.Ordinal) ||
            NodeUserSid.Length > 184 ||
            string.IsNullOrWhiteSpace(NodeUserAccount) ||
            NodeUserAccount.Length > 256 ||
            string.IsNullOrWhiteSpace(ControlIdentity) ||
            ControlIdentity.Length > 200 ||
            string.IsNullOrWhiteSpace(KeeperPipeName) ||
            KeeperPipeName.Length > 128 ||
            KeeperPipeName.Any(character =>
                !(char.IsLetterOrDigit(character) ||
                  character is '-' or '_' or '.')) ||
            HostId == Guid.Empty ||
            !System.Version.TryParse(InstalledProductVersion, out _) ||
            string.IsNullOrWhiteSpace(ApprovedSourceRepository) ||
            ApprovedSignerWorkflow != ApprovedSourceRepository +
                "/.github/workflows/release-endpoint.yml" ||
            !Path.IsPathFullyQualified(EndpointStateRoot) ||
            !Path.IsPathFullyQualified(InstallRoot) ||
            !Path.IsPathFullyQualified(VersionedRoot) ||
            !Guid.TryParse(EndpointUpgradeCode, out var upgradeCode) ||
            upgradeCode == Guid.Empty)
            throw new InvalidDataException(
                "Maintenance service configuration is invalid."); MaintenanceStateSecurity.ValidatePath(EndpointStateRoot);
        MaintenanceStateSecurity.ValidatePath(InstallRoot);
        MaintenanceStateSecurity.ValidatePath(VersionedRoot);
    }
}

internal static class MaintenanceMachineSecret
{
    public static byte[] LoadOrCreate(string path)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Machine secret protection requires Windows.");
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var full = Path.GetFullPath(path);
        MaintenanceStateSecurity.ValidatePath(
            Path.GetDirectoryName(full) ?? string.Empty);
        if (File.Exists(full))
        {
            if (File.GetAttributes(full).HasFlag(FileAttributes.ReparsePoint) ||
                new FileInfo(full).Length is <= 0 or > 4096)
                throw new InvalidDataException(
                    "Maintenance machine secret is invalid.");
            var protectedBytes = File.ReadAllBytes(full);
            try
            {
                var clear = ProtectedData.Unprotect(
                    protectedBytes,
                    optionalEntropy: null,
                    DataProtectionScope.LocalMachine);
                if (clear.Length != 32)
                {
                    CryptographicOperations.ZeroMemory(clear);
                    throw new InvalidDataException(
                        "Maintenance machine secret length is invalid.");
                }
                return clear;
            }
            catch (CryptographicException exception)
            {
                throw new InvalidDataException(
                    "Maintenance machine secret authentication failed.",
                    exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }

        var secret = RandomNumberGenerator.GetBytes(32);
        var protectedSecret = ProtectedData.Protect(
            secret,
            optionalEntropy: null,
            DataProtectionScope.LocalMachine);
        try
        {
            using var stream = new FileStream(
                full,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            stream.Write(protectedSecret);
            stream.Flush(flushToDisk: true);
            return secret;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secret);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedSecret);
        }
    }
}


