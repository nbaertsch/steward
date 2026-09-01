using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace Steward.ConnectionHost.Windows;

public sealed record ConnectionHostAutoConnectOptions(
    int Version,
    Uri DevBoxEndpoint,
    string Project,
    string User,
    string DevBox,
    string ConnectionId,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId)
{
    public static async Task<ConnectionHostAutoConnectOptions?> LoadAsync(
        string? path,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor path must be absolute.");
        var fullPath = Path.GetFullPath(path);
        EnsureNoReparseSegments(fullPath);
        var directory = Path.GetDirectoryName(fullPath) ??
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor has no directory.");
        EnsurePrivateDirectory(directory);
        if (!File.Exists(fullPath) ||
            File.GetAttributes(fullPath).HasFlag(
                FileAttributes.ReparsePoint) ||
            new FileInfo(fullPath).Length is <= 0 or > 64 * 1024)
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor is unavailable.");
        var claimedPath = Path.Combine(
            directory,
            "." + Path.GetFileName(fullPath) + "." +
            Guid.NewGuid().ToString("N") + ".claimed");
        File.Move(fullPath, claimedPath);
        ConnectionHostAutoConnectOptions options;
        try
        {
            await using var stream = new FileStream(
                claimedPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None);
            EnsurePrivateDescriptor(stream);
            var protectedBytes = new byte[stream.Length];
            await stream.ReadExactlyAsync(
                protectedBytes,
                cancellationToken).ConfigureAwait(false);
            byte[]? clearBytes = null;
            try
            {
                clearBytes = ProtectedData.Unprotect(
                    protectedBytes,
                    optionalEntropy: null,
                    DataProtectionScope.CurrentUser);
                options = JsonSerializer.Deserialize<
                              ConnectionHostAutoConnectOptions>(
                              clearBytes,
                              new JsonSerializerOptions(
                                  JsonSerializerDefaults.Web))
                          ?? throw new InvalidDataException(
                              "The ConnectionHost auto-connect descriptor is empty.");
                options.Validate();
            }
            catch (CryptographicException exception)
            {
                throw new InvalidDataException(
                    "The ConnectionHost auto-connect descriptor is not protected.",
                    exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
                if (clearBytes is not null)
                    CryptographicOperations.ZeroMemory(clearBytes);
            }
        }
        finally
        {
            if (File.Exists(claimedPath))
                File.Delete(claimedPath);
        }
        return options;
    }

    public static async Task WriteProtectedAsync(
        string path,
        ConnectionHostAutoConnectOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        options.Validate();
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor path must be absolute.");
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath) ??
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor has no directory.");
        Directory.CreateDirectory(directory);
        EnsureNoReparseSegments(directory);
        RestrictDirectory(directory);
        var clearBytes = JsonSerializer.SerializeToUtf8Bytes(
            options,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        byte[]? protectedBytes = null;
        var temporary = fullPath + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            protectedBytes = ProtectedData.Protect(
                clearBytes,
                optionalEntropy: null,
                DataProtectionScope.CurrentUser);
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.WriteThrough))
            {
                await stream.WriteAsync(
                    protectedBytes,
                    cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            RestrictDescriptor(temporary);
            File.Move(temporary, fullPath, overwrite: true);
            RestrictDescriptor(fullPath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearBytes);
            if (protectedBytes is not null)
                CryptographicOperations.ZeroMemory(protectedBytes);
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static void EnsurePrivateDescriptor(FileStream stream)
    {
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var trusted = new HashSet<SecurityIdentifier>
        {
            current,
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null)
        };
        var security = stream.GetAccessControl();
        if (!security.AreAccessRulesProtected ||
            !current.Equals(
                security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException(
                "The ConnectionHost auto-connect descriptor is not private.");
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType == AccessControlType.Allow &&
                !trusted.Contains(
                    (SecurityIdentifier)rule.IdentityReference))
                throw new UnauthorizedAccessException(
                    "The ConnectionHost auto-connect descriptor grants unintended access.");
    }

    private static void RestrictDescriptor(string path)
    {
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new FileSecurity();
        security.SetOwner(current);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static void RestrictDirectory(string path)
    {
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new DirectorySecurity();
        security.SetOwner(current);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            current,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static void EnsurePrivateDirectory(string path)
    {
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new DirectoryInfo(path).GetAccessControl();
        if (!security.AreAccessRulesProtected ||
            !current.Equals(
                security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException(
                "The ConnectionHost auto-connect directory is not private.");
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType == AccessControlType.Allow &&
                !current.Equals(rule.IdentityReference))
                throw new UnauthorizedAccessException(
                    "The ConnectionHost auto-connect directory grants unintended access.");
    }

    private static void EnsureNoReparseSegments(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath) ??
            throw new InvalidDataException(
                "The ConnectionHost auto-connect descriptor has no path root.");
        var current = root;
        foreach (var segment in fullPath[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                File.GetAttributes(current).HasFlag(
                    FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "The ConnectionHost auto-connect descriptor path cannot traverse reparse points.");
        }
    }

    public ConnectionHostAutoConnectOptions Validate()
    {
        if (Version != 2)
            throw new InvalidDataException(
                "The ConnectionHost auto-connect version is unsupported.");
        Steward.DevBox.Windows.DevBoxDiscoveryService
            .ValidateProjectEndpoint(DevBoxEndpoint);
        ValidateIdentifier(Project, nameof(Project));
        if (!string.Equals(User, "me", StringComparison.Ordinal) &&
            !Guid.TryParse(User, out _))
            throw new InvalidDataException(
                "The auto-connect Dev Box user is invalid.");
        ValidateIdentifier(DevBox, nameof(DevBox));
        ValidateBounded(ConnectionId, 128, nameof(ConnectionId));
        if (SessionId == Guid.Empty ||
            HostId == Guid.Empty ||
            NodeIncarnationId == Guid.Empty)
            throw new InvalidDataException(
                "The auto-connect transport identity is invalid.");
        return this;
    }

    private static void ValidateIdentifier(
        string value,
        string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length is < 3 or > 63 ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.'))
            throw new InvalidDataException(
                $"The auto-connect identifier '{name}' is invalid.");
    }

    private static void ValidateBounded(
        string value,
        int maximum,
        string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximum ||
            value.Any(char.IsControl))
            throw new InvalidDataException(
                $"The auto-connect value '{name}' is invalid.");
    }
}
