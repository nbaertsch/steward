using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace Steward.Transport.Rdp.Windows;

public sealed record RegistryStringValue(string Value, RegistryValueKind Kind);

public interface IUserRegistryStore
{
    void SetString(string keyPath, string? valueName, string value);
    RegistryStringValue? ReadString(string keyPath, string? valueName);
    void DeleteKeyTree(string keyPath);
}

public interface IRdpDvcExecutableValidator
{
    string Validate(string executablePath);
}

public sealed record DvcPluginRegistrationStatus(
    bool Registered,
    bool ConfigurationValid,
    string Code);

public sealed class RdpDvcPluginRegistration(
    IUserRegistryStore registry,
    IRdpDvcExecutableValidator executableValidator)
{
    public const string RegisteredActivationPendingCode =
        "DvcPluginRegisteredActivationPending";

    public static string AddInKeyPath =>
        $@"Software\Microsoft\Terminal Server Client\Default\AddIns\{StewardRdpDvc.AddInName}";

    public static string ClsidKeyPath =>
        $@"Software\Classes\CLSID\{StewardRdpDvc.PluginClsid:B}";

    public static string LocalServerKeyPath =>
        $@"{ClsidKeyPath}\LocalServer32";

    public void Register(string executablePath)
    {
        var validated =
            executableValidator.Validate(executablePath);
        var clsid = StewardRdpDvc.PluginClsid.ToString("B");
        var command = $"\"{validated}\" -Embedding";
        try
        {
            registry.SetString(AddInKeyPath, "Name", clsid);
            registry.SetString(
                ClsidKeyPath,
                null,
                "Steward RDP DVC Transport v1");
            registry.SetString(LocalServerKeyPath, null, command);
            Verify(clsid, command);
        }
        catch
        {
            registry.DeleteKeyTree(AddInKeyPath);
            registry.DeleteKeyTree(ClsidKeyPath);
            throw;
        }
    }

    public void Unregister()
    {
        registry.DeleteKeyTree(AddInKeyPath);
        registry.DeleteKeyTree(ClsidKeyPath);
        if (registry.ReadString(AddInKeyPath, "Name") is not null ||
            registry.ReadString(LocalServerKeyPath, null) is not null)
            throw new InvalidOperationException(
                "Steward DVC per-user registration was not removed.");
    }

    public DvcPluginRegistrationStatus GetStatus()
    {
        RegistryStringValue? addIn;
        RegistryStringValue? description;
        RegistryStringValue? command;
        try
        {
            addIn = registry.ReadString(AddInKeyPath, "Name");
            description = registry.ReadString(ClsidKeyPath, null);
            command = registry.ReadString(LocalServerKeyPath, null);
        }
        catch (Exception exception)
            when (exception is
                UnauthorizedAccessException or
                System.Security.SecurityException or
                IOException)
        {
            return new(false, false, "DvcRegistrationUnreadable");
        }
        if (addIn is null &&
            description is null &&
            command is null)
            return new(false, true, "DvcPluginNotRegistered");
        var clsid = StewardRdpDvc.PluginClsid.ToString("B");
        if (!Exact(addIn, clsid) ||
            !Exact(
                description,
                "Steward RDP DVC Transport v1") ||
            command is null ||
            command.Kind != RegistryValueKind.String ||
            !TryParseLocalServerCommand(
                command.Value,
                out var executable))
            return new(false, false, "DvcRegistrationInvalid");
        try
        {
            _ = executableValidator.Validate(executable);
        }
        catch (Exception exception)
            when (exception is
                ArgumentException or
                FileNotFoundException or
                InvalidDataException or
                InvalidOperationException or
                UnauthorizedAccessException or
                IOException)
        {
            return new(false, false, "DvcPluginExecutableInvalid");
        }
        return new(
            true,
            true,
            RegisteredActivationPendingCode);
    }

    public static bool IsExactStewardRegistration(
        DvcPluginRegistrationStatus? status) =>
        status is
        {
            Registered: true,
            ConfigurationValid: true,
            Code: RegisteredActivationPendingCode
        };

    private void Verify(string clsid, string command)
    {
        RequireExact(
            registry.ReadString(AddInKeyPath, "Name"),
            clsid,
            "DVC AddIns Name");
        RequireExact(
            registry.ReadString(ClsidKeyPath, null),
            "Steward RDP DVC Transport v1",
            "COM class description");
        RequireExact(
            registry.ReadString(LocalServerKeyPath, null),
            command,
            "COM LocalServer32 command");
    }

    private static void RequireExact(
        RegistryStringValue? actual,
        string expected,
        string description)
    {
        if (actual is null ||
            actual.Kind != RegistryValueKind.String ||
            !string.Equals(
                actual.Value,
                expected,
                StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"{description} did not round-trip exactly.");
    }

    private static bool Exact(
        RegistryStringValue? value,
        string expected) =>
        value is
        {
            Kind: RegistryValueKind.String
        } &&
        string.Equals(
            value.Value,
            expected,
            StringComparison.Ordinal);

    private static bool TryParseLocalServerCommand(
        string command,
        out string executable)
    {
        executable = string.Empty;
        if (command.Length < 15 ||
            command[0] != '"')
            return false;
        var closingQuote = command.IndexOf('"', 1);
        if (closingQuote <= 1 ||
            !string.Equals(
                command[(closingQuote + 1)..],
                " -Embedding",
                StringComparison.Ordinal))
            return false;
        executable = command[1..closingQuote];
        return Path.IsPathFullyQualified(executable);
    }
}

public sealed class CurrentUserRegistryStore : IUserRegistryStore
{
    public void SetString(
        string keyPath,
        string? valueName,
        string value)
    {
        using var key = Registry.CurrentUser.CreateSubKey(
            keyPath,
            writable: true) ??
            throw new InvalidOperationException(
                "Unable to create the per-user Steward DVC registry key.");
        key.SetValue(
            valueName ?? string.Empty,
            value,
            RegistryValueKind.String);
        key.Flush();
    }

    public RegistryStringValue? ReadString(
        string keyPath,
        string? valueName)
    {
        using var key = Registry.CurrentUser.OpenSubKey(
            keyPath,
            writable: false);
        if (key is null)
            return null;
        var name = valueName ?? string.Empty;
        var value = key.GetValue(
            name,
            null,
            RegistryValueOptions.DoNotExpandEnvironmentNames);
        return value is string text
            ? new(text, key.GetValueKind(name))
            : null;
    }

    public void DeleteKeyTree(string keyPath)
    {
        Registry.CurrentUser.DeleteSubKeyTree(
            keyPath,
            throwOnMissingSubKey: false);
    }
}

public sealed class WindowsRdpDvcExecutableValidator :
    IRdpDvcExecutableValidator
{
    private const FileSystemRights UnsafeWriteRights =
        FileSystemRights.Write |
        FileSystemRights.Modify |
        FileSystemRights.FullControl |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership |
        FileSystemRights.Delete;

    public string Validate(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath) ||
            !Path.IsPathFullyQualified(executablePath))
            throw new ArgumentException(
                "The DVC LocalServer path must be absolute.",
                nameof(executablePath));
        var fullPath = Path.GetFullPath(executablePath);
        if (!string.Equals(
                Path.GetExtension(fullPath),
                ".exe",
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(fullPath))
            throw new FileNotFoundException(
                "The DVC LocalServer executable does not exist.",
                fullPath);
        ValidateNoReparsePoints(fullPath);
        ValidateAcl(fullPath);
        using var executable = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete);
        if (executable.Length == 0)
            throw new InvalidDataException(
                "The DVC LocalServer executable is empty.");
        return fullPath;
    }

    private static void ValidateNoReparsePoints(string path)
    {
        FileSystemInfo? current = new FileInfo(path);
        while (current is not null)
        {
            current.Refresh();
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0 ||
                current.LinkTarget is not null)
                throw new InvalidOperationException(
                    "The DVC LocalServer path cannot contain a reparse point.");
            current = current switch
            {
                FileInfo file => file.Directory,
                DirectoryInfo directory => directory.Parent,
                _ => null
            };
        }
    }

    private static void ValidateAcl(string path)
    {
        using var identity = WindowsIdentity.GetCurrent(
            TokenAccessLevels.Query);
        var currentSid = identity.User ??
            throw new InvalidOperationException(
                "The current Windows user SID is unavailable.");
        var security = FileSystemAclExtensions.GetAccessControl(
            new FileInfo(path),
            AccessControlSections.Access);
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                (rule.FileSystemRights & UnsafeWriteRights) == 0 ||
                rule.IdentityReference is not SecurityIdentifier sid ||
                IsTrustedWriter(sid, currentSid))
                continue;
            throw new UnauthorizedAccessException(
                "The DVC LocalServer executable is writable by an untrusted principal.");
        }
    }

    private static bool IsTrustedWriter(
        SecurityIdentifier sid,
        SecurityIdentifier currentSid) =>
        sid.Equals(currentSid) ||
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
        sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
}
