using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Steward.DevBox.Windows;

[SupportedOSPlatform("windows")]
internal static class DevBoxIdentityStorageSecurity
{
    internal static void PrepareDirectory(string path)
    {
        EnsureNoReparseSegments(path, requireLeaf: false);
        Directory.CreateDirectory(path);
        EnsureSafeDirectory(path);
        var identity = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new DirectorySecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    internal static void EnsureSafeDirectory(string path)
    {
        if (!Directory.Exists(path))
            throw new IOException(
                "Dev Box identity storage directory is unavailable.");
        EnsureNoReparseSegments(path, requireLeaf: true);
    }

    internal static bool IsSafeRegularFile(string path)
    {
        if (!File.Exists(path))
            return false;
        var attributes = File.GetAttributes(path);
        return !attributes.HasFlag(FileAttributes.Directory) &&
               !attributes.HasFlag(FileAttributes.ReparsePoint);
    }

    internal static void RestrictFile(string path)
    {
        if (!IsSafeRegularFile(path))
            throw new IOException(
                "Dev Box identity storage requires a regular file.");
        var identity = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new FileSecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static void EnsureNoReparseSegments(
        string path,
        bool requireLeaf)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full)
            ?? throw new IOException(
                "Dev Box identity storage path has no root.");
        var current = root;
        foreach (var segment in full[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (Directory.Exists(current) &&
                File.GetAttributes(current)
                    .HasFlag(FileAttributes.ReparsePoint))
                throw new IOException(
                    "Dev Box identity storage cannot traverse " +
                    "reparse points.");
        }
        if (requireLeaf && !Directory.Exists(full))
            throw new IOException(
                "Dev Box identity storage directory is unavailable.");
    }
}
