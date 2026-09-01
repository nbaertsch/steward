using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

namespace Steward.Maintenance.Windows;

internal static class EndpointPreservationInspector
{
    private static readonly string EmptyHash = new('0', 64);

    internal static string HashTree(string root)
    {
        if (!Directory.Exists(root))
            return EmptyHash;
        MaintenanceStateSecurity.ValidatePath(root);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories)
                 .Order(StringComparer.OrdinalIgnoreCase))
        {
            var attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new EndpointUpdateException(
                    "preservation_reparse",
                    "Preserved endpoint state contains a reparse point.");
            var relative = Path.GetRelativePath(root, path)
                .Replace(Path.DirectorySeparatorChar, '/');
            AppendText(hash, relative);
            AppendText(hash, ((int)attributes).ToString(
                System.Globalization.CultureInfo.InvariantCulture));
            AppendText(hash, File.GetLastWriteTimeUtc(path).Ticks.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
            AppendText(hash, SecurityDescriptor(path));
            if (attributes.HasFlag(FileAttributes.Directory))
            {
                AppendText(hash, "directory");
                continue;
            }
            var information = new FileInfo(path);
            AppendText(hash, information.Length.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.SequentialScan);
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                hash.AppendData(buffer, 0, read);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string SecurityDescriptor(string path)
    {
        if (!OperatingSystem.IsWindows())
            return "acl-unavailable";
        FileSystemSecurity security = Directory.Exists(path)
            ? new DirectoryInfo(path).GetAccessControl()
            : new FileInfo(path).GetAccessControl();
        return security.GetSecurityDescriptorSddlForm(
            AccessControlSections.Access |
            AccessControlSections.Owner |
            AccessControlSections.Group);
    }

    private static void AppendText(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
            length,
            bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}
