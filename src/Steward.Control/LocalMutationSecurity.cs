using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Steward.Control;

public sealed class LocalMutationSecurity
{
    public const string HeaderName = "X-Steward-Mutation-Token";
    private readonly byte[] tokenBytes;

    public LocalMutationSecurity(string tokenPath)
    {
        if (!Path.IsPathFullyQualified(tokenPath))
            throw new InvalidOperationException("Control local session-token path must be absolute.");
        TokenPath = Path.GetFullPath(tokenPath);
        var directory = Path.GetDirectoryName(TokenPath)!;
        Directory.CreateDirectory(directory);
        ProtectDirectory(directory);
        if (!File.Exists(TokenPath))
        {
            var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            var temporary = $"{TokenPath}.{Guid.NewGuid():N}.new";
            var createOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 4096,
                Options = FileOptions.WriteThrough
            };
            if (!OperatingSystem.IsWindows())
                createOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temporary, createOptions))
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(token);
                writer.Flush();
                stream.Flush(true);
            }
            ProtectFile(temporary);
            File.Move(temporary, TokenPath, false);
            File.SetAttributes(TokenPath, FileAttributes.Hidden);
        }
        ValidateProtection(TokenPath);
        var text = File.ReadAllText(TokenPath).Trim();
        if (text.Length != 64 || !text.All(Uri.IsHexDigit))
            throw new InvalidDataException("Control local session-token file is invalid.");
        tokenBytes = Convert.FromHexString(text);
    }

    public string TokenPath { get; }

    public bool Authorize(HttpRequest request)
    {
        if (request.Headers.Origin.Count > 0)
            return false;
        var supplied = request.Headers[HeaderName].FirstOrDefault();
        if (supplied?.Length != 64) return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                tokenBytes, Convert.FromHexString(supplied));
        }
        catch (FormatException) { return false; }
    }

    private static void ProtectDirectory(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            return;
        }
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Current Windows identity has no SID.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new(
            current, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static void ProtectFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return;
        }
        var current = WindowsIdentity.GetCurrent().User!;
        var security = new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new(current, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static void ValidateProtection(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(path);
            var forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
            if ((mode & forbidden) != 0)
                throw new InvalidDataException("Control mutation-token file is broadly accessible.");
            return;
        }
        var security = new FileInfo(path).GetAccessControl();
        if (!security.AreAccessRulesProtected)
            throw new InvalidDataException("Control mutation-token ACL inheritance must be disabled.");
        var current = WindowsIdentity.GetCurrent().User!;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference is SecurityIdentifier sid &&
                sid != current && sid != system)
                throw new InvalidDataException("Control mutation-token file is broadly accessible.");
    }
}
