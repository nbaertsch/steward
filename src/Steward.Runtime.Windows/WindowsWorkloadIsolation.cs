using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Steward.Domain;
using Steward.Tasks.Abstractions;

namespace Steward.Runtime.Windows;

#pragma warning disable CA1416

public enum WorkloadOsBoundary
{
    AppContainer
}

public sealed record WorkloadIsolationAuthority(
    string RestrictedSid,
    ProcessIsolationCapability Capability,
    WorkloadOsBoundary Boundary,
    string Workspace);

public sealed record WorkloadEnvironmentVariable(
    string Name,
    string Value);

public sealed record WorkloadProcessEnvironment(
    IReadOnlyList<WorkloadEnvironmentVariable> Variables);

public sealed class WorkloadIsolationException(
    string code,
    string message) : UnauthorizedAccessException(message)
{
    public string Code { get; } = code;
}

public static class WindowsWorkloadIsolation
{
    public static class DockerTransportCapability
    {
        public const string Sid =
            "S-1-15-3-1024-2998326250-2988858485-1442624992-3960250298-" +
            "982467102-3587974224-2518029134-186276071";
    }

    private static readonly SecurityIdentifier SystemSid = new(
        WellKnownSidType.LocalSystemSid,
        null);
    private static readonly SecurityIdentifier AdministratorsSid = new(
        WellKnownSidType.BuiltinAdministratorsSid,
        null);
    public static WorkloadIsolationAuthority Describe(
        ProcessIsolationProfile profile)
    {
        ValidateProfile(profile);
        return new WorkloadIsolationAuthority(
            DeriveRestrictedSid(profile).Value,
            profile.Capability,
            Boundary(profile.Capability),
            Path.GetFullPath(profile.Workspace));
    }

    private static WorkloadOsBoundary Boundary(
        ProcessIsolationCapability capability) => capability switch
        {
            ProcessIsolationCapability.Process or
            ProcessIsolationCapability.Compose or
            ProcessIsolationCapability.Evaluation or
            ProcessIsolationCapability.Agent or
            ProcessIsolationCapability.Terminal => WorkloadOsBoundary.AppContainer,
            _ => throw new ArgumentOutOfRangeException(nameof(capability))
        };
    public static WorkloadProcessEnvironment BuildEnvironment(
        ProcessIsolationProfile profile,
        string applicationPath)
    {
        ValidateProfile(profile);
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationPath);
        var application = Path.GetFullPath(applicationPath);
        var workspace = Path.GetFullPath(profile.Workspace);
        var system = Environment.SystemDirectory;
        var windows = Environment.GetFolderPath(
            Environment.SpecialFolder.Windows);
        var temporary = Path.Combine(workspace, ".steward", "temp");
        var applicationDirectory = Path.GetDirectoryName(application) ??
            throw new WorkloadIsolationException(
                "isolation.application-path",
                "Workload application has no parent directory.");
        var path = string.Join(
            Path.PathSeparator,
            new[] { applicationDirectory, system, windows }
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase));
        var values = new List<WorkloadEnvironmentVariable>
        {
            new("APPDATA", Path.Combine(workspace, ".steward", "appdata", "roaming")),
            new("COMSPEC", Path.Combine(system, "cmd.exe")),
            new("HOMEDRIVE", Path.GetPathRoot(workspace) ?? string.Empty),
            new("HOMEPATH", workspace),
            new("LOCALAPPDATA", Path.Combine(workspace, ".steward", "appdata", "local")),
            new("PATH", path),
            new("PATHEXT", ".COM;.EXE"),
            new("TEMP", temporary),
            new("TMP", temporary),
            new("USERPROFILE", workspace),
            new("WINDIR", windows),
            new("SYSTEMROOT", windows),
            new("STEWARD_WORKLOAD_CAPABILITY", profile.Capability.ToString()),
            new("STEWARD_WORKLOAD_ID", profile.AttemptId.ToString()),
            new("STEWARD_WORKLOAD_GENERATION", profile.Generation.ToString(
                System.Globalization.CultureInfo.InvariantCulture))
        };
        if (profile.Capability == ProcessIsolationCapability.Terminal)
        {
            var programFiles = Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);
            values.Add(new WorkloadEnvironmentVariable(
                "PSModulePath",
                string.Join(
                    Path.PathSeparator,
                    new[]
                    {
                        Path.Combine(system, "WindowsPowerShell", "v1.0", "Modules"),
                        Path.Combine(programFiles, "WindowsPowerShell", "Modules"),
                        Path.Combine(programFiles, "PowerShell", "7", "Modules")
                    }.Distinct(StringComparer.OrdinalIgnoreCase))));
        }
        if (values.Any(value =>
                value.Value.IndexOf('\0', StringComparison.Ordinal) >= 0))
            throw new WorkloadIsolationException(
                "isolation.environment-invalid",
                "Workload environment contains invalid data.");
        return new WorkloadProcessEnvironment(
            values.OrderBy(value => value.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray());
    }

    public static void Prepare(ProcessIsolationProfile profile)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Windows workload isolation requires Windows.");
        ValidateProfile(profile);
        var root = Path.GetFullPath(profile.WorkspaceRoot);
        var workspace = Path.GetFullPath(profile.Workspace);
        if (!Directory.Exists(root))
            throw new WorkloadIsolationException(
                "isolation.root-missing",
                "Workload workspace root is unavailable.");
        ValidatePath(profile, root, allowRoot: true);
        Directory.CreateDirectory(workspace);
        ValidatePath(profile, workspace);

        var authority = DeriveRestrictedSid(profile);
        ProtectWorkspace(workspace, authority);
        GrantTraverseOnParents(root, workspace, authority);
        foreach (var directory in new[]
                 {
                     Path.Combine(workspace, ".steward"),
                     Path.Combine(workspace, ".steward", "spool"),
                     Path.Combine(workspace, ".steward", "temp"),
                     Path.Combine(workspace, ".steward", "appdata", "local"),
                     Path.Combine(workspace, ".steward", "appdata", "roaming")
                 })
            Directory.CreateDirectory(directory);
        GrantAuthorityToTree(workspace, authority);
        ValidateTree(workspace);
    }

    public static string ValidatePath(
        ProcessIsolationProfile profile,
        string candidate) => ValidatePath(profile, candidate, allowRoot: false);

    internal static EnvironmentBlock AllocateEnvironment(
        ProcessIsolationProfile profile,
        string applicationPath)
    {
        Prepare(profile);
        return new EnvironmentBlock(BuildEnvironment(profile, applicationPath));
    }

    private static string ValidatePath(
        ProcessIsolationProfile profile,
        string candidate,
        bool allowRoot)
    {
        ValidateProfile(profile);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidate);
        if (!Path.IsPathFullyQualified(candidate))
            throw new WorkloadIsolationException(
                "isolation.path-relative",
                "Workload paths must be fully qualified.");
        var root = Path.GetFullPath(profile.WorkspaceRoot).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        var workspace = Path.GetFullPath(profile.Workspace).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        var full = Path.GetFullPath(candidate).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        if (allowRoot && string.Equals(
                full,
                root,
                StringComparison.OrdinalIgnoreCase))
        {
            RejectReparseComponents(full);
            return full;
        }
        if (!string.Equals(full, workspace, StringComparison.OrdinalIgnoreCase) &&
            !full.StartsWith(
                workspace + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
            throw new WorkloadIsolationException(
                "isolation.cross-workspace",
                "Workload path is outside its dedicated workspace.");
        RejectReparseComponents(full);
        return full;
    }

    private static void ValidateProfile(ProcessIsolationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.Version != 1 ||
            !Enum.IsDefined(profile.Capability) ||
            profile.AttemptId.Value == Guid.Empty ||
            profile.Generation <= 0 ||
            !Path.IsPathFullyQualified(profile.WorkspaceRoot) ||
            !Path.IsPathFullyQualified(profile.Workspace))
            throw new WorkloadIsolationException(
                "isolation.profile-invalid",
                "Workload isolation profile is invalid.");
        var root = Path.GetFullPath(profile.WorkspaceRoot).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        var workspace = Path.GetFullPath(profile.Workspace).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        if (!workspace.StartsWith(
                root + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
            throw new WorkloadIsolationException(
                "isolation.cross-workspace",
                "Workload workspace is outside its configured root.");
    }

    private static SecurityIdentifier DeriveRestrictedSid(
        ProcessIsolationProfile profile) => DeriveAppContainerSid(profile);

    private static SecurityIdentifier DeriveAppContainerSid(
        ProcessIsolationProfile profile)
    {
        var result = NativeMethods.DeriveAppContainerSidFromAppContainerName(
            AppContainerName(profile),
            out var sid);
        if (result != 0 || sid == IntPtr.Zero)
            throw new Win32Exception(
                result,
                $"AppContainer SID derivation failed with HRESULT 0x{result:X8}.");
        try
        {
            return new SecurityIdentifier(sid);
        }
        finally
        {
            _ = NativeMethods.FreeSid(sid);
        }
    }


    internal static SecurityCapabilitiesLease CreateSecurityCapabilities(
        ProcessIsolationProfile profile)
    {
        ValidateProfile(profile);
        var name = AppContainerName(profile);
        IntPtr capabilitySid = IntPtr.Zero;
        IntPtr capabilityArray = IntPtr.Zero;
        int result;
        IntPtr sid;
        try
        {
            if (profile.Capability == ProcessIsolationCapability.Compose)
            {
                var dockerSid = new SecurityIdentifier(
                    DockerTransportCapability.Sid);
                var bytes = new byte[dockerSid.BinaryLength];
                dockerSid.GetBinaryForm(bytes, 0);
                capabilitySid = Marshal.AllocHGlobal(bytes.Length);
                Marshal.Copy(bytes, 0, capabilitySid, bytes.Length);
                capabilityArray = Marshal.AllocHGlobal(
                    Marshal.SizeOf<NativeMethods.SidAndAttributes>());
                Marshal.StructureToPtr(
                    new NativeMethods.SidAndAttributes
                    {
                        Sid = capabilitySid,
                        Attributes = NativeMethods.SecurityGroupEnabled
                    },
                    capabilityArray,
                    fDeleteOld: false);
                CryptographicOperations.ZeroMemory(bytes);
            }
            result = NativeMethods.CreateAppContainerProfile(
                name,
                name,
                "Isolated Steward task authority",
                capabilityArray,
                capabilityArray == IntPtr.Zero ? 0u : 1u,
                out sid);
        }
        finally
        {
            if (capabilityArray != IntPtr.Zero)
                Marshal.FreeHGlobal(capabilityArray);
            if (capabilitySid != IntPtr.Zero)
                Marshal.FreeHGlobal(capabilitySid);
        }
        if (result == NativeMethods.HResultAlreadyExists)
        {
            result = NativeMethods.DeriveAppContainerSidFromAppContainerName(
                name,
                out sid);
        }
        if (result != 0 || sid == IntPtr.Zero)
            throw new Win32Exception(
                result,
                $"AppContainer authority creation failed with HRESULT 0x{result:X8}.");
        return new SecurityCapabilitiesLease(sid, profile.Capability);
    }

    private static string AppContainerName(ProcessIsolationProfile profile) =>
        $"Steward.Workload.{profile.AttemptId.Value:N}.{profile.Generation}";
    internal static void Release(
        TaskAttemptId attemptId,
        int generation)
    {
        if (attemptId.Value == Guid.Empty || generation <= 0)
            throw new ArgumentException(
                "Workload isolation identity is invalid.");
        var name = $"Steward.Workload.{attemptId.Value:N}.{generation}";
        var result = NativeMethods.DeleteAppContainerProfile(name);
        if (result != 0 && result != NativeMethods.HResultNotFound)
            System.Diagnostics.Trace.TraceWarning(
                "AppContainer profile cleanup failed: HRESULT 0x{0:X8}.",
                result);
    }
    internal static WorkloadDesktopLease CreateDesktop(
        ProcessIsolationProfile profile)
    {
        ValidateProfile(profile);
        var authority = DeriveRestrictedSid(profile);
        var windowStation = NativeMethods.GetProcessWindowStation();
        if (windowStation == IntPtr.Zero)
            NativeMethods.ThrowLastError(nameof(
                NativeMethods.GetProcessWindowStation));
        GrantUserObjectAccess(
            windowStation,
            authority,
            NativeMethods.WindowStationReadAttributes |
            NativeMethods.WindowStationAccessGlobalAtoms |
            NativeMethods.WindowStationEnumerate |
            NativeMethods.ReadControl);
        var name = $"Steward-{profile.AttemptId.Value:N}-{profile.Generation}";
        var desktop = NativeMethods.CreateDesktop(
            name,
            null,
            IntPtr.Zero,
            0,
            NativeMethods.DesktopAllAccess,
            IntPtr.Zero);
        if (desktop.IsInvalid)
            NativeMethods.ThrowLastError(nameof(NativeMethods.CreateDesktop));
        try
        {
            GrantUserObjectAccess(
                desktop.DangerousGetHandle(),
                authority,
                NativeMethods.DesktopAllAccess);
            return new WorkloadDesktopLease(
                $@"WinSta0\{name}",
                desktop);
        }
        catch
        {
            desktop.Dispose();
            throw;
        }
    }
    private static void GrantUserObjectAccess(
        IntPtr handle,
        SecurityIdentifier authority,
        int accessMask)
    {
        var securityInformation = NativeMethods.DaclSecurityInformation;
        _ = NativeMethods.GetUserObjectSecurity(
            handle,
            ref securityInformation,
            null,
            0,
            out var required);
        if (required is 0 or > 64 * 1024)
            NativeMethods.ThrowLastError(nameof(
                NativeMethods.GetUserObjectSecurity));
        var binary = new byte[required];
        if (!NativeMethods.GetUserObjectSecurity(
                handle,
                ref securityInformation,
                binary,
                checked((uint)binary.Length),
                out _))
            NativeMethods.ThrowLastError(nameof(
                NativeMethods.GetUserObjectSecurity));
        var descriptor = new RawSecurityDescriptor(binary, 0);
        var dacl = descriptor.DiscretionaryAcl ?? new RawAcl(
            GenericAcl.AclRevision,
            1);
        var exists = dacl.Cast<GenericAce>()
            .OfType<CommonAce>()
            .Any(ace =>
                ace.AceQualifier == AceQualifier.AccessAllowed &&
                ace.SecurityIdentifier == authority &&
                (ace.AccessMask & accessMask) == accessMask);
        if (!exists)
        {
            dacl.InsertAce(
                dacl.Count,
                new CommonAce(
                    AceFlags.None,
                    AceQualifier.AccessAllowed,
                    accessMask,
                    authority,
                    isCallback: false,
                    opaque: null));
            descriptor.DiscretionaryAcl = dacl;
            var updated = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(updated, 0);
            if (!NativeMethods.SetUserObjectSecurity(
                    handle,
                    ref securityInformation,
                    updated))
                NativeMethods.ThrowLastError(nameof(
                    NativeMethods.SetUserObjectSecurity));
        }
        CryptographicOperations.ZeroMemory(binary);
    }
    private static void ProtectWorkspace(
        string workspace,
        SecurityIdentifier authority)
    {
        var current = WindowsIdentity.GetCurrent().User ??
            throw new WorkloadIsolationException(
                "isolation.identity-missing",
                "Node process identity is unavailable.");
        var owner = new DirectoryInfo(workspace)
            .GetAccessControl(AccessControlSections.Owner)
            .GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner != current)
            throw new WorkloadIsolationException(
                "isolation.owner-mismatch",
                "Workload workspace is not owned by the Node process identity.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        AddFullControl(security, current);
        AddFullControl(security, SystemSid);
        AddFullControl(security, AdministratorsSid);
        AddFullControl(security, authority);
        new DirectoryInfo(workspace).SetAccessControl(security);
    }

    private static void GrantTraverseOnParents(
        string root,
        string workspace,
        SecurityIdentifier authority)
    {
        var parent = Path.GetDirectoryName(workspace);
        while (parent is not null &&
               parent.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            var security = new DirectoryInfo(parent).GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                authority,
                FileSystemRights.Traverse |
                FileSystemRights.ListDirectory |
                FileSystemRights.ReadAttributes |
                FileSystemRights.ReadPermissions,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
            new DirectoryInfo(parent).SetAccessControl(security);
            if (string.Equals(parent, root, StringComparison.OrdinalIgnoreCase))
                break;
            parent = Path.GetDirectoryName(parent);
        }
    }

    private static void GrantAuthorityToTree(
        string workspace,
        SecurityIdentifier authority)
    {
        var pending = new Stack<string>();
        pending.Push(workspace);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new WorkloadIsolationException(
                        "isolation.reparse",
                        "Workload workspace cannot contain reparse points.");
                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    var security = new DirectoryInfo(entry).GetAccessControl();
                    security.AddAccessRule(new FileSystemAccessRule(
                        authority,
                        FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit |
                        InheritanceFlags.ObjectInherit,
                        PropagationFlags.None,
                        AccessControlType.Allow));
                    new DirectoryInfo(entry).SetAccessControl(security);
                    pending.Push(entry);
                }
                else
                {
                    RejectMultipleLinks(entry);
                    var security = new FileInfo(entry).GetAccessControl();
                    security.AddAccessRule(new FileSystemAccessRule(
                        authority,
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));
                    new FileInfo(entry).SetAccessControl(security);
                }
            }
        }
    }
    private static void ValidateTree(string workspace)
    {
        var pending = new Stack<string>();
        pending.Push(workspace);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new WorkloadIsolationException(
                        "isolation.reparse",
                        "Workload workspace cannot contain reparse points.");
                if (attributes.HasFlag(FileAttributes.Directory))
                    pending.Push(entry);
                else
                    RejectMultipleLinks(entry);
            }
        }
    }

    private static void RejectReparseComponents(string path)
    {
        var root = Path.GetPathRoot(path) ??
            throw new WorkloadIsolationException(
                "isolation.path-root",
                "Workload path has no volume root.");
        var current = root;
        foreach (var component in Path.GetRelativePath(root, path).Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            if ((Directory.Exists(current) || File.Exists(current)) &&
                File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint))
                throw new WorkloadIsolationException(
                    "isolation.reparse",
                    "Workload path cannot traverse reparse points.");
        }
    }

    private static void RejectMultipleLinks(string file)
    {
        using var handle = File.OpenHandle(
            file,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        if (!NativeMethods.GetFileInformationByHandle(handle, out var information))
            NativeMethods.ThrowLastError(nameof(
                NativeMethods.GetFileInformationByHandle));
        if (information.NumberOfLinks != 1)
            throw new WorkloadIsolationException(
                "isolation.hardlink",
                "Workload workspace cannot contain hard-linked files.");
    }

    private static void AddFullControl(
        DirectorySecurity security,
        SecurityIdentifier sid) => security.AddAccessRule(
        new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

    internal sealed class SecurityCapabilitiesLease : IDisposable
    {
        private IntPtr structure;
        private IntPtr capabilitySid;
        private IntPtr capabilityArray;

        internal SecurityCapabilitiesLease(
            IntPtr appContainerSid,
            ProcessIsolationCapability capability)
        {
            AppContainerSid = appContainerSid;
            if (capability == ProcessIsolationCapability.Compose)
            {
                var sid = new SecurityIdentifier(
                    DockerTransportCapability.Sid);
                var bytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(bytes, 0);
                capabilitySid = Marshal.AllocHGlobal(bytes.Length);
                Marshal.Copy(bytes, 0, capabilitySid, bytes.Length);
                capabilityArray = Marshal.AllocHGlobal(
                    Marshal.SizeOf<NativeMethods.SidAndAttributes>());
                Marshal.StructureToPtr(
                    new NativeMethods.SidAndAttributes
                    {
                        Sid = capabilitySid,
                        Attributes = NativeMethods.SecurityGroupEnabled
                    },
                    capabilityArray,
                    fDeleteOld: false);
                CryptographicOperations.ZeroMemory(bytes);
            }
            var value = new NativeMethods.SecurityCapabilities
            {
                AppContainerSid = appContainerSid,
                Capabilities = capabilityArray,
                CapabilityCount = capabilityArray == IntPtr.Zero ? 0u : 1u,
                Reserved = 0
            };
            structure = Marshal.AllocHGlobal(
                Marshal.SizeOf<NativeMethods.SecurityCapabilities>());
            Marshal.StructureToPtr(value, structure, fDeleteOld: false);
        }

        internal IntPtr AppContainerSid { get; private set; }
        internal IntPtr Pointer => structure;
        internal nuint Size => checked((nuint)Marshal.SizeOf<
            NativeMethods.SecurityCapabilities>());

        public void Dispose()
        {
            if (structure != IntPtr.Zero)
                Marshal.FreeHGlobal(structure);
            if (capabilityArray != IntPtr.Zero)
                Marshal.FreeHGlobal(capabilityArray);
            if (capabilitySid != IntPtr.Zero)
                Marshal.FreeHGlobal(capabilitySid);
            if (AppContainerSid != IntPtr.Zero)
                _ = NativeMethods.FreeSid(AppContainerSid);
            structure = IntPtr.Zero;
            capabilityArray = IntPtr.Zero;
            capabilitySid = IntPtr.Zero;
            AppContainerSid = IntPtr.Zero;
        }
    }
    internal sealed class WorkloadDesktopLease(
        string name,
        SafeDesktopHandle handle) : IDisposable
    {
        internal string Name { get; } = name;

        public void Dispose() => handle.Dispose();
    }

    internal sealed class SafeDesktopHandle : SafeHandle
    {
        internal SafeDesktopHandle() : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        public override bool IsInvalid =>
            handle == IntPtr.Zero || handle == new IntPtr(-1);

        protected override bool ReleaseHandle() =>
            NativeMethods.CloseDesktop(handle);
    }
    internal sealed class EnvironmentBlock : IDisposable
    {
        internal EnvironmentBlock(WorkloadProcessEnvironment environment)
        {
            var builder = new StringBuilder();
            foreach (var variable in environment.Variables)
                builder.Append(variable.Name)
                    .Append('=')
                    .Append(variable.Value)
                    .Append('\0');
            builder.Append('\0');
            Pointer = Marshal.StringToHGlobalUni(builder.ToString());
        }

        internal IntPtr Pointer { get; private set; }

        public void Dispose()
        {
            if (Pointer != IntPtr.Zero)
                Marshal.FreeHGlobal(Pointer);
            Pointer = IntPtr.Zero;
        }
    }

#pragma warning disable SYSLIB1054
    private static class NativeMethods
    {
        internal const uint SecurityGroupEnabled = 0x00000004;
        internal const uint DaclSecurityInformation = 0x00000004;
        internal const int ReadControl = 0x00020000;
        internal const int WindowStationReadAttributes = 0x00000002;
        internal const int WindowStationAccessGlobalAtoms = 0x00000020;
        internal const int WindowStationEnumerate = 0x00000100;
        internal const int DesktopAllAccess = 0x000F01FF;
        internal const int HResultAlreadyExists = unchecked((int)0x800700B7);
        internal const int HResultNotFound = unchecked((int)0x80070490);

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityCapabilities
        {
            internal IntPtr AppContainerSid;
            internal IntPtr Capabilities;
            internal uint CapabilityCount;
            internal uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SidAndAttributes
        {
            internal IntPtr Sid;
            internal uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ByHandleFileInformation
        {
            internal uint FileAttributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            internal uint VolumeSerialNumber;
            internal uint FileSizeHigh;
            internal uint FileSizeLow;
            internal uint NumberOfLinks;
            internal uint FileIndexHigh;
            internal uint FileIndexLow;
        }
        [DllImport("userenv.dll", EntryPoint = "CreateAppContainerProfile", CharSet = CharSet.Unicode)]
        internal static extern int CreateAppContainerProfile(
            string appContainerName,
            string displayName,
            string description,
            IntPtr capabilities,
            uint capabilityCount,
            out IntPtr appContainerSid);

        [DllImport("userenv.dll", EntryPoint = "DeleteAppContainerProfile", CharSet = CharSet.Unicode)]
        internal static extern int DeleteAppContainerProfile(
            string appContainerName);
        [DllImport("userenv.dll", EntryPoint = "DeriveAppContainerSidFromAppContainerName", CharSet = CharSet.Unicode)]
        internal static extern int DeriveAppContainerSidFromAppContainerName(
            string appContainerName,
            out IntPtr appContainerSid);

        [DllImport("advapi32.dll")]
        internal static extern IntPtr FreeSid(IntPtr sid);
        [DllImport("user32.dll", SetLastError = true)]
        internal static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", EntryPoint = "CreateDesktopW", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeDesktopHandle CreateDesktop(
            string desktop,
            string? device,
            IntPtr deviceMode,
            uint flags,
            int desiredAccess,
            IntPtr securityAttributes);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseDesktop(IntPtr desktop);


        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetUserObjectSecurity(
            IntPtr handle,
            ref uint securityInformation,
            byte[]? securityDescriptor,
            uint length,
            out uint needed);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetUserObjectSecurity(
            IntPtr handle,
            ref uint securityInformation,
            byte[] securityDescriptor);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        internal static void ThrowLastError(string operation)
        {
            var code = Marshal.GetLastWin32Error();
            throw new Win32Exception(
                code,
                $"{operation} failed with Win32 error {code}.");
        }
    }
#pragma warning restore SYSLIB1054
}
#pragma warning restore CA1416
