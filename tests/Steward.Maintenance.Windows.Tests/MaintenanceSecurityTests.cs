using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class MaintenanceSecurityTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "steward-maintenance-security-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void State_acl_is_protected_and_excludes_assigned_user_and_workloads()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var security = MaintenanceStateSecurity.CreateDescriptor();
        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .ToArray();

        Assert.True(security.AreAccessRulesProtected);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier ??
            throw new InvalidDataException("State root owner SID is missing.");
        Assert.Equal("S-1-5-18", owner.Value);
        Assert.Equal(
            new[] { "S-1-5-18", "S-1-5-32-544" },
            rules.Select(rule => rule.IdentityReference.Value)
                .Order(StringComparer.Ordinal));
        Assert.All(rules, rule => Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights));
    }

    [Fact]
    public void Maintenance_pipe_acl_excludes_AppContainer_and_task_SIDs_without_denies()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var user = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException();
        var security = MaintenancePipeSecurity.CreateDescriptor(user.Value);
        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .ToArray();
        var appContainer = new SecurityIdentifier(
            "S-1-15-2-1-2-3-4-5-6-7-8");
        var taskSid = new SecurityIdentifier(
            "S-1-5-80-111111111-222222222-333333333-444444444-555555555");

        Assert.DoesNotContain(rules, rule =>
            rule.AccessControlType == AccessControlType.Deny);
        Assert.DoesNotContain(rules, rule =>
            rule.IdentityReference == appContainer ||
            rule.IdentityReference == taskSid);
        Assert.Equal(
            new[] { "S-1-5-18", "S-1-5-32-544", user.Value }
                .Order(StringComparer.Ordinal),
            rules.Select(rule => rule.IdentityReference.Value)
                .Order(StringComparer.Ordinal));
    }
    [Fact]
    public void State_validation_rejects_reparse_points()
    {
        if (!OperatingSystem.IsWindows())
            return;
        Directory.CreateDirectory(root);
        var target = Path.Combine(root, "target");
        Directory.CreateDirectory(target);
        var link = Path.Combine(root, "link");
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (IOException)
        {
            return;
        }

        Assert.Throws<InvalidDataException>(() =>
            MaintenanceStateSecurity.ValidateTree(root));
    }

    [Fact]
    public void Docker_client_capability_is_read_only_without_maintenance_authority()
    {
        if (!OperatingSystem.IsWindows()) return;
        Directory.CreateDirectory(root);
        var client = Path.Combine(root, "docker.exe");
        File.WriteAllText(client, "verified-client");
        var sid = WindowsIdentity.GetCurrent().User!.Value;

        WindowsMaintenanceOperationExecutor.ProtectDockerClientCapability(
            root,
            [new DockerTaskIdentity(1, sid)],
            new SecurityIdentifier(sid));

        var file = new FileInfo(client).GetAccessControl();
        var rules = file.GetAccessRules(
                true,
                true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .ToArray();
        var restore = new DirectorySecurity();
        restore.SetAccessRuleProtection(true, false);
        restore.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(sid),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(root).SetAccessControl(restore);

        var task = Assert.Single(rules, rule =>
            rule.IdentityReference.Value == sid);
        Assert.True(task.FileSystemRights.HasFlag(
            FileSystemRights.ReadAndExecute));
        Assert.DoesNotContain(rules, rule =>
            rule.IdentityReference.Value == sid &&
            rule.FileSystemRights.HasFlag(FileSystemRights.Write));

        var maintenance = MaintenanceStateSecurity.CreateDescriptor();
        Assert.DoesNotContain(
            maintenance.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>(),
            rule => rule.IdentityReference.Value == sid);


    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }
}







