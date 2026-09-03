using System.IO.Pipes;
using System.Net;
using System.Net.Http.Headers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class MaintenanceSecurityTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "steward-maintenance-security-tests",
        Guid.NewGuid().ToString("N"));

    [Theory]
    [InlineData(0)]
    [InlineData(1379)]
    [InlineData(2223)]
    public void Existing_local_group_results_are_idempotent_success(uint result)
    {
        Assert.True(
            WindowsMaintenanceOperationExecutor
                .IsLocalGroupCreationSuccess(result));
    }

    [Fact]
    public void Matching_Docker_runtime_binary_is_preserved_for_idempotent_replay()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "dockerd.exe");
        File.WriteAllText(path, "approved-runtime");
        var expected = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                File.ReadAllBytes(path)));

        Assert.True(
            WindowsMaintenanceOperationExecutor.HasSha256(
                path,
                expected));
        Assert.False(
            WindowsMaintenanceOperationExecutor.HasSha256(
                path,
                new string('0', 64)));
    }

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

    [Fact]
    public void Docker_task_capability_rejects_an_invalid_sid_as_a_protocol_failure()
    {
        var exception = Assert.Throws<MaintenanceProtocolException>(() =>
            WindowsMaintenanceOperationExecutor.AddLocalGroupMember(
                "StewardDockerTasks",
                "not-a-sid"));

        Assert.Equal("docker_capability_failed", exception.Code);
        Assert.Equal(
            "A declared Docker task identity SID is invalid.",
            exception.Message);
    }

    [Fact]
    public async Task Approved_artifact_download_resumes_a_verified_partial_file()
    {
        var stateRoot = Path.Combine(root, "resume");
        Directory.CreateDirectory(Path.Combine(stateRoot, "staging"));
        var content = System.Text.Encoding.UTF8.GetBytes(
            "signed-endpoint-release");
        const int partialLength = 7;
        const string name = "endpoint.msi";
        await File.WriteAllBytesAsync(
            Path.Combine(stateRoot, "staging", name + ".partial"),
            content[..partialLength]);
        var handler = new RangeHandler(content, partialLength);
        using var client = new HttpClient(handler);
        var executor = new WindowsMaintenanceOperationExecutor(
            stateRoot,
            new MaintenanceServiceConfiguration(
                1,
                "pipe",
                WindowsIdentity.GetCurrent().User!.Value,
                "account",
                "control",
                "keeper",
                Guid.NewGuid(),
                "1.0.0",
                "owner/repository",
                "owner/repository/.github/workflows/release-endpoint.yml",
                Path.Combine(root, "endpoint"),
                Path.Combine(root, "install"),
                Path.Combine(root, "versions"),
                Guid.NewGuid().ToString("D")),
            client,
            RandomNumberGenerator.GetBytes(32));
        var artifact = new ApprovedArtifact(
            1,
            ApprovedArtifactKind.EndpointMsi,
            new Uri(
                "https://github.com/owner/repository/releases/download/v1/endpoint.msi"),
            Convert.ToHexString(SHA256.HashData(content)),
            content.Length);

        var path = await executor.DownloadAsync(artifact, name, default);

        Assert.Equal(content, await File.ReadAllBytesAsync(path));
        Assert.Equal(partialLength, handler.ObservedOffset);
        Assert.False(File.Exists(path + ".partial"));
    }

    private sealed class RangeHandler(byte[] content, int expectedOffset)
        : HttpMessageHandler
    {
        internal long? ObservedOffset { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObservedOffset = request.Headers.Range?.Ranges.Single().From;
            var responseContent = new ByteArrayContent(
                content[expectedOffset..]);
            responseContent.Headers.ContentRange = new ContentRangeHeaderValue(
                expectedOffset,
                content.Length - 1,
                content.Length);
            return Task.FromResult(new HttpResponseMessage(
                HttpStatusCode.PartialContent)
            {
                RequestMessage = request,
                Content = responseContent
            });
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }
}



