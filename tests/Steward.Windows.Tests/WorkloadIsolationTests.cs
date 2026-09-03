using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Steward.Domain;
using Steward.Runtime.Windows;
using Steward.Tasks.Abstractions;

namespace Steward.Windows.Tests;

public sealed class WorkloadIsolationTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "steward-workload-isolation",
        Guid.NewGuid().ToString("N"));
    private readonly InProcessJobHandleKeeper keeper = new();
    private readonly NodeIncarnationId incarnation = NodeIncarnationId.New();

    public WorkloadIsolationTests() => Directory.CreateDirectory(root);

    [Fact]
    public void Task_authorities_are_stable_unique_and_environment_is_closed()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var first = Profile("first", ProcessIsolationCapability.Process);
        var second = Profile("second", ProcessIsolationCapability.Compose);
        Directory.CreateDirectory(first.Workspace);
        Directory.CreateDirectory(second.Workspace);

        var firstAuthority = WindowsWorkloadIsolation.Describe(first);
        var repeated = WindowsWorkloadIsolation.Describe(first);
        var secondAuthority = WindowsWorkloadIsolation.Describe(second);
        var environment = WindowsWorkloadIsolation.BuildEnvironment(
            first,
            Path.Combine(Environment.SystemDirectory, "where.exe"));

        Assert.Equal(firstAuthority, repeated);
        Assert.Equal(WorkloadOsBoundary.AppContainer, firstAuthority.Boundary);
        Assert.Equal(WorkloadOsBoundary.AppContainer, secondAuthority.Boundary);
        Assert.NotEqual(firstAuthority.RestrictedSid, secondAuthority.RestrictedSid);
        _ = new SecurityIdentifier(firstAuthority.RestrictedSid);
        Assert.DoesNotContain(
            environment.Variables,
            variable => variable.Name.Equals(
                "STEWARD_PARENT_SECRET",
                StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            environment.Variables,
            variable => variable.Name.Equals(
                "DOTNET_STARTUP_HOOKS",
                StringComparison.OrdinalIgnoreCase));
        Assert.Equal(
            first.Workspace,
            environment.Variables.Single(variable =>
                variable.Name == "USERPROFILE").Value);
    }

    [Fact]
    public void Docker_transport_capability_is_a_narrow_capability_sid()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var sid = new SecurityIdentifier(
            WindowsWorkloadIsolation.DockerTransportCapability.Sid);

        Assert.StartsWith("S-1-15-3-1024-", sid.Value);
        Assert.NotEqual("S-1-15-2-1", sid.Value);
    }

    [Fact]
    public void Compose_authority_receives_only_the_Docker_transport_capability()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var profile = Profile("compose-capability", ProcessIsolationCapability.Compose);
        Directory.CreateDirectory(profile.Workspace);
        try
        {
            using var lease =
                WindowsWorkloadIsolation.CreateSecurityCapabilities(profile);
            var capabilities = Marshal.PtrToStructure<TestSecurityCapabilities>(
                lease.Pointer);
            var capability = Marshal.PtrToStructure<TestSidAndAttributes>(
                capabilities.Capabilities);

            Assert.Equal(1u, capabilities.CapabilityCount);
            Assert.Equal(
                WindowsWorkloadIsolation.DockerTransportCapability.Sid,
                new SecurityIdentifier(capability.Sid).Value);
            Assert.Equal(0x00000004u, capability.Attributes);
        }
        finally
        {
            WindowsWorkloadIsolation.Release(
                profile.AttemptId,
                profile.Generation);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TestSecurityCapabilities
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TestSidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [Fact]
    public void Prepare_does_not_require_workspace_owner_reassignment()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException();
        var profile = Profile("owner", ProcessIsolationCapability.Process);
        var rootSecurity = new DirectorySecurity();
        rootSecurity.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        rootSecurity.AddAccessRule(new FileSystemAccessRule(
            current,
            FileSystemRights.Modify | FileSystemRights.Synchronize,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(root).SetAccessControl(rootSecurity);
        Directory.CreateDirectory(profile.Workspace);

        WindowsWorkloadIsolation.Prepare(profile);

        var workspaceSecurity = new DirectoryInfo(profile.Workspace)
            .GetAccessControl();
        Assert.True(workspaceSecurity.AreAccessRulesProtected);
        Assert.Equal(
            current,
            workspaceSecurity.GetOwner(typeof(SecurityIdentifier)));
    }

    [Fact]
    public async Task Restricted_task_cannot_cross_workspace_or_inherit_parent_environment()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var first = Profile("first", ProcessIsolationCapability.Process);
        var second = Profile("second", ProcessIsolationCapability.Process);
        Directory.CreateDirectory(first.Workspace);
        Directory.CreateDirectory(second.Workspace);
        WindowsWorkloadIsolation.Prepare(first);
        WindowsWorkloadIsolation.Prepare(second);
        var siblingSecret = Path.Combine(second.Workspace, "secret.txt");
        await File.WriteAllTextAsync(siblingSecret, "node-secret");
        var prior = Environment.GetEnvironmentVariable("STEWARD_PARENT_SECRET");
        Environment.SetEnvironmentVariable("STEWARD_PARENT_SECRET", "must-not-inherit");
        try
        {
            using var executor = Executor();
            var command =
                $"(type \"{siblingSecret}\" >nul 2>&1 && echo leaked || echo denied) " +
                "& (if defined STEWARD_PARENT_SECRET (echo inherited) else (echo absent))";
            var request = Request(
                first,
                Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                ["/d", "/s", "/c", command]);

            var handle = await executor.StartAsync(request, default);
            var observation = await WaitForExit(executor, handle);
            var output = await executor.ReadOutputAsync(
                handle,
                "stdout",
                0,
                4096,
                default);
            var value = System.Text.Encoding.UTF8.GetString(output.Data.Span);

            var errorOutput = await executor.ReadOutputAsync(
                handle,
                "stderr",
                0,
                4096,
                default);
            var error = System.Text.Encoding.UTF8.GetString(
                errorOutput.Data.Span);
            Assert.True(
                value.Replace("\r", string.Empty, StringComparison.Ordinal).Trim() ==
                    "denied\nabsent",
                $"exit={observation.ExitCode}; stdout={value}; stderr={error}");
        }
        finally
        {
            Environment.SetEnvironmentVariable("STEWARD_PARENT_SECRET", prior);
        }
    }

    [Fact]
    public async Task Retained_workspace_recovers_with_the_same_task_authority()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var profile = Profile("retained", ProcessIsolationCapability.Process);
        Directory.CreateDirectory(profile.Workspace);
        var retained = Path.Combine(profile.Workspace, "retained.txt");
        await File.WriteAllTextAsync(retained, "retained-work");
        WindowsWorkloadIsolation.Prepare(profile);
        WindowsWorkloadIsolation.Prepare(profile);
        using var executor = Executor();
        var command = $"set /p value=<{retained} & echo !value!";

        var handle = await executor.StartAsync(Request(
            profile,
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            ["/d", "/v:on", "/c", command]), default);
        await WaitForExit(executor, handle);
        var output = await executor.ReadOutputAsync(
            handle, "stdout", 0, 4096, default);

        var standardError = await executor.ReadOutputAsync(
            handle, "stderr", 0, 4096, default);
        Assert.True(
            standardError.Data.IsEmpty,
            System.Text.Encoding.UTF8.GetString(standardError.Data.Span));
        Assert.Equal(
            "retained-work",
            System.Text.Encoding.UTF8.GetString(output.Data.Span).Trim());
    }
    [Fact]
    public async Task Restricted_task_cannot_open_node_only_named_pipe()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var profile = Profile("pipe", ProcessIsolationCapability.Process);
        Directory.CreateDirectory(profile.Workspace);
        WindowsWorkloadIsolation.Prepare(profile);
        var pipeName = "Steward.Isolation." + Guid.NewGuid().ToString("N");
        await using var server = new System.IO.Pipes.NamedPipeServerStream(
            pipeName,
            System.IO.Pipes.PipeDirection.InOut,
            1,
            System.IO.Pipes.PipeTransmissionMode.Byte,
            System.IO.Pipes.PipeOptions.Asynchronous |
            System.IO.Pipes.PipeOptions.CurrentUserOnly);
        using var executor = Executor();
        var pipePath = $@"\\.\pipe\{pipeName}";
        var command = $"(echo probe>\"{pipePath}\") 2>nul && echo connected || echo denied";
        var handle = await executor.StartAsync(
            Request(
                profile,
                Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                ["/d", "/s", "/c", command]),
            default);
        await WaitForExit(executor, handle);
        var output = await executor.ReadOutputAsync(
            handle,
            "stdout",
            0,
            4096,
            default);

        Assert.Equal("denied", System.Text.Encoding.UTF8.GetString(output.Data.Span).Trim());
    }

    [Fact]
    public void Boundary_rejects_cross_workspace_reparse_and_hardlinked_input()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var profile = Profile("safe", ProcessIsolationCapability.Evaluation);
        Directory.CreateDirectory(profile.Workspace);
        WindowsWorkloadIsolation.Prepare(profile);
        var sibling = Path.Combine(root, "sibling");
        Directory.CreateDirectory(sibling);
        Assert.Throws<WorkloadIsolationException>(() =>
            WindowsWorkloadIsolation.ValidatePath(profile, sibling));

        var firstLink = Path.Combine(profile.Workspace, "first-link.txt");
        var secondLink = Path.Combine(profile.Workspace, "second-link.txt");
        File.WriteAllText(firstLink, "linked");
        Assert.True(CreateHardLink(secondLink, firstLink, IntPtr.Zero));
        var hardLink = Assert.Throws<WorkloadIsolationException>(() =>
            WindowsWorkloadIsolation.Prepare(profile));
        Assert.Equal("isolation.hardlink", hardLink.Code);
        File.Delete(secondLink);
        File.Delete(firstLink);

        var target = Path.Combine(profile.Workspace, "target");
        Directory.CreateDirectory(target);
        var link = Path.Combine(profile.Workspace, "link");
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (IOException)
        {
            return;
        }
        Assert.Throws<WorkloadIsolationException>(() =>
            WindowsWorkloadIsolation.ValidatePath(profile, link));
    }

#pragma warning disable SYSLIB1054
    [System.Runtime.InteropServices.DllImport(
        "kernel32.dll",
        EntryPoint = "CreateHardLinkW",
        SetLastError = true,
        CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(
        System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);
#pragma warning restore SYSLIB1054
    private WindowsProcessExecutor Executor() => new(
        new ExecutionJournal(Path.Combine(root, Guid.NewGuid() + ".db")),
        keeper,
        incarnation,
        "boot");

    private ProcessIsolationProfile Profile(
        string name,
        ProcessIsolationCapability capability) => new(
            1,
            capability,
            root,
            Path.Combine(root, name),
            TaskAttemptId.New(),
            1);

    private ProcessLaunchRequest Request(
        ProcessIsolationProfile profile,
        string executable,
        IReadOnlyList<string> arguments) => new(
            profile.AttemptId,
            profile.Generation,
            executable,
            arguments,
            profile.Workspace,
            Path.Combine(profile.Workspace, ".steward", "spool"),
            1024 * 1024,
            0,
            Isolation: profile);

    private static string PowerShell() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe");

    private static async Task<ExecutionObservation> WaitForExit(
        IProcessExecutor executor,
        IExecutionHandle handle)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (true)
        {
            var observation = await executor.ObserveAsync(handle, timeout.Token);
            if (observation.State == ExecutionState.Exited)
                return observation;
            await Task.Delay(25, timeout.Token);
        }
    }

    public void Dispose()
    {
        keeper.Dispose();
        try
        {
            Directory.Delete(root, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        GC.SuppressFinalize(this);
    }
}
