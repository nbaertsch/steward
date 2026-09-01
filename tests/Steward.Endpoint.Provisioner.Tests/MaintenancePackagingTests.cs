namespace Steward.Endpoint.Provisioner.Tests;

public sealed class MaintenancePackagingTests
{
    private static readonly string Repository = FindRepository();

    [Fact]
    public void Msi_installs_exact_narrow_LocalSystem_service_with_rollback_control()
    {
        var source = Read("packaging", "Steward.Endpoint.Msi", "Package.wxs");

        Assert.Contains("Id=\"StewardMaintenanceService\"", source, StringComparison.Ordinal);
        Assert.Contains("Name=\"StewardMaintenance\"", source, StringComparison.Ordinal);
        Assert.Contains("Account=\"LocalSystem\"", source, StringComparison.Ordinal);
        Assert.Contains("Start=\"auto\"", source, StringComparison.Ordinal);
        Assert.Contains("ErrorControl=\"normal\"", source, StringComparison.Ordinal);
        Assert.Contains("Vital=\"yes\"", source, StringComparison.Ordinal);
        Assert.Contains("Stop=\"both\"", source, StringComparison.Ordinal);
        Assert.Contains("Remove=\"uninstall\"", source, StringComparison.Ordinal);
        Assert.Contains("Wait=\"yes\"", source, StringComparison.Ordinal);
        Assert.Contains("Execute=\"rollback\"", source, StringComparison.Ordinal);
        Assert.Contains("Execute=\"commit\"", source, StringComparison.Ordinal);
        Assert.True(source.IndexOf("Execute=\"commit\"", StringComparison.Ordinal) <
            source.IndexOf("After=\"StartServices\"", StringComparison.Ordinal));
        Assert.Contains("--state-root", source, StringComparison.Ordinal);
        Assert.Contains("Steward\\Maintenance", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ServiceInstall" + Environment.NewLine + "          Name=\"Steward.HandleKeeper", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Self_update_uses_one_fixed_demand_only_Provisioner_task_and_never_direct_msiexec()
    {
        var update = Read(
            "src", "Steward.Maintenance.Windows",
            "WindowsEndpointUpdatePlatform.cs");
        var provisioner = Read(
            "src", "Steward.Endpoint.Provisioner", "Program.cs");

        Assert.Contains("EndpointInstallerHandoff-", update, StringComparison.Ordinal);
        Assert.Contains("PersistInstallerHandoffAsync", update, StringComparison.Ordinal);
        Assert.Contains("ObserveInstallerReceiptAsync", update, StringComparison.Ordinal);
        Assert.DoesNotContain("MaintenanceTool.WindowsInstaller", update, StringComparison.Ordinal);
        Assert.Contains(
            "terminateOnCancellation: tool !=",
            Read("src", "Steward.Maintenance.Windows", "Execution.cs"),
            StringComparison.Ordinal);
        Assert.Contains("$handoffName='EndpointInstallerHandoff-", provisioner,
            StringComparison.Ordinal);
        Assert.Contains("--execute-update-handoff", provisioner,
            StringComparison.Ordinal);
        Assert.Contains("-LogonType ServiceAccount", provisioner,
            StringComparison.Ordinal);
        Assert.Contains("-UserId 'SYSTEM'", provisioner,
            StringComparison.Ordinal);
        Assert.Contains("-MultipleInstances IgnoreNew", provisioner,
            StringComparison.Ordinal);
        Assert.DoesNotContain("--package", provisioner, StringComparison.Ordinal);
        Assert.DoesNotContain("--arguments", provisioner, StringComparison.Ordinal);
    }
    [Fact]
    public void Provisioner_owns_private_maintenance_state_without_user_grant()
    {
        var source = Read("src", "Steward.Endpoint.Provisioner", "Program.cs");

        Assert.Contains("MaintenanceStateRoot", source, StringComparison.Ordinal);
        Assert.Contains("service-config.json", source, StringComparison.Ordinal);
        Assert.Contains("control-signing.spki", source, StringComparison.Ordinal);
        Assert.Contains("bootstrap-envelope.spki", source, StringComparison.Ordinal);
        Assert.Contains("STEWARD_CONFIG", Read("src", "Steward.Maintenance.Windows", "Execution.cs"), StringComparison.Ordinal);
        Assert.Contains("STEWARD_ATTESTATION", Read("src", "Steward.Maintenance.Windows", "Execution.cs"), StringComparison.Ordinal);
        Assert.Contains("repairExistingChildren: true", source, StringComparison.Ordinal);
        Assert.Contains("PrepareMaintenanceState", source, StringComparison.Ordinal);
        Assert.Contains("maintenanceStateRoot, null", source, StringComparison.Ordinal);
        Assert.Contains("StewardMaintenance", source, StringComparison.Ordinal);
        Assert.Contains("NamedPipeEndpointInstallerFenceCompletion", source,
            StringComparison.Ordinal);
        Assert.Contains("LogonType Interactive", source, StringComparison.Ordinal);
        Assert.Contains("RunLevel Limited", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Provisioner_preserves_durable_fence_while_quiescing_and_restores_exact_tasks()
    {
        var source = Read("src", "Steward.Endpoint.Provisioner", "Program.cs");

        Assert.Contains("--fence-state-file", source, StringComparison.Ordinal);
        Assert.Contains("--fence-key-file", source, StringComparison.Ordinal);
        Assert.DoesNotContain("--begin-drain-fence", source, StringComparison.Ordinal);
        Assert.DoesNotContain("--end-drain-fence", source, StringComparison.Ordinal);
        Assert.Contains("tasks.Restore", source, StringComparison.Ordinal);
        Assert.Contains("TaskSnapshot", source, StringComparison.Ordinal);
    }
    [Fact]
    public void Endpoint_payload_and_Msi_smoke_contract_include_service()
    {
        var build = Read("scripts", "Build-StewardEndpointMsi.ps1");
        var test = Read("scripts", "Test-StewardEndpointMsi.ps1");

        Assert.Contains("Steward.Maintenance.Windows.csproj", build, StringComparison.Ordinal);
        Assert.Contains("Steward.Maintenance.Windows.exe", test, StringComparison.Ordinal);
        Assert.Contains("Steward.Maintenance.Windows.dll", test, StringComparison.Ordinal);
        Assert.Contains("StewardMaintenance", test, StringComparison.Ordinal);
        Assert.Contains("LocalSystem", test, StringComparison.Ordinal);
        Assert.Contains("Steward\\Maintenance", test, StringComparison.Ordinal);
        Assert.Contains("rollback", test, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("'/i'", test, StringComparison.Ordinal);
        Assert.DoesNotContain("'/a'", test, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_policy_runs_maintenance_security_tests_before_publish()
    {
        var workflow = Read(".github", "workflows", "release-endpoint.yml");
        var testIndex = workflow.IndexOf(
            "Steward.Maintenance.Windows.Tests",
            StringComparison.Ordinal);
        var buildIndex = workflow.IndexOf(
            "Build-StewardEndpointMsi.ps1",
            StringComparison.Ordinal);
        var publishIndex = workflow.IndexOf(
            "gh release create",
            StringComparison.Ordinal);

        Assert.True(testIndex >= 0);
        Assert.True(testIndex < buildIndex);
        Assert.True(buildIndex < publishIndex);
        Assert.Contains("dotnet format", workflow, StringComparison.Ordinal);
        Assert.Contains("--verify-no-changes", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void HandleKeeper_pipe_allows_only_Node_System_and_service_identity()
    {
        var source = Read("src", "Steward.HandleKeeper", "HandleKeeperServer.cs");

        Assert.Contains("WellKnownSidType.LocalSystemSid", source, StringComparison.Ordinal);
        Assert.Contains("PipeAccessRights.FullControl", source, StringComparison.Ordinal);
        Assert.Contains("expectedNodeSid", source, StringComparison.Ordinal);
        Assert.Contains("PipeRejectRemoteClients", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Sqlite_package_and_native_provider_policy_is_centralized()
    {
        var props = Read("Directory.Build.props");
        var targets = Read("Directory.Build.targets");
        var initializer = Read(
            "build", "StewardSqliteProviderInitializer.cs");
        var provider = Read(
            "src", "Steward.Sqlite", "StewardSqliteProvider.cs");
        Assert.Contains("MicrosoftDataSqlitePackageVersion", props, StringComparison.Ordinal);
        Assert.Contains("SQLitePCLRawPackageVersion", props, StringComparison.Ordinal);
        Assert.Contains("UsesStewardSqlite", targets, StringComparison.Ordinal);
        Assert.Contains("StewardSqliteProvider.Initialize", initializer, StringComparison.Ordinal);
        Assert.Contains("Batteries_V2.Init", provider, StringComparison.Ordinal);

        foreach (var project in Directory.GetFiles(
                     Path.Combine(Repository, "src"),
                     "*.csproj",
                     SearchOption.AllDirectories))
        {
            var source = File.ReadAllText(project);
            if (!source.Contains("Microsoft.Data.Sqlite", StringComparison.Ordinal))
                continue;
            Assert.Contains("<UsesStewardSqlite>true</UsesStewardSqlite>", source, StringComparison.Ordinal);
            Assert.Contains("$(MicrosoftDataSqlitePackageVersion)", source, StringComparison.Ordinal);
            Assert.DoesNotMatch(
                "SQLitePCLRaw[^\r\n]*Version=\"[0-9]",
                source);
        }
    }

    [Fact]
    public void Touched_runtime_paths_use_verified_Windows_boot_identity()
    {
        foreach (var source in new[]
                 {
                     Read("src", "Steward.Runtime.Windows", "WindowsProcessExecutor.cs"),
                     Read("src", "Steward.Node.Host", "ProductionNodeRuntime.cs"),
                     Read("src", "Steward.Maintenance.Windows", "Execution.cs")
                 })
        {
            Assert.DoesNotContain("TickCount64", source, StringComparison.Ordinal);
            Assert.Contains("WindowsBootIdentity", source, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Release_manifest_binds_size_catalog_and_Msi_identity_and_is_attested()
    {
        var build = Read("scripts", "Build-StewardEndpointMsi.ps1");
        var workflow = Read(".github", "workflows", "release-endpoint.yml");
        var installer = Read(
            "catalog", "devbox", "steward-endpoint", "Install-Steward.ps1");

        foreach (var claim in new[]
                 {
                     "MsiLength",
                     "ProductCode",
                     "UpgradeCode",
                     "CatalogIdentity"
                 })
        {
            Assert.Contains(claim, build, StringComparison.Ordinal);
            Assert.Contains(claim, installer, StringComparison.Ordinal);
        }
        Assert.Contains("steward-endpoint.release.psd1", workflow, StringComparison.Ordinal);
        Assert.Contains("gh attestation verify", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void Wsl_and_Docker_execution_remain_typed_verified_and_user_bound()
    {
        var source = Read("src", "Steward.Maintenance.Windows", "Execution.cs");

        Assert.Contains("MaintenanceArtifactCatalog.WslVersion", source, StringComparison.Ordinal);
        Assert.Contains("AssignedUserProcessRunner", source, StringComparison.Ordinal);
        Assert.Contains("operation.User.Sid", source, StringComparison.Ordinal);
        Assert.Contains("docker-compose.exe", source, StringComparison.Ordinal);
        Assert.Contains("DockerCapability", source, StringComparison.Ordinal);
        Assert.DoesNotContain("docker-compose.zip", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Updater_consumes_only_the_shared_v2_health_and_state_file_contract()
    {
        var update = Read(
            "src", "Steward.Maintenance.Windows",
            "WindowsEndpointUpdatePlatform.cs");
        var provisioner = Read(
            "src", "Steward.Endpoint.Provisioner", "Program.cs");
        var server = Read(
            "src", "Steward.RdpDvc.Server.Windows", "Program.cs");

        Assert.Contains("EndpointV2Health", update, StringComparison.Ordinal);
        Assert.DoesNotContain("AuthenticatedGenerations", update, StringComparison.Ordinal);
        Assert.Contains("EndpointStateFiles.ReconnectLedgerV2", update, StringComparison.Ordinal);
        Assert.Contains("EndpointStateFiles.ReconnectLedgerV2", provisioner, StringComparison.Ordinal);
        Assert.Contains("EndpointStateFiles.V2Health", server, StringComparison.Ordinal);
    }

    [Fact]
    public void Maintenance_update_uses_authenticated_durable_transaction_and_version_root()
    {
        var execution = Read("src", "Steward.Maintenance.Windows", "Execution.cs");
        var program = Read("src", "Steward.Maintenance.Windows", "Program.cs");
        var provisioner = Read("src", "Steward.Endpoint.Provisioner", "Program.cs");

        Assert.Contains("EndpointUpdateCoordinator", execution, StringComparison.Ordinal);
        Assert.Contains("FileEndpointUpdateTransactionStore", execution, StringComparison.Ordinal);
        Assert.Contains("machineSecret", program, StringComparison.Ordinal);
        Assert.Contains("VersionedRoot", provisioner, StringComparison.Ordinal);
        Assert.Contains("EndpointStateRoot", provisioner, StringComparison.Ordinal);
        Assert.Contains("EndpointUpgradeCode", provisioner, StringComparison.Ordinal);
    }
    private static string Read(params string[] segments) =>
        File.ReadAllText(Path.Combine([Repository, .. segments]));

    private static string FindRepository()
    {
        var candidate = new DirectoryInfo(AppContext.BaseDirectory);
        while (candidate is not null)
        {
            if (File.Exists(Path.Combine(candidate.FullName, "Steward.slnx")))
                return candidate.FullName;
            candidate = candidate.Parent;
        }
        throw new DirectoryNotFoundException(
            "Switchyard repository root was not found.");
    }
}


