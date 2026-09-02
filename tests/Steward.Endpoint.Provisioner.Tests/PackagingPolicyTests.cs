namespace Steward.Endpoint.Provisioner.Tests;

public sealed class PackagingPolicyTests
{
    private static readonly string Repository = FindRepository();

    private static string FindRepository()
    {
        foreach (var seed in new[]
                 {
                     Directory.GetCurrentDirectory(),
                     AppContext.BaseDirectory
                 })
        {
            var candidate = new DirectoryInfo(
                Path.GetFullPath(seed));
            while (candidate is not null)
            {
                if (File.Exists(
                        Path.Combine(candidate.FullName, "Steward.slnx")) &&
                    Directory.Exists(
                        Path.Combine(candidate.FullName, ".git")))
                    return candidate.FullName;
                candidate = candidate.Parent;
            }
        }
        throw new DirectoryNotFoundException(
            "The Switchyard repository root was not found.");
    }

    [Fact]
    public void CatalogInstallerFailsClosedBeforeMsiExecution()
    {
        var script = File.ReadAllText(
            Path.Combine(
                Repository,
                "catalog",
                "devbox",
                "steward-endpoint",
                "Install-Steward.ps1"));

        Assert.Contains("Get-FileHash", script, StringComparison.Ordinal);
        Assert.Contains("attestation verify", script, StringComparison.Ordinal);
        Assert.Contains("--signer-workflow", script, StringComparison.Ordinal);
        Assert.Contains("--signer-digest", script, StringComparison.Ordinal);
        Assert.Contains("--source-digest", script, StringComparison.Ordinal);
        Assert.Contains("--deny-self-hosted-runners", script, StringComparison.Ordinal);
        Assert.Contains("HashSet[string]", script, StringComparison.Ordinal);
        Assert.Contains("FileAttributes]::ReparsePoint", script, StringComparison.Ordinal);
        Assert.Contains("$unixFileType -eq 0xA000", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Expand-Archive", script, StringComparison.Ordinal);
        Assert.Contains("artifact-attestation", script, StringComparison.Ordinal);
        Assert.Contains("ProductVersion", script, StringComparison.Ordinal);
        Assert.Contains("/qn", script, StringComparison.Ordinal);
        Assert.Contains("/norestart", script, StringComparison.Ordinal);
        Assert.Contains("'/i'", script, StringComparison.Ordinal);
        Assert.DoesNotContain("'/a'", script, StringComparison.Ordinal);
        Assert.DoesNotContain("AdministrativeRoot", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Stop-ScheduledTask", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-AuthenticodeSignature", script, StringComparison.Ordinal);
        Assert.Contains("RelatedProducts", script, StringComparison.Ordinal);
        Assert.Contains("STEWARD_ENDPOINT_MSI_HEALTHY_NOOP", script, StringComparison.Ordinal);
        Assert.Contains("A different Steward MSI with the same version is installed", script, StringComparison.Ordinal);
        Assert.True(
            script.IndexOf("attestation verify", StringComparison.Ordinal) <
            script.IndexOf("msiexec.exe", StringComparison.Ordinal));
    }

    [Fact]
    public void CatalogTaskIsSingleBoundedPowerShellEntryPoint()
    {
        var task = File.ReadAllText(
            Path.Combine(
                Repository,
                "catalog",
                "devbox",
                "steward-endpoint",
                "task.yaml"));

        Assert.Contains("$schema: \"1.0\"", task, StringComparison.Ordinal);
        Assert.Contains("name: install-steward-endpoint", task, StringComparison.Ordinal);
        Assert.Contains("command: .\\Install-Steward.ps1", task, StringComparison.Ordinal);
        Assert.Contains("timeout: 30", task, StringComparison.Ordinal);
        Assert.Contains("parameters:", task, StringComparison.Ordinal);
        Assert.Contains("releaseAssetUrl:", task, StringComparison.Ordinal);
        Assert.Contains(
            "bootstrapEncryptionPublicKeyBase64:",
            task,
            StringComparison.Ordinal);
        Assert.Contains(
            "controlSigningPublicKeyBase64:",
            task,
            StringComparison.Ordinal);
        Assert.Contains("controlIdentity:", task, StringComparison.Ordinal);
        Assert.Contains("nodeUserAccount:", task, StringComparison.Ordinal);
        Assert.Contains("nodeUserSid:", task, StringComparison.Ordinal);
        Assert.Contains(
            "release-assets\\\\.githubusercontent\\\\.com",
            task,
            StringComparison.Ordinal);
        Assert.Contains(
            "[A-Za-z0-9._~:/?&=%+-]+$",
            task,
            StringComparison.Ordinal);
        Assert.DoesNotContain("token", task, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildScriptRejectsControllerComponentsAndRequiresCiProvenance()
    {
        var script = File.ReadAllText(
            Path.Combine(Repository, "scripts", "Build-StewardEndpointMsi.ps1"));

        foreach (var excluded in new[]
                 {
                     "Steward.Control",
                     "Steward.Desktop",
                     "Steward.Mcp",
                     "Steward.ConnectionHost",
                     "Steward.RdpDvc.Client",
                     "Steward.RdpDvc.Shim"
                 })
            Assert.Contains(excluded, script, StringComparison.Ordinal);
        Assert.Contains("GITHUB_ACTIONS", script, StringComparison.Ordinal);
        Assert.Contains("$Version -ne '1.0.28'", script, StringComparison.Ordinal);
        Assert.Contains("SourceRepository", script, StringComparison.Ordinal);
        Assert.Contains("SourceCommit", script, StringComparison.Ordinal);
        Assert.Contains("SignerWorkflow", script, StringComparison.Ordinal);
        Assert.Contains("refs/heads/main", script, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "BootstrapEncryptionPublicKey",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "ControlSigningPublicKey",
            script,
            StringComparison.Ordinal);
        Assert.Contains("THIRD-PARTY-NOTICES.txt", script, StringComparison.Ordinal);
        Assert.Contains("Apache-2.0.txt", script, StringComparison.Ordinal);
        Assert.Contains("dotnet-runtime-LICENSE.txt", script, StringComparison.Ordinal);
        Assert.Contains(
            "dotnet-runtime-THIRD-PARTY-NOTICES.txt",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "Steward.Endpoint.Msi.msi",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Sort-Object LastWriteTimeUtc",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain("signtool", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReleaseWorkflowUsesPinnedKeylessGitHubAttestation()
    {
        var workflow = File.ReadAllText(
            Path.Combine(
                Repository,
                ".github",
                "workflows",
                "release-endpoint.yml"));

        Assert.Contains("id-token: write", workflow, StringComparison.Ordinal);
        Assert.Contains("attestations: write", workflow, StringComparison.Ordinal);
        Assert.Contains("artifact-metadata: write", workflow, StringComparison.Ordinal);
        Assert.Contains("contents: write", workflow, StringComparison.Ordinal);
        Assert.Contains("runs-on: windows-latest", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "Require public repository",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "github.event.repository.private",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains("--deny-self-hosted-runners", workflow, StringComparison.Ordinal);
        Assert.Contains("--source-digest '${{ github.sha }}'", workflow, StringComparison.Ordinal);
        Assert.Contains("refs/heads/main", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "must be exactly Steward endpoint 1.0.28",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "[Version]::Parse($Matches[1]) -ge $requested",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains("gh release create", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "Execute generated catalog bootstrap validation",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "Get-StewardEndpointEphemeralReleaseUrl.ps1",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "-ValidateOnly",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "STEWARD_BOOTSTRAP_ENCRYPTION_PUBLIC_KEY",
            workflow,
            StringComparison.Ordinal);
        Assert.DoesNotContain("signtool", workflow, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EphemeralReleaseUrlHelperKeepsTokenLocal()
    {
        var script = File.ReadAllText(
            Path.Combine(
                Repository,
                "scripts",
                "Get-StewardEndpointEphemeralReleaseUrl.ps1"));

        Assert.Contains("gh auth token", script, StringComparison.Ordinal);
        Assert.Contains(
            "AllowAutoRedirect = $false",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "release-assets.githubusercontent.com",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Write-Output $token", script, StringComparison.Ordinal);
    }

    [Fact]
    public void MsiOwnsOnlyProgramFilesAndLeavesMachineIdentityDurable()
    {
        var source = File.ReadAllText(
            Path.Combine(
                Repository,
                "packaging",
                "Steward.Endpoint.Msi",
                "Package.wxs"));

        Assert.Contains("ProgramFiles6432Folder", source, StringComparison.Ordinal);
        Assert.Contains("MajorUpgrade", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ProgramData", source, StringComparison.Ordinal);
        Assert.Contains("Id=\"ProvisionStewardEndpoint\"", source, StringComparison.Ordinal);
        Assert.Contains("Execute=\"deferred\"", source, StringComparison.Ordinal);
        Assert.Contains("Execute=\"rollback\"", source, StringComparison.Ordinal);
        Assert.Contains("Execute=\"commit\"", source, StringComparison.Ordinal);
        Assert.Contains("Impersonate=\"no\"", source, StringComparison.Ordinal);
        Assert.Contains("STEWARD_CONFIG", source, StringComparison.Ordinal);
        Assert.Contains("STEWARD_ATTESTATION", source, StringComparison.Ordinal);
        Assert.Contains("--p", source, StringComparison.Ordinal);
        Assert.Contains("--r", source, StringComparison.Ordinal);
        Assert.Contains("--c", source, StringComparison.Ordinal);
        Assert.DoesNotContain("--l", source, StringComparison.Ordinal);
        foreach (var line in source.Split('\n').Where(line => line.Contains("ExeCommand=", StringComparison.Ordinal)))
            Assert.True(
                line.Length <= 255,
                $"MSI CustomAction Target line is too long: {line.Length} characters.");
        var provisioner = File.ReadAllText(
            Path.Combine(
                Repository,
                "src",
                "Steward.Endpoint.Provisioner",
                "Program.cs"));
        Assert.Contains(
            "Steward\", \"install\", \"Endpoint",
            provisioner,
            StringComparison.Ordinal);
        Assert.Contains("After=\"StartServices\"", source, StringComparison.Ordinal);
        Assert.Equal(
            3,
            source.Split(
                "ACTION &lt;&gt; &quot;ADMIN&quot;",
                StringSplitOptions.None).Length - 1);
        Assert.Contains("--verify-installed", File.ReadAllText(
            Path.Combine(
                Repository,
                "catalog",
                "devbox",
                "steward-endpoint",
                "Install-Steward.ps1")), StringComparison.Ordinal);
    }

    [Fact]
    public void ProvisionedEndpointTasksRestartAfterUnexpectedExit()
    {
        var source = File.ReadAllText(
            Path.Combine(
                Repository,
                "src",
                "Steward.Endpoint.Provisioner",
                "Program.cs"));

        Assert.Contains(
            "-RestartCount 999",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "-RestartInterval (New-TimeSpan -Minutes 1)",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "Resolve-TaskUserSid",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "(Resolve-TaskUserSid $aLogon[0].UserId)-eq'{{Escape(userSid)}}'",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "--reconnect-ledger-file",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "$\"--nonce-sequence-file",
            source,
            StringComparison.Ordinal);
    }

    [Fact]
    public void MsiTestScriptCoversCleanRepairRollbackAndUninstall()
    {
        var script = File.ReadAllText(
            Path.Combine(
                Repository,
                "scripts",
                "Test-StewardEndpointMsi.ps1"));

        Assert.Contains("foreach ($attempt in 1, 2)", script, StringComparison.Ordinal);
        Assert.Contains("'/i'", script, StringComparison.Ordinal);
        Assert.DoesNotContain("'/a'", script, StringComparison.Ordinal);
        Assert.Contains("failed activation rollback", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("MSI repair changed", script, StringComparison.Ordinal);
        Assert.Contains("'/x'", script, StringComparison.Ordinal);
        Assert.Contains("durable machine identity", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Catalog_identity_and_bootstrap_pin_are_generated_from_the_immutable_release()
    {
        var build = File.ReadAllText(Path.Combine(
            Repository, "scripts", "Build-StewardEndpointMsi.ps1"));
        var bootstrap = File.ReadAllText(Path.Combine(
            Repository, "scripts", "Build-StewardEndpointCatalogBootstrap.ps1"));
        var installer = File.ReadAllText(Path.Combine(
            Repository, "catalog", "devbox", "steward-endpoint",
            "Install-Steward.ps1"));
        var dsc = File.ReadAllText(Path.Combine(
            Repository, "catalog", "devbox", "steward-endpoint",
            "steward-endpoint.dsc.yaml"));

        Assert.Contains("steward-endpoint/$Version/$SourceRunId", build, StringComparison.Ordinal);
        Assert.Contains("^steward-endpoint/[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$", installer, StringComparison.Ordinal);
        Assert.Contains("SourceCommit", bootstrap, StringComparison.Ordinal);
        Assert.Contains("HttpClient", bootstrap, StringComparison.Ordinal);
        Assert.Contains("ResponseHeadersRead", bootstrap, StringComparison.Ordinal);
        Assert.True(
            bootstrap.IndexOf(
                "$installerHash = (Get-FileHash -LiteralPath $installerSource",
                StringComparison.Ordinal) >
            bootstrap.IndexOf("if ($TestBuild)", StringComparison.Ordinal));
        Assert.Contains("__STEWARD_INSTALLER_URI__", dsc, StringComparison.Ordinal);
        Assert.Contains("__STEWARD_INSTALLER_SHA256__", dsc, StringComparison.Ordinal);
        Assert.DoesNotContain("8db99e3377fe4799234e8b9deca631c63cb479b9", dsc, StringComparison.Ordinal);
    }

    [Fact]
    public void Endpoint_publish_is_isolated_and_composed_from_an_exact_allowlist()
    {
        var build = File.ReadAllText(Path.Combine(
            Repository, "scripts", "Build-StewardEndpointMsi.ps1"));

        Assert.Contains("publish\\rdp-dvc", build, StringComparison.Ordinal);
        Assert.Contains("publish\\handle-keeper", build, StringComparison.Ordinal);
        Assert.Contains("publish\\maintenance", build, StringComparison.Ordinal);
        Assert.Contains("publish\\provisioner", build, StringComparison.Ordinal);
        Assert.Contains("$endpointPayloadAllowlist", build, StringComparison.Ordinal);
        Assert.Contains("Unexpected endpoint payload file", build, StringComparison.Ordinal);
        Assert.Contains("SQLite native provider divergence", build, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_requires_full_production_security_and_migration_gates()
    {
        var workflow = File.ReadAllText(Path.Combine(
            Repository, ".github", "workflows", "release-endpoint.yml"));

        foreach (var gate in new[]
                 {
                     "Hosted deterministic dependency tests",
                     "Hosted Windows timing probe",
                     "ControlProviderBootstrapCompositionTests",
                     "Test-StewardEndpointMsi.ps1",
                     "dependency vulnerability",
                     "secret scan",
                     "SBOM",
                     "1.0.23",
                     "second upgrade",
                     "failed activation rollback",
                     "catalog provenance"
                 })
            Assert.Contains(gate, workflow, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("STEWARD_1_0_23_RELEASE_INPUT", workflow, StringComparison.Ordinal);
        Assert.Contains("Authentic Steward 1.0.23 release input is required", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "$repository -ne '${{ github.repository }}'",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "$tag -ne 'steward-endpoint-v1.0.23'",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "Authentic Steward 1.0.23 provenance verification failed",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "contents/catalog/devbox/steward-endpoint/Install-Steward.ps1?ref=",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "-LegacyReleaseAssetUrl $env:STEWARD_LEGACY_RELEASE_URL",
            workflow,
            StringComparison.Ordinal);
    }

    [Fact]
    public void LegacyChunkDeploymentIsQuarantined()
    {
        var source = File.ReadAllText(
            Path.Combine(
                Repository,
                "tools",
                "Steward.DevBox.BootstrapDeploy",
                "Program.cs"));

        Assert.Contains(
            "Chunked Dev Box customization delivery, probes, and lifecycle mutation are quarantined",
            source,
            StringComparison.Ordinal);
        Assert.Contains("options.InspectStaging ||", source, StringComparison.Ordinal);
        Assert.Contains("options.ProbeEndpoint ||", source, StringComparison.Ordinal);
        Assert.Contains(
            "options.RestartOnlyId is not null",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "Use the signed catalog MSI bootstrap",
            source,
            StringComparison.Ordinal);
    }

    [Fact]
    public void DevBoxEndpointInstallUsesExactReleasedCatalogTask()
    {
        var source = File.ReadAllText(
            Path.Combine(
                Repository,
                "tools",
                "Steward.DevBox.BootstrapDeploy",
                "Program.cs"));

        Assert.Contains(
            "ListTaskDefinitionsAsync",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"install-steward-endpoint\"",
            source,
            StringComparison.Ordinal);
        foreach (var parameter in new[]
                 {
                     "releaseAssetUrl",
                     "bootstrapEncryptionPublicKeyBase64",
                     "controlSigningPublicKeyBase64",
                     "controlIdentity",
                     "nodeUserAccount",
                     "nodeUserSid"
                 })
            Assert.Contains(
                $"\"{parameter}\"",
                source,
                StringComparison.Ordinal);
        Assert.Contains(
            "definition.Parameters.SetEquals(expectedParameters)",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "[\"controlIdentity\"] = installControlIdentity",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "[\"controlIdentity\"] = \"control\"",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "8db99e3377fe4799234e8b9deca631c63cb479b9",
            source,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "C07BFE96AA88492C94EBCA1614885E3081AE2CB0944FE670000C23FB838DF68A",
            source,
            StringComparison.OrdinalIgnoreCase);
    }
}
