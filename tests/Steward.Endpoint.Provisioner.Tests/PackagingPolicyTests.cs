namespace Steward.Endpoint.Provisioner.Tests;

public sealed class PackagingPolicyTests
{
    private static readonly string Repository =
        Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "..", "..", "..", "..", ".."));

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
        Assert.Contains(
            "HashSet[string]",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "FileAttributes]::ReparsePoint",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "$unixFileType -eq 0xA000",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Expand-Archive", script, StringComparison.Ordinal);
        Assert.Contains("artifact-attestation", script, StringComparison.Ordinal);
        Assert.Contains("ProductVersion", script, StringComparison.Ordinal);
        Assert.Contains("/qn", script, StringComparison.Ordinal);
        Assert.Contains("/norestart", script, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Get-AuthenticodeSignature",
            script,
            StringComparison.Ordinal);
        Assert.Contains("RelatedProducts", script, StringComparison.Ordinal);
        Assert.Contains("LocalPackage", script, StringComparison.Ordinal);
        Assert.Contains("rollback could not restore", script, StringComparison.Ordinal);
        Assert.Contains("STEWARD_ENDPOINT_MSI_HEALTHY_NOOP", script, StringComparison.Ordinal);
        Assert.Contains("AdministrativeRoot", script, StringComparison.Ordinal);
        Assert.Contains("'/a'", script, StringComparison.Ordinal);
        Assert.Contains(".staging-", script, StringComparison.Ordinal);
        Assert.Contains(".backup-", script, StringComparison.Ordinal);
        Assert.Contains(
            "STEWARD_ENDPOINT_ADMINISTRATIVE_IMAGE_PROVISIONED",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "A different Steward MSI with the same version is installed",
            script,
            StringComparison.Ordinal);
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
        Assert.Contains("gh release create", workflow, StringComparison.Ordinal);
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
        Assert.Contains(
            "Id=\"ProvisionStewardEndpoint\"",
            source,
            StringComparison.Ordinal);
        Assert.Contains("Execute=\"deferred\"", source, StringComparison.Ordinal);
        Assert.Contains("Impersonate=\"no\"", source, StringComparison.Ordinal);
        Assert.Contains("STEWARD_CONFIG", source, StringComparison.Ordinal);
        Assert.Contains("STEWARD_ATTESTATION", source, StringComparison.Ordinal);
        Assert.Contains(
            "ACTION &lt;&gt; &quot;ADMIN&quot;",
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
        Assert.Contains("corrupt.msi", script, StringComparison.Ordinal);
        Assert.Contains("clean rollback", script, StringComparison.Ordinal);
        Assert.Contains("MSI repair changed", script, StringComparison.Ordinal);
        Assert.Contains("'/x'", script, StringComparison.Ordinal);
        Assert.Contains("durable machine identity", script, StringComparison.Ordinal);
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
}
