param(
    [Parameter(Mandatory = $true)]
    [string]$CatalogDirectory,
    [string]$BootstrapEncryptionPublicKeyBase64,
    [string]$ControlSigningPublicKeyBase64,
    [string]$ControlIdentity = 'control',
    [string]$NodeUserAccount,
    [string]$NodeUserSid,
    [string]$LegacyCatalogDirectory,
    [uri]$LegacyReleaseAssetUrl,
    [switch]$Machine,
    [switch]$KeepInstalled
)

$ErrorActionPreference = 'Stop'
$catalog = [IO.Path]::GetFullPath($CatalogDirectory)
$manifest = Import-PowerShellDataFile (
    Join-Path $catalog 'steward-endpoint.release.psd1')
$msi = Join-Path $catalog $manifest.MsiFile
if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) {
    throw 'MSI test input is missing.'
}

$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($msi, 0)
function Get-MsiRows([object]$Database, [string]$Query, [int]$Fields) {
    $view = $Database.OpenView($Query)
    [void]$view.Execute()
    $rows = [Collections.Generic.List[object]]::new()
    while ($null -ne ($record = $view.Fetch())) {
        $values = @(
            for ($index = 1; $index -le $Fields; $index++) {
                $record.StringData($index)
            })
        [void]$rows.Add([pscustomobject]@{ Values = $values })
    }
    return $rows
}
function Get-LongMsiFileName([string]$Value) {
    $separator = $Value.IndexOf('|')
    if ($separator -ge 0) { return $Value.Substring($separator + 1) }
    return $Value
}

$fileNames = @(Get-MsiRows $database 'SELECT `FileName` FROM `File`' 1 |
    ForEach-Object { Get-LongMsiFileName $_.Values[0] })
foreach ($required in @(
    'Steward.RdpDvc.Server.Windows.dll',
    'Steward.HandleKeeper.dll',
    'Steward.Maintenance.Windows.exe',
    'Steward.Maintenance.Windows.dll',
    'Steward.Endpoint.Provisioner.exe',
    'e_sqlite3.dll',
    'THIRD-PARTY-NOTICES.txt',
    'Apache-2.0.txt',
    'dotnet-runtime-LICENSE.txt',
    'dotnet-runtime-THIRD-PARTY-NOTICES.txt')) {
    if ($required -notin $fileNames) {
        throw "MSI File table omitted $required."
    }
}
foreach ($excluded in @(
    'Steward.Control',
    'Steward.Desktop',
    'Steward.Mcp',
    'Steward.ConnectionHost',
    'Steward.RdpDvc.Client',
    'Steward.RdpDvc.Shim')) {
    if ($fileNames.Where({ $_.StartsWith(
            $excluded,
            [StringComparison]::OrdinalIgnoreCase) }).Count -ne 0) {
        throw "MSI File table included excluded component $excluded."
    }
}
$service = @(Get-MsiRows $database (
    'SELECT `Name`,`StartName`,`StartType` FROM `ServiceInstall`') 3)
if ($service.Count -ne 1 -or
    $service[0].Values[0] -ne 'StewardMaintenance' -or
    $service[0].Values[1] -ne 'LocalSystem' -or
    $service[0].Values[2] -ne '2') {
    throw 'MSI service table does not define the exact auto LocalSystem service.'
}
$actions = @(Get-MsiRows $database (
    'SELECT `Action`,`Type`,`Target` FROM `CustomAction`') 3)
foreach ($requiredAction in @(
    'RollbackStewardEndpointProvisioning',
    'ProvisionStewardEndpoint',
    'CommitStewardEndpointProvisioning')) {
    if ($actions.Where({ $_.Values[0] -eq $requiredAction }).Count -ne 1) {
        throw "MSI custom action $requiredAction is missing."
    }
}
if ($actions.Where({  $_.Values[2] -match '(^|\s)/a(\s|$)' }).Count -ne 0) {
    throw 'MSI contains an administrative extraction action.'
}
$sequence = @(Get-MsiRows $database (
    'SELECT `Action`,`Sequence` FROM `InstallExecuteSequence`') 2)
$startServices = [int]($sequence.Where({ $_.Values[0] -eq 'StartServices' })[0].Values[1])
$commit = [int]($sequence.Where({
    $_.Values[0] -eq 'CommitStewardEndpointProvisioning' })[0].Values[1])
if ($commit -le $startServices) {
    throw 'Provisioner commit is not sequenced after StartServices.'
}

$corrupt = [IO.Path]::ChangeExtension($msi, '.corrupt-test.msi')
try {
    $bytes = [IO.File]::ReadAllBytes($msi)
    [IO.File]::WriteAllBytes(
        $corrupt,
        $bytes[0..([Math]::Floor($bytes.Length / 2))])
    try {
        $null = $installer.OpenDatabase($corrupt, 0)
        throw 'Corrupt MSI unexpectedly opened.'
    } catch [Runtime.InteropServices.COMException] {
    }
} finally {
    Remove-Item -LiteralPath $corrupt -Force -ErrorAction SilentlyContinue
}

if ($Machine) {
    $legacyIdentity = $null
    if (-not [string]::IsNullOrWhiteSpace($LegacyCatalogDirectory)) {
        if ($null -eq $LegacyReleaseAssetUrl -or
            -not $LegacyReleaseAssetUrl.IsAbsoluteUri -or
            $LegacyReleaseAssetUrl.Scheme -ne 'https') {
            throw 'Authentic legacy testing requires its HTTPS release asset URL.'
        }
        $legacyCatalog = [IO.Path]::GetFullPath($LegacyCatalogDirectory)
        $legacyManifest = Import-PowerShellDataFile (
            Join-Path $legacyCatalog 'steward-endpoint.release.psd1')
        if ($legacyManifest.ProductVersion -ne '1.0.23') {
            throw 'Authentic legacy catalog must be Steward endpoint 1.0.23.'
        }
        $legacyInstall = Join-Path $legacyCatalog 'Install-Steward.ps1'
        if (-not (Test-Path -LiteralPath $legacyInstall -PathType Leaf)) {
            throw 'Authentic legacy catalog omitted Install-Steward.ps1.'
        }
        $legacyRuntime = Join-Path $env:ProgramData `
            'Steward\install\Runtime\1.0.23'
        $legacyUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        & $legacyInstall `
            -ReleaseAssetUrl $LegacyReleaseAssetUrl `
            -BootstrapEncryptionPublicKeyBase64 `
                $BootstrapEncryptionPublicKeyBase64 `
            -ControlSigningPublicKeyBase64 `
                $ControlSigningPublicKeyBase64 `
            -ControlIdentity $ControlIdentity `
            -NodeUserAccount $legacyUser.Name `
            -NodeUserSid $legacyUser.User.Value `
            -AdministrativeRoot $legacyRuntime
        if ($LASTEXITCODE -ne 0) {
            throw 'Authentic Steward 1.0.23 administrative deployment failed.'
        }
        $legacyState = Join-Path $env:ProgramData `
            'Steward\install\Endpoint'
        $legacyPayload = Join-Path $legacyRuntime 'PFiles64\Steward'
        $legacyIdentityPath = Join-Path $legacyState 'identity.json'
        if (-not (Test-Path -LiteralPath $legacyPayload -PathType Container) -or
            -not (Test-Path -LiteralPath $legacyIdentityPath -PathType Leaf)) {
            throw 'Authentic 1.0.23 administrative layout was not created.'
        }
        $legacyIdentity = Get-Content $legacyIdentityPath -Raw
    }
    if ([string]::IsNullOrWhiteSpace(
            $BootstrapEncryptionPublicKeyBase64) -or
        [string]::IsNullOrWhiteSpace($ControlSigningPublicKeyBase64) -or
        [string]::IsNullOrWhiteSpace($NodeUserAccount) -or
        [string]::IsNullOrWhiteSpace($NodeUserSid)) {
        throw 'Machine install tests require runtime trust and assigned-user inputs.'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Signed machine install tests require elevation.'
    }
    $machineRoot = Join-Path $catalog (
        '.machine-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $machineRoot -Force | Out-Null
    try {
        $bootstrap = Join-Path $machineRoot 'bootstrap-envelope.spki'
        $control = Join-Path $machineRoot 'control-signing.spki'
        [IO.File]::WriteAllBytes(
            $bootstrap,
            [Convert]::FromBase64String($BootstrapEncryptionPublicKeyBase64))
        [IO.File]::WriteAllBytes(
            $control,
            [Convert]::FromBase64String($ControlSigningPublicKeyBase64))
        $config = Join-Path $machineRoot 'config.json'
        [ordered]@{
            version = 1
            productVersion = $manifest.ProductVersion
            bootstrapEncryptionPublicKey = 'bootstrap-envelope.spki'
            controlSigningPublicKey = 'control-signing.spki'
            controlIdentity = $ControlIdentity
            provisionedUserAccount = $NodeUserAccount
            provisionedUserSid = $NodeUserSid
        } | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding utf8
        $attestation = Join-Path $machineRoot 'attestation.json'
        [ordered]@{
            version = 1
            productVersion = $manifest.ProductVersion
            msiSha256 = $manifest.MsiSha256
            sourceRepository = $manifest.SourceRepository
            sourceCommit = $manifest.SourceCommit
            sourceRef = $manifest.SourceRef
            signerWorkflow = $manifest.SignerWorkflow
            sourceRunId = $manifest.SourceRunId
            productCode = $manifest.ProductCode
            configSha256 = (Get-FileHash $config -Algorithm SHA256).Hash
            bootstrapEncryptionPublicKeySha256 =
                (Get-FileHash $bootstrap -Algorithm SHA256).Hash
            controlSigningPublicKeySha256 =
                (Get-FileHash $control -Algorithm SHA256).Hash
            controlIdentity = $ControlIdentity
        } | ConvertTo-Json | Set-Content -LiteralPath $attestation -Encoding utf8
        foreach ($attempt in 1, 2) {
            $log = Join-Path $machineRoot "install-$attempt.log"
            $arguments = @(
                '/i', $msi, '/qn', '/norestart', '/L*v', $log,
                "STEWARD_CONFIG=$config",
                "STEWARD_ATTESTATION=$attestation")
            $process = Start-Process msiexec.exe -ArgumentList $arguments `
                -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -notin 0, 1641, 3010) {
                if (Test-Path -LiteralPath $log) {
                    $lines = @(Get-Content -LiteralPath $log)
                    $failureIndexes = @(for ($index = 0; $index -lt $lines.Count; $index++) {
                        if ($lines[$index] -match 'Return value 3|Error [0-9]{4}|Steward endpoint provisioning failed') {
                            $index
                        }
                    })
                    if ($failureIndexes.Count -eq 0) {
                        $lines | Select-Object -Last 300 | Write-Host
                    } else {
                        foreach ($failureIndex in $failureIndexes) {
                            $start = [Math]::Max(0, $failureIndex - 80)
                            $count = [Math]::Min(
                                $lines.Count - $start,
                                180)
                            $lines[$start..($start + $count - 1)] |
                                Write-Host
                        }
                    }
                }
                throw "Per-machine install attempt $attempt failed with exit code $($process.ExitCode)."
            }
        }
        $state = Join-Path $env:ProgramData 'Steward\Endpoint'
        $maintenanceState = Join-Path $env:ProgramData 'Steward\Maintenance'
        $identityPath = Join-Path $state 'identity.json'
        $first = Get-Content $identityPath -Raw
        if ($null -ne $legacyIdentity -and $legacyIdentity -ne $first) {
            throw 'Authentic 1.0.23 upgrade changed the endpoint identity.'
        }
        if ($null -ne $legacyIdentity) {
            $legacyState = Join-Path $env:ProgramData `
                'Steward\install\Endpoint'
            if (Test-Path -LiteralPath $legacyState) {
                throw 'Committed upgrade left the legacy administrative state authoritative.'
            }
            $legacyRuntimePrefix = [IO.Path]::GetFullPath(
                (Join-Path $env:ProgramData `
                    'Steward\install\Runtime\1.0.23'))
            $scheduled = @(Get-ScheduledTask -TaskPath '\Steward\' `
                -ErrorAction SilentlyContinue)
            foreach ($task in $scheduled) {
                $xml = Export-ScheduledTask -TaskName $task.TaskName `
                    -TaskPath '\Steward\'
                if ($xml.IndexOf(
                        $legacyRuntimePrefix,
                        [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    throw 'Committed upgrade retained a legacy runtime task path.'
                }
            }
        }
        $maintenanceService = Get-CimInstance Win32_Service `
            -Filter "Name='StewardMaintenance'" -ErrorAction SilentlyContinue
        if ($null -eq $maintenanceService -or
            $maintenanceService.StartName -ne 'LocalSystem' -or
            $maintenanceService.StartMode -ne 'Auto' -or
            $maintenanceService.State -ne 'Running' -or
            -not (Test-Path -LiteralPath $maintenanceState -PathType Container)) {
            throw 'Steward LocalSystem maintenance service is unhealthy.'
        }
        $failed = Start-Process msiexec.exe -ArgumentList @(
            '/i', $msi, '/qn', '/norestart',
            'STEWARD_CONFIG=Z:\missing\config.json',
            "STEWARD_ATTESTATION=$attestation") `
            -Wait -PassThru -NoNewWindow
        if ($failed.ExitCode -eq 0) {
            throw 'Injected failed activation rollback unexpectedly succeeded.'
        }
        $second = Get-Content $identityPath -Raw
        if ($first -ne $second) {
            throw 'MSI repair changed the machine identity or failed activation rollback did so.'
        }
        if ($KeepInstalled) {
            Write-Output 'STEWARD_ENDPOINT_MSI_KEPT_FOR_UPGRADE'
            return
        }
        $productCode = $manifest.ProductCode
        $process = Start-Process msiexec.exe -ArgumentList @(
            '/x', $productCode, '/qn', '/norestart') `
            -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -notin 0, 1605) {
            throw "MSI uninstall failed with exit code $($process.ExitCode)."
        }
        if ($null -ne (Get-CimInstance Win32_Service `
                -Filter "Name='StewardMaintenance'" -ErrorAction SilentlyContinue)) {
            throw 'MSI uninstall left the maintenance service registered.'
        }
        if (Test-Path (Join-Path $env:ProgramFiles 'Steward')) {
            throw 'MSI uninstall left immutable runtime files installed.'
        }
        if (-not (Test-Path $identityPath -PathType Leaf)) {
            throw 'MSI uninstall removed the durable machine identity.'
        }
    } finally {
        Remove-Item -LiteralPath $machineRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}
Write-Output 'STEWARD_ENDPOINT_MSI_TESTS_PASSED'


