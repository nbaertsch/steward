param(
    [Parameter(Mandatory = $true)]
    [string]$CatalogDirectory,
    [string]$BootstrapEncryptionPublicKeyBase64,
    [string]$ControlSigningPublicKeyBase64,
    [string]$ControlIdentity = 'control',
    [string]$NodeUserAccount,
    [string]$NodeUserSid,
    [string]$LegacyCatalogDirectory,
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
        $legacyCatalog = [IO.Path]::GetFullPath($LegacyCatalogDirectory)
        $legacyManifest = Import-PowerShellDataFile (
            Join-Path $legacyCatalog 'steward-endpoint.release.psd1')
        if ($legacyManifest.ProductVersion -ne '1.0.23') {
            throw 'Authentic legacy catalog must be Steward endpoint 1.0.23.'
        }
        & $PSCommandPath `
            -CatalogDirectory $legacyCatalog `
            -BootstrapEncryptionPublicKeyBase64 `
                $BootstrapEncryptionPublicKeyBase64 `
            -ControlSigningPublicKeyBase64 `
                $ControlSigningPublicKeyBase64 `
            -ControlIdentity $ControlIdentity `
            -NodeUserAccount $NodeUserAccount `
            -NodeUserSid $NodeUserSid `
            -Machine -KeepInstalled
        if ($LASTEXITCODE -ne 0) {
            throw 'Authentic Steward 1.0.23 clean install/repair gate failed.'
        }
        $legacyIdentity = Get-Content (Join-Path $env:ProgramData `
            'Steward\Endpoint\identity.json') -Raw
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
        $arguments = @(
            '/i', $msi, '/qn', '/norestart',
            "STEWARD_CONFIG=$config",
            "STEWARD_ATTESTATION=$attestation")
        foreach ($attempt in 1, 2) {
            $process = Start-Process msiexec.exe -ArgumentList $arguments `
                -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -notin 0, 1641, 3010) {
                throw "Per-machine install attempt $attempt failed."
            }
        }
        $state = Join-Path $env:ProgramData 'Steward\Endpoint'
        $maintenanceState = Join-Path $env:ProgramData 'Steward\Maintenance'
        $identityPath = Join-Path $state 'identity.json'
        $first = Get-Content $identityPath -Raw
        if ($null -ne $legacyIdentity -and $legacyIdentity -ne $first) {
            throw 'Authentic 1.0.23 upgrade changed the endpoint identity.'
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



