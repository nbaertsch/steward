param(
    [Parameter(Mandatory = $true)]
    [string]$CatalogDirectory,
    [uri]$ReleaseAssetUrl,
    [string]$BootstrapEncryptionPublicKeyBase64,
    [string]$ControlSigningPublicKeyBase64,
    [string]$ControlIdentity = 'control',
    [switch]$Machine
)

$ErrorActionPreference = 'Stop'
$catalog = [IO.Path]::GetFullPath($CatalogDirectory)
$manifest = Import-PowerShellDataFile (
    Join-Path $catalog 'steward-endpoint.release.psd1')
$msi = Join-Path $catalog $manifest.msiFile
if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) {
    throw 'MSI test input is missing.'
}

$testRoot = Join-Path $env:TEMP ('steward-msi-test-' + [guid]::NewGuid().ToString('N'))
$extract = Join-Path $testRoot 'extract'
$rollback = Join-Path $testRoot 'rollback'
New-Item -ItemType Directory -Path $extract, $rollback -Force | Out-Null
try {
    foreach ($attempt in 1, 2) {
        $process = Start-Process msiexec.exe -ArgumentList @(
            '/a', "`"$msi`"", '/qn', "TARGETDIR=`"$extract`"") `
            -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -ne 0) {
            throw "Administrative install attempt $attempt failed."
        }
    }
    $installed = Join-Path $extract 'PFiles64\Steward'
    foreach ($required in @(
        'Steward.RdpDvc.Server.Windows.dll',
        'Steward.HandleKeeper.dll',
        'Steward.Endpoint.Provisioner.exe',
        'e_sqlite3.dll',
        'THIRD-PARTY-NOTICES.txt',
        'Apache-2.0.txt',
        'dotnet-runtime-LICENSE.txt',
        'dotnet-runtime-THIRD-PARTY-NOTICES.txt',
        'Microsoft.RdpDvcSamples.LICENSE.txt')) {
        if (-not (Test-Path (Join-Path $installed $required) -PathType Leaf)) {
            throw "Administrative install omitted $required."
        }
    }
    if ((Get-Content (Join-Path $installed 'Apache-2.0.txt') -Raw) -notmatch
            'TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION' -or
        (Get-Content (Join-Path $installed 'Apache-2.0.txt') -Raw) -notmatch
            'END OF TERMS AND CONDITIONS' -or
        (Get-Content (Join-Path $installed 'dotnet-runtime-LICENSE.txt') -Raw) -notmatch
            'MICROSOFT SOFTWARE LICENSE TERMS' -or
        (Get-Content (Join-Path $installed 'dotnet-runtime-LICENSE.txt') -Raw) -notmatch
            'DISTRIBUTABLE CODE' -or
        (Get-Content (Join-Path $installed 'THIRD-PARTY-NOTICES.txt') -Raw) -notmatch
            'Copyright \(c\) Microsoft Corporation') {
        throw 'Administrative install contains incomplete third-party notices.'
    }
    foreach ($excluded in @(
        'Steward.Control*',
        'Steward.Desktop*',
        'Steward.Mcp*',
        'Steward.ConnectionHost*',
        'Steward.RdpDvc.Client*',
        'Steward.RdpDvc.Shim*')) {
        if (Get-ChildItem $installed -Filter $excluded -File -ErrorAction SilentlyContinue) {
            throw "Administrative install included excluded component $excluded."
        }
    }

    $corrupt = Join-Path $testRoot 'corrupt.msi'
    $bytes = [IO.File]::ReadAllBytes($msi)
    [IO.File]::WriteAllBytes($corrupt, $bytes[0..([Math]::Floor($bytes.Length / 2))])
    $process = Start-Process msiexec.exe -ArgumentList @(
        '/a', "`"$corrupt`"", '/qn', "TARGETDIR=`"$rollback`"") `
        -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -eq 0 -or (
        Test-Path (Join-Path $rollback 'PFiles64\Steward'))) {
        throw 'Corrupt MSI did not fail with a clean rollback.'
    }

    if ($Machine) {
        if ($null -eq $ReleaseAssetUrl) {
            throw 'Machine install tests require a private release asset URL.'
        }
        if ([string]::IsNullOrWhiteSpace(
                $BootstrapEncryptionPublicKeyBase64) -or
            [string]::IsNullOrWhiteSpace($ControlSigningPublicKeyBase64)) {
            throw 'Machine install tests require runtime trust public keys.'
        }
        $principal = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Signed machine install tests require elevation.'
        }
        & (Join-Path $catalog 'Install-Steward.ps1') `
            -ReleaseAssetUrl $ReleaseAssetUrl `
            -BootstrapEncryptionPublicKeyBase64 `
                $BootstrapEncryptionPublicKeyBase64 `
            -ControlSigningPublicKeyBase64 $ControlSigningPublicKeyBase64 `
            -ControlIdentity $ControlIdentity
        $state = Join-Path $env:ProgramData 'Steward\Endpoint'
        $identityPath = Join-Path $state 'identity.json'
        $first = Get-Content $identityPath -Raw
        & (Join-Path $catalog 'Install-Steward.ps1') `
            -ReleaseAssetUrl $ReleaseAssetUrl `
            -BootstrapEncryptionPublicKeyBase64 `
                $BootstrapEncryptionPublicKeyBase64 `
            -ControlSigningPublicKeyBase64 $ControlSigningPublicKeyBase64 `
            -ControlIdentity $ControlIdentity
        $second = Get-Content $identityPath -Raw
        if ($first -ne $second) {
            throw 'MSI repair changed the machine identity.'
        }
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($msi, 0)
        $view = $database.OpenView(
            "SELECT `Value` FROM `Property` WHERE `Property`='ProductCode'")
        $view.Execute()
        $productCode = $view.Fetch().StringData(1)
        $process = Start-Process msiexec.exe -ArgumentList @(
            '/x', $productCode, '/qn', '/norestart') `
            -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -notin 0, 1605) {
            throw "MSI uninstall failed with exit code $($process.ExitCode)."
        }
        if (Test-Path (Join-Path $env:ProgramFiles 'Steward')) {
            throw 'MSI uninstall left immutable runtime files installed.'
        }
        if (-not (Test-Path $identityPath -PathType Leaf)) {
            throw 'MSI uninstall removed the durable machine identity.'
        }
    }
    Write-Output 'STEWARD_ENDPOINT_MSI_TESTS_PASSED'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
