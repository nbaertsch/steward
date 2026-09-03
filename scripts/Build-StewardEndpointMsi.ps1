param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [string]$SourceRepository = $env:GITHUB_REPOSITORY,
    [string]$SourceCommit = $env:GITHUB_SHA,
    [string]$SourceRef = $env:GITHUB_REF,
    [string]$SignerWorkflow,
    [string]$SourceRunId = $env:GITHUB_RUN_ID,
    [switch]$TestBuild
)

$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'Product version must be a three-part numeric version.'
}
$root = Split-Path -Parent $PSScriptRoot
$output = [IO.Path]::GetFullPath($OutputDirectory)
$payload = Join-Path $output 'payload'
$catalog = Join-Path $output 'catalog'
$msiOutput = Join-Path $output 'msi'
$wix = Join-Path $root 'packaging\Steward.Endpoint.Msi\Steward.Endpoint.Msi.wixproj'
Remove-Item -LiteralPath $payload -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $catalog -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $msiOutput -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $payload, $catalog, $msiOutput -Force | Out-Null
if ($TestBuild) {
    if ([string]::IsNullOrWhiteSpace($SourceRepository)) {
        $SourceRepository = 'local/switchyard'
    }
    if ([string]::IsNullOrWhiteSpace($SourceCommit)) {
        $SourceCommit = '0000000000000000000000000000000000000000'
    }
    if ([string]::IsNullOrWhiteSpace($SourceRef)) {
        $SourceRef = 'refs/heads/local-test'
    }
    if ([string]::IsNullOrWhiteSpace($SignerWorkflow)) {
        $SignerWorkflow =
            "$SourceRepository/.github/workflows/release-endpoint.yml"
    }
    if ([string]::IsNullOrWhiteSpace($SourceRunId)) {
        $SourceRunId = '0'
    }
} else {
    if ($env:GITHUB_ACTIONS -ne 'true' -or
        $Version -ne '1.0.45' -or
        [string]::IsNullOrWhiteSpace($SourceRepository) -or
        $SourceCommit -notmatch '^[0-9A-Fa-f]{40}$' -or
        $SourceRef -ne 'refs/heads/main' -or
        $SignerWorkflow -ne
            "$SourceRepository/.github/workflows/release-endpoint.yml" -or
        [string]::IsNullOrWhiteSpace($SourceRunId)) {
        throw 'Production endpoint MSI builds require exact 1.0.45 GitHub Actions provenance.'
    }
}

$publishRoot = Join-Path $output 'publish'
$components = @(
    [pscustomobject]@{
        Project = 'src\Steward.RdpDvc.Server.Windows\Steward.RdpDvc.Server.Windows.csproj'
        Directory = Join-Path $output 'publish\rdp-dvc'
    },
    [pscustomobject]@{
        Project = 'src\Steward.HandleKeeper\Steward.HandleKeeper.csproj'
        Directory = Join-Path $output 'publish\handle-keeper'
    },
    [pscustomobject]@{
        Project = 'src\Steward.Maintenance.Windows\Steward.Maintenance.Windows.csproj'
        Directory = Join-Path $output 'publish\maintenance'
    },
    [pscustomobject]@{
        Project = 'src\Steward.Endpoint.Provisioner\Steward.Endpoint.Provisioner.csproj'
        Directory = Join-Path $output 'publish\provisioner'
    }
)
Remove-Item -LiteralPath $publishRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $publishRoot -Force | Out-Null
foreach ($component in $components) {
    dotnet publish (Join-Path $root $component.Project) -c Release -f net10.0-windows -r win-x64 `
        --self-contained true -o $component.Directory `
        -p:UseAppHost=true -p:DebugSymbols=false -p:DebugType=None
    if ($LASTEXITCODE -ne 0) {
        throw "Publishing $($component.Project) failed."
    }
}

$nativeProviders = @($components | ForEach-Object {
    Get-ChildItem -LiteralPath $_.Directory -Filter 'e_sqlite3.dll' `
        -File -Recurse -ErrorAction SilentlyContinue
})
$nativeProviderHashes = @($nativeProviders | ForEach-Object {
    (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
} | Sort-Object -Unique)
if ($nativeProviders.Count -lt 3 -or $nativeProviderHashes.Count -ne 1) {
    throw 'SQLite native provider divergence across endpoint publishes.'
}
$endpointPayloadAllowlist = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($component in $components) {
    foreach ($file in Get-ChildItem -LiteralPath $component.Directory `
            -File -Recurse) {
        if ($file.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
            throw "Endpoint publish contains a reparse point: $($file.FullName)"
        }
        $relative = [IO.Path]::GetRelativePath(
            $component.Directory,
            $file.FullName)
        $destination = Join-Path $payload $relative
        if ($endpointPayloadAllowlist.Add($relative)) {
            New-Item -ItemType Directory -Path (
                Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $destination
            continue
        }
        if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash) {
            throw "Conflicting endpoint payload file: $relative"
        }
    }
}
foreach ($requiredEntrypoint in @(
    'Steward.RdpDvc.Server.Windows.exe',
    'Steward.HandleKeeper.exe',
    'Steward.Maintenance.Windows.exe',
    'Steward.Endpoint.Provisioner.exe',
    'e_sqlite3.dll')) {
    if (-not $endpointPayloadAllowlist.Contains($requiredEntrypoint) -or
        -not (Test-Path -LiteralPath (
            Join-Path $payload $requiredEntrypoint) -PathType Leaf)) {
        throw "Required endpoint payload file is missing: $requiredEntrypoint"
    }
}
$endpointNotices = Join-Path $root 'THIRD-PARTY-NOTICES.txt'
$apacheLicense = Join-Path $root 'third_party\Apache-2.0.txt'
$dotnetLicense = Join-Path (
    Split-Path -Parent (Get-Command dotnet).Source) `
    'LICENSE.txt'
$dotnetNotices = Join-Path (
    Split-Path -Parent (Get-Command dotnet).Source) `
    'ThirdPartyNotices.txt'
foreach ($notice in @(
    $endpointNotices,
    $apacheLicense,
    $dotnetLicense,
    $dotnetNotices)) {
    if (-not (Test-Path -LiteralPath $notice -PathType Leaf)) {
        throw "Required third-party notice is unavailable: $notice"
    }
}
Copy-Item -LiteralPath $endpointNotices `
    -Destination (Join-Path $payload 'THIRD-PARTY-NOTICES.txt')
Copy-Item -LiteralPath $apacheLicense `
    -Destination (Join-Path $payload 'Apache-2.0.txt')
Copy-Item -LiteralPath $dotnetLicense `
    -Destination (Join-Path $payload 'dotnet-runtime-LICENSE.txt')
Copy-Item -LiteralPath $dotnetNotices `
    -Destination (
        Join-Path $payload 'dotnet-runtime-THIRD-PARTY-NOTICES.txt')

$excluded = @(
    'Steward.Control',
    'Steward.Desktop',
    'Steward.Mcp',
    'Steward.ConnectionHost',
    'Steward.RdpDvc.Client',
    'Steward.RdpDvc.Shim'
)
foreach ($file in Get-ChildItem -LiteralPath $payload -File -Recurse) {
    if ($excluded | Where-Object {
            $file.Name.StartsWith($_, 'OrdinalIgnoreCase')
        }) {
        throw "Excluded controller component entered the endpoint payload: $($file.Name)"
    }
    $relative = [IO.Path]::GetRelativePath($payload, $file.FullName)
    if (-not $endpointPayloadAllowlist.Contains($relative) -and
        $file.Name -notin @(
            'THIRD-PARTY-NOTICES.txt',
            'Apache-2.0.txt',
            'dotnet-runtime-LICENSE.txt',
            'dotnet-runtime-THIRD-PARTY-NOTICES.txt')) {
        throw "Unexpected endpoint payload file: $relative"
    }
}

$payloadFiles = Get-ChildItem -LiteralPath $payload -File -Recurse |
    Where-Object {
        -not $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)
    } |
    Sort-Object FullName |
    ForEach-Object {
        [ordered]@{
            relativePath = [IO.Path]::GetRelativePath(
                $payload,
                $_.FullName).Replace('\', '/')
            length = $_.Length
            sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        }
    }
[ordered]@{
    version = 1
    productVersion = $Version
    files = @($payloadFiles)
} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 `
    (Join-Path $payload 'endpoint-payload.hashes.json')

$wixArguments = @(
    'build', $wix, '-c', 'Release',
    "-p:ProductVersion=$Version",
    "-p:PayloadDir=$payload",
    "-p:OutputPath=$msiOutput"
)
Remove-Item -LiteralPath (
    Join-Path (Split-Path -Parent $wix) 'obj') `
    -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (
    Join-Path (Split-Path -Parent $wix) 'bin') `
    -Recurse -Force -ErrorAction SilentlyContinue
if ($TestBuild) {
    $wixArguments += '-p:SuppressValidation=true'
}
dotnet @wixArguments
if ($LASTEXITCODE -ne 0) {
    throw 'Building the Steward endpoint MSI failed.'
}
$msiPath = Join-Path $msiOutput 'Steward.Endpoint.Msi.msi'
if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw 'The Steward endpoint MSI was not produced.'
}
$msi = Get-Item -LiteralPath $msiPath
$windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
$msiDatabase = $windowsInstaller.OpenDatabase($msi.FullName, 0)
function Get-StewardMsiProperty([object]$Database, [string]$Name) {
    $view = $Database.OpenView(
        "SELECT `Value` FROM `Property` WHERE `Property`='$Name'")
    [void]$view.Execute()
    $record = $view.Fetch()
    if ($null -eq $record) {
        throw "Required MSI property $Name is missing."
    }
    return $record.StringData(1).Trim()
}
$productCode = Get-StewardMsiProperty $msiDatabase 'ProductCode'
$upgradeCode = Get-StewardMsiProperty $msiDatabase 'UpgradeCode'
if ($productCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or
    $upgradeCode -ne '{37C34E0A-E245-48A4-B07C-78E2955A7E65}') {
    throw 'Endpoint MSI identity is invalid.'
}
Copy-Item $msi.FullName $catalog
$msiSha256 = (Get-FileHash $msi.FullName -Algorithm SHA256).Hash
$release = Join-Path $catalog 'steward-endpoint.release.psd1'
function ConvertTo-Psd1Literal([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}
$releaseContent = @"
@{
    Version = 4
    MsiFile = $(ConvertTo-Psd1Literal $msi.Name)
    ProductVersion = $(ConvertTo-Psd1Literal $Version)
    MsiSha256 = $(ConvertTo-Psd1Literal $msiSha256)
    MsiLength = $($msi.Length)
    ProductCode = $(ConvertTo-Psd1Literal $productCode)
    UpgradeCode = $(ConvertTo-Psd1Literal $upgradeCode)
    CatalogIdentity = $(ConvertTo-Psd1Literal "steward-endpoint/$Version/$SourceRunId")
    AttestationBundleFile = 'Steward.Endpoint.Msi.sigstore.json'
    SourceRepository = $(ConvertTo-Psd1Literal $SourceRepository)
    SourceCommit = $(ConvertTo-Psd1Literal $SourceCommit)
    SourceRef = $(ConvertTo-Psd1Literal $SourceRef)
    SignerWorkflow = $(ConvertTo-Psd1Literal $SignerWorkflow)
    SourceRunId = $(ConvertTo-Psd1Literal $SourceRunId)
}
"@
Set-Content -LiteralPath $release -Value $releaseContent -Encoding utf8
if ($TestBuild) {
    Set-Content -LiteralPath (
        Join-Path $catalog 'Steward.Endpoint.Msi.sigstore.json') `
        -Value 'TEST BUILD - GITHUB ATTESTATION REQUIRED FOR DEPLOYMENT' `
        -Encoding utf8
}
Write-Output $catalog
