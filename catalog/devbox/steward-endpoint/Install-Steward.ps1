param(
    [Parameter(Mandatory = $true)]
    [uri]$ReleaseAssetUrl,
    [Parameter(Mandatory = $true)]
    [string]$BootstrapEncryptionPublicKeyBase64,
    [Parameter(Mandatory = $true)]
    [string]$ControlSigningPublicKeyBase64,
    [Parameter(Mandatory = $true)]
    [string]$ControlIdentity,
    [Parameter(Mandatory = $true)]
    [string]$NodeUserAccount,
    [Parameter(Mandatory = $true)]
    [string]$NodeUserSid,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
$SourceRepository = '__STEWARD_APPROVED_SOURCE_REPOSITORY__'
$SignerWorkflow = '__STEWARD_APPROVED_SIGNER_WORKFLOW__'
$SourceRef = 'refs/heads/main'
if ($SourceRepository -match '^__STEWARD_' -or
    $SignerWorkflow -match '^__STEWARD_' -or
    $SourceRepository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    $SignerWorkflow -ne
        "$SourceRepository/.github/workflows/release-endpoint.yml") {
    throw 'Steward endpoint GitHub provenance policy is invalid.'
}
if ($BootstrapEncryptionPublicKeyBase64 -notmatch
        '^[A-Za-z0-9+/]{300,1600}={0,2}$' -or
    $ControlSigningPublicKeyBase64 -notmatch
        '^[A-Za-z0-9+/]{80,1600}={0,2}$' -or
    $ControlIdentity -notmatch '^[A-Za-z0-9._:@/-]{1,200}$' -or
    $NodeUserAccount -notmatch '^[A-Za-z0-9._@\\/-]{3,256}$' -or
    $NodeUserSid -notmatch '^S-1-12-1-(\d+-){2}\d+-\d+$') {
    throw 'Steward endpoint runtime trust arguments are invalid.'
}
function Assert-StewardDirectory([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Steward endpoint directory containment is invalid.'
    }
}
Assert-StewardDirectory $env:ProgramData
$stewardInstallRoot = Join-Path $env:ProgramData 'Steward\install'
$current = $env:ProgramData
foreach ($segment in 'Steward', 'install') {
    $current = Join-Path $current $segment
    if (-not (Test-Path -LiteralPath $current)) {
        New-Item -ItemType Directory -Path $current | Out-Null
    }
    Assert-StewardDirectory $current
}
$downloadRoot = Join-Path $stewardInstallRoot (
    'download-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null
try {
if ($ValidateOnly) {
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().
        User.Value
    & icacls.exe $downloadRoot /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
        "*$currentSid`:(OI)(CI)F" | Out-Null
} else {
    & icacls.exe $downloadRoot /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}
if ($LASTEXITCODE -ne 0) {
    throw 'Steward endpoint download staging ACL failed.'
}
if ($ReleaseAssetUrl.Scheme -ne 'https' -or
    $ReleaseAssetUrl.Host -ne 'release-assets.githubusercontent.com' -or
    [string]::IsNullOrWhiteSpace($ReleaseAssetUrl.Query) -or
    $ReleaseAssetUrl.AbsoluteUri -notmatch
        '^https://release-assets\.githubusercontent\.com/[A-Za-z0-9._~:/?&=%+-]+$') {
    throw 'Steward endpoint release URL is not an ephemeral GitHub asset link.'
}
$archive = Join-Path $downloadRoot 'steward-endpoint.zip'
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.IO.Compression.FileSystem
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $true
$handler.MaxAutomaticRedirections = 3
$client = [Net.Http.HttpClient]::new($handler)
try {
    $response = $client.GetAsync(
        $ReleaseAssetUrl,
        [Net.Http.HttpCompletionOption]::ResponseHeadersRead
    ).GetAwaiter().GetResult()
    [void]$response.EnsureSuccessStatusCode()
    if ($response.RequestMessage.RequestUri.Scheme -ne 'https' -or
        $response.RequestMessage.RequestUri.Host -ne
            'release-assets.githubusercontent.com') {
        throw 'Steward endpoint release download escaped the approved host.'
    }
    $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $output = [IO.File]::Open(
        $archive,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $buffer = [byte[]]::new(65536)
        $total = 0L
        while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt 134217728) {
                throw 'Steward endpoint release archive exceeds 128 MiB.'
            }
            $output.Write($buffer, 0, $read)
        }
        $output.Flush($true)
        if ($total -le 0) {
            throw 'Steward endpoint release archive is empty.'
        }
    } finally {
        $output.Dispose()
        $input.Dispose()
    }
} finally {
    $client.Dispose()
    $handler.Dispose()
}
$root = Join-Path $downloadRoot 'catalog'
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    $expectedFiles = @(
        'Steward.Endpoint.Msi.msi',
        'Steward.Endpoint.Msi.sigstore.json',
        'steward-endpoint.release.psd1')
    if ($zip.Entries.Count -ne $expectedFiles.Count) {
        throw 'Steward endpoint release archive contains unexpected entries.'
    }
    $observedFiles = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $expandedBytes = 0L
    foreach ($entry in $zip.Entries) {
        $externalAttributes = [uint32]$entry.ExternalAttributes
        $unixFileType = ($externalAttributes -shr 16) -band 0xF000
        $windowsAttributes = $externalAttributes -band 0xFFFF
        if ($entry.FullName -notin $expectedFiles -or
            $entry.FullName -ne $entry.Name -or
            -not $observedFiles.Add($entry.FullName) -or
            $unixFileType -eq 0xA000 -or
            ($windowsAttributes -band
                [uint32][IO.FileAttributes]::Directory) -ne 0 -or
            ($windowsAttributes -band
                [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $entry.Length -le 0 -or
            $entry.Length -gt 134217728) {
            throw 'Steward endpoint release archive entry is invalid.'
        }
        $expandedBytes += $entry.Length
    }
    if ($observedFiles.Count -ne $expectedFiles.Count -or
        @($expectedFiles | Where-Object {
            -not $observedFiles.Contains($_)
        }).Count -ne 0 -or
        $expandedBytes -gt 268435456) {
        throw 'Steward endpoint expanded release exceeds 256 MiB.'
    }
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    foreach ($entry in $zip.Entries) {
        $destination = Join-Path $root $entry.Name
        $input = $entry.Open()
        $output = [IO.File]::Open(
            $destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $input.CopyTo($output)
            $output.Flush($true)
        } finally {
            $output.Dispose()
            $input.Dispose()
        }
    }
} finally {
    $zip.Dispose()
}
$releasePath = Join-Path $root 'steward-endpoint.release.psd1'
if (-not (Test-Path -LiteralPath $releasePath -PathType Leaf)) {
    throw 'Steward endpoint CI release manifest is missing.'
}
$manifest = Import-PowerShellDataFile -LiteralPath $releasePath
if ($manifest.Version -ne 4 -or
    [string]::IsNullOrWhiteSpace($manifest.MsiFile) -or
    [string]::IsNullOrWhiteSpace($manifest.ProductVersion) -or
    $manifest.MsiSha256 -notmatch '^[0-9A-Fa-f]{64}$' -or
    $manifest.MsiLength -le 0 -or
    $manifest.MsiLength -gt 4294967296 -or
    $manifest.ProductCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or
    $manifest.UpgradeCode -ne
        '{37C34E0A-E245-48A4-B07C-78E2955A7E65}' -or
    $manifest.CatalogIdentity -notmatch
        '^steward-endpoint/[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' -or
    [string]::IsNullOrWhiteSpace($manifest.AttestationBundleFile) -or
    $manifest.SourceRepository -ne $SourceRepository -or
    $manifest.SourceCommit -notmatch '^[0-9A-Fa-f]{40}$' -or
    $manifest.SourceRef -ne $SourceRef -or
    $manifest.SignerWorkflow -ne $SignerWorkflow -or
    [string]::IsNullOrWhiteSpace($manifest.SourceRunId)) {
    throw 'Steward endpoint CI release manifest is invalid.'
}
$msi = Join-Path $root $manifest.MsiFile
if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) {
    throw 'Steward endpoint MSI is missing.'
}
$hash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash
if ((Get-Item -LiteralPath $msi).Length -ne $manifest.MsiLength) {
    throw 'Steward endpoint MSI size mismatch.'
}
if ($hash -ne $manifest.MsiSha256) {
    throw 'Steward endpoint MSI hash mismatch.'
}
$bundle = Join-Path $root $manifest.AttestationBundleFile
if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) {
    throw 'Steward endpoint GitHub attestation bundle is missing.'
}
$gh = Get-Command gh.exe -ErrorAction SilentlyContinue
if ($null -eq $gh) {
    throw 'GitHub CLI is required to verify Steward endpoint provenance.'
}
foreach ($subject in @(
    $releasePath,
    $msi)) {
    & $gh.Source attestation verify $subject `
        --bundle $bundle `
        --repo $SourceRepository `
        --signer-workflow $SignerWorkflow `
        --signer-digest $manifest.SourceCommit `
        --source-digest $manifest.SourceCommit `
        --source-ref $manifest.SourceRef `
        --deny-self-hosted-runners
    if ($LASTEXITCODE -ne 0) {
        throw 'Steward endpoint GitHub Actions provenance verification failed.'
    }
}
$provisioningRoot = Join-Path $downloadRoot 'provisioning'
New-Item -ItemType Directory -Path $provisioningRoot -Force | Out-Null
$bootstrapKey = Join-Path $provisioningRoot 'bootstrap-envelope.spki'
$controlKey = Join-Path $provisioningRoot 'control-signing.spki'
$config = Join-Path $provisioningRoot 'steward-endpoint.config.json'
$bootstrapBytes = [Convert]::FromBase64String(
    $BootstrapEncryptionPublicKeyBase64)
$controlBytes = [Convert]::FromBase64String(
    $ControlSigningPublicKeyBase64)
if ($bootstrapBytes.Length -notin 294, 422, 550 -or
    $controlBytes.Length -lt 80 -or $controlBytes.Length -gt 512) {
    throw 'Steward endpoint runtime trust key sizes are invalid.'
}
[IO.File]::WriteAllBytes($bootstrapKey, $bootstrapBytes)
[IO.File]::WriteAllBytes($controlKey, $controlBytes)
[ordered]@{
    version = 1
    productVersion = $manifest.ProductVersion
    bootstrapEncryptionPublicKey = 'bootstrap-envelope.spki'
    controlSigningPublicKey = 'control-signing.spki'
    controlIdentity = $ControlIdentity
    provisionedUserAccount = $NodeUserAccount
    provisionedUserSid = $NodeUserSid
} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding utf8
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($msi, 0)
function Get-MsiProperty([object]$Database, [string]$Name) {
    $propertyView = $Database.OpenView(
        "SELECT `Value` FROM `Property` WHERE `Property`='$Name'")
    [void]$propertyView.Execute()
    $propertyRecord = $propertyView.Fetch()
    if ($null -eq $propertyRecord) {
        throw "MSI property $Name is missing."
    }
    return $propertyRecord.StringData(1).Trim()
}
$version = Get-MsiProperty $database 'ProductVersion'
if ($version -ne $manifest.ProductVersion) {
    throw 'Steward endpoint MSI version mismatch.'
}
$productCode = Get-MsiProperty $database 'ProductCode'
$upgradeCode = Get-MsiProperty $database 'UpgradeCode'
if ($productCode -ne $manifest.ProductCode -or
    $upgradeCode -ne $manifest.UpgradeCode) {
    throw 'Steward endpoint MSI identity mismatch.'
}
$wasCurrentInstalled = $installer.ProductState($productCode) -eq 5
$relatedProducts = @($installer.RelatedProducts($upgradeCode))
if ($ValidateOnly) {
    Write-Output 'STEWARD_ENDPOINT_VALIDATION_PASSED'
    return
}
$attestationDirectory = Join-Path $env:ProgramData 'Steward\install'
$attestationData = [ordered]@{
    version = 1
    productVersion = $version
    msiSha256 = $hash
    sourceRepository = $manifest.SourceRepository
    sourceCommit = $manifest.SourceCommit
    sourceRef = $manifest.SourceRef
    signerWorkflow = $manifest.SignerWorkflow
    sourceRunId = $manifest.SourceRunId
    productCode = $productCode
    configSha256 = (Get-FileHash $config -Algorithm SHA256).Hash
    bootstrapEncryptionPublicKeySha256 =
        (Get-FileHash $bootstrapKey -Algorithm SHA256).Hash
    controlSigningPublicKeySha256 =
        (Get-FileHash $controlKey -Algorithm SHA256).Hash
    controlIdentity = $ControlIdentity
}
function Write-ArtifactAttestation([string]$Path) {
    New-Item -ItemType Directory -Path $attestationDirectory -Force | Out-Null
    $attestationData | ConvertTo-Json |
        Set-Content -LiteralPath $Path -Encoding utf8
    & icacls.exe $Path /inheritance:r /grant:r `
        '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Steward endpoint artifact attestation ACL failed.'
    }
}
$state = Join-Path $env:ProgramData 'Steward\Endpoint'
if ($wasCurrentInstalled) {
    $receiptPath = Join-Path $state 'bootstrap-receipt.json'
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
        throw 'The installed Steward signed receipt is missing.'
    }
    $committedReceipt = Get-Content -LiteralPath $receiptPath -Raw |
        ConvertFrom-Json
    foreach ($claim in $attestationData.Keys) {
        if ($committedReceipt.body.$claim -ne $attestationData[$claim]) {
            throw 'The installed Steward artifact differs from the incoming same-version artifact.'
        }
    }
    $installedProvisioner = Join-Path $env:ProgramFiles `
        'Steward\Steward.Endpoint.Provisioner.exe'
    if (Test-Path -LiteralPath $installedProvisioner -PathType Leaf) {
        $healthAttestation = Join-Path $attestationDirectory (
            'steward-endpoint.health-' +
            [guid]::NewGuid().ToString('N') + '.json')
        try {
            Write-ArtifactAttestation $healthAttestation
            & $installedProvisioner `
                --verify-installed `
                --install-root (Split-Path -Parent $installedProvisioner) `
                --config $config `
                --state-root $state `
                --maintenance-state-root (
                    Join-Path $env:ProgramData 'Steward\Maintenance') `
                --artifact-attestation $healthAttestation
            if ($LASTEXITCODE -eq 0) {
                Write-Output 'STEWARD_ENDPOINT_MSI_HEALTHY_NOOP'
                return
            }
        } finally {
            Remove-Item -LiteralPath $healthAttestation -Force `
                -ErrorAction SilentlyContinue
        }
    }
}
foreach ($related in $relatedProducts) {
    if ($related -ne $productCode -and
        $installer.ProductState($related) -eq 5 -and
        $installer.ProductInfo($related, 'VersionString') -eq $version) {
        throw 'A different Steward MSI with the same version is installed.'
    }
}
$provisionAttestation = Join-Path $downloadRoot `
    'steward-endpoint.attestation.json'
Write-ArtifactAttestation $provisionAttestation
$msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$log = Join-Path $env:ProgramData `
    'Steward\install\steward-endpoint-msi.log'
$installArguments = @(
    '/i', $msi,
    '/qn',
    '/norestart',
    '/L*v', $log,
    "STEWARD_CONFIG=$config",
    "STEWARD_ATTESTATION=$provisionAttestation")
& $msiexec @installArguments
$installExitCode = $LASTEXITCODE
if ($installExitCode -notin 0, 1641, 3010) {
    throw (
        "Steward endpoint MSI failed with exit code $installExitCode; " +
        'Windows Installer failed activation rollback.')
}
if ($installer.ProductState($productCode) -ne 5 -or
    $installer.ProductInfo($productCode, 'VersionString') -ne $version) {
    throw 'Steward endpoint MSI did not commit the requested product identity.'
}
$service = Get-CimInstance Win32_Service `
    -Filter "Name='StewardMaintenance'" -ErrorAction SilentlyContinue
if ($null -eq $service -or
    $service.StartName -ne 'LocalSystem' -or
    $service.StartMode -ne 'Auto' -or
    $service.State -ne 'Running') {
    throw 'Steward LocalSystem maintenance service did not start.'
}
$installedProvisioner = Join-Path $env:ProgramFiles `
    'Steward\Steward.Endpoint.Provisioner.exe'
& $installedProvisioner `
    --verify-installed `
    --install-root (Split-Path -Parent $installedProvisioner) `
    --config $config `
    --state-root $state `
    --maintenance-state-root (
        Join-Path $env:ProgramData 'Steward\Maintenance') `
    --artifact-attestation $provisionAttestation
if ($LASTEXITCODE -ne 0) {
    throw 'Steward endpoint MSI committed without a healthy provisioner state.'
}
Write-Output 'STEWARD_ENDPOINT_MSI_INSTALLED'} catch {
    Write-Error (
        "Steward endpoint bootstrap failed at line " +
        "$($_.InvocationInfo.ScriptLineNumber):" +
        "$($_.Exception.GetType().Name):$($_.Exception.Message)")
    throw
} finally {
    Remove-Item -LiteralPath $downloadRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
}
