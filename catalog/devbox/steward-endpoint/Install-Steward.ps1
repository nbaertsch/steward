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
    [string]$AdministrativeRoot,
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
$downloadRoot = Join-Path $env:ProgramData (
    'Steward\install\download-' + [guid]::NewGuid().ToString('N'))
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
if ($manifest.Version -ne 3 -or
    [string]::IsNullOrWhiteSpace($manifest.MsiFile) -or
    [string]::IsNullOrWhiteSpace($manifest.ProductVersion) -or
    $manifest.MsiSha256 -notmatch '^[0-9A-Fa-f]{64}$' -or
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
if ($wasCurrentInstalled -and
    [string]::IsNullOrWhiteSpace($AdministrativeRoot)) {
    $state = Join-Path $env:ProgramData 'Steward\Endpoint'
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
    $installedProvisioner = Join-Path (
        Join-Path $env:ProgramFiles 'Steward') `
        'Steward.Endpoint.Provisioner.exe'
    if (Test-Path -LiteralPath $installedProvisioner -PathType Leaf) {
        $healthAttestation = Join-Path $attestationDirectory (
            'steward-endpoint.health-' +
            [guid]::NewGuid().ToString('N') + '.json')
        Write-ArtifactAttestation $healthAttestation
        $healthArguments = @(
            '--install-root', (Split-Path -Parent $installedProvisioner),
            '--config', $config,
            '--state-root', $state,
            '--artifact-attestation', $healthAttestation)
        & $installedProvisioner @healthArguments
        $healthExitCode = $LASTEXITCODE
        Remove-Item -LiteralPath $healthAttestation -Force
        if ($healthExitCode -eq 0) {
            Write-Output 'STEWARD_ENDPOINT_MSI_HEALTHY_NOOP'
            return
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
$rollbackDirectory = Join-Path $downloadRoot 'rollback'
New-Item -ItemType Directory -Path $rollbackDirectory -Force | Out-Null
& icacls.exe $rollbackDirectory /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Steward endpoint rollback directory ACL failed.'
}
$previousPackages = @()
$currentPackage = $null
if ($wasCurrentInstalled) {
    $localPackage = $installer.ProductInfo($productCode, 'LocalPackage')
    if (-not (Test-Path -LiteralPath $localPackage -PathType Leaf)) {
        throw 'The installed Steward MSI cache is unavailable for repair.'
    }
    $backupPackage = Join-Path $rollbackDirectory (
        $productCode.Trim('{}') + '.msi')
    Copy-Item -LiteralPath $localPackage -Destination $backupPackage
    if ((Get-FileHash -LiteralPath $localPackage -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $backupPackage -Algorithm SHA256).Hash) {
        throw 'The installed Steward MSI backup failed verification.'
    }
    $currentPackage = [pscustomobject]@{
        productCode = $productCode
        productVersion = $version
        package = $backupPackage
    }
}
foreach ($related in $relatedProducts) {
    if ($related -eq $productCode) {
        continue
    }
    $localPackage = $installer.ProductInfo($related, 'LocalPackage')
    if (-not (Test-Path -LiteralPath $localPackage -PathType Leaf)) {
        throw "Prior Steward MSI cache is unavailable for $related."
    }
    $backupPackage = Join-Path $rollbackDirectory (
        $related.Trim('{}') + '.msi')
    Copy-Item -LiteralPath $localPackage -Destination $backupPackage
    if ((Get-FileHash -LiteralPath $localPackage -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $backupPackage -Algorithm SHA256).Hash) {
        throw "Prior Steward MSI backup failed verification for $related."
    }
    $previousPackages += [pscustomobject]@{
        productCode = $related
        productVersion = $installer.ProductInfo($related, 'VersionString')
        package = $backupPackage
    }
}
$preMsiTaskSnapshot = $null
$msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$logRelativePath = if (
    [string]::IsNullOrWhiteSpace($AdministrativeRoot)) {
    'Steward\install\steward-endpoint-msi.log'
} else {
    'Steward\install\steward-endpoint-admin-' +
    [guid]::NewGuid().ToString('N') + '.log'
}
$log = Join-Path $env:ProgramData $logRelativePath
New-Item -ItemType Directory -Path (Split-Path -Parent $log) -Force | Out-Null
$administrativeStateRoot = Join-Path $env:ProgramData `
    'Steward\install\Endpoint'
if (-not [string]::IsNullOrWhiteSpace($AdministrativeRoot) -and
    -not (Test-Path -LiteralPath $administrativeStateRoot) -and
    (Test-Path -LiteralPath (
        Join-Path $env:ProgramData 'Steward\Endpoint') -PathType Container)) {
    throw (
        'Legacy Steward endpoint state exists outside the durable root; ' +
        'automatic secret-bearing state migration is not permitted.')
}
$selectedStateRoot = if (
    [string]::IsNullOrWhiteSpace($AdministrativeRoot)) {
    Join-Path $env:ProgramData 'Steward\Endpoint'
} else {
    $administrativeStateRoot
}
$identityPath = Join-Path $selectedStateRoot 'identity.json'
if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
    $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
    if ($identity.hostId -notmatch '^[0-9A-Fa-f-]{36}$') {
        throw 'Installed Steward endpoint identity is invalid.'
    }
    $keeperName = 'HandleKeeper-' + ([guid]$identity.hostId).ToString('N')
    $serverName = 'RdpDvcEndpoint-' + ([guid]$identity.hostId).ToString('N')
    $keeperTask = Get-ScheduledTask -TaskName $keeperName `
        -TaskPath '\Steward\' -ErrorAction SilentlyContinue
    $serverTask = Get-ScheduledTask -TaskName $serverName `
        -TaskPath '\Steward\' -ErrorAction SilentlyContinue
    $preMsiTaskSnapshot = [pscustomobject]@{
        keeperName = $keeperName
        keeperXml = if ($null -ne $keeperTask) {
            Export-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\'
        } else { $null }
        keeperRunning = $null -ne $keeperTask -and
            $keeperTask.State -eq 'Running'
        serverName = $serverName
        serverXml = if ($null -ne $serverTask) {
            Export-ScheduledTask -TaskName $serverName -TaskPath '\Steward\'
        } else { $null }
        serverRunning = $null -ne $serverTask -and
            $serverTask.State -eq 'Running'
    }
    foreach ($name in $keeperName, $serverName) {
        Stop-ScheduledTask -TaskName $name -TaskPath '\Steward\' `
            -ErrorAction SilentlyContinue
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $running = @(@($keeperName, $serverName) | Where-Object {
            (Get-ScheduledTask -TaskName $_ -TaskPath '\Steward\' `
                -ErrorAction SilentlyContinue).State -eq 'Running'
        }).Count
        if ($running -gt 0) {
            Start-Sleep -Milliseconds 250
        }
    } until ($running -eq 0 -or [DateTime]::UtcNow -ge $deadline)
    if ($running -ne 0) {
        if ($preMsiTaskSnapshot.keeperRunning) {
            Start-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\'
        }
        if ($preMsiTaskSnapshot.serverRunning) {
            Start-ScheduledTask -TaskName $serverName -TaskPath '\Steward\'
        }
        Remove-Item -LiteralPath $rollbackDirectory -Recurse -Force
        throw 'Installed Steward endpoint tasks did not quiesce.'
    }
}
function Restore-PreMsiTasks {
    if ($null -eq $preMsiTaskSnapshot) {
        return
    }
    foreach ($task in @(
        @(
            $preMsiTaskSnapshot.keeperName,
            $preMsiTaskSnapshot.keeperXml,
            $preMsiTaskSnapshot.keeperRunning),
        @(
            $preMsiTaskSnapshot.serverName,
            $preMsiTaskSnapshot.serverXml,
            $preMsiTaskSnapshot.serverRunning))) {
        Unregister-ScheduledTask -TaskName $task[0] -TaskPath '\Steward\' `
            -Confirm:$false -ErrorAction SilentlyContinue
        if ($null -ne $task[1]) {
            Register-ScheduledTask -TaskName $task[0] -TaskPath '\Steward\' `
                -Xml $task[1] -Force | Out-Null
            if ($task[2]) {
                Start-ScheduledTask -TaskName $task[0] -TaskPath '\Steward\'
            }
        }
    }
}
$provisionAttestation = Join-Path $rollbackDirectory `
    'steward-endpoint.attestation.json'
Write-ArtifactAttestation $provisionAttestation
$administrativeRootFull = $null
$administrativeStaging = $null
$administrativeBackup = $null
$administrativePromoted = $false
$administrativeCommitted = $false
$replacementCommitted = $false
try {
try {
    $installArguments = @(
        '/qn',
        '/norestart',
        '/L*v', $log,
        "STEWARD_CONFIG=$config",
        "STEWARD_ATTESTATION=$provisionAttestation")
    if ([string]::IsNullOrWhiteSpace($AdministrativeRoot)) {
        $installArguments = @('/i', $msi) + $installArguments
    } else {
        $administrativeRootFull = [IO.Path]::GetFullPath(
            $AdministrativeRoot)
        $allowedRoot = [IO.Path]::GetFullPath(
            (Join-Path $env:ProgramData 'Steward\install\Runtime'))
        if (-not [string]::Equals(
                [IO.Path]::GetDirectoryName($administrativeRootFull),
                $allowedRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Steward administrative root is outside the runtime root.'
        }
        New-Item -ItemType Directory -Path $allowedRoot -Force | Out-Null
        $runtimeItem = Get-Item -LiteralPath $allowedRoot -Force
        if (($runtimeItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Steward runtime root cannot be a reparse point.'
        }
        $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $administratorsSid =
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        function Protect-AdministrativeDirectory([string]$Path) {
            $item = Get-Item -LiteralPath $Path -Force
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Steward administrative directory cannot be a reparse point.'
            }
            $security = [Security.AccessControl.DirectorySecurity]::new()
            $security.SetAccessRuleProtection($true, $false)
            $security.SetOwner($systemSid)
            foreach ($sid in @($systemSid, $administratorsSid)) {
                $security.AddAccessRule(
                    [Security.AccessControl.FileSystemAccessRule]::new(
                        $sid,
                        [Security.AccessControl.FileSystemRights]::FullControl,
                        [Security.AccessControl.InheritanceFlags]::ContainerInherit `
                            -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
                        [Security.AccessControl.PropagationFlags]::None,
                        [Security.AccessControl.AccessControlType]::Allow))
            }
            Set-Acl -LiteralPath $Path -AclObject $security
        }
        Protect-AdministrativeDirectory $allowedRoot
        if (Test-Path -LiteralPath $administrativeRootFull) {
            $existingItem = Get-Item -LiteralPath $administrativeRootFull -Force
            if (($existingItem.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Steward administrative image cannot be a reparse point.'
            }
        }
        $administrativeStaging = Join-Path $allowedRoot (
            '.staging-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $administrativeStaging | Out-Null
        Protect-AdministrativeDirectory $administrativeStaging
        $expectedAdministrativeProvisioner = Join-Path `
            $administrativeStaging `
            'PFiles64\Steward\Steward.Endpoint.Provisioner.exe'
        $installArguments = @(
            '/a', $msi, "TARGETDIR=$administrativeStaging") +
            $installArguments
    }
    & $msiexec @installArguments
    $installExitCode = $LASTEXITCODE
} catch {
    Restore-PreMsiTasks
    throw
}
if ($installExitCode -notin 0, 1641, 3010) {
    $rollbackFailures = [Collections.Generic.List[string]]::new()
    if (-not $wasCurrentInstalled -and
        $installer.ProductState($productCode) -eq 5) {
        & $msiexec @('/x', $productCode, '/qn', '/norestart')
        $removeExitCode = $LASTEXITCODE
        if ($removeExitCode -notin 0, 1605, 1614, 1641, 3010) {
            $rollbackFailures.Add(
                "failed MSI cleanup exited $removeExitCode")
        }
    }
    if ($wasCurrentInstalled -and
        $installer.ProductState($productCode) -ne 5) {
        & $msiexec @(
            '/i', $currentPackage.package, '/qn', '/norestart')
        $restoreExitCode = $LASTEXITCODE
        if ($restoreExitCode -notin 0, 1641, 3010) {
            $rollbackFailures.Add(
                "current MSI restore exited $restoreExitCode")
        }
    }
    foreach ($previousPackage in $previousPackages) {
        if ($installer.ProductState($previousPackage.productCode) -ne 5) {
            & $msiexec @(
                '/i', $previousPackage.package, '/qn', '/norestart')
            $restoreExitCode = $LASTEXITCODE
            if ($restoreExitCode -notin 0, 1641, 3010) {
                $rollbackFailures.Add(
                    "prior MSI restore exited $restoreExitCode")
                continue
            }
        }
        if ($installer.ProductState($previousPackage.productCode) -ne 5 -or
            $installer.ProductInfo(
                $previousPackage.productCode,
                'VersionString') -ne $previousPackage.productVersion) {
            $rollbackFailures.Add(
                "prior MSI $($previousPackage.productCode) was not restored")
        }
    }
    Restore-PreMsiTasks
    if ($rollbackFailures.Count -gt 0) {
        throw (
            "Steward endpoint MSI failed with exit code $installExitCode; " +
            'rollback could not restore the previous MSI: ' +
            ($rollbackFailures -join '; '))
    }
    if ($wasCurrentInstalled -and (
        $installer.ProductState($productCode) -ne 5 -or
        $installer.ProductInfo($productCode, 'VersionString') -ne $version)) {
        throw 'Steward endpoint failed repair did not preserve the installed MSI.'
    }
    Remove-Item -LiteralPath $rollbackDirectory -Recurse -Force
    throw "Steward endpoint MSI failed with exit code $installExitCode."
}
if (-not [string]::IsNullOrWhiteSpace($AdministrativeRoot)) {
    $administrativeDeadline = [DateTime]::UtcNow.AddMinutes(2)
    do {
        $administrativeLogComplete =
            (Test-Path -LiteralPath $log -PathType Leaf) -and
            (Select-String -LiteralPath $log `
                -SimpleMatch 'Installation completed successfully.' `
                -Quiet)
        if (-not $administrativeLogComplete -or
            -not (Test-Path -LiteralPath `
                $expectedAdministrativeProvisioner -PathType Leaf)) {
            Start-Sleep -Milliseconds 250
        }
    } until (($administrativeLogComplete -and
        (Test-Path -LiteralPath $expectedAdministrativeProvisioner `
            -PathType Leaf)) -or
        [DateTime]::UtcNow -ge $administrativeDeadline)
    if (-not $administrativeLogComplete -or
        -not (Test-Path -LiteralPath $expectedAdministrativeProvisioner `
            -PathType Leaf)) {
        throw 'Steward administrative image did not finish materializing.'
    }
    $relativeProvisioner = Join-Path 'PFiles64\Steward' `
        'Steward.Endpoint.Provisioner.exe'
    $stagedProvisioner = $expectedAdministrativeProvisioner
    if (-not (Test-Path -LiteralPath $stagedProvisioner -PathType Leaf)) {
        throw 'Steward administrative image has an invalid provisioner layout.'
    }
    if (((Get-Item -LiteralPath $stagedProvisioner).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Steward administrative provisioner cannot be a reparse point.'
    }
    if (Test-Path -LiteralPath $administrativeRootFull) {
        $administrativeBackup = Join-Path $allowedRoot (
            '.backup-' + [guid]::NewGuid().ToString('N'))
        Move-Item -LiteralPath $administrativeRootFull `
            -Destination $administrativeBackup
    }
    Move-Item -LiteralPath $administrativeStaging `
        -Destination $administrativeRootFull
    $administrativeStaging = $null
    $administrativePromoted = $true
    $administrativeProvisioner = Join-Path $administrativeRootFull `
        $relativeProvisioner
    $stateRoot = $administrativeStateRoot
    $provisionArguments = @(
        '--install-root', (Split-Path -Parent $administrativeProvisioner),
        '--config', $config,
        '--state-root', $stateRoot,
        '--artifact-attestation', $provisionAttestation)
    & $administrativeProvisioner @provisionArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Steward administrative image provisioning failed.'
    }
    $administrativeCommitted = $true
    if ($null -ne $administrativeBackup) {
        try {
            Remove-Item -LiteralPath $administrativeBackup -Recurse -Force
            $administrativeBackup = $null
        } catch {
            Write-Warning (
                'Steward administrative backup cleanup failed; ' +
                "the committed image remains active: $administrativeBackup")
        }
    }
}
$replacementCommitted = $true
Remove-Item -LiteralPath $rollbackDirectory -Recurse -Force
$successMessage = if ([string]::IsNullOrWhiteSpace($AdministrativeRoot)) {
    'STEWARD_ENDPOINT_MSI_INSTALLED'
} else {
    'STEWARD_ENDPOINT_ADMINISTRATIVE_IMAGE_PROVISIONED'
}
Write-Output $successMessage
} finally {
    $rollbackFailures = [Collections.Generic.List[string]]::new()
    if (-not $administrativeCommitted) {
        if ($administrativePromoted -and
            $null -ne $administrativeRootFull -and
            (Test-Path -LiteralPath $administrativeRootFull)) {
            try {
                Remove-Item -LiteralPath $administrativeRootFull `
                    -Recurse -Force
            } catch {
                $rollbackFailures.Add(
                    "failed to remove promoted image: $($_.Exception.Message)")
            }
        }
        if ($null -ne $administrativeBackup -and
            (Test-Path -LiteralPath $administrativeBackup)) {
            if (Test-Path -LiteralPath $administrativeRootFull) {
                $rollbackFailures.Add(
                    'cannot restore backup while promoted image remains')
            } else {
                try {
                    Move-Item -LiteralPath $administrativeBackup `
                        -Destination $administrativeRootFull
                } catch {
                    $rollbackFailures.Add(
                        "failed to restore backup: $($_.Exception.Message)")
                }
            }
        }
        if ($null -ne $administrativeStaging -and
            (Test-Path -LiteralPath $administrativeStaging)) {
            try {
                Remove-Item -LiteralPath $administrativeStaging `
                    -Recurse -Force
            } catch {
                $rollbackFailures.Add(
                    "failed to remove staging image: $($_.Exception.Message)")
            }
        }
    }
    if (-not $replacementCommitted) {
        try {
            Restore-PreMsiTasks
        } catch {
            $rollbackFailures.Add(
                "failed to restore scheduled tasks: $($_.Exception.Message)")
        }
    }
    if ($rollbackFailures.Count -gt 0) {
        throw (
            'Steward endpoint rollback failed: ' +
            ($rollbackFailures -join '; '))
    }
}
} catch {
    Write-Error (
        "Steward endpoint bootstrap failed at line " +
        "$($_.InvocationInfo.ScriptLineNumber):" +
        "$($_.Exception.GetType().Name):$($_.Exception.Message)")
    throw
} finally {
    Remove-Item -LiteralPath $downloadRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
}
