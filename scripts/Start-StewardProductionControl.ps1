param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "Programs\Steward"),
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA "Steward\control"),
    [int]$ControlPort = 5112,
    [string]$DevCenterEndpoint =
        "https://72f988bf-86f1-41af-91ab-2d7cd011db47-devcenter-rt3pumrdz6yc6-dc.westus3.devcenter.azure.com/"
)

$ErrorActionPreference = "Stop"

$controlRoot = Join-Path $InstallRoot "Steward.Control"
$control = Join-Path $controlRoot "Steward.Control.exe"
$authority = Join-Path $env:LOCALAPPDATA "Steward\keys\devbox-operation-hmac.key"
$pidPath = Join-Path $DataRoot "control.pid"
$healthUri = "http://127.0.0.1:$ControlPort/health"
$databasePath = Join-Path $DataRoot "control.db"
$sessionTokenPath = Join-Path $DataRoot "control.session"
$schedulerDatabasePath = Join-Path $DataRoot "scheduler.db"
$rateDatabasePath = Join-Path $DataRoot "rates.db"
$portableStateRoot = Join-Path $DataRoot "objects"
$credentialVaultRoot = Join-Path $DataRoot "credentials"
$controlPrivateKeyPath = Join-Path $env:LOCALAPPDATA `
    "Steward\keys\control-private.pem"
$operationKeyEnvironmentVariable =
    "STEWARD_DEVBOX_OPERATION_HMAC_KEY"

try {
    $health = Invoke-RestMethod -Uri $healthUri -TimeoutSec 2
    if ($health.healthy -eq $true) {
        return
    }
} catch {
}

if (-not (Test-Path -LiteralPath $control) -or
    -not (Test-Path -LiteralPath $authority) -or
    -not (Test-Path -LiteralPath $controlPrivateKeyPath)) {
    throw "The Steward Control installation or provider authority is unavailable."
}

New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null
$authorityBytes = [IO.File]::ReadAllBytes($authority)
try {
    if ($authorityBytes.Length -lt 32) {
        throw "The Steward provider authority is invalid."
    }
    $env:STEWARD_DEVBOX_OPERATION_HMAC_KEY =
        [Convert]::ToBase64String($authorityBytes)
    $process = Start-Process `
        -FilePath $control `
        -ArgumentList @(
            "--urls", "http://127.0.0.1:$ControlPort",
            "--Control:DatabasePath", $databasePath,
            "--Control:LocalSessionTokenPath", $sessionTokenPath,
            "--Control:Orchestration:SchedulerDatabasePath",
                $schedulerDatabasePath,
            "--Control:Orchestration:GlobalRateDatabasePath",
                $rateDatabasePath,
            "--Steward:LocalStack:DataRoot", $DataRoot,
            "--Steward:LocalStack:PortableStateRoot",
                $portableStateRoot,
            "--Steward:LocalStack:CredentialVaultRoot",
                $credentialVaultRoot,
            "--Steward:LocalStack:TransportEnabled", "true",
            "--Steward:LocalStack:TransportIdentity", "control",
            "--Steward:LocalStack:TransportPrivateKeyPemPath",
                $controlPrivateKeyPath,
            "--Steward:LocalStack:RdpDvcControlCarrierEnabled", "true",
            "--Steward:LocalStack:RdpDvcControlCarrierPipeName",
                "Steward.Control.RdpDvc.v2",
            "--Steward:LocalStack:DevBox:Enabled", "true",
            "--Steward:LocalStack:DevBox:Endpoint", $DevCenterEndpoint,
            "--Steward:LocalStack:DevBox:OperationHandleHmacKeyEnvironmentVariable",
                $operationKeyEnvironmentVariable
        ) `
        -WorkingDirectory $controlRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $DataRoot "control.out.log") `
        -RedirectStandardError (Join-Path $DataRoot "control.err.log") `
        -PassThru
} finally {
    Remove-Item Env:STEWARD_DEVBOX_OPERATION_HMAC_KEY `
        -ErrorAction SilentlyContinue
    [Security.Cryptography.CryptographicOperations]::ZeroMemory(
        $authorityBytes)
}

for ($attempt = 0; $attempt -lt 40; $attempt++) {
    if ($process.HasExited) {
        throw "Steward Control exited during startup."
    }
    try {
        $health = Invoke-RestMethod -Uri $healthUri -TimeoutSec 2
        if ($health.healthy -eq $true) {
            [pscustomobject]@{
                ProcessId = $process.Id
                ExecutablePath = [IO.Path]::GetFullPath($control)
                StartTimeUtc =
                    $process.StartTime.ToUniversalTime().ToString("O")
            } | ConvertTo-Json |
                Set-Content -LiteralPath $pidPath -Encoding utf8
            return
        }
    } catch {
    }
    Start-Sleep -Milliseconds 500
}

throw "Steward Control did not become healthy."
