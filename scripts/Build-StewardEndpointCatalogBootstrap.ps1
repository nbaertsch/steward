param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRepository,
    [Parameter(Mandatory = $true)]
    [string]$SourceCommit,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [switch]$TestBuild
)

$ErrorActionPreference = 'Stop'
if ($SourceRepository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw 'Approved source repository must use owner/name form.'
}
if ($SourceCommit -notmatch '^[0-9A-Fa-f]{40}$') {
    throw 'Immutable catalog source commit must be a full Git commit.'
}
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'catalog\devbox\steward-endpoint'
$output = [IO.Path]::GetFullPath($OutputDirectory)
Remove-Item -LiteralPath $output -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $output -Force | Out-Null
$workflow = "$SourceRepository/.github/workflows/release-endpoint.yml"
$installerSource = Join-Path $source 'Install-Steward.ps1'
$installerTemplate = Get-Content -LiteralPath $installerSource -Raw
$installer = $installerTemplate.Replace(
    '__STEWARD_APPROVED_SOURCE_REPOSITORY__',
    $SourceRepository).Replace(
    '__STEWARD_APPROVED_SIGNER_WORKFLOW__',
    $workflow)
if ($installer.Contains('__STEWARD_APPROVED_SOURCE_REPOSITORY__') -or
    $installer.Contains('__STEWARD_APPROVED_SIGNER_WORKFLOW__')) {
    throw 'Catalog bootstrap provenance placeholders were not resolved.'
}
Set-Content -LiteralPath (Join-Path $output 'Install-Steward.ps1') `
    -Value $installer -Encoding utf8
Copy-Item -LiteralPath (Join-Path $source 'task.yaml') `
    -Destination (Join-Path $output 'task.yaml')

$installerUri =
    "https://raw.githubusercontent.com/$SourceRepository/$SourceCommit/" +
    'catalog/devbox/steward-endpoint/Install-Steward.ps1'
if ($TestBuild) {
    $installerHash = (Get-FileHash -LiteralPath $installerSource `
        -Algorithm SHA256).Hash
} else {
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(2)
    try {
        $uri = [uri]$installerUri
        $response = $client.GetAsync(
            $uri,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()
        try {
            [void]$response.EnsureSuccessStatusCode()
            if ($response.RequestMessage.RequestUri -ne $uri -or
                $response.Content.Headers.ContentLength -gt 1048576) {
                throw 'Immutable catalog installer source redirected or exceeded its bound.'
            }
            $stream = $response.Content.ReadAsStreamAsync().
                GetAwaiter().GetResult()
            try {
                $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
                    [Security.Cryptography.HashAlgorithmName]::SHA256)
                try {
                    $buffer = [byte[]]::new(65536)
                    $total = 0L
                    while (($read = $stream.Read(
                            $buffer, 0, $buffer.Length)) -gt 0) {
                        $total += $read
                        if ($total -gt 1048576) {
                            throw 'Immutable catalog installer source exceeded its bound.'
                        }
                        $hash.AppendData($buffer, 0, $read)
                    }
                    if ($total -le 0) {
                        throw 'Immutable catalog installer source was empty.'
                    }
                    $installerHash = [Convert]::ToHexString(
                        $hash.GetHashAndReset())
                } finally {
                    $hash.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}
$dsc = (Get-Content -LiteralPath (
    Join-Path $source 'steward-endpoint.dsc.yaml') -Raw).
    Replace('__STEWARD_INSTALLER_URI__', $installerUri).
    Replace('__STEWARD_INSTALLER_SHA256__', $installerHash).
    Replace('__STEWARD_SOURCE_REPOSITORY__', $SourceRepository).
    Replace('__STEWARD_SIGNER_WORKFLOW__', $workflow)
foreach ($placeholder in @(
    '__STEWARD_INSTALLER_URI__',
    '__STEWARD_INSTALLER_SHA256__',
    '__STEWARD_SOURCE_REPOSITORY__',
    '__STEWARD_SIGNER_WORKFLOW__')) {
    if ($dsc.Contains($placeholder)) {
        throw "Catalog DSC immutable source placeholder was not resolved: $placeholder"
    }
}
Set-Content -LiteralPath (Join-Path $output 'steward-endpoint.dsc.yaml') `
    -Value $dsc -Encoding utf8
Write-Output $output

