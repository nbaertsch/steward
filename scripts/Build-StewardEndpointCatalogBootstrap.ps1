param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRepository,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
if ($SourceRepository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw 'Approved source repository must use owner/name form.'
}
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'catalog\devbox\steward-endpoint'
$output = [IO.Path]::GetFullPath($OutputDirectory)
Remove-Item -LiteralPath $output -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $output -Force | Out-Null
$workflow = "$SourceRepository/.github/workflows/release-endpoint.yml"
$installer = Get-Content -LiteralPath (
    Join-Path $source 'Install-Steward.ps1') -Raw
$installer = $installer.Replace(
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
Write-Output $output
