$ErrorActionPreference = 'Stop'

$project = Join-Path $PSScriptRoot 'JobObjectSpike.csproj'
dotnet build $project --nologo --verbosity quiet
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$dll = Join-Path $PSScriptRoot 'bin\Debug\net8.0\JobObjectSpike.dll'
$scratch = Join-Path $PSScriptRoot 'artifacts'
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

function Start-Creator([string] $suffix) {
    $output = Join-Path $scratch "creator-$suffix.out"
    $errorOutput = Join-Path $scratch "creator-$suffix.err"
    Remove-Item $output, $errorOutput -ErrorAction SilentlyContinue

    $process = Start-Process dotnet `
        -ArgumentList @($dll, 'create') `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $output `
        -RedirectStandardError $errorOutput
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw (Get-Content $errorOutput -Raw)
    }

    return (Get-Content $output -Raw).Trim()
}

Write-Host 'Case 1: creator closes the only user handle'
$childPid = Start-Creator 'no-keeper'
$openOutput = & dotnet $dll open $childPid 2>&1
$openExit = $LASTEXITCODE
if ($openExit -eq 0) {
    & dotnet $dll terminate
    throw 'Expected OpenJobObject to fail without a retained handle.'
}
Write-Host "Open failed as expected: $openOutput"
& dotnet $dll kill $childPid

Write-Host 'Case 2: an independent process retains a handle'
$pidFile = Join-Path $scratch 'child.pid'
$releaseFile = Join-Path $scratch 'creator.release'
$readyFile = Join-Path $scratch 'holder.ready'
$stopFile = Join-Path $scratch 'holder.stop'
$creatorOutput = Join-Path $scratch 'creator-with-keeper.out'
$creatorError = Join-Path $scratch 'creator-with-keeper.err'
$holderOutput = Join-Path $scratch 'holder.out'
$holderError = Join-Path $scratch 'holder.err'
Remove-Item $pidFile, $releaseFile, $readyFile, $stopFile,
    $creatorOutput, $creatorError, $holderOutput, $holderError `
    -ErrorAction SilentlyContinue

$creator = Start-Process dotnet `
    -ArgumentList @($dll, 'create-wait', $pidFile, $releaseFile) `
    -NoNewWindow `
    -PassThru `
    -RedirectStandardOutput $creatorOutput `
    -RedirectStandardError $creatorError
if (-not [System.Threading.SpinWait]::SpinUntil(
    { Test-Path $pidFile },
    10000)) {
    throw 'Creator did not publish the child PID.'
}

$childPid = (Get-Content $pidFile -Raw).Trim()
$holder = Start-Process dotnet `
    -ArgumentList @($dll, 'hold', $readyFile, $stopFile) `
    -NoNewWindow `
    -PassThru `
    -RedirectStandardOutput $holderOutput `
    -RedirectStandardError $holderError
if (-not [System.Threading.SpinWait]::SpinUntil(
    { Test-Path $readyFile },
    10000)) {
    throw (Get-Content $holderError -Raw)
}

Set-Content -Path $releaseFile -Value 'release'
$creator.WaitForExit()
if ($creator.ExitCode -ne 0) {
    throw (Get-Content $creatorError -Raw)
}

& dotnet $dll open $childPid
if ($LASTEXITCODE -ne 0) {
    throw 'Expected the named Job Object to remain reopenable.'
}
& dotnet $dll terminate
Set-Content -Path $stopFile -Value 'stop'
$holder.WaitForExit()
if ($holder.ExitCode -ne 0) {
    throw (Get-Content $holderError -Raw)
}

Write-Host 'Both continuity cases behaved as expected.'
