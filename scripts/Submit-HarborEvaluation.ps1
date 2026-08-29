<#
.SYNOPSIS
    Submits Harbor/Incalmo evaluation tasks to Steward Control as a single
    sharded evaluation Workload across a Dev Box Pool.

.DESCRIPTION
    Reads the harbor task YAMLs from proprietary_saber, constructs the
    evaluation inventory, and submits a harbor Workload to the running
    Steward Control instance. Tasks are sharded by family across the Pool.

.PARAMETER ControlEndpoint
    The Steward Control loopback HTTP endpoint. Default: http://127.0.0.1:5112

.PARAMETER PoolId
    The registered Steward PoolId to schedule against.

.PARAMETER HarborTasksPath
    Optional override for the harbor tasks directory. Defaults to
    $SaberRepoPath/domains/harbor/tasks.

.PARAMETER HarnessExecutable
    Absolute path to the harbor harness executable on the target Nodes.

.PARAMETER SaberRepoPath
    Path to the proprietary_saber repository root.

.PARAMETER InferenceEndpoint
    Azure OpenAI endpoint for inference.

.PARAMETER MaxConcurrency
    Maximum number of concurrent evaluation tasks. Default: 4

.PARAMETER CasesPerHost
    Preferred number of cases to place on each host. Default: 6

.PARAMETER IdempotencyKey
    Idempotency key for the submission. Generated if not provided.

.EXAMPLE
    .\Submit-HarborEvaluation.ps1 `
        -PoolId "00000000-0000-0000-0000-000000000001" `
        -SaberRepoPath "C:\Projects\proprietary_saber" `
        -HarnessExecutable "C:\tools\harbor-runner.exe"
#>
[CmdletBinding()]
param(
    [string]$ControlEndpoint = "http://127.0.0.1:5112",
    [Parameter(Mandatory)][string]$PoolId,
    [string]$HarborTasksPath,
    [Parameter(Mandatory)][string]$HarnessExecutable,
    [Parameter(Mandatory)][string]$SaberRepoPath,
    [string]$InferenceEndpoint,
    [int]$MaxConcurrency = 4,
    [int]$CasesPerHost = 6,
    [int]$ReplicaCount = 1,
    [string]$IdempotencyKey
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$saberRoot = Resolve-Path $SaberRepoPath
$harborDir = Join-Path $saberRoot "domains" "harbor"
$tasksDir = if ($HarborTasksPath) { Resolve-Path $HarborTasksPath } else { Join-Path $harborDir "tasks" }

if (-not (Test-Path $tasksDir)) {
    throw "Harbor tasks directory not found: $tasksDir"
}

# Resolve the repository commit
$repoCommit = (git -C $saberRoot rev-parse HEAD 2>$null)
if (-not $repoCommit -or $repoCommit.Length -lt 40) {
    throw "Cannot resolve proprietary_saber HEAD commit."
}
$repoCommit = $repoCommit.Substring(0, 40).ToLowerInvariant()

# Read all task YAMLs (excluding global.yaml) and build inventory
$taskFiles = Get-ChildItem -Path $tasksDir -Filter "*.yaml" |
    Where-Object { $_.Name -ne "global.yaml" } |
    Sort-Object Name

$cases = @()
foreach ($file in $taskFiles) {
    $content = Get-Content $file.FullName -Raw
    # Extract task_id from YAML (simple regex since these are auto-generated)
    if ($content -match 'task_id:\s*(\S+)') {
        $taskId = $Matches[1]
        # Extract task_family
        $family = "unknown"
        if ($content -match 'task_family:\s*(\S+)') {
            $family = $Matches[1]
        }
        # Extract sandbox_environment
        $sandbox = $taskId
        if ($content -match 'sandbox_environment:\s*(\S+)') {
            $sandbox = $Matches[1]
        }
        $cases += @{
            caseId     = $taskId
            definition = @{
                taskId             = $taskId
                family             = $family
                sandboxEnvironment = $sandbox
                sourceFile         = $file.Name
            }
        }
    }
}

if ($cases.Count -eq 0) {
    throw "No evaluation cases found in $tasksDir"
}

Write-Host "Found $($cases.Count) harbor evaluation cases across families:"
$families = $cases | ForEach-Object { $_.definition.family } | Sort-Object -Unique
foreach ($f in $families) {
    $count = ($cases | Where-Object { $_.definition.family -eq $f }).Count
    Write-Host "  $f : $count tasks"
}

# Build the dataset hash from the inventory content
$inventoryJson = $cases |
    Sort-Object { $_.caseId } |
    ForEach-Object { @{ caseId = $_.caseId; definition = $_.definition } } |
    ConvertTo-Json -Depth 10 -Compress
$hashBytes = [System.Security.Cryptography.SHA256]::HashData(
    [System.Text.Encoding]::UTF8.GetBytes($inventoryJson))
$inventoryHash = "sha256:" + [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLowerInvariant()

if (-not $IdempotencyKey) {
    $IdempotencyKey = "harbor-full-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([guid]::NewGuid().ToString('N').Substring(0,8))"
}

if (-not $InferenceEndpoint) {
    $InferenceEndpoint = $env:AZURE_OPENAI_ENDPOINT
}
if (-not $InferenceEndpoint) {
    $InferenceEndpoint = "https://steward-inference.openai.azure.com/"
}

# Build the evaluation submission input
$submissionInput = @{
    workload = @{
        harness    = @{
            uri            = "https://github.com/MSECAIModels/Benchmarking/proprietary_saber.git"
            requestedRef   = "main"
            resolvedCommit = $repoCommit
        }
        repository = @{
            uri            = "https://github.com/MSECAIModels/Benchmarking/proprietary_saber.git"
            requestedRef   = "main"
            resolvedCommit = $repoCommit
        }
        dataset    = @{
            identity    = "harbor-incalmo-v1"
            contentHash = $inventoryHash
        }
        evaluationSet          = "harbor-full"
        taskFilters            = @()
        modelProfileReference  = "inference-profile://azure-openai/harbor"
        shardPolicy            = @{
            maximumConcurrency    = $MaxConcurrency
            preferredCasesPerHost = $CasesPerHost
            preferOneHost         = $false
        }
        locations              = @{
            resultLocation = "results/harbor"
            outputLocation = "artifacts/harbor"
        }
        runtime                = @{
            runtimeVersion    = "1.0"
            setupVersion      = "1.0"
            requiresDocker    = $true
            composeFile       = "compose.yaml"
        }
        identityCapabilities   = @(
            @{
                reference  = "identity://inference/azure-openai"
                capability = "inference.use"
            }
        )
        inventory              = $cases | Sort-Object { $_.caseId } | ForEach-Object {
            @{ caseId = $_.caseId; definition = $_.definition }
        }
        inferenceRateScope     = "inference"
        inferenceUnitsPerCase  = 1
        replicaCount           = $ReplicaCount
    }
    harness = @{
        harnessName      = "harbor"
        harnessVersion   = "1.0"
        profileVersion   = "1.0"
        executable       = $HarnessExecutable
        argumentTemplate = @(
            "--case-id", "{caseId}",
            "--dataset", "{dataset}",
            "--dataset-hash", "{datasetHash}",
            "--model-profile", "{modelProfile}",
            "--repository-commit", "{repositoryCommit}",
            "--harness-commit", "{harnessCommit}",
            "--result-location", "{resultLocation}",
            "--output-location", "{outputLocation}",
            "--generation", "{generation}"
        )
        requiresDocker   = $true
        requiredIdentityCapabilities = @("inference.use")
    }
    setup  = @{
        profileVersion = "1.0"
        harnessAcquisition = @{
            executable = $HarnessExecutable
            arguments  = @("setup", "--harness")
        }
        repositoryAcquisition = @{
            executable = $HarnessExecutable
            arguments  = @("setup", "--repository")
        }
        dockerPreparation = @{
            executable = $HarnessExecutable
            arguments  = @("setup", "--docker")
        }
        harnessOwnsDockerLifecycle = $false
    }
}

Write-Host ""
Write-Host "Submitting harbor evaluation workload..."
Write-Host "  Pool:            $PoolId"
Write-Host "  Cases:           $($cases.Count)"
Write-Host "  Replicas:        $ReplicaCount"
Write-Host "  Total tasks:     $($cases.Count * $ReplicaCount)"
Write-Host "  Max concurrency: $MaxConcurrency"
Write-Host "  Cases per host:  $CasesPerHost"
Write-Host "  Idempotency key: $IdempotencyKey"
Write-Host "  Repository:      $repoCommit"
Write-Host ""

$submissionJson = $submissionInput | ConvertTo-Json -Depth 20 -Compress

$cliArgs = @(
    "run", "--project",
    (Join-Path $PSScriptRoot ".." "src" "Steward.Cli" "Steward.Cli.csproj"),
    "--framework", "net10.0-windows",
    "--",
    "workload-submit-harbor",
    "--input", $submissionJson,
    "--pool-id", $PoolId,
    "--idempotency-key", $IdempotencyKey
)

if ($ControlEndpoint -ne "http://127.0.0.1:5112") {
    $cliArgs += @("--endpoint", $ControlEndpoint)
}

Write-Host "Executing: dotnet run --project ... -- workload-submit-harbor --pool-id $PoolId --idempotency-key $IdempotencyKey"
$result = & dotnet @cliArgs 2>&1
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "Workload submitted successfully."
    $result | Write-Host
} else {
    Write-Error "Submission failed (exit code $exitCode):`n$result"
}
