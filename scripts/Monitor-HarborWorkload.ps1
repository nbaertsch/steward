<#
.SYNOPSIS
    Reactively monitors a Harbor evaluation workload using Steward task events.

.PARAMETER WorkloadId
    The Steward WorkloadId to monitor.

.PARAMETER ControlEndpoint
    The Steward Control loopback HTTP endpoint. Default: http://127.0.0.1:5112

.PARAMETER PollIntervalSeconds
    Seconds between event polls (minimum 2). Default: 5

.PARAMETER ReplicaCount
    Expected replica count for coverage reporting. Default: 3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WorkloadId,
    [string]$ControlEndpoint = "http://127.0.0.1:5112",
    [int]$PollIntervalSeconds = 5,
    [int]$ReplicaCount = 3
)

$ErrorActionPreference = 'Stop'
if ($PollIntervalSeconds -lt 2) { $PollIntervalSeconds = 2 }

$tokenFile = $env:STEWARD_CONTROL_MUTATION_TOKEN_FILE
if (-not $tokenFile) {
    $tokenFile = Join-Path $env:LOCALAPPDATA "Steward\control\control.session"
}
$token = (Get-Content $tokenFile -Raw).Trim()
$headers = @{ "X-Steward-Mutation-Token" = $token }

function Get-Workload {
    Invoke-RestMethod -Uri "$ControlEndpoint/workloads/$WorkloadId" -Headers $headers -TimeoutSec 10
}

function Get-TaskStatus([string]$taskId) {
    Invoke-RestMethod -Uri "$ControlEndpoint/tasks/$taskId" -Headers $headers -TimeoutSec 10
}

function Get-TaskEvents([string]$taskId, [long]$after = 0, [int]$limit = 100) {
    Invoke-RestMethod -Uri "$ControlEndpoint/tasks/$taskId/events?after=$after&limit=$limit" -Headers $headers -TimeoutSec 10
}

$stateNames = @{
    0 = "Pending"; 1 = "Accepted"; 2 = "Scheduling"; 3 = "Running"
    5 = "Paused"; 8 = "Cancelled"; 9 = "Failed"; 10 = "Succeeded"
}

$eventCursors = @{}
$taskStates = @{}

Write-Host "Monitoring Harbor workload: $WorkloadId"
Write-Host "Replica count: $ReplicaCount"
Write-Host "Poll interval: ${PollIntervalSeconds}s"
Write-Host ""

$startTime = Get-Date
$iteration = 0

while ($true) {
    $iteration++
    try {
        $workload = Get-Workload
        $taskIds = $workload.payload.taskIds
        $observedState = $workload.payload.observedState
        $stateName = $stateNames[$observedState] ?? "Unknown($observedState)"

        $succeeded = 0; $failed = 0; $running = 0; $pending = 0; $other = 0
        $nodeHostMap = @{}

        foreach ($taskId in $taskIds) {
            $tidStr = if ($taskId -is [string]) { $taskId } else { $taskId.value ?? $taskId.ToString() }
            try {
                $task = Get-TaskStatus $tidStr
                $tState = $task.payload.observedState
                switch ($tState) {
                    10 { $succeeded++ }
                    9 { $failed++ }
                    3 { $running++ }
                    { $_ -le 2 } { $pending++ }
                    default { $other++ }
                }
                $taskStates[$tidStr] = $tState

                # Check for new events
                $cursor = $eventCursors[$tidStr] ?? 0
                $events = Get-TaskEvents $tidStr $cursor 50
                if ($events -and $events.Count -gt 0) {
                    foreach ($evt in $events) {
                        $kind = $evt.kind
                        $seq = $evt.sequence
                        if ($kind -match "terminal" -or $kind -match "accepted" -or $kind -match "running") {
                            $payload = $evt.payloadJson | ConvertFrom-Json -ErrorAction SilentlyContinue
                            $hostId = $payload.identity.hostId
                            $nodeId = $payload.identity.nodeIncarnationId
                            if ($hostId) { $nodeHostMap[$tidStr] = $hostId }
                            if ($kind -match "terminal") {
                                $termState = $payload.state
                                $exitCode = $payload.exitCode
                                Write-Host "  [$tidStr] $kind state=$termState exit=$exitCode host=$hostId" -ForegroundColor $(if ($termState -eq "succeeded") { "Green" } else { "Red" })
                            }
                        }
                        $eventCursors[$tidStr] = [Math]::Max($eventCursors[$tidStr] ?? 0, $seq)
                    }
                }
            } catch {
                # Task might not be queryable yet
            }
        }

        $elapsed = ((Get-Date) - $startTime).ToString("hh\:mm\:ss")
        $total = $taskIds.Count
        $progress = if ($total -gt 0) { [math]::Round(($succeeded + $failed) / $total * 100, 1) } else { 0 }
        $distinctHosts = ($nodeHostMap.Values | Sort-Object -Unique).Count

        Write-Host "`r[$elapsed] Workload=$stateName Tasks: $succeeded✓ $failed✗ $running⟳ $pending… ($progress% complete) Nodes=$distinctHosts" -NoNewline:($iteration -gt 1)

        # Check for terminal workload state
        if ($observedState -ge 8) {
            Write-Host ""
            Write-Host ""
            Write-Host "=== Workload Complete ==="
            Write-Host "Status: $stateName"
            Write-Host "Total tasks: $total"
            Write-Host "Succeeded: $succeeded"
            Write-Host "Failed: $failed"
            Write-Host "Distinct nodes used: $distinctHosts"

            # Per-case replica coverage
            $expectedCases = [math]::Floor($total / $ReplicaCount)
            Write-Host ""
            Write-Host "Expected: $expectedCases cases × $ReplicaCount replicas = $total tasks"
            Write-Host "Coverage: $succeeded / $total valid receipts"
            if ($succeeded -eq $total) {
                Write-Host "ALL REPLICAS COMPLETE" -ForegroundColor Green
            } else {
                Write-Host "INCOMPLETE: $($total - $succeeded) tasks did not succeed" -ForegroundColor Yellow
            }
            break
        }
    } catch {
        Write-Host "  [poll error: $($_.Exception.Message)]" -ForegroundColor Yellow
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}
