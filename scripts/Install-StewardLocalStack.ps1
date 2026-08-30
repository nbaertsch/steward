param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "Programs\Steward"),
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA "Steward"),
    [int]$DirectPort = 7332,
    [int]$ControlPort = 5112,
    [switch]$Start
)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot
$dotnet = Join-Path $env:USERPROFILE ".dotnet\dotnet.exe"
if (-not (Test-Path $dotnet)) {
    $dotnet = (Get-Command dotnet -ErrorAction Stop).Source
}

$install = [IO.Path]::GetFullPath($InstallRoot)
$data = [IO.Path]::GetFullPath($DataRoot)
$keys = Join-Path $data "keys"
$controlData = Join-Path $data "control"
$nodeData = Join-Path $data "node"
foreach ($path in @($install, $data, $keys, $controlData, $nodeData)) {
    New-Item -ItemType Directory -Force -Path $path | Out-Null
}

function Protect-Path([string]$Path, [bool]$Directory) {
    if (-not $IsWindows) { return }
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new(
        [Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    if ($Directory) {
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $current, "FullControl", $inheritance, "None", "Allow"))
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $system, "FullControl", $inheritance, "None", "Allow"))
        [IO.FileSystemAclExtensions]::SetAccessControl(
            [IO.DirectoryInfo]::new($Path), $security)
    } else {
        $security = [Security.AccessControl.FileSecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $current, "FullControl", "Allow"))
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $system, "FullControl", "Allow"))
        [IO.FileSystemAclExtensions]::SetAccessControl(
            [IO.FileInfo]::new($Path), $security)
    }
}
Protect-Path $data $true

function Ensure-EcdsaKey([string]$Name) {
    $privatePath = Join-Path $keys "$Name-private.pem"
    $publicPath = Join-Path $keys "$Name-public.pem"
    if ((Test-Path $privatePath) -and (Test-Path $publicPath)) {
        return [pscustomobject]@{ Private = $privatePath; Public = $publicPath }
    }
    $key = [Security.Cryptography.ECDsa]::Create()
    try {
        $key.GenerateKey(
            [Security.Cryptography.ECCurve]::CreateFromFriendlyName("nistP256"))
        [IO.File]::WriteAllText($privatePath, $key.ExportPkcs8PrivateKeyPem())
        [IO.File]::WriteAllText($publicPath, $key.ExportSubjectPublicKeyInfoPem())
        Protect-Path $privatePath $false
    } finally {
        if ($null -ne $key) { $key.Dispose() }
    }
    return [pscustomobject]@{ Private = $privatePath; Public = $publicPath }
}

$controlKey = Ensure-EcdsaKey "control"
$nodeKey = Ensure-EcdsaKey "node"
$statePath = Join-Path $data "installation.json"
if (Test-Path $statePath) {
    $state = Get-Content $statePath -Raw | ConvertFrom-Json
} else {
    $state = [pscustomobject]@{
        HostId = [guid]::NewGuid().ToString()
        NodeIncarnationId = [guid]::NewGuid().ToString()
        PoolId = [guid]::NewGuid().ToString()
        KeeperPipe = "Steward.HandleKeeper.$([guid]::NewGuid().ToString('N'))"
    }
    $state | ConvertTo-Json | Set-Content -Encoding UTF8 $statePath
}

$projects = @(
    "Steward.Control",
    "Steward.Node.Host",
    "Steward.HandleKeeper",
    "Steward.Cli",
    "Steward.Mcp",
    "Steward.Desktop.Windows",
    "Steward.RdpDvc.Client.Windows",
    "Steward.RdpDvc.Server.Windows"
)
foreach ($project in $projects) {
    $output = Join-Path $install $project
    New-Item -ItemType Directory -Force -Path $output | Out-Null
    $publishArgs = @(
        "publish",
        (Join-Path $repo "src\$project\$project.csproj"),
        "-c", "Release", "-r", "win-x64", "--self-contained", "true",
        "--nologo", "--verbosity", "quiet", "-o", $output
    )
    $csproj = Get-Content (Join-Path $repo "src\$project\$project.csproj") -Raw
    if ($csproj -match "TargetFrameworks" -and $csproj -notmatch "TargetFramework>") {
        $publishArgs += @("-f", "net10.0-windows")
    }
    & $dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Publishing $project failed."
    }
}

$dvcClient = Join-Path $install "Steward.RdpDvc.Client.Windows\Steward.RdpDvc.Client.Windows.exe"
& $dvcClient /register
if ($LASTEXITCODE -ne 0) {
    throw "Per-user Steward RDP DVC registration failed."
}

$endpoint = "ws://127.0.0.1:$DirectPort/steward/"
$controlConfig = @{
    urls = "http://127.0.0.1:$ControlPort"
    Control = @{
        DatabasePath = (Join-Path $controlData "control.db")
        LocalSessionTokenPath = (Join-Path $controlData "control.session")
        Orchestration = @{
            Enabled = $true
            SchedulerDatabasePath = (Join-Path $controlData "scheduler.db")
            GlobalRateDatabasePath = (Join-Path $controlData "rates.db")
        }
        Terminal = @{ Enabled = $false }
        Agents = @{ Enabled = $false }
    }
    Steward = @{
        LocalStack = @{
            DataRoot = $controlData
            PortableStateRoot = (Join-Path $controlData "objects")
            CredentialVaultRoot = (Join-Path $controlData "credentials")
            TransportEnabled = $true
            TransportIdentity = "control"
            TransportPrivateKeyPemPath = $controlKey.Private
            MaximumTransportPayloadBytes = 262144
            MaximumBufferedFrames = 256
            Nodes = @(@{
                HostId = $state.HostId
                NodeIncarnationId = $state.NodeIncarnationId
                PoolId = $state.PoolId
                DialDirection = "ControlDialsNode"
                Endpoint = $endpoint
                PeerIdentity = "node"
                PeerPublicKeyPemPath = $nodeKey.Public
                CpuCores = 8
                MemoryBytes = 8589934592
                DiskBytes = 53687091200
                ProcessCount = 32
                ContainerCount = 8
                ConcurrencyUnits = 16
                Capabilities = @("process", "docker", "terminal")
                SetupFingerprints = @()
            })
            DevBox = @{ Enabled = $false }
        }
    }
}

$nodeConfig = @{
    NodeHost = @{
        JournalPath = (Join-Path $nodeData "node.db")
        ExecutionJournalPath = (Join-Path $nodeData "execution.db")
        EvaluationDatabasePath = (Join-Path $nodeData "evaluation.db")
        WorkspaceRoot = (Join-Path $nodeData "workspaces")
        SpoolRoot = (Join-Path $nodeData "spool")
        SpoolHighLimitBytes = 1073741824
        SpoolHardLimitBytes = 2147483648
        SpoolOsReserveBytes = 536870912
        KeeperPipeName = $state.KeeperPipe
        NodeIncarnationId = $state.NodeIncarnationId
        HostId = $state.HostId
        TerminalJournalPath = (Join-Path $nodeData "terminal.db")
        MaximumTerminalSessions = 8
        AgentsEnabled = $false
        AgentRuntimeProfile = "process-jsonl/1.0"
    }
    Steward = @{
        LocalStack = @{
            DataRoot = $nodeData
            PortableStateRoot = (Join-Path $nodeData "objects")
            CredentialVaultRoot = (Join-Path $nodeData "credentials")
            TransportEnabled = $true
            TransportIdentity = "node"
            TransportPrivateKeyPemPath = $nodeKey.Private
            MaximumTransportPayloadBytes = 262144
            MaximumBufferedFrames = 256
            Nodes = @(@{
                HostId = $state.HostId
                NodeIncarnationId = $state.NodeIncarnationId
                PoolId = $state.PoolId
                DialDirection = "ControlDialsNode"
                Endpoint = $endpoint
                PeerIdentity = "control"
                PeerPublicKeyPemPath = $controlKey.Public
                CpuCores = 8
                MemoryBytes = 8589934592
                DiskBytes = 53687091200
                ProcessCount = 32
                ContainerCount = 8
                ConcurrencyUnits = 16
                Capabilities = @("process", "docker", "terminal")
                SetupFingerprints = @()
            })
            DevBox = @{ Enabled = $false }
        }
    }
}

$controlConfig | ConvertTo-Json -Depth 12 |
    Set-Content -Encoding UTF8 (Join-Path $install "Steward.Control\appsettings.json")
$nodeConfig | ConvertTo-Json -Depth 12 |
    Set-Content -Encoding UTF8 (Join-Path $install "Steward.Node.Host\appsettings.json")

$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$startScript = Join-Path $install "Start-StewardLocalStack.ps1"
$startBody = @"
`$ErrorActionPreference = "Stop"
function Start-StewardProcess([string]`$Name, [string]`$Executable, [string]`$WorkingDirectory, [string[]]`$Arguments) {
    `$pidPath = Join-Path "$data" "`$Name.pid"
    `$expectedPath = [IO.Path]::GetFullPath(`$Executable)
    if (Test-Path `$pidPath) {
        try {
            `$record = Get-Content `$pidPath -Raw -ErrorAction Stop | ConvertFrom-Json
            `$existing = Get-Process -Id ([int]`$record.ProcessId) -ErrorAction Stop
            `$actualPath = [IO.Path]::GetFullPath(`$existing.MainModule.FileName)
            `$actualStart = `$existing.StartTime.ToUniversalTime()
            `$recordedStart = ([DateTimeOffset]`$record.StartTimeUtc).UtcDateTime
            if ([string]::Equals(
                    `$actualPath,
                    `$expectedPath,
                    [StringComparison]::OrdinalIgnoreCase) -and
                `$actualStart -eq `$recordedStart) {
                return
            }
        } catch {
        }
        Remove-Item -LiteralPath `$pidPath -Force -ErrorAction SilentlyContinue
    }
    `$outLog = Join-Path "$data" "`$Name.out.log"
    `$errLog = Join-Path "$data" "`$Name.err.log"
    `$process = Start-Process -FilePath `$Executable -ArgumentList `$Arguments -WorkingDirectory `$WorkingDirectory -WindowStyle Hidden -RedirectStandardOutput `$outLog -RedirectStandardError `$errLog -PassThru
    Start-Sleep -Milliseconds 250
    if (`$process.HasExited) {
        throw "Steward process '`$Name' exited during startup."
    }
    [pscustomobject]@{
        ProcessId = `$process.Id
        ExecutablePath = `$expectedPath
        StartTimeUtc = `$process.StartTime.ToUniversalTime().ToString("O")
    } | ConvertTo-Json | Set-Content -Encoding UTF8 `$pidPath
}
Start-StewardProcess "handlekeeper" (Join-Path "$install" "Steward.HandleKeeper\Steward.HandleKeeper.exe") (Join-Path "$install" "Steward.HandleKeeper") @("--pipe","$($state.KeeperPipe)","--node-account","$sid")
Start-Sleep -Milliseconds 500
Start-StewardProcess "node" (Join-Path "$install" "Steward.Node.Host\Steward.Node.Host.exe") (Join-Path "$install" "Steward.Node.Host") @()
Start-Sleep -Milliseconds 500
Start-StewardProcess "control" (Join-Path "$install" "Steward.Control\Steward.Control.exe") (Join-Path "$install" "Steward.Control") @()
`$health = "http://127.0.0.1:$ControlPort/health"
for (`$attempt = 0; `$attempt -lt 30; `$attempt++) {
    try {
        `$status = Invoke-RestMethod -Uri `$health -TimeoutSec 2
        if (`$status.healthy -eq `$true) { break }
    } catch {
    }
    Start-Sleep -Milliseconds 500
}
if (`$status.healthy -ne `$true) {
    throw "Steward Control did not become healthy."
}
"@
Set-Content -Encoding UTF8 $startScript $startBody

$startup = [Environment]::GetFolderPath("Startup")
$startupCommand = Join-Path $startup "Steward Local Stack.cmd"
Set-Content -Encoding ASCII $startupCommand (
    "@echo off`r`npowershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$startScript`"`r`n")

[Environment]::SetEnvironmentVariable(
    "STEWARD_CONTROL_URL",
    "http://127.0.0.1:$ControlPort/",
    "User")
[Environment]::SetEnvironmentVariable(
    "STEWARD_CONTROL_MUTATION_TOKEN_FILE",
    (Join-Path $controlData "control.session"),
    "User")

$programs = [Environment]::GetFolderPath("Programs")
$shortcutPath = Join-Path $programs "Steward.lnk"
$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $install "Steward.Desktop.Windows\Steward.Desktop.Windows.exe"
$shortcut.WorkingDirectory = Join-Path $install "Steward.Desktop.Windows"
$shortcut.Description = "Steward operations"
$shortcut.Save()

if ($Start) {
    & $startScript
}

[pscustomobject]@{
    InstallRoot = $install
    DataRoot = $data
    ControlUrl = "http://127.0.0.1:$ControlPort/"
    HostId = $state.HostId
    NodeIncarnationId = $state.NodeIncarnationId
    PoolId = $state.PoolId
    DesktopPath = (Join-Path $install "Steward.Desktop.Windows\Steward.Desktop.Windows.exe")
    DvcClientPluginPath = $dvcClient
    DvcServerTestPath = (Join-Path $install "Steward.RdpDvc.Server.Windows\Steward.RdpDvc.Server.Windows.exe")
    Started = [bool]$Start
}
