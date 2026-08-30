using System.Security.Cryptography;
using System.Text;
using Steward.Domain;

namespace Steward.Providers.DevBox;

public sealed record DevBoxRdpDvcBootstrapRequest(
    ProviderOperationId OperationId,
    string IdempotencyKey,
    string Project,
    string User,
    string DevBox,
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId IncarnationId,
    IReadOnlyList<Guid> ConnectionNonces,
    ReadOnlyMemory<byte> AuthenticationKey,
    string? NodeTransportIdentity = null,
    ReadOnlyMemory<byte> NodeSigningPrivateKey = default,
    string? ControlTransportIdentity = null,
    ReadOnlyMemory<byte> ControlSigningPublicKey = default,
    ReadOnlyMemory<byte> BootstrapEncryptionPublicKey = default)
{
    public DevBoxRdpDvcBootstrapRequest Validate()
    {
        if (OperationId.Value == Guid.Empty ||
            string.IsNullOrWhiteSpace(IdempotencyKey) ||
            IdempotencyKey.Length > 256 ||
            SessionId == Guid.Empty ||
            HostId.Value == Guid.Empty ||
            IncarnationId.Value == Guid.Empty ||
            ConnectionNonces.Count != 2 ||
            ConnectionNonces.Any(nonce => nonce == Guid.Empty) ||
            ConnectionNonces.Distinct().Count() != 2 ||
            AuthenticationKey.Length is < 32 or > 64 ||
            BootstrapEncryptionPublicKey.Length is < 256 or > 1024 ||
            !ValidTransportKeys())
            throw new ArgumentException(
                "RDP DVC bootstrap request is invalid.");
        ValidateIdentifier(Project, nameof(Project));
        if (!string.Equals(User, "me", StringComparison.Ordinal) &&
            !Guid.TryParse(User, out _))
            throw new ArgumentException(
                "Dev Box user must be 'me' or a GUID.",
                nameof(User));
        ValidateIdentifier(DevBox, nameof(DevBox));
        return this;
    }

    private bool ValidTransportKeys()
    {
        return ValidTransportIdentity(NodeTransportIdentity) &&
            NodeSigningPrivateKey.Length is >= 64 and <= 4096 &&
            ValidTransportIdentity(ControlTransportIdentity) &&
            ControlSigningPublicKey.Length is >= 64 and <= 2048;
    }

    private static bool ValidTransportIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 128 &&
        !value.Any(character =>
            char.IsControl(character) || character == '"');

    private static void ValidateIdentifier(string value, string name)
    {
        if (value.Length is < 3 or > 63 ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.'))
            throw new ArgumentException(
                "Dev Box identifier is invalid.",
                name);
    }
}

public sealed record DevBoxRdpDvcBootstrapIntent(
    ProviderOperationId OperationId,
    string IdempotencyKey,
    string Project,
    string User,
    string DevBox,
    string Version,
    string ArchiveSha256,
    string AuthenticationKeySha256,
    string Fingerprint,
    int GroupCount);

public sealed record DevBoxRdpDvcBootstrapGroup(
    string Name,
    IReadOnlyList<DevBoxCustomizationTaskRequest> Tasks);

public sealed record DevBoxRdpDvcBootstrapOperation(
    DevBoxRdpDvcBootstrapIntent Intent,
    IReadOnlyList<DevBoxRdpDvcBootstrapGroup> Groups);

internal static class DevBoxRdpDvcBootstrapRecovery
{
    internal static bool CanRestartWithoutLosingStaging(
        string groupName,
        string firstGroupName)
    {
        const string firstSuffix = "0000";
        if (!firstGroupName.EndsWith(
                firstSuffix,
                StringComparison.Ordinal))
            return false;
        var prefix = firstGroupName[..^firstSuffix.Length];
        return groupName.StartsWith(prefix, StringComparison.Ordinal) &&
            groupName.Length == prefix.Length + 4 &&
            groupName.AsSpan(prefix.Length).ToString().All(char.IsAsciiDigit);
    }

    internal static bool CanRecoverFinalInstaller(
        string groupStatus,
        IReadOnlyList<string> taskStatuses) =>
        string.Equals(
            groupStatus,
            "Failed",
            StringComparison.OrdinalIgnoreCase) &&
        taskStatuses is [var taskStatus] &&
        (string.Equals(
             taskStatus,
             "Failed",
             StringComparison.OrdinalIgnoreCase) ||
         string.Equals(
             taskStatus,
             "TimedOut",
             StringComparison.OrdinalIgnoreCase));
}

public static class DevBoxRdpDvcBootstrapPlan
{
    public const int MaximumBase64ChunkCharacters = 14_390;
    public const int MaximumTasksPerGroup = 15;
    public const int MaximumGroups = 32;
    public const string ProviderName = "azure-dev-box-customization/rdp-dvc";
    public const string StartupFileName = "StewardRdpDvcEndpoint.vbs";

    public static DevBoxRdpDvcBootstrapOperation Create(
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle)
    {
        request.Validate();
        bundle.Validate();
        var key = request.AuthenticationKey.ToArray();
        try
        {
            var keySha256 = Convert.ToHexString(SHA256.HashData(key))
                .ToLowerInvariant();
            var fingerprint = Fingerprint(
                request,
                bundle,
                keySha256);
            var encoded = Convert.ToBase64String(
                bundle.Archive.ToMemory().Span);
            var chunks = Enumerable.Range(
                    0,
                    (encoded.Length + MaximumBase64ChunkCharacters - 1) /
                    MaximumBase64ChunkCharacters)
                .Select(index => encoded.Substring(
                    index * MaximumBase64ChunkCharacters,
                    Math.Min(
                        MaximumBase64ChunkCharacters,
                        encoded.Length -
                        index * MaximumBase64ChunkCharacters)))
                .ToArray();
            var chunkTasks = chunks.Select((chunk, index) =>
                    Task(
                        $"Stage RDP DVC payload {index + 1}/{chunks.Length}",
                        ChunkScript(
                            bundle.ArchiveSha256,
                            request.OperationId,
                            index,
                            chunk)))
                .ToArray();
            var groups = chunkTasks
                .Chunk(MaximumTasksPerGroup)
                .Select((tasks, index) =>
                    new DevBoxRdpDvcBootstrapGroup(
                        GroupName(request.OperationId, index),
                        tasks))
                .ToList();
            var installer = Task(
                "Verify and atomically install RDP DVC endpoint",
                InstallationScript(
                    request,
                    bundle,
                    fingerprint,
                    chunks.Length,
                    encoded.Length,
                    Convert.ToBase64String(key)),
                timeoutSeconds: 900);
            if (groups[^1].Tasks.Count < MaximumTasksPerGroup)
            {
                groups[^1] = groups[^1] with
                {
                    Tasks = [.. groups[^1].Tasks, installer]
                };
            }
            else
            {
                groups.Add(new(
                    GroupName(request.OperationId, groups.Count),
                    [installer]));
            }
            if (groups.Count > MaximumGroups)
                throw new InvalidDataException(
                    "RDP DVC bootstrap plan exceeds its customization group bound.");
            var intent = new DevBoxRdpDvcBootstrapIntent(
                request.OperationId,
                request.IdempotencyKey,
                request.Project,
                request.User,
                request.DevBox,
                bundle.Manifest.Version,
                bundle.ArchiveSha256,
                keySha256,
                fingerprint,
                groups.Count);
            return new(intent, groups);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static DevBoxCustomizationTaskRequest
        CreateEndpointRecoveryTask(
            DevBoxRdpDvcBootstrapRequest request,
            RdpDvcBootstrapBundle bundle)
    {
        request.Validate();
        bundle.Validate();
        var launcherSource = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(SessionLauncherSource));
        var operationId = request.OperationId.Value.ToString("N");
        var sessionId = request.SessionId.ToString("D");
        var hostId = request.HostId.ToString();
        var incarnationId = request.IncarnationId.ToString();
        var version = bundle.Manifest.Version;
        var startupSource = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(
                "$ErrorActionPreference='Stop'\r\n" +
                $"$target=Join-Path $env:LOCALAPPDATA 'StewardNode\\rdp-dvc\\versions\\{version}'\r\n" +
                $"$nodeState=Join-Path $env:LOCALAPPDATA 'StewardNode\\rdp-dvc\\nodes\\{hostId}\\{incarnationId}'\r\n" +
                $"$keyDirectory=Join-Path $env:ProgramData 'Steward\\rdp-dvc\\keys\\{operationId}'\r\n" +
                $"$runDirectory=Join-Path $env:LOCALAPPDATA 'StewardNode\\rdp-dvc\\runs\\{operationId}'\r\n" +
                "$dotnet=Join-Path $env:ProgramFiles 'dotnet\\dotnet.exe'\r\n" +
                "$server=Join-Path $target 'Steward.RdpDvc.Server.Windows.dll'\r\n" +
                "$runtimeConfig=Join-Path $target 'Steward.RdpDvc.Server.Windows.runtimeconfig.json'\r\n" +
                "$depsFile=Join-Path $target 'Steward.RdpDvc.Server.Windows.deps.json'\r\n" +
                "$keeper=Join-Path $target 'Steward.HandleKeeper.dll'\r\n" +
                "$keeperRuntimeConfig=Join-Path $target 'Steward.HandleKeeper.runtimeconfig.json'\r\n" +
                "$keeperDepsFile=Join-Path $target 'Steward.HandleKeeper.deps.json'\r\n" +
                $"$keeperPipe='Steward.Node.{request.IncarnationId.Value:N}'\r\n" +
                $"$keyPath=Join-Path $keyDirectory 'rdp-dvc-{operationId}.key'\r\n" +
                $"$nodeSigningPath=Join-Path $keyDirectory 'node-signing-{operationId}.pk8'\r\n" +
                $"$controlSigningPath=Join-Path $keyDirectory 'control-signing-{operationId}.spki'\r\n" +
                "$noncePath=Join-Path $runDirectory 'nonce-sequence.json'\r\n" +
                "$readinessPath=Join-Path $runDirectory 'readiness.json'\r\n" +
                "$nodeConfig=Join-Path $nodeState 'node-host.json'\r\n" +
                "$portable=Join-Path $nodeState 'portable'\r\n" +
                "$credentials=Join-Path $nodeState 'credentials'\r\n" +
                "New-Item -ItemType Directory -Force -Path $runDirectory|Out-Null\r\n" +
                "$lockPath=Join-Path $runDirectory 'launcher.lock'\r\n" +
                "try{$launchLock=[IO.File]::Open($lockPath,'OpenOrCreate','ReadWrite','None')}catch{exit 0}\r\n" +
                "$launchId=[guid]::NewGuid().ToString('N')\r\n" +
                "$launcherLog=Join-Path $runDirectory ('launcher-'+$launchId+'.log')\r\n" +
                "$keeperOut=Join-Path $runDirectory ('keeper-'+$launchId+'.out.log')\r\n" +
                "$keeperErr=Join-Path $runDirectory ('keeper-'+$launchId+'.err.log')\r\n" +
                "$serverOut=Join-Path $runDirectory ('server-'+$launchId+'.out.log')\r\n" +
                "$serverErr=Join-Path $runDirectory ('server-'+$launchId+'.err.log')\r\n" +
                "try{\r\n" +
                "if(Test-Path -LiteralPath $readinessPath){try{$existing=Get-Content -LiteralPath $readinessPath -Raw|ConvertFrom-Json;$running=if([int]$existing.processId -gt 0){Get-Process -Id ([int]$existing.processId) -ErrorAction SilentlyContinue}else{$null};if($null-ne $running){exit 0}}catch{}}\r\n" +
                "Add-Content -LiteralPath $launcherLog -Value ('start '+[DateTime]::UtcNow.ToString('O'))\r\n" +
                "$keeperArgs=@('exec','--runtimeconfig',$keeperRuntimeConfig,'--depsfile',$keeperDepsFile,$keeper,'--console','--pipe',$keeperPipe,'--node-account',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)\r\n" +
                "$keeperProcess=Start-Process -FilePath $dotnet -ArgumentList $keeperArgs -WorkingDirectory $target -WindowStyle Hidden -RedirectStandardOutput $keeperOut -RedirectStandardError $keeperErr -PassThru\r\n" +
                "Add-Content -LiteralPath $launcherLog -Value ('keeper '+$keeperProcess.Id)\r\n" +
                "Start-Sleep -Milliseconds 500\r\n" +
                "$serverArgs=@('exec','--runtimeconfig',$runtimeConfig,'--depsfile',$depsFile,$server,'--session-id','" + sessionId + "','--host-id','" + hostId + "','--incarnation-id','" + incarnationId + "','--auth-key-file',$keyPath,'--nonce-sequence-file',$noncePath,'--readiness-receipt-file',$readinessPath,'--node-host-config',$nodeConfig,'--portable-state-root',$portable,'--credential-vault-root',$credentials,'--node-signing-key-file',$nodeSigningPath,'--node-identity','" + request.NodeTransportIdentity + "','--control-signing-key-file',$controlSigningPath,'--control-identity','" + request.ControlTransportIdentity + "')\r\n" +
                "$serverProcess=Start-Process -FilePath $dotnet -ArgumentList $serverArgs -WorkingDirectory $target -WindowStyle Hidden -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -PassThru\r\n" +
                "Add-Content -LiteralPath $launcherLog -Value ('server '+$serverProcess.Id)\r\n" +
                "Start-Sleep -Seconds 2\r\n" +
                "if($serverProcess.HasExited){Add-Content -LiteralPath $launcherLog -Value ('server-exit '+$serverProcess.ExitCode);exit 1}\r\n" +
                "}catch{Add-Content -LiteralPath $launcherLog -Value ('failure '+$_.Exception.GetType().Name+' 0x'+$_.Exception.HResult.ToString('X8'));exit 1}finally{$launchLock.Dispose()}\r\n"));
        var command =
            "$ErrorActionPreference='Stop';" +
            "$startup=Join-Path $env:ProgramData 'Microsoft\\Windows\\Start Menu\\Programs\\Startup';" +
            "[void](New-Item -ItemType Directory -Path $startup -Force);" +
            $"$startupPath=Join-Path $startup 'StewardRdpDvcEndpoint-{hostId}.ps1';" +
            $"[IO.File]::WriteAllBytes($startupPath,[Convert]::FromBase64String('{startupSource}'));" +
            "& icacls.exe $startupPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-545:RX'|Out-Null;" +
            "if($LASTEXITCODE -ne 0){throw 'RDP DVC startup launcher ACL failed'};" +
            $"$taskName='RdpDvcEndpoint-{hostId}';" +
            $"$keeperTaskName='HandleKeeper-{hostId}';" +
            $"$nodeStatePath=Get-Item -Path 'C:\\Users\\*\\AppData\\Local\\StewardNode\\rdp-dvc\\nodes\\{hostId}\\{incarnationId}' -ErrorAction SilentlyContinue|Select-Object -First 1;" +
            "if($null-eq $nodeStatePath){throw 'RDP DVC node user state is unavailable'};" +
            "$profileDirectory=$nodeStatePath;for($index=0;$index-lt 7;$index++){$profileDirectory=$profileDirectory.Parent};" +
            "$nodeUsers=@((Get-Acl -LiteralPath $nodeStatePath.FullName).Access|ForEach-Object{try{$sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]);$account=$sid.Translate([Security.Principal.NTAccount]).Value;if(($sid.Value-like 'S-1-5-21-*' -or $sid.Value-like 'S-1-12-1-*') -and ($account-split '\\\\')[-1]-eq $profileDirectory.Name){$account}}catch{}}|Where-Object{$_}|Select-Object -Unique);" +
            "if($nodeUsers.Count-ne 1){throw 'RDP DVC node user identity is ambiguous'};" +
            $"$target=Join-Path $profileDirectory.FullName 'AppData\\Local\\StewardNode\\rdp-dvc\\versions\\{version}';" +
            $"$runDirectory=Join-Path $profileDirectory.FullName 'AppData\\Local\\StewardNode\\rdp-dvc\\runs\\{operationId}';" +
            $"$nodeState=Join-Path $profileDirectory.FullName 'AppData\\Local\\StewardNode\\rdp-dvc\\nodes\\{hostId}\\{incarnationId}';" +
            $"$keyDirectory=Join-Path $env:ProgramData 'Steward\\rdp-dvc\\keys\\{operationId}';" +
            "$dotnet=Join-Path $env:ProgramFiles 'dotnet\\dotnet.exe';" +
            "$keeperArguments='exec --runtimeconfig \"'+(Join-Path $target 'Steward.HandleKeeper.runtimeconfig.json')+'\" --depsfile \"'+(Join-Path $target 'Steward.HandleKeeper.deps.json')+'\" \"'+(Join-Path $target 'Steward.HandleKeeper.dll')+'\" --console --pipe \"Steward.Node." + request.IncarnationId.Value.ToString("N") + "\" --node-account \"'+$nodeUsers[0]+'\"';" +
            "$serverArguments='exec --runtimeconfig \"'+(Join-Path $target 'Steward.RdpDvc.Server.Windows.runtimeconfig.json')+'\" --depsfile \"'+(Join-Path $target 'Steward.RdpDvc.Server.Windows.deps.json')+'\" \"'+(Join-Path $target 'Steward.RdpDvc.Server.Windows.dll')+'\" --session-id " + sessionId + " --host-id " + hostId + " --incarnation-id " + incarnationId + " --auth-key-file \"'+(Join-Path $keyDirectory 'rdp-dvc-" + operationId + ".key')+'\" --nonce-sequence-file \"'+(Join-Path $runDirectory 'nonce-sequence.json')+'\" --readiness-receipt-file \"'+(Join-Path $runDirectory 'readiness.json')+'\" --node-host-config \"'+(Join-Path $nodeState 'node-host.json')+'\" --portable-state-root \"'+(Join-Path $nodeState 'portable')+'\" --credential-vault-root \"'+(Join-Path $nodeState 'credentials')+'\" --node-signing-key-file \"'+(Join-Path $keyDirectory 'node-signing-" + operationId + ".pk8')+'\" --node-identity \"" + request.NodeTransportIdentity + "\" --control-signing-key-file \"'+(Join-Path $keyDirectory 'control-signing-" + operationId + ".spki')+'\" --control-identity \"" + request.ControlTransportIdentity + "\"';" +
            "$keeperAction=New-ScheduledTaskAction -Execute $dotnet -Argument $keeperArguments -WorkingDirectory $target;" +
            "$taskAction=New-ScheduledTaskAction -Execute $dotnet -Argument $serverArguments -WorkingDirectory $target;" +
            "$taskTrigger=New-ScheduledTaskTrigger -AtLogOn -User $nodeUsers[0];" +
            "$taskPrincipal=New-ScheduledTaskPrincipal -UserId $nodeUsers[0] -LogonType Interactive -RunLevel Limited;" +
            "$taskSettings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -Hidden;" +
            "Register-ScheduledTask -TaskName $keeperTaskName -TaskPath '\\Steward\\' -Action $keeperAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force|Out-Null;" +
            "Register-ScheduledTask -TaskName $taskName -TaskPath '\\Steward\\' -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force|Out-Null;" +
            "if(@(Get-Process -IncludeUserName -ErrorAction SilentlyContinue|Where-Object{$_.UserName-eq $nodeUsers[0]}).Count-gt 0){Start-ScheduledTask -TaskName $keeperTaskName -TaskPath '\\Steward\\';Start-Sleep -Milliseconds 500;Start-ScheduledTask -TaskName $taskName -TaskPath '\\Steward\\'};" +
            "Write-Output ('STEWARD_RDP_DVC_TASKS:'+$keeperTaskName+','+$taskName)";
        return Task(
            "Restart verified RDP DVC endpoint",
            command,
            timeoutSeconds: 300);
    }

    public static DevBoxCustomizationTaskRequest CreateEndpointProbeTask(
        DevBoxRdpDvcBootstrapRequest request)
    {
        request.Validate();
        var operationId = request.OperationId.Value.ToString("N");
        var hostId = request.HostId.ToString();
        var command =
            "$ErrorActionPreference='Stop';" +
            $"$readinessPattern='C:\\Users\\*\\AppData\\Local\\StewardNode\\rdp-dvc\\runs\\{operationId}\\readiness.json';" +
            "$readiness=@(Get-Item -Path $readinessPattern -ErrorAction SilentlyContinue|ForEach-Object{try{Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json}catch{$null}}|Where-Object{$null-ne $_});" +
            "$lastReadiness=$readiness|Sort-Object updatedAtUtc|Select-Object -Last 1;" +
            "$failureFiles=@(Get-Item -Path ($readinessPattern+'.failure') -ErrorAction SilentlyContinue|Sort-Object LastWriteTime);" +
            "$remoteFailure=if($failureFiles.Count-gt 0){((Get-Content -LiteralPath $failureFiles[-1].FullName -Raw)-replace '[;\\r\\n]+',' ')}else{'none'};" +
            "if($remoteFailure.Length-gt 384){$remoteFailure=$remoteFailure.Substring($remoteFailure.Length-384)};" +
            "$remoteState=if($null-ne $lastReadiness){[string]$lastReadiness.state}else{'none'};" +
            "$remotePid=if($null-ne $lastReadiness){[int]$lastReadiness.processId}else{0};" +
            "$remoteProcess=if($remotePid-gt 0){Get-Process -Id $remotePid -ErrorAction SilentlyContinue}else{$null};" +
            "$remoteSession=if($null-ne $remoteProcess){[int]$remoteProcess.SessionId}else{-1};" +
            "$nextGeneration=if($null-ne $lastReadiness){[int]$lastReadiness.nextGeneration}else{-1};" +
            "$probe='state='+$remoteState+';pid='+$remotePid+';session='+$remoteSession+';next='+$nextGeneration+';failure='+$remoteFailure;" +
            "$marker='STEWARD_RDP_DVC_'+'PROBE:';Write-Output ($marker+$probe)";
        return Task(
            "Probe RDP DVC endpoint state",
            command,
            timeoutSeconds: 300);
    }

    public static DevBoxCustomizationTaskRequest CreateStagingProbeTask(
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle)
    {
        request.Validate();
        bundle.Validate();
        var operationId = request.OperationId.Value.ToString("N");
        var archiveHash = bundle.ArchiveSha256;
        var encodedLength = Convert.ToBase64String(bundle.Archive).Length;
        var chunkCount = checked(
            (encodedLength + MaximumBase64ChunkCharacters - 1) /
            MaximumBase64ChunkCharacters);
        var command =
            "$ErrorActionPreference='Stop';" +
            "$stageRoot=Join-Path $env:ProgramData 'Steward\\rdp-dvc\\staging';" +
            $"$stage=Join-Path $stageRoot '{archiveHash}\\{operationId}';" +
            "$chunks=Join-Path $stage 'chunks';" +
            "$files=@(Get-ChildItem -LiteralPath $chunks -Filter '*.txt' -File -ErrorAction SilentlyContinue|Sort-Object Name);" +
            "$valid=@($files|Where-Object{$_.Name-match '^\\d{4}\\.txt$'});" +
            "$present=@($valid|ForEach-Object{[int]$_.BaseName});" +
            $"$missing=@(0..{chunkCount - 1}|Where-Object{{$present-notcontains $_}});" +
            "$lengths=@($valid|ForEach-Object{[ordered]@{index=[int]$_.BaseName;length=[long]$_.Length}});" +
            $"$probe=[ordered]@{{version=1;stageExists=(Test-Path -LiteralPath $stage);expectedCount={chunkCount};presentCount=$valid.Count;missing=$missing;unexpected=@($files|Where-Object{{$_.Name-notmatch '^\\d{{4}}\\.txt$'}}|ForEach-Object{{$_.Name}});expectedEncodedLength={encodedLength};presentEncodedLength=[long](($valid|Measure-Object Length -Sum).Sum);lengths=$lengths}}|ConvertTo-Json -Compress -Depth 4;" +
            "Write-Output ('STEWARD_RDP_DVC_STAGING_PROBE:'+$probe)";
        return Task(
            "Probe RDP DVC staging state",
            command,
            timeoutSeconds: 300);
    }

    private static DevBoxCustomizationTaskRequest Task(
        string displayName,
        string command,
        int timeoutSeconds = 300) =>
        new DevBoxCustomizationTaskRequest(
            "~/powershell",
            displayName,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["command"] = command
            },
            DevBoxCustomizationExecutionAccount.System,
            timeoutSeconds).Validate();

    private static string GroupName(
        ProviderOperationId operationId,
        int index) =>
        $"steward-rdp-{operationId.Value:N}-{index:D4}";

    private static string InstallationScript(
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle,
        string fingerprint,
        int chunkCount,
        int encodedLength,
        string authenticationKey)
    {
        var version = bundle.Manifest.Version;
        var archiveHash = bundle.ArchiveSha256;
        var sessionId = request.SessionId.ToString("D");
        var hostId = request.HostId.ToString();
        var incarnationId = request.IncarnationId.ToString();
        var nonce0 = request.ConnectionNonces[0].ToString("D");
        var nonce1 = request.ConnectionNonces[1].ToString("D");
        var operationId = request.OperationId.Value.ToString("N");
        var secureArguments =
            ",'--node-signing-key-file',$nodeSigningPath,'--node-identity',$nodeTransportIdentity,'--control-signing-key-file',$controlSigningPath,'--control-identity',$controlTransportIdentity";
        var launcherSource = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(SessionLauncherSource));
        return         "$ErrorActionPreference='Stop';" +
        "$root=Join-Path $env:ProgramData 'Steward\\rdp-dvc';" +
        "$stageRoot=Join-Path $root 'staging';" +
        $"$stage=Join-Path $stageRoot '{archiveHash}\\{operationId}';" +
        "$chunks=Join-Path $stage 'chunks';" +
        $"$chunkDeadline=[DateTime]::UtcNow.AddMinutes(5);do{{Start-Sleep -Milliseconds 500;$chunkFiles=@(Get-ChildItem -LiteralPath $chunks -Filter '*.txt' -File -ErrorAction SilentlyContinue)}}while($chunkFiles.Count -ne {chunkCount} -and [DateTime]::UtcNow -lt $chunkDeadline);" +
        $"if($chunkFiles.Count -ne {chunkCount}){{throw 'RDP DVC staging incomplete'}};" +
        $"$encoded=((0..{chunkCount - 1}|ForEach-Object{{Get-Content -LiteralPath (Join-Path $chunks ($_.ToString('D4')+'.txt')) -Raw}}) -join '');" +
               $"if($encoded.Length -ne {encodedLength}){{throw 'RDP DVC base64 length mismatch'}};" +
               "$archiveBytes=[Convert]::FromBase64String($encoded);" +
               "try{" +
               "$archivePath=Join-Path $stage 'bundle.zip';" +
               "[IO.File]::WriteAllBytes($archivePath,$archiveBytes);" +
               $"if((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne '{archiveHash}'){{throw 'RDP DVC archive hash mismatch'}};" +
               "$extract=Join-Path $stage 'verified';" +
               "if(Test-Path -LiteralPath $extract){Remove-Item -LiteralPath $extract -Recurse -Force};" +
               "Expand-Archive -LiteralPath $archivePath -DestinationPath $extract -Force;" +
               "$manifestPath=Join-Path $extract 'manifest.json';" +
               "$manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json;" +
               $"if($manifest.formatVersion -ne 1 -or $manifest.version -cne '{version}'){{throw 'RDP DVC manifest version mismatch'}};" +
               "$payload=[IO.Path]::GetFullPath((Join-Path $extract 'payload'));" +
               "$prefix=$payload.TrimEnd('\\')+'\\';" +
               "$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);" +
               "foreach($entry in $manifest.files){" +
               "$relative=[string]$entry.relativePath;" +
               "if([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or $relative.Contains('\\') -or $relative.Split('/') -contains '..'){throw 'RDP DVC manifest path traversal'};" +
               "$candidate=[IO.Path]::GetFullPath((Join-Path $payload $relative));" +
               "if(!$candidate.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or !$seen.Add($relative)){throw 'RDP DVC manifest path is unsafe'};" +
               "$item=Get-Item -LiteralPath $candidate;" +
               "if($item.PSIsContainer -or $item.Length -ne [long]$entry.length -or (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -ne ([string]$entry.sha256).ToLowerInvariant()){throw 'RDP DVC payload verification failed'}" +
               "};" +
               "$actual=@(Get-ChildItem -LiteralPath $payload -File -Recurse);" +
               "if($actual.Count -ne $seen.Count){throw 'RDP DVC payload contains unmanifested files'};" +
               "$dotnet=Join-Path $env:ProgramFiles 'dotnet\\dotnet.exe';if(!(Test-Path -LiteralPath $dotnet)){throw '.NET runtime is not installed'};" +
               "$bootstrapServer=Join-Path $payload 'Steward.RdpDvc.Server.Windows.dll';$bootstrapRuntimeConfig=Join-Path $payload 'Steward.RdpDvc.Server.Windows.runtimeconfig.json';$bootstrapDepsFile=Join-Path $payload 'Steward.RdpDvc.Server.Windows.deps.json';" +
               "$executorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;" +
               $"$keyRoot=Join-Path $root 'keys';[void](New-Item -ItemType Directory -Path $keyRoot -Force);$keyDirectory=Join-Path $keyRoot '{operationId}';[void](New-Item -ItemType Directory -Path $keyDirectory -Force);& icacls.exe $keyDirectory /inheritance:r /grant:r ('*'+$executorSid+':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C|Out-Null;if($LASTEXITCODE -ne 0){{throw 'RDP DVC secure key directory ACL failed'}};" +
               $"$envelopePublicPath=Join-Path $keyDirectory 'bootstrap-envelope-{operationId}.spki';[IO.File]::WriteAllBytes($envelopePublicPath,[Convert]::FromBase64String('{Convert.ToBase64String(request.BootstrapEncryptionPublicKey.Span)}'));$keyPath=Join-Path $keyDirectory 'rdp-dvc-{operationId}.key';$nodeSigningPath=Join-Path $keyDirectory 'node-signing-{operationId}.pk8';$controlSigningPath=Join-Path $keyDirectory 'control-signing-{operationId}.spki';[IO.File]::WriteAllBytes($controlSigningPath,[Convert]::FromBase64String('{Convert.ToBase64String(request.ControlSigningPublicKey.Span)}'));$nodeTransportIdentity=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{Convert.ToBase64String(Encoding.UTF8.GetBytes(request.NodeTransportIdentity!))}'));$controlTransportIdentity=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{Convert.ToBase64String(Encoding.UTF8.GetBytes(request.ControlTransportIdentity!))}'));$envelopeOutput=& $dotnet exec --runtimeconfig $bootstrapRuntimeConfig --depsfile $bootstrapDepsFile $bootstrapServer --generate-bootstrap-secrets --operation-id '{request.OperationId.Value:D}' --session-id '{sessionId}' --host-id '{hostId}' --incarnation-id '{incarnationId}' --encryption-public-key-file $envelopePublicPath --auth-key-output $keyPath --node-signing-key-output $nodeSigningPath;if($LASTEXITCODE -ne 0){{throw 'RDP DVC secret generation failed'}};Write-Output $envelopeOutput;" +
               $"Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{launcherSource}')));" +
               "$userSessionDeadline=[DateTime]::UtcNow.AddMinutes(14);$userSession=[StewardSessionLauncher]::SelectUserSession();while($userSession -eq [uint32]::MaxValue -and [DateTime]::UtcNow -lt $userSessionDeadline){Start-Sleep -Seconds 2;$userSession=[StewardSessionLauncher]::SelectUserSession()};if($userSession -eq [uint32]::MaxValue){throw 'RDP DVC user session unavailable'};$userSid=[StewardSessionLauncher]::UserSid($userSession);if([string]::IsNullOrWhiteSpace($userSid)){throw 'RDP DVC user identity unavailable'};$userProfile=[StewardSessionLauncher]::UserProfile($userSession);if([string]::IsNullOrWhiteSpace($userProfile)){throw 'RDP DVC user profile unavailable'};" +
               "$userRoot=Join-Path $userProfile 'AppData\\Local\\StewardNode\\rdp-dvc';$versions=Join-Path $userRoot 'versions';[void](New-Item -ItemType Directory -Path $versions -Force);" +
               $"$target=Join-Path $versions '{version}';$new=$target+'.new';$old=$target+'.old';" +
               $"$runDirectory=Join-Path $userRoot 'runs\\{operationId}';[void](New-Item -ItemType Directory -Path $runDirectory -Force);$noncePath=Join-Path $runDirectory 'nonce-sequence.json';$writeNonce=$true;" +
               $"$nodeState=Join-Path $userRoot 'nodes\\{hostId}\\{incarnationId}';$portableStateRoot=Join-Path $nodeState 'portable';$credentialVaultRoot=Join-Path $nodeState 'credentials';$workspaceRoot=Join-Path $nodeState 'workspaces';$spoolRoot=Join-Path $nodeState 'spool';$keeperPipeName='Steward.Node.{request.IncarnationId.Value:N}';foreach($directory in @($nodeState,$portableStateRoot,$credentialVaultRoot,$workspaceRoot,$spoolRoot)){{[void](New-Item -ItemType Directory -Path $directory -Force)}};$nodeHostConfigPath=Join-Path $nodeState 'node-host.json';" +
               $"$nodeHostConfig=[ordered]@{{journalPath=(Join-Path $nodeState 'node.db');executionJournalPath=(Join-Path $nodeState 'execution.db');evaluationDatabasePath=(Join-Path $nodeState 'evaluation.db');workspaceRoot=$workspaceRoot;spoolRoot=$spoolRoot;spoolHighLimitBytes=4294967296;spoolHardLimitBytes=8589934592;spoolOsReserveBytes=2147483648;keeperPipeName=$keeperPipeName;nodeIncarnationId='{incarnationId}';hostId='{hostId}';terminalJournalPath=(Join-Path $nodeState 'terminal.db');maximumTerminalSessions=32;agentsEnabled=$false;agentExecutable='';agentRuntimeProfile='process-jsonl/1.0'}}|ConvertTo-Json -Compress;$nodeHostConfigPending=$nodeHostConfigPath+'.new';[IO.File]::WriteAllText($nodeHostConfigPending,$nodeHostConfig,[Text.UTF8Encoding]::new($false));Move-Item -LiteralPath $nodeHostConfigPending -Destination $nodeHostConfigPath -Force;" +
               "& icacls.exe $nodeState /inheritance:r /grant:r ('*'+$executorSid+':(OI)(CI)F') ('*'+$userSid+':(OI)(CI)F') /T /C|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC node state ACL failed'};" +
               "if(Test-Path -LiteralPath $noncePath){try{$existingNonce=Get-Content -LiteralPath $noncePath -Raw|ConvertFrom-Json;" +
               $"$writeNonce=($existingNonce.version -ne 1 -or $existingNonce.sessionId -cne '{sessionId}' -or $existingNonce.hostId -cne '{hostId}' -or $existingNonce.nodeIncarnationId -cne '{incarnationId}' -or $existingNonce.nonces.Count -ne 2 -or $existingNonce.nonces[0] -cne '{nonce0}' -or $existingNonce.nonces[1] -cne '{nonce1}')" +
               "}catch{$writeNonce=$true}};" +
               "if($writeNonce){" +
               $"$nonceState=[ordered]@{{version=1;sessionId='{sessionId}';hostId='{hostId}';nodeIncarnationId='{incarnationId}';nonces=@('{nonce0}','{nonce1}');nextIndex=0}}|ConvertTo-Json -Compress;" +
               "$noncePending=$noncePath+'.new';if(Test-Path -LiteralPath $noncePending){Remove-Item -LiteralPath $noncePending -Force};[IO.File]::WriteAllText($noncePending,$nonceState,[Text.UTF8Encoding]::new($false));Move-Item -LiteralPath $noncePending -Destination $noncePath -Force};" +
               "& icacls.exe $noncePath /inheritance:r /grant:r ('*'+$executorSid+':F') ('*'+$userSid+':M') | Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC nonce ACL failed'};" +
               $"$receipt=@{{version='{version}';archiveSha256='{archiveHash}';deploymentFingerprint='{fingerprint}'}}|ConvertTo-Json -Compress;" +
               "[IO.File]::WriteAllText((Join-Path $payload '.steward-deployment.json'),$receipt,[Text.UTF8Encoding]::new($false));" +
               "if(Test-Path -LiteralPath $new){Remove-Item -LiteralPath $new -Recurse -Force};Move-Item -LiteralPath $payload -Destination $new;" +
               "& icacls.exe $new /inheritance:r /grant:r ('*'+$executorSid+':F') '*S-1-5-32-545:RX' /T /C | Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC install ACL failed'};" +
               "if(Test-Path -LiteralPath $old){Remove-Item -LiteralPath $old -Recurse -Force};" +
               "if(Test-Path -LiteralPath $target){Move-Item -LiteralPath $target -Destination $old};" +
               "try{Move-Item -LiteralPath $new -Destination $target}catch{if(Test-Path -LiteralPath $old){Move-Item -LiteralPath $old -Destination $target};throw};" +
               "if(Test-Path -LiteralPath $old){Remove-Item -LiteralPath $old -Recurse -Force};" +
               "$runtimeDiagnostic=(((& $dotnet --list-runtimes)|Out-String).Trim() -replace '[\\r\\n]+','|');Write-Output ('STEWARD_RDP_DVC_RUNTIMES:'+$runtimeDiagnostic);" +
               "$server=Join-Path $target 'Steward.RdpDvc.Server.Windows.dll';" +
               "$runtimeConfig=Join-Path $target 'Steward.RdpDvc.Server.Windows.runtimeconfig.json';$depsFile=Join-Path $target 'Steward.RdpDvc.Server.Windows.deps.json';" +
               "$keeper=Join-Path $target 'Steward.HandleKeeper.dll';$keeperRuntimeConfig=Join-Path $target 'Steward.HandleKeeper.runtimeconfig.json';$keeperDepsFile=Join-Path $target 'Steward.HandleKeeper.deps.json';" +
               "& $dotnet exec --runtimeconfig $runtimeConfig --depsfile $depsFile $server --help;$systemHostExit=$LASTEXITCODE;Write-Output ('STEWARD_RDP_DVC_SYSTEM_HOST_EXIT:'+$systemHostExit);" +
               "& icacls.exe $keyPath /inheritance:r /grant:r ('*'+$executorSid+':F') ('*'+$userSid+':R') | Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC key ACL failed'};" +
               "& icacls.exe $nodeSigningPath /inheritance:r /grant:r ('*'+$executorSid+':F') ('*'+$userSid+':R')|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC node signing key ACL failed'};& icacls.exe $controlSigningPath /inheritance:r /grant:r ('*'+$executorSid+':F') ('*'+$userSid+':R')|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC control signing key ACL failed'};" +
               "$readinessPath=Join-Path $runDirectory 'readiness.json';" +
               $"$arguments=('\"'+$server+'\" --session-id {sessionId} --host-id {hostId} --incarnation-id {incarnationId} --auth-key-file \"'+$keyPath+'\" --nonce-sequence-file \"'+$noncePath+'\" --readiness-receipt-file \"'+$readinessPath+'\" --node-host-config \"'+$nodeHostConfigPath+'\" --portable-state-root \"'+$portableStateRoot+'\" --credential-vault-root \"'+$credentialVaultRoot+'\"');" +
               "& icacls.exe $userRoot /grant ('*'+$userSid+':RX') /T /C|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC user root ACL failed'};" +
               "& icacls.exe $root /grant ('*'+$userSid+':(X)')|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC root traverse ACL failed'};& icacls.exe $keyRoot /grant ('*'+$userSid+':(X)')|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC key root traverse ACL failed'};& icacls.exe $keyDirectory /grant ('*'+$userSid+':(X)')|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC key directory traverse ACL failed'};" +
               "& icacls.exe (Split-Path -Parent $runDirectory) /grant ('*'+$userSid+':(X)')|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC runs traverse ACL failed'};" +
               "& icacls.exe $target /grant '*S-1-5-32-545:RX' /T /C|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC package read ACL failed'};" +
               "& icacls.exe $keyPath /grant ('*'+$userSid+':R')|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC key read ACL failed'};" +
               "& icacls.exe $runDirectory /grant ('*'+$userSid+':(OI)(CI)M') /T /C|Out-Null;if($LASTEXITCODE -ne 0){throw 'RDP DVC run-state ACL failed'};" +
               "$aclDiagnostic=(((& icacls.exe $server)|Out-String).Trim() -replace '[\\r\\n]+','|');Write-Output ('STEWARD_RDP_DVC_ACL:'+$aclDiagnostic);" +
               "$keeperArgs=@('exec','--runtimeconfig',$keeperRuntimeConfig,'--depsfile',$keeperDepsFile,$keeper,'--console','--pipe',$keeperPipeName,'--node-account',$userSid);$keeperProcessId=[StewardSessionLauncher]::Start($userSession,$dotnet,$target,$keeperArgs);if($keeperProcessId -lt 0){throw ('RDP DVC Handle Keeper failed to start '+(-$keeperProcessId))};Start-Sleep -Milliseconds 500;Write-Output ('STEWARD_RDP_DVC_KEEPER_PID:'+$keeperProcessId);" +
               "$launchArgs=@('exec','--runtimeconfig',$runtimeConfig,'--depsfile',$depsFile,$server,'--session-id','" + sessionId + "','--host-id','" + hostId + "','--incarnation-id','" + incarnationId + "','--auth-key-file',$keyPath,'--nonce-sequence-file',$noncePath,'--readiness-receipt-file',$readinessPath,'--node-host-config',$nodeHostConfigPath,'--portable-state-root',$portableStateRoot,'--credential-vault-root',$credentialVaultRoot" + secureArguments + ");" +
               "$launchExit=[StewardSessionLauncher]::Run($userSession,$dotnet,$target,$launchArgs);if($launchExit -ne 0){$failurePath=$readinessPath+'.failure';$failure=if(Test-Path -LiteralPath $failurePath){Get-Content -LiteralPath $failurePath -Raw}else{'unknown'};throw ('RDP DVC endpoint failed '+$launchExit+' '+$failure)};" +
               "$remote=Get-Content -LiteralPath $readinessPath -Raw|ConvertFrom-Json;" +
               "if($remote.state -ne 'completed'){throw 'RDP DVC endpoint did not complete authenticated generations'};" +
               "$remote=Get-Content -LiteralPath $readinessPath -Raw|ConvertFrom-Json;$running=$false;$dvcReady=$remote.state -eq 'completed';" +
               "$observation=[ordered]@{version=1;scheduledTaskState='Completed';endpointProcessRunning=$running;dvcEndpointReady=$dvcReady;receipt=$remote}|ConvertTo-Json -Compress -Depth 8;Write-Output ('STEWARD_RDP_DVC_READINESS:'+$observation);" +
               "Remove-Item -LiteralPath $stage -Recurse -Force" +
               "}finally{[Array]::Clear($archiveBytes,0,$archiveBytes.Length)}";
    }

    private static string ChunkScript(
        string archiveHash,
        ProviderOperationId operationId,
        int index,
        string chunk)
    {
        var operation = operationId.Value.ToString("N");
        return
            $"$d=Join-Path $env:ProgramData 'Steward\\rdp-dvc\\staging\\{archiveHash}\\{operation}\\chunks';" +
            $"$p=Join-Path $d '{index:D4}.txt';$n='SRD-{operation}-{index:D4}';" +
            $"$w=\"[void](New-Item -ItemType Directory -Path '\"+$d+\"' -Force);[IO.File]::WriteAllText('\"+$p+\"','{chunk}',[Text.Encoding]::ASCII)\";" +
            "$q=$env:SystemRoot+'\\Temp\\'+$n+'.ps1';[IO.File]::WriteAllText($q,$w,[Text.UTF8Encoding]::new($false));" +
            "$e=$env:SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';" +
            "$a=New-ScheduledTaskAction -Execute $e -Argument ('-NoP -NonI -EP Bypass -File \"'+$q+'\"');" +
            "$r=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount;" +
            "try{Register-ScheduledTask -TaskName $n -Action $a -Principal $r -Force|Out-Null;Start-ScheduledTask -TaskName $n;" +
            "$x=[DateTime]::UtcNow.AddMinutes(2);while((Get-ScheduledTask $n).State-eq'Running'-and[DateTime]::UtcNow-lt$x){Start-Sleep -Milliseconds 250};" +
            "$i=(Get-ScheduledTaskInfo $n).LastTaskResult;if($i){throw ('RDP DVC external chunk writer failed result='+$i)}" +
            "}finally{Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $q -Force -ErrorAction SilentlyContinue}";
    }

    private const string SessionLauncherSource =
        """
        using System;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Text;
        public static class StewardSessionLauncher {
          [StructLayout(LayoutKind.Sequential)] struct SI { public int cb; public IntPtr r,d,t; public int x,y,xs,ys,xc,yc,f,flags; public short show,res; public IntPtr rb,si,so,se; }
          [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr p,t; public uint pid,tid; }
          [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct WS { public uint id; public string name; public int state; }
          [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode)] static extern bool WTSEnumerateSessions(IntPtr s,int r,int v,out IntPtr p,out int c);
          [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
          [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQueryUserToken(uint id,out IntPtr t);
          [DllImport("userenv.dll",SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr e,IntPtr t,bool i);
          [DllImport("userenv.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserProfileDirectory(IntPtr t,StringBuilder p,ref uint n);
          [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr e);
          [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr t,string a,StringBuilder c,IntPtr pa,IntPtr ta,bool ih,uint f,IntPtr e,string d,ref SI s,out PI p);
          [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint m);
          [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h,out uint c);
          [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
          [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int c,IntPtr i,int l,out int r);
          [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSidToStringSid(IntPtr s,out IntPtr v);
          [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
          public static uint SelectUserSession(){IntPtr p;int c;if(!WTSEnumerateSessions(IntPtr.Zero,0,1,out p,out c))return uint.MaxValue;uint best=uint.MaxValue;int rank=99,n=Marshal.SizeOf(typeof(WS));for(int i=0;i<c;i++){WS s=(WS)Marshal.PtrToStructure(IntPtr.Add(p,i*n),typeof(WS));int r=s.state==0?0:s.state==1?1:s.state==4?2:99;if(s.id==0||r>=rank)continue;IntPtr token;if(!WTSQueryUserToken(s.id,out token))continue;CloseHandle(token);best=s.id;rank=r;}WTSFreeMemory(p);return best;}
          static string Q(string v){return "\""+v.Replace("\"","\\\"")+"\"";}
          public static string UserSid(uint id){if(id==uint.MaxValue)return null;IntPtr token;if(!WTSQueryUserToken(id,out token))return null;int needed;GetTokenInformation(token,1,IntPtr.Zero,0,out needed);IntPtr data=Marshal.AllocHGlobal(needed);try{if(!GetTokenInformation(token,1,data,needed,out needed))return null;IntPtr text;if(!ConvertSidToStringSid(Marshal.ReadIntPtr(data),out text))return null;try{return Marshal.PtrToStringUni(text);}finally{LocalFree(text);}}finally{Marshal.FreeHGlobal(data);CloseHandle(token);}}
          public static string UserProfile(uint id){if(id==uint.MaxValue)return null;IntPtr token;if(!WTSQueryUserToken(id,out token))return null;try{uint n=0;GetUserProfileDirectory(token,null,ref n);StringBuilder p=new StringBuilder((int)n);return GetUserProfileDirectory(token,p,ref n)?p.ToString():null;}finally{CloseHandle(token);}}
          public static int Start(uint id,string exe,string working,string[] args){if(id==uint.MaxValue)return -7022;IntPtr token;if(!WTSQueryUserToken(id,out token))return -Marshal.GetLastWin32Error();IntPtr env;if(!CreateEnvironmentBlock(out env,token,false)){int e=Marshal.GetLastWin32Error();CloseHandle(token);return -e;}StringBuilder cmd=new StringBuilder(Q(exe));foreach(string a in args)cmd.Append(" ").Append(Q(a));SI si=new SI();si.cb=Marshal.SizeOf(typeof(SI));si.d=Marshal.StringToHGlobalUni("winsta0\\default");PI pi;bool ok=CreateProcessAsUser(token,exe,cmd,IntPtr.Zero,IntPtr.Zero,false,0x400,env,working,ref si,out pi);int error=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(si.d);DestroyEnvironmentBlock(env);CloseHandle(token);if(!ok)return -error;CloseHandle(pi.t);CloseHandle(pi.p);return (int)pi.pid;}
          public static int Run(uint id,string exe,string working,string[] args){if(id==uint.MaxValue)return 7022;IntPtr token;if(!WTSQueryUserToken(id,out token))return Marshal.GetLastWin32Error();IntPtr env;if(!CreateEnvironmentBlock(out env,token,false)){int e=Marshal.GetLastWin32Error();CloseHandle(token);return e;}StringBuilder cmd=new StringBuilder(Q(exe));foreach(string a in args)cmd.Append(" ").Append(Q(a));SI si=new SI();si.cb=Marshal.SizeOf(typeof(SI));si.d=Marshal.StringToHGlobalUni("winsta0\\default");PI pi;bool ok=CreateProcessAsUser(token,exe,cmd,IntPtr.Zero,IntPtr.Zero,false,0x400,env,working,ref si,out pi);int error=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(si.d);DestroyEnvironmentBlock(env);CloseHandle(token);if(!ok)return error;CloseHandle(pi.t);WaitForSingleObject(pi.p,0xffffffff);uint code;GetExitCodeProcess(pi.p,out code);CloseHandle(pi.p);return (int)code;}
        }
        """;

    private static string Fingerprint(
        DevBoxRdpDvcBootstrapRequest request,
        RdpDvcBootstrapBundle bundle,
        string keySha256)
    {
        var canonical = string.Join(
            "\n",
            request.OperationId,
            request.IdempotencyKey,
            request.Project,
            request.User,
            request.DevBox,
            bundle.Manifest.Version,
            bundle.ArchiveSha256,
            MaximumBase64ChunkCharacters,
            MaximumTasksPerGroup,
            "installer-in-final-chunk-group-v1",
            "task-scheduler-external-staging-v1",
            request.SessionId,
            request.HostId,
            request.IncarnationId,
            request.ConnectionNonces[0],
            request.ConnectionNonces[1],
            keySha256,
            request.NodeTransportIdentity ?? "",
            SigningPublicKeyHash(request.NodeSigningPrivateKey.Span),
            request.ControlTransportIdentity ?? "",
            Convert.ToHexString(
                    SHA256.HashData(
                        request.BootstrapEncryptionPublicKey.Span))
                .ToLowerInvariant(),
            request.ControlSigningPublicKey.IsEmpty
                ? ""
                : Convert.ToHexString(
                        SHA256.HashData(
                            request.ControlSigningPublicKey.Span))
                    .ToLowerInvariant());
        return Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
            .ToLowerInvariant();
    }

    private static string SigningPublicKeyHash(
        ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.IsEmpty)
            return "";
        using var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(privateKey, out var read);
        if (read != privateKey.Length)
            throw new CryptographicException(
                "The node signing key contains trailing data.");
        return Convert.ToHexString(
                SHA256.HashData(key.ExportSubjectPublicKeyInfo()))
            .ToLowerInvariant();
    }
}
