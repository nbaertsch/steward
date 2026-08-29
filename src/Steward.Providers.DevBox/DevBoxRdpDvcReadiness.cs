using System.Text.Json;

namespace Steward.Providers.DevBox;

public sealed record DevBoxRdpDvcAuthenticatedGeneration(
    int Index,
    Guid Nonce,
    int WtsSessionId,
    long Sequence,
    DateTimeOffset AuthenticatedAtUtc);

public sealed record DevBoxRdpDvcRemoteReadinessReceipt(
    int Version,
    string State,
    int ProcessId,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    int NextGeneration,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<DevBoxRdpDvcAuthenticatedGeneration>
        AuthenticatedGenerations);

public sealed record DevBoxRdpDvcReadinessObservation(
    int Version,
    string ScheduledTaskState,
    bool EndpointProcessRunning,
    bool DvcEndpointReady,
    DevBoxRdpDvcRemoteReadinessReceipt Receipt)
{
    public DevBoxRdpDvcReadinessObservation Validate(
        DevBoxRdpDvcBootstrapRequest expected)
    {
        expected.Validate();
        return Validate(
            expected.SessionId,
            expected.HostId,
            expected.IncarnationId,
            expected.ConnectionNonces);
    }

    public DevBoxRdpDvcReadinessObservation Validate(
        Guid sessionId,
        Steward.Domain.HostId hostId,
        Steward.Domain.NodeIncarnationId incarnationId,
        IReadOnlyList<Guid> connectionNonces)
    {
        if (sessionId == Guid.Empty ||
            hostId.Value == Guid.Empty ||
            incarnationId.Value == Guid.Empty ||
            connectionNonces.Count != 2 ||
            connectionNonces.Any(nonce => nonce == Guid.Empty) ||
            connectionNonces.Distinct().Count() != 2)
            throw new ArgumentException(
                "Expected RDP DVC readiness identity is invalid.");
        if (Version != 1 ||
            Receipt.Version != 1 ||
            Receipt.SessionId != sessionId ||
            Receipt.HostId != hostId.Value ||
            Receipt.NodeIncarnationId !=
                incarnationId.Value ||
            Receipt.ProcessId < 0 ||
            Receipt.ProcessId == 0 &&
            (EndpointProcessRunning ||
             Receipt.State != "waitingForActiveRdpSession") ||
            Receipt.NextGeneration is < 0 or > 2 ||
            Receipt.State is not (
                "waitingForActiveRdpSession" or
                "handshaking" or
                "authenticatedGeneration" or
                "waitingForReconnect" or
                "completed" or
                "exhausted") ||
            Receipt.UpdatedAtUtc >
                DateTimeOffset.UtcNow.AddMinutes(5) ||
            Receipt.UpdatedAtUtc <
                DateTimeOffset.UtcNow.Subtract(TimeSpan.FromHours(24)) ||
            Receipt.AuthenticatedGenerations.Count > 2 ||
            Receipt.AuthenticatedGenerations.Any(generation =>
                generation.Index is < 0 or > 1 ||
                generation.Nonce !=
                    connectionNonces[generation.Index] ||
                generation.WtsSessionId <= 0 ||
                generation.Sequence != 1) ||
            Receipt.AuthenticatedGenerations
                .Select(generation => generation.Index)
                .Distinct()
                .Count() != Receipt.AuthenticatedGenerations.Count ||
            DvcEndpointReady !=
            (Receipt.State == "completed" ||
             EndpointProcessRunning &&
             Receipt.State == "authenticatedGeneration"))
            throw new InvalidDataException(
                "Remote RDP DVC readiness observation is invalid.");
        return this;
    }
}

public static class DevBoxRdpDvcReadiness
{
    public const string LogMarker = "STEWARD_RDP_DVC_READINESS:";

    public static DevBoxCustomizationTaskRequest CreateStatusTask(
        DevBoxRdpDvcBootstrapRequest expected)
    {
        expected.Validate();
        var session = expected.SessionId.ToString("D");
        var host = expected.HostId.ToString();
        var incarnation = expected.IncarnationId.ToString();
        var nonce0 = expected.ConnectionNonces[0].ToString("D");
        var nonce1 = expected.ConnectionNonces[1].ToString("D");
        var command =
            "$ErrorActionPreference='Stop';" +
            "$root='C:\\ProgramData\\Steward\\rdp-dvc';" +
            "$path=Join-Path $root 'readiness.json';" +
            "$startup=Join-Path $env:ProgramData 'Microsoft\\Windows\\Start Menu\\Programs\\Startup\\StewardRdpDvcEndpoint.vbs';" +
            "$taskState=if(Test-Path -LiteralPath $startup){'Installed'}else{'Missing'};" +
            "$versions=Join-Path $root 'versions';$endpoint=@(Get-ChildItem -LiteralPath $versions -Directory -ErrorAction SilentlyContinue|Where-Object{Test-Path -LiteralPath (Join-Path $_.FullName 'Steward.RdpDvc.Server.Windows.dll')}).Count;" +
            "$key=Test-Path -LiteralPath 'C:\\ProgramData\\Steward\\keys\\rdp-dvc.key';$nonce=Test-Path -LiteralPath (Join-Path $root 'nonce-sequence.json');" +
            "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$system=$identity.User.Value -eq 'S-1-5-18';$interactive=@($identity.Groups|Where-Object{$_.Value -eq 'S-1-5-4'}).Count -gt 0;" +
            "$persistence=('system='+$system+'; interactive='+$interactive+'; root='+(Test-Path -LiteralPath $root)+'; endpoint='+$endpoint+'; key='+$key+'; nonce='+$nonce+'; startup='+$taskState);Write-Output ('STEWARD_PERSISTENCE:'+$persistence);" +
            "if(!(Test-Path -LiteralPath $path)){throw ('RDP DVC readiness receipt is unavailable; '+$persistence)};" +
            "$receipt=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json;" +
            $"if($receipt.version -ne 1 -or $receipt.sessionId -cne '{session}' -or $receipt.hostId -cne '{host}' -or $receipt.nodeIncarnationId -cne '{incarnation}'){{throw 'RDP DVC readiness identity mismatch'}};" +
            $"$expected=@('{nonce0}','{nonce1}');foreach($generation in $receipt.authenticatedGenerations){{if($generation.index -lt 0 -or $generation.index -gt 1 -or $generation.nonce -cne $expected[[int]$generation.index]){{throw 'RDP DVC readiness nonce mismatch'}}}};" +
            "$running=([int]$receipt.processId -gt 0) -and [bool](Get-Process -Id ([int]$receipt.processId) -ErrorAction SilentlyContinue);" +
            "$ready=$running -and ($receipt.state -eq 'authenticatedGeneration' -or $receipt.state -eq 'completed');" +
            "$observation=[ordered]@{version=1;scheduledTaskState=$taskState;endpointProcessRunning=$running;dvcEndpointReady=$ready;receipt=$receipt}|ConvertTo-Json -Compress -Depth 8;" +
            $"Write-Output ('{LogMarker}'+$observation)";
        return new DevBoxCustomizationTaskRequest(
            "~/powershell",
            "Read Steward RDP DVC endpoint readiness",
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["command"] = command
            },
            DevBoxCustomizationExecutionAccount.System,
            300).Validate();
    }

    public static DevBoxRdpDvcReadinessObservation ParseLog(
        string log,
        DevBoxRdpDvcBootstrapRequest expected)
    {
        if (log.Length > DevBoxCustomizationClient.MaximumResponseBytes)
            throw new InvalidDataException(
                "RDP DVC readiness log exceeds its bound.");
        var marker = log.LastIndexOf(LogMarker, StringComparison.Ordinal);
        if (marker < 0)
            throw new InvalidDataException(
                "RDP DVC readiness marker is missing.");
        var json = log[(marker + LogMarker.Length)..];
        var lineEnd = json.IndexOfAny(['\r', '\n']);
        if (lineEnd >= 0)
            json = json[..lineEnd];
        try
        {
            return (JsonSerializer.Deserialize<
                        DevBoxRdpDvcReadinessObservation>(
                        json,
                        new JsonSerializerOptions(
                            JsonSerializerDefaults.Web))
                    ?? throw new InvalidDataException(
                        "RDP DVC readiness observation is empty."))
                .Validate(expected);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "RDP DVC readiness observation is malformed.",
                exception);
        }
    }
}
