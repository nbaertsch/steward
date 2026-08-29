using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure;
using Azure.Developer.DevCenter;
using Steward.DevBox.Windows;
using Steward.Domain;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;
using Steward.Transport;

const string Consent =
    "I_UNDERSTAND_THIS_MUTATES_THE_RETAINED_DEV_BOX_CUSTOMIZATION";

if (args is ["--help"])
{
    Console.WriteLine(
        """
        Steward.DevBox.BootstrapDeploy
          --endpoint HTTPS_DEV_CENTER --project NAME --user me|GUID --devbox NAME
          --bundle ZIP --operation-id GUID --idempotency-key VALUE --status-query-id GUID
          --session-id GUID --host-id GUID --incarnation-id GUID
          --nonce-0 GUID --nonce-1 GUID --auth-key-file PATH
          --checkpoint-key-file PATH --handle-key-file PATH
          --state-directory PATH --receipt PATH
          --consent I_UNDERSTAND_THIS_MUTATES_THE_RETAINED_DEV_BOX_CUSTOMIZATION

        Optional dual attestation:
          --node-signing-private-key PATH --node-identity VALUE
          --control-signing-private-key PATH --control-identity VALUE
          --attested-receipt PATH
        """);
    return 0;
}

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

byte[]? authenticationKey = null;
byte[]? checkpointKey = null;
byte[]? handleKey = null;
byte[]? nodeTransportPrivateKey = null;
byte[]? controlTransportPublicKey = null;
var stage = "options";
try
{
    var options = Options.Parse(args);
    if (options.Consent != Consent)
        throw new InvalidOperationException(
            $"Live customization is disabled. Pass --consent {Consent}.");

    stage = "keys";
    checkpointKey = ReadKey(
        options.CheckpointKeyFile,
        32,
        32,
        "checkpoint");
    handleKey = ReadKey(
        options.HandleKeyFile,
        32,
        32,
        "handle");
    using var bootstrapEncryption = LoadOrCreateBootstrapEncryptionKey(
        options.StateDirectory,
        options.OperationId.Value,
        checkpointKey);
    authenticationKey = SHA256.HashData(
        bootstrapEncryption.ExportSubjectPublicKeyInfo());
    RequireDistinct(authenticationKey, checkpointKey, handleKey);
    if (options.NodeSigningPrivateKeyFile is not null)
    {
        using var nodeTransportKey = ReadSigningKey(
            options.NodeSigningPrivateKeyFile);
        using var controlTransportKey = ReadSigningKey(
            options.ControlSigningPrivateKeyFile!);
        nodeTransportPrivateKey =
            nodeTransportKey.ExportPkcs8PrivateKey();
        controlTransportPublicKey =
            controlTransportKey.ExportSubjectPublicKeyInfo();
    }

    stage = "bundle";
    var bundle = RdpDvcBootstrapBundle.Load(options.BundlePath);
    var request = new DevBoxRdpDvcBootstrapRequest(
        options.OperationId,
        options.IdempotencyKey,
        options.Project,
        options.User,
        options.DevBox,
        options.SessionId,
        options.HostId,
        options.IncarnationId,
        options.ConnectionNonces,
        authenticationKey,
        options.NodeIdentity,
        nodeTransportPrivateKey is null
            ? ReadOnlyMemory<byte>.Empty
            : nodeTransportPrivateKey,
        options.ControlIdentity,
        controlTransportPublicKey is null
            ? ReadOnlyMemory<byte>.Empty
            : controlTransportPublicKey,
        bootstrapEncryption.ExportSubjectPublicKeyInfo()).Validate();
    var planned = DevBoxRdpDvcBootstrapPlan.Create(request, bundle);
    for (var index = 0; index < planned.Groups.Count; index++)
        Console.Error.WriteLine(
            $"BOOTSTRAP PLAN GROUP {index}: tasks={planned.Groups[index].Tasks.Count}; " +
            $"commandChars={planned.Groups[index].Tasks.Sum(task => task.Parameters.Values.Sum(value => value.Length))}");

    stage = "identity";
    var defaultStore = new DevBoxIdentityStore();
    var connectionIdentity = new DevBoxConnectionIdentityService(
        defaultStore,
        new DevBoxConnectionIdentityStore());
    var connectionStatus = await connectionIdentity.StatusAsync(
            cancellation.Token)
        .ConfigureAwait(false);
    if (connectionStatus.Outcome != DevBoxConnectionIdentityOutcome.Ready ||
        !connectionStatus.Enrolled)
        throw new InvalidOperationException(
            "Production DevBoxConnectionIdentity is not ready.");

    var devCenterIdentity = new DevBoxIdentityService(defaultStore);
    var credential = new DevBoxSilentTokenCredential(devCenterIdentity);
    var sdkClient = new DevBoxesClient(options.Endpoint, credential);
    var customization = new DevBoxCustomizationClient(
        options.Endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdkClient.Pipeline));
    var nonterminalGroups = (await customization.ListAsync(
            options.Project,
            options.User,
            options.DevBox,
            cancellation.Token)
        .ConfigureAwait(false))
        .Where(group =>
            !Succeeded(group.Status) &&
            !group.Status.Equals(
                "Failed",
                StringComparison.OrdinalIgnoreCase) &&
            !group.Status.Equals(
                "ValidationFailed",
                StringComparison.OrdinalIgnoreCase))
        .OrderBy(group => group.StartTime ?? DateTimeOffset.MaxValue)
        .ToArray();
    Console.Error.WriteLine(
        $"BOOTSTRAP QUEUE: nonterminal={nonterminalGroups.Length}");
    foreach (var group in nonterminalGroups.Take(20))
        Console.Error.WriteLine(
            $"  QUEUED GROUP: {group.Name}; status={group.Status}; " +
            $"started={group.StartTime?.ToString("O") ?? "none"}");
    if (options.RestartStalledCustomization &&
        nonterminalGroups is
        [
            {
                Status: "NotStarted",
                StartTime: null
            }
        ])
    {
        stage = "dispatch-recovery";
        await RecoverStalledDispatchAsync(
                sdkClient,
                planned,
                nonterminalGroups,
                options,
                cancellation.Token)
            .ConfigureAwait(false);
    }
    using var checkpointProtector =
        new AesGcmDevBoxRdpDvcBootstrapCheckpointProtector(
            checkpointKey);
    var durableStore = new EncryptedFileDevBoxRdpDvcBootstrapStore(
        Path.Combine(options.StateDirectory, "operations"),
        checkpointProtector);
    var deployer = new DevBoxRdpDvcBootstrapDeployer(
        customization,
        durableStore,
        new HmacDevBoxOperationHandleProtector(handleKey));
    var prior = await durableStore.LoadAsync(
            options.OperationId,
            options.IdempotencyKey,
            cancellation.Token)
        .ConfigureAwait(false);
    if (prior is not null)
    {
        Console.Error.WriteLine(
            $"BOOTSTRAP CHECKPOINT: group={prior.GroupIndex}/{prior.Operation.Groups.Count}; completed={prior.Completed}");
        if (!prior.Completed &&
            prior.GroupIndex < prior.Operation.Groups.Count)
        {
            try
            {
                var active = await customization.GetAsync(
                        request.Project,
                        request.User,
                        request.DevBox,
                        prior.Operation.Groups[prior.GroupIndex].Name,
                        cancellation.Token)
                    .ConfigureAwait(false);
                Console.Error.WriteLine(
                    $"BOOTSTRAP ACTIVE GROUP: {active.Status}; tasks={active.Tasks.Count}");
                foreach (var task in active.Tasks)
                {
                    Console.Error.WriteLine(
                        $"  ACTIVE TASK: {task.Status}");
                    if (task.Status.Equals(
                            "Failed",
                            StringComparison.OrdinalIgnoreCase))
                    {
                        var log = await customization.GetTaskLogAsync(
                                task.LogUri,
                                cancellation.Token)
                            .ConfigureAwait(false);
                        Console.Error.WriteLine(
                            $"    ERROR-CODE: {ClassifyBootstrapLog(log)}");
                    }
                }
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(
                    $"BOOTSTRAP ACTIVE GROUP: unavailable ({exception.GetType().Name})");
            }
        }
    }

    stage = "deploy";
    var result = await deployer.DeployAsync(
            request,
            bundle,
            cancellation.Token)
        .ConfigureAwait(false);
    var deferredCheckpoint = await durableStore.LoadAsync(
            options.OperationId,
            options.IdempotencyKey,
            cancellation.Token)
        .ConfigureAwait(false);
    if (deferredCheckpoint is not null &&
        deferredCheckpoint.GroupIndex ==
            planned.Groups.Count - 1 &&
        planned.Groups[^1].Tasks.All(task =>
            task.RunAs ==
                DevBoxCustomizationExecutionAccount.System) &&
        result.Status == ProviderOperationStatus.Running)
    {
        var deferredDeadline =
            DateTimeOffset.UtcNow + options.Timeout;
        DevBoxCustomizationGroupResult deferred;
        while (true)
        {
            await Task.Delay(options.PollInterval, cancellation.Token)
                .ConfigureAwait(false);
            deferred = await customization.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    planned.Groups[^1].Name,
                    cancellation.Token)
                .ConfigureAwait(false);
            var installerRunning =
                deferred.Tasks.Count == planned.Groups[^1].Tasks.Count &&
                deferred.Tasks
                    .Take(deferred.Tasks.Count - 1)
                    .All(task => Succeeded(task.Status)) &&
                deferred.Tasks[^1].Status.Equals(
                    "Running",
                    StringComparison.OrdinalIgnoreCase);
            if (installerRunning || Terminal(deferred.Status))
                break;
            if (DateTimeOffset.UtcNow >= deferredDeadline)
                throw new TimeoutException(
                    "Deferred bootstrap did not reach the endpoint installer.");
        }
        if (deferred.Status is not ("NotStarted" or "Running"))
            throw new InvalidOperationException(
                "Deferred user bootstrap did not remain accepted.");
        await MaterializeBootstrapEnvelopeAsync(
                customization,
                deferred.Tasks[^1].LogUri,
                bootstrapEncryption,
                request,
                options.AuthenticationKeyFile,
                options.PollInterval,
                options.Timeout,
                cancellation.Token)
            .ConfigureAwait(false);
        var deferredReceipt =
            DevBoxRdpDvcBootstrapReceipts.CreateDeploymentPending(
                request,
                bundle,
                result);
        await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
                options.ReceiptPath,
                deferredReceipt,
                cancellation.Token)
            .ConfigureAwait(false);
        if (options.NodeSigningPrivateKeyFile is not null)
        {
            using var controlKey = ReadSigningKey(
                options.ControlSigningPrivateKeyFile!);
            var attested =
                DevBoxRdpDvcBootstrapReceipts.AttestPending(
                deferredReceipt,
                options.ControlIdentity!,
                controlKey);
            await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
                    options.AttestedReceiptPath!,
                    attested,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        Console.WriteLine(
            "Deferred SYSTEM bootstrap receipt written; awaiting headless RDCore user session.");
        return 0;
    }
    var deadline = DateTimeOffset.UtcNow + options.Timeout;
    var notStartedSince = new Dictionary<string, DateTimeOffset>(
        StringComparer.Ordinal);
    while (result.Status is
           ProviderOperationStatus.Accepted or
           ProviderOperationStatus.Running)
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException(
                "Dev Box bootstrap customization did not reach terminal status.");
        await Task.Delay(options.PollInterval, cancellation.Token)
            .ConfigureAwait(false);
        stage = "reconcile";
        result = await deployer.ReconcileAsync(
                result.Handle
                ?? throw new InvalidDataException(
                    "Running bootstrap operation has no durable handle."),
                cancellation.Token)
            .ConfigureAwait(false);
        if (options.RestartStalledCustomization &&
            result.Status is
                ProviderOperationStatus.Accepted or
                ProviderOperationStatus.Running)
        {
            var queued = (await customization.ListAsync(
                    options.Project,
                    options.User,
                    options.DevBox,
                    cancellation.Token)
                .ConfigureAwait(false))
                .Where(group =>
                    !Succeeded(group.Status) &&
                    !group.Status.Equals(
                        "Failed",
                        StringComparison.OrdinalIgnoreCase) &&
                    !group.Status.Equals(
                        "ValidationFailed",
                        StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (queued is
                [
                    {
                        Status: "NotStarted",
                        StartTime: null
                    } stalled
                ])
            {
                var now = DateTimeOffset.UtcNow;
                if (!notStartedSince.TryGetValue(
                        stalled.Name,
                        out var observed))
                {
                    notStartedSince[stalled.Name] = now;
                }
                else if (now - observed >= TimeSpan.FromMinutes(2))
                {
                    stage = "dispatch-recovery";
                    await RecoverStalledDispatchAsync(
                            sdkClient,
                            planned,
                            queued,
                            options,
                            cancellation.Token)
                        .ConfigureAwait(false);
                    notStartedSince.Remove(stalled.Name);
                    stage = "reconcile";
                }
            }
            else
            {
                notStartedSince.Clear();
            }
        }
    }
    if (result.Status != ProviderOperationStatus.Succeeded)
    {
        await PrintSafeTaskStatusesAsync(
                customization,
                request,
                bundle,
                cancellation.Token)
            .ConfigureAwait(false);
        throw new InvalidOperationException(
            $"Dev Box bootstrap ended in {result.Status}.");
    }
    if (options.RestartAfterBootstrap)
    {
        stage = "post-bootstrap-restart";
        await RestartDevBoxAsync(
                sdkClient,
                options,
                $"bootstrap-{options.OperationId.Value:N}",
                cancellation.Token)
            .ConfigureAwait(false);
    }

    stage = "readiness";
    var readiness = await ReadInstallerReadinessAsync(
            customization,
            request,
            planned.Groups[^1].Name,
            cancellation.Token)
        .ConfigureAwait(false);
    if (readiness.Receipt.State == "completed" &&
        readiness.Receipt.NextGeneration == 2 &&
        readiness.Receipt.AuthenticatedGenerations.Count == 2)
    {
        Console.WriteLine(
            "Bootstrap terminal readiness verified from the successful installer log; signed pre-connect receipt preserved.");
        return 0;
    }
    stage = "receipt";
    var receipt = DevBoxRdpDvcBootstrapReceipts.Create(
        request,
        bundle,
        result,
        readiness);
    await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
            options.ReceiptPath,
            receipt,
            cancellation.Token)
        .ConfigureAwait(false);

    if (options.NodeSigningPrivateKeyFile is not null)
    {
        using var nodeKey = ReadSigningKey(
            options.NodeSigningPrivateKeyFile);
        using var controlKey = ReadSigningKey(
            options.ControlSigningPrivateKeyFile!);
        stage = "attestation";
        var attested = DevBoxRdpDvcBootstrapReceipts.Attest(
            receipt,
            options.NodeIdentity!,
            nodeKey,
            options.ControlIdentity!,
            controlKey);
        await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
                options.AttestedReceiptPath!,
                attested,
                cancellation.Token)
            .ConfigureAwait(false);
    }

    Console.WriteLine(
        $"Bootstrap receipt written to {Path.GetFileName(options.ReceiptPath)}; remote state={readiness.Receipt.State}, pre-connect-ready={receipt.PreConnectReady}.");
    return 0;
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine(
        "CANCELLED: durable bootstrap state is preserved.");
    return 130;
}
catch (Exception exception)
{
    var safeDetail = exception switch
    {
        RequestFailedException request =>
            $"HTTP {request.Status}; code={request.ErrorCode ?? "none"}",
        ArgumentException or InvalidDataException or InvalidOperationException =>
            exception.Message,
        _ => "details suppressed"
    };
    Console.Error.WriteLine(
        $"FAILED ({stage}/{exception.GetType().Name}): {safeDetail}; durable state is preserved.");
    return 1;
}
finally
{
    Zero(authenticationKey);
    Zero(checkpointKey);
    Zero(handleKey);
    Zero(nodeTransportPrivateKey);
    Zero(controlTransportPublicKey);
}

static async Task<DevBoxRdpDvcReadinessObservation>
    ReadInstallerReadinessAsync(
        DevBoxCustomizationClient client,
        DevBoxRdpDvcBootstrapRequest request,
        string groupName,
        CancellationToken cancellationToken)
{
    var group = await client.GetAsync(
            request.Project,
            request.User,
            request.DevBox,
            groupName,
            cancellationToken)
        .ConfigureAwait(false);
    if (!Succeeded(group.Status) ||
        group.Tasks.Count == 0 ||
        !Succeeded(group.Tasks[^1].Status))
        throw new InvalidOperationException(
            "The completed bootstrap installer result is unavailable.");
    var log = await client.GetTaskLogAsync(
            group.Tasks[^1].LogUri,
            cancellationToken)
        .ConfigureAwait(false);
    return DevBoxRdpDvcReadiness.ParseLog(log, request);
}

static async Task MaterializeBootstrapEnvelopeAsync(
    DevBoxCustomizationClient client,
    Uri logUri,
    RSA encryptionKey,
    DevBoxRdpDvcBootstrapRequest request,
    string authenticationKeyPath,
    TimeSpan pollInterval,
    TimeSpan timeout,
    CancellationToken cancellationToken)
{
    const string marker = "STEWARD_RDP_DVC_BOOTSTRAP_ENVELOPE:";
    var deadline = DateTimeOffset.UtcNow + timeout;
    string? encoded = null;
    while (DateTimeOffset.UtcNow < deadline)
    {
        try
        {
            var log = await client.GetTaskLogAsync(
                    logUri,
                    cancellationToken)
                .ConfigureAwait(false);
            var markerIndex = log.LastIndexOf(
                marker,
                StringComparison.Ordinal);
            if (markerIndex >= 0)
            {
                encoded = log[(markerIndex + marker.Length)..];
                var lineEnd = encoded.IndexOfAny(['\r', '\n']);
                if (lineEnd >= 0)
                    encoded = encoded[..lineEnd];
                encoded = encoded.Trim();
                break;
            }
        }
        catch (RequestFailedException exception)
            when (exception.Status is 404 or 409)
        {
        }
        await Task.Delay(pollInterval, cancellationToken)
            .ConfigureAwait(false);
    }
    if (string.IsNullOrWhiteSpace(encoded))
        throw new TimeoutException(
            "The encrypted bootstrap envelope was not published.");
    var ciphertext = Convert.FromBase64String(encoded);
    var payload = RdpDvcBootstrapEnvelope.Decrypt(
        encryptionKey,
        ciphertext);
    try
    {
        if (payload.OperationId != request.OperationId.Value ||
            payload.SessionId != request.SessionId ||
            payload.HostId != request.HostId.Value ||
            payload.NodeIncarnationId != request.IncarnationId.Value)
            throw new InvalidDataException(
                "The bootstrap envelope identity is invalid.");
        WritePrivateFile(
            authenticationKeyPath,
            payload.AuthenticationKey);
        var nodePublicPath = authenticationKeyPath +
            ".node-transport-public.pem";
        WritePrivateFile(
            nodePublicPath,
            Encoding.ASCII.GetBytes(
                PemEncoding.WriteString(
                    "PUBLIC KEY",
                    payload.NodeSigningPublicKey)));
        Console.WriteLine(
            $"Bootstrap secrets materialized to protected local files; node transport public key={Path.GetFileName(nodePublicPath)}.");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(ciphertext);
        CryptographicOperations.ZeroMemory(
            payload.AuthenticationKey);
        CryptographicOperations.ZeroMemory(
            payload.NodeSigningPublicKey);
    }
}

static void WritePrivateFile(string path, ReadOnlySpan<byte> content)
{
    var fullPath = Path.GetFullPath(path);
    var directory = Path.GetDirectoryName(fullPath)
        ?? throw new InvalidOperationException(
            "A private file path requires a directory.");
    var current = WindowsIdentity.GetCurrent().User
        ?? throw new InvalidOperationException(
            "The current Windows identity has no SID.");
    Directory.CreateDirectory(directory);
    if (File.GetAttributes(directory)
        .HasFlag(FileAttributes.ReparsePoint))
        throw new IOException(
            "The private file directory is unsafe.");
    var directorySecurity = new DirectorySecurity();
    directorySecurity.SetOwner(current);
    directorySecurity.SetAccessRuleProtection(true, false);
    directorySecurity.AddAccessRule(new(
        current,
        FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit |
        InheritanceFlags.ObjectInherit,
        PropagationFlags.None,
        AccessControlType.Allow));
    new DirectoryInfo(directory).SetAccessControl(directorySecurity);
    var pending = Path.Combine(
        directory,
        $".{Path.GetFileName(fullPath)}." +
        $"{RandomNumberGenerator.GetHexString(16)}.new");
    var security = new FileSecurity();
    security.SetOwner(current);
    security.SetAccessRuleProtection(true, false);
    security.AddAccessRule(new(
        current,
        FileSystemRights.FullControl,
        AccessControlType.Allow));
    try
    {
        using (var stream = new FileStream(
                   pending,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   4096,
                   FileOptions.WriteThrough))
        {
            new FileInfo(pending).SetAccessControl(security);
            stream.Write(content);
            stream.Flush(flushToDisk: true);
        }
        File.Move(pending, fullPath, overwrite: true);
    }
    finally
    {
        if (File.Exists(pending))
            File.Delete(pending);
    }
}

static async Task PrintSafeTaskStatusesAsync(
    DevBoxCustomizationClient client,
    DevBoxRdpDvcBootstrapRequest request,
    RdpDvcBootstrapBundle bundle,
    CancellationToken cancellationToken)
{
    var operation = DevBoxRdpDvcBootstrapPlan.Create(request, bundle);
    for (var index = 0; index < operation.Groups.Count; index++)
    {
        try
        {
            var group = await client.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    operation.Groups[index].Name,
                    cancellationToken)
                .ConfigureAwait(false);
            Console.Error.WriteLine(
                $"BOOTSTRAP GROUP {index}: {group.Status}");
            foreach (var task in group.Tasks)
            {
                Console.Error.WriteLine(
                    $"  TASK {task.DisplayName}: {task.Status}");
                if (task.Status.Equals(
                        "Failed",
                        StringComparison.OrdinalIgnoreCase))
                {
                    var log = await client.GetTaskLogAsync(
                            task.LogUri,
                            cancellationToken)
                        .ConfigureAwait(false);
                    Console.Error.WriteLine(
                        $"    ERROR-CODE: {ClassifyBootstrapLog(log)}");
                    Console.Error.WriteLine(
                        $"    SAFE-DIAGNOSTIC: {SafeBootstrapLogDiagnostic(log)}");
                }
            }
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"BOOTSTRAP GROUP {index}: status unavailable ({exception.GetType().Name})");
        }
    }
}

static async Task RecoverStalledDispatchAsync(
    DevBoxesClient client,
    DevBoxRdpDvcBootstrapOperation operation,
    IReadOnlyList<DevBoxCustomizationGroupSummary> nonterminalGroups,
    Options options,
    CancellationToken cancellationToken)
{
    var expected = operation.Groups
        .Select(static group => group.Name)
        .ToHashSet(StringComparer.Ordinal);
    if (nonterminalGroups.Count != 1 ||
        !expected.Contains(nonterminalGroups[0].Name) ||
        nonterminalGroups[0].Status != "NotStarted" ||
        nonterminalGroups[0].StartTime is not null)
        throw new InvalidOperationException(
            "Dispatch recovery requires exactly the current unstarted bootstrap group.");
    var directory = Path.Combine(
        options.StateDirectory,
        "dispatch-recovery");
    Directory.CreateDirectory(directory);
    var path = Path.Combine(
        directory,
        $"{options.OperationId.Value:N}-{nonterminalGroups[0].Name}.phase");
    var phase = File.Exists(path)
        ? await File.ReadAllTextAsync(path, cancellationToken)
            .ConfigureAwait(false)
        : null;
    if (phase is null)
    {
        await WriteRecoveryPhaseAsync(path, "stop-intent", cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            "BOOTSTRAP DISPATCH RECOVERY: stopping the idle evidence Dev Box.");
        await client.StopDevBoxAsync(
                WaitUntil.Completed,
                options.Project,
                options.User,
                options.DevBox,
                false,
                new RequestContext
                {
                    CancellationToken = cancellationToken
                })
            .ConfigureAwait(false);
        await WriteRecoveryPhaseAsync(path, "stopped", cancellationToken)
            .ConfigureAwait(false);
        phase = "stopped";
    }
    else if (phase == "stop-intent")
    {
        throw new InvalidOperationException(
            "Dev Box dispatch recovery stopped at an ambiguous power boundary.");
    }
    if (phase == "stopped")
    {
        Console.Error.WriteLine(
            "BOOTSTRAP DISPATCH RECOVERY: starting the evidence Dev Box.");
        await client.StartDevBoxAsync(
                WaitUntil.Completed,
                options.Project,
                options.User,
                options.DevBox,
                new RequestContext
                {
                    CancellationToken = cancellationToken
                })
            .ConfigureAwait(false);
        await WriteRecoveryPhaseAsync(path, "completed", cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            "BOOTSTRAP DISPATCH RECOVERY: restart completed.");
        return;
    }
    if (phase != "completed")
        throw new InvalidDataException(
            "Dev Box dispatch recovery state is invalid.");
}

static async Task RestartDevBoxAsync(
    DevBoxesClient client,
    Options options,
    string recoveryId,
    CancellationToken cancellationToken)
{
    var directory = Path.Combine(
        options.StateDirectory,
        "post-bootstrap-restart");
    Directory.CreateDirectory(directory);
    var path = Path.Combine(
        directory,
        $"{recoveryId}.phase");
    var phase = File.Exists(path)
        ? await File.ReadAllTextAsync(path, cancellationToken)
            .ConfigureAwait(false)
        : null;
    if (phase is null)
    {
        await WriteRecoveryPhaseAsync(path, "stop-intent", cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            "BOOTSTRAP COMMIT RECOVERY: stopping the idle evidence Dev Box.");
        await client.StopDevBoxAsync(
                WaitUntil.Completed,
                options.Project,
                options.User,
                options.DevBox,
                false,
                new RequestContext
                {
                    CancellationToken = cancellationToken
                })
            .ConfigureAwait(false);
        await WriteRecoveryPhaseAsync(path, "stopped", cancellationToken)
            .ConfigureAwait(false);
        phase = "stopped";
    }
    else if (phase == "stop-intent")
    {
        throw new InvalidOperationException(
            "Post-bootstrap restart stopped at an ambiguous power boundary.");
    }
    if (phase == "stopped")
    {
        Console.Error.WriteLine(
            "BOOTSTRAP COMMIT RECOVERY: starting the evidence Dev Box.");
        await client.StartDevBoxAsync(
                WaitUntil.Completed,
                options.Project,
                options.User,
                options.DevBox,
                new RequestContext
                {
                    CancellationToken = cancellationToken
                })
            .ConfigureAwait(false);
        await WriteRecoveryPhaseAsync(path, "completed", cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            "BOOTSTRAP COMMIT RECOVERY: restart completed.");
        return;
    }
    if (phase != "completed")
        throw new InvalidDataException(
            "Post-bootstrap restart state is invalid.");
}

static async Task WriteRecoveryPhaseAsync(
    string path,
    string phase,
    CancellationToken cancellationToken)
{
    var pending = path + ".new";
    await File.WriteAllTextAsync(
            pending,
            phase,
            new UTF8Encoding(false),
            cancellationToken)
        .ConfigureAwait(false);
    File.Move(pending, path, overwrite: true);
}

static string ClassifyBootstrapLog(string log)
{
    var diagnosticLog = string.Join(
        '\n',
        log.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Where(line => !line.Contains(
                "Running command",
                StringComparison.OrdinalIgnoreCase)));
    var known = new Dictionary<string, string>(
        StringComparer.OrdinalIgnoreCase)
    {
        ["staging is missing"] = "STAGING_MISSING",
        ["chunk sequence is incomplete"] = "CHUNK_SEQUENCE_INCOMPLETE",
        ["bundle is incomplete"] = "BUNDLE_INCOMPLETE",
        ["base64 length mismatch"] = "BASE64_LENGTH_MISMATCH",
        ["archive hash mismatch"] = "ARCHIVE_HASH_MISMATCH",
        ["manifest version mismatch"] = "MANIFEST_VERSION_MISMATCH",
        ["manifest path"] = "MANIFEST_PATH_INVALID",
        ["payload verification failed"] = "PAYLOAD_HASH_MISMATCH",
        ["payload contains unmanifested"] = "UNMANIFESTED_PAYLOAD",
        ["root ACL failed"] = "ROOT_ACL_FAILED",
        ["key ACL failed"] = "KEY_ACL_FAILED",
        ["install ACL failed"] = "INSTALL_ACL_FAILED",
        [".NET runtime is not installed"] = "DOTNET_RUNTIME_MISSING"
    };
    foreach (var item in known)
        if (diagnosticLog.Contains(
                item.Key,
                StringComparison.OrdinalIgnoreCase))
            return item.Value;
    return "UNCLASSIFIED_REMOTE_TASK_FAILURE";
}

static string SafeBootstrapLogDiagnostic(string log)
{
    var lines = log.Split(
        ['\r', '\n'],
        StringSplitOptions.RemoveEmptyEntries);
    var candidates = lines
        .Where(line =>
            line.Contains(
                "STEWARD_PERSISTENCE",
                StringComparison.Ordinal) ||
            line.Contains(
                "STEWARD_RDP_DVC_ACL:",
                StringComparison.Ordinal) ||
            line.Contains(
                "STEWARD_RDP_DVC_RUNTIMES:",
                StringComparison.Ordinal) ||
            line.Contains(
                "STEWARD_RDP_DVC_SYSTEM_HOST_EXIT:",
                StringComparison.Ordinal))
        .TakeLast(2)
        .Concat(lines.Where(line =>
            !line.Contains(
                "Running command",
                StringComparison.OrdinalIgnoreCase) &&
            (line.Contains("error", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("exception", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("unavailable", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("mismatch", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("limit", StringComparison.OrdinalIgnoreCase)))
            .TakeLast(8));
    var diagnostic = string.Join(" | ", candidates);
    if (diagnostic.Length == 0)
        diagnostic = string.Join(
            " | ",
            log.Split(
                    ['\r', '\n'],
                    StringSplitOptions.RemoveEmptyEntries)
                .Where(line => !line.Contains(
                    "Running command",
                    StringComparison.OrdinalIgnoreCase))
                .TakeLast(3));
    if (diagnostic.Length == 0)
        diagnostic = "No diagnostic line was returned.";
    diagnostic = Regex.Replace(
        diagnostic,
        "[A-Za-z0-9+/=_-]{48,}",
        "<redacted-token>",
        RegexOptions.CultureInvariant);
    diagnostic = Regex.Replace(
        diagnostic,
        @"https?://\S+",
        "<redacted-uri>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    var bytes = Encoding.UTF8.GetBytes(log);
    var hash = Convert.ToHexString(SHA256.HashData(bytes))
        .ToLowerInvariant();
    if (diagnostic.Length > 1024)
        diagnostic = diagnostic[^1024..];
    return $"{diagnostic} (bytes={bytes.Length}; sha256={hash})";
}

static bool Terminal(string status) =>
    Succeeded(status) ||
    status.Equals("Failed", StringComparison.OrdinalIgnoreCase) ||
    status.Equals("Canceled", StringComparison.OrdinalIgnoreCase) ||
    status.Equals("Cancelled", StringComparison.OrdinalIgnoreCase);

static bool Succeeded(string status) =>
    status.Equals("Succeeded", StringComparison.OrdinalIgnoreCase) ||
    status.Equals("Completed", StringComparison.OrdinalIgnoreCase);

static byte[] ReadKey(
    string path,
    int minimum,
    int maximum,
    string description)
{
    var fullPath = ValidatePrivateKeyPath(path, description);
    byte[] key;
    using (var stream = new FileStream(
               fullPath,
               FileMode.Open,
               FileAccess.Read,
               FileShare.Read,
               4096,
               FileOptions.SequentialScan))
    {
        key = new byte[stream.Length];
        stream.ReadExactly(key);
    }
    if (key.Length < minimum || key.Length > maximum)
    {
        CryptographicOperations.ZeroMemory(key);
        throw new InvalidDataException(
            $"{description} key length is invalid.");
    }
    return key;
}

static void RequireDistinct(params byte[][] keys)
{
    for (var left = 0; left < keys.Length; left++)
    for (var right = left + 1; right < keys.Length; right++)
        if (keys[left].Length == keys[right].Length &&
            CryptographicOperations.FixedTimeEquals(
                keys[left],
                keys[right]))
            throw new InvalidDataException(
                "Bootstrap authentication and persistence keys must be distinct.");
}

static ECDsa ReadSigningKey(string path)
{
    var fullPath = ValidatePrivateKeyPath(path, "signing");
    var key = ECDsa.Create();
    try
    {
        key.ImportFromPem(File.ReadAllText(fullPath));
        _ = key.ExportParameters(includePrivateParameters: true);
        return key;
    }
    catch
    {
        key.Dispose();
        throw;
    }
}

static string ValidatePrivateKeyPath(
        string path,
        string description)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException(
                $"{description} key path is invalid.");
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException(
                $"{description} key directory is invalid.");
        var root = Path.GetPathRoot(directory)
            ?? throw new InvalidOperationException(
                $"{description} key root is invalid.");
        var currentPath = root;
        foreach (var segment in directory[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            currentPath = Path.Combine(currentPath, segment);
            if (Directory.Exists(currentPath) &&
                File.GetAttributes(currentPath)
                    .HasFlag(FileAttributes.ReparsePoint))
                throw new IOException(
                    $"{description} key path contains a reparse point.");
        }
        if (!File.Exists(fullPath) ||
            File.GetAttributes(fullPath)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException(
                $"{description} key file is unavailable.");
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var system = new SecurityIdentifier(
            WellKnownSidType.LocalSystemSid,
            null);
        var security = new FileInfo(fullPath).GetAccessControl();
        if (!current.Equals(
                security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException(
                $"{description} key owner is invalid.");
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType == AccessControlType.Allow &&
                !current.Equals(rule.IdentityReference) &&
                !system.Equals(rule.IdentityReference))
                throw new UnauthorizedAccessException(
                    $"{description} key grants unintended access.");
        return fullPath;
}

static RSA LoadOrCreateBootstrapEncryptionKey(
        string stateDirectory,
        Guid operationId,
        ReadOnlySpan<byte> checkpointKey)
    {
        var directory = Path.Combine(
            Path.GetFullPath(stateDirectory),
            "bootstrap-envelopes");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{operationId:N}.key");
        var aad = operationId.ToByteArray();
        if (File.Exists(path))
        {
            var stored = File.ReadAllBytes(path);
            if (stored.Length < 12 + 16 + 1)
                throw new InvalidDataException(
                    "The bootstrap envelope key state is malformed.");
            var cleartext = new byte[stored.Length - 28];
            try
            {
                using var aes = new AesGcm(checkpointKey, 16);
                aes.Decrypt(
                    stored.AsSpan(0, 12),
                    stored.AsSpan(28),
                    stored.AsSpan(12, 16),
                    cleartext,
                    aad);
                var rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(cleartext, out var read);
                if (read != cleartext.Length)
                {
                    rsa.Dispose();
                    throw new InvalidDataException(
                        "The bootstrap envelope key contains trailing data.");
                }
                return rsa;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stored);
                CryptographicOperations.ZeroMemory(cleartext);
            }
        }
        var created = RSA.Create(3072);
        var privateKey = created.ExportPkcs8PrivateKey();
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[privateKey.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(checkpointKey, 16);
            aes.Encrypt(nonce, privateKey, ciphertext, tag, aad);
            var stored = new byte[nonce.Length + tag.Length + ciphertext.Length];
            nonce.CopyTo(stored, 0);
            tag.CopyTo(stored, nonce.Length);
            ciphertext.CopyTo(stored, nonce.Length + tag.Length);
            var pending = path + ".new";
            File.WriteAllBytes(pending, stored);
            File.Move(pending, path, overwrite: false);
            CryptographicOperations.ZeroMemory(stored);
            return created;
        }
        catch
        {
            created.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
}

static void Zero(byte[]? value)
{
    if (value is not null)
        CryptographicOperations.ZeroMemory(value);
}

internal sealed record Options(
    Uri Endpoint,
    string Project,
    string User,
    string DevBox,
    string BundlePath,
    ProviderOperationId OperationId,
    string IdempotencyKey,
    Guid StatusQueryId,
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId IncarnationId,
    IReadOnlyList<Guid> ConnectionNonces,
    string AuthenticationKeyFile,
    string CheckpointKeyFile,
    string HandleKeyFile,
    string StateDirectory,
    string ReceiptPath,
    TimeSpan PollInterval,
    TimeSpan Timeout,
    string Consent,
    string? NodeSigningPrivateKeyFile,
    string? NodeIdentity,
    string? ControlSigningPrivateKeyFile,
    string? ControlIdentity,
    string? AttestedReceiptPath,
    bool RestartStalledCustomization,
    bool RestartAfterBootstrap,
    bool RestartStalledStatus)
{
    private const string RestartConsent =
        "I_CONFIRM_THIS_DEV_BOX_HAS_NO_ACTIVE_WORK_AND_MAY_BE_RESTARTED";

    internal static Options Parse(string[] arguments)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Length; index += 2)
        {
            if (index + 1 >= arguments.Length ||
                !Known.Contains(arguments[index]) ||
                !values.TryAdd(arguments[index], arguments[index + 1]))
                throw new ArgumentException(
                    "Bootstrap deployment arguments are invalid.");
        }
        var endpointText = Required(values, "--endpoint");
        if (!Uri.TryCreate(
                endpointText,
                UriKind.Absolute,
                out var endpoint))
            throw new ArgumentException("Dev Center endpoint is invalid.");
        var pollSeconds = Integer(
            values,
            "--poll-seconds",
            defaultValue: 5,
            minimum: 1,
            maximum: 60);
        var timeoutSeconds = Integer(
            values,
            "--timeout-seconds",
            defaultValue: 900,
            minimum: 30,
            maximum: 7200);
        var nodeKey = Optional(values, "--node-signing-private-key");
        var nodeIdentity = Optional(values, "--node-identity");
        var controlKey = Optional(
            values,
            "--control-signing-private-key");
        var controlIdentity = Optional(values, "--control-identity");
        var attestedPath = Optional(values, "--attested-receipt");
        var restart = Optional(
            values,
            "--restart-stalled-customization");
        if (restart is not null && restart != RestartConsent)
            throw new ArgumentException(
                "The stalled-customization restart consent is invalid.");
        var restartAfterBootstrap = Optional(
            values,
            "--restart-after-bootstrap");
        if (restartAfterBootstrap is not null &&
            restartAfterBootstrap != RestartConsent)
            throw new ArgumentException(
                "The post-bootstrap restart consent is invalid.");
        var restartStalledStatus = Optional(
            values,
            "--restart-stalled-status");
        if (restartStalledStatus is not null &&
            restartStalledStatus != RestartConsent)
            throw new ArgumentException(
                "The stalled-status restart consent is invalid.");
        var attestationCount = new[]
        {
            nodeKey,
            nodeIdentity,
            controlKey,
            controlIdentity,
            attestedPath
        }.Count(value => value is not null);
        if (attestationCount is not 0 and not 5)
            throw new ArgumentException(
                "Node and Control attestation options must be supplied together.");
        return new(
            endpoint,
            Required(values, "--project"),
            Required(values, "--user"),
            Required(values, "--devbox"),
            Path.GetFullPath(Required(values, "--bundle")),
            new ProviderOperationId(GuidValue(values, "--operation-id")),
            Required(values, "--idempotency-key"),
            GuidValue(values, "--status-query-id"),
            GuidValue(values, "--session-id"),
            new HostId(GuidValue(values, "--host-id")),
            new NodeIncarnationId(
                GuidValue(values, "--incarnation-id")),
            [
                GuidValue(values, "--nonce-0"),
                GuidValue(values, "--nonce-1")
            ],
            Path.GetFullPath(Required(values, "--auth-key-file")),
            Path.GetFullPath(
                Required(values, "--checkpoint-key-file")),
            Path.GetFullPath(Required(values, "--handle-key-file")),
            Path.GetFullPath(Required(values, "--state-directory")),
            Path.GetFullPath(Required(values, "--receipt")),
            TimeSpan.FromSeconds(pollSeconds),
            TimeSpan.FromSeconds(timeoutSeconds),
            Required(values, "--consent"),
            nodeKey is null ? null : Path.GetFullPath(nodeKey),
            nodeIdentity,
            controlKey is null ? null : Path.GetFullPath(controlKey),
            controlIdentity,
            attestedPath is null ? null : Path.GetFullPath(attestedPath),
            restart is not null,
            restartAfterBootstrap is not null,
            restartStalledStatus is not null);
    }

    private static readonly HashSet<string> Known =
    [
        "--endpoint",
        "--project",
        "--user",
        "--devbox",
        "--bundle",
        "--operation-id",
        "--idempotency-key",
        "--status-query-id",
        "--session-id",
        "--host-id",
        "--incarnation-id",
        "--nonce-0",
        "--nonce-1",
        "--auth-key-file",
        "--checkpoint-key-file",
        "--handle-key-file",
        "--state-directory",
        "--receipt",
        "--poll-seconds",
        "--timeout-seconds",
        "--consent",
        "--node-signing-private-key",
        "--node-identity",
        "--control-signing-private-key",
        "--control-identity",
        "--attested-receipt",
        "--restart-stalled-customization",
        "--restart-after-bootstrap",
        "--restart-stalled-status"
    ];

    private static string Required(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var value) &&
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException(
                $"Required argument '{name}' is missing.");

    private static string? Optional(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.GetValueOrDefault(name);

    private static Guid GuidValue(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        Guid.TryParse(Required(values, name), out var value) &&
        value != Guid.Empty
            ? value
            : throw new ArgumentException(
                $"Argument '{name}' must be a nonempty GUID.");

    private static int Integer(
        IReadOnlyDictionary<string, string> values,
        string name,
        int defaultValue,
        int minimum,
        int maximum)
    {
        var text = values.GetValueOrDefault(name);
        if (text is null)
            return defaultValue;
        if (!int.TryParse(text, out var value) ||
            value < minimum ||
            value > maximum)
            throw new ArgumentException(
                $"Argument '{name}' is outside its bound.");
        return value;
    }

}

internal sealed record StatusQueryIntent(
    int Version,
    Guid QueryId,
    Guid OperationId,
    string Project,
    string User,
    string DevBox,
    string BundleVersion,
    string ArchiveSha256)
{
    internal static async Task RecordAsync(
        string stateDirectory,
        Guid queryId,
        Options options,
        RdpDvcBootstrapBundle bundle,
        CancellationToken cancellationToken)
    {
        var directory = Path.Combine(
            Path.GetFullPath(stateDirectory),
            "status-queries");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{queryId:N}.json");
        var intent = new StatusQueryIntent(
            1,
            queryId,
            options.OperationId.Value,
            options.Project,
            options.User,
            options.DevBox,
            bundle.Manifest.Version,
            bundle.ArchiveSha256);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            intent,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (File.Exists(path))
        {
            var existing = await File.ReadAllBytesAsync(
                    path,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!existing.AsSpan().SequenceEqual(bytes))
                throw new InvalidOperationException(
                    "Status query ID was reused with different intent.");
            return;
        }
        var pending = path + ".new";
        await using (var stream = new FileStream(
                         pending,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await stream.WriteAsync(bytes, cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        File.Move(pending, path);
    }
}
