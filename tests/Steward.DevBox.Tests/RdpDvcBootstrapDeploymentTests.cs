using System.Security.Cryptography;
using System.ComponentModel;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Core;
using Steward.Domain;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;
using Steward.RdpDvc.Server.Windows;

namespace Steward.DevBox.Tests;

public sealed class RdpDvcBootstrapDeploymentTests : IDisposable
{
    private readonly string _artifacts = Path.Combine(
        AppContext.BaseDirectory,
        "bootstrap-test-artifacts",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void BundleIsDeterministicFrameworkDependentAndManifested()
    {
        var publish = CreatePublishDirectory();

        var first = RdpDvcBootstrapBundle.CreateFromPublishDirectory(
            publish,
            "1.2.3");
        var second = RdpDvcBootstrapBundle.CreateFromPublishDirectory(
            publish,
            "1.2.3");

        Assert.Equal(
            first.Archive.ToArray(),
            second.Archive.ToArray());
        Assert.Equal(first.ArchiveSha256, second.ArchiveSha256);
        Assert.All(first.Manifest.Files, entry =>
        {
            Assert.True(entry.Length > 0);
            Assert.Matches("^[0-9a-f]{64}$", entry.Sha256);
        });
        Assert.DoesNotContain(
            first.Manifest.Files,
            entry => entry.RelativePath.EndsWith(
                ".exe",
                StringComparison.OrdinalIgnoreCase));
        var path = Path.Combine(_artifacts, "deterministic.tar.br");
        File.WriteAllBytes(path, first.Archive.ToArray());
        var loaded = RdpDvcBootstrapBundle.Load(path);
        Assert.Equal(first.Manifest.FormatVersion, loaded.Manifest.FormatVersion);
        Assert.Equal(first.Manifest.Version, loaded.Manifest.Version);
        Assert.Equal(first.Manifest.Files, loaded.Manifest.Files);
    }

    [Fact]
    public void PlanBoundsAndSequencesTypedSystemTasks()
    {
        var bundle = Bundle();
        var request = Request();
        var operation = DevBoxRdpDvcBootstrapPlan.Create(request, bundle);
        var tasks = operation.Groups.SelectMany(group => group.Tasks).ToArray();
        var commands = tasks.Select(task => task.Parameters["command"]).ToArray();
        var stagingRoot =
            $"{bundle.ArchiveSha256}\\{request.OperationId.Value:N}";

        Assert.All(operation.Groups, group =>
        {
            Assert.InRange(
                group.Tasks.Count,
                1,
                DevBoxRdpDvcBootstrapPlan.MaximumTasksPerGroup);
            Assert.InRange(
                DevBoxCustomizationClient.MeasureApplyRequestBytes(
                    group.Tasks),
                1,
                256 * 1024);
        });
        Assert.InRange(
            operation.Groups.Count,
            1,
            DevBoxRdpDvcBootstrapPlan.MaximumGroups);
        Assert.All(tasks, task =>
        {
            Assert.Equal("~/powershell", task.Name);
            Assert.Equal(
                DevBoxCustomizationExecutionAccount.System,
                task.RunAs);
            Assert.True(task.Parameters["command"].Length <= 64 * 1024);
        });
        Assert.True(tasks.Length >= 2);
        Assert.Contains(
            "Register-ScheduledTask",
            operation.Groups[^1].Tasks[0].Parameters["command"],
            StringComparison.Ordinal);
        Assert.Contains(
            "$encoded=((0..",
            operation.Groups[^1].Tasks[^1].Parameters["command"],
            StringComparison.Ordinal);
        Assert.All(
            commands,
            command => Assert.Contains(
                stagingRoot,
                command,
                StringComparison.Ordinal));
        Assert.All(
            commands[..^1],
            command =>
            {
                Assert.Contains(
                    "Register-ScheduledTask",
                    command,
                    StringComparison.Ordinal);
                Assert.Contains(
                    "-LogonType ServiceAccount",
                    command,
                    StringComparison.Ordinal);
                Assert.Contains(
                    "external chunk writer failed result=",
                    command,
                    StringComparison.Ordinal);
            });
        var install = commands[^1];
        Assert.Contains(
            "$encoded=((0..",
            install,
            StringComparison.Ordinal);
        Assert.Contains("Get-FileHash", install, StringComparison.Ordinal);
        Assert.Contains(
            "manifest path traversal",
            install,
            StringComparison.Ordinal);
        Assert.Contains("icacls.exe", install, StringComparison.Ordinal);
        Assert.Contains(
            "StewardSessionLauncher",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "Move-Item -LiteralPath $target -Destination $old",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "RDP DVC endpoint failed",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "SelectUserSession",
            install,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "runtimeBytes",
            install,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Steward-rdp-dvc",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "--nonce-sequence-file",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "--readiness-receipt-file",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "--node-host-config",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "--portable-state-root",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "--credential-vault-root",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "nodes\\",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "agentsEnabled=$false",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "RDP DVC node state ACL failed",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "Steward.HandleKeeper.dll",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "STEWARD_RDP_DVC_KEEPER_PID:",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "'--console'",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "bootstrapServer",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            "userSessionDeadline",
            install,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "--rdp-session-id",
            install,
            StringComparison.Ordinal);
        Assert.Contains(
            DevBoxRdpDvcReadiness.LogMarker,
            install,
            StringComparison.Ordinal);
    }

    [Fact]
    public void EndpointRecoveryUsesVerifiedUserInstallAndDetachedLaunch()
    {
        var request = Request();
        var bundle = Bundle();

        var task =
            DevBoxRdpDvcBootstrapPlan.CreateEndpointRecoveryTask(
                request,
                bundle);
        var command = task.Parameters["command"];
        var startupMatch = Regex.Match(
            command,
            @"WriteAllBytes\(\$startupPath,\[Convert\]::FromBase64String\('(?<value>[A-Za-z0-9+/=]+)'\)\)");
        Assert.True(startupMatch.Success);
        var startup = Encoding.UTF8.GetString(
            Convert.FromBase64String(
                startupMatch.Groups["value"].Value));

        Assert.Equal(
            DevBoxCustomizationExecutionAccount.System,
            task.RunAs);
        Assert.Equal(300, task.TimeoutInSeconds);
        Assert.Contains(
            "StewardNode\\rdp-dvc\\versions\\" +
            bundle.Manifest.Version,
            startup,
            StringComparison.Ordinal);
        Assert.Contains(
            "$runDirectory=Join-Path $env:LOCALAPPDATA " +
            "'StewardNode\\rdp-dvc\\runs\\",
            startup,
            StringComparison.Ordinal);
        Assert.Contains(
            "launcher.lock",
            startup,
            StringComparison.Ordinal);
        Assert.Contains(
            "RedirectStandardError $serverErr",
            startup,
            StringComparison.Ordinal);
        Assert.Contains(
            "Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "StewardRdpDvcEndpoint-",
            command,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "$launchExit=[StewardSessionLauncher]::Run",
            startup,
            StringComparison.Ordinal);
        Assert.Contains(
            "--node-account",
            startup,
            StringComparison.Ordinal);
        Assert.Contains(
            "Register-ScheduledTask",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "$keeperAction=New-ScheduledTaskAction -Execute $dotnet",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "$taskAction=New-ScheduledTaskAction -Execute $dotnet",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "HandleKeeper-",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "-ExecutionTimeLimit ([TimeSpan]::Zero)",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "-LogonType Interactive -RunLevel Limited",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "S-1-5-21-*",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "S-1-12-1-*",
            command,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            Convert.ToBase64String(request.AuthenticationKey.Span),
            command,
            StringComparison.Ordinal);
        Assert.True(command.Length <= 64 * 1024);
    }

    [Fact]
    public void StagingProbeReportsOnlyOperationScopedChunkMetadata()
    {
        var request = Request();
        var bundle = Bundle();

        var task = DevBoxRdpDvcBootstrapPlan.CreateStagingProbeTask(
            request,
            bundle);
        var command = task.Parameters["command"];

        Assert.Equal(
            DevBoxCustomizationExecutionAccount.System,
            task.RunAs);
        Assert.Contains(
            "$env:ProgramData",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            $"{bundle.ArchiveSha256}\\" +
            request.OperationId.Value.ToString("N"),
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "STEWARD_RDP_DVC_STAGING_PROBE:",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "expectedCount",
            command,
            StringComparison.Ordinal);
        Assert.Contains(
            "presentEncodedLength",
            command,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            Convert.ToBase64String(bundle.Archive),
            command,
            StringComparison.Ordinal);
        Assert.True(command.Length <= 64 * 1024);
    }

    [Fact]
    public void NodeSessionTreatsClosedWindowsHandlesAsReconnectable()
    {
        Assert.True(DvcDisconnectClassifier.IsExpected(
            new Win32Exception(12)));
        Assert.True(DvcDisconnectClassifier.IsExpected(
            new Win32Exception(233)));
        Assert.False(DvcDisconnectClassifier.IsExpected(
            new Win32Exception(5)));
    }

    [Theory]
    [InlineData("Failed")]
    [InlineData("TimedOut")]
    [InlineData("failed")]
    public void FailedFinalInstallerStatusesAreRecoverable(string taskStatus)
    {
        Assert.True(
            DevBoxRdpDvcBootstrapRecovery.CanRecoverFinalInstaller(
                "Failed",
                [taskStatus]));
        Assert.False(
            DevBoxRdpDvcBootstrapRecovery.CanRecoverFinalInstaller(
                "Succeeded",
                [taskStatus]));
        Assert.False(
            DevBoxRdpDvcBootstrapRecovery.CanRecoverFinalInstaller(
                "Failed",
                [taskStatus, taskStatus]));
    }

    [Fact]
    public void DispatchRestartIsAllowedOnlyBeforeStagingBegins()
    {
        Assert.True(
            DevBoxRdpDvcBootstrapRecovery.CanRestartWithoutLosingStaging(
                "operation-0000",
                "operation-0000"));
        Assert.False(
            DevBoxRdpDvcBootstrapRecovery.CanRestartWithoutLosingStaging(
                "other-operation-0001",
                "operation-0000"));
        Assert.True(
            DevBoxRdpDvcBootstrapRecovery.CanRestartWithoutLosingStaging(
                "operation-0014",
                "operation-0000"));
    }

    [Fact]
    public void TransportIdentitiesAreEncodedAndAffectFingerprint()
    {
        using var node = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var control = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var malicious = "node');Write-Output PWN;#";
        var request = Request() with
        {
            NodeTransportIdentity = malicious,
            NodeSigningPrivateKey = node.ExportPkcs8PrivateKey(),
            ControlTransportIdentity = "control",
            ControlSigningPublicKey =
                control.ExportSubjectPublicKeyInfo()
        };

        var first = DevBoxRdpDvcBootstrapPlan.Create(request, Bundle());
        var install = first.Groups[0].Tasks[^1].Parameters["command"];
        Assert.DoesNotContain(
            Convert.ToBase64String(request.AuthenticationKey.Span),
            install,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            Convert.ToBase64String(request.NodeSigningPrivateKey.Span),
            install,
            StringComparison.Ordinal);
        Assert.DoesNotContain(malicious, install, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Write-Output PWN",
            install,
            StringComparison.Ordinal);

        var changedIdentity = DevBoxRdpDvcBootstrapPlan.Create(
            request with { NodeTransportIdentity = "different" },
            Bundle());
        using var replacement = ECDsa.Create(
            ECCurve.NamedCurves.nistP256);
        var changedKey = DevBoxRdpDvcBootstrapPlan.Create(
            request with
            {
                NodeSigningPrivateKey =
                    replacement.ExportPkcs8PrivateKey()
            },
            Bundle());

        Assert.NotEqual(
            first.Intent.Fingerprint,
            changedIdentity.Intent.Fingerprint);
        Assert.NotEqual(
            first.Intent.Fingerprint,
            changedKey.Intent.Fingerprint);
    }

    [Fact]
    public void OperationsWithSameArchiveUseIsolatedStagingRoots()
    {
        var bundle = Bundle();
        var firstRequest = Request();
        var secondRequest = firstRequest with
        {
            OperationId = ProviderOperationId.New(),
            IdempotencyKey = "bootstrap-attempt-2"
        };

        var firstCommands = DevBoxRdpDvcBootstrapPlan
            .Create(firstRequest, bundle)
            .Groups.SelectMany(group => group.Tasks)
            .Select(task => task.Parameters["command"])
            .ToArray();
        var secondCommands = DevBoxRdpDvcBootstrapPlan
            .Create(secondRequest, bundle)
            .Groups.SelectMany(group => group.Tasks)
            .Select(task => task.Parameters["command"])
            .ToArray();
        var firstRoot =
            $"{bundle.ArchiveSha256}\\{firstRequest.OperationId.Value:N}";
        var secondRoot =
            $"{bundle.ArchiveSha256}\\{secondRequest.OperationId.Value:N}";

        Assert.NotEqual(firstRoot, secondRoot);
        Assert.All(
            firstCommands,
            command => Assert.Contains(
                firstRoot,
                command,
                StringComparison.Ordinal));
        Assert.All(
            firstCommands,
            command => Assert.DoesNotContain(
                secondRoot,
                command,
                StringComparison.Ordinal));
        Assert.All(
            secondCommands,
            command => Assert.Contains(
                secondRoot,
                command,
                StringComparison.Ordinal));
        Assert.All(
            secondCommands,
            command => Assert.DoesNotContain(
                firstRoot,
                command,
                StringComparison.Ordinal));
    }

    [Fact]
    public void PendingReceiptAttestsOnlyObservedDeploymentState()
    {
        var request = Request();
        var bundle = Bundle();
        var result = new ProviderOperationResult(
            ProviderOperationStatus.Running,
            new(
                request.OperationId,
                request.IdempotencyKey,
                DevBoxRdpDvcBootstrapPlan.ProviderName,
                "opaque"),
            null);

        var receipt =
            DevBoxRdpDvcBootstrapReceipts.CreateDeploymentPending(
                request,
                bundle,
                result);

        Assert.False(receipt.PreConnectReady);
        Assert.Equal(
            "Running",
            receipt.RemoteReadiness.ScheduledTaskState);
        Assert.Equal(
            "deploymentPending",
            receipt.RemoteReadiness.RemoteState);
        Assert.False(receipt.RemoteReadiness.EndpointProcessRunning);
    }

    [Fact]
    public async Task DurableCheckpointPrecedesEveryEffectAndRetryIsIdempotent()
    {
        var events = new List<string>();
        var transport = new BootstrapTransport(events);
        var store = new BootstrapStore(events);
        var deployer = Deployer(transport, store);
        var request = Request();
        var secret = Convert.ToBase64String(
            request.AuthenticationKey.Span);

        var first = await CompleteAsync(
            deployer,
            await deployer.DeployAsync(request, Bundle()));
        var callCount = transport.Calls.Count;
        var second = await deployer.DeployAsync(request, Bundle());

        Assert.Equal(ProviderOperationStatus.Succeeded, first.Status);
        Assert.Equal(ProviderOperationStatus.Succeeded, second.Status);
        Assert.Equal(callCount, transport.Calls.Count);
        Assert.NotNull(store.Checkpoint);
        Assert.True(store.Checkpoint.Completed);
        foreach (var call in transport.Calls.Where(call =>
                     call.Method == RequestMethod.Put))
        {
            var groupIndex = GroupIndex(call.Group);
            var record = events.IndexOf($"record:{groupIndex}");
            var effect = events.IndexOf($"put:{groupIndex}");
            Assert.InRange(record, 0, effect - 1);
        }
        Assert.DoesNotContain(
            secret,
            first.Handle!.OpaqueHandle,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            secret,
            JsonSerializer.Serialize(first.Metadata),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            secret,
            first.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReconcileResumesRunningGroupWithoutDuplicatePut()
    {
        var events = new List<string>();
        var transport = new BootstrapTransport(events)
        {
            FirstPutStatus = "Running"
        };
        var store = new BootstrapStore(events);
        var deployer = Deployer(transport, store);

        var started = await deployer.DeployAsync(Request(), Bundle());
        var completed = await CompleteAsync(
            deployer,
            await deployer.ReconcileAsync(started.Handle!));

        Assert.Equal(ProviderOperationStatus.Running, started.Status);
        Assert.Equal(ProviderOperationStatus.Succeeded, completed.Status);
        Assert.Equal(
            1,
            transport.Calls.Count(call =>
                call.Method == RequestMethod.Put &&
                GroupIndex(call.Group) == 0));
        Assert.Contains(
            transport.Calls,
            call => call.Method == RequestMethod.Get &&
                    GroupIndex(call.Group) == 0);
    }

    [Fact]
    public async Task Reconcile_keeps_existing_not_started_group_without_duplicate_put()
    {
        var events = new List<string>();
        var transport = new BootstrapTransport(events)
        {
            FirstPutStatus = "NotStarted",
            GetStatus = "NotStarted"
        };
        var store = new BootstrapStore(events);
        var deployer = Deployer(transport, store);

        var started = await deployer.DeployAsync(Request(), Bundle());
        var completed = await deployer.ReconcileAsync(started.Handle!);

        Assert.Equal(ProviderOperationStatus.Running, started.Status);
        Assert.Equal(ProviderOperationStatus.Running, completed.Status);
        Assert.Equal(
            1,
            transport.Calls.Count(call =>
                call.Method == RequestMethod.Put &&
                GroupIndex(call.Group) == 0));
    }

    [Theory]
    [InlineData("../escape.dll")]
    [InlineData("nested/../../escape.dll")]
    [InlineData("C:/escape.dll")]
    [InlineData("nested\\escape.dll")]
    public void ManifestRejectsPathTraversal(string path)
    {
        Assert.Throws<ArgumentException>(() =>
            new RdpDvcBootstrapManifestEntry(
                    path,
                    1,
                    new string('a', 64))
                .Validate());
    }

    [Fact]
    public async Task ReusedIdempotencyKeyRejectsDifferentSecretBeforeEffect()
    {
        var events = new List<string>();
        var transport = new BootstrapTransport(events)
        {
            FirstPutStatus = "Running"
        };
        var store = new BootstrapStore(events);
        var deployer = Deployer(transport, store);
        var request = Request();
        _ = await deployer.DeployAsync(request, Bundle());
        var calls = transport.Calls.Count;
        var changedKey = Enumerable.Repeat((byte)0x7f, 32).ToArray();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            deployer.DeployAsync(
                request with { AuthenticationKey = changedKey },
                Bundle()));
        Assert.Equal(calls, transport.Calls.Count);
    }

    [Fact]
    public async Task EncryptedFileStoreDurablyResumesWithoutPlaintextSecret()
    {
        var events = new List<string>();
        var transport = new BootstrapTransport(events)
        {
            FirstPutStatus = "Running"
        };
        var request = Request();
        var directory = Path.Combine(_artifacts, "durable-store");
        using var protector =
            new AesGcmDevBoxRdpDvcBootstrapCheckpointProtector(
                Enumerable.Repeat((byte)0x5a, 32).ToArray());
        var firstStore = new EncryptedFileDevBoxRdpDvcBootstrapStore(
            directory,
            protector);
        var firstDeployer = new DevBoxRdpDvcBootstrapDeployer(
            new DevBoxCustomizationClient(
                new("https://center.westus.devcenter.azure.com/"),
                transport),
            firstStore,
            TestProvider.Protector());

        var started = await firstDeployer.DeployAsync(request, Bundle());
        var checkpointPath = Assert.Single(
            Directory.GetFiles(directory, "*.checkpoint"));
        var persisted = await File.ReadAllBytesAsync(checkpointPath);
        Assert.DoesNotContain(
            Convert.ToBase64String(request.AuthenticationKey.Span),
            Encoding.UTF8.GetString(persisted),
            StringComparison.Ordinal);

        var restarted = new DevBoxRdpDvcBootstrapDeployer(
            new DevBoxCustomizationClient(
                new("https://center.westus.devcenter.azure.com/"),
                transport),
            new EncryptedFileDevBoxRdpDvcBootstrapStore(
                directory,
                protector),
            TestProvider.Protector());
        var completed = await CompleteAsync(
            restarted,
            await restarted.ReconcileAsync(started.Handle!));

        Assert.Equal(ProviderOperationStatus.Succeeded, completed.Status);
    }

    [Fact]
    public async Task NonceSequenceConsumesTwoGenerationsExactlyOnce()
    {
        var directory = Path.Combine(_artifacts, "server-state");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "nonces.json");
        var request = Request();
        await File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(
                new DvcConnectionNonceSequence(
                    1,
                    request.SessionId,
                    request.HostId.Value,
                    request.IncarnationId.Value,
                    request.ConnectionNonces,
                    0),
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var store = new DvcConnectionNonceSequenceStore(path);

        var first = await store.PeekNextAsync(
            request.SessionId,
            request.HostId.Value,
            request.IncarnationId.Value,
            default);
        var repeated = await store.PeekNextAsync(
            request.SessionId,
            request.HostId.Value,
            request.IncarnationId.Value,
            default);
        await store.CommitAsync(
            request.SessionId,
            request.HostId.Value,
            request.IncarnationId.Value,
            first,
            default);
        var second = await store.PeekNextAsync(
            request.SessionId,
            request.HostId.Value,
            request.IncarnationId.Value,
            default);

        Assert.Equal(0, first.Index);
        Assert.Equal(request.ConnectionNonces[0], first.Nonce);
        Assert.Equal(first, repeated);
        Assert.Equal(1, second.Index);
        Assert.Equal(request.ConnectionNonces[1], second.Nonce);
        await store.CommitAsync(
            request.SessionId,
            request.HostId.Value,
            request.IncarnationId.Value,
            second,
            default);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.PeekNextAsync(
                request.SessionId,
                request.HostId.Value,
                request.IncarnationId.Value,
                default));
    }

    [Fact]
    public void ServerOptionsRejectAnyWtsSessionPrebinding()
    {
        var directory = Path.Combine(_artifacts, "server-options");
        Directory.CreateDirectory(directory);
        var key = Path.Combine(directory, "key");
        var nonces = Path.Combine(directory, "nonces.json");
        File.WriteAllBytes(key, new byte[32]);
        File.WriteAllText(nonces, "{}");
        var common = new[]
        {
            "--session-id", Guid.NewGuid().ToString(),
            "--host-id", Guid.NewGuid().ToString(),
            "--incarnation-id", Guid.NewGuid().ToString(),
            "--auth-key-file", key,
            "--nonce-sequence-file", nonces,
            "--readiness-receipt-file",
            Path.Combine(directory, "readiness.json")
        };

        var parsed = ServerOptions.Parse(common);

        Assert.Equal(key, parsed.AuthenticationKeyFile);
        Assert.Throws<ArgumentException>(() =>
            ServerOptions.Parse(
                [.. common, "--rdp-session-id", "7"]));
    }

    [Fact]
    public void ReadinessLogRequiresExactNonceAndRunningState()
    {
        var request = Request();
        var observation = new DevBoxRdpDvcReadinessObservation(
            1,
            "Running",
            true,
            true,
            new(
                1,
                "authenticatedGeneration",
                123,
                request.SessionId,
                request.HostId.Value,
                request.IncarnationId.Value,
                1,
                DateTimeOffset.UtcNow,
                [
                    new(
                        0,
                        request.ConnectionNonces[0],
                        7,
                        1,
                        DateTimeOffset.UtcNow)
                ]));
        var log = "prefix\r\n" + DevBoxRdpDvcReadiness.LogMarker +
                  JsonSerializer.Serialize(
                      observation,
                      new JsonSerializerOptions(JsonSerializerDefaults.Web)) +
                  "\r\nsuffix";

        var parsed = DevBoxRdpDvcReadiness.ParseLog(log, request);

        Assert.True(parsed.DvcEndpointReady);
        Assert.Single(parsed.Receipt.AuthenticatedGenerations);
        var changed = request with
        {
            ConnectionNonces =
            [
                Guid.NewGuid(),
                request.ConnectionNonces[1]
            ]
        };
        Assert.Throws<InvalidDataException>(() =>
            DevBoxRdpDvcReadiness.ParseLog(log, changed));
    }

    [Fact]
    public void BundleLoadRejectsCorruptArchive()
    {
        var bundle = Bundle();
        var path = Path.Combine(_artifacts, "bundle.tar.br");
        File.WriteAllBytes(path, bundle.Archive.ToArray());
        Assert.Equal(
            bundle.ArchiveSha256,
            RdpDvcBootstrapBundle.Load(path).ArchiveSha256);
        var corrupted = File.ReadAllBytes(path);
        File.WriteAllBytes(
            path,
            corrupted.AsSpan(0, corrupted.Length / 2).ToArray());

        Assert.Throws<InvalidDataException>(() =>
            RdpDvcBootstrapBundle.Load(path));
    }

    [Fact]
    public void RedactedReceiptRequiresExactPreConnectReadiness()
    {
        var request = Request();
        var bundle = Bundle();
        var handle = new ProviderOperationHandle(
            request.OperationId,
            request.IdempotencyKey,
            DevBoxRdpDvcBootstrapPlan.ProviderName,
            "opaque");
        var result = new ProviderOperationResult(
            ProviderOperationStatus.Succeeded,
            handle,
            null);
        var waiting = Observation(
            request,
            "waitingForActiveRdpSession",
            []);

        var receipt = DevBoxRdpDvcBootstrapReceipts.Create(
            request,
            bundle,
            result,
            waiting);

        Assert.True(receipt.PreConnectReady);
        Assert.Equal(0, receipt.RemoteReadiness.NextGeneration);
        Assert.Equal(
            "waitingForActiveRdpSession",
            receipt.RemoteReadiness.RemoteState);
        Assert.Throws<InvalidOperationException>(() =>
            DevBoxRdpDvcBootstrapReceipts.Create(
                request,
                bundle,
                result,
                Observation(
                    request,
                    "authenticatedGeneration",
                    [Generation(request, 0)])));
        Assert.DoesNotContain(
            Convert.ToBase64String(request.AuthenticationKey.Span),
            JsonSerializer.Serialize(receipt),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReceiptAttestationUsesBothExistingSigningKeys()
    {
        var request = Request();
        var bundle = Bundle();
        var receipt = DevBoxRdpDvcBootstrapReceipts.Create(
            request,
            bundle,
            new(
                ProviderOperationStatus.Succeeded,
                new(
                    request.OperationId,
                    request.IdempotencyKey,
                    DevBoxRdpDvcBootstrapPlan.ProviderName,
                    "opaque"),
                null),
            Observation(
                request,
                "waitingForActiveRdpSession",
                []));
        using var node = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var control = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var attested = DevBoxRdpDvcBootstrapReceipts.Attest(
            receipt,
            "node/test",
            node,
            "control/test",
            control);
        var path = Path.Combine(_artifacts, "attested-receipt.json");
        await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
            path,
            attested,
            default);
        attested = await DevBoxRdpDvcBootstrapReceipts
            .LoadAttestedAsync(path, default);
        var verified = DevBoxRdpDvcBootstrapReceipts.Verify(
            attested,
            DevBoxRdpDvcBootstrapReceiptExpectation.From(request, bundle),
            "node/test",
            node.ExportSubjectPublicKeyInfo(),
            "control/test",
            control.ExportSubjectPublicKeyInfo());
        Assert.Equal(receipt.BundleVersion, verified.BundleVersion);
        Assert.Equal(receipt.ArchiveSha256, verified.ArchiveSha256);
        Assert.True(
            receipt.ConnectionNonces.SequenceEqual(
                verified.ConnectionNonces));
        Assert.Equal(receipt.RemoteReadiness, verified.RemoteReadiness);
        Assert.Equal(request.OperationId, verified.OperationId);
        Assert.Equal(request.HostId, verified.HostId);
        Assert.Equal(request.IncarnationId, verified.NodeIncarnationId);
        Assert.Throws<InvalidDataException>(() =>
            DevBoxRdpDvcBootstrapReceipts.Verify(
                attested with
                {
                    Node = attested.Node! with
                    {
                        Signature = Convert.ToBase64String(
                            RandomNumberGenerator.GetBytes(64))
                    }
                },
                DevBoxRdpDvcBootstrapReceiptExpectation.From(
                    request,
                    bundle),
                "node/test",
                node.ExportSubjectPublicKeyInfo(),
                "control/test",
                control.ExportSubjectPublicKeyInfo()));
    }

    public void Dispose()
    {
        for (var attempt = 0; Directory.Exists(_artifacts); attempt++)
        {
            try
            {
                Directory.Delete(_artifacts, recursive: true);
            }
            catch (IOException) when (attempt < 20)
            {
                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException) when (attempt < 20)
            {
                Thread.Sleep(50);
            }
        }
    }

    private DevBoxRdpDvcBootstrapDeployer Deployer(
        BootstrapTransport transport,
        BootstrapStore store) =>
        new(
            new DevBoxCustomizationClient(
                new("https://center.westus.devcenter.azure.com/"),
                transport),
            store,
            TestProvider.Protector());

    private static async Task<ProviderOperationResult> CompleteAsync(
        DevBoxRdpDvcBootstrapDeployer deployer,
        ProviderOperationResult result)
    {
        for (var attempt = 0;
             attempt < 64 &&
             result.Status is
                 ProviderOperationStatus.Accepted or
                 ProviderOperationStatus.Running;
             attempt++)
            result = await deployer.ReconcileAsync(
                result.Handle!);
        return result;
    }

    private RdpDvcBootstrapBundle Bundle() =>
        RdpDvcBootstrapBundle.CreateFromPublishDirectory(
            CreatePublishDirectory(),
            "1.2.3");

    private string CreatePublishDirectory()
    {
        var directory = Path.Combine(_artifacts, "publish");
        Directory.CreateDirectory(directory);
        var files = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Microsoft.RdpDvcSamples.LICENSE.txt"] = "license",
            ["Steward.Contracts.dll"] = "contracts",
            ["Steward.Domain.dll"] = "domain",
            ["Steward.HandleKeeper.deps.json"] = "{}",
            ["Steward.HandleKeeper.dll"] = "keeper",
            ["Steward.HandleKeeper.runtimeconfig.json"] = "{}",
            ["Steward.RdpDvc.Server.Windows.deps.json"] = "{}",
            ["Steward.RdpDvc.Server.Windows.dll"] = "server",
            ["Steward.RdpDvc.Server.Windows.runtimeconfig.json"] = "{}",
            ["Steward.Transport.Rdp.Endpoint.Windows.dll"] = "rdp",
            ["Steward.Transport.dll"] = "transport"
        };
        foreach (var file in files)
            File.WriteAllText(
                Path.Combine(directory, file.Key),
                file.Value,
                Encoding.UTF8);
        File.WriteAllBytes(
            Path.Combine(directory, "Steward.Bootstrap.Payload.dll"),
            Enumerable.Range(0, 600 * 1024)
                .Select(value => (byte)(value % 251))
                .ToArray());
        File.WriteAllText(
            Path.Combine(directory, "Steward.RdpDvc.Server.Windows.exe"),
            "excluded",
            Encoding.UTF8);
        return directory;
    }

    private static DevBoxRdpDvcBootstrapRequest Request() =>
        RequestWithEncryptionKey();

    private static DevBoxRdpDvcBootstrapRequest RequestWithEncryptionKey()
    {
        using var envelope = RSA.Create(3072);
        using var node = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var control = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new(
            ProviderOperationId.New(),
            "bootstrap-attempt-1",
            "project",
            "me",
            "box-name",
            Guid.NewGuid(),
            HostId.New(),
            NodeIncarnationId.New(),
            [Guid.NewGuid(), Guid.NewGuid()],
            Enumerable.Range(1, 32).Select(value => (byte)value).ToArray(),
            "node",
            node.ExportPkcs8PrivateKey(),
            "control",
            control.ExportSubjectPublicKeyInfo(),
            BootstrapEncryptionPublicKey:
                envelope.ExportSubjectPublicKeyInfo());
    }

    private static int GroupIndex(string group) =>
        int.Parse(
            group[^4..],
            System.Globalization.CultureInfo.InvariantCulture);

    private static DevBoxRdpDvcReadinessObservation Observation(
        DevBoxRdpDvcBootstrapRequest request,
        string state,
        IReadOnlyList<DevBoxRdpDvcAuthenticatedGeneration> generations) =>
        new(
            1,
            "Queued",
            state != "waitingForActiveRdpSession",
            state is "authenticatedGeneration" or "completed",
            new(
                1,
                state,
                state == "waitingForActiveRdpSession" ? 0 : 123,
                request.SessionId,
                request.HostId.Value,
                request.IncarnationId.Value,
                generations.Count,
                DateTimeOffset.UtcNow,
                generations));

    private static DevBoxRdpDvcAuthenticatedGeneration Generation(
        DevBoxRdpDvcBootstrapRequest request,
        int index) =>
        new(
            index,
            request.ConnectionNonces[index],
            7 + index,
            1,
            DateTimeOffset.UtcNow);

    private sealed class BootstrapStore(List<string> events) :
        ISecureDurableDevBoxRdpDvcBootstrapStore
    {
        public DevBoxRdpDvcBootstrapCheckpoint? Checkpoint { get; private set; }

        public Task<DevBoxRdpDvcBootstrapCheckpoint?> LoadAsync(
            ProviderOperationId operationId,
            string idempotencyKey,
            CancellationToken cancellationToken) =>
            Task.FromResult(Checkpoint);

        public Task RecordBeforeEffectAsync(
            DevBoxRdpDvcBootstrapCheckpoint checkpoint,
            CancellationToken cancellationToken)
        {
            events.Add($"record:{checkpoint.GroupIndex}");
            Checkpoint = checkpoint;
            return Task.CompletedTask;
        }

        public Task RecordCompletedAsync(
            DevBoxRdpDvcBootstrapCheckpoint checkpoint,
            CancellationToken cancellationToken)
        {
            events.Add("completed");
            Checkpoint = checkpoint;
            return Task.CompletedTask;
        }
    }

    private sealed class BootstrapTransport(List<string> events) :
        IDevBoxCustomizationTransport
    {
        private bool _firstPut = true;
        public string FirstPutStatus { get; init; } = "Succeeded";
        public string GetStatus { get; init; } = "Succeeded";
        public List<TransportCall> Calls { get; } = [];

        public Task<DevBoxCustomizationHttpResponse> SendAsync(
            RequestMethod method,
            Uri uri,
            BinaryData? content,
            CancellationToken cancellationToken)
        {
            var group = uri.AbsolutePath.Split('/')[^1];
            var index = GroupIndex(group);
            events.Add($"{method.ToString().ToLowerInvariant()}:{index}");
            Calls.Add(new(method, group, content));
            var status = method == RequestMethod.Get
                ? GetStatus
                : method == RequestMethod.Put && _firstPut
                    ? FirstPutStatus
                    : "Succeeded";
            if (method == RequestMethod.Put)
                _firstPut = false;
            return Task.FromResult(new DevBoxCustomizationHttpResponse(
                200,
                BinaryData.FromString(
                    $$"""
                    {
                      "name": "{{group}}",
                      "uri": "https://center.westus.devcenter.azure.com/projects/project/users/me/devboxes/box-name/customizationGroups/{{group}}",
                      "status": "{{status}}",
                      "tasks": []
                    }
                    """)));
        }
    }

    private sealed record TransportCall(
        RequestMethod Method,
        string Group,
        BinaryData? Content);
}
