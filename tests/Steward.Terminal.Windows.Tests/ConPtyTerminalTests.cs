using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Steward.Domain;
using Steward.Runtime.Windows;
using Steward.Tasks.Abstractions;
using Steward.Terminal.Abstractions;
using Steward.Terminal.Windows;

namespace Steward.Terminal.Windows.Tests;

public sealed class ConPtyTerminalTests : IAsyncLifetime
{
    private readonly string directory = Path.Combine(
        Path.GetTempPath(), "steward-conpty-tests", Guid.NewGuid().ToString("N"));
    private readonly HostId host = HostId.New();
    private readonly NodeIncarnationId node = NodeIncarnationId.New();

    public Task InitializeAsync()
    {
        Directory.CreateDirectory(directory);
        return Task.CompletedTask;
    }

    [Fact(Timeout = 30_000)]
    public async Task ConPty_round_trip_resize_and_mutation_evidence()
    {
        await using var service = Service();
        var token = "steward-" + Guid.NewGuid().ToString("N");
        var request = Request(TerminalTranscriptMode.Full, taskBound: true) with
        {
            ShellKind = TerminalShellKind.CommandPrompt,
            ShellExecutable = CommandPrompt(),
            Arguments = ["/D", "/Q", "/K", $"title {token}"]
        };
        var opened = await OpenWithRetryAsync(service, request);
        Assert.Equal(TerminalSessionState.Open, opened.State);
        Assert.False(opened.ElevationGranted);
        Assert.NotNull(opened.ProcessId);
        Assert.NotEmpty(opened.ExecutionIdentity);

        var afterInput = await service.WriteInputAsync(new(request.Authority.SessionId,
            Context(request.Authority), NewRequestId(), opened.Revision, "echo managed-input\r\n"u8.ToArray()));
        Assert.True(afterInput.UnmanagedMutationSuspected);
        Assert.True(SpinWait.SpinUntil(() => TranscriptText(service, request).Contains(token, StringComparison.Ordinal),
            TimeSpan.FromSeconds(10)));
        var latest = await service.GetAsync(request.Authority.SessionId, Context(request.Authority));
        if (latest.State == TerminalSessionState.Open)
            await service.CloseAsync(new(request.Authority.SessionId, Context(request.Authority),
                NewRequestId(), latest.Revision, TimeSpan.Zero));
        var transcript = service.ReadRetainedTranscript(request.Authority.SessionId, Context(request.Authority));
        var output = Encoding.UTF8.GetString([.. transcript.Where(record => record.Direction == "output" &&
            record.Content is not null).SelectMany(record => record.Content!)]);
        Assert.Contains(token, output, StringComparison.Ordinal);
    }

    [Fact(Timeout = 30_000)]
    public async Task Terminal_receives_only_the_typed_clean_environment()
    {
        var name = "STEWARD_TERMINAL_PARENT_SECRET";
        var prior = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, "must-not-inherit");
        try
        {
            await using var service = Service();
            var request = Request(TerminalTranscriptMode.Full) with
            {
                ShellKind = TerminalShellKind.CommandPrompt,
                ShellExecutable = CommandPrompt(),
                Arguments =
                [
                    "/D", "/Q", "/K",
                    $"echo %{name}%"
                ]
            };

            await OpenWithRetryAsync(service, request);

            var observed = SpinWait.SpinUntil(
                () => TranscriptText(service, request).Contains(
                    "%STEWARD_TERMINAL_PARENT_SECRET%", StringComparison.Ordinal),
                TimeSpan.FromSeconds(10));
            var transcript = TranscriptText(service, request);
            Assert.True(observed, transcript);
            Assert.DoesNotContain(
                "must-not-inherit",
                transcript,
                StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, prior);
        }
    }
    [Fact(Timeout = 30_000)]
    public async Task Terminal_child_has_native_restricted_AppContainer_token_for_its_attempt()
    {
        var workspace = Path.Combine(directory, "native-token");
        Directory.CreateDirectory(workspace);
        await using var service = Service();
        var seed = Request(TerminalTranscriptMode.None);
        var request = seed with
        {
            Authority = seed.Authority with
            {
                WorkspaceRoot = workspace,
                Task = new(TaskAttemptId.New(), 3)
            },
            WorkingDirectory = workspace,
            Arguments = ["-NoLogo", "-NoProfile", "-Command", "Start-Sleep 30"]
        };

        var opened = await OpenWithRetryAsync(service, request);
        using var token = OpenToken(opened.ProcessId!.Value);
        var expected = WindowsWorkloadIsolation.Describe(TerminalIsolation(request));

        Assert.Equal(1, ReadTokenInt32(token, TokenIsAppContainer));
        Assert.Equal(expected.RestrictedSid, ReadAppContainerSid(token));
        Assert.Equal(0, ReadTokenInt32(token, TokenCapabilities));
    }

    [Fact(Timeout = 30_000)]
    public async Task Terminal_authority_can_use_only_workspace_and_ConPty_handles()
    {
        var workspace = Path.Combine(directory, "authority-workspace");
        var sibling = Path.Combine(directory, "sibling-workspace");
        var identity = Path.Combine(directory, "endpoint-identity");
        var trust = Path.Combine(directory, "control-trust");
        var update = Path.Combine(directory, "update-state");
        var maintenance = Path.Combine(directory, "maintenance-state");
        foreach (var path in new[] { workspace, sibling, identity, trust, update, maintenance })
            Directory.CreateDirectory(path);
        foreach (var protectedRoot in new[] { sibling, identity, trust, update, maintenance })
        {
            await File.WriteAllTextAsync(Path.Combine(protectedRoot, "secret.txt"), "forbidden");
            WindowsWorkloadIsolation.Prepare(new(
                1,
                ProcessIsolationCapability.Process,
                directory,
                protectedRoot,
                TaskAttemptId.New(),
                1));
        }

        var inheritedPath = Path.Combine(directory, "inherited-handle.txt");
        using var inherited = File.OpenHandle(
            inheritedPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.ReadWrite);
        Assert.True(SetHandleInformation(inherited, 1, 1));
        var inheritedValue = inherited.DangerousGetHandle().ToInt64()
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        var parentSecret = "STEWARD_TERMINAL_AUTHORITY_PARENT_SECRET";
        var previousSecret = Environment.GetEnvironmentVariable(parentSecret);
        Environment.SetEnvironmentVariable(parentSecret, "must-not-inherit");
        var pipeName = "Steward.Maintenance." + Guid.NewGuid().ToString("N");
        await using var pipe = new System.IO.Pipes.NamedPipeServerStream(
            pipeName,
            System.IO.Pipes.PipeDirection.InOut,
            1,
            System.IO.Pipes.PipeTransmissionMode.Byte,
            System.IO.Pipes.PipeOptions.Asynchronous |
            System.IO.Pipes.PipeOptions.CurrentUserOnly);
        try
        {
            var checks = new[]
            {
                $"try {{ Set-Content -LiteralPath '{Path.Combine(workspace, "allowed.txt")}' allowed -ErrorAction Stop; 'workspace-allowed' }} catch {{ 'workspace-denied' }}",
                DeniedPowerShellFileCheck("sibling", Path.Combine(sibling, "secret.txt")),
                DeniedPowerShellFileCheck("identity", Path.Combine(identity, "secret.txt")),
                DeniedPowerShellFileCheck("trust", Path.Combine(trust, "secret.txt")),
                DeniedPowerShellFileCheck("update", Path.Combine(update, "secret.txt")),
                DeniedPowerShellFileCheck("maintenance", Path.Combine(maintenance, "secret.txt")),
                $"try {{ $p=[IO.Pipes.NamedPipeClientStream]::new('.', '{pipeName}', [IO.Pipes.PipeDirection]::Out); $p.Connect(500); $p.Dispose(); 'pipe-leaked' }} catch {{ 'pipe-denied' }}",
                $"if ($env:{parentSecret}) {{ 'environment-leaked' }} else {{ 'environment-denied' }}",
                $"try {{ $h=[Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]{inheritedValue}, $false); $s=[IO.FileStream]::new($h,[IO.FileAccess]::Write); $s.WriteByte(88); $s.Dispose(); $h.Dispose(); 'handle-leaked' }} catch {{ 'handle-denied' }}",
                "'conpty-available'"
            };
            await using var service = Service();
            var seed = Request(TerminalTranscriptMode.Full);
            var request = seed with
            {
                Authority = seed.Authority with { WorkspaceRoot = workspace },
                WorkingDirectory = workspace,
                Arguments = ["-NoLogo", "-NoProfile", "-NoExit", "-Command", string.Join("; ", checks)]
            };
            var opened = await service.OpenAsync(
                request, Context(request.Authority));
            using var childToken = OpenToken(opened.ProcessId!.Value);
            var expectedAuthority = WindowsWorkloadIsolation.Describe(
                TerminalIsolation(request));
            Assert.Equal(1, ReadTokenInt32(childToken, TokenIsAppContainer));
            Assert.Equal(
                expectedAuthority.RestrictedSid,
                ReadAppContainerSid(childToken));
            Assert.Equal(0, ReadTokenInt32(childToken, TokenCapabilities));
            Assert.True(SpinWait.SpinUntil(
                () => TranscriptText(service, request).Contains(
                    "conpty-available", StringComparison.Ordinal),
                TimeSpan.FromSeconds(10)),
                TranscriptText(service, request));
            var transcript = TranscriptText(service, request);

            Assert.Contains("workspace-allowed", transcript, StringComparison.Ordinal);

            Assert.Contains("sibling-denied", transcript, StringComparison.Ordinal);
            Assert.Contains("identity-denied", transcript, StringComparison.Ordinal);
            Assert.Contains("trust-denied", transcript, StringComparison.Ordinal);
            Assert.Contains("update-denied", transcript, StringComparison.Ordinal);
            Assert.Contains("maintenance-denied", transcript, StringComparison.Ordinal);
            Assert.Contains("pipe-denied", transcript, StringComparison.Ordinal);
            Assert.Contains("environment-denied", transcript, StringComparison.Ordinal);
            Assert.Contains("handle-denied", transcript, StringComparison.Ordinal);
            Assert.Contains("conpty-available", transcript, StringComparison.Ordinal);
            Assert.Equal(0, new FileInfo(inheritedPath).Length);
        }
        finally
        {
            Environment.SetEnvironmentVariable(parentSecret, previousSecret);
        }
    }
    [Fact(Timeout = 30_000)]
    public async Task Input_and_output_are_bounded()
    {
        await using var service = Service(maximumInputMessageBytes: 64);
        var request = Request(TerminalTranscriptMode.Metadata, maximumInput: 1024, maximumOutput: 1024) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command", "Start-Sleep 10"]
        };
        var opened = await OpenWithRetryAsync(service, request);
        var tooLarge = await Assert.ThrowsAsync<TerminalException>(() =>
            service.WriteInputAsync(new(request.Authority.SessionId, Context(request.Authority),
                NewRequestId(), opened.Revision, new byte[65])).AsTask());
        Assert.Equal(TerminalProblemCode.InvalidRequest, tooLarge.Problem.Code);

        await using var limitedService = Service(maximumInputMessageBytes: 64);
        var limitedRequest = Request(TerminalTranscriptMode.None, maximumInput: 16, maximumOutput: 1024);
        var limitedOpened = await OpenWithRetryAsync(limitedService, limitedRequest);
        var overLease = await Assert.ThrowsAsync<TerminalException>(() =>
            limitedService.WriteInputAsync(new(limitedRequest.Authority.SessionId, Context(limitedRequest.Authority),
                NewRequestId(), limitedOpened.Revision, new byte[17])).AsTask());
        Assert.Equal(TerminalProblemCode.InputLimitExceeded, overLease.Problem.Code);

        var afterInput = await service.WriteInputAsync(new(request.Authority.SessionId,
            Context(request.Authority), NewRequestId(), opened.Revision, "x"u8.ToArray()));
        Assert.Equal(1, afterInput.InputBytes);
        var latest = await service.GetAsync(request.Authority.SessionId, Context(request.Authority));
        await service.CloseAsync(new(request.Authority.SessionId, Context(request.Authority),
            NewRequestId(), latest.Revision, TimeSpan.Zero));
        Assert.All(service.ReadRetainedTranscript(request.Authority.SessionId, Context(request.Authority)),
            record => Assert.Null(record.Content));

        await using var outputService = Service();
        var outputRequest = Request(TerminalTranscriptMode.Metadata, maximumOutput: 32) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command", "[Console]::Write('x'*5000)"]
        };
        await OpenWithRetryAsync(outputService, outputRequest);
        Assert.True(SpinWait.SpinUntil(() =>
                outputService.GetAsync(outputRequest.Authority.SessionId, Context(outputRequest.Authority)).Result.State
                    is TerminalSessionState.Closed or TerminalSessionState.Interrupted,
            TimeSpan.FromSeconds(10)));
        var bounded = await outputService.GetAsync(outputRequest.Authority.SessionId, Context(outputRequest.Authority));
        Assert.Equal(32, bounded.OutputBytes);
        Assert.Equal(TerminalSessionState.Interrupted, bounded.State);
        Assert.Equal("output-limit-exceeded", bounded.InterruptionReason);
    }

    [Fact(Timeout = 30_000)]
    public async Task Cancellation_terminates_the_process_tree()
    {
        await using var service = Service();
        var childFile = Path.Combine(directory, "child.pid");
        var script = $"$p=Start-Process '{Path.Combine(Environment.SystemDirectory, "ping.exe")}' " +
                     $"-ArgumentList '127.0.0.1','-n','120' -WindowStyle Hidden -PassThru; " +
                     $"Set-Content -LiteralPath '{childFile}' $p.Id; Wait-Process $p";
        var request = Request(TerminalTranscriptMode.None) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command", script]
        };
        var opened = await OpenWithRetryAsync(service, request);
        var resized = await service.ResizeAsync(new(request.Authority.SessionId, Context(request.Authority),
            NewRequestId(), opened.Revision, 100, 40));
        var childPid = 0;
        Assert.True(SpinWait.SpinUntil(() => TryReadProcessId(childFile, out childPid), TimeSpan.FromSeconds(10)));
        var closed = await service.CloseAsync(new(request.Authority.SessionId, Context(request.Authority),
            NewRequestId(), resized.Revision, TimeSpan.Zero));
        Assert.Equal(TerminalSessionState.Closed, closed.State);
        Assert.True(SpinWait.SpinUntil(() => !IsRunning(childPid), TimeSpan.FromSeconds(10)));
    }

    [Fact(Timeout = 30_000)]
    public async Task No_reader_never_backpressures_child_and_disconnected_readers_replay_independently()
    {
        var sentinel = Path.Combine(directory, "no-reader.done");
        var noReaderJournal = new TerminalJournal(Path.Combine(directory, Guid.NewGuid() + ".db"));
        await using (var service = new TerminalSessionService(noReaderJournal, host, node,
                         "boot-" + Guid.NewGuid().ToString("N"),
                         options: new(NotificationCapacity: 2)))
        {
            var script = $"[Console]::Write(('x'*1048576)); Set-Content -LiteralPath '{sentinel}' done";
            var request = Request(TerminalTranscriptMode.Metadata, maximumOutput: 2 * 1024 * 1024,
                operationalSpoolBytes: 256 * 1024) with
            {
                Arguments = ["-NoLogo", "-NoProfile", "-Command", script]
            };
            await OpenWithRetryAsync(service, request);

            Assert.True(SpinWait.SpinUntil(() => File.Exists(sentinel), TimeSpan.FromSeconds(15)));
            Assert.True(SpinWait.SpinUntil(() =>
                noReaderJournal.Get(request.Authority.SessionId).OutputBytes > 0, TimeSpan.FromSeconds(10)));
        }

        await using var replayService = Service(notificationCapacity: 2);
        var token = "replay-" + Guid.NewGuid().ToString("N");
        var replayRequest = Request(TerminalTranscriptMode.None, operationalSpoolBytes: 1024 * 1024) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command",
                $"$host.UI.RawUI.WindowTitle='{token}'; Start-Sleep 10"]
        };
        var opened = await OpenWithRetryAsync(replayService, replayRequest);
        Assert.True(SpinWait.SpinUntil(() =>
            replayService.ReadRetainedTranscript(replayRequest.Authority.SessionId,
                Context(replayRequest.Authority)).Count == 0 &&
            ReadAllAsync(replayService, new(replayRequest.Authority.SessionId, Context(replayRequest.Authority),
                0, 0, 100, 1024 * 1024, false)).GetAwaiter().GetResult()
                .SelectMany(item => item.Data.ToArray()).ToArray()
                .AsSpan().IndexOf(Encoding.UTF8.GetBytes(token)) >= 0,
            TimeSpan.FromSeconds(10)));
        var read = new TerminalOutputReadRequest(replayRequest.Authority.SessionId,
            Context(replayRequest.Authority), 0, 0, 100, 1024 * 1024, false);
        var firstTask = ReadAllAsync(replayService, read);
        var secondTask = ReadAllAsync(replayService, read);
        await Task.WhenAll(firstTask, secondTask);
        var first = await firstTask;
        var second = await secondTask;
        Assert.NotEmpty(first);
        Assert.Equal(first.Select(item => item.Sequence), second.Select(item => item.Sequence));
        Assert.Contains(token, Encoding.UTF8.GetString([.. first.SelectMany(item => item.Data.ToArray())]),
            StringComparison.Ordinal);
        var last = first[^1];
        var follow = read with
        {
            AfterSequence = last.Sequence,
            AfterOffset = last.Offset + last.Length,
            MaximumItems = 1,
            Follow = true
        };
        var followerOne = ReadAllAsync(replayService, follow);
        var followerTwo = ReadAllAsync(replayService, follow);
        await Task.Delay(100);
        var resized = await replayService.ResizeAsync(new(replayRequest.Authority.SessionId,
            Context(replayRequest.Authority), NewRequestId(), opened.Revision, 100, 40));
        var followed = await Task.WhenAll(followerOne.WaitAsync(TimeSpan.FromSeconds(10)),
            followerTwo.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Single(followed[0]);
        Assert.Equal(followed[0][0].Sequence, Assert.Single(followed[1]).Sequence);
        var closed = await replayService.CloseAsync(new(replayRequest.Authority.SessionId,
            Context(replayRequest.Authority), NewRequestId(), resized.Revision, TimeSpan.Zero));
        Assert.Equal(TerminalSessionState.Closed, closed.State);
        var resumed = await ReadAllAsync(replayService, read with
        {
            AfterSequence = last.Sequence,
            AfterOffset = last.Offset + last.Length
        });
        Assert.DoesNotContain(resumed, item => item.Sequence <= last.Sequence);
        Assert.Single(resumed, item => item.EndOfStream);
    }

    [Fact(Timeout = 30_000)]
    public async Task Mutating_operations_replay_exact_outcome_and_reject_changed_body()
    {
        var journal = new TerminalJournal(Path.Combine(directory, Guid.NewGuid() + ".db"));
        await using var service = new TerminalSessionService(journal, host, node,
            "boot-" + Guid.NewGuid().ToString("N"));
        var request = Request(TerminalTranscriptMode.None, operationalSpoolBytes: 1024 * 1024) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command", "Start-Sleep 10"]
        };
        var opened = await OpenWithRetryAsync(service, request);
        var uncertainId = NewRequestId();
        var uncertainData = "z"u8.ToArray();
        _ = journal.BeginOperation(uncertainId, request.Authority.SessionId, "input",
            OperationFingerprint("input", request.Authority.SessionId, Context(request.Authority),
                opened.Revision, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(uncertainData))),
            DateTimeOffset.UtcNow);
        var uncertain = await Assert.ThrowsAsync<TerminalException>(() =>
            service.WriteInputAsync(new(request.Authority.SessionId, Context(request.Authority),
                uncertainId, opened.Revision, uncertainData)).AsTask());
        Assert.Equal(TerminalProblemCode.AmbiguousOperation, uncertain.Problem.Code);
        Assert.True(uncertain.Problem.SideEffectMayHaveOccurred);
        Assert.Equal(0, journal.Get(request.Authority.SessionId).InputBytes);

        var inputId = NewRequestId();
        var input = new TerminalInputRequest(request.Authority.SessionId, Context(request.Authority),
            inputId, opened.Revision, "x"u8.ToArray());
        var appliedInput = await service.WriteInputAsync(input);
        Assert.Equal(appliedInput, await service.WriteInputAsync(input));
        var inputConflict = await Assert.ThrowsAsync<TerminalException>(() =>
            service.WriteInputAsync(input with { Data = "y"u8.ToArray() }).AsTask());
        Assert.Equal(TerminalProblemCode.IdempotencyConflict, inputConflict.Problem.Code);

        var resizeId = NewRequestId();
        var resize = new TerminalResizeRequest(request.Authority.SessionId, Context(request.Authority),
            resizeId, appliedInput.Revision, 90, 30);
        var appliedResize = await service.ResizeAsync(resize);
        Assert.Equal(appliedResize, await service.ResizeAsync(resize));
        var resizeConflict = await Assert.ThrowsAsync<TerminalException>(() =>
            service.ResizeAsync(resize with { Columns = 91 }).AsTask());
        Assert.Equal(TerminalProblemCode.IdempotencyConflict, resizeConflict.Problem.Code);

        var closeId = NewRequestId();
        var close = new TerminalCloseRequest(request.Authority.SessionId, Context(request.Authority),
            closeId, appliedResize.Revision, TimeSpan.Zero);
        var appliedClose = await service.CloseAsync(close);
        Assert.Equal(appliedClose, await service.CloseAsync(close));
        var closeConflict = await Assert.ThrowsAsync<TerminalException>(() =>
            service.CloseAsync(close with { GracePeriod = TimeSpan.FromMilliseconds(1) }).AsTask());
        Assert.Equal(TerminalProblemCode.IdempotencyConflict, closeConflict.Problem.Code);
    }

    [Fact(Timeout = 30_000)]
    public async Task Active_revision_revocation_terminates_idle_terminal()
    {
        var revision = 0L;
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var journal = new TerminalJournal(Path.Combine(directory, Guid.NewGuid() + ".db"));
        await using var service = new TerminalSessionService(journal, host, node, "boot-" + Guid.NewGuid().ToString("N"),
            options: new(AuthorityMonitorInterval: TimeSpan.FromSeconds(1)),
            currentRevocationRevision: () => Volatile.Read(ref revision), timeProvider: clock);
        var childFile = Path.Combine(directory, "revoked-child.pid");
        var script = $"$p=Start-Process '{PowerShell()}' " +
                     "-ArgumentList '-NoLogo','-NoProfile','-Command','Start-Sleep 120' -PassThru; " +
                     $"Set-Content -LiteralPath '{childFile}' $p.Id; Wait-Process $p";
        var request = Request(TerminalTranscriptMode.None) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command", script]
        };
        var opened = await OpenWithRetryAsync(service, request);
        Assert.Equal(TerminalSessionState.Open, opened.State);
        var childPid = 0;
        Assert.True(SpinWait.SpinUntil(
            () => TryReadProcessId(childFile, out childPid),
            TimeSpan.FromSeconds(10)));
        Volatile.Write(ref revision, 1);
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True(SpinWait.SpinUntil(() =>
        {
            var snapshot = journal.Get(request.Authority.SessionId);
            return snapshot.State == TerminalSessionState.Interrupted &&
                   snapshot.InterruptionReason == "authority-revoked";
        }, TimeSpan.FromSeconds(10)));
        Assert.True(SpinWait.SpinUntil(() => !IsRunning(opened.ProcessId!.Value), TimeSpan.FromSeconds(10)));
        Assert.True(SpinWait.SpinUntil(() => !IsRunning(childPid), TimeSpan.FromSeconds(10)));
    }

    private static async Task<TerminalSessionSnapshot> OpenWithRetryAsync(
        TerminalSessionService service,
        TerminalOpenRequest request)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return await service.OpenAsync(
                    request,
                    Context(request.Authority));
            }
            catch (TerminalException) when (attempt < 3)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100 * (attempt + 1)));
            }
        }
    }

    private TerminalSessionService Service(
        int maximumInputMessageBytes = 64 * 1024,
        int notificationCapacity = 64)
    {
        var journal = new TerminalJournal(Path.Combine(directory, Guid.NewGuid() + ".db"));
        return new(journal, host, node, "boot-" + Guid.NewGuid().ToString("N"),
            options: new(NotificationCapacity: notificationCapacity,
                MaximumInputMessageBytes: maximumInputMessageBytes));
    }

    private TerminalOpenRequest Request(
        TerminalTranscriptMode mode,
        bool taskBound = false,
        long maximumInput = 1024 * 1024,
        long maximumOutput = 1024 * 1024,
        long operationalSpoolBytes = 0)
    {
        var now = DateTimeOffset.UtcNow;
        var authority = new TerminalAuthority(TerminalContractLimits.SchemaVersion, TerminalSessionId.New(),
            host, node, "actor", directory, taskBound ? new(TaskAttemptId.New(), 1) : null,
            now - TimeSpan.FromSeconds(1), now - TimeSpan.FromSeconds(1), now + TimeSpan.FromMinutes(5),
            TimeSpan.FromMinutes(10), maximumInput, maximumOutput, mode,
            mode == TerminalTranscriptMode.Full ? maximumOutput : 0,
            TerminalFileTransferCapabilities.None, false, false, 0,
            operationalSpoolBytes == 0 ? TimeSpan.Zero : TimeSpan.FromMinutes(5),
            operationalSpoolBytes);
        return new(TerminalContractLimits.SchemaVersion, "request-" + Guid.NewGuid().ToString("N"),
            authority, TerminalShellKind.PowerShell, PowerShell(), ["-NoLogo", "-NoProfile", "-NoExit"],
            directory, 80, 25);
    }

    private static TerminalOperationContext Context(TerminalAuthority authority) =>
        new(authority.HostId, authority.NodeIncarnationId, authority.Actor, 0);

    private static string NewRequestId() => "operation-" + Guid.NewGuid().ToString("N");

    private static string OperationFingerprint(
        string operationType,
        TerminalSessionId sessionId,
        TerminalOperationContext context,
        long expectedRevision,
        string bodyFingerprint)
    {
        var canonical = string.Join('\n', operationType, sessionId.ToString(), context.HostId.ToString(),
            context.NodeIncarnationId.ToString(), context.Actor,
            context.CurrentRevocationRevision.ToString(System.Globalization.CultureInfo.InvariantCulture),
            expectedRevision.ToString(System.Globalization.CultureInfo.InvariantCulture), bodyFingerprint);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(canonical)));
    }

    private static string PowerShell() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");

    private static string CommandPrompt() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

    private static string TranscriptText(TerminalSessionService service, TerminalOpenRequest request) =>
        Encoding.UTF8.GetString([.. service.ReadRetainedTranscript(
                request.Authority.SessionId, Context(request.Authority))
            .Where(record => record.Direction == "output" && record.Content is not null)
            .SelectMany(record => record.Content!)]);

    private static async Task<List<TerminalOutput>> ReadAllAsync(
        ITerminalSessionService service,
        TerminalOutputReadRequest request)
    {
        var result = new List<TerminalOutput>();
        await foreach (var item in service.ReadOutputAsync(request))
            result.Add(item);
        return result;
    }

    private static bool IsRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }

        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool TryReadProcessId(string path, out int processId)
    {
        processId = 0;
        try
        {
            return File.Exists(path) && int.TryParse(File.ReadAllText(path).Trim(), out processId);
        }

        catch (IOException)
        {
            return false;
        }
    }

    private sealed class ManualTimeProvider(DateTimeOffset initial) : TimeProvider
    {
        private readonly Lock gate = new();
        private readonly List<ManualTimer> timers = [];
        private DateTimeOffset now = initial;

        public override DateTimeOffset GetUtcNow()
        {
            lock (gate)
                return now;
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(this, callback, state, dueTime, period);
            lock (gate)
                timers.Add(timer);
            return timer;
        }

        internal DateTimeOffset Now
        {
            get
            {
                lock (gate)
                    return now;
            }
        }

        public void Advance(TimeSpan duration)
        {
            ManualTimer[] snapshot;
            lock (gate)
            {
                now += duration;
                snapshot = [.. timers];
            }
            foreach (var timer in snapshot)
                timer.FireIfDue(now);
        }

        private sealed class ManualTimer(
            ManualTimeProvider owner,
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period) : ITimer
        {
            private readonly Lock gate = new();
            private DateTimeOffset due = owner.Now + dueTime;
            private TimeSpan interval = period;
            private bool disposed;

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (gate)
                {
                    if (disposed)
                        return false;
                    due = owner.Now + dueTime;
                    interval = period;
                    return true;
                }
            }

            internal void FireIfDue(DateTimeOffset current)
            {
                lock (gate)
                {
                    if (disposed || current < due)
                        return;
                    if (interval == Timeout.InfiniteTimeSpan)
                        disposed = true;
                    else
                        due = current + interval;
                }
                callback(state);
            }

            public void Dispose()
            {
                lock (gate)
                    disposed = true;
            }

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }

    private const int TokenIsAppContainer = 29;
    private const int TokenCapabilities = 30;
    private const int TokenAppContainerSid = 31;

    private static ProcessIsolationProfile TerminalIsolation(
        TerminalOpenRequest request) => new(
        1,
        ProcessIsolationCapability.Terminal,
        Directory.GetParent(request.Authority.WorkspaceRoot)!.FullName,
        request.Authority.WorkspaceRoot,
        request.Authority.Task?.TaskAttemptId ??
            new TaskAttemptId(request.Authority.SessionId.Value),
        request.Authority.Task?.Generation ?? 1);

    private static string DeniedPowerShellFileCheck(string name, string path) =>
        $"try {{ Get-Content -LiteralPath '{path}' -ErrorAction Stop | Out-Null; '{name}-leaked' }} catch {{ '{name}-denied' }}";

    private static SafeFileHandle OpenToken(int processId)
    {
        using var process = OpenProcess(0x1000, false, checked((uint)processId));
        Assert.False(process.IsInvalid);
        Assert.True(OpenProcessToken(process, 0x0008, out var token));
        return token;
    }

    private static int ReadTokenInt32(SafeFileHandle token, int informationClass)
    {
        var pointer = ReadTokenInformation(token, informationClass);
        try
        {
            return Marshal.ReadInt32(pointer);
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    private static string ReadAppContainerSid(SafeFileHandle token)
    {
        var pointer = ReadTokenInformation(token, TokenAppContainerSid);
        try
        {
            var sid = Marshal.ReadIntPtr(pointer);
            Assert.NotEqual(IntPtr.Zero, sid);
            return new SecurityIdentifier(sid).Value;
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    private static IntPtr ReadTokenInformation(
        SafeFileHandle token,
        int informationClass)
    {
        _ = GetTokenInformation(
            token,
            informationClass,
            IntPtr.Zero,
            0,
            out var required);
        Assert.True(required > 0);
        var pointer = Marshal.AllocHGlobal(checked((int)required));
        if (!GetTokenInformation(
                token,
                informationClass,
                pointer,
                required,
                out _))
        {
            Marshal.FreeHGlobal(pointer);
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error());
        }
        return pointer;
    }

#pragma warning disable SYSLIB1054
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeFileHandle process,
        uint desiredAccess,
        out SafeFileHandle token);


    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeFileHandle token,
        int tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(
        SafeFileHandle handle,
        uint mask,
        uint flags);
#pragma warning restore SYSLIB1054
    public Task DisposeAsync()
    {
        try { Directory.Delete(directory, true); }
        catch (IOException) { }
        return Task.CompletedTask;
    }
}
