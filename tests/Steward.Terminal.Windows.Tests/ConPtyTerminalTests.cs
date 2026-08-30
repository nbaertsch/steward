using System.Diagnostics;
using System.Text;
using Steward.Domain;
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
        var opened = await service.OpenAsync(request, Context(request.Authority));
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
        var output = Encoding.UTF8.GetString(transcript.Where(record => record.Direction == "output" &&
            record.Content is not null).SelectMany(record => record.Content!).ToArray());
        Assert.Contains(token, output, StringComparison.Ordinal);
    }

    [Fact(Timeout = 30_000)]
    public async Task Input_and_output_are_bounded()
    {
        await using var service = Service(maximumInputMessageBytes: 64);
        var request = Request(TerminalTranscriptMode.Metadata, maximumInput: 1024, maximumOutput: 1024) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command", "Start-Sleep 10"]
        };
        var opened = await service.OpenAsync(request, Context(request.Authority));
        var tooLarge = await Assert.ThrowsAsync<TerminalException>(() =>
            service.WriteInputAsync(new(request.Authority.SessionId, Context(request.Authority),
                NewRequestId(), opened.Revision, new byte[65])).AsTask());
        Assert.Equal(TerminalProblemCode.InvalidRequest, tooLarge.Problem.Code);

        await using var limitedService = Service(maximumInputMessageBytes: 64);
        var limitedRequest = Request(TerminalTranscriptMode.None, maximumInput: 16, maximumOutput: 1024);
        var limitedOpened = await limitedService.OpenAsync(limitedRequest, Context(limitedRequest.Authority));
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
        await outputService.OpenAsync(outputRequest, Context(outputRequest.Authority));
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
        var opened = await service.OpenAsync(request, Context(request.Authority));
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
            await service.OpenAsync(request, Context(request.Authority));
            Assert.True(SpinWait.SpinUntil(() => File.Exists(sentinel), TimeSpan.FromSeconds(15)));
            Assert.True(SpinWait.SpinUntil(() =>
                noReaderJournal.Get(request.Authority.SessionId).OutputSequence > 2, TimeSpan.FromSeconds(10)));
        }

        await using var replayService = Service(notificationCapacity: 2);
        var token = "replay-" + Guid.NewGuid().ToString("N");
        var replayRequest = Request(TerminalTranscriptMode.None, operationalSpoolBytes: 1024 * 1024) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command",
                $"$host.UI.RawUI.WindowTitle='{token}'; Start-Sleep 10"]
        };
        var opened = await replayService.OpenAsync(replayRequest, Context(replayRequest.Authority));
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
        Assert.Contains(token, Encoding.UTF8.GetString(first.SelectMany(item => item.Data.ToArray()).ToArray()),
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
        var opened = await service.OpenAsync(request, Context(request.Authority));
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
        var request = Request(TerminalTranscriptMode.None) with
        {
            Arguments = ["-NoLogo", "-NoProfile", "-Command", "Start-Sleep 30"]
        };
        var opened = await service.OpenAsync(request, Context(request.Authority));
        Assert.Equal(TerminalSessionState.Open, opened.State);
        Volatile.Write(ref revision, 1);
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True(SpinWait.SpinUntil(() =>
        {
            var snapshot = journal.Get(request.Authority.SessionId);
            return snapshot.State == TerminalSessionState.Interrupted &&
                   snapshot.InterruptionReason == "authority-revoked";
        }, TimeSpan.FromSeconds(10)));
        Assert.True(SpinWait.SpinUntil(() => !IsRunning(opened.ProcessId!.Value), TimeSpan.FromSeconds(10)));
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
        Encoding.UTF8.GetString(service.ReadRetainedTranscript(
                request.Authority.SessionId, Context(request.Authority))
            .Where(record => record.Direction == "output" && record.Content is not null)
            .SelectMany(record => record.Content!)
            .ToArray());

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
        private readonly object gate = new();
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
                snapshot = timers.ToArray();
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
            private readonly object gate = new();
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

    public Task DisposeAsync()
    {
        try { Directory.Delete(directory, true); }
        catch (IOException) { }
        return Task.CompletedTask;
    }
}
