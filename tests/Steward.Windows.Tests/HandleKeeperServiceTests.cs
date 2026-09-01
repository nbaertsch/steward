using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Steward.Domain;
using Steward.HandleKeeper;
using Steward.Runtime.Windows;
using Steward.Tasks.Abstractions;

namespace Steward.Windows.Tests;

[SupportedOSPlatform("windows")]
public sealed class HandleKeeperServiceTests : IAsyncLifetime
{
    private readonly List<Process> services = [];
    private readonly List<string> serviceRoots = [];
    private static readonly ConcurrentDictionary<int, StringBuilder> ServiceLogs = new();

    public Task InitializeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Retain_open_list_release_and_pid_spoof_use_actual_pipe_client()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = $"steward-keeper-{Guid.NewGuid():N}";
        await StartService(pipeName, CurrentSid());
        using var client = Client(pipeName);
        Assert.True(client.Health());

        var identity = Identity();
        using var job = CreateJob(identity.JobName);
        var spoofed = new JobKeeperRequest(JobKeeperProtocol.Version, JobKeeperCommand.Retain, Nonce(),
            JobKeeperLeaseDto.From(identity), job.DangerousGetHandle().ToInt64(), ClaimedClientProcessId: int.MaxValue);
        var response = await RawCall(pipeName, spoofed);
        Assert.True(response.Success, response.Error);

        using var opened = client.Open(identity);
        Assert.False(opened.IsInvalid);
        Assert.Contains(identity, client.List());
        var mismatch = identity with { NodeIncarnationId = NodeIncarnationId.New() };
        Assert.Throws<UnauthorizedAccessException>(() => client.Open(mismatch));
        client.Release(identity);
        Assert.Throws<KeyNotFoundException>(() => client.Open(identity));
    }

    [Fact]
    public async Task Lost_responses_retry_idempotently_for_retain_open_and_release()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = $"steward-keeper-{Guid.NewGuid():N}";
        await StartService(pipeName, CurrentSid(), "--cache-ttl-seconds", "1");
        var identity = Identity();
        using var job = CreateJob(identity.JobName);

        var retain = new JobKeeperRequest(JobKeeperProtocol.Version, JobKeeperCommand.Retain, Nonce(),
            JobKeeperLeaseDto.From(identity), job.DangerousGetHandle().ToInt64(), int.MaxValue);
        await SendWithoutReading(pipeName, retain);
        await Task.Delay(100);
        Assert.True((await RawCall(pipeName, retain)).Success);

        var open = new JobKeeperRequest(JobKeeperProtocol.Version, JobKeeperCommand.Open, Nonce(),
            JobKeeperLeaseDto.From(identity), ClaimedClientProcessId: int.MaxValue);
        var firstOpenResponse = await RawCallWithoutAcknowledgement(pipeName, open);
        var lostConfirmationResponse = await RawCallWithAcknowledgementWithoutConfirmation(pipeName, open);
        var openResponse = await RawCall(pipeName, open);
        Assert.True(openResponse.Success);
        Assert.Equal(firstOpenResponse.HandleValue, openResponse.HandleValue);
        Assert.Equal(lostConfirmationResponse.HandleValue, openResponse.HandleValue);
        using (var opened = new SafeFileHandle(new IntPtr(openResponse.HandleValue), true))
        {
            Assert.True(IsJobHandle(opened));
            await Task.Delay(1200);
            Assert.True(IsJobHandle(opened));
        }

        var release = new JobKeeperRequest(JobKeeperProtocol.Version, JobKeeperCommand.Release, Nonce(),
            JobKeeperLeaseDto.From(identity), ClaimedClientProcessId: int.MaxValue);
        await SendWithoutReading(pipeName, release);
        await Task.Delay(100);
        Assert.True((await RawCall(pipeName, release)).Success);
        Assert.Equal("request_id_conflict",
            (await RawCall(pipeName, release with { Command = JobKeeperCommand.Health, Lease = null })).ErrorCode);
    }

    [Fact]
    public async Task Health_list_lease_capacity_and_cache_expiry_are_bounded()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = $"steward-keeper-{Guid.NewGuid():N}";
        await StartService(pipeName, CurrentSid(), "--max-leases", "1");
        var first = Identity();
        using var firstJob = CreateJob(first.JobName);
        Assert.True((await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Retain, Nonce(),
            JobKeeperLeaseDto.From(first), firstJob.DangerousGetHandle().ToInt64()))).Success);
        var second = Identity();
        using var secondJob = CreateJob(second.JobName);
        var full = await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Retain, Nonce(),
            JobKeeperLeaseDto.From(second), secondJob.DangerousGetHandle().ToInt64()));
        Assert.Equal("lease_capacity", full.ErrorCode);
        var health = await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce()));
        var list = await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.List, Nonce()));
        Assert.Equal(1, health.RetainedLeaseCount);
        Assert.Equal(1, list.RetainedLeaseCount);
        Assert.Single(list.Leases!);

        var cachePipe = $"steward-keeper-{Guid.NewGuid():N}";
        await StartService(cachePipe, CurrentSid(), "--cache-capacity", "2", "--cache-ttl-seconds", "1");
        Assert.True((await RawCall(cachePipe, new(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce()))).Success);
        Assert.Equal("request_cache_full",
            (await RawCall(cachePipe, new(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce()))).ErrorCode);
        await Task.Delay(1200);
        Assert.True((await RawCall(cachePipe, new(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce()))).Success);
    }

    [Fact]
    public async Task Unacknowledged_open_handle_is_closed_when_cache_entry_expires()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = $"steward-keeper-{Guid.NewGuid():N}";
        await StartService(pipeName, CurrentSid(), "--cache-ttl-seconds", "1");
        var identity = Identity();
        using var job = CreateJob(identity.JobName);
        Assert.True((await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Retain, Nonce(),
            JobKeeperLeaseDto.From(identity), job.DangerousGetHandle().ToInt64()))).Success);

        var response = await RawCallWithoutAcknowledgement(pipeName,
            new(JobKeeperProtocol.Version, JobKeeperCommand.Open, Nonce(), JobKeeperLeaseDto.From(identity)));
        using var borrowed = new SafeFileHandle(new IntPtr(response.HandleValue), ownsHandle: false);
        Assert.True(IsJobHandle(borrowed));
        await Task.Delay(1200);
        Assert.True((await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce()))).Success);
        Assert.False(IsJobHandle(borrowed));
    }

    [Fact]
    public async Task Abandon_has_exclusive_close_authority_and_never_closes_a_reused_handle()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = $"steward-keeper-{Guid.NewGuid():N}";
        await StartService(pipeName, CurrentSid(), "--cache-ttl-seconds", "1");
        var identity = Identity();
        using var job = CreateJob(identity.JobName);
        await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Retain, Nonce(),
            JobKeeperLeaseDto.From(identity), job.DangerousGetHandle().ToInt64()));
        var openRequest = new JobKeeperRequest(JobKeeperProtocol.Version, JobKeeperCommand.Open, Nonce(), JobKeeperLeaseDto.From(identity));
        var openResponse = await RawCallWithAcknowledgementWithoutConfirmation(pipeName, openRequest);
        using var oldHandle = new SafeFileHandle(new IntPtr(openResponse.HandleValue), ownsHandle: false);
        Assert.True(IsJobHandle(oldHandle));

        var abandon = await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Abandon, Nonce(),
            RelatedRequestId: openRequest.RequestId));
        Assert.True(abandon.Success);
        Assert.False(IsJobHandle(oldHandle));
        Assert.Equal("open_abandoned", (await RawCall(pipeName, openRequest)).ErrorCode);
        var afterAbandon = await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce()));
        Assert.Equal(1, afterAbandon.RevokedProvisionalOpenCount);

        using var unrelated = CreateEvent(IntPtr.Zero, false, false, null);
        await Task.Delay(1200);
        var afterTtl = await RawCall(pipeName, new(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce()));
        Assert.Equal(1, afterTtl.RevokedProvisionalOpenCount);
        Assert.True(SetEvent(unrelated));
    }

    [Fact]
    public async Task Node_identity_cannot_invoke_system_drain_fence()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = $"steward-keeper-{Guid.NewGuid():N}";
        await StartService(pipeName, CurrentSid());

        var capability = new JobKeeperFenceCapability(
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        var transactionId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        var begin = await RawCall(pipeName, new(
            JobKeeperProtocol.Version,
            JobKeeperCommand.AcquireDrainFence,
            Nonce(),
            Fence: new JobKeeperFenceDto(
                transactionId,
                scopeId,
                capability,
                0)));
        var end = await RawCall(pipeName, new(
            JobKeeperProtocol.Version,
            JobKeeperCommand.ReleaseDrainFence,
            Nonce(),
            Fence: new JobKeeperFenceDto(
                transactionId,
                scopeId,
                capability,
                1)));

        Assert.Equal("unauthorized", begin.ErrorCode);
        Assert.Equal("unauthorized", end.ErrorCode);
    }

    [Fact]
    public void Drain_fence_atomically_blocks_new_retains_until_owner_release()
    {
        var state = new HandleKeeperDrainFenceState();
        var active = 1;
        var capability = HandleKeeperFenceCapability.Create();
        var transactionId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        var request = new HandleKeeperFenceAcquireRequest(
            transactionId,
            scopeId,
            capability,
            ExpectedGeneration: 0);

        var held = state.Acquire(request, () => active);
        Assert.Equal(HandleKeeperFenceAcquireStatus.LeaseHeld, held.Status);
        Assert.Throws<HandleKeeperFencedException>(() =>
            state.ExecuteRetain(() => active++));

        active--;
        var acquired = state.Acquire(request, () => active);
        Assert.Equal(HandleKeeperFenceAcquireStatus.Acquired, acquired.Status);
        _ = state.Release(new HandleKeeperFenceReleaseRequest(
            transactionId,
            scopeId,
            capability,
            acquired.Snapshot.Generation));
        state.ExecuteRetain(() => active++);

        Assert.False(state.IsFenced);
        Assert.Equal(1, active);
    }
    [Fact]
    public void Durable_fence_enforces_capability_generation_depth_and_restart_CAS()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "steward-keeper-fence-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "fence.journal");
            var key = RandomNumberGenerator.GetBytes(32);
            var capability = HandleKeeperFenceCapability.Create();
            var transactionId = Guid.NewGuid();
            var firstScope = Guid.NewGuid();
            var state = new HandleKeeperDrainFenceState(
                new FileHandleKeeperFenceStore(path, key));

            var held = state.Acquire(
                new HandleKeeperFenceAcquireRequest(
                    transactionId,
                    firstScope,
                    capability,
                    ExpectedGeneration: 0),
                () => 1);
            Assert.Equal(HandleKeeperFenceAcquireStatus.LeaseHeld, held.Status);
            Assert.Equal((ulong)1, held.Snapshot.Generation);
            Assert.Equal(1, held.Snapshot.Depth);
            Assert.Throws<HandleKeeperFencedException>(() =>
                state.ExecuteRetain(() => true));

            var restarted = new HandleKeeperDrainFenceState(
                new FileHandleKeeperFenceStore(path, key));
            var replay = restarted.Acquire(
                new HandleKeeperFenceAcquireRequest(
                    transactionId,
                    firstScope,
                    capability,
                    ExpectedGeneration: 0),
                () => 0);
            Assert.Equal((ulong)1, replay.Snapshot.Generation);
            Assert.Equal(1, replay.Snapshot.Depth);

            var nested = restarted.Acquire(
                new HandleKeeperFenceAcquireRequest(
                    transactionId,
                    Guid.NewGuid(),
                    capability,
                    ExpectedGeneration: 1),
                () => 0);
            Assert.Equal(2, nested.Snapshot.Depth);
            Assert.Equal((ulong)2, nested.Snapshot.Generation);
            Assert.Throws<HandleKeeperFenceException>(() =>
                restarted.Release(new HandleKeeperFenceReleaseRequest(
                    transactionId,
                    firstScope,
                    capability,
                    ExpectedGeneration: 1)));
            Assert.Throws<HandleKeeperFenceException>(() =>
                restarted.Acquire(
                    new HandleKeeperFenceAcquireRequest(
                        transactionId,
                        Guid.NewGuid(),
                        HandleKeeperFenceCapability.Create(),
                        ExpectedGeneration: 2),
                    () => 0));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Fence_transfer_binds_transaction_provisioner_identity_and_exact_rollback_snapshot()
    {
        var store = new InMemoryHandleKeeperFenceStore();
        var state = new HandleKeeperDrainFenceState(store);
        var transactionId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        var maintenance = HandleKeeperFenceCapability.Create();
        var provisioner = HandleKeeperFenceCapability.Create();
        var image = new string('A', 64);
        var acquired = state.Acquire(
            new HandleKeeperFenceAcquireRequest(
                transactionId,
                scopeId,
                maintenance,
                ExpectedGeneration: 0),
            () => 0);

        var transferred = state.Transfer(
            new HandleKeeperFenceTransferRequest(
                transactionId,
                maintenance,
                acquired.Snapshot.Generation,
                provisioner,
                image));

        Assert.Equal(HandleKeeperFencePhase.ProvisionerOwned,
            transferred.Phase);
        Assert.NotNull(transferred.RollbackSnapshot);
        Assert.Equal(HandleKeeperFencePhase.MaintenanceOwned,
            transferred.RollbackSnapshot!.Phase);
        Assert.Throws<HandleKeeperFenceException>(() =>
            state.ReleaseTransferred(new HandleKeeperTransferredReleaseRequest(
                transactionId,
                provisioner,
                transferred.Generation,
                new string('B', 64))));
        Assert.Throws<HandleKeeperFenceException>(() =>
            state.RollbackTransfer(
                Guid.NewGuid(),
                maintenance,
                transferred.Generation));

        var rolledBack = state.RollbackTransfer(
            transactionId,
            maintenance,
            transferred.Generation);
        Assert.Equal(HandleKeeperFencePhase.MaintenanceOwned,
            rolledBack.Phase);
        Assert.Equal(1, rolledBack.Depth);
        Assert.Equal(scopeId, Assert.Single(rolledBack.ScopeIds));
        Assert.True(rolledBack.Generation > transferred.Generation);
    }
    [Fact]
    public async Task Unauthorized_configuration_is_denied()
    {
        if (!OperatingSystem.IsWindows()) return;
        var unauthorizedPipe = $"steward-keeper-{Guid.NewGuid():N}";
        var service = StartServiceProcess(unauthorizedPipe, "S-1-5-18");
        services.Add(service);
        await Task.Delay(1000);
        Assert.False(service.HasExited);
        Assert.False((await RawCall(unauthorizedPipe,
            new(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce(), ClaimedClientProcessId: Environment.ProcessId))).Success);
    }

    [Fact]
    public async Task Replayed_malformed_and_oversized_requests_are_denied()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = $"steward-keeper-{Guid.NewGuid():N}";
        await StartService(pipeName, CurrentSid());
        var request = new JobKeeperRequest(JobKeeperProtocol.Version, JobKeeperCommand.Health, Nonce(),
            ClaimedClientProcessId: int.MaxValue);
        Assert.True((await RawCall(pipeName, request)).Success);
        Assert.True((await RawCall(pipeName, request)).Success);
        Assert.Equal("request_id_conflict",
            (await RawCall(pipeName, request with { Command = JobKeeperCommand.List })).ErrorCode);

        Assert.False((await RawBytes(pipeName, [1, 2, 3])).Success);
        var oversizedPrefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(oversizedPrefix, JobKeeperProtocol.AbsoluteMaximumMessageBytes + 1);
        Assert.False((await RawFramed(pipeName, oversizedPrefix)).Success);
    }

    [Fact]
    public async Task First_instance_squatting_is_rejected()
    {
        if (!OperatingSystem.IsWindows()) return;
        var occupied = $"steward-keeper-{Guid.NewGuid():N}";
        await using var squatter = new NamedPipeServerStream(occupied, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var rejected = StartServiceProcess(occupied, CurrentSid());
        services.Add(rejected);
        Assert.True(rejected.WaitForExit(10_000));
    }

    [Fact]
    public async Task Executor_can_reconnect_while_service_lives_and_keeper_crash_terminates_tree()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = $"steward-keeper-{Guid.NewGuid():N}";
        var service = await StartService(pipeName, CurrentSid());
        var node = NodeIncarnationId.New();
        var folder = Path.Combine(Path.GetTempPath(), "steward-keeper-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var journal = new ExecutionJournal(Path.Combine(folder, "journal.db"));
        var options = new NamedPipeJobHandleKeeperOptions(pipeName, TimeSpan.FromSeconds(2), ConnectAttempts: 10);
        IExecutionHandle execution;
        using (var firstKeeper = new NamedPipeJobHandleKeeper(options))
        using (var first = new WindowsProcessExecutor(journal, firstKeeper, node, "boot"))
        {
            var attemptId = TaskAttemptId.New();
            execution = await first.StartAsync(new(
                AttemptId: attemptId,
                Generation: 1,
                ApplicationPath: Path.Combine(
                    Environment.SystemDirectory,
                    "cmd.exe"),
                Arguments:
                [
                    "/d", "/c",
                    "for /L %i in (1,1,2147483647) do @rem"
                ],
                WorkingDirectory: folder,
                SpoolDirectory: Path.Combine(folder, "spool"),
                MaxOutputBytes: 1024 * 1024,
                RequiredDiskReserveBytes: 0,
                Isolation: new ProcessIsolationProfile(
                    1,
                    ProcessIsolationCapability.Process,
                    Path.GetDirectoryName(folder)!,
                    folder,
                    attemptId,
                    1)), default);
        }

        using (var secondKeeper = new NamedPipeJobHandleKeeper(options))
        using (var second = new WindowsProcessExecutor(journal, secondKeeper, node, "boot"))
        {
            var recovered = await second.RecoverAsync(execution.AttemptId, execution.Generation, "boot", default);
            Assert.Equal(execution.ProcessCreationTimeUtcTicks, recovered.ProcessCreationTimeUtcTicks);
        }

        service.Kill(entireProcessTree: true);
        await service.WaitForExitAsync();
        await StartService(pipeName, CurrentSid());
        using (var replacementKeeper = new NamedPipeJobHandleKeeper(options))
        {
            Assert.True(replacementKeeper.Health());
            Assert.Empty(replacementKeeper.List());
        }
        Assert.True(SpinWait.SpinUntil(
            () => !IsRunning(execution.ProcessId),
            TimeSpan.FromSeconds(10)));
        using var deadKeeper = new NamedPipeJobHandleKeeper(options with { ConnectAttempts = 1, ConnectTimeout = TimeSpan.FromMilliseconds(100) });
        using var recovery = new WindowsProcessExecutor(journal, deadKeeper, node, "boot");
        var error = await Assert.ThrowsAsync<ExecutionRecoveryException>(
            () => recovery.RecoverAsync(execution.AttemptId, execution.Generation, "boot", default).AsTask());
        Assert.False(error.IsAmbiguous);
        try { Process.GetProcessById(execution.ProcessId).Kill(entireProcessTree: true); } catch (ArgumentException) { }
        try { Directory.Delete(folder, true); } catch (IOException) { }
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
    private async Task<Process> StartService(string pipeName, string sid, params string[] extraArguments)
    {
        var process = StartServiceProcess(pipeName, sid, extraArguments);
        services.Add(process);
        using var client = Client(pipeName, attempts: 1);
        for (var index = 0; index < 50; index++)
        {
            if (process.HasExited)
                throw new InvalidOperationException(ServiceLogs.TryGetValue(process.Id, out var log) ? log.ToString() : "Handle keeper exited during startup.");
            try
            {
                if (client.Health()) return process;
            }
            catch (Exception exception) when (exception is IOException or TimeoutException or UnauthorizedAccessException)
            {
                if (sid != CurrentSid() && exception is UnauthorizedAccessException) return process;
            }
            await Task.Delay(50);
        }
        throw new TimeoutException("Handle keeper did not become ready.");
    }

    private Process StartServiceProcess(string pipeName, string sid, params string[] extraArguments)
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "Steward.HandleKeeper.dll");
        if (!File.Exists(path))
            throw new FileNotFoundException(
                "The referenced HandleKeeper test executable is unavailable.",
                path);
        var runtime = new DirectoryInfo(Path.GetDirectoryName(typeof(object).Assembly.Location)!);
        var dotnet = Path.Combine(runtime.Parent!.Parent!.Parent!.FullName, "dotnet.exe");
        var serviceRoot = Path.Combine(
            Path.GetTempPath(),
            "steward-keeper-service-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(serviceRoot);
        serviceRoots.Add(serviceRoot);
        var keyPath = Path.Combine(serviceRoot, "fence.key");
        File.WriteAllBytes(keyPath, RandomNumberGenerator.GetBytes(32));
        var fencePath = Path.Combine(serviceRoot, "fence.journal");
        var startInfo = new ProcessStartInfo
        {
            FileName = dotnet,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };
        startInfo.ArgumentList.Add(path);
        startInfo.ArgumentList.Add("--pipe");
        startInfo.ArgumentList.Add(pipeName);
        startInfo.ArgumentList.Add("--node-account");
        startInfo.ArgumentList.Add(sid);
        startInfo.ArgumentList.Add("--fence-state-file");
        startInfo.ArgumentList.Add(fencePath);
        startInfo.ArgumentList.Add("--fence-key-file");
        startInfo.ArgumentList.Add(keyPath);
        startInfo.ArgumentList.Add("--maintenance-image");
        startInfo.ArgumentList.Add(dotnet);
        startInfo.ArgumentList.Add("--provisioner-image");
        startInfo.ArgumentList.Add(dotnet);
        foreach (var argument in extraArguments) startInfo.ArgumentList.Add(argument);
        var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start HandleKeeper.");
        var log = new StringBuilder();
        ServiceLogs[process.Id] = log;
        process.OutputDataReceived += (_, eventArgs) => { if (eventArgs.Data is not null) log.AppendLine(eventArgs.Data); };
        process.ErrorDataReceived += (_, eventArgs) => { if (eventArgs.Data is not null) log.AppendLine(eventArgs.Data); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
    }

    private static NamedPipeJobHandleKeeper Client(string pipeName, int attempts = 3) =>
        new(new(pipeName, TimeSpan.FromMilliseconds(250), ConnectAttempts: attempts));

    private static JobLeaseIdentity Identity()
    {
        var attempt = TaskAttemptId.New();
        return new($@"Local\Steward.{attempt.Value:N}.1", attempt, 1, NodeIncarnationId.New());
    }

    private static SafeFileHandle CreateJob(string name)
    {
        var handle = CreateJobObject(IntPtr.Zero, name);
        if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        return handle;
    }

    private static async Task<JobKeeperResponse> RawCall(string pipeName, JobKeeperRequest request)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(2000, timeout.Token);
        await JobKeeperProtocol.WriteAsync(pipe, request, 16 * 1024, timeout.Token);
        var response = await JobKeeperProtocol.ReadAsync<JobKeeperResponse>(pipe, 16 * 1024, timeout.Token);
        if (response.RequiresAcknowledgement)
        {
            pipe.WriteByte(JobKeeperProtocol.ResponseAcknowledgement);
            await pipe.FlushAsync(timeout.Token);
            var confirmation = new byte[1];
            await pipe.ReadExactlyAsync(confirmation, timeout.Token);
            Assert.Equal(JobKeeperProtocol.AcknowledgementConfirmation, confirmation[0]);
        }
        return response;
    }

    private static async Task<JobKeeperResponse> RawCallWithoutAcknowledgement(string pipeName, JobKeeperRequest request)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(2000, timeout.Token);
        await JobKeeperProtocol.WriteAsync(pipe, request, 16 * 1024, timeout.Token);
        return await JobKeeperProtocol.ReadAsync<JobKeeperResponse>(pipe, 16 * 1024, timeout.Token);
    }

    private static async Task<JobKeeperResponse> RawCallWithAcknowledgementWithoutConfirmation(string pipeName, JobKeeperRequest request)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(2000, timeout.Token);
        await JobKeeperProtocol.WriteAsync(pipe, request, 16 * 1024, timeout.Token);
        var response = await JobKeeperProtocol.ReadAsync<JobKeeperResponse>(pipe, 16 * 1024, timeout.Token);
        pipe.WriteByte(JobKeeperProtocol.ResponseAcknowledgement);
        await pipe.FlushAsync(timeout.Token);
        return response;
    }

    private static async Task<JobKeeperResponse> RawBytes(string pipeName, byte[] payload)
    {
        var prefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        return await RawFramed(pipeName, [.. prefix, .. payload]);
    }

    private static async Task SendWithoutReading(string pipeName, JobKeeperRequest request)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(2000, timeout.Token);
        await JobKeeperProtocol.WriteAsync(pipe, request, 16 * 1024, timeout.Token);
        await pipe.FlushAsync(timeout.Token);
    }

    private static async Task<JobKeeperResponse> RawFramed(string pipeName, byte[] bytes)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(2000, timeout.Token);
        await pipe.WriteAsync(bytes, timeout.Token);
        await pipe.FlushAsync(timeout.Token);
        return await JobKeeperProtocol.ReadAsync<JobKeeperResponse>(pipe, 16 * 1024, timeout.Token);
    }

    private static string CurrentSid() => WindowsIdentity.GetCurrent().User!.Value;
    private static string PowerShell() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Steward.slnx"))) current = current.Parent;
        return current?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }

    public Task DisposeAsync()
    {
        foreach (var service in services)
        {
            if (!service.HasExited) service.Kill();
            service.WaitForExit(5000);
            ServiceLogs.TryRemove(service.Id, out _);
            service.Dispose();
        }
        foreach (var root in serviceRoots)
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        return Task.CompletedTask;
    }

    private static string Nonce() => Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));

#pragma warning disable SYSLIB1054
    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateJobObject(IntPtr securityAttributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int informationClass,
        IntPtr information, uint informationLength, out uint returnLength);
    [DllImport("kernel32.dll", EntryPoint = "CreateEventW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeWaitHandle CreateEvent(IntPtr securityAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool manualReset,
        [MarshalAs(UnmanagedType.Bool)] bool initialState,
        string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetEvent(SafeWaitHandle handle);
#pragma warning restore SYSLIB1054

    private static bool IsJobHandle(SafeFileHandle handle)
    {
        var buffer = Marshal.AllocHGlobal(48);
        try { return QueryInformationJobObject(handle, 1, buffer, 48, out _); }
        finally { Marshal.FreeHGlobal(buffer); }
    }
}
