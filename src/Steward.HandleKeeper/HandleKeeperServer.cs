using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Steward.Runtime.Windows;

namespace Steward.HandleKeeper;

public sealed record HandleKeeperOptions(
    string PipeName,
    string ExpectedNodeAccount,
    int MaximumMessageBytes,
    int MaximumCachedRequests,
    TimeSpan RequestTimeout,
    TimeSpan IdempotencyTtl,
    int MaximumRetainedLeases,
    string? TrustedMaintenanceImagePath = null,
    string? TrustedProvisionerImagePath = null);

[SupportedOSPlatform("windows")]
public sealed class HandleKeeperServer : IDisposable
{
    private const uint ProcessDuplicateHandle = 0x0040;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint PipeRejectRemoteClients = 0x00000008;
    private readonly SecurityIdentifier expectedNodeSid;
    private readonly SecurityIdentifier systemSid = new(
        WellKnownSidType.LocalSystemSid,
        null);
    private readonly HandleKeeperOptions options;
    private readonly HandleKeeperDrainFenceState drainFence;
    private readonly ConcurrentDictionary<string, Lease> leases = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CachedRequest> requests = new(StringComparer.Ordinal);
    private readonly object requestGate = new();
    public HandleKeeperServer(HandleKeeperOptions options) :
        this(options, new HandleKeeperDrainFenceState())
    {
    }

    internal HandleKeeperServer(
        HandleKeeperOptions options,
        HandleKeeperDrainFenceState drainFence)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        expectedNodeSid = ResolveSid(this.options.ExpectedNodeAccount);
        this.drainFence = drainFence ??
            throw new ArgumentNullException(nameof(drainFence));
    }
    private long revokedProvisionalOpenCount;
    private bool disposed;

    private sealed record Lease(JobLeaseIdentity Identity, SafeFileHandle Handle);
    private sealed record ClientIdentity(
        uint ProcessId,
        long CreationTimeUtcTicks,
        SecurityIdentifier Sid,
        string ImagePath,
        string ImageSha256);
    private enum OpenHandleOwnership { None, Keeper, Client, Closed }
    private sealed record CachedRequest(
        uint ClientProcessId,
        long ClientCreationTimeUtcTicks,
        JobKeeperCommand Command,
        string PayloadHash,
        JobKeeperResponse Response,
        DateTimeOffset ExpiresAt,
        bool Acknowledged,
        bool InFlight,
        OpenHandleOwnership OpenHandleOwnership);
    private sealed class KeeperProtocolException(string code, string safeMessage) : Exception(safeMessage)
    {
        public string Code { get; } = code;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        ValidateOptions();
        using var cleanupCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var cleanup = ExpireRequestsLoop(cleanupCancellation.Token);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await using var pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(cancellationToken);
                using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                requestTimeout.CancelAfter(options.RequestTimeout);
                try { await HandleConnectionAsync(pipe, requestTimeout.Token); }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
            }
        }
        finally
        {
            cleanupCancellation.Cancel();
            try { await cleanup; }
            catch (OperationCanceledException) when (cleanupCancellation.IsCancellationRequested) { }
        }
    }

    private NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(expectedNodeSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        using var serviceIdentity = WindowsIdentity.GetCurrent();
        if (serviceIdentity.User is null) throw new InvalidOperationException("Keeper service identity has no SID.");
        security.AddAccessRule(new PipeAccessRule(serviceIdentity.User, PipeAccessRights.FullControl, AccessControlType.Allow));
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        var descriptorPointer = Marshal.AllocHGlobal(descriptor.Length);
        try
        {
            Marshal.Copy(descriptor, 0, descriptorPointer, descriptor.Length);
            var attributes = new NativeMethods.SecurityAttributes
            {
                Length = checked((uint)Marshal.SizeOf<NativeMethods.SecurityAttributes>()),
                SecurityDescriptor = descriptorPointer
            };
            var handle = NativeMethods.CreateNamedPipe(
                $@"\\.\pipe\{options.PipeName}",
                PipeAccessDuplex | FileFlagFirstPipeInstance | FileFlagOverlapped,
                PipeRejectRemoteClients,
                1,
                checked((uint)options.MaximumMessageBytes),
                checked((uint)options.MaximumMessageBytes),
                0,
                ref attributes);
            if (handle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.CreateNamedPipe));
            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }
        finally { Marshal.FreeHGlobal(descriptorPointer); }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        JobKeeperResponse response;
        JobKeeperRequest? request = null;
        ClientIdentity? caller = null;
        var cacheable = false;
        try
        {
            if (!NativeMethods.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid))
                throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.GetNamedPipeClientProcessId));
            caller = GetClientIdentity(pipe, clientPid);
            request = await JobKeeperProtocol.ReadAsync<JobKeeperRequest>(pipe, options.MaximumMessageBytes, cancellationToken);
            ValidateEnvelope(request);
            Authorize(request.Command, caller);
            var payloadHash = PayloadHash(request);
            lock (requestGate)
            {
                ExpireRequestsUnderLock();
                if (requests.TryGetValue(request.RequestId, out var cached))
                {
                    if (cached.ClientProcessId != caller.ProcessId ||
                        cached.ClientCreationTimeUtcTicks != caller.CreationTimeUtcTicks ||
                        cached.Command != request.Command ||
                        !StringComparer.Ordinal.Equals(cached.PayloadHash, payloadHash))
                        throw new KeeperProtocolException("request_id_conflict", "Request ID was reused with different authenticated content.");
                    response = cached.OpenHandleOwnership == OpenHandleOwnership.Closed
                        ? Error("open_abandoned", "Open request was abandoned.") with { RequiresAcknowledgement = true }
                        : cached.Response;
                    requests[request.RequestId] = cached with { InFlight = true };
                }
                else
                {
                    if (requests.Count >= options.MaximumCachedRequests)
                        throw new KeeperProtocolException("request_cache_full", "Request cache capacity is temporarily exhausted.");
                    try { response = Handle(request, caller); }
                    catch (Exception exception) { response = ToSafeError(exception); }
                    response = response with { RequiresAcknowledgement = true };
                    requests.Add(request.RequestId, new(caller.ProcessId, caller.CreationTimeUtcTicks,
                        request.Command, payloadHash, response, DateTimeOffset.UtcNow + options.IdempotencyTtl, false, true,
                        request.Command == JobKeeperCommand.Open && response.Success ? OpenHandleOwnership.Keeper : OpenHandleOwnership.None));
                }
                cacheable = true;
            }
        }
        catch (KeeperProtocolException exception)
        {
            response = Error(exception.Code, exception.Message);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            response = ToSafeError(exception);
        }

        try
        {
            await JobKeeperProtocol.WriteAsync(pipe, response, options.MaximumMessageBytes, cancellationToken);
            if (cacheable && request is not null && caller is not null)
            {
                var acknowledgement = new byte[1];
                await pipe.ReadExactlyAsync(acknowledgement, cancellationToken);
                if (acknowledgement[0] == JobKeeperProtocol.ResponseAcknowledgement)
                {
                    lock (requestGate)
                    {
                        if (requests.TryGetValue(request.RequestId, out var cached) &&
                            cached.ClientProcessId == caller.ProcessId &&
                            cached.ClientCreationTimeUtcTicks == caller.CreationTimeUtcTicks)
                            requests[request.RequestId] = cached with
                            {
                                Acknowledged = true,
                                OpenHandleOwnership = cached.OpenHandleOwnership == OpenHandleOwnership.Keeper
                                    ? OpenHandleOwnership.Client
                                    : cached.OpenHandleOwnership
                            };
                    }
                    await pipe.WriteAsync(new[] { JobKeeperProtocol.AcknowledgementConfirmation }, cancellationToken);
                    await pipe.FlushAsync(cancellationToken);
                }
            }
        }
        catch (IOException) { }
        finally
        {
            if (cacheable && request is not null && caller is not null)
            {
                lock (requestGate)
                {
                    if (requests.TryGetValue(request.RequestId, out var cached) &&
                        cached.ClientProcessId == caller.ProcessId &&
                        cached.ClientCreationTimeUtcTicks == caller.CreationTimeUtcTicks)
                        requests[request.RequestId] = cached with { InFlight = false };
                }
            }
        }
    }

    private JobKeeperResponse Handle(JobKeeperRequest request, ClientIdentity caller)
    {
        return request.Command switch
        {
            JobKeeperCommand.Retain => Retain(request, caller),
            JobKeeperCommand.Open => Open(request, caller),
            JobKeeperCommand.Release => Release(request),
            JobKeeperCommand.Abandon => Abandon(request, caller),
            JobKeeperCommand.List => List(),
            JobKeeperCommand.Health => FenceResponse(success: true),
            JobKeeperCommand.AcquireDrainFence => AcquireDrainFence(request),
            JobKeeperCommand.ReleaseDrainFence => ReleaseDrainFence(request),
            JobKeeperCommand.TransferDrainFence => TransferDrainFence(request),
            JobKeeperCommand.RollbackDrainFence => RollbackDrainFence(request),
            JobKeeperCommand.ReleaseTransferredDrainFence =>
                ReleaseTransferredDrainFence(request, caller),
            _ => throw new KeeperProtocolException("unknown_command", "Command is not supported.")
        };
    }

    private JobKeeperResponse Retain(
        JobKeeperRequest request,
        ClientIdentity caller) =>
        drainFence.ExecuteRetain(() =>
        {
            var identity = RequireIdentity(request);
            if (request.HandleValue is 0 or -1)
                throw new ArgumentException(
                    "Retain requires a valid source handle.");
            using var client = OpenVerifiedClient(
                caller,
                ProcessDuplicateHandle);
            if (!NativeMethods.DuplicateHandle(
                    client,
                    new IntPtr(request.HandleValue),
                    NativeMethods.GetCurrentProcess(),
                    out var duplicate,
                    0,
                    false,
                    DuplicateSameAccess))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    nameof(NativeMethods.DuplicateHandle));
            if (!NativeMethods.IsJobHandle(duplicate))
            {
                duplicate.Dispose();
                throw new UnauthorizedAccessException(
                    "Transferred handle is not a Job Object.");
            }

            if (leases.TryGetValue(identity.JobName, out var existing))
            {
                duplicate.Dispose();
                if (existing.Identity != identity)
                    throw new UnauthorizedAccessException(
                        "Job name is bound to another immutable identity.");
                return new JobKeeperResponse(
                    JobKeeperProtocol.Version,
                    true);
            }
            if (leases.Count >= options.MaximumRetainedLeases)
            {
                duplicate.Dispose();
                throw new KeeperProtocolException(
                    "lease_capacity",
                    "Retained lease capacity is exhausted.");
            }
            if (!leases.TryAdd(
                    identity.JobName,
                    new(identity, duplicate)))
            {
                duplicate.Dispose();
                throw new InvalidOperationException(
                    "Concurrent Job retention conflict.");
            }
            return new JobKeeperResponse(
                JobKeeperProtocol.Version,
                true);
        });

    private JobKeeperResponse Open(JobKeeperRequest request, ClientIdentity caller) =>
        drainFence.ExecuteRetain(() =>
    {
        var identity = RequireIdentity(request);
        if (!leases.TryGetValue(identity.JobName, out var lease))
            return Error("not_found", "Job lease was not found.");
        if (lease.Identity != identity) throw new UnauthorizedAccessException("Job lease identity mismatch.");
        using var client = OpenVerifiedClient(caller, ProcessDuplicateHandle);
        if (!NativeMethods.DuplicateHandle(NativeMethods.GetCurrentProcess(), lease.Handle, client,
                out var targetHandle, 0, false, DuplicateSameAccess))
            throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.DuplicateHandle));
        return new(JobKeeperProtocol.Version, true, HandleValue: targetHandle.ToInt64());
    });

    private JobKeeperResponse Release(JobKeeperRequest request) =>
        drainFence.ExecuteLeaseMutation(() =>
        {
            var identity = RequireIdentity(request);
            if (!leases.TryGetValue(identity.JobName, out var lease))
                return new JobKeeperResponse(
                    JobKeeperProtocol.Version,
                    true);
            if (lease.Identity != identity)
                throw new UnauthorizedAccessException(
                    "Job lease identity mismatch.");
            if (leases.TryRemove(identity.JobName, out lease))
                lease.Handle.Dispose();
            return new JobKeeperResponse(
                JobKeeperProtocol.Version,
                true);
        });

    private JobKeeperResponse Abandon(JobKeeperRequest request, ClientIdentity caller)
    {
        if (request.RelatedRequestId is null || !requests.TryGetValue(request.RelatedRequestId, out var original))
            return Error("not_found", "Related Open request was not found.");
        if (original.ClientProcessId != caller.ProcessId ||
            original.ClientCreationTimeUtcTicks != caller.CreationTimeUtcTicks ||
            original.Command != JobKeeperCommand.Open)
            throw new KeeperProtocolException("request_id_conflict", "Related Open request identity does not match.");
        if (original.OpenHandleOwnership is OpenHandleOwnership.Keeper or OpenHandleOwnership.Client)
        {
            CloseRemoteHandle(original);
            Interlocked.Increment(ref revokedProvisionalOpenCount);
            requests[request.RelatedRequestId] = original with { OpenHandleOwnership = OpenHandleOwnership.Closed };
        }
        return new(JobKeeperProtocol.Version, true);
    }

    private JobKeeperResponse AcquireDrainFence(JobKeeperRequest request)
    {
        var fence = RequireFence(request);
        var result = drainFence.Acquire(
            new HandleKeeperFenceAcquireRequest(
                fence.TransactionId,
                fence.ScopeId,
                Capability(fence.Capability),
                fence.ExpectedGeneration),
            () => leases.Count);
        return result.Status == HandleKeeperFenceAcquireStatus.Acquired
            ? FenceResponse(success: true)
            : FenceResponse(
                success: false,
                errorCode: "active_leases",
                error: "HandleKeeper retains active Job leases.");
    }

    private JobKeeperResponse ReleaseDrainFence(JobKeeperRequest request)
    {
        var fence = RequireFence(request);
        _ = drainFence.Release(new HandleKeeperFenceReleaseRequest(
            fence.TransactionId,
            fence.ScopeId,
            Capability(fence.Capability),
            fence.ExpectedGeneration));
        return FenceResponse(success: true);
    }

    private JobKeeperResponse TransferDrainFence(JobKeeperRequest request)
    {
        var fence = RequireFence(request);
        if (fence.TargetCapability is null ||
            fence.ProvisionerImageSha256 is null)
            throw new KeeperProtocolException(
                "invalid_request",
                "Fence transfer target is incomplete.");
        _ = drainFence.Transfer(new HandleKeeperFenceTransferRequest(
            fence.TransactionId,
            Capability(fence.Capability),
            fence.ExpectedGeneration,
            Capability(fence.TargetCapability),
            fence.ProvisionerImageSha256));
        return FenceResponse(success: true);
    }

    private JobKeeperResponse RollbackDrainFence(JobKeeperRequest request)
    {
        var fence = RequireFence(request);
        _ = drainFence.RollbackTransfer(
            fence.TransactionId,
            Capability(fence.Capability),
            fence.ExpectedGeneration);
        return FenceResponse(success: true);
    }

    private JobKeeperResponse ReleaseTransferredDrainFence(
        JobKeeperRequest request,
        ClientIdentity caller)
    {
        var fence = RequireFence(request);
        _ = drainFence.ReleaseTransferred(
            new HandleKeeperTransferredReleaseRequest(
                fence.TransactionId,
                Capability(fence.Capability),
                fence.ExpectedGeneration,
                caller.ImageSha256));
        return FenceResponse(success: true);
    }

    private JobKeeperResponse FenceResponse(
        bool success,
        string? errorCode = null,
        string? error = null)
    {
        var snapshot = drainFence.Snapshot;
        return new JobKeeperResponse(
            JobKeeperProtocol.Version,
            success,
            error,
            ErrorCode: errorCode,
            RetainedLeaseCount: leases.Count,
            RevokedProvisionalOpenCount:
                Interlocked.Read(ref revokedProvisionalOpenCount),
            DrainFenced: snapshot.Phase != HandleKeeperFencePhase.Unfenced,
            FenceGeneration: snapshot.Generation,
            FenceDepth: snapshot.Depth,
            FencePhase: ToProtocolPhase(snapshot.Phase));
    }

    private static JobKeeperFenceDto RequireFence(JobKeeperRequest request) =>
        request.Fence ?? throw new KeeperProtocolException(
            "invalid_request",
            "Fence command requires typed ownership.");

    private static HandleKeeperFenceCapability Capability(
        JobKeeperFenceCapability capability) => new(capability.Encoded);

    private static JobKeeperFencePhase ToProtocolPhase(
        HandleKeeperFencePhase phase) => phase switch
        {
            HandleKeeperFencePhase.Unfenced =>
                JobKeeperFencePhase.Unfenced,
            HandleKeeperFencePhase.MaintenanceOwned =>
                JobKeeperFencePhase.MaintenanceOwned,
            HandleKeeperFencePhase.ProvisionerOwned =>
                JobKeeperFencePhase.ProvisionerOwned,
            _ => throw new InvalidOperationException(
                "HandleKeeper fence phase is unsupported.")
        };
    private void Authorize(
        JobKeeperCommand command,
        ClientIdentity caller)
    {
        var maintenance = command is
            JobKeeperCommand.AcquireDrainFence or
            JobKeeperCommand.ReleaseDrainFence or
            JobKeeperCommand.TransferDrainFence or
            JobKeeperCommand.RollbackDrainFence;
        var provisioner = command ==
            JobKeeperCommand.ReleaseTransferredDrainFence;
        var health = command == JobKeeperCommand.Health;
        var authorized = maintenance
            ? caller.Sid.Equals(systemSid) &&
              options.TrustedMaintenanceImagePath is { } maintenanceImage &&
              string.Equals(
                  caller.ImagePath,
                  Path.GetFullPath(maintenanceImage),
                  StringComparison.OrdinalIgnoreCase)
            : provisioner
                ? caller.Sid.Equals(systemSid) &&
                  options.TrustedProvisionerImagePath is { } provisionerImage &&
                  string.Equals(
                      caller.ImagePath,
                      Path.GetFullPath(provisionerImage),
                      StringComparison.OrdinalIgnoreCase)
                : health
                    ? caller.Sid.Equals(systemSid) ||
                      caller.Sid.Equals(expectedNodeSid)
                    : caller.Sid.Equals(expectedNodeSid);
        if (!authorized)
            throw new KeeperProtocolException(
                "unauthorized",
                "Caller is not authorized for this HandleKeeper operation.");
    }

    private void ValidateEnvelope(JobKeeperRequest request)
    {
        if (request.ProtocolVersion != JobKeeperProtocol.Version)
            throw new KeeperProtocolException("unsupported_version", "Protocol version is unsupported.");
        if (request.RequestId.Length != 32 || !request.RequestId.All(Uri.IsHexDigit))
            throw new KeeperProtocolException("invalid_request_id", "Request ID is invalid.");
        if (!Enum.IsDefined(request.Command))
            throw new KeeperProtocolException("unknown_command", "Command is not supported.");
        if (request.Command is JobKeeperCommand.Retain or
            JobKeeperCommand.Open or JobKeeperCommand.Release)
        {
            _ = RequireIdentity(request);
            if (request.Fence is not null)
                throw new KeeperProtocolException(
                    "invalid_request",
                    "Lease command cannot contain fence ownership.");
        }
        else if (request.Command == JobKeeperCommand.Abandon)
        {
            if (request.Lease is not null || request.HandleValue != 0 ||
                request.Fence is not null ||
                request.RelatedRequestId is null ||
                request.RelatedRequestId.Length != 32 ||
                !request.RelatedRequestId.All(Uri.IsHexDigit))
                throw new KeeperProtocolException(
                    "invalid_request",
                    "Abandon payload is invalid.");
        }
        else if (request.Command is
            JobKeeperCommand.AcquireDrainFence or
            JobKeeperCommand.ReleaseDrainFence or
            JobKeeperCommand.TransferDrainFence or
            JobKeeperCommand.RollbackDrainFence or
            JobKeeperCommand.ReleaseTransferredDrainFence)
        {
            ValidateFenceRequest(request);
        }
        else if (request.Lease is not null || request.HandleValue != 0 ||
                 request.RelatedRequestId is not null ||
                 request.Fence is not null)
            throw new KeeperProtocolException(
                "invalid_request",
                "Command payload is invalid.");
        if (request.Command != JobKeeperCommand.Retain &&
            request.HandleValue != 0)
            throw new KeeperProtocolException(
                "invalid_request",
                "Only Retain accepts a handle.");
    }

    private static void ValidateFenceRequest(JobKeeperRequest request)
    {
        var fence = request.Fence ?? throw new KeeperProtocolException(
            "invalid_request",
            "Fence ownership payload is required.");
        if (request.Lease is not null || request.HandleValue != 0 ||
            request.RelatedRequestId is not null ||
            fence.TransactionId == Guid.Empty || fence.ScopeId == Guid.Empty)
            throw new KeeperProtocolException(
                "invalid_request",
                "Fence ownership payload is invalid.");
        var transfer = request.Command == JobKeeperCommand.TransferDrainFence;
        if (transfer != (fence.TargetCapability is not null) ||
            transfer != (fence.ProvisionerImageSha256 is not null) ||
            fence.ProvisionerImageSha256 is { } digest &&
            (digest.Length != 64 || !digest.All(char.IsAsciiHexDigit)))
            throw new KeeperProtocolException(
                "invalid_request",
                "Fence transfer target is invalid.");
    }
    private static JobLeaseIdentity RequireIdentity(JobKeeperRequest request)
    {
        var identity = request.Lease?.ToIdentity() ?? throw new ArgumentException("Command requires a lease identity.");
        identity.Validate();
        return identity;
    }

    private static ClientIdentity GetClientIdentity(NamedPipeServerStream pipe, uint clientPid)
    {
        SecurityIdentifier? impersonatedSid = null;
        if (!NativeMethods.ImpersonateNamedPipeClient(pipe.SafePipeHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.ImpersonateNamedPipeClient));
        try
        {
            if (!NativeMethods.OpenThreadToken(NativeMethods.GetCurrentThread(), 0x0008, true, out var threadToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.OpenThreadToken));
            using (threadToken) impersonatedSid = ReadTokenSid(threadToken);
        }
        finally
        {
            if (!NativeMethods.RevertToSelf()) throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.RevertToSelf));
        }

        using var process = NativeMethods.OpenProcess(0x1000, false, clientPid);
        if (process.IsInvalid) throw new KeeperProtocolException("caller_unverifiable", "Caller process cannot be verified.");
        if (!NativeMethods.OpenProcessToken(process, 0x0008, out var token))
            throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.OpenProcessToken));
        using (token)
        {
            var processSid = ReadTokenSid(token);
            if (!processSid.Equals(impersonatedSid))
                throw new KeeperProtocolException("caller_identity_changed", "Caller token identity changed during authentication.");
        }
        if (!NativeMethods.GetProcessTimes(process, out var creation, out _, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.GetProcessTimes));
        var imagePath = QueryProcessImagePath(process);
        var imageSha256 = Convert.ToHexString(
            SHA256.HashData(File.ReadAllBytes(imagePath)));
        return new ClientIdentity(
            clientPid,
            DateTime.FromFileTimeUtc(creation.ToLong()).Ticks,
            impersonatedSid,
            imagePath,
            imageSha256);
    }

    private void ValidateOptions()
    {
        if (string.IsNullOrWhiteSpace(options.PipeName) ||
            options.MaximumMessageBytes is < 1024 or > JobKeeperProtocol.AbsoluteMaximumMessageBytes ||
            options.MaximumCachedRequests is <= 0 or > 65536 ||
            options.RequestTimeout < TimeSpan.FromMilliseconds(100) || options.RequestTimeout > TimeSpan.FromSeconds(30) ||
            options.IdempotencyTtl < TimeSpan.FromSeconds(1) || options.IdempotencyTtl > TimeSpan.FromMinutes(10) ||
            options.MaximumRetainedLeases is <= 0 or > 65536 ||
            options.TrustedMaintenanceImagePath is not null &&
            !Path.IsPathFullyQualified(
                options.TrustedMaintenanceImagePath) ||
            options.TrustedProvisionerImagePath is not null &&
            !Path.IsPathFullyQualified(
                options.TrustedProvisionerImagePath) ||
            options.PipeName.Length > 128 ||
            options.PipeName.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.')))
            throw new ArgumentException("Handle keeper configuration is invalid.");
    }

    private JobKeeperResponse List()
    {
        var maximumItems = Math.Max(1, Math.Min(32, options.MaximumMessageBytes / 512));
        var items = leases.Values.Take(maximumItems).Select(x => JobKeeperLeaseDto.From(x.Identity)).ToArray();
        return new(JobKeeperProtocol.Version, true, Leases: items, RetainedLeaseCount: leases.Count,
            ListTruncated: items.Length < leases.Count);
    }

    private static JobKeeperResponse Error(string code, string message) =>
        new(JobKeeperProtocol.Version, false, message.Length <= 160 ? message : message[..160], ErrorCode: code);

    private static JobKeeperResponse ToSafeError(Exception exception) =>
        exception switch
        {
            KeeperProtocolException protocol => Error(protocol.Code, protocol.Message),
            HandleKeeperFenceException fence => Error(fence.Code, fence.Message),
            InvalidDataException or JsonException => Error("malformed_message", "Request message is malformed."),
            UnauthorizedAccessException => Error("unauthorized", "Caller is not authorized."),
            ArgumentException or FormatException => Error("invalid_request", "Request fields are invalid."),
            Win32Exception => Error("win32_failure", "Required Windows operation failed."),
            HandleKeeperFencedException => Error(
                "keeper_fenced",
                "HandleKeeper is fenced for maintenance."),
            _ => Error("internal_error", "Keeper request failed.")
        };

    private static string PayloadHash(JobKeeperRequest request)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            request.ProtocolVersion,
            request.Command,
            request.Lease,
            request.HandleValue,
            request.RelatedRequestId,
            request.Fence
        });
        return Convert.ToHexString(SHA256.HashData(payload));
    }

    private async Task ExpireRequestsLoop(CancellationToken cancellationToken)
    {
        var interval = TimeSpan.FromMilliseconds(Math.Max(100, Math.Min(1000, options.IdempotencyTtl.TotalMilliseconds / 2)));
        while (true)
        {
            await Task.Delay(interval, cancellationToken);
            lock (requestGate) ExpireRequestsUnderLock();
        }
    }

    private void ExpireRequestsUnderLock()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in requests.Where(pair => !pair.Value.InFlight && pair.Value.ExpiresAt <= now).ToArray())
        {
            if (pair.Value.OpenHandleOwnership == OpenHandleOwnership.Keeper)
            {
                try { CloseRemoteHandle(pair.Value); }
                catch (Exception exception) when (exception is Win32Exception or KeeperProtocolException or ArgumentException) { continue; }
                Interlocked.Increment(ref revokedProvisionalOpenCount);
            }
            requests.Remove(pair.Key);
        }
    }

    private static void CloseRemoteHandle(CachedRequest cached)
    {
        var caller = new ClientIdentity(
            cached.ClientProcessId,
            cached.ClientCreationTimeUtcTicks,
            null!,
            string.Empty,
            string.Empty);
        using var process = OpenVerifiedClient(caller, ProcessDuplicateHandle, verifySid: false);
        if (!NativeMethods.DuplicateHandle(process, new IntPtr(cached.Response.HandleValue), NativeMethods.GetCurrentProcess(),
                out var local, 0, false, DuplicateSameAccess | 0x00000001))
            throw new KeeperProtocolException("close_failed", "Provisional Open handle could not be revoked.");
        local.Dispose();
    }

    private static SafeFileHandle OpenVerifiedClient(ClientIdentity caller, uint access, bool verifySid = true)
    {
        var process = NativeMethods.OpenProcess(access | 0x1000, false, caller.ProcessId);
        if (process.IsInvalid) throw new KeeperProtocolException("caller_unverifiable", "Caller process cannot be verified.");
        if (!NativeMethods.GetProcessTimes(process, out var creation, out _, out _, out _) ||
            DateTime.FromFileTimeUtc(creation.ToLong()).Ticks != caller.CreationTimeUtcTicks)
        {
            process.Dispose();
            throw new KeeperProtocolException("caller_identity_changed", "Caller process identity changed.");
        }
        if (verifySid)
        {
            if (!NativeMethods.OpenProcessToken(process, 0x0008, out var token))
            {
                process.Dispose();
                throw new KeeperProtocolException("caller_unverifiable", "Caller token cannot be verified.");
            }
            using (token)
            {
                if (!ReadTokenSid(token).Equals(caller.Sid))
                {
                    process.Dispose();
                    throw new KeeperProtocolException("caller_identity_changed", "Caller token identity changed.");
                }
            }
        }
        return process;
    }

    private static string QueryProcessImagePath(SafeFileHandle process)
    {
        var capacity = 32_768;
        var value = new System.Text.StringBuilder(capacity);
        if (!NativeMethods.QueryFullProcessImageName(
                process,
                0,
                value,
                ref capacity) || capacity <= 0)
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                nameof(NativeMethods.QueryFullProcessImageName));
        var path = Path.GetFullPath(value.ToString());
        if (!File.Exists(path) ||
            File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new KeeperProtocolException(
                "caller_unverifiable",
                "Caller image cannot be verified.");
        return path;
    }
    private static SecurityIdentifier ReadTokenSid(SafeFileHandle token)
    {
        _ = NativeMethods.GetTokenInformation(token, 1, IntPtr.Zero, 0, out var required);
        if (required == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.GetTokenInformation));
        var buffer = Marshal.AllocHGlobal(checked((int)required));
        try
        {
            if (!NativeMethods.GetTokenInformation(token, 1, buffer, required, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), nameof(NativeMethods.GetTokenInformation));
            return new SecurityIdentifier(Marshal.ReadIntPtr(buffer));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static SecurityIdentifier ResolveSid(string accountOrSid)
    {
        if (accountOrSid.StartsWith("S-", StringComparison.OrdinalIgnoreCase))
            return new SecurityIdentifier(accountOrSid);
        return (SecurityIdentifier)new NTAccount(accountOrSid).Translate(typeof(SecurityIdentifier));
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        foreach (var lease in leases.Values) lease.Handle.Dispose();
        leases.Clear();
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityAttributes
        {
            internal uint Length;
            internal IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            internal bool InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FileTime
        {
            internal uint Low;
            internal uint High;
            internal long ToLong() => ((long)High << 32) | Low;
        }

#pragma warning disable SYSLIB1054
        [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafePipeHandle CreateNamedPipe(
            string name,
            uint openMode,
            uint pipeMode,
            uint maximumInstances,
            uint outBufferSize,
            uint inBufferSize,
            uint defaultTimeout,
            ref SecurityAttributes securityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ImpersonateNamedPipeClient(SafePipeHandle pipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool RevertToSelf();

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenThreadToken(IntPtr thread, uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out SafeFileHandle token);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "QueryFullProcessImageNameW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(
            SafeFileHandle process,
            uint flags,
            System.Text.StringBuilder imagePath,
            ref int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeFileHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetProcessTimes(SafeFileHandle process, out FileTime creation, out FileTime exit,
            out FileTime kernel, out FileTime user);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenProcessToken(SafeFileHandle process, uint desiredAccess, out SafeFileHandle token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetTokenInformation(SafeFileHandle token, int informationClass, IntPtr information,
            uint informationLength, out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(SafeFileHandle sourceProcess, IntPtr sourceHandle, IntPtr targetProcess,
            out SafeFileHandle targetHandle, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(IntPtr sourceProcess, SafeFileHandle sourceHandle, SafeFileHandle targetProcess,
            out IntPtr targetHandle, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(SafeFileHandle job, int informationClass,
            IntPtr information, uint informationLength, out uint returnLength);

#pragma warning restore SYSLIB1054

        internal static bool IsJobHandle(SafeFileHandle handle)
        {
            const int bufferSize = 48;
            var buffer = Marshal.AllocHGlobal(bufferSize);
            try { return QueryInformationJobObject(handle, 1, buffer, bufferSize, out _); }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
