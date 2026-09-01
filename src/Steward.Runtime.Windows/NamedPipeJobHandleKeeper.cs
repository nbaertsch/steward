using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Steward.Runtime.Windows;

public sealed record NamedPipeJobHandleKeeperOptions(
    string PipeName,
    TimeSpan ConnectTimeout,
    int MaximumMessageBytes = 16 * 1024,
    int ConnectAttempts = 3);

public enum JobKeeperFencePhase
{
    Unfenced,
    MaintenanceOwned,
    ProvisionerOwned
}

public sealed record JobKeeperFenceCapability
{
    public JobKeeperFenceCapability(string encoded)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encoded);
        byte[] value;
        try
        {
            value = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "Job keeper fence capability is invalid.",
                nameof(encoded),
                exception);
        }
        try
        {
            if (value.Length != 32)
                throw new ArgumentException(
                    "Job keeper fence capability must be 256 bits.",
                    nameof(encoded));
            Encoded = encoded;
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(
                value);
        }
    }

    public string Encoded { get; }

    public override string ToString() => "[job-keeper-fence-capability]";
}

public sealed record JobKeeperFenceDto(
    Guid TransactionId,
    Guid ScopeId,
    JobKeeperFenceCapability Capability,
    ulong ExpectedGeneration,
    JobKeeperFenceCapability? TargetCapability = null,
    string? ProvisionerImageSha256 = null);

public sealed record JobKeeperFenceLease(
    Guid TransactionId,
    Guid ScopeId,
    JobKeeperFenceCapability Capability,
    ulong Generation,
    int Depth,
    JobKeeperFencePhase Phase);

public sealed record JobKeeperFenceStatus(
    ulong Generation,
    int Depth,
    JobKeeperFencePhase Phase);

public sealed record JobKeeperFenceAcquireResult(
    bool Acquired,
    JobKeeperFenceLease Lease);

public sealed record JobKeeperLeaseDto(
    string JobName,
    string AttemptId,
    int Generation,
    string NodeIncarnationId)
{
    public static JobKeeperLeaseDto From(JobLeaseIdentity identity) =>
        new(identity.JobName, identity.AttemptId.ToString(), identity.Generation, identity.NodeIncarnationId.ToString());

    public JobLeaseIdentity ToIdentity() => new(
        JobName,
        Steward.Domain.TaskAttemptId.Parse(AttemptId),
        Generation,
        Steward.Domain.NodeIncarnationId.Parse(NodeIncarnationId));
}

public enum JobKeeperCommand
{
    Retain,
    Open,
    Release,
    Abandon,
    List,
    Health,
    AcquireDrainFence,
    ReleaseDrainFence,
    TransferDrainFence,
    RollbackDrainFence,
    ReleaseTransferredDrainFence
}

public sealed record JobKeeperRequest(
    int ProtocolVersion,
    JobKeeperCommand Command,
    string RequestId,
    JobKeeperLeaseDto? Lease = null,
    long HandleValue = 0,
    int ClaimedClientProcessId = 0,
    string? RelatedRequestId = null,
    JobKeeperFenceDto? Fence = null);

public sealed record JobKeeperResponse(
    int ProtocolVersion,
    bool Success,
    string? Error = null,
    long HandleValue = 0,
    IReadOnlyList<JobKeeperLeaseDto>? Leases = null,
    string? ErrorCode = null,
    int RetainedLeaseCount = 0,
    bool ListTruncated = false,
    bool RequiresAcknowledgement = false,
    long RevokedProvisionalOpenCount = 0,
    bool DrainFenced = false,
    ulong FenceGeneration = 0,
    int FenceDepth = 0,
    JobKeeperFencePhase FencePhase = JobKeeperFencePhase.Unfenced);

public static class JobKeeperProtocol
{
    public const int Version = 1;
    public const int AbsoluteMaximumMessageBytes = 64 * 1024;
    public const byte ResponseAcknowledgement = 0xA5;
    public const byte AcknowledgementConfirmation = 0x5A;
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();

    private static JsonSerializerOptions CreateSerializerOptions()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter(
            JsonNamingPolicy.CamelCase,
            allowIntegerValues: false));
        return options;
    }
    public static async ValueTask WriteAsync<T>(Stream stream, T value, int maximumBytes, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(value, SerializerOptions);
        if (payload.Length == 0 || payload.Length > maximumBytes || payload.Length > AbsoluteMaximumMessageBytes)
            throw new InvalidDataException("Keeper protocol message exceeds its configured bound.");
        var prefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    public static async ValueTask<T> ReadAsync<T>(Stream stream, int maximumBytes, CancellationToken cancellationToken)
    {
        var prefix = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(prefix, cancellationToken);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length <= 0 || length > maximumBytes || length > AbsoluteMaximumMessageBytes)
            throw new InvalidDataException("Keeper protocol message length is invalid.");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken);
        return JsonSerializer.Deserialize<T>(payload, SerializerOptions) ?? throw new InvalidDataException("Keeper protocol message is invalid.");
    }
}

public sealed class NamedPipeJobHandleKeeper : IJobHandleKeeper
{
    private readonly NamedPipeJobHandleKeeperOptions options;
    private bool disposed;

    public NamedPipeJobHandleKeeper(NamedPipeJobHandleKeeperOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.PipeName) || options.PipeName.Length > 128 ||
            options.PipeName.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.')) ||
            options.ConnectTimeout <= TimeSpan.Zero || options.ConnectTimeout > TimeSpan.FromSeconds(30) ||
            options.MaximumMessageBytes is < 1024 or > JobKeeperProtocol.AbsoluteMaximumMessageBytes ||
            options.ConnectAttempts is <= 0 or > 10)
            throw new ArgumentException("Named-pipe keeper options are invalid.", nameof(options));
        this.options = options;
    }

    public bool SurvivesClientRestart => true;

    public void Retain(JobLeaseIdentity identity, SafeFileHandle handle)
    {
        identity.Validate();
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid || handle.IsClosed) throw new ArgumentException("Job handle is invalid.", nameof(handle));
        var response = Call(new(JobKeeperProtocol.Version, JobKeeperCommand.Retain, NewRequestId(), JobKeeperLeaseDto.From(identity),
            handle.DangerousGetHandle().ToInt64(), Environment.ProcessId));
        RequireSuccess(response);
        handle.Dispose();
    }

    public SafeFileHandle Open(JobLeaseIdentity identity)
    {
        identity.Validate();
        var response = Call(new(JobKeeperProtocol.Version, JobKeeperCommand.Open, NewRequestId(), JobKeeperLeaseDto.From(identity),
            ClaimedClientProcessId: Environment.ProcessId));
        RequireSuccess(response);
        if (response.HandleValue == 0 || response.HandleValue == -1)
            throw new InvalidDataException("Keeper returned an invalid duplicated handle.");
        return new SafeFileHandle(new IntPtr(response.HandleValue), true);
    }

    public void Release(JobLeaseIdentity identity)
    {
        identity.Validate();
        RequireSuccess(Call(new(JobKeeperProtocol.Version, JobKeeperCommand.Release, NewRequestId(), JobKeeperLeaseDto.From(identity),
            ClaimedClientProcessId: Environment.ProcessId)));
    }

    public IReadOnlyList<JobLeaseIdentity> List()
    {
        var response = Call(new(JobKeeperProtocol.Version, JobKeeperCommand.List, NewRequestId(), ClaimedClientProcessId: Environment.ProcessId));
        RequireSuccess(response);
        return response.Leases?.Select(lease => lease.ToIdentity()).ToArray() ?? [];
    }

    public bool Health()
    {
        var response = Call(new(JobKeeperProtocol.Version, JobKeeperCommand.Health, NewRequestId(), ClaimedClientProcessId: Environment.ProcessId));
        RequireSuccess(response);
        return true;
    }

    public JobKeeperFenceStatus FenceStatus()
    {
        var response = Call(new(
            JobKeeperProtocol.Version,
            JobKeeperCommand.Health,
            NewRequestId(),
            ClaimedClientProcessId: Environment.ProcessId));
        RequireSuccess(response);
        return new JobKeeperFenceStatus(
            response.FenceGeneration,
            response.FenceDepth,
            response.FencePhase);
    }

    public JobKeeperFenceAcquireResult AcquireDrainFence(
        Guid transactionId,
        Guid scopeId,
        JobKeeperFenceCapability capability,
        ulong expectedGeneration)
    {
        var response = Call(new(
            JobKeeperProtocol.Version,
            JobKeeperCommand.AcquireDrainFence,
            NewRequestId(),
            ClaimedClientProcessId: Environment.ProcessId,
            Fence: new JobKeeperFenceDto(
                transactionId,
                scopeId,
                capability,
                expectedGeneration)));
        var lease = FenceLease(
            response,
            transactionId,
            scopeId,
            capability);
        if (!response.Success && response.ErrorCode != "active_leases")
            RequireSuccess(response);
        return new JobKeeperFenceAcquireResult(response.Success, lease);
    }

    public JobKeeperFenceStatus ReleaseDrainFence(
        JobKeeperFenceLease lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        var response = Call(new(
            JobKeeperProtocol.Version,
            JobKeeperCommand.ReleaseDrainFence,
            NewRequestId(),
            ClaimedClientProcessId: Environment.ProcessId,
            Fence: new JobKeeperFenceDto(
                lease.TransactionId,
                lease.ScopeId,
                lease.Capability,
                lease.Generation)));
        RequireSuccess(response);
        return new JobKeeperFenceStatus(
            response.FenceGeneration,
            response.FenceDepth,
            response.FencePhase);
    }

    public JobKeeperFenceStatus TransferDrainFence(
        JobKeeperFenceLease lease,
        JobKeeperFenceCapability provisionerCapability,
        string provisionerImageSha256)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(provisionerCapability);
        var response = Call(new(
            JobKeeperProtocol.Version,
            JobKeeperCommand.TransferDrainFence,
            NewRequestId(),
            ClaimedClientProcessId: Environment.ProcessId,
            Fence: new JobKeeperFenceDto(
                lease.TransactionId,
                lease.ScopeId,
                lease.Capability,
                lease.Generation,
                provisionerCapability,
                provisionerImageSha256)));
        RequireSuccess(response);
        return new JobKeeperFenceStatus(
            response.FenceGeneration,
            response.FenceDepth,
            response.FencePhase);
    }

    public JobKeeperFenceStatus RollbackDrainFence(
        JobKeeperFenceLease lease,
        ulong expectedGeneration)
    {
        ArgumentNullException.ThrowIfNull(lease);
        var response = Call(new(
            JobKeeperProtocol.Version,
            JobKeeperCommand.RollbackDrainFence,
            NewRequestId(),
            ClaimedClientProcessId: Environment.ProcessId,
            Fence: new JobKeeperFenceDto(
                lease.TransactionId,
                lease.ScopeId,
                lease.Capability,
                expectedGeneration)));
        RequireSuccess(response);
        return new JobKeeperFenceStatus(
            response.FenceGeneration,
            response.FenceDepth,
            response.FencePhase);
    }

    public JobKeeperFenceStatus ReleaseTransferredDrainFence(
        Guid transactionId,
        Guid scopeId,
        JobKeeperFenceCapability provisionerCapability,
        ulong expectedGeneration)
    {
        var response = Call(new(
            JobKeeperProtocol.Version,
            JobKeeperCommand.ReleaseTransferredDrainFence,
            NewRequestId(),
            ClaimedClientProcessId: Environment.ProcessId,
            Fence: new JobKeeperFenceDto(
                transactionId,
                scopeId,
                provisionerCapability,
                expectedGeneration)));
        RequireSuccess(response);
        return new JobKeeperFenceStatus(
            response.FenceGeneration,
            response.FenceDepth,
            response.FencePhase);
    }
    private static JobKeeperFenceLease FenceLease(
        JobKeeperResponse response,
        Guid transactionId,
        Guid scopeId,
        JobKeeperFenceCapability capability)
    {
        if (!response.DrainFenced ||
            response.FencePhase == JobKeeperFencePhase.Unfenced)
            throw new InvalidDataException(
                "Keeper drain response did not confirm durable ownership.");
        return new JobKeeperFenceLease(
            transactionId,
            scopeId,
            capability,
            response.FenceGeneration,
            response.FenceDepth,
            response.FencePhase);
    }

    private JobKeeperResponse Call(JobKeeperRequest request, bool abandonUnconfirmedOpen = true)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        Exception? last = null;
        JobKeeperResponse? terminalResponse = null;
        long provisionalOpenHandle = 0;
        for (var attempt = 0; attempt < options.ConnectAttempts; attempt++)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", options.PipeName, PipeDirection.InOut,
                    PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
                pipe.Connect(checked((int)options.ConnectTimeout.TotalMilliseconds));
                using var timeout = new CancellationTokenSource(options.ConnectTimeout);
                JobKeeperProtocol.WriteAsync(pipe, request, options.MaximumMessageBytes, timeout.Token).AsTask().GetAwaiter().GetResult();
                var response = JobKeeperProtocol.ReadAsync<JobKeeperResponse>(pipe, options.MaximumMessageBytes, timeout.Token).AsTask().GetAwaiter().GetResult();
                if (response.Success && !response.RequiresAcknowledgement)
                    throw new InvalidDataException("Keeper success was not acknowledgement-bound.");
                if (request.Command == JobKeeperCommand.Open && response.Success)
                {
                    if (response.HandleValue is 0 or -1)
                        throw new InvalidDataException("Keeper returned an invalid duplicated handle.");
                    if (provisionalOpenHandle != 0 && provisionalOpenHandle != response.HandleValue)
                    {
                        if (abandonUnconfirmedOpen) TryAbandon(request);
                        throw new InvalidDataException("Keeper changed an Open result while retrying the same RequestId.");
                    }
                    provisionalOpenHandle = response.HandleValue;
                }
                if (response.RequiresAcknowledgement)
                {
                    pipe.WriteAsync(new[] { JobKeeperProtocol.ResponseAcknowledgement }, timeout.Token).AsTask().GetAwaiter().GetResult();
                    pipe.FlushAsync(timeout.Token).GetAwaiter().GetResult();
                    var confirmation = new byte[1];
                    pipe.ReadExactlyAsync(confirmation, timeout.Token).AsTask().GetAwaiter().GetResult();
                    if (confirmation[0] != JobKeeperProtocol.AcknowledgementConfirmation)
                        throw new InvalidDataException("Keeper acknowledgement confirmation is invalid.");
                }
                if (!response.Success && provisionalOpenHandle != 0)
                {
                    terminalResponse = response;
                    break;
                }
                return response;
            }
            catch (OperationCanceledException exception)
            {
                last = new TimeoutException("Timed out waiting for the retained-handle service.", exception);
                if (attempt + 1 < options.ConnectAttempts) Thread.Sleep(50);
            }
            catch (InvalidDataException)
            {
                if (provisionalOpenHandle != 0 && abandonUnconfirmedOpen) TryAbandon(request);
                throw;
            }
            catch (Exception exception) when (exception is IOException or TimeoutException)
            {
                last = exception;
                if (attempt + 1 < options.ConnectAttempts) Thread.Sleep(50);
            }
        }
        if (provisionalOpenHandle != 0 && abandonUnconfirmedOpen) TryAbandon(request);
        if (terminalResponse is not null) return terminalResponse;
        throw new IOException("Unable to reach the retained-handle service.", last);
    }

    private void TryAbandon(JobKeeperRequest openRequest)
    {
        if (openRequest.Command != JobKeeperCommand.Open) return;
        try
        {
            var response = Call(new(JobKeeperProtocol.Version, JobKeeperCommand.Abandon, NewRequestId(),
                ClaimedClientProcessId: Environment.ProcessId, RelatedRequestId: openRequest.RequestId),
                abandonUnconfirmedOpen: false);
            RequireSuccess(response);
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or UnauthorizedAccessException or KeyNotFoundException) { }
    }

    private static void RequireSuccess(JobKeeperResponse response)
    {
        if (response.ProtocolVersion != JobKeeperProtocol.Version)
            throw new InvalidDataException("Keeper protocol version mismatch.");
        if (!response.Success)
        {
            if (response.ErrorCode == "not_found") throw new KeyNotFoundException(response.Error);
            throw new UnauthorizedAccessException(response.Error ?? "Keeper request denied.");
        }
    }

    private static string NewRequestId() => Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));

    public void Dispose() => disposed = true;
}
