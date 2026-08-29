using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Steward.Domain;
using Steward.Orchestration;
using Steward.PortableState;
using Steward.Tasks.Abstractions;
using Steward.Transport;

namespace Steward.Stack.Local;

public enum LocalPortableOperation
{
    Stage,
    Commit
}

public sealed record LocalPortableTransferRequest(
    Guid RequestId,
    LocalPortableOperation Operation,
    PortableObjectDescriptor Descriptor,
    string? BlockId = null,
    byte[]? Content = null,
    byte[]? Md5 = null,
    IReadOnlyList<string>? OrderedBlockIds = null);

public sealed record LocalPortableTransferResponse(
    Guid RequestId,
    bool Success,
    PortableObjectReceipt? Receipt = null,
    string? ErrorCode = null);

public static class LocalPortableTransferCodec
{
    public const int MaximumMessageBytes = 256 * 1024;

    public static ReadOnlyMemory<byte> Encode<T>(T value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        if (bytes.Length is 0 or > MaximumMessageBytes)
            throw new InvalidDataException(
                "Local portable transfer message exceeds its bound.");
        return bytes;
    }

    public static T Decode<T>(ReadOnlyMemory<byte> value)
    {
        if (value.Length is 0 or > MaximumMessageBytes)
            throw new InvalidDataException(
                "Local portable transfer message exceeds its bound.");
        return JsonSerializer.Deserialize<T>(value.Span)
            ?? throw new InvalidDataException(
                "Local portable transfer message is invalid.");
    }
}

public sealed class LocalPortableReceiveHandler(
    IPortableObjectStore store) : IAuxiliaryTransportStreamHandler
{
    private readonly ConditionalWeakTable<
        ITransportConnection, SendSequence> sequences = new();
    private readonly SemaphoreSlim sendGate = new(1, 1);

    public StreamKind Stream => StreamKind.Artifacts;

    public async ValueTask HandleAsync(
        ITransportConnection connection,
        TransportFrame frame,
        CancellationToken cancellationToken)
    {
        var request = LocalPortableTransferCodec.Decode<
            LocalPortableTransferRequest>(frame.Payload);
        LocalPortableTransferResponse response;
        try
        {
            response = request.Operation switch
            {
                LocalPortableOperation.Stage =>
                    await StageAsync(request, cancellationToken),
                LocalPortableOperation.Commit =>
                    await CommitAsync(request, cancellationToken),
                _ => throw new InvalidDataException(
                    "Unknown local portable transfer operation.")
            };
        }
        catch (Exception exception) when (
            exception is PortableStateException or
            InvalidDataException or
            IOException or
            CryptographicException)
        {
            response = new(
                request.RequestId,
                false,
                ErrorCode: "portable-transfer-rejected");
        }
        await sendGate.WaitAsync(cancellationToken);
        try
        {
            var state = sequences.GetValue(
                connection,
                current => new(
                    current.Session.RemoteResumeCursors
                        .GetValueOrDefault(StreamKind.Artifacts, 0)));
            var sequence = checked(++state.Value);
            await connection.SendAsync(new(
                connection.Session.SessionId,
                connection.Session.NodeIncarnationId,
                StreamKind.Artifacts,
                sequence,
                sequence,
                LocalPortableTransferCodec.Encode(response)),
                cancellationToken);
        }
        finally
        {
            sendGate.Release();
        }
    }

    private sealed class SendSequence(long value)
    {
        public long Value = value;
    }

    private async Task<LocalPortableTransferResponse> StageAsync(
        LocalPortableTransferRequest request,
        CancellationToken cancellationToken)
    {
        if (request.BlockId is null ||
            request.Content is null ||
            request.Md5 is not { Length: 16 })
            throw new InvalidDataException(
                "Portable stage request is incomplete.");
        await using var content = new MemoryStream(
            request.Content, writable: false);
        await store.StageBlockAsync(
            request.Descriptor.ObjectName,
            request.BlockId,
            content,
            request.Content.Length,
            TransportHashAlgorithm.Md5,
            request.Md5,
            cancellationToken);
        return new(request.RequestId, true);
    }

    private async Task<LocalPortableTransferResponse> CommitAsync(
        LocalPortableTransferRequest request,
        CancellationToken cancellationToken)
    {
        if (request.OrderedBlockIds is null)
            throw new InvalidDataException(
                "Portable commit request is incomplete.");
        var etag = await store.CommitBlockListAsync(
            request.Descriptor,
            request.OrderedBlockIds,
            cancellationToken);
        return new(
            request.RequestId,
            true,
            new(
                request.Descriptor.ObjectName,
                request.Descriptor.Sha256,
                request.Descriptor.Length,
                etag,
                DateTimeOffset.UtcNow));
    }
}

public sealed class LocalPortableTransferClient :
    IAuxiliaryTransportStreamHandler
{
    private readonly ConcurrentDictionary<
        Guid, TaskCompletionSource<LocalPortableTransferResponse>> pending = [];
    private readonly SemaphoreSlim sendGate = new(1, 1);
    private ITransportConnection? connection;
    private long sendSequence;

    public StreamKind Stream => StreamKind.Artifacts;
    public bool IsConnected => Volatile.Read(ref connection) is not null;

    public IDisposable Attach(ITransportConnection value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (Interlocked.CompareExchange(
                ref connection, value, null) is not null)
            throw new InvalidOperationException(
                "A Local portable transfer session is already attached.");
        sendSequence = value.Session.RemoteResumeCursors
            .GetValueOrDefault(StreamKind.Artifacts, 0);
        return new Attachment(this, value);
    }

    public ValueTask HandleAsync(
        ITransportConnection connection,
        TransportFrame frame,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var response = LocalPortableTransferCodec.Decode<
            LocalPortableTransferResponse>(frame.Payload);
        if (pending.TryGetValue(response.RequestId, out var completion))
            completion.TrySetResult(response);
        return ValueTask.CompletedTask;
    }

    public async Task<PortableObjectReceipt> ReplicateAsync(
        IPortableObjectStore source,
        PortableObjectDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref connection) is null)
            throw new InvalidOperationException(
                "Direct peer portable replication is disconnected.");
        const int chunkSize = 64 * 1024;
        var blocks = new List<string>();
        await using var content = await source.OpenReadAsync(
            descriptor.ObjectName, cancellationToken);
        var buffer = new byte[chunkSize];
        var index = 0;
        while (true)
        {
            var read = await content.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            var blockId = index++.ToString("D8",
                System.Globalization.CultureInfo.InvariantCulture);
            blocks.Add(blockId);
            var bytes = buffer.AsSpan(0, read).ToArray();
            var response = await SendAsync(new(
                Guid.NewGuid(),
                LocalPortableOperation.Stage,
                descriptor,
                blockId,
                bytes,
                MD5.HashData(bytes)), cancellationToken);
            if (!response.Success)
                throw new InvalidOperationException(
                    response.ErrorCode ?? "portable-transfer-rejected");
        }
        var committed = await SendAsync(new(
            Guid.NewGuid(),
            LocalPortableOperation.Commit,
            descriptor,
            OrderedBlockIds: blocks), cancellationToken);
        return committed.Success && committed.Receipt is not null
            ? committed.Receipt
            : throw new InvalidOperationException(
                committed.ErrorCode ?? "portable-transfer-rejected");
    }

    private async Task<LocalPortableTransferResponse> SendAsync(
        LocalPortableTransferRequest request,
        CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<
            LocalPortableTransferResponse>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pending.TryAdd(request.RequestId, completion))
            throw new InvalidOperationException(
                "Portable transfer request identity collision.");
        try
        {
            await sendGate.WaitAsync(cancellationToken);
            try
            {
                var current = Volatile.Read(ref connection)
                    ?? throw new InvalidOperationException(
                        "Direct peer portable replication is disconnected.");
                var sequence = checked(++sendSequence);
                await current.SendAsync(new(
                    current.Session.SessionId,
                    current.Session.NodeIncarnationId,
                    StreamKind.Artifacts,
                    sequence,
                    sequence,
                    LocalPortableTransferCodec.Encode(request)),
                    cancellationToken);
            }
            finally
            {
                sendGate.Release();
            }
            return await completion.Task.WaitAsync(cancellationToken);
        }
        finally
        {
            pending.TryRemove(request.RequestId, out _);
        }
    }

    private void Detach(ITransportConnection value)
    {
        _ = Interlocked.CompareExchange(ref connection, null, value);
        foreach (var completion in pending.Values)
            completion.TrySetException(new IOException(
                "Direct peer portable replication disconnected."));
    }

    private sealed class Attachment(
        LocalPortableTransferClient owner,
        ITransportConnection connection) : IDisposable
    {
        public void Dispose() => owner.Detach(connection);
    }
}

public sealed class LocalReplicatingTaskPortablePublisher(
    SpoolingTaskPortablePublisher localPublisher,
    IPortableObjectStore localStore,
    LocalPortableTransferClient transfer) : ITaskPortablePublisher
{
    public async ValueTask<PublishedTaskOutput> PublishAsync(
        AttemptIdentity identity,
        string workspace,
        TaskRuntimeOutput output,
        bool required,
        CancellationToken cancellationToken)
    {
        var local = await localPublisher.PublishAsync(
            identity, workspace, output, required, cancellationToken);
        if (!local.HasPortableReceipt ||
            local.Output is not (TaskRuntimeArtifact or TaskRuntimeCheckpoint))
            return local;
        var (objectId, mediaType, hash, length, reference, kind) =
            local.Output switch
            {
                TaskRuntimeArtifact artifact => (
                    artifact.PortableObjectId,
                    artifact.MediaType,
                    artifact.ContentHash,
                    artifact.SizeBytes,
                    artifact.Reference,
                    "artifact"),
                TaskRuntimeCheckpoint checkpoint => (
                    checkpoint.PortableObjectId,
                    "application/octet-stream",
                    checkpoint.ContentHash,
                    checkpoint.SizeBytes,
                    checkpoint.Reference,
                    "checkpoint"),
                _ => throw new InvalidOperationException()
            };
        if (!Uri.TryCreate(reference, UriKind.Absolute, out var portable) ||
            portable.Scheme != "portable")
            throw new InvalidDataException(
                "Local portable receipt is invalid.");
        var objectName = $"{portable.Host}{portable.AbsolutePath}".Trim('/');
        var descriptor = new PortableObjectDescriptor(
            objectName,
            objectId.ToString(),
            "1.0",
            mediaType,
            hash,
            length,
            new Dictionary<string, string>
            {
                ["workloadId"] = identity.WorkloadId.ToString(),
                ["taskId"] = identity.TaskId.ToString(),
                ["attemptId"] = identity.AttemptId.ToString(),
                ["generation"] = identity.Generation.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                ["kind"] = kind
            });
        _ = await transfer.ReplicateAsync(
            localStore, descriptor, cancellationToken);
        return new(local.Output, true);
    }
}
