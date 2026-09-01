using System.Collections.Concurrent;
using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.Terminal.Abstractions;
using Steward.Transport;

namespace Steward.Orchestration;

internal sealed record TerminalWireRequest(
    string RequestId,
    string Operation,
    JsonElement Payload);
public sealed record TerminalWireResponse(
    string RequestId,
    string Status,
    TerminalSessionSnapshot? Snapshot,
    IReadOnlyList<TerminalOutput>? Output,
    TerminalProblem? Problem);

internal static class TerminalWireCodec
{
    public const int MaximumBytes = 4 * 1024 * 1024 + 64 * 1024;
    private static readonly JsonSerializerOptions Options = CreateOptions();
    public static byte[] Encode<T>(T value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Options);
        if (bytes.Length is 0 or > MaximumBytes)
            throw new InvalidDataException("Terminal transport payload exceeds its bound.");
        return bytes;
    }

    public static TerminalWireRequest DecodeRequest(ReadOnlyMemory<byte> bytes) =>
        Decode<TerminalWireRequest>(bytes);
    public static TerminalWireResponse DecodeResponse(ReadOnlyMemory<byte> bytes) =>
        Decode<TerminalWireResponse>(bytes);
    private static T Decode<T>(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is 0 or > MaximumBytes)
            throw new InvalidDataException("Terminal transport payload exceeds its bound.");
        return JsonSerializer.Deserialize<T>(bytes.Span, Options)
            ?? throw new InvalidDataException("Terminal transport payload is invalid.");
    }

    public static JsonElement Element<T>(T value) =>
        JsonSerializer.SerializeToElement(value, Options);

    public static T? FromElement<T>(JsonElement value) => value.Deserialize<T>(Options);

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(StewardJson.Options);
        options.Converters.Add(new TerminalSessionIdJsonConverter());
        return options;
    }
}

public sealed class NodeTerminalCommandProcessor(
    ITerminalSessionService service,
    ITerminalRevocationSink? revocations = null)
{
    private long sequence;

    public async Task ProcessAsync(
        ITransportConnection connection,
        TransportFrame frame,
        CancellationToken cancellationToken)
    {
        var request = TerminalWireCodec.DecodeRequest(frame.Payload);
        TerminalWireResponse response;
        try
        {
            var payload = request.Payload;
            TerminalSessionSnapshot? snapshot = null;
            IReadOnlyList<TerminalOutput>? output = null;
            switch (request.Operation)
            {
                case "open":
                    var open = TerminalWireCodec.FromElement<TerminalOpenCommand>(payload)!;
                    snapshot = await service.OpenAsync(open.Request, open.Context, cancellationToken);
                    break;
                case "get":
                    var get = TerminalWireCodec.FromElement<TerminalGetCommand>(payload)!;
                    snapshot = await service.GetAsync(get.SessionId, get.Context, cancellationToken);
                    break;
                case "input":
                    snapshot = await service.WriteInputAsync(
                        TerminalWireCodec.FromElement<TerminalInputRequest>(payload)!, cancellationToken);
                    break;
                case "resize":
                    snapshot = await service.ResizeAsync(
                        TerminalWireCodec.FromElement<TerminalResizeRequest>(payload)!, cancellationToken);
                    break;
                case "close":
                    snapshot = await service.CloseAsync(
                        TerminalWireCodec.FromElement<TerminalCloseRequest>(payload)!, cancellationToken);
                    break;
                case "output":
                    var requested = TerminalWireCodec.FromElement<TerminalOutputReadRequest>(payload)!;
                    var frameBudget = Math.Max(
                        1, (connection.Session.Limits.MaximumPayloadBytes - 8 * 1024) * 3L / 4L);
                    var read = requested with
                    {
                        Follow = false,
                        MaximumBytes = Math.Min(requested.MaximumBytes, frameBudget),
                        MaximumItems = Math.Min(requested.MaximumItems, 128)
                    };
                    var values = new List<TerminalOutput>();
                    await foreach (var item in service.ReadOutputAsync(read, cancellationToken))
                        values.Add(item);
                    output = values;
                    break;
                case "revoke":
                    var revoke = TerminalWireCodec.FromElement<TerminalRevocationCommand>(payload)!;
                    if (revocations is null)
                        throw new InvalidDataException("Terminal revocation sink is unavailable.");
                    await revocations.AdvanceAsync(
                        revoke.SessionId, revoke.Revision, cancellationToken);
                    break;
                default:
                    throw new InvalidDataException("Unknown terminal operation.");
            }
            response = new(request.RequestId, "ok",
                snapshot,
                output, null);
        }
        catch (TerminalException exception)
        {
            response = new(request.RequestId, "problem", null, null, exception.Problem);
        }
        var remoteCursor = connection.Session.RemoteResumeCursors
            .GetValueOrDefault(StreamKind.Terminal, 0);
        if (sequence < remoteCursor) Interlocked.Exchange(ref sequence, remoteCursor);
        var next = Interlocked.Increment(ref sequence);
        var encoded = TerminalWireCodec.Encode(response);
        if (encoded.Length > connection.Session.Limits.MaximumPayloadBytes)
            throw new TransportProtocolException(
                TransportError.PayloadTooLarge,
                "Terminal response exceeds the negotiated frame limit.");
        await connection.SendAsync(new(
            connection.Session.SessionId, connection.Session.NodeIncarnationId,
            StreamKind.Terminal, next, next, encoded), cancellationToken);
    }
}

public sealed record TerminalOpenCommand(
    TerminalOpenRequest Request,
    TerminalOperationContext Context);
public sealed record TerminalRevocationCommand(
    TerminalSessionId SessionId,
    long Revision);

public interface ITerminalRevocationSink
{
    ValueTask AdvanceAsync(
        TerminalSessionId sessionId, long revision, CancellationToken cancellationToken);
}
public sealed record TerminalGetCommand(
    TerminalSessionId SessionId,
    TerminalOperationContext Context);

public sealed class ControlTerminalRouter
{
    private readonly ConcurrentDictionary<HostId, Session> sessions = [];
    private readonly ConcurrentDictionary<string, TaskCompletionSource<TerminalWireResponse>> pending = [];
    private readonly ConcurrentDictionary<NodeIncarnationId, long> received = [];

    public IDisposable Attach(HostId hostId, ITransportConnection connection)
    {
        var session = new Session(connection);
        if (!sessions.TryAdd(hostId, session))
            throw new InvalidOperationException("A terminal route already exists for this Host.");
        return new Detach(() => sessions.TryRemove(hostId, out _));
    }

    public async Task<TerminalWireResponse> SendAsync<TPayload>(
        HostId hostId,
        string operation,
        TPayload payload,
        CancellationToken cancellationToken)
    {
        if (!sessions.TryGetValue(hostId, out var session))
            throw new InvalidOperationException("Selected Host terminal route is unavailable.");
        var id = Guid.NewGuid().ToString("N");
        var completion = new TaskCompletionSource<TerminalWireResponse>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pending.TryAdd(id, completion)) throw new InvalidOperationException("Terminal request collision.");
        try
        {
            var sequence = Interlocked.Increment(ref session.Sequence);
            var request = new TerminalWireRequest(
                id, operation, TerminalWireCodec.Element(payload));
            var encoded = TerminalWireCodec.Encode(request);
            if (encoded.Length > session.Connection.Session.Limits.MaximumPayloadBytes)
                throw new TransportProtocolException(
                    TransportError.PayloadTooLarge,
                    "Terminal request exceeds the negotiated frame limit.");
            await session.Connection.SendAsync(new(
                session.Connection.Session.SessionId, session.Connection.Session.NodeIncarnationId,
                StreamKind.Terminal, sequence, sequence, encoded), cancellationToken);
            return await completion.Task.WaitAsync(cancellationToken);
        }
        finally { pending.TryRemove(id, out _); }
    }

    public void Accept(TransportFrame frame)
    {
        received.AddOrUpdate(
            frame.NodeIncarnationId, frame.Sequence, (_, current) => Math.Max(current, frame.Sequence));
        var response = TerminalWireCodec.DecodeResponse(frame.Payload);
        if (pending.TryGetValue(response.RequestId, out var completion))
            completion.TrySetResult(response);
    }

    public long GetReceivedCursor(NodeIncarnationId nodeId) =>
        received.GetValueOrDefault(nodeId, 0);

    private sealed class Session(ITransportConnection connection)
    {
        public ITransportConnection Connection { get; } = connection;
        public long Sequence = connection.Session.RemoteResumeCursors
            .GetValueOrDefault(StreamKind.Terminal, 0);
    }
    private sealed class Detach(Action action) : IDisposable
    {
        public void Dispose() => action();
    }
}
