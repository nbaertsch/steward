using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.Client.Windows;

internal interface IClientDvcChannel
{
    int Write(ReadOnlySpan<byte> pdu);
    int Close();
}

internal sealed class ComClientDvcChannel(
    IWTSVirtualChannel channel) : IClientDvcChannel
{
    public int Write(ReadOnlySpan<byte> pdu)
    {
        var buffer = Marshal.AllocHGlobal(pdu.Length);
        try
        {
            Marshal.Copy(pdu.ToArray(), 0, buffer, pdu.Length);
            return channel.Write(
                checked((uint)pdu.Length),
                buffer,
                IntPtr.Zero);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public int Close() => channel.Close();
}

internal sealed class ClientDvcAttachment(
    IClientDvcChannel channel,
    RdpDvcEvidencePublisherSession? evidence) : IAsyncDisposable
{
    public ClientDvcAttachment(IClientDvcChannel channel)
        : this(channel, null)
    {
    }
    private readonly Channel<byte[]> _inbound =
        Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(
                StewardRdpDvc.MaximumBufferedPdus)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false
            });
    private readonly BoundedDvcMessageReassembler _reassembler = new();
    private readonly CancellationTokenSource _closed = new();
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly TaskCompletionSource<byte[]> _firstPdu =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _receivedFirstPdu;
    private int _disposed;

    public CancellationToken Closed => _closed.Token;
    public Task<byte[]> FirstPdu => _firstPdu.Task;
    public RdpDvcEvidencePublisherSession? Evidence { get; } = evidence;

    public bool ReceiveFragment(ReadOnlySpan<byte> fragment)
    {
        foreach (var pdu in _reassembler.Push(fragment))
        {
            if (Interlocked.CompareExchange(
                    ref _receivedFirstPdu,
                    1,
                    0) == 0)
            {
                if (!_firstPdu.TrySetResult(pdu))
                    return false;
            }
            else if (!_inbound.Writer.TryWrite(pdu))
                return false;
        }
        return true;
    }

    public ValueTask<byte[]> ReadAsync(
        CancellationToken cancellationToken) =>
        _inbound.Reader.ReadAsync(cancellationToken);

    public async ValueTask WriteAsync(
        ReadOnlyMemory<byte> pdu,
        CancellationToken cancellationToken)
    {
        await _writeGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var result = channel.Write(pdu.Span);
            if (result < 0)
                Marshal.ThrowExceptionForHR(result);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _closed.Cancel();
            _firstPdu.TrySetCanceled(_closed.Token);
            _inbound.Writer.TryComplete();
            _ = channel.Close();
            _writeGate.Dispose();
            _closed.Dispose();
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class ClientDvcBroker : IAsyncDisposable
{
    internal const int MaximumConcurrentAttachments = 64;
    private static readonly TimeSpan RouteWaitTimeout =
        TimeSpan.FromMinutes(5);
    private readonly Action<string> _log;
    private readonly string _pipeName;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _pipeLoop;
    private readonly object _gate = new();
    private readonly HashSet<ClientDvcAttachment> _attachments = [];
    private readonly Dictionary<
        RdpDvcBrokerRoute,
        ClientDvcAttachment> _available = [];
    private readonly ConcurrentDictionary<int, Task> _pipeHandlers = new();
    private readonly SemaphoreSlim _pipeSlots =
        new(MaximumConcurrentAttachments);
    private TaskCompletionSource _routesChanged =
        NewRouteCompletion();
    private int _nextHandlerId;
    private int _disposed;

    public ClientDvcBroker(
        Action<string> log,
        string? pipeName = null)
    {
        _log = log;
        _pipeName =
            pipeName ?? StewardRdpDvc.CurrentUserPipeName();
        _pipeLoop = RunPipeLoopAsync();
    }

    public ClientDvcAttachment? TryAttach(
        IClientDvcChannel channel,
        RdpDvcEvidencePublisherSession evidence) =>
        TryAttachCore(channel, evidence);

    internal ClientDvcAttachment? TryAttach(
        IClientDvcChannel channel) =>
        TryAttachCore(channel, null);

    private ClientDvcAttachment? TryAttachCore(
        IClientDvcChannel channel,
        RdpDvcEvidencePublisherSession? evidence)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);
        lock (_gate)
        {
            if (_attachments.Count >=
                MaximumConcurrentAttachments)
                return null;
            var attachment = new ClientDvcAttachment(channel, evidence);
            _attachments.Add(attachment);
            _ = ObserveCandidateAsync(attachment);
            _log("DVC_CHANNEL_OPEN");
            return attachment;
        }
    }

    public async ValueTask DetachAsync(ClientDvcAttachment attachment)
    {
        var removed = false;
        lock (_gate)
        {
            removed = _attachments.Remove(attachment);
            foreach (var route in _available
                         .Where(item =>
                             ReferenceEquals(
                                 item.Value,
                                 attachment))
                         .Select(item => item.Key)
                         .ToArray())
                _available.Remove(route);
            if (removed)
                SignalRoutesChanged();
        }
        if (!removed)
            return;
        await attachment.DisposeAsync().ConfigureAwait(false);
        _log("DVC_CHANNEL_CLOSED");
    }

    internal async ValueTask DisconnectAsync(
        IReadOnlyCollection<ClientDvcAttachment> attachments)
    {
        foreach (var attachment in attachments)
            await DetachAsync(attachment).ConfigureAwait(false);
    }

    private async Task RunPipeLoopAsync()
    {
        while (!_lifetime.IsCancellationRequested)
        {
            await _pipeSlots.WaitAsync(_lifetime.Token)
                .ConfigureAwait(false);
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    MaximumConcurrentAttachments,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous |
                    PipeOptions.CurrentUserOnly,
                    64 * 1024,
                    64 * 1024);
                await pipe.WaitForConnectionAsync(_lifetime.Token)
                    .ConfigureAwait(false);
                _log("LOCAL_CARRIER_CONNECTED");
                var handlerId =
                    Interlocked.Increment(ref _nextHandlerId);
                var handler = HandlePipeAsync(pipe);
                pipe = null;
                _pipeHandlers.TryAdd(handlerId, handler);
                _ = handler.ContinueWith(
                    completed =>
                    {
                        _ = completed;
                        _pipeHandlers.TryRemove(
                            handlerId,
                            out _);
                        _pipeSlots.Release();
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
            catch (OperationCanceledException)
                when (_lifetime.IsCancellationRequested)
            {
                pipe?.Dispose();
                _pipeSlots.Release();
                break;
            }
            catch (Exception exception)
            {
                pipe?.Dispose();
                _pipeSlots.Release();
                _log($"BROKER_RECOVERABLE_{exception.GetType().Name}");
                try
                {
                    await Task.Delay(
                            TimeSpan.FromMilliseconds(250),
                            _lifetime.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                    when (_lifetime.IsCancellationRequested)
                {
                    break;
                }
            }
        }
    }

    private async Task HandlePipeAsync(
        NamedPipeServerStream pipe)
    {
        await using (pipe.ConfigureAwait(false))
        {
            ClientDvcAttachment? attachment = null;
            try
            {
                using var routeTimeout =
                    CancellationTokenSource.CreateLinkedTokenSource(
                        _lifetime.Token);
                routeTimeout.CancelAfter(RouteWaitTimeout);
                var request = new byte[
                    RdpDvcBrokerRoutingProtocol.RequestSize];
                await RdpDvcBrokerRoutingProtocol.ReadExactlyAsync(
                        pipe,
                        request,
                        routeTimeout.Token)
                    .ConfigureAwait(false);
                var route =
                    RdpDvcBrokerRoutingProtocol.DecodeRequest(
                        request);
                attachment = await ReserveAttachmentAsync(
                        route,
                        routeTimeout.Token)
                    .ConfigureAwait(false);
                var candidate =
                    await attachment.FirstPdu.WaitAsync(
                        routeTimeout.Token)
                    .ConfigureAwait(false);
                await RdpDvcBrokerRoutingProtocol.WriteCandidateAsync(
                        pipe,
                        candidate,
                        routeTimeout.Token)
                    .ConfigureAwait(false);
                var decision = new byte[1];
                await RdpDvcBrokerRoutingProtocol.ReadExactlyAsync(
                        pipe,
                        decision,
                        routeTimeout.Token)
                    .ConfigureAwait(false);
                if (decision[0] !=
                    RdpDvcBrokerRoutingProtocol.Accepted)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.AuthenticationFailed,
                        "The local carrier rejected the authenticated DVC route.");

                await using var broker =
                    new LengthPrefixedDvcWireChannel(pipe);
                using var pairing =
                    CancellationTokenSource.CreateLinkedTokenSource(
                        _lifetime.Token,
                        attachment.Closed);
                var toPipe = PumpToPipeAsync(
                    broker,
                    attachment,
                    pairing.Token);
                var toDvc = PumpToDvcAsync(
                    broker,
                    attachment,
                    pairing.Token);
                await Task.WhenAny(toPipe, toDvc)
                    .ConfigureAwait(false);
                pairing.Cancel();
                try
                {
                    await Task.WhenAll(toPipe, toDvc)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                    when (pairing.IsCancellationRequested)
                {
                }
            }
            catch (OperationCanceledException)
                when (_lifetime.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                _log(
                    $"BROKER_ROUTE_REJECTED_{exception.GetType().Name}");
            }
            finally
            {
                if (attachment is not null)
                    await DetachAsync(attachment)
                        .ConfigureAwait(false);
            }
        }
    }

    private async Task ObserveCandidateAsync(
        ClientDvcAttachment attachment)
    {
        try
        {
            var first = await attachment.FirstPdu.WaitAsync(
                    _lifetime.Token)
                .ConfigureAwait(false);
            _log($"DVC_PDU_COMPLETE_{first.Length}");
            if (!RdpDvcBrokerRoutingProtocol
                    .TryReadUntrustedCandidateRoute(
                        first,
                        out var route))
            {
                _log("DVC_ROUTE_CANDIDATE_INVALID");
                await DetachAsync(attachment)
                    .ConfigureAwait(false);
                return;
            }
            if (attachment.Evidence is { } evidence)
                await evidence.PublishAsync(
                        RdpDvcEvidencePublicationEvent
                            .StewardChannelOpened,
                        RdpDvcEvidenceRoute.From(route.Identity),
                        _lifetime.Token)
                    .ConfigureAwait(false);
            var duplicate = false;
            lock (_gate)
            {
                if (!_attachments.Contains(attachment))
                    return;
                duplicate = _available.ContainsKey(route);
                if (!duplicate)
                {
                    _available.Add(route, attachment);
                    _log("DVC_ROUTE_CANDIDATE_READY");
                    SignalRoutesChanged();
                }
            }
            if (duplicate)
                await DetachAsync(attachment)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (_lifetime.IsCancellationRequested ||
                  attachment.Closed.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _log(
                $"DVC_ROUTE_CANDIDATE_REJECTED_{exception.GetType().Name}");
            await DetachAsync(attachment).ConfigureAwait(false);
        }
    }

    private async Task<ClientDvcAttachment> ReserveAttachmentAsync(
        RdpDvcBrokerRoute route,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            Task changed;
            lock (_gate)
            {
                var matches = _available
                    .Where(item => item.Key.MatchesRequest(route))
                    .Take(2)
                    .ToArray();
                if (matches.Length > 1)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.BindingMismatch,
                        "The preauthorized DVC route matched multiple channel candidates.");
                if (matches.Length == 1)
                {
                    _available.Remove(matches[0].Key);
                    return matches[0].Value;
                }
                if (_available.Count != 0)
                    _log(
                        "DVC_ROUTE_MISMATCH_" +
                        string.Join(
                            "_",
                            _available.Keys.Select(
                                candidate =>
                                    candidate.DescribeMatch(route))));
                changed = _routesChanged.Task;
            }
            await changed.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private void SignalRoutesChanged()
    {
        _routesChanged.TrySetResult();
        _routesChanged = NewRouteCompletion();
    }

    private static async Task PumpToPipeAsync(
        IRdpDvcWireChannel pipe,
        ClientDvcAttachment attachment,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var pdu = await attachment.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            await pipe.WritePduAsync(pdu, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static async Task PumpToDvcAsync(
        IRdpDvcWireChannel pipe,
        ClientDvcAttachment attachment,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var pdu = await pipe.ReadPduAsync(cancellationToken)
                .ConfigureAwait(false);
            await attachment.WriteAsync(pdu, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static TaskCompletionSource NewRouteCompletion() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        _lifetime.Cancel();
        ClientDvcAttachment[] attachments;
        lock (_gate)
        {
            attachments = _attachments.ToArray();
            _attachments.Clear();
            _available.Clear();
            _routesChanged.TrySetCanceled(_lifetime.Token);
        }
        foreach (var attachment in attachments)
            await attachment.DisposeAsync().ConfigureAwait(false);
        try
        {
            await _pipeLoop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (_lifetime.IsCancellationRequested)
        {
        }
        var handlers = _pipeHandlers.Values.ToArray();
        if (handlers.Length != 0)
            await Task.WhenAll(handlers).ConfigureAwait(false);
        _pipeSlots.Dispose();
        _lifetime.Dispose();
    }
}
