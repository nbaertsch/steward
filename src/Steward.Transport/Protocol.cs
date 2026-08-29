using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Steward.Domain;

namespace Steward.Transport;

public enum StreamKind
{
    Control,
    Events,
    Logs,
    Artifacts,
    Identity,
    Terminal,
    AgentTurns
}

public sealed record TransportLimits(int MaximumPayloadBytes = 1024 * 1024, int MaximumBufferedFrames = 256)
{
    public TransportLimits Validate()
    {
        if (MaximumPayloadBytes <= 0 || MaximumBufferedFrames <= 0)
            throw new ArgumentOutOfRangeException(nameof(MaximumPayloadBytes));
        return this;
    }
}

public sealed record VerifiedSessionSecurity(
    bool MutuallyAuthenticated,
    bool Encrypted,
    string LocalIdentity,
    string RemoteIdentity,
    string ChannelBinding)
{
    public bool IsSecure =>
        MutuallyAuthenticated && Encrypted &&
        !string.IsNullOrWhiteSpace(LocalIdentity) &&
        !string.IsNullOrWhiteSpace(RemoteIdentity) &&
        !string.IsNullOrWhiteSpace(ChannelBinding);
}

public sealed record SessionHello(
    Guid SessionId,
    NodeIncarnationId NodeIncarnationId,
    int ProtocolMajor,
    int ProtocolMinor,
    IReadOnlySet<string> SupportedFeatures,
    IReadOnlySet<string> RequiredFeatures,
    IReadOnlyDictionary<StreamKind, long> ResumeCursors,
    TransportLimits Limits);

public sealed record NegotiatedSession(
    Guid SessionId,
    NodeIncarnationId NodeIncarnationId,
    int ProtocolMajor,
    int ProtocolMinor,
    IReadOnlySet<string> Features,
    IReadOnlyDictionary<StreamKind, long> LocalResumeCursors,
    IReadOnlyDictionary<StreamKind, long> RemoteResumeCursors,
    TransportLimits Limits,
    VerifiedSessionSecurity Security);

public sealed record TransportFrame(
    Guid SessionId,
    NodeIncarnationId NodeIncarnationId,
    StreamKind Stream,
    long Sequence,
    long Cursor,
    ReadOnlyMemory<byte> Payload);

public enum TransportError
{
    InsecureSession,
    UnsupportedVersion,
    UnsupportedRequiredFeature,
    SessionBindingMismatch,
    PayloadTooLarge,
    InvalidSequence,
    Backpressure
}

public sealed class TransportProtocolException(TransportError error, string message) : InvalidOperationException(message)
{
    public TransportError Error { get; } = error;
}

public static class SessionNegotiator
{
    public static NegotiatedSession Negotiate(SessionHello local, SessionHello remote, VerifiedSessionSecurity security)
    {
        local.Limits.Validate();
        remote.Limits.Validate();
        if (!security.IsSecure)
            throw new TransportProtocolException(TransportError.InsecureSession, "The carrier did not verify mutual authentication and encryption.");
        if (local.SessionId == Guid.Empty || local.SessionId != remote.SessionId ||
            local.NodeIncarnationId != remote.NodeIncarnationId)
            throw new TransportProtocolException(TransportError.SessionBindingMismatch, "Session or Node incarnation binding differs.");
        if (local.ProtocolMajor != remote.ProtocolMajor)
            throw new TransportProtocolException(TransportError.UnsupportedVersion, "Protocol major versions are incompatible.");

        var missingRemote = local.RequiredFeatures.Except(remote.SupportedFeatures, StringComparer.Ordinal).ToArray();
        var missingLocal = remote.RequiredFeatures.Except(local.SupportedFeatures, StringComparer.Ordinal).ToArray();
        if (missingRemote.Length != 0 || missingLocal.Length != 0)
            throw new TransportProtocolException(
                TransportError.UnsupportedRequiredFeature,
                $"Unsupported required features: {string.Join(", ", missingRemote.Concat(missingLocal).Distinct())}.");

        return new NegotiatedSession(
            local.SessionId,
            local.NodeIncarnationId,
            local.ProtocolMajor,
            Math.Min(local.ProtocolMinor, remote.ProtocolMinor),
            local.SupportedFeatures.Intersect(remote.SupportedFeatures, StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal),
            local.ResumeCursors,
            remote.ResumeCursors,
            new TransportLimits(
                Math.Min(local.Limits.MaximumPayloadBytes, remote.Limits.MaximumPayloadBytes),
                Math.Min(local.Limits.MaximumBufferedFrames, remote.Limits.MaximumBufferedFrames)),
            security);
    }
}

public interface ITransportConnection : IAsyncDisposable
{
    NegotiatedSession Session { get; }
    ValueTask SendAsync(TransportFrame frame, CancellationToken cancellationToken = default);
    bool TrySend(TransportFrame frame);
    IAsyncEnumerable<TransportFrame> ReceiveAsync(CancellationToken cancellationToken = default);
}

public interface ITransportCarrier
{
    ValueTask<ITransportConnection> ConnectAsync(SessionHello hello, CancellationToken cancellationToken = default);
}

public sealed class InMemoryDuplexCarrier
{
    public static (ITransportCarrier First, ITransportCarrier Second) CreatePair(
        VerifiedSessionSecurity firstSecurity,
        VerifiedSessionSecurity secondSecurity)
    {
        var hub = new Hub(firstSecurity, secondSecurity);
        return (new Endpoint(hub, true), new Endpoint(hub, false));
    }

    private sealed class Endpoint(Hub hub, bool first) : ITransportCarrier
    {
        public ValueTask<ITransportConnection> ConnectAsync(SessionHello hello, CancellationToken cancellationToken = default) =>
            hub.ConnectAsync(first, hello, cancellationToken);
    }

    private sealed class Hub(VerifiedSessionSecurity firstSecurity, VerifiedSessionSecurity secondSecurity)
    {
        private readonly object _gate = new();
        private Pending? _first;
        private Pending? _second;

        public ValueTask<ITransportConnection> ConnectAsync(bool first, SessionHello hello, CancellationToken cancellationToken)
        {
            var pending = new Pending(hello);
            lock (_gate)
            {
                if (first)
                {
                    if (_first is not null) throw new InvalidOperationException("Endpoint already has a pending connection.");
                    _first = pending;
                }
                else
                {
                    if (_second is not null) throw new InvalidOperationException("Endpoint already has a pending connection.");
                    _second = pending;
                }

                pending.Cancellation = cancellationToken.Register(() => Cancel(first, pending, cancellationToken));
                if (_first is not null && _second is not null)
                {
                    var a = _first;
                    var b = _second;
                    _first = _second = null;
                    try
                    {
                        var aSession = SessionNegotiator.Negotiate(a.Hello, b.Hello, firstSecurity);
                        var bSession = SessionNegotiator.Negotiate(b.Hello, a.Hello, secondSecurity);
                        var capacity = aSession.Limits.MaximumBufferedFrames;
                        var aToB = Channel.CreateBounded<TransportFrame>(new BoundedChannelOptions(capacity) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
                        var bToA = Channel.CreateBounded<TransportFrame>(new BoundedChannelOptions(capacity) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
                        a.Completion.SetResult(new Connection(aSession, aToB.Writer, bToA.Reader));
                        b.Completion.SetResult(new Connection(bSession, bToA.Writer, aToB.Reader));
                    }
                    catch (Exception ex)
                    {
                        a.Completion.SetException(ex);
                        b.Completion.SetException(ex);
                    }
                }
            }

            return new ValueTask<ITransportConnection>(pending.Completion.Task.WaitAsync(cancellationToken));
        }

        private void Cancel(bool first, Pending pending, CancellationToken cancellationToken)
        {
            lock (_gate)
            {
                if (first && ReferenceEquals(_first, pending))
                    _first = null;
                else if (!first && ReferenceEquals(_second, pending))
                    _second = null;
                else
                    return;
            }
            pending.Completion.TrySetCanceled(cancellationToken);
        }

        private sealed class Pending(SessionHello hello)
        {
            public SessionHello Hello { get; } = hello;
            public CancellationTokenRegistration Cancellation { get; set; }
            public TaskCompletionSource<ITransportConnection> Completion { get; } =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }

    private sealed class Connection(
        NegotiatedSession session,
        ChannelWriter<TransportFrame> writer,
        ChannelReader<TransportFrame> reader) : ITransportConnection
    {
        private readonly ConcurrentDictionary<StreamKind, long> _sent = new(session.RemoteResumeCursors);
        private readonly ConcurrentDictionary<StreamKind, long> _received = new(session.LocalResumeCursors);
        private readonly SemaphoreSlim _sendGate = new(1, 1);
        public NegotiatedSession Session { get; } = session;

        public async ValueTask SendAsync(TransportFrame frame, CancellationToken cancellationToken = default)
        {
            await _sendGate.WaitAsync(cancellationToken);
            try
            {
                Validate(frame, _sent, commit: false);
                await writer.WriteAsync(frame, cancellationToken);
                _sent[frame.Stream] = frame.Sequence;
            }
            finally { _sendGate.Release(); }
        }

        public bool TrySend(TransportFrame frame)
        {
            if (!_sendGate.Wait(0))
                return false;
            try
            {
                Validate(frame, _sent, commit: false);
                if (!writer.TryWrite(frame))
                    return false;
                _sent[frame.Stream] = frame.Sequence;
                return true;
            }
            finally { _sendGate.Release(); }
        }

        public async IAsyncEnumerable<TransportFrame> ReceiveAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await foreach (var frame in reader.ReadAllAsync(cancellationToken))
            {
                Validate(frame, _received);
                yield return frame;
            }
        }

        private void Validate(TransportFrame frame, ConcurrentDictionary<StreamKind, long> cursors, bool commit = true)
        {
            if (frame.SessionId != Session.SessionId || frame.NodeIncarnationId != Session.NodeIncarnationId)
                throw new TransportProtocolException(TransportError.SessionBindingMismatch, "Frame is bound to another session or incarnation.");
            if (frame.Payload.Length > Session.Limits.MaximumPayloadBytes)
                throw new TransportProtocolException(TransportError.PayloadTooLarge, "Frame payload exceeds the negotiated limit.");
            var prior = cursors.GetValueOrDefault(frame.Stream, 0);
            if (frame.Sequence != prior + 1 || frame.Cursor < 0)
                throw new TransportProtocolException(TransportError.InvalidSequence, "Frame sequence is not contiguous.");
            if (commit)
                cursors[frame.Stream] = frame.Sequence;
        }

        public ValueTask DisposeAsync()
        {
            writer.TryComplete();
            _sendGate.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
