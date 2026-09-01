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

public sealed record ReconnectTransportBinding(
    int Version,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    long ReconnectGeneration,
    Guid AttemptId,
    int RdpSessionId,
    string CarrierTranscriptSha256)
{
    public const int CurrentVersion = 2;

    public Guid RouteId { get; init; } = HostId.Value;

    public ReconnectTransportBinding Validate(
        NodeIncarnationId expectedIncarnation)
    {
        if (Version != CurrentVersion ||
            RouteId == Guid.Empty ||
            HostId.Value == Guid.Empty ||
            NodeIncarnationId.Value == Guid.Empty ||
            NodeIncarnationId != expectedIncarnation ||
            ReconnectGeneration <= 0 ||
            AttemptId == Guid.Empty ||
            RdpSessionId <= 0 ||
            CarrierTranscriptSha256.Length != 64 ||
            CarrierTranscriptSha256.Any(character =>
                !Uri.IsHexDigit(character)) ||
            !string.Equals(
                CarrierTranscriptSha256,
                CarrierTranscriptSha256.ToUpperInvariant(),
                StringComparison.Ordinal))
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "The reconnect transport binding is invalid.");
        return this;
    }
}
public sealed record SessionHello(
    Guid SessionId,
    NodeIncarnationId NodeIncarnationId,
    int ProtocolMajor,
    int ProtocolMinor,
    IReadOnlySet<string> SupportedFeatures,
    IReadOnlySet<string> RequiredFeatures,
    IReadOnlyDictionary<StreamKind, long> ResumeCursors,
    TransportLimits Limits,
    ReconnectTransportBinding? ReconnectBinding = null);

public sealed record NegotiatedSession(
    Guid SessionId,
    NodeIncarnationId NodeIncarnationId,
    int ProtocolMajor,
    int ProtocolMinor,
    IReadOnlySet<string> Features,
    IReadOnlyDictionary<StreamKind, long> LocalResumeCursors,
    IReadOnlyDictionary<StreamKind, long> RemoteResumeCursors,
    TransportLimits Limits,
    VerifiedSessionSecurity Security,
    ReconnectTransportBinding? ReconnectBinding = null);

public sealed record TransportFrame(
    Guid SessionId,
    NodeIncarnationId NodeIncarnationId,
    StreamKind Stream,
    long Sequence,
    long Cursor,
    ReadOnlyMemory<byte> Payload);

public sealed class TransportDisconnectedException(
    string message,
    Exception? innerException = null) : IOException(message, innerException);

public sealed class TransientTransportException(
    string message,
    Exception? innerException = null) : IOException(message, innerException);
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
        local.ReconnectBinding?.Validate(local.NodeIncarnationId);
        remote.ReconnectBinding?.Validate(remote.NodeIncarnationId);
        if (local.SessionId == Guid.Empty || local.SessionId != remote.SessionId ||
            local.NodeIncarnationId != remote.NodeIncarnationId ||
            local.ReconnectBinding != remote.ReconnectBinding)
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "Session, Node incarnation, or reconnect binding differs.");
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
            security,
            local.ReconnectBinding);
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
public sealed record RdpDvcRetainedV1EndpointState(
    string EndpointVersion,
    bool FiniteNonceStateRetained)
{
    public const string SupportedEndpointVersion = "1.0.23";

    public RdpDvcRetainedV1EndpointState Validate()
    {
        if (!string.Equals(
                EndpointVersion,
                SupportedEndpointVersion,
                StringComparison.Ordinal) ||
            !FiniteNonceStateRetained)
            throw new InvalidDataException(
                "The retained v1 endpoint migration state is invalid.");
        return this;
    }
}

public enum RdpDvcControlCarrierProtocol
{
    RetainedV1 = 1,
    ReconnectV2 = 2
}

public interface IRdpDvcControlCarrierAttachment
{
    RdpDvcControlCarrierProtocol Protocol { get; }
    Guid SessionId { get; }
    Guid RouteId { get; }
    HostId HostId { get; }
    NodeIncarnationId NodeIncarnationId { get; }
    long? ReconnectGeneration { get; }
    Guid AttemptId { get; }
    int RdpSessionId { get; }
}

public sealed record RetainedV1CarrierAttachment(
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    int RdpSessionId,
    Guid ConnectionNonce,
    RdpDvcRetainedV1EndpointState EndpointState) :
    IRdpDvcControlCarrierAttachment
{
    public Guid RouteId { get; init; } = HostId.Value;
    public RdpDvcControlCarrierProtocol Protocol =>
        RdpDvcControlCarrierProtocol.RetainedV1;
    public long? ReconnectGeneration => null;
    public Guid AttemptId => ConnectionNonce;

    public RetainedV1CarrierAttachment Validate()
    {
        if (SessionId == Guid.Empty ||
            RouteId == Guid.Empty ||
            HostId.Value == Guid.Empty ||
            NodeIncarnationId.Value == Guid.Empty ||
            RdpSessionId <= 0 ||
            ConnectionNonce == Guid.Empty ||
            EndpointState is null)
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "The retained v1 carrier attachment is invalid.");
        _ = EndpointState.Validate();
        return this;
    }
}
public sealed record ReconnectCarrierAttachment(
    Guid SessionId,
    ReconnectTransportBinding Binding) :
    IRdpDvcControlCarrierAttachment
{
    public RdpDvcControlCarrierProtocol Protocol =>
        RdpDvcControlCarrierProtocol.ReconnectV2;
    public Guid RouteId => Binding.RouteId;
    public HostId HostId => Binding.HostId;
    public NodeIncarnationId NodeIncarnationId =>
        Binding.NodeIncarnationId;
    public long? ReconnectGeneration =>
        Binding.ReconnectGeneration;
    public Guid AttemptId => Binding.AttemptId;
    public int RdpSessionId => Binding.RdpSessionId;
    public ReconnectCarrierAttachment Validate()
    {
        if (SessionId == Guid.Empty || Binding is null)
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "The reconnect carrier attachment is invalid.");
        Binding.Validate(Binding.NodeIncarnationId);
        return this;
    }
}

public static class ReconnectCarrierAttachmentCodec
{
    public const int EncodedBytes = 136;

    public static string AcknowledgementPipeName(
        string pipeName,
        Guid attemptId)
    {
        if (string.IsNullOrWhiteSpace(pipeName) ||
            attemptId == Guid.Empty)
            throw new ArgumentException(
                "The reconnect acknowledgement pipe identity is invalid.");
        var value = pipeName + ".ack." + attemptId.ToString("N");
        if (value.Length > 128 ||
            value.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new ArgumentException(
                "The reconnect acknowledgement pipe name is invalid.",
                nameof(pipeName));
        return value;
    }
    private const int CodecVersion = 1;

    public static async Task WriteAsync(
        Stream stream,
        ReconnectCarrierAttachment attachment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        attachment.Validate();
        var value = new byte[EncodedBytes];
        "SRCA"u8.CopyTo(value);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(4, 4),
            CodecVersion);
        attachment.SessionId.TryWriteBytes(value.AsSpan(8, 16));
        var binding = attachment.Binding;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(24, 4),
            binding.Version);
        binding.RouteId.TryWriteBytes(value.AsSpan(28, 16));
        binding.HostId.Value.TryWriteBytes(value.AsSpan(44, 16));
        binding.NodeIncarnationId.Value.TryWriteBytes(
            value.AsSpan(60, 16));
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(
            value.AsSpan(76, 8),
            binding.ReconnectGeneration);
        binding.AttemptId.TryWriteBytes(value.AsSpan(84, 16));
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(100, 4),
            binding.RdpSessionId);
        Convert.FromHexString(binding.CarrierTranscriptSha256)
            .CopyTo(value, 104);
        await stream.WriteAsync(value, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public static async Task<ReconnectCarrierAttachment> ReadAsync(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var value = new byte[EncodedBytes];
        var offset = 0;
        while (offset < value.Length)
        {
            var read = await stream.ReadAsync(
                    value.AsMemory(offset),
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException(
                    "The reconnect carrier attachment closed early.");
            offset += read;
        }
        if (!value.AsSpan(0, 4).SequenceEqual("SRCA"u8) ||
            System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                value.AsSpan(4, 4)) != CodecVersion)
            throw new TransportProtocolException(
                TransportError.UnsupportedVersion,
                "The reconnect carrier attachment version is invalid.");
        var attachment = new ReconnectCarrierAttachment(
            new Guid(value.AsSpan(8, 16)),
            new(
                System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                    value.AsSpan(24, 4)),
                new HostId(new Guid(value.AsSpan(44, 16))),
                new NodeIncarnationId(
                    new Guid(value.AsSpan(60, 16))),
                System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(
                    value.AsSpan(76, 8)),
                new Guid(value.AsSpan(84, 16)),
                System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                    value.AsSpan(100, 4)),
                Convert.ToHexString(value.AsSpan(104, 32)))
            {
                RouteId = new Guid(value.AsSpan(28, 16))
            });
        return attachment.Validate();
    }
}
public static class RdpDvcControlCarrierAttachmentCodec
{
    private const int RetainedV1EncodedBytes = 108;
    private const int RetainedV1CodecVersion = 1;

    public static Task WriteAsync(
        Stream stream,
        IRdpDvcControlCarrierAttachment attachment,
        CancellationToken cancellationToken = default) =>
        attachment switch
        {
            ReconnectCarrierAttachment reconnect =>
                ReconnectCarrierAttachmentCodec.WriteAsync(
                    stream,
                    reconnect,
                    cancellationToken),
            RetainedV1CarrierAttachment retained =>
                WriteRetainedV1Async(
                    stream,
                    retained,
                    cancellationToken),
            _ => throw new ArgumentException(
                "The DVC Control carrier attachment type is invalid.",
                nameof(attachment))
        };

    public static async Task<IRdpDvcControlCarrierAttachment> ReadAsync(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var magic = new byte[4];
        await ReadExactlyAsync(stream, magic, cancellationToken)
            .ConfigureAwait(false);
        var encodedBytes = magic.AsSpan().SequenceEqual("SRCA"u8)
            ? ReconnectCarrierAttachmentCodec.EncodedBytes
            : magic.AsSpan().SequenceEqual("SV1A"u8)
                ? RetainedV1EncodedBytes
                : throw new TransportProtocolException(
                    TransportError.UnsupportedVersion,
                    "The DVC Control carrier attachment version is invalid.");
        var value = new byte[encodedBytes];
        magic.CopyTo(value, 0);
        await ReadExactlyAsync(
                stream,
                value.AsMemory(magic.Length),
                cancellationToken)
            .ConfigureAwait(false);
        if (encodedBytes ==
            ReconnectCarrierAttachmentCodec.EncodedBytes)
        {
            await using var encoded = new MemoryStream(
                value,
                writable: false);
            return await ReconnectCarrierAttachmentCodec.ReadAsync(
                    encoded,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        return DecodeRetainedV1(value);
    }

    private static async Task WriteRetainedV1Async(
        Stream stream,
        RetainedV1CarrierAttachment attachment,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        attachment = attachment.Validate();
        var value = new byte[RetainedV1EncodedBytes];
        "SV1A"u8.CopyTo(value);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(4, 4),
            RetainedV1CodecVersion);
        attachment.SessionId.TryWriteBytes(value.AsSpan(8, 16));
        attachment.RouteId.TryWriteBytes(value.AsSpan(24, 16));
        attachment.HostId.Value.TryWriteBytes(value.AsSpan(40, 16));
        attachment.NodeIncarnationId.Value.TryWriteBytes(
            value.AsSpan(56, 16));
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(72, 4),
            attachment.RdpSessionId);
        attachment.ConnectionNonce.TryWriteBytes(
            value.AsSpan(76, 16));
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(92, 4),
            1);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(96, 4),
            0);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(100, 4),
            23);
        value[104] = attachment.EndpointState.FiniteNonceStateRetained
            ? (byte)1
            : (byte)0;
        await stream.WriteAsync(value, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static RetainedV1CarrierAttachment DecodeRetainedV1(
        ReadOnlySpan<byte> value)
    {
        if (value.Length != RetainedV1EncodedBytes ||
            !value[..4].SequenceEqual("SV1A"u8) ||
            System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                value.Slice(4, 4)) != RetainedV1CodecVersion ||
            value[105] != 0 ||
            value[106] != 0 ||
            value[107] != 0)
            throw new TransportProtocolException(
                TransportError.UnsupportedVersion,
                "The retained v1 carrier attachment version is invalid.");
        var endpointVersion = string.Join(
            '.',
            System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                value.Slice(92, 4)),
            System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                value.Slice(96, 4)),
            System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                value.Slice(100, 4)));
        return new RetainedV1CarrierAttachment(
            new Guid(value.Slice(8, 16)),
            new HostId(new Guid(value.Slice(40, 16))),
            new NodeIncarnationId(new Guid(value.Slice(56, 16))),
            System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                value.Slice(72, 4)),
            new Guid(value.Slice(76, 16)),
            new(endpointVersion, value[104] == 1))
        {
            RouteId = new Guid(value.Slice(24, 16))
        }.Validate();
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(
                    destination[offset..],
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException(
                    "The DVC Control carrier attachment closed early.");
            offset += read;
        }
    }
}
public enum ReconnectCarrierControlPhase
{
    RelayReady = 1,
    SecureSessionAuthenticated = 2,
    Failed = 3
}

public enum ReconnectCarrierFailure
{
    None = 0,
    AttachmentRejected = 1,
    SessionAuthenticationFailed = 2,
    SessionBindingRejected = 3,
    GenerationRejected = 4,
    ControlTransportFailed = 5
}

public sealed record ReconnectCarrierControlMessage(
    Guid AttemptId,
    ReconnectCarrierControlPhase Phase,
    ReconnectCarrierFailure Failure)
{
    public ReconnectCarrierControlMessage Validate()
    {
        if (AttemptId == Guid.Empty ||
            !Enum.IsDefined(Phase) ||
            !Enum.IsDefined(Failure) ||
            Phase == ReconnectCarrierControlPhase.Failed &&
            Failure == ReconnectCarrierFailure.None ||
            Phase != ReconnectCarrierControlPhase.Failed &&
            Failure != ReconnectCarrierFailure.None)
            throw new ArgumentException(
                "The reconnect carrier Control message is invalid.");
        return this;
    }

    public static ReconnectCarrierControlMessage RelayReady(
        Guid attemptId) =>
        new(
            attemptId,
            ReconnectCarrierControlPhase.RelayReady,
            ReconnectCarrierFailure.None);

    public static ReconnectCarrierControlMessage
        SecureSessionAuthenticated(Guid attemptId) =>
        new(
            attemptId,
            ReconnectCarrierControlPhase.SecureSessionAuthenticated,
            ReconnectCarrierFailure.None);

    public static ReconnectCarrierControlMessage Failed(
        Guid attemptId,
        ReconnectCarrierFailure failure) =>
        new ReconnectCarrierControlMessage(
            attemptId,
            ReconnectCarrierControlPhase.Failed,
            failure).Validate();
}

public static class ReconnectCarrierControlMessageCodec
{
    public const int EncodedBytes = 32;
    private const int CodecVersion = 1;

    public static async Task WriteAsync(
        Stream stream,
        ReconnectCarrierControlMessage message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        message = message.Validate();
        var value = new byte[EncodedBytes];
        "SRCR"u8.CopyTo(value);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(4, 4),
            CodecVersion);
        message.AttemptId.TryWriteBytes(value.AsSpan(8, 16));
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(24, 4),
            (int)message.Phase);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
            value.AsSpan(28, 4),
            (int)message.Failure);
        await stream.WriteAsync(value, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public static async Task<ReconnectCarrierControlMessage> ReadAsync(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var value = new byte[EncodedBytes];
        var offset = 0;
        while (offset < value.Length)
        {
            var read = await stream.ReadAsync(
                    value.AsMemory(offset),
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException(
                    "The reconnect carrier Control response closed early.");
            offset += read;
        }
        if (!value.AsSpan(0, 4).SequenceEqual("SRCR"u8) ||
            System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                value.AsSpan(4, 4)) != CodecVersion)
            throw new TransportProtocolException(
                TransportError.UnsupportedVersion,
                "The reconnect carrier Control response version is invalid.");
        return new ReconnectCarrierControlMessage(
            new Guid(value.AsSpan(8, 16)),
            (ReconnectCarrierControlPhase)
                System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                    value.AsSpan(24, 4)),
            (ReconnectCarrierFailure)
                System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(
                    value.AsSpan(28, 4))).Validate();
    }
}
