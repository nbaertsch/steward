using System.IO.Pipes;
using Steward.Transport;

namespace Steward.ConnectionHost.Windows;

public sealed record RdpDvcOpaqueControlPipeBridgeOptions(
    string PipeName,
    TimeSpan ConnectTimeout,
    int BufferBytes)
{
    public RdpDvcOpaqueControlPipeBridgeOptions Validate()
    {
        if (string.IsNullOrWhiteSpace(PipeName) ||
            PipeName.Length > 80 ||
            PipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new ArgumentException(
                "The Control carrier pipe name is invalid.");
        if (ConnectTimeout <= TimeSpan.Zero ||
            ConnectTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(
                nameof(ConnectTimeout));
        if (BufferBytes is < 4096 or > 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(BufferBytes));
        return this;
    }
}

public sealed class ReconnectCarrierControlRejectedException(
    ReconnectCarrierFailure failure) : IOException(
        "Control rejected the reconnect carrier before authentication.")
{
    public ReconnectCarrierFailure Failure { get; } =
        failure == ReconnectCarrierFailure.None
            ? throw new ArgumentOutOfRangeException(nameof(failure))
            : failure;
}

public interface IRdpDvcOpaqueControlBridgeLease : IAsyncDisposable
{
    Task Completion { get; }
}

public interface IRdpDvcOpaqueControlBridge
{
    Task<IRdpDvcOpaqueControlBridgeLease> AttachAsync(
        Stream carrier,
        IRdpDvcControlCarrierAttachment attachment,
        ConnectionRouteContext context,
        CancellationToken cancellationToken);
}

public sealed class RdpDvcOpaqueControlPipeBridge :
    IRdpDvcOpaqueControlBridge
{
    private readonly RdpDvcOpaqueControlPipeBridgeOptions options;
    private readonly IConnectionRecoveryStore? stateStore;

    public RdpDvcOpaqueControlPipeBridge(
        RdpDvcOpaqueControlPipeBridgeOptions options,
        IConnectionRecoveryStore? stateStore = null)
    {
        this.options = options.Validate();
        this.stateStore = stateStore;
    }

    public async Task<IRdpDvcOpaqueControlBridgeLease> AttachAsync(
        Stream carrier,
        IRdpDvcControlCarrierAttachment attachment,
        ConnectionRouteContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(carrier);
        context.Validate();
        ValidateAttachment(attachment);
        if (!carrier.CanRead || !carrier.CanWrite)
            throw new ArgumentException(
                "The opaque carrier stream must be duplex.",
                nameof(carrier));
        var lease = new BridgeLease(
            options,
            carrier,
            attachment,
            context,
            stateStore);
        try
        {
            await lease.ConnectAsync(cancellationToken)
                .ConfigureAwait(false);
            return lease;
        }
        catch
        {
            await lease.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static void ValidateAttachment(
        IRdpDvcControlCarrierAttachment attachment)
    {
        ArgumentNullException.ThrowIfNull(attachment);
        switch (attachment)
        {
            case ReconnectCarrierAttachment reconnect:
                _ = reconnect.Validate();
                break;
            case RetainedV1CarrierAttachment retained:
                _ = retained.Validate();
                break;
            default:
                throw new ArgumentException(
                    "The opaque carrier attachment type is invalid.",
                    nameof(attachment));
        }
    }
    public static string AcknowledgementPipeName(
        string pipeName,
        Guid attemptId) =>
        ReconnectCarrierAttachmentCodec.AcknowledgementPipeName(
            pipeName,
            attemptId);

    private sealed class BridgeLease :
        IRdpDvcOpaqueControlBridgeLease
    {
        private readonly RdpDvcOpaqueControlPipeBridgeOptions options;
        private readonly Stream carrier;
        private readonly IRdpDvcControlCarrierAttachment attachment;
        private readonly ConnectionRouteContext context;
        private readonly IConnectionRecoveryStore? stateStore;
        private readonly NamedPipeClientStream control;
        private readonly NamedPipeServerStream acknowledgement;
        private readonly CancellationTokenSource stop = new();
        private Task? lifetime;
        private readonly SemaphoreSlim routeStateGate = new(1, 1);
        private bool routeRecorded;
        private bool relayCompleted;
        private bool detached;
        private int disposed;

        public BridgeLease(
            RdpDvcOpaqueControlPipeBridgeOptions options,
            Stream carrier,
            IRdpDvcControlCarrierAttachment attachment,
            ConnectionRouteContext context,
            IConnectionRecoveryStore? stateStore)
        {
            this.options = options;
            this.carrier = carrier;
            this.attachment = attachment;
            this.context = context;
            this.stateStore = stateStore;
            control = new(
                ".",
                options.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            acknowledgement = new(
                AcknowledgementPipeName(
                    options.PipeName,
                    attachment.AttemptId),
                PipeDirection.In,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                ReconnectCarrierControlMessageCodec.EncodedBytes * 2,
                ReconnectCarrierControlMessageCodec.EncodedBytes * 2);
        }

        public Task Completion => lifetime ?? Task.CompletedTask;

        public async Task ConnectAsync(
            CancellationToken cancellationToken)
        {
            using var timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken);
            timeout.CancelAfter(options.ConnectTimeout);
            try
            {
                await control.ConnectAsync(timeout.Token)
                    .ConfigureAwait(false);
                await RdpDvcControlCarrierAttachmentCodec.WriteAsync(
                        control,
                        attachment,
                        timeout.Token)
                    .ConfigureAwait(false);
                await acknowledgement.WaitForConnectionAsync(
                        timeout.Token)
                    .ConfigureAwait(false);
                var ready = await ReconnectCarrierControlMessageCodec
                    .ReadAsync(acknowledgement, timeout.Token)
                    .ConfigureAwait(false);
                RequireAttempt(ready);
                ThrowIfRejected(ready);
                if (ready.Phase !=
                    ReconnectCarrierControlPhase.RelayReady)
                    throw UnexpectedPhase();

                lifetime = RunAsync(stop.Token);
                var authenticated =
                    await ReconnectCarrierControlMessageCodec
                        .ReadAsync(acknowledgement, timeout.Token)
                        .ConfigureAwait(false);
                RequireAttempt(authenticated);
                ThrowIfRejected(authenticated);
                if (authenticated.Phase !=
                    ReconnectCarrierControlPhase
                        .SecureSessionAuthenticated)
                    throw UnexpectedPhase();

                if (stateStore is not null)
                    await RecordRouteAsync(timeout.Token)
                        .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(
                    "Control did not authenticate the local reconnect attachment in time.");
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;
            stop.Cancel();
            await control.DisposeAsync().ConfigureAwait(false);
            await carrier.DisposeAsync().ConfigureAwait(false);
            acknowledgement.Dispose();
            if (lifetime is not null)
            {
                try
                {
                    await lifetime.ConfigureAwait(false);
                }
                catch (Exception exception)
                    when (IsExpectedRelayTermination(exception))
                {
                }
            }
            await ForceDetachRouteAsync().ConfigureAwait(false);
            routeStateGate.Dispose();
            stop.Dispose();
        }

        private async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                var nodeToControl = PumpAsync(
                    carrier,
                    control,
                    cancellationToken);
                var controlToNode = PumpAsync(
                    control,
                    carrier,
                    cancellationToken);
                await Task.WhenAny(nodeToControl, controlToNode)
                    .ConfigureAwait(false);
                stop.Cancel();
                try
                {
                    await Task.WhenAll(nodeToControl, controlToNode)
                        .ConfigureAwait(false);
                }
                catch (Exception exception)
                    when (IsExpectedRelayTermination(exception))
                {
                }
            }
            finally
            {
                await MarkRelayCompletedAsync().ConfigureAwait(false);
            }
        }

        private async Task RecordRouteAsync(
            CancellationToken cancellationToken)
        {
            await routeStateGate.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            try
            {
                await stateStore!.RecordAuthenticatedRouteAsync(
                        context,
                        attachment,
                        cancellationToken)
                    .ConfigureAwait(false);
                routeRecorded = true;
                if (relayCompleted)
                    await DetachRouteCoreAsync().ConfigureAwait(false);
            }
            finally
            {
                routeStateGate.Release();
            }
        }

        private async Task MarkRelayCompletedAsync()
        {
            await routeStateGate.WaitAsync(CancellationToken.None)
                .ConfigureAwait(false);
            try
            {
                relayCompleted = true;
                await DetachRouteCoreAsync().ConfigureAwait(false);
            }
            finally
            {
                routeStateGate.Release();
            }
        }

        private async Task ForceDetachRouteAsync()
        {
            await routeStateGate.WaitAsync(CancellationToken.None)
                .ConfigureAwait(false);
            try
            {
                relayCompleted = true;
                await DetachRouteCoreAsync().ConfigureAwait(false);
            }
            finally
            {
                routeStateGate.Release();
            }
        }

        private async Task DetachRouteCoreAsync()
        {
            if (stateStore is null ||
                !routeRecorded ||
                !relayCompleted ||
                detached)
                return;
            await stateStore.DetachControlAsync(
                    attachment.AttemptId,
                    CancellationToken.None)
                .ConfigureAwait(false);
            detached = true;
        }
        private void RequireAttempt(
            ReconnectCarrierControlMessage message)
        {
            if (message.AttemptId != attachment.AttemptId)
                throw new TransportProtocolException(
                    TransportError.SessionBindingMismatch,
                    "The Control response names another reconnect attempt.");
        }

        private static void ThrowIfRejected(
            ReconnectCarrierControlMessage message)
        {
            if (message.Phase == ReconnectCarrierControlPhase.Failed)
                throw new ReconnectCarrierControlRejectedException(
                    message.Failure);
        }

        private static TransportProtocolException UnexpectedPhase() =>
            new(
                TransportError.SessionBindingMismatch,
                "Control returned an out-of-order reconnect carrier phase.");

        private static bool IsExpectedRelayTermination(
            Exception exception) =>
            exception is
                OperationCanceledException or
                IOException or
                ObjectDisposedException or
                System.Threading.Channels.ChannelClosedException;

        private async Task PumpAsync(
            Stream source,
            Stream destination,
            CancellationToken cancellationToken)
        {
            var buffer = new byte[options.BufferBytes];
            while (true)
            {
                var read = await source.ReadAsync(
                        buffer,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                    return;
                await destination.WriteAsync(
                        buffer.AsMemory(0, read),
                        cancellationToken)
                    .ConfigureAwait(false);
                await destination.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }
}
