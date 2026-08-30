using System.Net.WebSockets;
using System.Security.Cryptography;
using Steward.Transport;
using Steward.Transport.Local;

namespace Steward.ConnectionHost.Windows;

public sealed record RdpDvcLoopbackTransportBridgeOptions(
    Uri Endpoint,
    string BridgeIdentity,
    string BridgeSigningPrivateKeyFile,
    string ControlIdentity,
    string ControlSigningPublicKeyFile,
    int MaximumBufferedFrames = 4096)
{
    public RdpDvcLoopbackTransportBridgeOptions Validate()
    {
        if (Endpoint is null ||
            !Endpoint.IsAbsoluteUri ||
            Endpoint.Scheme != Uri.UriSchemeWs ||
            !Endpoint.IsLoopback ||
            !string.IsNullOrEmpty(Endpoint.UserInfo) ||
            !string.IsNullOrEmpty(Endpoint.Query) ||
            !string.IsNullOrEmpty(Endpoint.Fragment))
            throw new ArgumentException(
                "The ConnectionHost bridge endpoint must be loopback ws.");
        ValidateIdentity(BridgeIdentity, nameof(BridgeIdentity));
        ValidateIdentity(ControlIdentity, nameof(ControlIdentity));
        ValidateFile(
            BridgeSigningPrivateKeyFile,
            nameof(BridgeSigningPrivateKeyFile));
        ValidateFile(
            ControlSigningPublicKeyFile,
            nameof(ControlSigningPublicKeyFile));
        if (MaximumBufferedFrames is < 8 or > 65_536)
            throw new ArgumentOutOfRangeException(
                nameof(MaximumBufferedFrames));
        return this;
    }

    private static void ValidateIdentity(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 256 ||
            value.Any(char.IsControl))
            throw new ArgumentException(
                "The bridge transport identity is invalid.",
                name);
    }

    private static void ValidateFile(string value, string name)
    {
        if (!Path.IsPathFullyQualified(value) ||
            !File.Exists(value) ||
            File.GetAttributes(value).HasFlag(
                FileAttributes.ReparsePoint))
            throw new ArgumentException(
                "The bridge key file must be an absolute regular file.",
                name);
    }
}

public interface IRdpDvcControlBridge
{
    ValueTask<IAsyncDisposable> AttachAsync(
        ITransportConnection connection,
        CancellationToken cancellationToken);
}

public sealed class RdpDvcLoopbackTransportBridge :
    IRdpDvcControlBridge,
    IAsyncDisposable
{
    private readonly RdpDvcLoopbackTransportBridgeOptions options;
    private readonly SemaphoreSlim gate = new(1, 1);
    private BridgeLease? active;

    public RdpDvcLoopbackTransportBridge(
        RdpDvcLoopbackTransportBridgeOptions options)
    {
        this.options = options.Validate();
    }

    public async ValueTask<IAsyncDisposable> AttachAsync(
        ITransportConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (active is not null)
                throw new InvalidOperationException(
                    "The ConnectionHost bridge already owns a DVC connection.");
            var lease = new BridgeLease(
                options,
                connection,
                OnLeaseDisposed);
            active = lease;
            lease.Start();
            return lease;
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        BridgeLease? lease;
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            lease = active;
            active = null;
        }
        finally
        {
            gate.Release();
        }
        if (lease is not null)
            await lease.DisposeAsync().ConfigureAwait(false);
        gate.Dispose();
    }

    private void OnLeaseDisposed(BridgeLease lease)
    {
        gate.Wait();
        try
        {
            if (ReferenceEquals(active, lease))
                active = null;
        }
        finally
        {
            gate.Release();
        }
    }

    private sealed class BridgeLease :
        IAsyncDisposable
    {
        private readonly ITransportConnection remote;
        private readonly DirectWebSocketConnectionAcceptor acceptor;
        private readonly CancellationTokenSource stop = new();
        private readonly Action<BridgeLease> disposedCallback;
        private readonly object localGate = new();
        private TaskCompletionSource<ITransportConnection> localAvailable =
            NewLocalSource();
        private ITransportConnection? local;
        private Task? lifetime;
        private int disposed;

        public BridgeLease(
            RdpDvcLoopbackTransportBridgeOptions options,
            ITransportConnection remote,
            Action<BridgeLease> disposedCallback)
        {
            this.remote = remote;
            this.disposedCallback = disposedCallback;
            ECDsa? bridgeKey = ECDsa.Create();
            try
            {
                bridgeKey.ImportFromPem(
                    File.ReadAllText(
                        options.BridgeSigningPrivateKeyFile));
                var signing = new EcdsaEndpointSigningKey(
                    options.BridgeIdentity,
                    bridgeKey);
                bridgeKey = null;
                using var controlKey = ECDsa.Create();
                controlKey.ImportFromPem(
                    File.ReadAllText(
                        options.ControlSigningPublicKeyFile));
                acceptor = new(
                    new(
                        options.Endpoint,
                        TransportEndpointRole.Node,
                        signing,
                        new(
                            options.ControlIdentity,
                            controlKey.ExportSubjectPublicKeyInfo()),
                        AllowUnencryptedLoopback: true,
                        MaximumWireFrameBytes:
                            remote.Session.Limits.MaximumPayloadBytes +
                            4096,
                        MaximumBufferedFrames:
                            options.MaximumBufferedFrames));
            }
            catch
            {
                bridgeKey?.Dispose();
                throw;
            }
        }

        public void Start() => lifetime = RunAsync();

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;
            stop.Cancel();
            ITransportConnection? current;
            lock (localGate)
            {
                current = local;
                local = null;
                localAvailable.TrySetCanceled(stop.Token);
            }
            if (current is not null)
                await current.DisposeAsync().ConfigureAwait(false);
            if (lifetime is not null)
            {
                try
                {
                    await lifetime.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                    when (stop.IsCancellationRequested)
                {
                }
            }
            await acceptor.DisposeAsync().ConfigureAwait(false);
            await remote.DisposeAsync().ConfigureAwait(false);
            stop.Dispose();
            disposedCallback(this);
        }

        private async Task RunAsync()
        {
            var remotePump = PumpRemoteAsync(stop.Token);
            var acceptLoop = AcceptLoopAsync(stop.Token);
            var completed = await Task.WhenAny(
                    remotePump,
                    acceptLoop)
                .ConfigureAwait(false);
            stop.Cancel();
            await completed.ConfigureAwait(false);
            try
            {
                await Task.WhenAll(remotePump, acceptLoop)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (stop.IsCancellationRequested)
            {
            }
        }

        private async Task AcceptLoopAsync(
            CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var connection = await acceptor.AcceptAsync(
                        CreateHello(remote.Session),
                        cancellationToken)
                    .ConfigureAwait(false);
                SetLocal(connection);
                try
                {
                    await PumpLocalAsync(
                            connection,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (Exception exception)
                    when (IsLocalDisconnect(exception))
                {
                }
                finally
                {
                    InvalidateLocal(connection);
                    await connection.DisposeAsync()
                        .ConfigureAwait(false);
                }
            }
        }

        private async Task PumpLocalAsync(
            ITransportConnection connection,
            CancellationToken cancellationToken)
        {
            await foreach (var frame in connection.ReceiveAsync(
                               cancellationToken)
                               .ConfigureAwait(false))
                await remote.SendAsync(frame, cancellationToken)
                    .ConfigureAwait(false);
        }

        private async Task PumpRemoteAsync(
            CancellationToken cancellationToken)
        {
            await foreach (var frame in remote.ReceiveAsync(
                               cancellationToken)
                               .ConfigureAwait(false))
            {
                while (true)
                {
                    var connection = await WaitForLocalAsync(
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (connection.Session.RemoteResumeCursors
                            .TryGetValue(
                                frame.Stream,
                                out var cursor) &&
                        frame.Cursor <= cursor)
                        break;
                    try
                    {
                        await connection.SendAsync(
                                frame,
                                cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }
                    catch (Exception exception)
                        when (IsLocalDisconnect(exception))
                    {
                        InvalidateLocal(connection);
                    }
                }
            }
        }

        private Task<ITransportConnection> WaitForLocalAsync(
            CancellationToken cancellationToken)
        {
            lock (localGate)
                return local is not null
                    ? Task.FromResult(local)
                    : localAvailable.Task.WaitAsync(
                        cancellationToken);
        }

        private void SetLocal(ITransportConnection connection)
        {
            lock (localGate)
            {
                if (local is not null)
                    throw new InvalidOperationException(
                        "The ConnectionHost bridge already has a Control connection.");
                local = connection;
                localAvailable.TrySetResult(connection);
            }
        }

        private void InvalidateLocal(ITransportConnection connection)
        {
            lock (localGate)
            {
                if (!ReferenceEquals(local, connection))
                    return;
                local = null;
                localAvailable = NewLocalSource();
            }
        }

        private static SessionHello CreateHello(
            NegotiatedSession session) =>
            new(
                session.SessionId,
                session.NodeIncarnationId,
                session.ProtocolMajor,
                session.ProtocolMinor,
                session.Features,
                session.Features.Contains("orchestration-v1")
                    ? new HashSet<string>(
                        ["orchestration-v1"],
                        StringComparer.Ordinal)
                    : new HashSet<string>(StringComparer.Ordinal),
                session.RemoteResumeCursors,
                session.Limits);

        private static TaskCompletionSource<ITransportConnection>
            NewLocalSource() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private static bool IsLocalDisconnect(Exception exception) =>
            exception is
                IOException or
                WebSocketException or
                ObjectDisposedException or
                OperationCanceledException or
                TransportProtocolException;
    }
}
