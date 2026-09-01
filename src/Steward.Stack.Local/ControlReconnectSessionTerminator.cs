using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Steward.Orchestration;
using Steward.Transport;

namespace Steward.Stack.Local;

public sealed class ControlReconnectSessionTerminator
{
    private readonly string controlIdentity;
    private readonly string controlSigningPrivateKeyFile;
    private readonly TimeSpan handshakeTimeout;

    public ControlReconnectSessionTerminator(
        string controlIdentity,
        string controlSigningPrivateKeyFile,
        TimeSpan handshakeTimeout)
    {
        if (string.IsNullOrWhiteSpace(controlIdentity) ||
            controlIdentity.Length > 256 ||
            controlIdentity.Any(char.IsControl))
            throw new ArgumentException(
                "The Control transport identity is invalid.",
                nameof(controlIdentity));
        this.controlSigningPrivateKeyFile = ValidateFile(
            controlSigningPrivateKeyFile,
            nameof(controlSigningPrivateKeyFile));
        if (handshakeTimeout <= TimeSpan.Zero ||
            handshakeTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(
                nameof(handshakeTimeout));
        this.controlIdentity = controlIdentity;
        this.handshakeTimeout = handshakeTimeout;
    }

    public async Task<ITransportConnection> AcceptAsync(
        Stream carrier,
        IRdpDvcControlCarrierAttachment attachment,
        NodeEndpointRegistration endpoint,
        SessionHello hello,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(carrier);
        ArgumentNullException.ThrowIfNull(attachment);
        endpoint.Validate();
        var expectedReconnectBinding = attachment switch
        {
            ReconnectCarrierAttachment reconnect =>
                reconnect.Validate().Binding,
            RetainedV1CarrierAttachment retained =>
                ValidateRetained(retained),
            _ => throw new TransportProtocolException(
                TransportError.UnsupportedVersion,
                "The Control carrier attachment type is unsupported.")
        };
        if (attachment.SessionId != hello.SessionId ||
            attachment.HostId != endpoint.HostId ||
            attachment.NodeIncarnationId != endpoint.NodeIncarnationId ||
            hello.NodeIncarnationId != endpoint.NodeIncarnationId ||
            hello.ReconnectBinding != expectedReconnectBinding)
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "The Control carrier does not match its registered Node.");
        var privateKey = await File.ReadAllTextAsync(
                controlSigningPrivateKeyFile,
                cancellationToken)
            .ConfigureAwait(false);
        using var nodeKey = ECDsa.Create();
        nodeKey.ImportFromPem(
            await File.ReadAllTextAsync(
                    ValidateFile(
                        endpoint.PeerPublicKeyReference,
                        nameof(endpoint.PeerPublicKeyReference)),
                    cancellationToken)
                .ConfigureAwait(false));
        ECDsa? controlKey = ECDsa.Create();
        SecureStreamConnectionAcceptor? acceptor = null;
        try
        {
            controlKey.ImportFromPem(privateKey);
            acceptor = new(
                new SingleStreamAcceptor(carrier),
                new(
                    TransportEndpointRole.Control,
                    new EcdsaEndpointSigningKey(
                        controlIdentity,
                        controlKey),
                    new(
                        endpoint.PeerIdentity,
                        nodeKey.ExportSubjectPublicKeyInfo()),
                    HandshakeTimeout: handshakeTimeout,
                    OperationTimeout: handshakeTimeout));
            controlKey = null;
            var connection = await acceptor.AcceptAsync(
                    hello,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!connection.Session.Security.IsSecure ||
                connection.Session.SessionId != attachment.SessionId ||
                connection.Session.NodeIncarnationId !=
                    endpoint.NodeIncarnationId ||
                !string.Equals(
                    connection.Session.Security.LocalIdentity,
                    controlIdentity,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    connection.Session.Security.RemoteIdentity,
                    endpoint.PeerIdentity,
                    StringComparison.Ordinal) ||
                connection.Session.ReconnectBinding != expectedReconnectBinding)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw new CryptographicException(
                    "Control did not establish the bound signed reconnect session.");
            }
            var owned = new OwnedConnection(connection, acceptor);
            acceptor = null;
            return owned;
        }
        finally
        {
            controlKey?.Dispose();
            if (acceptor is not null)
                await acceptor.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static ReconnectTransportBinding? ValidateRetained(
        RetainedV1CarrierAttachment attachment)
    {
        _ = attachment.Validate();
        return null;
    }
    private static string ValidateFile(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !Path.IsPathFullyQualified(value))
            throw new ArgumentException(
                "The transport key path must be absolute.",
                name);
        var path = Path.GetFullPath(value);
        if (!File.Exists(path) ||
            File.GetAttributes(path).HasFlag(
                FileAttributes.ReparsePoint))
            throw new ArgumentException(
                "The transport key file must be regular.",
                name);
        return path;
    }

    private sealed class SingleStreamAcceptor(Stream stream) :
        ITransportStreamAcceptor
    {
        private int used;

        public ValueTask<Stream> AcceptStreamAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref used, 1) != 0)
                throw new InvalidOperationException(
                    "The Control carrier stream is single-use.");
            return ValueTask.FromResult(stream);
        }
    }

    private sealed class OwnedConnection(
        ITransportConnection inner,
        SecureStreamConnectionAcceptor acceptor) : ITransportConnection
    {
        public NegotiatedSession Session => inner.Session;

        public ValueTask SendAsync(
            TransportFrame frame,
            CancellationToken cancellationToken = default) =>
            inner.SendAsync(frame, cancellationToken);

        public bool TrySend(TransportFrame frame) =>
            inner.TrySend(frame);

        public async IAsyncEnumerable<TransportFrame> ReceiveAsync(
            [EnumeratorCancellation]
            CancellationToken cancellationToken = default)
        {
            await foreach (var frame in inner.ReceiveAsync(cancellationToken)
                               .ConfigureAwait(false))
                yield return frame;
        }

        public async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync().ConfigureAwait(false);
            await acceptor.DisposeAsync().ConfigureAwait(false);
        }
    }
}
