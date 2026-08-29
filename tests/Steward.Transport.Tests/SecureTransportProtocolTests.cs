using System.Security.Cryptography;
using Steward.Domain;

namespace Steward.Transport.Tests;

public sealed class SecureTransportProtocolTests
{
    [Fact]
    public void Bootstrap_envelope_is_operation_bound_and_confidential()
    {
        using var encryption = RSA.Create(3072);
        using var node = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authentication = RandomNumberGenerator.GetBytes(32);
        var payload = new RdpDvcBootstrapEnvelopePayload(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            authentication,
            node.ExportSubjectPublicKeyInfo());

        var ciphertext = RdpDvcBootstrapEnvelope.Encrypt(
            encryption,
            payload);
        var decoded = RdpDvcBootstrapEnvelope.Decrypt(
            encryption,
            ciphertext);

        Assert.Equal(payload.OperationId, decoded.OperationId);
        Assert.Equal(payload.SessionId, decoded.SessionId);
        Assert.Equal(payload.HostId, decoded.HostId);
        Assert.Equal(
            payload.NodeIncarnationId,
            decoded.NodeIncarnationId);
        Assert.Equal(authentication, decoded.AuthenticationKey);
        Assert.Equal(
            payload.NodeSigningPublicKey,
            decoded.NodeSigningPublicKey);
        Assert.Equal(-1, ciphertext.AsSpan().IndexOf(authentication));
    }

    [Fact]
    public async Task In_memory_transport_preserves_multiplexing_and_backpressure()
    {
        var incarnation = NodeIncarnationId.New();
        var sessionId = Guid.NewGuid();
        var securityA = new VerifiedSessionSecurity(
            true, true, "control", "node", "binding");
        var securityB = new VerifiedSessionSecurity(
            true, true, "node", "control", "binding");
        var (first, second) = InMemoryDuplexCarrier.CreatePair(
            securityA, securityB);
        var hello = Hello(sessionId, incarnation, maximumBufferedFrames: 1);
        var connectingA = first.ConnectAsync(hello).AsTask();
        var connectingB = second.ConnectAsync(hello).AsTask();
        await using var a = await connectingA;
        await using var b = await connectingB;

        Assert.True(a.TrySend(Frame(
            hello, StreamKind.Control, 1, "command")));
        Assert.False(a.TrySend(Frame(
            hello, StreamKind.Control, 2, "blocked")));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var received = await b.ReceiveAsync(timeout.Token).FirstAsync(
            timeout.Token);
        Assert.Equal(StreamKind.Control, received.Stream);
        Assert.Equal(
            "command",
            System.Text.Encoding.UTF8.GetString(received.Payload.Span));
        Assert.True(a.TrySend(Frame(hello, StreamKind.Logs, 1, "log")));
    }

    [Fact]
    public async Task Session_negotiation_rejects_substitution_and_oversize()
    {
        var sessionId = Guid.NewGuid();
        var hello = Hello(
            sessionId, NodeIncarnationId.New(), 1, maximumPayloadBytes: 1);
        var substituted = Hello(
            sessionId, NodeIncarnationId.New(), 1, maximumPayloadBytes: 1);
        var security = new VerifiedSessionSecurity(
            true, true, "a", "b", "binding");
        Assert.Equal(
            TransportError.SessionBindingMismatch,
            Assert.Throws<TransportProtocolException>(() =>
                SessionNegotiator.Negotiate(
                    hello, substituted, security)).Error);

        var (first, second) = InMemoryDuplexCarrier.CreatePair(
            security, security);
        var aTask = first.ConnectAsync(hello).AsTask();
        var bTask = second.ConnectAsync(hello).AsTask();
        await using var a = await aTask;
        await using var b = await bTask;
        var oversized = new TransportFrame(
            sessionId,
            hello.NodeIncarnationId,
            StreamKind.Artifacts,
            1,
            0,
            new byte[2]);
        Assert.Equal(
            TransportError.PayloadTooLarge,
            (await Assert.ThrowsAsync<TransportProtocolException>(
                () => a.SendAsync(oversized).AsTask())).Error);
    }

    [Fact]
    public void Ciphertext_is_opaque_authenticated_and_sequence_bound()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var session = Guid.NewGuid();
        var plaintext = "highly secret payload"u8.ToArray();
        var encrypted = SecureTransportProtocol.Encrypt(
            key, TransportEndpointRole.Control, session, 1, plaintext);

        Assert.DoesNotContain(
            Convert.ToHexString(plaintext),
            Convert.ToHexString(encrypted),
            StringComparison.Ordinal);
        Assert.Equal(
            plaintext,
            SecureTransportProtocol.Decrypt(
                key, TransportEndpointRole.Control, session, 1, encrypted));
        Assert.Equal(
            TransportError.InvalidSequence,
            Assert.Throws<TransportProtocolException>(() =>
                SecureTransportProtocol.Decrypt(
                    key,
                    TransportEndpointRole.Control,
                    session,
                    2,
                    encrypted)).Error);
        encrypted[^1] ^= 1;
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            SecureTransportProtocol.Decrypt(
                key, TransportEndpointRole.Control, session, 1, encrypted));
    }

    [Fact]
    public void Handshake_binds_both_endpoint_identities_and_transcript()
    {
        using var controlSigning = EcdsaEndpointSigningKey.Create("control");
        using var nodeSigning = EcdsaEndpointSigningKey.Create("node");
        using var controlEphemeral = ECDiffieHellman.Create(
            ECCurve.NamedCurves.nistP256);
        using var nodeEphemeral = ECDiffieHellman.Create(
            ECCurve.NamedCurves.nistP256);
        var hello = Hello(Guid.NewGuid(), NodeIncarnationId.New(), 4);
        var controlRecord = SecureTransportProtocol.CreateHandshake(
            TransportEndpointRole.Control,
            controlSigning,
            hello,
            controlEphemeral);
        var nodeRecord = SecureTransportProtocol.CreateHandshake(
            TransportEndpointRole.Node,
            nodeSigning,
            hello,
            nodeEphemeral);
        var parsedNode = SecureTransportProtocol.ParseAndVerifyHandshake(
            nodeRecord,
            TransportEndpointRole.Control,
            new(nodeSigning.Identity, nodeSigning.ExportPublicKey()),
            hello);
        var parsedControl = SecureTransportProtocol.ParseAndVerifyHandshake(
            controlRecord,
            TransportEndpointRole.Node,
            new(controlSigning.Identity, controlSigning.ExportPublicKey()),
            hello);

        var controlKeys = SecureTransportProtocol.DeriveKeys(
            controlEphemeral,
            parsedNode,
            controlRecord,
            nodeRecord,
            TransportEndpointRole.Control);
        var nodeKeys = SecureTransportProtocol.DeriveKeys(
            nodeEphemeral,
            parsedControl,
            nodeRecord,
            controlRecord,
            TransportEndpointRole.Node);
        Assert.Equal(controlKeys.Binding, nodeKeys.Binding);
        Assert.Equal(controlKeys.Send, nodeKeys.Receive);
        Assert.Equal(controlKeys.Receive, nodeKeys.Send);
    }

    [Fact]
    public void Handshake_and_frame_parsers_enforce_bounds()
    {
        var oversized = new byte[
            SecureTransportProtocol.MaximumHandshakeBytes + 1];
        oversized[0] = SecureTransportProtocol.HandshakeRecord;
        var error = Assert.Throws<SecureHandshakeException>(() =>
            SecureTransportProtocol.GetHandshakeSigningKeyFingerprint(oversized));
        Assert.Equal(SecureHandshakeError.BoundsExceeded, error.Error);

        var hello = Hello(Guid.NewGuid(), NodeIncarnationId.New(), 4);
        var serialized = SecureTransportProtocol.SerializeFrame(
            Frame(hello, StreamKind.Control, 1, "x"));
        serialized[32] = byte.MaxValue;
        Assert.Throws<TransportProtocolException>(() =>
            SecureTransportProtocol.DeserializeFrame(serialized));
    }

    private static SessionHello Hello(
        Guid id,
        NodeIncarnationId incarnation,
        int maximumBufferedFrames,
        int maximumPayloadBytes = 1024) =>
        new(
            id,
            incarnation,
            1,
            0,
            new HashSet<string>(),
            new HashSet<string>(),
            new Dictionary<StreamKind, long>(),
            new TransportLimits(
                maximumPayloadBytes, maximumBufferedFrames));

    private static TransportFrame Frame(
        SessionHello hello,
        StreamKind kind,
        long sequence,
        string payload) =>
        new(
            hello.SessionId,
            hello.NodeIncarnationId,
            kind,
            sequence,
            0,
            System.Text.Encoding.UTF8.GetBytes(payload));
}
