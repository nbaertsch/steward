using System.Security.Cryptography;
using System.Text.Json;
using Steward.Orchestration;
using Steward.Transport;
using Steward.Transport.Local;

namespace Steward.Stack.Local;

public interface ILocalTransportFactory
{
    ITransportCarrier CreateDialer(
        NodeEndpointRegistration endpoint,
        TransportEndpointRole localRole);

    ITransportConnectionAcceptor CreateAcceptor(
        NodeEndpointRegistration endpoint,
        TransportEndpointRole localRole);
}

public sealed class LocalDirectTransportFactory(
    ValidatedLocalStackOptions options) : ILocalTransportFactory
{
    public ITransportCarrier CreateDialer(
        NodeEndpointRegistration endpoint,
        TransportEndpointRole localRole)
    {
        var binding = ReadBinding(endpoint);
        return new DirectWebSocketCarrier(
            CreateOptions(endpoint, binding, localRole));
    }

    public ITransportConnectionAcceptor CreateAcceptor(
        NodeEndpointRegistration endpoint,
        TransportEndpointRole localRole)
    {
        var binding = ReadBinding(endpoint);
        return new DirectWebSocketConnectionAcceptor(
            CreateOptions(endpoint, binding, localRole));
    }

    private DirectWebSocketOptions CreateOptions(
        NodeEndpointRegistration endpoint,
        LocalDirectTransportBinding binding,
        TransportEndpointRole localRole)
    {
        if (!options.TransportEnabled ||
            options.TransportPrivateKeyPemPath is null)
            throw new InvalidOperationException(
                "Local direct transport is not enabled.");
        ECDsa? signingKey = ECDsa.Create();
        try
        {
            signingKey.ImportFromPem(
                File.ReadAllText(options.TransportPrivateKeyPemPath));
            var local = new EcdsaEndpointSigningKey(
                options.TransportIdentity, signingKey);
            signingKey = null;

            using var peerKey = ECDsa.Create();
            peerKey.ImportFromPem(
                File.ReadAllText(endpoint.PeerPublicKeyReference));
            return new(
                binding.Endpoint,
                localRole,
                local,
                new ExpectedPeerIdentity(
                    endpoint.PeerIdentity,
                    peerKey.ExportSubjectPublicKeyInfo()),
                AllowUnencryptedLoopback:
                    binding.Endpoint.Scheme == Uri.UriSchemeWs &&
                    binding.Endpoint.IsLoopback,
                MaximumWireFrameBytes:
                    options.MaximumTransportPayloadBytes + 4096,
                MaximumBufferedFrames: options.MaximumBufferedFrames);
        }
        catch
        {
            signingKey?.Dispose();
            throw;
        }
    }

    private static LocalDirectTransportBinding ReadBinding(
        NodeEndpointRegistration endpoint)
    {
        endpoint.Validate();
        if (endpoint.Transport.Kind != LocalStackOptions.TransportKind ||
            endpoint.Transport.Version != LocalStackOptions.TransportVersion)
            throw new InvalidOperationException(
                "The Node endpoint is not a Local Stack direct transport binding.");
        return endpoint.Transport
            .DeserializeData<LocalDirectTransportBinding>()
            ?.Validate()
            ?? throw new InvalidDataException(
                "The Local Stack direct transport binding is invalid.");
    }
}
