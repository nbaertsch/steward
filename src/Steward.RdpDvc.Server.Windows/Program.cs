using System.Security.Cryptography;
using System.ComponentModel;
using System.Text.Json;
using Steward.Domain;
using Steward.Node.Host;
using Steward.PortableState;
using Steward.Stack.Local;
using Steward.Transport;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.Server.Windows;

internal static class Program
{
    internal const string BootstrapEnvelopeMarker =
        "STEWARD_RDP_DVC_BOOTSTRAP_ENVELOPE:";

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 0 &&
            args[0] == "--generate-bootstrap-secrets")
            return GenerateBootstrapSecrets(args[1..]);
        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        byte[]? key = null;
        ServerOptions? options = null;
        var stage = "options";
        try
        {
            options = ServerOptions.Parse(args);
            stage = "authentication-key";
            key = await File.ReadAllBytesAsync(
                    options.AuthenticationKeyFile,
                    cancellation.Token)
                .ConfigureAwait(false);
            if (key.Length is < 32 or > 64)
                throw new InvalidDataException(
                    "The DVC authentication key length is invalid.");

            stage = "nonce-state";
            var nonces = new DvcConnectionNonceSequenceStore(
                options.NonceSequenceFile);
            var sequence = await nonces.InspectAsync(
                    options.SessionId,
                    options.HostId,
                    options.NodeIncarnationId,
                    cancellation.Token)
                .ConfigureAwait(false);
            var readiness = new DvcEndpointReadinessStore(
                options.ReadinessReceiptFile,
                options.SessionId,
                options.HostId,
                options.NodeIncarnationId,
                sequence.Nonces);
            stage = "readiness-state";
            var previous = await readiness.LoadAsync(cancellation.Token)
                .ConfigureAwait(false);
            var authenticated = previous?.AuthenticatedGenerations.ToList()
                ?? [];
            if (authenticated.Count == sequence.NextIndex + 1)
            {
                var interrupted = authenticated[^1];
                if (interrupted.Index != sequence.NextIndex ||
                    interrupted.Nonce !=
                        sequence.Nonces[sequence.NextIndex])
                    throw new InvalidDataException(
                        "Interrupted DVC nonce commit cannot be reconciled.");
                await nonces.CommitAsync(
                        options.SessionId,
                        options.HostId,
                        options.NodeIncarnationId,
                        new(interrupted.Index, interrupted.Nonce),
                        cancellation.Token)
                    .ConfigureAwait(false);
                sequence = await nonces.InspectAsync(
                        options.SessionId,
                        options.HostId,
                        options.NodeIncarnationId,
                        cancellation.Token)
                    .ConfigureAwait(false);
            }
            if (authenticated.Count != sequence.NextIndex)
            {
                await readiness.WriteAsync(
                        DvcEndpointReadinessState.Exhausted,
                        authenticated,
                        sequence.NextIndex,
                        cancellation.Token)
                    .ConfigureAwait(false);
                return 0;
            }

            if (authenticated.Count == sequence.Nonces.Count)
            {
                await readiness.WriteAsync(
                        DvcEndpointReadinessState.Completed,
                        authenticated,
                        sequence.Nonces.Count,
                        cancellation.Token)
                    .ConfigureAwait(false);
                return 0;
            }
            await readiness.WriteAsync(
                    authenticated.Count == 0
                        ? DvcEndpointReadinessState.WaitingForActiveRdpSession
                        : DvcEndpointReadinessState.WaitingForReconnect,
                    authenticated,
                    nextGeneration: authenticated.Count,
                    cancellation.Token)
                .ConfigureAwait(false);

            // Build the production Node runtime if node-host mode is configured.
            ProductionNodeRuntime? runtime = null;
            if (options.NodeHostConfigFile is not null)
            {
                stage = "node-runtime";
                runtime = await CreateNodeRuntimeAsync(
                        options, cancellation.Token)
                    .ConfigureAwait(false);
            }

            stage = "channel-open";
            Action<RdpDvcEndpointEvent>? events = null;
            var wts = new WtsRdpDvcWireChannelSource(onEvent: events);
            await using var source =
                new RdpDvcReconnectingWireChannelSource(
                    wts,
                    onEvent: events);
            try
            {
            while (!cancellation.IsCancellationRequested &&
                   authenticated.Count < sequence.Nonces.Count)
            {
                await readiness.WriteAsync(
                        authenticated.Count == 0
                            ? DvcEndpointReadinessState
                                .WaitingForActiveRdpSession
                            : DvcEndpointReadinessState.WaitingForReconnect,
                        authenticated,
                        authenticated.Count,
                        cancellation.Token)
                    .ConfigureAwait(false);
                var wire = await source.OpenChannelAsync(
                        cancellation.Token)
                    .ConfigureAwait(false);
                stage = "handshake";
                var generation = await nonces.PeekNextAsync(
                        options.SessionId,
                        options.HostId,
                        options.NodeIncarnationId,
                        cancellation.Token)
                    .ConfigureAwait(false);
                await readiness.WriteAsync(
                        DvcEndpointReadinessState.Handshaking,
                        authenticated,
                        generation.Index,
                        cancellation.Token)
                    .ConfigureAwait(false);
                var peer = new RdpDvcPeerIdentity(
                    options.SessionId,
                    options.HostId,
                    options.NodeIncarnationId,
                    RdpSessionId: null,
                    ConnectionNonce: generation.Nonce);
                var authentication = new RdpDvcAuthenticationOptions(
                    peer,
                    key,
                    HandshakeTimeout: options.Timeout,
                    OperationTimeout: options.Timeout);
                await using var connected =
                    await RdpDvcStreamHandshake.InitiateAsync(
                            wire,
                            authentication,
                            cancellation.Token)
                        .ConfigureAwait(false);
                ITransportConnection? secureConnection = null;
                SecureStreamCarrier? secureCarrier = null;
                if (options.NodeSigningKeyFile is not null)
                {
                    stage = "secure-handshake";
                    var privateKey = await File.ReadAllBytesAsync(
                            options.NodeSigningKeyFile,
                            cancellation.Token)
                        .ConfigureAwait(false);
                    var controlPublicKey = await File.ReadAllBytesAsync(
                            options.ControlSigningKeyFile!,
                            cancellation.Token)
                        .ConfigureAwait(false);
                    try
                    {
                        var ecdsa = ECDsa.Create();
                        ecdsa.ImportPkcs8PrivateKey(privateKey, out var read);
                        if (read != privateKey.Length)
                        {
                            ecdsa.Dispose();
                            throw new CryptographicException(
                                "The node signing key contains trailing data.");
                        }
                        var hello = runtime is not null
                            ? await runtime.CreateSessionHelloAsync(
                                options.SessionId,
                                new HashSet<string>(StringComparer.Ordinal)
                                {
                                    "rdp-dvc-secure", "orchestration-v1",
                                    "reconciliation-v1", "resume-cursors-v1"
                                },
                                new HashSet<string>(StringComparer.Ordinal)
                                {
                                    "orchestration-v1"
                                },
                                new(64 * 1024, 8),
                                cancellation.Token).ConfigureAwait(false)
                            : CreateHello(options);
                        secureCarrier = new(
                            new SingleStreamConnector(connected.Stream),
                            new(
                                TransportEndpointRole.Node,
                                new EcdsaEndpointSigningKey(
                                    options.NodeIdentity!,
                                    ecdsa),
                                new(
                                    options.ControlIdentity!,
                                    controlPublicKey),
                                HandshakeTimeout: options.Timeout,
                                OperationTimeout: options.Timeout));
                        secureConnection = await secureCarrier.ConnectAsync(
                                hello,
                                cancellation.Token)
                            .ConfigureAwait(false);
                        if (!secureConnection.Session.Security.IsSecure)
                            throw new CryptographicException(
                                "The signed secure transport was not established.");
                        DvcSessionValidator.ValidateSessionBinding(
                            secureConnection.Session,
                            options.SessionId,
                            new NodeIncarnationId(options.NodeIncarnationId),
                            options.NodeIdentity!,
                            options.ControlIdentity!);
                        stage = "connected";
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(privateKey);
                        CryptographicOperations.ZeroMemory(controlPublicKey);
                    }
                }
                authenticated.Add(new(
                    generation.Index,
                    connected.Handshake.Nonce,
                    connected.Handshake.RdpSessionId,
                    connected.Handshake.Sequence,
                    DateTimeOffset.UtcNow));
                await readiness.WriteAsync(
                        authenticated.Count == sequence.Nonces.Count
                            ? DvcEndpointReadinessState.Completed
                            : DvcEndpointReadinessState
                                .AuthenticatedGeneration,
                        authenticated,
                        authenticated.Count,
                        cancellation.Token)
                    .ConfigureAwait(false);
                await nonces.CommitAsync(
                        options.SessionId,
                        options.HostId,
                        options.NodeIncarnationId,
                        generation,
                        cancellation.Token)
                    .ConfigureAwait(false);
                if (options.Once)
                {
                    if (secureConnection is not null)
                        await secureConnection.DisposeAsync()
                            .ConfigureAwait(false);
                    if (secureCarrier is not null)
                        await secureCarrier.DisposeAsync()
                            .ConfigureAwait(false);
                    return 0;
                }
                try
                {
                    if (runtime is not null && secureConnection is not null)
                    {
                        stage = "node-session";
                        await runtime.RunSessionAsync(
                                secureConnection, cancellation.Token)
                            .ConfigureAwait(false);
                    }
                    else if (secureConnection is not null)
                    {
                        await foreach (var _ in secureConnection.ReceiveAsync(
                                           cancellation.Token)
                                           .ConfigureAwait(false))
                        {
                        }
                    }
                    else
                    {
                        var probe = new byte[256];
                        while (await connected.Stream.ReadAsync(
                                   probe,
                                   cancellation.Token)
                               .ConfigureAwait(false) != 0)
                        {
                        }
                    }
                }
                catch (Exception exception)
                    when (DvcDisconnectClassifier.IsExpected(exception))
                {
                }
                finally
                {
                    if (secureConnection is not null)
                        await secureConnection.DisposeAsync()
                            .ConfigureAwait(false);
                    if (secureCarrier is not null)
                        await secureCarrier.DisposeAsync()
                            .ConfigureAwait(false);
                }
            }
            }
            finally
            {
                if (runtime is not null)
                    await runtime.DisposeAsync().ConfigureAwait(false);
            }
            await readiness.WriteAsync(
                    DvcEndpointReadinessState.Completed,
                    authenticated,
                    authenticated.Count,
                    cancellation.Token)
                .ConfigureAwait(false);
            return 0;
        }
        catch (OperationCanceledException)
            when (cancellation.IsCancellationRequested)
        {
            return 130;
        }
        catch (Exception exception)
        {
            if (options is not null)
            {
                await File.WriteAllTextAsync(
                        options.ReadinessReceiptFile + ".failure",
                        exception is Win32Exception win32
                            ? $"{stage}:{exception.GetType().Name}:{win32.NativeErrorCode}"
                            : $"{stage}:{exception.GetType().Name}",
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }
            return 1;
        }
        finally
        {
            if (key is not null)
                CryptographicOperations.ZeroMemory(key);
        }
    }

    private static async Task<ProductionNodeRuntime> CreateNodeRuntimeAsync(
        ServerOptions options,
        CancellationToken cancellationToken)
    {
        var configJson = await File.ReadAllTextAsync(
                options.NodeHostConfigFile!, cancellationToken)
            .ConfigureAwait(false);
        var nodeHostOptions = JsonSerializer.Deserialize<NodeHostOptions>(
                configJson, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidDataException(
                "The node host configuration file is empty or invalid.");
        // Override host/incarnation from DVC endpoint identity to ensure consistency.
        nodeHostOptions.HostId = options.HostId.ToString();
        nodeHostOptions.NodeIncarnationId = options.NodeIncarnationId.ToString();
        var validated = nodeHostOptions.Validate();

        var portableMetadata = LocalStackOptions.PortableStateBinding(new
        {
            rootPath = options.PortableStateRoot!
        });
        var portableStore = new LocalStackContentAddressedObjectStore(
            portableMetadata);
        var portableTransfer = new LocalPortableTransferClient();

        return await ProductionNodeRuntime.CreateAsync(
                validated,
                options.CredentialVaultRoot!,
                portableStore,
                portableTransfer,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    private static int GenerateBootstrapSecrets(string[] arguments)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Length; index += 2)
        {
            if (index + 1 >= arguments.Length ||
                !values.TryAdd(arguments[index], arguments[index + 1]))
                throw new ArgumentException(
                    "Bootstrap secret arguments are invalid.");
        }
        var operation = RequiredGuid(values, "--operation-id");
        var session = RequiredGuid(values, "--session-id");
        var host = RequiredGuid(values, "--host-id");
        var incarnation = RequiredGuid(values, "--incarnation-id");
        var publicKeyPath = RequiredPath(
            values,
            "--encryption-public-key-file",
            mustExist: true);
        var authenticationPath = RequiredPath(
            values,
            "--auth-key-output",
            mustExist: false);
        var nodePrivatePath = RequiredPath(
            values,
            "--node-signing-key-output",
            mustExist: false);
        var encryptionPublic = File.ReadAllBytes(publicKeyPath);
        var authentication = RandomNumberGenerator.GetBytes(32);
        using var node = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var nodePrivate = node.ExportPkcs8PrivateKey();
        var nodePublic = node.ExportSubjectPublicKeyInfo();
        try
        {
            WriteNew(authenticationPath, authentication);
            WriteNew(nodePrivatePath, nodePrivate);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(
                encryptionPublic,
                out var read);
            if (read != encryptionPublic.Length)
                throw new CryptographicException(
                    "The envelope public key contains trailing data.");
            var ciphertext = RdpDvcBootstrapEnvelope.Encrypt(
                rsa,
                new(
                    operation,
                    session,
                    host,
                    incarnation,
                    authentication,
                    nodePublic));
            Console.WriteLine(
                BootstrapEnvelopeMarker +
                Convert.ToBase64String(ciphertext));
            CryptographicOperations.ZeroMemory(ciphertext);
            return 0;
        }

        finally
        {
            CryptographicOperations.ZeroMemory(encryptionPublic);
            CryptographicOperations.ZeroMemory(authentication);
            CryptographicOperations.ZeroMemory(nodePrivate);
            CryptographicOperations.ZeroMemory(nodePublic);
        }
    }

    private static void WriteNew(
        string path,
        ReadOnlySpan<byte> content)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough);
        stream.Write(content);
        stream.Flush(flushToDisk: true);
    }

    private static Guid RequiredGuid(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var text) &&
        Guid.TryParse(text, out var value) &&
        value != Guid.Empty
            ? value
            : throw new ArgumentException(
                $"Required bootstrap argument '{name}' is invalid.");

    private static string RequiredPath(
        IReadOnlyDictionary<string, string> values,
        string name,
        bool mustExist)
    {
        if (!values.TryGetValue(name, out var text) ||
            string.IsNullOrWhiteSpace(text))
            throw new ArgumentException(
                $"Required bootstrap argument '{name}' is missing.");
        var path = Path.GetFullPath(text);
        if (!Path.IsPathFullyQualified(path) ||
            mustExist && !File.Exists(path) ||
            File.Exists(path) &&
            File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new ArgumentException(
                $"Required bootstrap path '{name}' is invalid.");
        return path;
    }

    private static SessionHello CreateHello(ServerOptions options) =>
            new(
                options.SessionId,
                new NodeIncarnationId(options.NodeIncarnationId),
                1,
                0,
                new HashSet<string>(StringComparer.Ordinal)
                {
                    "rdp-dvc-secure"
                },
                new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<StreamKind, long>(),
                new(64 * 1024, 8));

}

internal static class DvcDisconnectClassifier
{
    internal static bool IsExpected(Exception exception) =>
        exception is EndOfStreamException or IOException or
            RdpDvcProtocolException ||
        exception is TransportProtocolException protocol &&
            protocol.Error != TransportError.SessionBindingMismatch ||
        exception is Win32Exception
        {
            NativeErrorCode: 12 or 233
        };
}

internal sealed class SingleStreamConnector(Stream stream) :
        ITransportStreamConnector
{
    private int used;

    public ValueTask<Stream> ConnectStreamAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Exchange(ref used, 1) != 0)
            throw new InvalidOperationException(
                "The DVC stream connector is single-use.");
        return ValueTask.FromResult(stream);
    }
}
