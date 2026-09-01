using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Transport;

namespace Steward.Transport.Rdp.Windows;

public enum RdpDvcEvidencePublicationEvent
{
    StewardComClassActivated = 1,
    StewardPluginInitialized = 2,
    StewardChannelOpened = 3,
    DvcHmacAuthenticated = 4,
    SecurePeerAuthenticated = 5
}

public sealed record RdpDvcEvidenceRoute(
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    int WtsSessionId,
    Guid ConnectionNonce,
    int ProtocolVersion = 2)
{
    public RdpDvcRetainedV1EndpointState? RetainedV1Endpoint
    { get; init; }

    public RdpDvcEvidenceRoute Validate()
    {
        if (SessionId == Guid.Empty ||
            HostId == Guid.Empty ||
            NodeIncarnationId == Guid.Empty ||
            WtsSessionId < 0 ||
            ConnectionNonce == Guid.Empty ||
            ProtocolVersion is not (1 or 2) ||
            ProtocolVersion == 2 && RetainedV1Endpoint is not null)
            throw new ArgumentException(
                "The DVC evidence route is invalid.");
        _ = RetainedV1Endpoint?.Validate();
        return this;
    }

    public RdpDvcEvidenceRoute ValidateBound()
    {
        _ = Validate();
        if (WtsSessionId == 0)
            throw new ArgumentException(
                "The bound DVC evidence route requires a positive WTS session.");
        return this;
    }

    public bool IsWtsWildcard => WtsSessionId == 0;

    public bool HasSamePreauthorizedBase(
        RdpDvcEvidenceRoute other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return SessionId == other.SessionId &&
            HostId == other.HostId &&
            NodeIncarnationId == other.NodeIncarnationId &&
            ConnectionNonce == other.ConnectionNonce;
    }

    public bool MatchesAuthenticatedRoute(
        RdpDvcEvidenceRoute authenticated)
    {
        ArgumentNullException.ThrowIfNull(authenticated);
        _ = Validate();
        _ = authenticated.ValidateBound();
        return authenticated.ProtocolVersion == 2
            ? ProtocolVersion == 2 &&
              RetainedV1Endpoint is null &&
              authenticated.RetainedV1Endpoint is null &&
              SessionId == authenticated.SessionId &&
              HostId == authenticated.HostId &&
              NodeIncarnationId == authenticated.NodeIncarnationId
            : ProtocolVersion == 1 &&
              RetainedV1Endpoint ==
                authenticated.RetainedV1Endpoint &&
              HasSamePreauthorizedBase(authenticated) &&
              (IsWtsWildcard || this == authenticated);
    }
    public RdpDvcEvidenceRoute BindWtsSession(int wtsSessionId)
    {
        _ = Validate();
        if (wtsSessionId <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(wtsSessionId));
        return this with { WtsSessionId = wtsSessionId };
    }

    public RdpDvcEvidenceRoute AsPreauthorized() =>
        this with { WtsSessionId = 0 };

    public static RdpDvcEvidenceRoute From(
        RdpDvcHandshakeResult handshake) =>
        new RdpDvcEvidenceRoute(
            handshake.SessionId,
            handshake.HostId,
            handshake.NodeIncarnationId,
            handshake.RdpSessionId,
            handshake.Nonce,
            ProtocolVersion: 1).ValidateBound();

    internal static RdpDvcEvidenceRoute From(
        RdpDvcConnectionIdentity identity) =>
        new RdpDvcEvidenceRoute(
            identity.SessionId,
            identity.HostId,
            identity.NodeIncarnationId,
            identity.RdpSessionId,
            identity.IsReconnectV2
                ? identity.AttemptId
                : identity.ConnectionNonce,
            identity.IsReconnectV2 ? 2 : 1).ValidateBound();
    public override string ToString() =>
        "RdpDvcEvidenceRoute { Redacted }";
}

public sealed record RdpDvcEvidenceTicketIdentity(
    string EvidenceReference,
    string ConnectionId,
    string RuntimeConnectionId,
    long ConnectionGeneration,
    RdpDvcEvidenceRoute Route)
{
    public RdpDvcEvidenceTicketIdentity Validate()
    {
        RdpDvcEvidenceValidation.RequireIdentifier(
            EvidenceReference,
            128,
            nameof(EvidenceReference));
        RdpDvcEvidenceValidation.RequireIdentifier(
            ConnectionId,
            128,
            nameof(ConnectionId));
        RdpDvcEvidenceValidation.RequireIdentifier(
            RuntimeConnectionId,
            128,
            nameof(RuntimeConnectionId));
        if (ConnectionGeneration <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(ConnectionGeneration));
        _ = Route.Validate();
        return this;
    }

    public override string ToString() =>
        $"RdpDvcEvidenceTicketIdentity {{ Generation = " +
        $"{ConnectionGeneration}, Route = [REDACTED] }}";
}

public sealed record RdpDvcEvidencePublication(
    Guid ReporterId,
    long Sequence,
    long SentAtUtcTicks,
    RdpDvcEvidencePublicationEvent Event,
    RdpDvcEvidenceTicketIdentity? Ticket = null,
    RdpDvcEvidenceRoute? CandidateRoute = null)
{
    public RdpDvcEvidencePublication Validate()
    {
        if (ReporterId == Guid.Empty ||
            Sequence <= 0 ||
            SentAtUtcTicks <= 0 ||
            !Enum.IsDefined(Event))
            throw new ArgumentException(
                "The DVC evidence publication is invalid.");
        _ = Ticket?.Validate();
        _ = CandidateRoute?.Validate();
        return this;
    }

    public override string ToString() =>
        $"RdpDvcEvidencePublication {{ Event = {Event}, " +
        $"Sequence = {Sequence}, Payload = [REDACTED] }}";
}

public sealed record RdpDvcEvidencePublicationResult(
    bool Accepted,
    string Code);

public static class RdpDvcEvidenceIpcProtocol
{
    public const int MaximumFrameBytes = 16 * 1024;
    public const int AuthenticationTagBytes = 32;
    private static readonly JsonSerializerOptions JsonOptions =
        CreateOptions();

    public static byte[] Encode(
        RdpDvcEvidencePublication publication,
        ReadOnlySpan<byte> authenticationKey)
    {
        _ = publication.Validate();
        ValidateKey(authenticationKey);
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            publication,
            JsonOptions);
        if (payload.Length <= 0 ||
            payload.Length >
            MaximumFrameBytes - AuthenticationTagBytes)
            throw new InvalidDataException(
                "The DVC evidence publication exceeds its bound.");
        var frame = new byte[payload.Length + AuthenticationTagBytes];
        payload.CopyTo(frame, 0);
        HMACSHA256.HashData(
            authenticationKey,
            payload,
            frame.AsSpan(payload.Length));
        return frame;
    }

    public static RdpDvcEvidencePublication Decode(
        ReadOnlySpan<byte> frame,
        ReadOnlySpan<byte> authenticationKey)
    {
        ValidateKey(authenticationKey);
        if (frame.Length <= AuthenticationTagBytes ||
            frame.Length > MaximumFrameBytes)
            throw new InvalidDataException(
                "The DVC evidence publication frame is invalid.");
        var payload = frame[..^AuthenticationTagBytes];
        Span<byte> expected = stackalloc byte[AuthenticationTagBytes];
        HMACSHA256.HashData(authenticationKey, payload, expected);
        if (!CryptographicOperations.FixedTimeEquals(
                expected,
                frame[^AuthenticationTagBytes..]))
            throw new UnauthorizedAccessException(
                "The DVC evidence publication authentication failed.");
        return (JsonSerializer.Deserialize<RdpDvcEvidencePublication>(
                    payload,
                    JsonOptions) ??
                throw new InvalidDataException(
                    "The DVC evidence publication was empty."))
            .Validate();
    }

    public static async ValueTask WriteFrameAsync(
        Stream stream,
        ReadOnlyMemory<byte> frame,
        CancellationToken cancellationToken)
    {
        if (frame.Length <= 0 || frame.Length > MaximumFrameBytes)
            throw new InvalidDataException(
                "The DVC evidence publication frame is invalid.");
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(
            header,
            frame.Length);
        await stream.WriteAsync(header, cancellationToken)
            .ConfigureAwait(false);
        await stream.WriteAsync(frame, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public static async ValueTask<byte[]> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken)
            .ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaximumFrameBytes)
            throw new InvalidDataException(
                "The DVC evidence publication frame is invalid.");
        var frame = new byte[length];
        await stream.ReadExactlyAsync(frame, cancellationToken)
            .ConfigureAwait(false);
        return frame;
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC evidence publication key must contain 32 through 64 bytes.");
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}

public static class CurrentUserProtectedDataFile
{
    private const int MaximumProtectedBytes = 64 * 1024;

    public static byte[] Read(
        string path,
        string purpose)
    {
        ValidatePurpose(purpose);
        var fullPath = ValidateExistingFile(path);
        var protectedValue = File.ReadAllBytes(fullPath);
        if (protectedValue.Length is <= 0 or > MaximumProtectedBytes)
            throw new InvalidDataException(
                "The protected current-user file has an invalid size.");
        try
        {
            return ProtectedData.Unprotect(
                protectedValue,
                Encoding.UTF8.GetBytes(purpose),
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedValue);
        }
    }

    public static void Write(
        string path,
        string purpose,
        ReadOnlySpan<byte> cleartext)
    {
        ValidatePurpose(purpose);
        if (cleartext.IsEmpty ||
            cleartext.Length > MaximumProtectedBytes / 2)
            throw new ArgumentException(
                "The current-user protected value is invalid.",
                nameof(cleartext));
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new ArgumentException(
                "The protected current-user path must be absolute.",
                nameof(path));
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath) ??
            throw new ArgumentException(
                "The protected current-user path has no directory.",
                nameof(path));
        EnsureNoReparseSegments(directory);
        PrepareDirectory(directory);
        if (File.Exists(fullPath))
            throw new IOException(
                "The protected current-user file already exists.");
        var cleartextCopy = cleartext.ToArray();
        var protectedValue = ProtectedData.Protect(
            cleartextCopy,
            Encoding.UTF8.GetBytes(purpose),
            DataProtectionScope.CurrentUser);
        try
        {
            File.WriteAllBytes(fullPath, protectedValue);
            RestrictFile(fullPath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartextCopy);
            CryptographicOperations.ZeroMemory(protectedValue);
        }
    }

    public static void Delete(string path)
    {
        var fullPath = ValidateExistingFile(path);
        File.Delete(fullPath);
    }

    public static void Replace(
        string path,
        string purpose,
        ReadOnlySpan<byte> cleartext)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new ArgumentException(
                "The protected current-user path must be absolute.",
                nameof(path));
        var fullPath = ValidateExistingFile(path);
        var directory = Path.GetDirectoryName(fullPath) ??
            throw new ArgumentException(
                "The protected current-user path has no directory.",
                nameof(path));
        var replacement = Path.Combine(
            directory,
            $".{Path.GetFileName(path)}." +
            $"{RandomNumberGenerator.GetHexString(16)}.new");
        try
        {
            Write(replacement, purpose, cleartext);
            _ = ValidateExistingFile(fullPath);
            File.Move(replacement, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(replacement))
                File.Delete(replacement);
        }
    }

    private static string ValidateExistingFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new ArgumentException(
                "The protected current-user path must be absolute.",
                nameof(path));
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath) ??
            throw new ArgumentException(
                "The protected current-user path has no directory.",
                nameof(path));
        EnsureNoReparseSegments(directory);
        if (!File.Exists(fullPath) ||
            File.GetAttributes(fullPath)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new FileNotFoundException(
                "The protected current-user file is unavailable.",
                fullPath);
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new FileInfo(fullPath).GetAccessControl();
        if (!current.Equals(
                security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException(
                "The protected current-user file owner is invalid.");
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                !current.Equals(rule.IdentityReference))
                throw new UnauthorizedAccessException(
                    "The protected current-user file grants another principal access.");
        }
        return fullPath;
    }

    private static void PrepareDirectory(string directory)
    {
        Directory.CreateDirectory(directory);
        if (File.GetAttributes(directory)
            .HasFlag(FileAttributes.ReparsePoint))
            throw new IOException(
                "The protected current-user directory is unsafe.");
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new DirectorySecurity();
        security.SetOwner(current);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new(
            current,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    private static void EnsureNoReparseSegments(string directory)
    {
        var fullPath = Path.GetFullPath(directory);
        var root = Path.GetPathRoot(fullPath) ??
            throw new IOException(
                "The protected current-user path has no root.");
        var current = root;
        foreach (var segment in fullPath[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (Directory.Exists(current) &&
                File.GetAttributes(current)
                    .HasFlag(FileAttributes.ReparsePoint))
                throw new IOException(
                    "The protected current-user path cannot traverse reparse points.");
        }
    }

    private static void RestrictFile(string path)
    {
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new FileSecurity();
        security.SetOwner(current);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static void ValidatePurpose(string purpose)
    {
        if (string.IsNullOrWhiteSpace(purpose) ||
            purpose.Length > 128)
            throw new ArgumentException(
                "The protected current-user purpose is invalid.",
                nameof(purpose));
    }
}

public sealed class AuthenticatedRdpDvcEvidencePublisher :
    IAsyncDisposable
{
    public const string KeyFilePurpose =
        "Steward.RdpDvc.Evidence.PublicationKey.v1";
    private readonly string pipeName;
    private readonly byte[] key;
    private readonly TimeSpan timeout;
    private int disposed;

    public AuthenticatedRdpDvcEvidencePublisher(
        string pipeName,
        ReadOnlySpan<byte> authenticationKey,
        TimeSpan? timeout = null)
    {
        RdpDvcEvidenceValidation.RequirePipeName(pipeName);
        if (authenticationKey.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC evidence publication key must contain 32 through 64 bytes.",
                nameof(authenticationKey));
        this.pipeName = pipeName;
        key = authenticationKey.ToArray();
        this.timeout = timeout ?? TimeSpan.FromSeconds(5);
        if (this.timeout <= TimeSpan.Zero ||
            this.timeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    public static AuthenticatedRdpDvcEvidencePublisher FromProtectedFile(
        string pipeName,
        string keyFile,
        TimeSpan? timeout = null)
    {
        var key = CurrentUserProtectedDataFile.Read(
            keyFile,
            KeyFilePurpose);
        try
        {
            return new(pipeName, key, timeout);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public RdpDvcEvidencePublisherSession CreateLifecycleSession() =>
        new(this, null);

    public RdpDvcEvidencePublisherSession CreateTransportSession(
        RdpDvcEvidenceTicketIdentity ticket) =>
        new(this, ticket.Validate());

    internal async ValueTask PublishAsync(
        RdpDvcEvidencePublication publication,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref disposed) != 0,
            this);
        var frame = RdpDvcEvidenceIpcProtocol.Encode(publication, key);
        using var deadline =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        deadline.CancelAfter(timeout);
        await using var pipe = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync(deadline.Token)
                .ConfigureAwait(false);
            await RdpDvcEvidenceIpcProtocol.WriteFrameAsync(
                    pipe,
                    frame,
                    deadline.Token)
                .ConfigureAwait(false);
            var response = new byte[1];
            await pipe.ReadExactlyAsync(response, deadline.Token)
                .ConfigureAwait(false);
            if (response[0] != 1)
                throw new InvalidDataException(
                    "The DVC evidence publication was rejected.");
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The DVC evidence publication timed out.");
        }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            CryptographicOperations.ZeroMemory(key);
        return ValueTask.CompletedTask;
    }
}

public sealed class RdpDvcEvidencePublisherSession
{
    private readonly AuthenticatedRdpDvcEvidencePublisher publisher;
    private RdpDvcEvidenceTicketIdentity? ticket;
    private readonly Guid reporterId = Guid.NewGuid();
    private readonly SemaphoreSlim gate = new(1, 1);
    private long sequence;

    internal RdpDvcEvidencePublisherSession(
        AuthenticatedRdpDvcEvidencePublisher publisher,
        RdpDvcEvidenceTicketIdentity? ticket)
    {
        this.publisher = publisher;
        this.ticket = ticket;
    }

    public async ValueTask PublishAsync(
        RdpDvcEvidencePublicationEvent evidenceEvent,
        RdpDvcEvidenceRoute? candidateRoute = null,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var next = checked(sequence + 1);
            await publisher.PublishAsync(
                    new(
                        reporterId,
                        next,
                        DateTimeOffset.UtcNow.UtcTicks,
                        evidenceEvent,
                        ticket,
                        candidateRoute),
                    cancellationToken)
                .ConfigureAwait(false);
            sequence = next;
        }
        finally
        {
            gate.Release();
        }
    }

    public void BindAuthenticatedReconnectRoute(
        RdpDvcEvidenceRoute authenticatedRoute)
    {
        var bound = authenticatedRoute.ValidateBound();
        if (bound.ProtocolVersion != 2)
            throw new InvalidOperationException(
                "Reconnect evidence requires protocol version two.");
        gate.Wait();
        try
        {
            if (ticket is not { } current)
                throw new InvalidOperationException(
                    "A lifecycle evidence publisher cannot bind a transport route.");
            if (!current.Route.MatchesAuthenticatedRoute(bound))
                throw new InvalidOperationException(
                    "The authenticated reconnect route differs from its preauthorized ticket.");
            ticket = current with { Route = bound };
        }
        finally
        {
            gate.Release();
        }
    }
    public void BindAuthenticatedRoute(
        RdpDvcEvidenceRoute authenticatedRoute)
    {
        var bound = authenticatedRoute.ValidateBound();
        gate.Wait();
        try
        {
            if (ticket is not { } current)
                throw new InvalidOperationException(
                    "A lifecycle evidence publisher cannot bind a transport route.");
            if (!current.Route.HasSamePreauthorizedBase(bound) ||
                !current.Route.IsWtsWildcard &&
                current.Route != bound)
                throw new InvalidOperationException(
                    "The authenticated DVC route differs from its preauthorized ticket.");
            ticket = current with { Route = bound };
        }
        finally
        {
            gate.Release();
        }
    }
}

public sealed class RdpDvcEvidencePublishingCarrier :
    ITransportCarrier,
    IAsyncDisposable
{
    private readonly SecureStreamCarrier inner;
    private readonly RdpDvcEvidencePublisherSession publisher;
    private readonly RdpDvcEvidenceRoute preauthorizedRoute;

    public RdpDvcEvidencePublishingCarrier(
        IRdpDvcWireChannelSource source,
        RdpDvcAuthenticationOptions dvcAuthentication,
        SecureStreamTransportOptions secureTransport,
        AuthenticatedRdpDvcEvidencePublisher evidencePublisher,
        RdpDvcEvidenceTicketIdentity ticket)
    {
        publisher = evidencePublisher.CreateTransportSession(ticket);
        preauthorizedRoute = ticket.Route.Validate();
        inner = new(
            new PublishingConnector(
                source,
                dvcAuthentication,
                publisher,
                preauthorizedRoute),
            secureTransport);
    }

    public async ValueTask<ITransportConnection> ConnectAsync(
        SessionHello hello,
        CancellationToken cancellationToken = default)
    {
        var connection = await inner.ConnectAsync(
                hello,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (!connection.Session.Security.IsSecure)
                throw new CryptographicException(
                    "The Steward secure peer was not mutually authenticated.");
            await publisher.PublishAsync(
                    RdpDvcEvidencePublicationEvent
                        .SecurePeerAuthenticated,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public ValueTask DisposeAsync() => inner.DisposeAsync();

    private sealed class PublishingConnector(
        IRdpDvcWireChannelSource source,
        RdpDvcAuthenticationOptions options,
        RdpDvcEvidencePublisherSession publisher,
        RdpDvcEvidenceRoute preauthorizedRoute) :
        ITransportStreamConnector
    {
        public async ValueTask<Stream> ConnectStreamAsync(
            CancellationToken cancellationToken = default)
        {
            var wire = await source.OpenChannelAsync(cancellationToken)
                .ConfigureAwait(false);
            var connected = await RdpDvcStreamHandshake.InitiateAsync(
                    wire,
                    options,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                var authenticatedRoute =
                    RdpDvcEvidenceRoute.From(connected.Handshake);
                if (!preauthorizedRoute.HasSamePreauthorizedBase(
                        authenticatedRoute) ||
                    !preauthorizedRoute.IsWtsWildcard &&
                    preauthorizedRoute != authenticatedRoute)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.BindingMismatch,
                        "The authenticated DVC route differs from its evidence ticket.");
                publisher.BindAuthenticatedRoute(authenticatedRoute);
                await publisher.PublishAsync(
                        RdpDvcEvidencePublicationEvent
                            .DvcHmacAuthenticated,
                        cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                return connected.Stream;
            }
            catch
            {
                await connected.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}

public sealed class RdpDvcEvidencePublishingConnectionAcceptor :
    ITransportConnectionAcceptor,
    IAsyncDisposable
{
    private readonly SecureStreamConnectionAcceptor inner;
    private readonly RdpDvcEvidencePublisherSession publisher;
    private readonly RdpDvcEvidenceRoute preauthorizedRoute;

    public RdpDvcEvidencePublishingConnectionAcceptor(
        IRdpDvcWireChannelSource source,
        RdpDvcAuthenticationOptions dvcAuthentication,
        SecureStreamTransportOptions secureTransport,
        AuthenticatedRdpDvcEvidencePublisher evidencePublisher,
        RdpDvcEvidenceTicketIdentity ticket)
    {
        publisher = evidencePublisher.CreateTransportSession(ticket);
        preauthorizedRoute = ticket.Route.Validate();
        inner = new(
            new PublishingAcceptor(
                source,
                dvcAuthentication,
                publisher,
                preauthorizedRoute),
            secureTransport);
    }

    public async ValueTask<ITransportConnection> AcceptAsync(
        SessionHello hello,
        CancellationToken cancellationToken = default)
    {
        var connection = await inner.AcceptAsync(
                hello,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (!connection.Session.Security.IsSecure)
                throw new CryptographicException(
                    "The Steward secure peer was not mutually authenticated.");
            await publisher.PublishAsync(
                    RdpDvcEvidencePublicationEvent
                        .SecurePeerAuthenticated,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public ValueTask DisposeAsync() => inner.DisposeAsync();

    private sealed class PublishingAcceptor(
        IRdpDvcWireChannelSource source,
        RdpDvcAuthenticationOptions options,
        RdpDvcEvidencePublisherSession publisher,
        RdpDvcEvidenceRoute preauthorizedRoute) :
        ITransportStreamAcceptor
    {
        public async ValueTask<Stream> AcceptStreamAsync(
            CancellationToken cancellationToken = default)
        {
            var wire = await source.OpenChannelAsync(cancellationToken)
                .ConfigureAwait(false);
            var connected = await RdpDvcStreamHandshake.RespondAsync(
                    wire,
                    options,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                var authenticatedRoute =
                    RdpDvcEvidenceRoute.From(connected.Handshake);
                if (!preauthorizedRoute.HasSamePreauthorizedBase(
                        authenticatedRoute) ||
                    !preauthorizedRoute.IsWtsWildcard &&
                    preauthorizedRoute != authenticatedRoute)
                    throw new RdpDvcProtocolException(
                        RdpDvcProtocolError.BindingMismatch,
                        "The authenticated DVC route differs from its evidence ticket.");
                publisher.BindAuthenticatedRoute(authenticatedRoute);
                await publisher.PublishAsync(
                        RdpDvcEvidencePublicationEvent
                            .DvcHmacAuthenticated,
                        cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                return connected.Stream;
            }
            catch
            {
                await connected.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}

internal static class RdpDvcEvidenceValidation
{
    internal static void RequireIdentifier(
        string value,
        int maximum,
        string parameter)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximum ||
            value.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new ArgumentException(
                "The DVC evidence identifier is invalid.",
                parameter);
    }

    internal static void RequirePipeName(string pipeName)
    {
        RequireIdentifier(pipeName, 128, nameof(pipeName));
    }
}
