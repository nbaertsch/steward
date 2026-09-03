using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public interface IRdpDvcEvidenceTicketResolver
{
    ValueTask<RdpDvcEvidenceRoute> ResolveAsync(
        string evidenceReference,
        CancellationToken cancellationToken);
}

public interface IRdpDvcEvidenceTicketBindingStore :
    IRdpDvcEvidenceTicketResolver
{
    ValueTask BindAsync(
        RdpDvcEvidenceTicketIdentity identity,
        CancellationToken cancellationToken);

    void BindWtsSession(
        RdpDvcEvidenceTicketIdentity identity);

    ValueTask ReleaseAsync(
        string evidenceReference);
}

public sealed class DpapiRdpDvcEvidenceTicketStore :
    IRdpDvcEvidenceTicketBindingStore
{
    public const string TicketFilePurpose =
        "Steward.RdpDvc.Evidence.Ticket.v1";
    private readonly string directory;

    public DpapiRdpDvcEvidenceTicketStore(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) ||
            !Path.IsPathFullyQualified(directory))
            throw new ArgumentException(
                "The DVC evidence ticket directory must be absolute.",
                nameof(directory));
        this.directory = Path.GetFullPath(directory);
        if (!Directory.Exists(this.directory) ||
            File.GetAttributes(this.directory)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new DirectoryNotFoundException(
                "The DVC evidence ticket directory is unavailable.");
    }

    public ValueTask<RdpDvcEvidenceRoute> ResolveAsync(
        string evidenceReference,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateReference(evidenceReference);
        var cleartext = CurrentUserProtectedDataFile.Read(
            Path.Combine(directory, evidenceReference + ".ticket"),
            TicketFilePurpose);
        try
        {
            var descriptor =
                JsonSerializer.Deserialize<TicketDescriptor>(cleartext) ??
                throw new InvalidDataException(
                    "The DVC evidence ticket descriptor is empty.");
            var route = ValidateCarrierAuthorization(
                descriptor.Route);
            if (!route.IsWtsWildcard)
                throw new InvalidDataException(
                    "The preauthorized DVC evidence ticket must leave WTS unspecified.");
            return ValueTask.FromResult(route);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
        }
    }

    public void Write(
        string evidenceReference,
        RdpDvcEvidenceRoute route)
    {
        ValidateReference(evidenceReference);
        route = ValidateCarrierAuthorization(route);
        if (!route.IsWtsWildcard)
            throw new ArgumentException(
                "A preauthorized DVC evidence ticket must leave WTS unspecified.",
                nameof(route));
        var cleartext = JsonSerializer.SerializeToUtf8Bytes(
            new TicketDescriptor(route));
        try
        {
            CurrentUserProtectedDataFile.Write(
                Path.Combine(directory, evidenceReference + ".ticket"),
                TicketFilePurpose,
                cleartext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
        }
    }

    public ValueTask BindAsync(
        RdpDvcEvidenceTicketIdentity identity,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = identity.Validate();
        if (!identity.Route.IsWtsWildcard)
            throw new InvalidOperationException(
                "The initial DVC evidence binding must leave WTS unspecified.");
        var cleartext = JsonSerializer.SerializeToUtf8Bytes(identity);
        try
        {
            CurrentUserProtectedDataFile.Write(
                BoundPath(identity.EvidenceReference),
                TicketFilePurpose + ".Bound",
                cleartext);
            CurrentUserProtectedDataFile.Delete(
                Path.Combine(
                    directory,
                    identity.EvidenceReference + ".ticket"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
        }
        return ValueTask.CompletedTask;
    }

    public RdpDvcEvidenceTicketIdentity ReadBound(
        string evidenceReference)
    {
        ValidateReference(evidenceReference);
        var cleartext = CurrentUserProtectedDataFile.Read(
            BoundPath(evidenceReference),
            TicketFilePurpose + ".Bound");
        try
        {
            return (JsonSerializer.Deserialize<
                        RdpDvcEvidenceTicketIdentity>(cleartext) ??
                    throw new InvalidDataException(
                        "The bound DVC evidence ticket is empty."))
                .Validate();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
        }
    }

    public void BindWtsSession(
        RdpDvcEvidenceTicketIdentity identity)
    {
        var bound = identity.Validate();
        _ = bound.Route.ValidateBound();
        var current = ReadBound(identity.EvidenceReference);
        if (!current.Route.IsWtsWildcard ||
            !current.Route.MatchesAuthenticatedRoute(bound.Route) ||
            current.ConnectionId != bound.ConnectionId ||
            current.RuntimeConnectionId != bound.RuntimeConnectionId ||
            current.ConnectionGeneration != bound.ConnectionGeneration)
            throw new InvalidOperationException(
                "The bound DVC evidence ticket cannot change identity or WTS session.");
        var cleartext = JsonSerializer.SerializeToUtf8Bytes(bound);
        try
        {
            CurrentUserProtectedDataFile.Replace(
                BoundPath(identity.EvidenceReference),
                TicketFilePurpose + ".Bound",
                cleartext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
        }
    }

    public ValueTask ReleaseAsync(string evidenceReference)
    {
        ValidateReference(evidenceReference);
        foreach (var path in new[]
                 {
                     Path.Combine(
                         directory,
                         evidenceReference + ".ticket"),
                     BoundPath(evidenceReference)
                 })
            if (File.Exists(path))
                CurrentUserProtectedDataFile.Delete(path);
        return ValueTask.CompletedTask;
    }

    private static RdpDvcEvidenceRoute ValidateCarrierAuthorization(
        RdpDvcEvidenceRoute route)
    {
        ArgumentNullException.ThrowIfNull(route);
        try
        {
            _ = route.Validate();
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                "The DVC evidence route is invalid.",
                exception);
        }
        if (route.ProtocolVersion == 1 &&
            route.RetainedV1Endpoint is null)
            throw new InvalidDataException(
                "A v1 evidence route requires explicit retained endpoint state.");
        return route;
    }
    private string BoundPath(string evidenceReference) =>
        Path.Combine(directory, evidenceReference + ".bound");

    private static void ValidateReference(string evidenceReference)
    {
        if (string.IsNullOrWhiteSpace(evidenceReference) ||
            evidenceReference.Length is < 16 or >
                ConnectionHostProtocol.MaximumEvidenceReferenceCharacters ||
            evidenceReference.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not ('-' or '_')))
            throw new ArgumentException(
                "The DVC evidence reference is invalid.",
                nameof(evidenceReference));
    }

    private sealed record TicketDescriptor(
        RdpDvcEvidenceRoute Route);
}

public sealed class ProductionRdpDvcRuntimeEvidenceSource :
    IRdpDvcRuntimeEvidenceSource,
    IAsyncDisposable
{
    private static readonly RdpDvcEvidencePublicationEvent[] RequiredOrder =
    [
        RdpDvcEvidencePublicationEvent.StewardComClassActivated,
        RdpDvcEvidencePublicationEvent.StewardPluginInitialized,
        RdpDvcEvidencePublicationEvent.StewardChannelOpened,
        RdpDvcEvidencePublicationEvent.DvcHmacAuthenticated,
        RdpDvcEvidencePublicationEvent.SecurePeerAuthenticated
    ];
    private static readonly TimeSpan MaximumPublicationAge =
        TimeSpan.FromMinutes(5);
    private readonly IRdpDvcEvidenceTicketResolver resolver;
    private readonly string pipeName;
    private readonly byte[] key;
    private readonly Action<string>? diagnosticSink;
    private readonly CancellationTokenSource lifetime = new();
    private readonly Task server;
    private readonly object gate = new();
    private readonly Dictionary<Guid, TicketState> tickets = [];
    private readonly Dictionary<RdpDvcEvidenceRoute, Guid> routes = [];
    private readonly Dictionary<Guid, ReporterState> reporters = [];
    private readonly ConcurrentDictionary<int, Task> handlers = [];
    private int nextHandler;
    private int disposed;

    public ProductionRdpDvcRuntimeEvidenceSource(
        IRdpDvcEvidenceTicketResolver resolver,
        string pipeName,
        ReadOnlySpan<byte> authenticationKey,
        Action<string>? diagnosticSink = null)
    {
        this.resolver = resolver ??
            throw new ArgumentNullException(nameof(resolver));
        if (string.IsNullOrWhiteSpace(pipeName) ||
            pipeName.Length > 128 ||
            pipeName.Any(character =>
                char.IsControl(character) ||
                character is '\\' or '/'))
            throw new ArgumentException(
                "The DVC evidence pipe name is invalid.",
                nameof(pipeName));
        if (authenticationKey.Length is < 32 or > 64)
            throw new ArgumentException(
                "The DVC evidence publication key is invalid.",
                nameof(authenticationKey));
        this.pipeName = pipeName;
        key = authenticationKey.ToArray();
        this.diagnosticSink = diagnosticSink;
        server = RunServerAsync();
    }

    public bool IsConfigured => true;

    public static ProductionRdpDvcRuntimeEvidenceSource FromProtectedFile(
        IRdpDvcEvidenceTicketResolver resolver,
        string pipeName,
        string keyFile,
        Action<string>? diagnosticSink = null)
    {
        var key = CurrentUserProtectedDataFile.Read(
            keyFile,
            AuthenticatedRdpDvcEvidencePublisher.KeyFilePurpose);
        try
        {
            return new(resolver, pipeName, key, diagnosticSink);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public async ValueTask<RdpDvcRuntimeEvidenceTicket>
        RegisterExpectedAsync(
            string evidenceReference,
            string connectionId,
            string runtimeConnectionId,
            long connectionGeneration,
            CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref disposed) != 0)
            throw new ObjectDisposedException(GetType().Name);
        var route = await resolver.ResolveAsync(
                evidenceReference,
                cancellationToken)
            .ConfigureAwait(false);
        if (!route.Validate().IsWtsWildcard)
            throw new InvalidDataException(
                "The production DVC evidence ticket must preauthorize WTS as unspecified.");
        var identity = new RdpDvcEvidenceTicketIdentity(
            evidenceReference,
            connectionId,
            runtimeConnectionId,
            connectionGeneration,
            route).Validate();
        var ticket = new RdpDvcRuntimeEvidenceTicket(
            Guid.NewGuid(),
            identity);
        lock (gate)
        {
            if (tickets.Count >=
                ConnectionHostProtocol.MaximumConnections)
                throw new InvalidOperationException(
                    "The pending DVC evidence ticket limit was reached.");
            if (routes.ContainsKey(route.AsPreauthorized()) ||
                tickets.Values.Any(value =>
                    string.Equals(
                        value.Ticket.Identity.EvidenceReference,
                        evidenceReference,
                        StringComparison.Ordinal)))
                throw new InvalidOperationException(
                    "The DVC evidence ticket route or reference is already active.");
            tickets.Add(ticket.TicketId, new(ticket));
            routes.Add(route.AsPreauthorized(), ticket.TicketId);
        }
        try
        {
            if (resolver is IRdpDvcEvidenceTicketBindingStore bindingStore)
                await bindingStore.BindAsync(identity, cancellationToken)
                    .ConfigureAwait(false);
        }
        catch
        {
            await CancelAsync(ticket).ConfigureAwait(false);
            throw;
        }
        return ticket;
    }

    public async Task<RdpDvcRuntimeEvidenceBatch> WaitForEvidenceAsync(
        RdpDvcRuntimeEvidenceTicket ticket,
        CancellationToken cancellationToken)
    {
        TicketState state;
        lock (gate)
        {
            if (!tickets.TryGetValue(ticket.TicketId, out state!) ||
                state.Ticket != ticket)
                throw new InvalidOperationException(
                    "The DVC evidence ticket is not active.");
        }
        return await state.Completion.Task.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask CancelAsync(
        RdpDvcRuntimeEvidenceTicket ticket)
    {
        var removed = false;
        lock (gate)
        {
            if (tickets.Remove(ticket.TicketId, out var state))
            {
                removed = true;
                routes.Remove(
                    state.Ticket.Identity.Route.AsPreauthorized());
                state.Completion.TrySetCanceled();
                foreach (var pair in reporters
                             .Where(value =>
                                 value.Value.TicketId ==
                                 ticket.TicketId)
                             .ToArray())
                {
                    if (!pair.Value.ReusableLifecycle)
                    {
                        reporters.Remove(pair.Key);
                        continue;
                    }
                    pair.Value.TicketId = null;
                    pair.Value.ReusableRoute =
                        state.BoundIdentity?.Route ??
                        state.Ticket.Identity.Route;
                    pair.Value.Pending.Clear();
                    pair.Value.Pending.Add(RequiredOrder[0]);
                    pair.Value.Pending.Add(RequiredOrder[1]);
                }
            }
        }
        if (removed &&
            resolver is IRdpDvcEvidenceTicketBindingStore bindingStore)
            await bindingStore.ReleaseAsync(
                    ticket.Identity.EvidenceReference)
                .ConfigureAwait(false);
    }

    internal RdpDvcEvidencePublicationResult AcceptFrame(
        ReadOnlySpan<byte> frame,
        DateTimeOffset now)
    {
        RdpDvcEvidencePublication publication;
        try
        {
            publication = RdpDvcEvidenceIpcProtocol.Decode(frame, key);
        }
        catch (UnauthorizedAccessException)
        {
            return new(false, "DVC_EVIDENCE_AUTHENTICATION_FAILED");
        }
        catch (Exception exception)
            when (exception is
                ArgumentException or
                InvalidDataException or
                JsonException)
        {
            return new(false, "DVC_EVIDENCE_PROTOCOL_INVALID");
        }

        DateTimeOffset sentAt;
        try
        {
            sentAt = new(
                publication.SentAtUtcTicks,
                TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException)
        {
            return new(false, "DVC_EVIDENCE_TIMESTAMP_INVALID");
        }
        if ((now - sentAt).Duration() > MaximumPublicationAge)
            return new(false, "DVC_EVIDENCE_TIMESTAMP_STALE");

        lock (gate)
        {
            if (!reporters.TryGetValue(
                    publication.ReporterId,
                    out var reporter))
            {
                if (reporters.Count >=
                    ConnectionHostProtocol.MaximumConnections * 2 ||
                    publication.Sequence != 1)
                    return new(false, "DVC_EVIDENCE_SEQUENCE_REJECTED");
                reporter = new();
                reporters.Add(publication.ReporterId, reporter);
            }
            else if (publication.Sequence != reporter.LastSequence + 1)
            {
                return new(false, "DVC_EVIDENCE_SEQUENCE_REJECTED");
            }

            var result = publication.Event switch
            {
                RdpDvcEvidencePublicationEvent
                    .StewardComClassActivated =>
                    AcceptLifecycle(
                        publication,
                        reporter,
                        expectedCount: 0),
                RdpDvcEvidencePublicationEvent
                    .StewardPluginInitialized =>
                    AcceptLifecycle(
                        publication,
                        reporter,
                        expectedCount: 1),
                RdpDvcEvidencePublicationEvent
                    .StewardChannelOpened =>
                    AcceptChannel(
                        publication,
                        reporter),
                RdpDvcEvidencePublicationEvent
                    .DvcHmacAuthenticated or
                RdpDvcEvidencePublicationEvent
                    .SecurePeerAuthenticated =>
                    AcceptTransport(
                        publication,
                        reporter),
                _ => new(false, "DVC_EVIDENCE_EVENT_REJECTED")
            };
            if (result.Accepted)
                reporter.LastSequence = publication.Sequence;
            return result;
        }
    }

    private RdpDvcEvidencePublicationResult AcceptLifecycle(
        RdpDvcEvidencePublication publication,
        ReporterState reporter,
        int expectedCount)
    {
        if (publication.Ticket is not null ||
            publication.CandidateRoute is not null ||
            reporter.TicketId is not null ||
            reporter.Pending.Count != expectedCount)
            return new(false, "DVC_EVIDENCE_ORDER_REJECTED");
        reporter.Pending.Add(publication.Event);
        return new(true, "DVC_EVIDENCE_ACCEPTED");
    }

    private RdpDvcEvidencePublicationResult AcceptChannel(
        RdpDvcEvidencePublication publication,
        ReporterState reporter)
    {
        if (publication.Ticket is not null ||
            publication.CandidateRoute is not { } route ||
            reporter.TicketId is not null ||
            !reporter.Pending.SequenceEqual(RequiredOrder[..2]) ||
            route.WtsSessionId <= 0)
            return new(false, "DVC_EVIDENCE_ROUTE_REJECTED");
        if (!TryFindTicketForCandidate(
                route,
                out var ticketId,
                out var ticket))
            return AcceptReusableChannel(route, reporter);
        if (route.ProtocolVersion == 1 &&
            ticket.Ticket.Identity.Route.RetainedV1Endpoint is
            { } retained)
            route = route with { RetainedV1Endpoint = retained };
        if (ticket.CandidateRoute is { } candidate &&
            candidate != route)
            return new(false, "DVC_EVIDENCE_ROUTE_AMBIGUOUS");
        ticket.CandidateRoute ??= route;
        foreach (var evidenceEvent in reporter.Pending)
        {
            if (!TryAppend(ticket, evidenceEvent))
                return new(false, "DVC_EVIDENCE_ORDER_REJECTED");
        }
        if (!TryAppend(ticket, publication.Event))
            return new(false, "DVC_EVIDENCE_ORDER_REJECTED");
        reporter.Pending.Clear();
        reporter.TicketId = ticketId;
        reporter.ReusableLifecycle = true;
        return new(true, "DVC_EVIDENCE_ACCEPTED");
    }

    private static RdpDvcEvidencePublicationResult AcceptReusableChannel(
        RdpDvcEvidenceRoute route,
        ReporterState reporter)
    {
        if (reporter.ReusableRoute is not { } reusable ||
            (route.ProtocolVersion == 2
                ? !reusable.MatchesAuthenticatedRoute(route)
                : !reusable.HasSamePreauthorizedBase(route)))
            return new(false, "DVC_EVIDENCE_ROUTE_REJECTED");
        return new(true, "DVC_EVIDENCE_ACCEPTED");
    }

    private RdpDvcEvidencePublicationResult AcceptTransport(
        RdpDvcEvidencePublication publication,
        ReporterState reporter)
    {
        if (publication.Ticket is not { } identity ||
            publication.CandidateRoute is not null ||
            !TryFindTicket(identity, out var ticket))
            return new(false, "DVC_EVIDENCE_TICKET_REJECTED");
        if (reporter.TicketId is { } bound &&
            bound != ticket.Ticket.TicketId)
            return new(false, "DVC_EVIDENCE_TICKET_REJECTED");
        if (publication.Event ==
            RdpDvcEvidencePublicationEvent.DvcHmacAuthenticated)
        {
            if (identity.Route.WtsSessionId <= 0 ||
                ticket.CandidateRoute != identity.Route)
                return new(false, "DVC_EVIDENCE_ROUTE_REJECTED");
            if (ticket.BoundIdentity is { } alreadyBound &&
                alreadyBound != identity)
                return new(false, "DVC_EVIDENCE_WTS_REBIND_REJECTED");
            if (ticket.BoundIdentity is null)
            {
                try
                {
                    if (resolver is
                        IRdpDvcEvidenceTicketBindingStore bindingStore)
                        bindingStore.BindWtsSession(identity);
                }
                catch (Exception exception)
                    when (exception is
                        ArgumentException or
                        InvalidDataException or
                        InvalidOperationException or
                        IOException or
                        UnauthorizedAccessException)
                {
                    return new(
                        false,
                        "DVC_EVIDENCE_WTS_BINDING_FAILED");
                }
                ticket.BoundIdentity = identity;
            }
        }
        else if (ticket.BoundIdentity != identity)
        {
            return new(false, "DVC_EVIDENCE_WTS_BINDING_REQUIRED");
        }
        if (!TryAppend(ticket, publication.Event))
            return new(false, "DVC_EVIDENCE_ORDER_REJECTED");
        reporter.TicketId = ticket.Ticket.TicketId;
        return new(true, "DVC_EVIDENCE_ACCEPTED");
    }

    private bool TryFindTicketForCandidate(
        RdpDvcEvidenceRoute route,
        out Guid ticketId,
        out TicketState ticket)
    {
        var matches = tickets
            .Where(pair =>
            {
                var expected = pair.Value.Ticket.Identity.Route;
                return expected.ProtocolVersion ==
                        route.ProtocolVersion &&
                    (route.ProtocolVersion == 2
                        ? expected.MatchesAuthenticatedRoute(route)
                        : expected.HasSamePreauthorizedBase(route));
            })
            .Take(2)
            .ToArray();
        if (matches.Length != 1)
        {
            ticketId = Guid.Empty;
            ticket = null!;
            return false;
        }
        ticketId = matches[0].Key;
        ticket = matches[0].Value;
        return true;
    }

    private bool TryFindTicket(
        RdpDvcEvidenceTicketIdentity identity,
        out TicketState ticket)
    {
        var matches = tickets.Values
            .Where(value =>
            {
                var expected = value.Ticket.Identity;
                return string.Equals(
                        expected.EvidenceReference,
                        identity.EvidenceReference,
                        StringComparison.Ordinal) &&
                    string.Equals(
                        expected.ConnectionId,
                        identity.ConnectionId,
                        StringComparison.Ordinal) &&
                    string.Equals(
                        expected.RuntimeConnectionId,
                        identity.RuntimeConnectionId,
                        StringComparison.Ordinal) &&
                    expected.ConnectionGeneration ==
                        identity.ConnectionGeneration &&
                    (identity.Route.ProtocolVersion == 2
                        ? expected.Route.MatchesAuthenticatedRoute(
                            identity.Route)
                        : expected.Route.HasSamePreauthorizedBase(
                            identity.Route));
            })
            .Take(2)
            .ToArray();
        if (matches.Length != 1)
        {
            ticket = null!;
            return false;
        }
        ticket = matches[0];
        return true;
    }
    private static bool TryAppend(
        TicketState ticket,
        RdpDvcEvidencePublicationEvent evidenceEvent)
    {
        if (ticket.Next >= RequiredOrder.Length ||
            RequiredOrder[ticket.Next] != evidenceEvent)
            return false;
        ticket.Evidence.Add(ToRuntimeEvidence(evidenceEvent));
        ticket.Next++;
        if (ticket.Next == RequiredOrder.Length)
        {
            var identity = ticket.Ticket.Identity;
            ticket.Completion.TrySetResult(
                new(
                    identity.ConnectionId,
                    identity.RuntimeConnectionId,
                    identity.ConnectionGeneration,
                    ticket.Evidence.ToArray(),
                    ticket.BoundIdentity?.Route));
        }
        return true;
    }

    private static RdCoreRuntimeEvidence ToRuntimeEvidence(
        RdpDvcEvidencePublicationEvent evidenceEvent) =>
        evidenceEvent switch
        {
            RdpDvcEvidencePublicationEvent.StewardComClassActivated =>
                new(RdCoreDvcEvidenceEvent.StewardComClassActivated),
            RdpDvcEvidencePublicationEvent.StewardPluginInitialized =>
                new(
                    RdCoreDvcEvidenceEvent.StewardPluginInitialized,
                    StewardRdpDvc.AddInName,
                    StewardRdpDvc.PluginClsid),
            RdpDvcEvidencePublicationEvent.StewardChannelOpened =>
                new(
                    RdCoreDvcEvidenceEvent.StewardChannelOpened,
                    ChannelName: StewardRdpDvc.ChannelName),
            RdpDvcEvidencePublicationEvent.DvcHmacAuthenticated =>
                new(RdCoreDvcEvidenceEvent.DvcHmacAuthenticated),
            RdpDvcEvidencePublicationEvent.SecurePeerAuthenticated =>
                new(RdCoreDvcEvidenceEvent.SecurePeerAuthenticated),
            _ => throw new ArgumentOutOfRangeException(
                nameof(evidenceEvent))
        };

    private async Task RunServerAsync()
    {
        while (!lifetime.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = new(
                    pipeName,
                    PipeDirection.InOut,
                    16,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous |
                    PipeOptions.CurrentUserOnly,
                    RdpDvcEvidenceIpcProtocol.MaximumFrameBytes,
                    RdpDvcEvidenceIpcProtocol.MaximumFrameBytes);
                await pipe.WaitForConnectionAsync(lifetime.Token)
                    .ConfigureAwait(false);
                var id = Interlocked.Increment(ref nextHandler);
                var handler = HandleAsync(pipe);
                pipe = null;
                handlers.TryAdd(id, handler);
                _ = handler.ContinueWith(
                    completed =>
                    {
                        _ = completed;
                        handlers.TryRemove(id, out var ignored);
                        _ = ignored;
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
            catch (OperationCanceledException)
                when (lifetime.IsCancellationRequested)
            {
                pipe?.Dispose();
                break;
            }
            catch
            {
                pipe?.Dispose();
                await Task.Delay(
                        TimeSpan.FromMilliseconds(100),
                        lifetime.Token)
                    .ConfigureAwait(false);
            }
        }
    }

    private async Task HandleAsync(NamedPipeServerStream pipe)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                if (!IsCurrentUser(pipe))
                    return;
                using var timeout = new CancellationTokenSource(
                    TimeSpan.FromSeconds(5));
                var frame = await RdpDvcEvidenceIpcProtocol.ReadFrameAsync(
                        pipe,
                        timeout.Token)
                    .ConfigureAwait(false);
                var result = AcceptFrame(
                    frame,
                    DateTimeOffset.UtcNow);
                if (!result.Accepted)
                    diagnosticSink?.Invoke(
                        $"evidence-publication-rejected-{result.Code}");
                await pipe.WriteAsync(
                        new byte[] { result.Accepted ? (byte)1 : (byte)0 },
                        timeout.Token)
                    .ConfigureAwait(false);
                await pipe.FlushAsync(timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (Exception exception)
                when (exception is
                    IOException or
                    InvalidDataException or
                    OperationCanceledException or
                    UnauthorizedAccessException)
            {
                diagnosticSink?.Invoke(
                    $"evidence-pipe-error-{exception.GetType().Name}");
            }
        }
    }

    private static bool IsCurrentUser(NamedPipeServerStream pipe)
    {
        var serverSid = WindowsIdentity.GetCurrent().User?.Value;
        string? clientSid = null;
        pipe.RunAsClient(
            () => clientSid =
                WindowsIdentity.GetCurrent(true)?.User?.Value);
        return serverSid is not null &&
            string.Equals(serverSid, clientSid, StringComparison.Ordinal);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        lifetime.Cancel();
        try
        {
            await server.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (lifetime.IsCancellationRequested)
        {
        }
        var remaining = handlers.Values.ToArray();
        if (remaining.Length != 0)
            await Task.WhenAll(remaining).ConfigureAwait(false);
        lock (gate)
        {
            foreach (var ticket in tickets.Values)
                ticket.Completion.TrySetCanceled();
            tickets.Clear();
            routes.Clear();
            reporters.Clear();
        }
        CryptographicOperations.ZeroMemory(key);
        lifetime.Dispose();
    }

    private sealed class TicketState(
        RdpDvcRuntimeEvidenceTicket ticket)
    {
        internal RdpDvcRuntimeEvidenceTicket Ticket { get; } = ticket;
        internal List<RdCoreRuntimeEvidence> Evidence { get; } = [];
        internal TaskCompletionSource<RdpDvcRuntimeEvidenceBatch>
            Completion
        { get; } = new(
                TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Next { get; set; }
        internal RdpDvcEvidenceRoute? CandidateRoute { get; set; }
        internal RdpDvcEvidenceTicketIdentity? BoundIdentity { get; set; }
    }

    private sealed class ReporterState
    {
        internal long LastSequence { get; set; }
        internal List<RdpDvcEvidencePublicationEvent> Pending { get; } = [];
        internal Guid? TicketId { get; set; }
        internal bool ReusableLifecycle { get; set; }
        internal RdpDvcEvidenceRoute? ReusableRoute { get; set; }
    }
}
