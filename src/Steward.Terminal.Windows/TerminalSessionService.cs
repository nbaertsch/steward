using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Steward.Domain;
using Steward.Terminal.Abstractions;

namespace Steward.Terminal.Windows;

public sealed record TerminalSessionServiceOptions(
    int MaximumConcurrentSessions = 32,
    int NotificationCapacity = 64,
    int MaximumReadersPerSession = 8,
    int MaximumInputMessageBytes = 64 * 1024,
    TimeSpan MaximumCloseGracePeriod = default,
    TimeSpan AuthorityMonitorInterval = default)
{
    public TimeSpan EffectiveMaximumCloseGracePeriod =>
        MaximumCloseGracePeriod == default ? TimeSpan.FromSeconds(10) : MaximumCloseGracePeriod;
    public TimeSpan EffectiveAuthorityMonitorInterval =>
        AuthorityMonitorInterval == default ? TimeSpan.FromSeconds(1) : AuthorityMonitorInterval;
}

public sealed class TerminalSessionService : ITerminalSessionService, IAsyncDisposable
{
    private sealed class LiveSession(TerminalShellKind shellKind)
    {
        internal TerminalShellKind ShellKind { get; } = shellKind;
        internal CancellationTokenSource Lease { get; } = new();
        internal ConcurrentDictionary<Guid, Channel<long>> Subscribers { get; } = new();
        internal string? ForcedReason;
        internal bool ForcedInterruption;
        internal int Completed;
    }

    private readonly TerminalJournal journal;
    private readonly ConPtyTerminalRuntime runtime;
    private readonly HostId hostId;
    private readonly NodeIncarnationId nodeIncarnationId;
    private readonly string bootId;
    private readonly Func<long> currentRevocationRevision;
    private readonly TimeProvider timeProvider;
    private readonly TerminalSessionServiceOptions options;
    private readonly ConcurrentDictionary<TerminalSessionId, LiveSession> live = new();
    private bool disposed;

    public TerminalSessionService(
        TerminalJournal journal,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        string bootId,
        ConPtyTerminalRuntimeOptions? runtimeOptions = null,
        TerminalSessionServiceOptions? options = null,
        Func<long>? currentRevocationRevision = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentException.ThrowIfNullOrWhiteSpace(bootId);
        this.options = options ?? new();
        if (this.options.MaximumConcurrentSessions <= 0 ||
            this.options.NotificationCapacity <= 0 ||
            this.options.MaximumReadersPerSession <= 0 ||
            this.options.MaximumInputMessageBytes <= 0 ||
            this.options.MaximumInputMessageBytes > 1024 * 1024 ||
            this.options.EffectiveMaximumCloseGracePeriod <= TimeSpan.Zero ||
            this.options.EffectiveMaximumCloseGracePeriod > TimeSpan.FromMinutes(1) ||
            this.options.EffectiveAuthorityMonitorInterval <= TimeSpan.Zero ||
            this.options.EffectiveAuthorityMonitorInterval > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(options));
        this.journal = journal;
        this.hostId = hostId;
        this.nodeIncarnationId = nodeIncarnationId;
        this.bootId = bootId;
        this.currentRevocationRevision = currentRevocationRevision ?? (() => 0);
        this.timeProvider = timeProvider ?? TimeProvider.System;
        runtime = new(runtimeOptions ?? ConPtyTerminalRuntimeOptions.CreateDefault());
        _ = journal.ReconcileAfterRestart(nodeIncarnationId, bootId, UtcNow);
    }

    public async ValueTask<TerminalSessionSnapshot> OpenAsync(
        TerminalOpenRequest request,
        TerminalOperationContext context,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        TerminalContractLimits.ValidateOpen(request);
        ValidateAuthority(request.Authority, context, requireLiveLease: true);
        var root = TerminalWorkspacePaths.ValidateRoot(request.Authority.WorkspaceRoot);
        var working = TerminalWorkspacePaths.ValidateWorkingDirectory(root, request.WorkingDirectory);
        if (request.Authority.ElevationRequested && !request.Authority.ElevationGranted)
            throw Problem(TerminalProblemCode.ElevationUnavailable,
                "Terminal elevation was requested but not granted.",
                TerminalProblemDisposition.RequiresNewUserIntent, false);
        if (live.Count >= options.MaximumConcurrentSessions)
            throw Problem(TerminalProblemCode.SessionLimitExceeded, "Concurrent terminal session limit reached.",
                TerminalProblemDisposition.RetrySafe, false);

        var fingerprint = Fingerprint(request, root, working);
        var durable = journal.CreateRequested(request, fingerprint, bootId, UtcNow);
        if (durable.State != TerminalSessionState.Requested)
            return durable;
        durable = journal.SetOpening(request.Authority.SessionId, durable.Revision, UtcNow);

        var liveSession = new LiveSession(request.ShellKind);
        if (!live.TryAdd(request.Authority.SessionId, liveSession))
        {
            journal.SetInterrupted(request.Authority.SessionId, "duplicate-live-runtime", UtcNow);
            throw Problem(TerminalProblemCode.IdempotencyConflict, "Terminal runtime identity is already active.",
                TerminalProblemDisposition.RequiresReconciliation, false);
        }

        try
        {
            var identity = await runtime.StartAsync(
                new(request.Authority.SessionId, request.ShellKind, request.ShellExecutable, request.Arguments,
                    working, request.Columns, request.Rows, request.Authority.MaximumOutputBytes,
                    request.Authority.ElevationGranted),
                (data, token) => OnOutputAsync(request.Authority.SessionId, data, token),
                reason => OnRuntimeCompletedAsync(request.Authority.SessionId, reason),
                cancellationToken).ConfigureAwait(false);
            durable = journal.SetOpen(request.Authority.SessionId, durable.Revision, identity.ProcessId,
                identity.CreationTimeUtcTicks, identity.ExecutionIdentity, UtcNow);
            _ = MonitorAuthorityAsync(request.Authority, liveSession);
            return durable;
        }
        catch (TerminalException)
        {
            await InterruptRuntimeAsync(request.Authority.SessionId, "terminal-open-failed").ConfigureAwait(false);
            throw;
        }
        catch (OperationCanceledException)
        {
            await InterruptRuntimeAsync(request.Authority.SessionId, "terminal-open-cancelled").ConfigureAwait(false);
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            InvalidOperationException or System.ComponentModel.Win32Exception or PlatformNotSupportedException)
        {
            await InterruptRuntimeAsync(request.Authority.SessionId, "terminal-runtime-unavailable").ConfigureAwait(false);
            throw Problem(TerminalProblemCode.RuntimeUnavailable, "Terminal runtime could not be opened.",
                TerminalProblemDisposition.RequiresReconciliation, true);
        }
    }

    public async ValueTask<TerminalSessionSnapshot> WriteInputAsync(
        TerminalInputRequest request,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (request.Data.IsEmpty || request.Data.Length > options.MaximumInputMessageBytes)
            throw Problem(TerminalProblemCode.InvalidRequest, "Terminal input message size is invalid.",
                TerminalProblemDisposition.Terminal, false);
        TerminalContractLimits.ValidateRequestId(request.RequestId);
        var authority = journal.GetAuthority(request.SessionId);
        ValidateAuthority(authority, request.Context, requireLiveLease: true);
        var operation = journal.BeginOperation(request.RequestId, request.SessionId, "input",
            OperationFingerprint("input", request.SessionId, request.Context, request.ExpectedRevision,
                Convert.ToHexString(SHA256.HashData(request.Data.Span))), UtcNow);
        if (!operation.IsNew)
            return ReplayOperation(operation);
        var current = operation.Snapshot;
        if (current.Revision != request.ExpectedRevision)
        {
            journal.AbandonAcceptedOperation(request.RequestId, request.SessionId);
            throw Problem(TerminalProblemCode.RevisionConflict, "Terminal session revision does not match.",
                TerminalProblemDisposition.RequiresReconciliation, false);
        }
        var hash = AdvanceHash(current.InputHash, request.Data.Span);
        try
        {
            _ = journal.AccountInput(request.SessionId, request.ExpectedRevision, request.Data.Span,
                hash, UtcNow, authority.Task is not null);
        }
        catch (TerminalException)
        {
            journal.AbandonAcceptedOperation(request.RequestId, request.SessionId);
            throw;
        }
        try
        {
            await runtime.WriteAsync(request.SessionId, request.Data, cancellationToken).ConfigureAwait(false);
            return journal.MarkOperationApplied(request.RequestId, request.SessionId, UtcNow);
        }
        catch (Exception exception) when (exception is TerminalException or OperationCanceledException)
        {
            journal.MarkOperationUncertain(request.RequestId, request.SessionId, UtcNow);
            await InterruptRuntimeAsync(request.SessionId, "input-side-effect-uncertain").ConfigureAwait(false);
            throw Problem(TerminalProblemCode.AmbiguousOperation,
                "Terminal input side effect is uncertain and requires reconciliation.",
                TerminalProblemDisposition.RequiresReconciliation, true);
        }
    }

    public async IAsyncEnumerable<TerminalOutput> ReadOutputAsync(
        TerminalOutputReadRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        TerminalContractLimits.ValidateOutputRead(request);
        var authority = journal.GetAuthority(request.SessionId);
        ValidateAuthority(authority, request.Context, requireLiveLease: false);
        LiveSession? session = null;
        Channel<long>? notifications = null;
        var subscriberId = Guid.NewGuid();
        if (request.Follow && live.TryGetValue(request.SessionId, out session) &&
            Volatile.Read(ref session.Completed) == 0)
        {
            if (session.Subscribers.Count >= options.MaximumReadersPerSession)
                throw Problem(TerminalProblemCode.SessionLimitExceeded,
                    "Terminal output reader limit reached.", TerminalProblemDisposition.RetrySafe, false);
            notifications = Channel.CreateBounded<long>(new BoundedChannelOptions(options.NotificationCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false
            });
            if (!session.Subscribers.TryAdd(subscriberId, notifications))
                throw Problem(TerminalProblemCode.RuntimeUnavailable,
                    "Terminal output reader could not be registered.", TerminalProblemDisposition.RetrySafe, false);
            if (session.Subscribers.Count > options.MaximumReadersPerSession)
            {
                _ = session.Subscribers.TryRemove(subscriberId, out _);
                notifications.Writer.TryComplete();
                throw Problem(TerminalProblemCode.SessionLimitExceeded,
                    "Terminal output reader limit reached.", TerminalProblemDisposition.RetrySafe, false);
            }
            if (Volatile.Read(ref session.Completed) != 0)
            {
                _ = session.Subscribers.TryRemove(subscriberId, out _);
                notifications.Writer.TryComplete();
                notifications = null;
                session = null;
            }
        }

        var sequence = request.AfterSequence;
        var offset = request.AfterOffset;
        var remainingItems = request.MaximumItems;
        var remainingBytes = request.MaximumBytes;
        try
        {
            while (remainingItems > 0 && remainingBytes > 0)
            {
                var page = journal.ReadOutput(request with
                {
                    AfterSequence = sequence,
                    AfterOffset = offset,
                    MaximumItems = remainingItems,
                    MaximumBytes = remainingBytes,
                    Follow = false
                }, UtcNow);
                foreach (var output in page)
                {
                    yield return output;
                    sequence = output.Sequence;
                    offset = checked(output.Offset + output.Length);
                    remainingItems--;
                    remainingBytes -= output.Data.Length;
                    if (output.EndOfStream || remainingItems == 0 || remainingBytes == 0)
                        yield break;
                }
                if (!request.Follow || notifications is null)
                    yield break;
                if (journal.Get(request.SessionId).State is TerminalSessionState.Closed or TerminalSessionState.Interrupted)
                    yield break;
                _ = await notifications.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            if (session is not null && session.Subscribers.TryRemove(subscriberId, out var removed))
                removed.Writer.TryComplete();
        }
    }

    public async ValueTask<TerminalSessionSnapshot> ResizeAsync(
        TerminalResizeRequest request,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        TerminalContractLimits.ValidateRequestId(request.RequestId);
        TerminalContractLimits.ValidateSize(request.Columns, request.Rows);
        var authority = journal.GetAuthority(request.SessionId);
        ValidateAuthority(authority, request.Context, requireLiveLease: true);
        var operation = journal.BeginOperation(request.RequestId, request.SessionId, "resize",
            OperationFingerprint("resize", request.SessionId, request.Context, request.ExpectedRevision,
                $"{request.Columns}:{request.Rows}"), UtcNow);
        if (!operation.IsNew)
            return ReplayOperation(operation);
        if (operation.Snapshot.Revision != request.ExpectedRevision)
        {
            journal.AbandonAcceptedOperation(request.RequestId, request.SessionId);
            throw Problem(TerminalProblemCode.RevisionConflict, "Terminal session revision does not match.",
                TerminalProblemDisposition.RequiresReconciliation, false);
        }
        try
        {
            _ = journal.RecordResize(request.SessionId, request.ExpectedRevision,
                request.Columns, request.Rows, UtcNow);
        }
        catch (TerminalException)
        {
            journal.AbandonAcceptedOperation(request.RequestId, request.SessionId);
            throw;
        }
        try
        {
            runtime.Resize(request.SessionId, request.Columns, request.Rows);
            return journal.MarkOperationApplied(request.RequestId, request.SessionId, UtcNow);
        }
        catch (TerminalException)
        {
            journal.MarkOperationUncertain(request.RequestId, request.SessionId, UtcNow);
            await InterruptRuntimeAsync(request.SessionId, "resize-side-effect-ambiguous").ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<TerminalSessionSnapshot> CloseAsync(
        TerminalCloseRequest request,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        TerminalContractLimits.ValidateRequestId(request.RequestId);
        var authority = journal.GetAuthority(request.SessionId);
        ValidateAuthority(authority, request.Context, requireLiveLease: false);
        if (request.GracePeriod < TimeSpan.Zero ||
            request.GracePeriod > options.EffectiveMaximumCloseGracePeriod)
            throw Problem(TerminalProblemCode.InvalidRequest, "Terminal close grace period is invalid.",
                TerminalProblemDisposition.Terminal, false);
        var operation = journal.BeginOperation(request.RequestId, request.SessionId, "close",
            OperationFingerprint("close", request.SessionId, request.Context, request.ExpectedRevision,
                request.GracePeriod.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)), UtcNow);
        if (!operation.IsNew)
            return ReplayOperation(operation);
        var current = operation.Snapshot;
        if (current.Revision != request.ExpectedRevision)
        {
            journal.AbandonAcceptedOperation(request.RequestId, request.SessionId);
            throw Problem(TerminalProblemCode.RevisionConflict, "Terminal session revision does not match.",
                TerminalProblemDisposition.RequiresReconciliation, false);
        }
        if (current.State == TerminalSessionState.Closed)
            return journal.MarkOperationApplied(request.RequestId, request.SessionId, UtcNow);
        try
        {
            _ = journal.SetClosing(request.SessionId, request.ExpectedRevision, UtcNow);
        }
        catch (TerminalException)
        {
            journal.AbandonAcceptedOperation(request.RequestId, request.SessionId);
            throw;
        }
        try
        {
            var shell = live.TryGetValue(request.SessionId, out var session)
                ? session.ShellKind
                : TerminalShellKind.CommandPrompt;
            await runtime.CloseAsync(request.SessionId, shell, request.GracePeriod, cancellationToken).ConfigureAwait(false);
            _ = journal.AppendEndOfStream(request.SessionId, UtcNow);
            _ = journal.SetClosed(request.SessionId, "closed-by-request", UtcNow);
            CompleteLive(request.SessionId);
            return journal.MarkOperationApplied(request.RequestId, request.SessionId, UtcNow);
        }
        catch (OperationCanceledException)
        {
            journal.MarkOperationUncertain(request.RequestId, request.SessionId, UtcNow);
            journal.SetInterrupted(request.SessionId, "close-cancelled", UtcNow);
            throw Problem(TerminalProblemCode.Interrupted,
                "Terminal close outcome requires reconciliation.",
                TerminalProblemDisposition.RequiresReconciliation, true);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or
            System.ComponentModel.Win32Exception or TerminalException)
        {
            journal.MarkOperationUncertain(request.RequestId, request.SessionId, UtcNow);
            await InterruptRuntimeAsync(request.SessionId, "close-outcome-ambiguous").ConfigureAwait(false);
            throw Problem(TerminalProblemCode.Interrupted, "Terminal close outcome requires reconciliation.",
                TerminalProblemDisposition.RequiresReconciliation, true);
        }
    }

    public ValueTask<TerminalSessionSnapshot> GetAsync(
        TerminalSessionId sessionId,
        TerminalOperationContext context,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        var authority = journal.GetAuthority(sessionId);
        ValidateAuthority(authority, context, requireLiveLease: false);
        return ValueTask.FromResult(journal.Get(sessionId));
    }

    public IReadOnlyList<TerminalTranscriptRecord> ReadRetainedTranscript(
        TerminalSessionId sessionId,
        TerminalOperationContext context)
    {
        var authority = journal.GetAuthority(sessionId);
        ValidateAuthority(authority, context, requireLiveLease: false);
        return journal.ReadTranscript(sessionId);
    }

    public ValueTask UploadFileAsync(
        TerminalSessionId sessionId,
        TerminalOperationContext context,
        CancellationToken cancellationToken = default) =>
        RejectFileTransferAsync(sessionId, context, TerminalFileTransferCapabilities.Upload, cancellationToken);

    public ValueTask DownloadFileAsync(
        TerminalSessionId sessionId,
        TerminalOperationContext context,
        CancellationToken cancellationToken = default) =>
        RejectFileTransferAsync(sessionId, context, TerminalFileTransferCapabilities.Download, cancellationToken);

    private ValueTask RejectFileTransferAsync(
        TerminalSessionId sessionId,
        TerminalOperationContext context,
        TerminalFileTransferCapabilities capability,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var authority = journal.GetAuthority(sessionId);
        ValidateAuthority(authority, context, requireLiveLease: true);
        if (!authority.FileTransferCapabilities.HasFlag(capability))
            throw Problem(TerminalProblemCode.CapabilityDenied, "Terminal file-transfer capability was not granted.",
                TerminalProblemDisposition.RequiresNewUserIntent, false);
        throw Problem(TerminalProblemCode.CapabilityDenied, "Terminal file transfer is not implemented by this runtime.",
            TerminalProblemDisposition.Terminal, false);
    }

    private async ValueTask OnOutputAsync(
        TerminalSessionId sessionId,
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        var current = journal.Get(sessionId);
        var sequence = checked(current.OutputSequence + 1);
        var offset = current.OutputBytes;
        var hash = AdvanceHash(current.OutputHash, data.Span);
        journal.AppendOutput(sessionId, sequence, offset, data.Span, hash, UtcNow);
        if (live.TryGetValue(sessionId, out var session))
            Notify(session, sequence);
        await ValueTask.CompletedTask;
    }

    private ValueTask OnRuntimeCompletedAsync(TerminalSessionId sessionId, string reason)
    {
        var snapshot = journal.Find(sessionId);
        if (snapshot is null)
            return ValueTask.CompletedTask;
        var eos = journal.AppendEndOfStream(sessionId, UtcNow);
        if (live.TryGetValue(sessionId, out var session))
            Notify(session, eos.Sequence);
        if (session?.ForcedInterruption == true)
            journal.SetInterrupted(sessionId, session.ForcedReason ?? "terminal-interrupted", UtcNow);
        else if (reason == "output-limit-reached")
            journal.SetInterrupted(sessionId, "output-limit-exceeded", UtcNow);
        else if (reason is "process-exited" or "cancelled")
            journal.SetClosed(sessionId, session?.ForcedReason ?? reason, UtcNow);
        else
            journal.SetInterrupted(sessionId, reason, UtcNow);
        CompleteLive(sessionId);
        return ValueTask.CompletedTask;
    }

    private async Task MonitorAuthorityAsync(TerminalAuthority authority, LiveSession session)
    {
        var maximumEnd = authority.IssuedAt + authority.MaximumDuration;
        var expiry = authority.ExpiresAt < maximumEnd ? authority.ExpiresAt : maximumEnd;
        try
        {
            while (!session.Lease.IsCancellationRequested)
            {
                var now = UtcNow;
                var revoked = currentRevocationRevision() > authority.RevocationRevision;
                if (revoked || now >= expiry)
                {
                    session.ForcedReason = revoked ? "authority-revoked" : "lease-expired";
                    session.ForcedInterruption = revoked;
                    var current = journal.Find(authority.SessionId);
                    if (current?.State == TerminalSessionState.Open)
                        journal.SetClosing(authority.SessionId, current.Revision, now);
                    await runtime.CloseAsync(authority.SessionId, session.ShellKind, TimeSpan.Zero,
                        CancellationToken.None).ConfigureAwait(false);
                    _ = journal.AppendEndOfStream(authority.SessionId, UtcNow);
                    if (revoked)
                        journal.SetInterrupted(authority.SessionId, "authority-revoked", UtcNow);
                    else
                        journal.SetClosed(authority.SessionId, "lease-expired", UtcNow);
                    CompleteLive(authority.SessionId);
                    return;
                }
                var untilExpiry = expiry - now;
                var delay = untilExpiry < options.EffectiveAuthorityMonitorInterval
                    ? untilExpiry
                    : options.EffectiveAuthorityMonitorInterval;
                await Task.Delay(delay, timeProvider, session.Lease.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (session.Lease.IsCancellationRequested) { }
        catch (TerminalException)
        {
            var current = journal.Find(authority.SessionId);
            if (current is not null && current.State is not (TerminalSessionState.Closed or TerminalSessionState.Interrupted))
                journal.SetInterrupted(authority.SessionId, "lease-expiry-close-ambiguous", UtcNow);
        }
    }

    private void ValidateAuthority(
        TerminalAuthority authority,
        TerminalOperationContext context,
        bool requireLiveLease)
    {
        TerminalContractLimits.ValidateAuthorityShape(authority);
        if (authority.HostId != hostId || context.HostId != hostId ||
            authority.NodeIncarnationId != nodeIncarnationId || context.NodeIncarnationId != nodeIncarnationId ||
            !StringComparer.Ordinal.Equals(authority.Actor, context.Actor))
            throw Problem(TerminalProblemCode.AuthorityMismatch, "Terminal authority binding does not match this operation.",
                TerminalProblemDisposition.RequiresNewUserIntent, false);
        var now = UtcNow;
        if (now < authority.NotBefore)
            throw Problem(TerminalProblemCode.AuthorityNotYetValid, "Terminal authority is not yet valid.",
                TerminalProblemDisposition.RetrySafe, false);
        if (requireLiveLease &&
            (now >= authority.ExpiresAt || now >= authority.IssuedAt + authority.MaximumDuration))
            throw Problem(TerminalProblemCode.AuthorityExpired, "Terminal authority has expired.",
                TerminalProblemDisposition.RequiresNewUserIntent, false);
        var revision = Math.Max(context.CurrentRevocationRevision, currentRevocationRevision());
        if (revision > authority.RevocationRevision)
            throw Problem(TerminalProblemCode.AuthorityRevoked, "Terminal authority has been revoked.",
                TerminalProblemDisposition.RequiresNewUserIntent, false);
    }

    private void CompleteLive(TerminalSessionId sessionId)
    {
        if (!live.TryGetValue(sessionId, out var session) ||
            Interlocked.Exchange(ref session.Completed, 1) != 0)
            return;
        _ = live.TryRemove(new KeyValuePair<TerminalSessionId, LiveSession>(sessionId, session));
        session.Lease.Cancel();
        foreach (var subscriber in session.Subscribers.Values)
            subscriber.Writer.TryComplete();
        session.Subscribers.Clear();
        session.Lease.Dispose();
    }

    private DateTimeOffset UtcNow => timeProvider.GetUtcNow();

    private static TerminalSessionSnapshot ReplayOperation(TerminalOperationStart operation)
    {
        if (operation.Status == TerminalOperationStatus.Applied)
            return operation.Snapshot;
        throw Problem(TerminalProblemCode.AmbiguousOperation,
            "Terminal operation side effect is uncertain and will not be repeated.",
            TerminalProblemDisposition.RequiresReconciliation, true);
    }

    private async ValueTask InterruptRuntimeAsync(TerminalSessionId sessionId, string reason)
    {
        if (live.TryGetValue(sessionId, out var session))
        {
            session.ForcedReason = reason;
            session.ForcedInterruption = true;
            try
            {
                await runtime.CloseAsync(sessionId, session.ShellKind, TimeSpan.Zero, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is TerminalException or IOException or
                System.ComponentModel.Win32Exception) { }
        }
        _ = journal.AppendEndOfStream(sessionId, UtcNow);
        journal.SetInterrupted(sessionId, reason, UtcNow);
        CompleteLive(sessionId);
    }

    private static void Notify(LiveSession session, long sequence)
    {
        foreach (var subscriber in session.Subscribers.Values)
            _ = subscriber.Writer.TryWrite(sequence);
    }

    private static string OperationFingerprint(
        string operationType,
        TerminalSessionId sessionId,
        TerminalOperationContext context,
        long expectedRevision,
        string bodyFingerprint)
    {
        var canonical = string.Join('\n', operationType, sessionId.ToString(), context.HostId.ToString(),
            context.NodeIncarnationId.ToString(), context.Actor,
            context.CurrentRevocationRevision.ToString(System.Globalization.CultureInfo.InvariantCulture),
            expectedRevision.ToString(System.Globalization.CultureInfo.InvariantCulture), bodyFingerprint);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static string AdvanceHash(string previousHash, ReadOnlySpan<byte> data)
    {
        byte[] previous;
        try { previous = Convert.FromHexString(previousHash); }
        catch (FormatException)
        {
            throw Problem(TerminalProblemCode.Interrupted, "Terminal hash cursor is malformed.",
                TerminalProblemDisposition.RequiresReconciliation, true);
        }
        var combined = new byte[checked(previous.Length + data.Length)];
        previous.CopyTo(combined, 0);
        data.CopyTo(combined.AsSpan(previous.Length));
        return Convert.ToHexString(SHA256.HashData(combined));
    }

    private static string Fingerprint(TerminalOpenRequest request, string root, string workingDirectory)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(request.SchemaVersion);
        Add(request.Authority.SessionId.ToString());
        Add(request.Authority.HostId.ToString());
        Add(request.Authority.NodeIncarnationId.ToString());
        Add(request.Authority.Actor);
        Add(root);
        Add(request.Authority.Task?.TaskAttemptId.ToString() ?? "");
        Add(request.Authority.Task?.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "");
        Add(request.Authority.ExpiresAt.ToUniversalTime().ToString("O"));
        Add(request.Authority.RevocationRevision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(request.Authority.OperationalReplayDuration.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(request.Authority.MaximumOperationalSpoolBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(request.ShellKind.ToString());
        Add(Path.GetFullPath(request.ShellExecutable));
        Add(workingDirectory);
        foreach (var argument in request.Arguments)
            Add(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(argument))));
        return Convert.ToHexString(hash.GetHashAndReset());

        void Add(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            hash.AppendData(BitConverter.GetBytes(bytes.Length));
            hash.AppendData(bytes);
        }
    }

    private static TerminalException Problem(
        TerminalProblemCode code,
        string detail,
        TerminalProblemDisposition disposition,
        bool sideEffectMayHaveOccurred) =>
        new(new(code, detail, disposition, sideEffectMayHaveOccurred));

    public async ValueTask DisposeAsync()
    {
        if (disposed)
            return;
        disposed = true;
        foreach (var sessionId in live.Keys.ToArray())
        {
            if (!live.TryGetValue(sessionId, out var session))
                continue;
            try
            {
                var snapshot = journal.Get(sessionId);
                if (snapshot.State == TerminalSessionState.Open)
                    journal.SetClosing(sessionId, snapshot.Revision, UtcNow);
                await runtime.CloseAsync(sessionId, session.ShellKind, TimeSpan.Zero, CancellationToken.None)
                    .ConfigureAwait(false);
                journal.SetClosed(sessionId, "service-disposed", UtcNow);
            }
            catch (TerminalException)
            {
                var snapshot = journal.Find(sessionId);
                if (snapshot is not null && snapshot.State is not (TerminalSessionState.Closed or TerminalSessionState.Interrupted))
                    journal.SetInterrupted(sessionId, "service-dispose-ambiguous", UtcNow);
            }
            CompleteLive(sessionId);
        }
        await runtime.DisposeAsync().ConfigureAwait(false);
    }
}
