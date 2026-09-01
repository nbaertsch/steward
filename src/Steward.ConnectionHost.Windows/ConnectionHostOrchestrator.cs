using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public sealed class ConnectionHostOperationException(
    string code,
    string message) : InvalidOperationException(message)
{
    public string Code { get; } = code;
}

public sealed class ConnectionHostOrchestrator : IAsyncDisposable
{
    private const int MaximumPendingWork = 256;
    private const int MaximumActiveQueues =
        ConnectionHostProtocol.MaximumConnections + MaximumPendingWork;

    private readonly ConnectionHostOptions options;
    private readonly IDevBoxConnectionIdentityGate identity;
    private readonly IDevBoxConnectionResolver resolver;
    private readonly IRdCoreCompatibilityInspector compatibility;
    private readonly IDvcRegistrationSnapshotProvider registration;
    private readonly IRdCoreConnectionRuntime runtime;
    private readonly IControlConnectAuthorizationValidator authorization;
    private readonly IConnectionMetadataStore metadata;
    private readonly IConnectionRecoveryMaterialIssuer? recoveryMaterialIssuer;
    private readonly object synchronization = new();
    private readonly SemaphoreSlim pendingCapacity =
        new(MaximumPendingWork, MaximumPendingWork);
    private readonly SemaphoreSlim persistenceGate = new(1, 1);
    private readonly CancellationTokenSource shutdown = new();
    private readonly Dictionary<string, QueueRegistration> queues =
        new(StringComparer.Ordinal);
    private readonly HashSet<Task> activeQueueActors = [];
    private readonly Dictionary<string, ConnectionEntry> connections =
        new(StringComparer.Ordinal);
    private TaskCompletionSource<bool>? actorsDrained;
    private Task? initializationTask;
    private Task? disposalTask;
    private bool initialized;
    private bool disposed;

    public ConnectionHostOrchestrator(
        ConnectionHostOptions options,
        IDevBoxConnectionIdentityGate identity,
        IDevBoxConnectionResolver resolver,
        IRdCoreCompatibilityInspector compatibility,
        IDvcRegistrationSnapshotProvider registration,
        IRdCoreConnectionRuntime runtime,
        IControlConnectAuthorizationValidator authorization,
        IConnectionMetadataStore metadata,
        IConnectionRecoveryMaterialIssuer? recoveryMaterialIssuer = null)
    {
        this.options = options ??
            throw new ArgumentNullException(nameof(options));
        this.identity = identity ??
            throw new ArgumentNullException(nameof(identity));
        this.resolver = resolver ??
            throw new ArgumentNullException(nameof(resolver));
        this.compatibility = compatibility ??
            throw new ArgumentNullException(nameof(compatibility));
        this.registration = registration ??
            throw new ArgumentNullException(nameof(registration));
        this.runtime = runtime ??
            throw new ArgumentNullException(nameof(runtime));
        this.authorization = authorization ??
            throw new ArgumentNullException(nameof(authorization));
        this.metadata = metadata ??
            throw new ArgumentNullException(nameof(metadata));
        this.recoveryMaterialIssuer = recoveryMaterialIssuer;
        ValidateOptions(options);
    }

    public ConnectionHostOrchestrator(
        ConnectionHostOptions options,
        IDevBoxConnectionIdentityGate identity,
        IDevBoxAvdResourceCatalog catalog,
        IDevBoxBrokerHttpTransport brokerTransport,
        IRdCoreCompatibilityInspector compatibility,
        IDvcRegistrationSnapshotProvider registration,
        IRdCoreConnectionRuntime runtime,
        IControlConnectAuthorizationValidator authorization,
        IConnectionMetadataStore metadata,
        DevBoxBrokerFeedResolverOptions? resolverOptions = null)
        : this(
            options,
            identity,
            new DevBoxConnectionResolver(
                new DevBoxBrokerFeedResolver(
                    identity,
                    catalog,
                    brokerTransport,
                    resolverOptions)),
            compatibility,
            registration,
            runtime,
            authorization,
            metadata)
    {
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        TaskCompletionSource<bool>? completion = null;
        Task task;
        lock (synchronization)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (initialized)
                return Task.CompletedTask;
            if (initializationTask is null)
            {
                completion = new(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                initializationTask = completion.Task;
            }
            task = initializationTask;
        }

        if (completion is not null)
            _ = RunInitializationAsync(completion);
        return task.WaitAsync(cancellationToken);
    }

    public Task<ConnectionHostResponse> ExecuteAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken = default)
    {
        ConnectionHostProtocol.Validate(command);
        return ExecuteAfterInitializationAsync(command, cancellationToken);
    }

    public Task<ConnectionHostStatus> NotifyViewClosedAsync(
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken = default) =>
        EnqueueAfterInitializationAsync(
            connectionId,
            async token =>
            {
                ConnectionHostStatus status;
                lock (synchronization)
                {
                    RequireInitialized();
                    var entry = Find(connectionId);
                    entry.Machine.CloseVisibleSurface(connectionGeneration);
                    entry.Apply(entry.Machine.Snapshot);
                    status = entry.Status;
                }
                await PersistAsync(token).ConfigureAwait(false);
                return status;
            },
            cancellationToken);

    public ValueTask DisposeAsync()
    {
        TaskCompletionSource<bool>? completion = null;
        Task? initialization;
        Task actorDrain;
        QueueRegistration[] queueSnapshot;
        lock (synchronization)
        {
            if (disposalTask is not null)
                return new(disposalTask);

            disposed = true;
            queueSnapshot = queues.Values.ToArray();
            initialization = initializationTask;
            if (activeQueueActors.Count == 0)
            {
                actorDrain = Task.CompletedTask;
            }
            else
            {
                actorsDrained = new(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                actorDrain = actorsDrained.Task;
            }
            completion = new(
                TaskCreationOptions.RunContinuationsAsynchronously);
            disposalTask = completion.Task;
        }

        shutdown.Cancel();
        foreach (var queue in queueSnapshot)
            queue.Queue.Complete();
        _ = RunDisposalAsync(completion, initialization, actorDrain);
        return new(completion.Task);
    }

    private async Task RunInitializationAsync(
        TaskCompletionSource<bool> completion)
    {
        try
        {
            await InitializeCoreAsync(shutdown.Token).ConfigureAwait(false);
            completion.TrySetResult(true);
        }
        catch (OperationCanceledException)
            when (shutdown.IsCancellationRequested)
        {
            completion.TrySetCanceled(shutdown.Token);
        }
        catch (Exception exception)
        {
            completion.TrySetException(exception);
        }
        finally
        {
            lock (synchronization)
            {
                if (!initialized &&
                    ReferenceEquals(initializationTask, completion.Task))
                    initializationTask = null;
            }
        }
    }

    private async Task RunDisposalAsync(
        TaskCompletionSource<bool> completion,
        Task? initialization,
        Task actorDrain)
    {
        try
        {
            await DisposeCoreAsync(initialization, actorDrain)
                .ConfigureAwait(false);
            completion.TrySetResult(true);
        }
        catch (OperationCanceledException exception)
        {
            completion.TrySetCanceled(exception.CancellationToken);
        }
        catch (Exception exception)
        {
            completion.TrySetException(exception);
        }
    }

    private async Task DisposeCoreAsync(
        Task? initialization,
        Task actorDrain)
    {
        try
        {
            if (initialization is not null)
            {
                try
                {
                    await initialization.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                    when (shutdown.IsCancellationRequested)
                {
                }
            }
            await actorDrain.ConfigureAwait(false);
        }
        finally
        {
            lock (synchronization)
            {
                foreach (var entry in connections.Values)
                    entry.DisposeResolved();
            }
            if (runtime is IAsyncDisposable asyncDisposable)
                await asyncDisposable.DisposeAsync().ConfigureAwait(false);
            else if (runtime is IDisposable disposable)
                disposable.Dispose();
        }
    }

    private async Task<ConnectionHostResponse>
        ExecuteAfterInitializationAsync(
            ConnectionHostCommand command,
            CancellationToken cancellationToken)
    {
        await AwaitInitializationAsync(cancellationToken)
            .ConfigureAwait(false);
        if (command.ConnectionId is null)
            return await RunBoundedAsync(
                    token => ExecuteCoreAsync(command, token),
                    cancellationToken)
                .ConfigureAwait(false);
        return await EnqueueAsync(
                command.ConnectionId,
                token => ExecuteCoreAsync(command, token),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<T> EnqueueAfterInitializationAsync<T>(
        string connectionId,
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        await AwaitInitializationAsync(cancellationToken)
            .ConfigureAwait(false);
        return await EnqueueAsync(connectionId, action, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task AwaitInitializationAsync(
        CancellationToken cancellationToken)
    {
        Task task;
        lock (synchronization)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            task = initializationTask ??
                throw new InvalidOperationException(
                    "The connection host has not been initialized.");
        }
        await task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task InitializeCoreAsync(CancellationToken cancellationToken)
    {
        lock (synchronization)
        {
            if (initialized)
                return;
        }
        var durable = await metadata.LoadAsync(cancellationToken)
            .ConfigureAwait(false);
        if (durable.Count > ConnectionHostProtocol.MaximumConnections)
            throw new InvalidDataException(
                "The connection metadata store exceeds its bound.");
        var restored = new Dictionary<string, ConnectionEntry>(
            StringComparer.Ordinal);
        foreach (var value in durable)
        {
            ValidateDurable(value);
            if (!restored.TryAdd(
                    value.ConnectionId,
                    ConnectionEntry.Restore(value)))
                throw new InvalidDataException(
                    "The connection metadata store contains duplicate IDs.");
        }
        if (metadata is IConnectionRecoveryStore recoveryStore)
        {
            var desired = await recoveryStore.LoadDesiredAsync(
                    cancellationToken)
                .ConfigureAwait(false);
            foreach (var value in desired)
            {
                var entry = restored.GetValueOrDefault(value.ConnectionId);
                if (entry is null)
                {
                    if (restored.Count >=
                        ConnectionHostProtocol.MaximumConnections)
                        throw new InvalidDataException(
                            "The desired connection store exceeds its bound.");
                    entry = new ConnectionEntry(value.ConnectionId)
                    {
                        State = RdpDvcSessionState.Disconnected,
                        Code = "CONNECTION_HOST_RECOVERY_PENDING"
                    };
                    restored.Add(value.ConnectionId, entry);
                }
                entry.Desired = value;
            }
        }

        ConnectionEntry[] entries;
        lock (synchronization)
        {
            if (connections.Count == 0)
            {
                foreach (var pair in restored)
                    connections.Add(pair.Key, pair.Value);
            }
            entries = connections.Values.ToArray();
        }
        await Task.WhenAll(entries.Select(entry =>
                ReconcileWithBoundAsync(entry, cancellationToken)))
            .ConfigureAwait(false);
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        if (options.EnableLiveConnections)
            await Task.WhenAll(entries
                    .Where(entry => entry.Desired is
                    { DesiredHeadless: true })
                    .Select(entry => RecoverDesiredAsync(
                        entry,
                        cancellationToken)))
                .ConfigureAwait(false);
        await RecoverTransitionOutboxAsync(cancellationToken)
            .ConfigureAwait(false);
        lock (synchronization)
            initialized = true;
    }

    private async Task ReconcileWithBoundAsync(
        ConnectionEntry entry,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            shutdown.Token);
        timeout.CancelAfter(options.CommandTimeout);
        await ReconcileAsync(entry, timeout.Token).ConfigureAwait(false);
    }

    private async Task RecoverDesiredAsync(
        ConnectionEntry entry,
        CancellationToken cancellationToken)
    {
        lock (synchronization)
            if (entry.State is RdpDvcSessionState.ConnectedTransport or
                RdpDvcSessionState.Viewing or
                RdpDvcSessionState.Controlled)
                return;
        var desired = entry.Desired ??
            throw new InvalidOperationException(
                "Desired recovery requires a typed desired identity.");
        var identityStatus = await identity.StatusAsync(cancellationToken)
            .ConfigureAwait(false);
        if (identityStatus.Outcome != DevBoxConnectionIdentityOutcome.Ready ||
            resolver is not IDesiredDevBoxConnectionResolver ||
            recoveryMaterialIssuer is null)
        {
            lock (synchronization)
            {
                entry.State = RdpDvcSessionState.Disconnected;
                entry.DvcConnected = false;
                entry.Code = "CONNECTION_HOST_SILENT_AUTH_REFUSED";
                entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
            }
            await PersistAsync(cancellationToken).ConfigureAwait(false);
            return;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            shutdown.Token);
        timeout.CancelAfter(options.CommandTimeout);
        try
        {
            var target = new DesiredConnectionTarget(
                desired.DevBoxEndpoint,
                desired.Project,
                desired.User,
                desired.DevBox,
                desired.SessionId,
                desired.HostId,
                desired.NodeIncarnationId);
            var resolve = RecoveryCommand(
                ConnectionHostOperation.Resolve,
                desired.ConnectionId,
                desired: target);
            _ = await ResolveAsync(resolve, timeout.Token)
                .ConfigureAwait(false);
            _ = await PrepareAsync(
                    RecoveryCommand(
                        ConnectionHostOperation.Prepare,
                        desired.ConnectionId),
                    timeout.Token)
                .ConfigureAwait(false);
            var material = await recoveryMaterialIssuer.IssueAsync(
                    desired,
                    timeout.Token)
                .ConfigureAwait(false);
            _ = await ConnectAsync(
                    RecoveryCommand(
                        ConnectionHostOperation.Connect,
                        desired.ConnectionId,
                        material.AuthorizationToken,
                        material.EvidenceReference),
                    timeout.Token)
                .ConfigureAwait(false);
            lock (synchronization)
            {
                entry.Code = "CONNECTION_HOST_DESIRED_RECOVERED";
                entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
            }
            await PersistAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (DevBoxConnectionIdentityException)
        {
            lock (synchronization)
            {
                entry.State = RdpDvcSessionState.Disconnected;
                entry.DvcConnected = false;
                entry.Code = "CONNECTION_HOST_SILENT_AUTH_REFUSED";
                entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
            }
            await PersistAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception)
            when (exception is
                IOException or
                TimeoutException or
                UnauthorizedAccessException)
        {
            lock (synchronization)
            {
                entry.State = RdpDvcSessionState.Disconnected;
                entry.DvcConnected = false;
                entry.Code = "CONNECTION_HOST_DESIRED_RECOVERY_DEFERRED";
                entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
            }
            await PersistAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    private static ConnectionHostCommand RecoveryCommand(
        ConnectionHostOperation operation,
        string connectionId,
        string? authorizationToken = null,
        string? evidenceReference = null,
        DesiredConnectionTarget? desired = null) =>
        new(
            ConnectionHostProtocol.CurrentVersion,
            Guid.NewGuid().ToString("N"),
            operation,
            connectionId,
            AuthorizationToken: authorizationToken,
            DvcEvidenceReference: evidenceReference,
            DesiredConnection: desired);

    private async Task RecoverTransitionOutboxAsync(
        CancellationToken cancellationToken)
    {
        if (metadata is not IConnectionRecoveryStore recoveryStore)
            return;
        var pending = await recoveryStore.ReadPendingTransitionsAsync(
                1000,
                cancellationToken)
            .ConfigureAwait(false);
        foreach (var transition in pending)
            await recoveryStore.AcknowledgeTransitionAsync(
                    transition.Sequence,
                    cancellationToken)
                .ConfigureAwait(false);
    }
    private async Task<ConnectionHostResponse> ExecuteCoreAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        RequireInitialized();
        try
        {
            return command.Operation switch
            {
                ConnectionHostOperation.Status => Status(command),
                ConnectionHostOperation.Resolve =>
                    Accepted(
                        command,
                        await ResolveAsync(command, cancellationToken)
                            .ConfigureAwait(false)),
                ConnectionHostOperation.Prepare =>
                    Accepted(
                        command,
                        await PrepareAsync(command, cancellationToken)
                            .ConfigureAwait(false)),
                ConnectionHostOperation.Connect =>
                    Accepted(
                        command,
                        await ConnectAsync(command, cancellationToken)
                            .ConfigureAwait(false)),
                ConnectionHostOperation.View =>
                    Accepted(
                        command,
                        await ViewAsync(command, cancellationToken)
                            .ConfigureAwait(false)),
                ConnectionHostOperation.TakeControl =>
                    Accepted(
                        command,
                        await TakeControlAsync(command, cancellationToken)
                            .ConfigureAwait(false)),
                ConnectionHostOperation.ReleaseControl =>
                    Accepted(
                        command,
                        await ReleaseControlAsync(command, cancellationToken)
                            .ConfigureAwait(false)),
                ConnectionHostOperation.Disconnect =>
                    Accepted(
                        command,
                        await DisconnectAsync(command, cancellationToken)
                            .ConfigureAwait(false)),
                _ => Rejected(command, "CONNECTION_HOST_OPERATION_UNSUPPORTED")
            };
        }
        catch (ConnectionHostOperationException exception)
        {
            return Rejected(command, exception.Code);
        }
        catch (RdpDvcSessionTransitionException exception)
        {
            return Rejected(command, exception.Code);
        }
        catch (DevBoxConnectionIdentityException exception)
        {
            options.DiagnosticSink?.Invoke(
                $"operation-{command.Operation}-identity-" +
                $"{exception.Outcome}-" +
                SanitizeReason(exception.Message));
            return Rejected(
                command,
                $"CONNECTION_IDENTITY_{exception.Outcome.ToString().ToUpperInvariant()}");
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            return Rejected(command, "CONNECTION_HOST_OPERATION_TIMEOUT");
        }
        catch (Exception exception)
            when (exception is
                ArgumentException or
                InvalidDataException or
                InvalidOperationException or
                IOException or
                UnauthorizedAccessException)
        {
            options.DiagnosticSink?.Invoke(
                $"operation-{command.Operation}-failed-" +
                $"{exception.GetType().Name}-0x{exception.HResult:X8}-" +
                SanitizeReason(exception.Message));
            return Rejected(command, "CONNECTION_HOST_OPERATION_FAILED");
        }
    }

    private static string SanitizeReason(string message) =>
        new string(message
                .Take(160)
                .Select(character =>
                    char.IsAsciiLetterOrDigit(character) ||
                    character is ' ' or '.' or '-' or '_' or ':'
                        ? character
                        : '_')
                .ToArray())
            .Replace(' ', '_');

    private ConnectionHostResponse Status(ConnectionHostCommand command)
    {
        lock (synchronization)
        {
            if (command.ConnectionId is { } connectionId)
                return Accepted(command, Find(connectionId).Status);
            return new(
                ConnectionHostProtocol.CurrentVersion,
                command.RequestId,
                true,
                "CONNECTION_HOST_STATUS",
                Connections: connections.Values
                    .Select(value => value.Status)
                    .OrderBy(
                        value => value.ConnectionId,
                        StringComparer.Ordinal)
                    .ToArray());
        }
    }

    private async Task<ConnectionHostStatus> ResolveAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        var connectionId = RequiredConnectionId(command);
        var desired = command.DesiredConnection?.ToRecord(connectionId);
        Uri? providerResource = null;
        if (command.ProviderResource is not null &&
            !Uri.TryCreate(
                command.ProviderResource,
                UriKind.Absolute,
                out providerResource))
            throw Failure(
                "CONNECTION_HOST_PROVIDER_RESOURCE_REQUIRED",
                "Resolve requires an absolute provider resource URI.");
        if (providerResource is null && desired is null)
            throw Failure(
                "CONNECTION_HOST_PROVIDER_RESOURCE_REQUIRED",
                "Resolve requires provider material or desired identity.");
        if (desired is not null)
        {
            if (metadata is not IConnectionRecoveryStore recoveryStore)
                throw new InvalidOperationException(
                    "Desired connections require the durable recovery store.");
            await recoveryStore.UpsertDesiredAsync(
                    desired,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        ConnectionEntry entry;
        lock (synchronization)
        {
            if (!connections.TryGetValue(connectionId, out entry!))
            {
                if (connections.Count >=
                    ConnectionHostProtocol.MaximumConnections)
                    throw Failure(
                        "CONNECTION_HOST_CONNECTION_LIMIT",
                        "The connection limit has been reached.");
                entry = new ConnectionEntry(connectionId);
                connections.Add(connectionId, entry);
            }
            entry.DisposeResolved();
            if (desired is not null)
                entry.Desired = desired;
            entry.PreparedPackage = null;
            entry.Configuration = null;
            entry.Machine.BeginResolving();
            entry.Apply(entry.Machine.Snapshot);
        }

        try
        {
            var resolved = providerResource is not null
                ? await resolver.ResolveAsync(
                        providerResource,
                        cancellationToken)
                    .ConfigureAwait(false)
                : await (resolver as IDesiredDevBoxConnectionResolver ??
                        throw new DevBoxConnectionIdentityException(
                            DevBoxConnectionIdentityOutcome
                                .InteractionRequired,
                            "Silent Dev Box connection refresh is unavailable."))
                    .ResolveDesiredAsync(
                        desired ?? throw new InvalidOperationException(
                            "Desired connection identity is unavailable."),
                        cancellationToken)
                    .ConfigureAwait(false);
            lock (synchronization)
            {
                entry.Resolved = resolved;
                entry.Code = "CONNECTION_HOST_RESOLVED";
            }
        }
        catch
        {
            lock (synchronization)
                entry.Apply(
                    entry.Machine.Fail("CONNECTION_HOST_RESOLVE_FAILED"));
            await PersistAsync(cancellationToken).ConfigureAwait(false);
            throw;
        }
        try
        {
            await PersistAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            lock (synchronization)
            {
                entry.DisposeResolved();
                entry.Apply(
                    entry.Machine.Fail(
                        "CONNECTION_HOST_RESOLVE_PERSIST_FAILED"));
            }
            try
            {
                await PersistAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception exception)
                when (exception is IOException or UnauthorizedAccessException)
            {
            }
            throw;
        }
        lock (synchronization)
            return entry.Status;
    }

    private async Task<ConnectionHostStatus> PrepareAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        ConnectionEntry entry;
        lock (synchronization)
        {
            entry = Find(RequiredConnectionId(command));
            if (entry.Resolved is null ||
                entry.Machine.Snapshot.State !=
                    RdpDvcSessionState.Resolving)
                throw Failure(
                    "CONNECTION_HOST_RESOLVE_REQUIRED",
                    "Prepare requires a resolved connection.");
        }

        var identityStatus = await identity.StatusAsync(cancellationToken)
            .ConfigureAwait(false);
        if (identityStatus.Outcome != DevBoxConnectionIdentityOutcome.Ready)
            throw new DevBoxConnectionIdentityException(
                identityStatus.Outcome,
                identityStatus.Problem ??
                "The connection identity is not ready.");
        var report = compatibility.Inspect();
        if (!report.IsCompatible || report.Artifacts is null)
            throw Failure(
                "CONNECTION_HOST_RDCORE_INCOMPATIBLE",
                $"RDCore compatibility failed with {report.Code}.");
        var snapshot = registration.GetStatus();
        var configuration = new RdCoreDvcConfigurationRequest(
            silentMode: true,
            allowThirdPartyPlugins: true,
            snapshot);
        var result = RdCoreDvcContract.ValidateConfiguration(configuration);
        if (!result.Accepted)
            throw Failure(result.Code, "The DVC configuration is not ready.");
        lock (synchronization)
        {
            entry.PreparedPackage = report.Artifacts;
            entry.Configuration = configuration;
            entry.Code = "CONNECTION_HOST_PREPARED";
            entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
        }
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        lock (synchronization)
            return entry.Status;
    }

    private async Task<ConnectionHostStatus> ConnectAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        ConnectionEntry entry;
        ISensitiveRdpConnectionMaterial resolved;
        RdCorePackageArtifacts preparedPackage;
        RdCoreDvcConfigurationRequest configuration;
        lock (synchronization)
        {
            entry = Find(RequiredConnectionId(command));
            if (!options.EnableLiveConnections)
                throw Failure(
                    "CONNECTION_HOST_LIVE_CONNECT_DISABLED",
                    "Live RDCore connections are disabled.");
            resolved = entry.Resolved ??
                throw Failure(
                    "CONNECTION_HOST_PREPARE_REQUIRED",
                    "Connect requires a prepared connection.");
            preparedPackage = entry.PreparedPackage ??
                throw Failure(
                    "CONNECTION_HOST_PREPARE_REQUIRED",
                    "Connect requires a prepared connection.");
            configuration = entry.Configuration ??
                throw Failure(
                    "CONNECTION_HOST_PREPARE_REQUIRED",
                    "Connect requires a prepared connection.");
        }
        try
        {
            if (string.IsNullOrWhiteSpace(command.AuthorizationToken))
                throw Failure(
                    "CONNECTION_HOST_CONTROL_AUTHORIZATION_REQUIRED",
                    "Connect requires a Control authorization token.");
            if (string.IsNullOrWhiteSpace(command.DvcEvidenceReference))
                throw Failure(
                    "CONNECTION_HOST_DVC_EVIDENCE_REFERENCE_REQUIRED",
                    "Connect requires an opaque DVC evidence reference.");
            if (!await authorization.ConsumeAsync(
                    command.AuthorizationToken,
                    entry.ConnectionId,
                    cancellationToken).ConfigureAwait(false))
                throw Failure(
                    "CONNECTION_HOST_CONTROL_AUTHORIZATION_REJECTED",
                    "Control rejected the connection authorization token.");
        }
        catch
        {
            lock (synchronization)
            {
                entry.DisposeResolved();
                entry.PreparedPackage = null;
                entry.Configuration = null;
            }
            throw;
        }

        var attemptId = Guid.NewGuid();
        var attemptStartedAt = DateTimeOffset.UtcNow;
        if (metadata is IConnectionRecoveryStore attemptStore)
            await attemptStore.RecordAttemptAsync(
                    new(
                        attemptId,
                        entry.ConnectionId,
                        null,
                        "Connecting",
                        attemptStartedAt,
                        null),
                    cancellationToken)
                .ConfigureAwait(false);
        lock (synchronization)
        {
            entry.CurrentAttemptId = attemptId;
            entry.Machine.BeginConnectingHeadless();
            entry.Apply(entry.Machine.Snapshot);
        }
        RdCoreConnectionRuntimeResult? started = null;
        try
        {
            await using var rdp = resolved.OpenRdpContent();
            started = await runtime.ConnectAsync(
                    new(
                        entry.ConnectionId,
                        resolved.ProviderResourceUri,
                        rdp,
                        preparedPackage,
                        configuration.DvcRegistration,
                        command.DvcEvidenceReference),
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateRuntimeResult(started);
            var verified = VerifyEvidence(configuration, started);
            lock (synchronization)
            {
                entry.Machine.ConfirmConnectedTransport(verified);
                entry.RuntimeConnectionId = started.RuntimeConnectionId;
                entry.Capabilities = started.PresentationCapabilities;
                entry.Apply(entry.Machine.Snapshot);
            }
            if (metadata is IConnectionRecoveryStore successStore)
                await successStore.RecordAttemptAsync(
                        new(
                            attemptId,
                            entry.ConnectionId,
                            started.ConnectionGeneration,
                            "Connected",
                            attemptStartedAt,
                            DateTimeOffset.UtcNow),
                        cancellationToken)
                    .ConfigureAwait(false);
            await PersistAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (started is
                {
                    RuntimeConnectionId: { Length: > 0 },
                    ConnectionGeneration: > 0
                })
            {
                try
                {
                    await runtime.DisconnectAsync(
                            started.RuntimeConnectionId,
                            started.ConnectionGeneration,
                            CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception exception)
                    when (exception is
                        IOException or
                        UnauthorizedAccessException)
                {
                }
            }
            if (metadata is IConnectionRecoveryStore failureStore)
                await failureStore.RecordAttemptAsync(
                        new(
                            attemptId,
                            entry.ConnectionId,
                            started?.ConnectionGeneration,
                            "Failed",
                            attemptStartedAt,
                            DateTimeOffset.UtcNow),
                        CancellationToken.None)
                    .ConfigureAwait(false);
            lock (synchronization)
            {
                entry.RuntimeConnectionId = null;
                entry.Capabilities = null;
                if (entry.Machine.Snapshot.State is not
                    (RdpDvcSessionState.Failed or
                     RdpDvcSessionState.Disconnected))
                    entry.Apply(
                        entry.Machine.Fail(
                            "CONNECTION_HOST_CONNECT_FAILED"));
            }
            try
            {
                await PersistAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception exception)
                when (exception is IOException or UnauthorizedAccessException)
            {
            }
            throw;
        }
        finally
        {
            lock (synchronization)
            {
                entry.DisposeResolved();
                entry.PreparedPackage = null;
                entry.Configuration = null;
            }
        }
        lock (synchronization)
            return entry.Status;
    }

    private async Task<ConnectionHostStatus> ViewAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        ConnectionEntry entry;
        string runtimeId;
        long generation;
        lock (synchronization)
        {
            entry = Connected(command);
            RequireGeneration(command, entry);
            if (entry.Capabilities is not
                {
                    IsVerified: true,
                    SameConnectionView: true
                })
                throw Failure(
                    "CONNECTION_HOST_SAME_CONNECTION_VIEW_UNPROVEN",
                    "The runtime has not proved same-connection presentation.");
            generation = command.ConnectionGeneration!.Value;
            runtimeId = entry.RuntimeConnectionId!;
            entry.Machine.View(generation);
        }
        try
        {
            var proof = await runtime.ViewExistingAsync(
                    runtimeId,
                    generation,
                    cancellationToken)
                .ConfigureAwait(false);
            lock (synchronization)
            {
                ValidatePresentationProof(entry, proof);
                entry.Apply(entry.Machine.Snapshot);
            }
            await SetPresentationLeaseAsync(
                    entry.ConnectionId,
                    generation,
                    PresentationLeaseMode.View,
                    active: true,
                    cancellationToken)
                .ConfigureAwait(false);
            await PersistAsync(cancellationToken).ConfigureAwait(false);
            lock (synchronization)
                return entry.Status;
        }
        catch
        {
            lock (synchronization)
            {
                entry.Machine.CloseVisibleSurface(generation);
                entry.Apply(entry.Machine.Snapshot);
            }
            await SetPresentationLeaseAsync(
                    entry.ConnectionId,
                    generation,
                    PresentationLeaseMode.View,
                    active: false,
                    CancellationToken.None)
                .ConfigureAwait(false);
            await PersistAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<ConnectionHostStatus> TakeControlAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        ConnectionEntry entry;
        string runtimeId;
        long generation;
        lock (synchronization)
        {
            entry = Connected(command);
            RequireGeneration(command, entry);
            if (entry.Capabilities is not
                {
                    IsVerified: true,
                    SameConnectionControl: true
                })
                throw Failure(
                    "CONNECTION_HOST_SAME_CONNECTION_CONTROL_UNPROVEN",
                    "The runtime has not proved same-connection control.");
            runtimeId = entry.RuntimeConnectionId!;
            generation = command.ConnectionGeneration!.Value;
        }
        var proof = await runtime.TakeControlAsync(
                runtimeId,
                generation,
                cancellationToken)
            .ConfigureAwait(false);
        lock (synchronization)
        {
            ValidatePresentationProof(entry, proof);
            entry.Machine.TakeControl(generation);
            entry.Apply(entry.Machine.Snapshot);
        }
        await SetPresentationLeaseAsync(
                entry.ConnectionId,
                generation,
                PresentationLeaseMode.Control,
                active: true,
                cancellationToken)
            .ConfigureAwait(false);
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        lock (synchronization)
            return entry.Status;
    }

    private async Task<ConnectionHostStatus> ReleaseControlAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        ConnectionEntry entry;
        string runtimeId;
        long generation;
        lock (synchronization)
        {
            entry = Connected(command);
            RequireGeneration(command, entry);
            runtimeId = entry.RuntimeConnectionId!;
            generation = command.ConnectionGeneration!.Value;
        }
        await runtime.ReleaseControlAsync(
                runtimeId,
                generation,
                cancellationToken)
            .ConfigureAwait(false);
        lock (synchronization)
        {
            entry.Machine.ReleaseControl(generation);
            entry.Apply(entry.Machine.Snapshot);
        }
        await SetPresentationLeaseAsync(
                entry.ConnectionId,
                generation,
                PresentationLeaseMode.Control,
                active: false,
                cancellationToken)
            .ConfigureAwait(false);
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        lock (synchronization)
            return entry.Status;
    }

    private async Task<ConnectionHostStatus> DisconnectAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        ConnectionEntry entry;
        string? runtimeId;
        long? generation;
        lock (synchronization)
        {
            entry = Find(RequiredConnectionId(command));
            runtimeId = entry.RuntimeConnectionId;
            generation = entry.ConnectionGeneration;
            if (runtimeId is not null &&
                generation is { } currentGeneration &&
                command.ConnectionGeneration is { } requested &&
                requested != currentGeneration)
                throw Failure(
                    "RDP_DVC_CONNECTION_GENERATION_MISMATCH",
                    "Disconnect belongs to a stale generation.");
        }
        if (runtimeId is not null && generation is { } connectedGeneration)
            await runtime.DisconnectAsync(
                    runtimeId,
                    connectedGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
        lock (synchronization)
        {
            entry.DisposeResolved();
            entry.PreparedPackage = null;
            entry.Configuration = null;
            entry.RuntimeConnectionId = null;
            entry.Capabilities = null;
            entry.Apply(entry.Machine.Disconnect());
        }
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        lock (synchronization)
            return entry.Status;
    }

    private async Task ReconcileAsync(
        ConnectionEntry entry,
        CancellationToken cancellationToken)
    {
        string runtimeId;
        long generation;
        lock (synchronization)
        {
            if (entry.RuntimeConnectionId is not { } currentRuntimeId ||
                entry.ConnectionGeneration is not { } currentGeneration ||
                entry.State is not
                    (RdpDvcSessionState.ConnectedTransport or
                     RdpDvcSessionState.Viewing or
                     RdpDvcSessionState.Controlled or
                     RdpDvcSessionState.Reconnecting))
                return;
            runtimeId = currentRuntimeId;
            generation = currentGeneration;
        }
        var result = await runtime.ReconcileAsync(
                runtimeId,
                generation,
                cancellationToken)
            .ConfigureAwait(false);
        if (result is null)
        {
            lock (synchronization)
            {
                entry.RuntimeConnectionId = null;
                entry.ConnectionGeneration = null;
                entry.Capabilities = null;
                entry.State = RdpDvcSessionState.Disconnected;
                entry.DvcConnected = false;
                entry.Code =
                    "CONNECTION_HOST_RESTART_TRANSPORT_NOT_FOUND";
                entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
            }
            return;
        }
        ValidateRuntimeResult(result);
        if (!string.Equals(
                result.RuntimeConnectionId,
                runtimeId,
                StringComparison.Ordinal) ||
            result.ConnectionGeneration != generation)
            throw new InvalidDataException(
                "Runtime reconciliation returned a different connection.");
        var configuration = new RdCoreDvcConfigurationRequest(
            true,
            true,
            new(
                true,
                true,
                RdpDvcPluginRegistration
                    .RegisteredActivationPendingCode));
        var verified = VerifyEvidence(configuration, result);
        lock (synchronization)
        {
            entry.Machine.BeginResolving();
            entry.Machine.BeginConnectingHeadless();
            entry.Machine.ConfirmConnectedTransport(verified);
            entry.Capabilities = result.PresentationCapabilities;
            entry.Apply(entry.Machine.Snapshot);
            entry.Code = "CONNECTION_HOST_RESTART_RECONCILED";
        }
    }

    private static RdCoreDvcConfigurationResult VerifyEvidence(
        RdCoreDvcConfigurationRequest configuration,
        RdCoreConnectionRuntimeResult result)
    {
        var sequence = new RdCoreDvcEvidenceSequence(
            result.ConnectionGeneration);
        foreach (var evidence in result.Evidence)
        {
            sequence.Record(
                evidence.Event,
                evidence.PluginAddInName,
                evidence.PluginClsid,
                evidence.ChannelName);
        }
        var verified = RdCoreDvcContract.ValidateEvidence(
            configuration,
            sequence);
        if (!verified.Accepted)
            throw Failure(
                verified.Code,
                "The runtime did not supply verified DVC evidence.");
        return verified;
    }

    private static void ValidateRuntimeResult(
        RdCoreConnectionRuntimeResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (string.IsNullOrWhiteSpace(result.RuntimeConnectionId) ||
            result.RuntimeConnectionId.Length >
                ConnectionHostProtocol.MaximumConnectionIdCharacters ||
            result.RuntimeConnectionId.Any(char.IsControl) ||
            result.ConnectionGeneration <= 0 ||
            result.Evidence is null ||
            result.Evidence.Count > 32 ||
            result.PresentationCapabilities is null)
            throw new InvalidDataException(
                "The RDCore runtime returned invalid bounded metadata.");
    }

    private static void ValidatePresentationProof(
        ConnectionEntry entry,
        RdCorePresentationProof proof)
    {
        if (!string.Equals(
                proof.RuntimeConnectionId,
                entry.RuntimeConnectionId,
                StringComparison.Ordinal) ||
            proof.ConnectionGeneration != entry.ConnectionGeneration ||
            !string.Equals(
                proof.EvidenceCode,
                RdCorePresentationCapabilities.VerifiedEvidenceCode,
                StringComparison.Ordinal))
            throw Failure(
                "CONNECTION_HOST_PRESENTATION_PROOF_REJECTED",
                "The runtime presentation proof did not match the connection.");
    }

    private ConnectionEntry Connected(ConnectionHostCommand command)
    {
        var entry = Find(RequiredConnectionId(command));
        if (entry.RuntimeConnectionId is null ||
            entry.ConnectionGeneration is null)
            throw Failure(
                "CONNECTION_HOST_CONNECTED_TRANSPORT_REQUIRED",
                "The operation requires a connected transport.");
        return entry;
    }

    private static void RequireGeneration(
        ConnectionHostCommand command,
        ConnectionEntry entry)
    {
        if (command.ConnectionGeneration is not { } generation ||
            generation != entry.ConnectionGeneration)
            throw Failure(
                "RDP_DVC_CONNECTION_GENERATION_MISMATCH",
                "The operation does not belong to the current generation.");
    }

    private ConnectionEntry Find(string connectionId) =>
        connections.TryGetValue(connectionId, out var entry)
            ? entry
            : throw Failure(
                "CONNECTION_HOST_CONNECTION_NOT_FOUND",
                "The connection ID was not found.");

    private static string RequiredConnectionId(
        ConnectionHostCommand command) =>
        command.ConnectionId ??
        throw Failure(
            "CONNECTION_HOST_CONNECTION_ID_REQUIRED",
            "The operation requires a connection ID.");

    private Task SetPresentationLeaseAsync(
        string connectionId,
        long generation,
        PresentationLeaseMode mode,
        bool active,
        CancellationToken cancellationToken) =>
        metadata is IConnectionRecoveryStore recoveryStore
            ? recoveryStore.SetPresentationLeaseAsync(
                new(connectionId, generation),
                mode,
                active,
                cancellationToken)
            : Task.CompletedTask;
    private async Task PersistAsync(CancellationToken cancellationToken)
    {
        await persistenceGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            DurableConnectionMetadata[] snapshot;
            lock (synchronization)
            {
                snapshot = connections.Values
                    .Select(value => value.ToDurable())
                    .OrderBy(
                        value => value.ConnectionId,
                        StringComparer.Ordinal)
                    .ToArray();
            }
            await metadata.SaveAsync(snapshot, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            persistenceGate.Release();
        }
    }

    private static ConnectionHostResponse Accepted(
        ConnectionHostCommand command,
        ConnectionHostStatus status) =>
        new(
            ConnectionHostProtocol.CurrentVersion,
            command.RequestId,
            true,
            status.Code,
            status);

    private static ConnectionHostResponse Rejected(
        ConnectionHostCommand command,
        string code) =>
        new(
            ConnectionHostProtocol.CurrentVersion,
            command.RequestId,
            false,
            code);

    private static ConnectionHostOperationException Failure(
        string code,
        string message) =>
        new(code, message);

    private void RequireInitialized()
    {
        if (!initialized)
            throw new InvalidOperationException(
                "The connection host has not been initialized.");
    }

    private static void ValidateOptions(ConnectionHostOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.PipeName) ||
            options.PipeName.Length > 128 ||
            options.PipeName.Any(char.IsControl))
            throw new ArgumentException(
                "The connection-host pipe name is invalid.",
                nameof(options));
        if (options.CommandTimeout <= TimeSpan.Zero ||
            options.CommandTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "The command timeout is unsupported.");
    }

    private static void ValidateDurable(DurableConnectionMetadata value)
    {
        if (value.Version != ConnectionHostProtocol.CurrentVersion ||
            string.IsNullOrWhiteSpace(value.ConnectionId) ||
            value.ConnectionId.Length >
                ConnectionHostProtocol.MaximumConnectionIdCharacters ||
            value.ConnectionId.Any(char.IsControl) ||
            value.ConnectionGeneration is <= 0 ||
            value.RuntimeConnectionId is { Length: 0 } ||
            value.RuntimeConnectionId?.Length >
                ConnectionHostProtocol.MaximumConnectionIdCharacters)
            throw new InvalidDataException(
                "The connection metadata store contains invalid metadata.");
    }

    private async Task<T> RunBoundedAsync<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            shutdown.Token);
        await pendingCapacity.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            lock (synchronization)
                ObjectDisposedException.ThrowIf(disposed, this);
            return await action(linked.Token).ConfigureAwait(false);
        }
        finally
        {
            pendingCapacity.Release();
        }
    }

    private async Task<T> EnqueueAsync<T>(
        string connectionId,
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            shutdown.Token);
        var capacityAcquired = false;
        QueueRegistration queue;
        try
        {
            await pendingCapacity.WaitAsync(linked.Token).ConfigureAwait(false);
            capacityAcquired = true;
            lock (synchronization)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                if (!queues.TryGetValue(connectionId, out queue!))
                {
                    if (queues.Count >= MaximumActiveQueues)
                        throw Failure(
                            "CONNECTION_HOST_CONNECTION_LIMIT",
                            "The connection work-queue limit has been reached.");
                    queue = CreateQueue(connectionId);
                    queues.Add(connectionId, queue);
                }
                queue.PendingCount++;
            }
        }
        catch
        {
            linked.Dispose();
            if (capacityAcquired)
                pendingCapacity.Release();
            throw;
        }

        var work = new WorkItem<T>(
            action,
            cancellationToken,
            linked,
            () => CompleteQueuedWork(queue));
        try
        {
            await queue.Queue.EnqueueAsync(work, linked.Token)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
            when (exception is OperationCanceledException or
                System.Threading.Channels.ChannelClosedException)
        {
            return await work.Completion.ConfigureAwait(false);
        }
        return await work.Completion.ConfigureAwait(false);
    }

    private QueueRegistration CreateQueue(string connectionId)
    {
        var queue = new ConnectionWorkQueue(MaximumPendingWork);
        var registration = new QueueRegistration(connectionId, queue);
        activeQueueActors.Add(queue.Completion);
        _ = ObserveQueueCompletionAsync(queue.Completion);
        return registration;
    }

    private async Task ObserveQueueCompletionAsync(Task completion)
    {
        try
        {
            await completion.ConfigureAwait(false);
        }
        finally
        {
            lock (synchronization)
            {
                activeQueueActors.Remove(completion);
                if (disposed && activeQueueActors.Count == 0)
                    actorsDrained?.TrySetResult(true);
            }
        }
    }

    private void CompleteQueuedWork(QueueRegistration queue)
    {
        var completeQueue = false;
        lock (synchronization)
        {
            queue.PendingCount--;
            if (!disposed &&
                queue.PendingCount == 0 &&
                !connections.ContainsKey(queue.ConnectionId) &&
                queues.TryGetValue(queue.ConnectionId, out var current) &&
                ReferenceEquals(current, queue))
            {
                queues.Remove(queue.ConnectionId);
                completeQueue = true;
            }
        }
        if (completeQueue)
            queue.Queue.Complete();
        pendingCapacity.Release();
    }

    private sealed class QueueRegistration(
        string connectionId,
        ConnectionWorkQueue queue)
    {
        public string ConnectionId { get; } = connectionId;
        public ConnectionWorkQueue Queue { get; } = queue;
        public int PendingCount { get; set; }
    }

    private sealed class WorkItem<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken callerCancellationToken,
        CancellationTokenSource linkedCancellation,
        Action completed) : IConnectionWorkItem
    {
        private readonly TaskCompletionSource<T> completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int finished;

        public Task<T> Completion => completion.Task;

        public async Task RunAsync()
        {
            try
            {
                if (linkedCancellation.IsCancellationRequested)
                {
                    completion.TrySetCanceled(
                        callerCancellationToken.IsCancellationRequested
                            ? callerCancellationToken
                            : new CancellationToken(canceled: true));
                    return;
                }
                completion.TrySetResult(
                    await action(linkedCancellation.Token)
                        .ConfigureAwait(false));
            }
            catch (OperationCanceledException)
                when (linkedCancellation.IsCancellationRequested)
            {
                completion.TrySetCanceled(
                    callerCancellationToken.IsCancellationRequested
                        ? callerCancellationToken
                        : new CancellationToken(canceled: true));
            }
            catch (Exception exception)
            {
                completion.TrySetException(exception);
            }
            finally
            {
                Finish();
            }
        }

        public void Reject(Exception exception)
        {
            if (exception is OperationCanceledException canceled)
                completion.TrySetCanceled(canceled.CancellationToken);
            else
                completion.TrySetException(exception);
            Finish();
        }

        private void Finish()
        {
            if (Interlocked.Exchange(ref finished, 1) != 0)
                return;
            linkedCancellation.Dispose();
            completed();
        }
    }

    private sealed class ConnectionEntry
    {
        public ConnectionEntry(string connectionId)
        {
            ConnectionId = connectionId;
            UpdatedAtUtc = DateTimeOffset.UtcNow;
        }

        public string ConnectionId { get; }
        public RdpDvcSessionStateMachine Machine { get; } = new();
        public ISensitiveRdpConnectionMaterial? Resolved { get; set; }
        public DesiredConnectionRecord? Desired { get; set; }
        public Guid? CurrentAttemptId { get; set; }
        public RdCorePackageArtifacts? PreparedPackage { get; set; }
        public RdCoreDvcConfigurationRequest? Configuration { get; set; }
        public string? RuntimeConnectionId { get; set; }
        public RdCorePresentationCapabilities? Capabilities { get; set; }
        public RdpDvcSessionState State { get; set; } =
            RdpDvcSessionState.Absent;
        public long? ConnectionGeneration { get; set; }
        public bool DvcConnected { get; set; }
        public string Code { get; set; } = "RDP_DVC_ABSENT";
        public DateTimeOffset UpdatedAtUtc { get; set; }

        public ConnectionHostStatus Status =>
            new(
                ConnectionHostProtocol.CurrentVersion,
                ConnectionId,
                State,
                ConnectionGeneration,
                DvcConnected,
                Capabilities is
                {
                    IsVerified: true,
                    SameConnectionView: true
                },
                Capabilities is
                {
                    IsVerified: true,
                    SameConnectionControl: true
                },
                Code,
                UpdatedAtUtc);

        public void Apply(RdpDvcSessionSnapshot snapshot)
        {
            State = snapshot.State;
            ConnectionGeneration = snapshot.ConnectionGeneration;
            DvcConnected = snapshot.DvcConnected;
            Code = snapshot.Code;
            UpdatedAtUtc = DateTimeOffset.UtcNow;
        }

        public void DisposeResolved()
        {
            Resolved?.Dispose();
            Resolved = null;
        }

        public DurableConnectionMetadata ToDurable() =>
            new(
                ConnectionHostProtocol.CurrentVersion,
                ConnectionId,
                State,
                ConnectionGeneration,
                RuntimeConnectionId,
                Capabilities is
                {
                    IsVerified: true,
                    SameConnectionView: true
                },
                Capabilities is
                {
                    IsVerified: true,
                    SameConnectionControl: true
                },
                Code,
                UpdatedAtUtc);

        public static ConnectionEntry Restore(
            DurableConnectionMetadata value) =>
            new(value.ConnectionId)
            {
                State = value.State,
                ConnectionGeneration = value.ConnectionGeneration,
                RuntimeConnectionId = value.RuntimeConnectionId,
                Capabilities = new(
                    value.ViewSupported,
                    value.ControlSupported,
                    value.ViewSupported || value.ControlSupported
                        ? RdCorePresentationCapabilities.VerifiedEvidenceCode
                        : "RDCORE_PRESENTATION_UNPROVEN"),
                DvcConnected = value.State is
                    (RdpDvcSessionState.ConnectedTransport or
                     RdpDvcSessionState.Viewing or
                     RdpDvcSessionState.Controlled),
                Code = value.Code,
                UpdatedAtUtc = value.UpdatedAtUtc
            };
    }
}
