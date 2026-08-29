using System.Threading.Channels;
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
    private readonly ConnectionHostOptions options;
    private readonly IDevBoxConnectionIdentityGate identity;
    private readonly IDevBoxConnectionResolver resolver;
    private readonly IRdCoreCompatibilityInspector compatibility;
    private readonly IDvcRegistrationSnapshotProvider registration;
    private readonly IRdCoreConnectionRuntime runtime;
    private readonly IControlConnectAuthorizationValidator authorization;
    private readonly IConnectionMetadataStore metadata;
    private readonly Channel<IWorkItem> queue;
    private readonly Dictionary<string, ConnectionEntry> connections =
        new(StringComparer.Ordinal);
    private readonly Task actor;
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
        IConnectionMetadataStore metadata)
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
        ValidateOptions(options);
        queue = Channel.CreateBounded<IWorkItem>(
            new BoundedChannelOptions(256)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait
            });
        actor = RunActorAsync();
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

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        EnqueueAsync(InitializeCoreAsync, cancellationToken);

    public Task<ConnectionHostResponse> ExecuteAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken = default)
    {
        ConnectionHostProtocol.Validate(command);
        return EnqueueAsync(
            token => ExecuteCoreAsync(command, token),
            cancellationToken);
    }

    public Task<ConnectionHostStatus> NotifyViewClosedAsync(
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken = default) =>
        EnqueueAsync(
            async token =>
            {
                RequireInitialized();
                var entry = Find(connectionId);
                entry.Machine.CloseVisibleSurface(connectionGeneration);
                entry.Apply(entry.Machine.Snapshot);
                await PersistAsync(token).ConfigureAwait(false);
                return entry.Status;
            },
            cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (disposed)
            return;
        disposed = true;
        queue.Writer.TryComplete();
        await actor.ConfigureAwait(false);
        if (runtime is IAsyncDisposable asyncDisposable)
            await asyncDisposable.DisposeAsync().ConfigureAwait(false);
        else if (runtime is IDisposable disposable)
            disposable.Dispose();
    }

    private async Task InitializeCoreAsync(CancellationToken cancellationToken)
    {
        if (initialized)
            return;
        var durable = await metadata.LoadAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var value in durable)
        {
            ValidateDurable(value);
            if (connections.Count >= ConnectionHostProtocol.MaximumConnections)
                throw new InvalidDataException(
                    "The connection metadata store exceeds its bound.");
            if (!connections.TryAdd(
                    value.ConnectionId,
                    ConnectionEntry.Restore(value)))
                throw new InvalidDataException(
                    "The connection metadata store contains duplicate IDs.");
        }

        foreach (var entry in connections.Values)
            await ReconcileAsync(entry, cancellationToken)
                .ConfigureAwait(false);
        initialized = true;
        await PersistAsync(cancellationToken).ConfigureAwait(false);
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
        if (command.ConnectionId is { } connectionId)
            return Accepted(command, Find(connectionId).Status);
        return new(
            ConnectionHostProtocol.CurrentVersion,
            command.RequestId,
            true,
            "CONNECTION_HOST_STATUS",
            Connections: connections.Values
                .Select(value => value.Status)
                .OrderBy(value => value.ConnectionId, StringComparer.Ordinal)
                .ToArray());
    }

    private async Task<ConnectionHostStatus> ResolveAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        var connectionId = RequiredConnectionId(command);
        if (!Uri.TryCreate(
                command.ProviderResource,
                UriKind.Absolute,
                out var providerResource))
            throw Failure(
                "CONNECTION_HOST_PROVIDER_RESOURCE_REQUIRED",
                "Resolve requires an absolute provider resource URI.");
        if (!connections.TryGetValue(connectionId, out var entry))
        {
            if (connections.Count >= ConnectionHostProtocol.MaximumConnections)
                throw Failure(
                    "CONNECTION_HOST_CONNECTION_LIMIT",
                    "The connection limit has been reached.");
            entry = new ConnectionEntry(connectionId);
            connections.Add(connectionId, entry);
        }
        entry.DisposeResolved();
        entry.PreparedPackage = null;
        entry.Configuration = null;
        entry.Machine.BeginResolving();
        entry.Apply(entry.Machine.Snapshot);
        try
        {
            entry.Resolved = await resolver.ResolveAsync(
                    providerResource,
                    cancellationToken)
                .ConfigureAwait(false);
            entry.Code = "CONNECTION_HOST_RESOLVED";
        }
        catch
        {
            entry.Apply(entry.Machine.Fail("CONNECTION_HOST_RESOLVE_FAILED"));
            await PersistAsync(cancellationToken).ConfigureAwait(false);
            throw;
        }
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        return entry.Status;
    }

    private async Task<ConnectionHostStatus> PrepareAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        var entry = Find(RequiredConnectionId(command));
        if (entry.Resolved is null ||
            entry.Machine.Snapshot.State != RdpDvcSessionState.Resolving)
            throw Failure(
                "CONNECTION_HOST_RESOLVE_REQUIRED",
                "Prepare requires a resolved connection.");
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
        entry.PreparedPackage = report.Artifacts;
        entry.Configuration = configuration;
        entry.Code = "CONNECTION_HOST_PREPARED";
        entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        return entry.Status;
    }

    private async Task<ConnectionHostStatus> ConnectAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        var entry = Find(RequiredConnectionId(command));
        if (!options.EnableLiveConnections)
            throw Failure(
                "CONNECTION_HOST_LIVE_CONNECT_DISABLED",
                "Live RDCore connections are disabled.");
        if (entry.Resolved is null ||
            entry.PreparedPackage is null ||
            entry.Configuration is null)
            throw Failure(
                "CONNECTION_HOST_PREPARE_REQUIRED",
                "Connect requires a prepared connection.");
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

        entry.Machine.BeginConnectingHeadless();
        entry.Apply(entry.Machine.Snapshot);
        RdCoreConnectionRuntimeResult? started = null;
        try
        {
            await using var rdp = entry.Resolved.OpenRdpContent();
            started = await runtime.ConnectAsync(
                    new(
                        entry.ConnectionId,
                        entry.Resolved.ProviderResourceUri,
                        rdp,
                        entry.PreparedPackage,
                        entry.Configuration.DvcRegistration,
                        command.DvcEvidenceReference),
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateRuntimeResult(started);
            var verified = VerifyEvidence(entry.Configuration, started);
            entry.Machine.ConfirmConnectedTransport(verified);
            entry.RuntimeConnectionId = started.RuntimeConnectionId;
            entry.Capabilities = started.PresentationCapabilities;
            entry.Apply(entry.Machine.Snapshot);
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
                        InvalidOperationException or
                        IOException or
                        UnauthorizedAccessException)
                {
                }
            }
            entry.RuntimeConnectionId = null;
            entry.Capabilities = null;
            if (entry.Machine.Snapshot.State is not
                (RdpDvcSessionState.Failed or
                 RdpDvcSessionState.Disconnected))
                entry.Apply(
                    entry.Machine.Fail(
                        "CONNECTION_HOST_CONNECT_FAILED"));
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
            entry.DisposeResolved();
            entry.PreparedPackage = null;
            entry.Configuration = null;
        }
        return entry.Status;
    }

    private async Task<ConnectionHostStatus> ViewAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        var entry = Connected(command);
        RequireGeneration(command, entry);
        if (entry.Capabilities is not
            {
                IsVerified: true,
                SameConnectionView: true
            })
            throw Failure(
                "CONNECTION_HOST_SAME_CONNECTION_VIEW_UNPROVEN",
                "The runtime has not proved same-connection presentation.");
        entry.Machine.View(command.ConnectionGeneration!.Value);
        try
        {
            var proof = await runtime.ViewExistingAsync(
                    entry.RuntimeConnectionId!,
                    command.ConnectionGeneration.Value,
                    cancellationToken)
                .ConfigureAwait(false);
            ValidatePresentationProof(entry, proof);
            entry.Apply(entry.Machine.Snapshot);
            await PersistAsync(cancellationToken).ConfigureAwait(false);
            return entry.Status;
        }
        catch
        {
            entry.Machine.CloseVisibleSurface(
                command.ConnectionGeneration.Value);
            entry.Apply(entry.Machine.Snapshot);
            await PersistAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<ConnectionHostStatus> TakeControlAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        var entry = Connected(command);
        RequireGeneration(command, entry);
        if (entry.Capabilities is not
            {
                IsVerified: true,
                SameConnectionControl: true
            })
            throw Failure(
                "CONNECTION_HOST_SAME_CONNECTION_CONTROL_UNPROVEN",
                "The runtime has not proved same-connection control.");
        var proof = await runtime.TakeControlAsync(
                entry.RuntimeConnectionId!,
                command.ConnectionGeneration!.Value,
                cancellationToken)
            .ConfigureAwait(false);
        ValidatePresentationProof(entry, proof);
        entry.Machine.TakeControl(command.ConnectionGeneration.Value);
        entry.Apply(entry.Machine.Snapshot);
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        return entry.Status;
    }

    private async Task<ConnectionHostStatus> ReleaseControlAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        var entry = Connected(command);
        RequireGeneration(command, entry);
        await runtime.ReleaseControlAsync(
                entry.RuntimeConnectionId!,
                command.ConnectionGeneration!.Value,
                cancellationToken)
            .ConfigureAwait(false);
        entry.Machine.ReleaseControl(command.ConnectionGeneration.Value);
        entry.Apply(entry.Machine.Snapshot);
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        return entry.Status;
    }

    private async Task<ConnectionHostStatus> DisconnectAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        var entry = Find(RequiredConnectionId(command));
        if (entry.RuntimeConnectionId is { } runtimeId &&
            entry.ConnectionGeneration is { } generation)
        {
            if (command.ConnectionGeneration is { } requested &&
                requested != generation)
                throw Failure(
                    "RDP_DVC_CONNECTION_GENERATION_MISMATCH",
                    "Disconnect belongs to a stale generation.");
            await runtime.DisconnectAsync(
                    runtimeId,
                    generation,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        entry.DisposeResolved();
        entry.PreparedPackage = null;
        entry.Configuration = null;
        entry.RuntimeConnectionId = null;
        entry.Capabilities = null;
        entry.Apply(entry.Machine.Disconnect());
        await PersistAsync(cancellationToken).ConfigureAwait(false);
        return entry.Status;
    }

    private async Task ReconcileAsync(
        ConnectionEntry entry,
        CancellationToken cancellationToken)
    {
        if (entry.RuntimeConnectionId is not { } runtimeId ||
            entry.ConnectionGeneration is not { } generation ||
            entry.State is not
                (RdpDvcSessionState.ConnectedTransport or
                 RdpDvcSessionState.Viewing or
                 RdpDvcSessionState.Controlled or
                 RdpDvcSessionState.Reconnecting))
            return;
        var result = await runtime.ReconcileAsync(
                runtimeId,
                generation,
                cancellationToken)
            .ConfigureAwait(false);
        if (result is null)
        {
            entry.RuntimeConnectionId = null;
            entry.ConnectionGeneration = null;
            entry.Capabilities = null;
            entry.State = RdpDvcSessionState.Disconnected;
            entry.DvcConnected = false;
            entry.Code = "CONNECTION_HOST_RESTART_TRANSPORT_NOT_FOUND";
            entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
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
        entry.Machine.BeginResolving();
        entry.Machine.BeginConnectingHeadless();
        entry.Machine.ConfirmConnectedTransport(
            VerifyEvidence(configuration, result));
        entry.Capabilities = result.PresentationCapabilities;
        entry.Apply(entry.Machine.Snapshot);
        entry.Code = "CONNECTION_HOST_RESTART_RECONCILED";
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

    private async Task PersistAsync(CancellationToken cancellationToken)
    {
        await metadata.SaveAsync(
                connections.Values
                    .Select(value => value.ToDurable())
                    .OrderBy(value => value.ConnectionId, StringComparer.Ordinal)
                    .ToArray(),
                cancellationToken)
            .ConfigureAwait(false);
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

    private async Task RunActorAsync()
    {
        await foreach (var work in queue.Reader.ReadAllAsync()
                           .ConfigureAwait(false))
            await work.RunAsync().ConfigureAwait(false);
        foreach (var entry in connections.Values)
            entry.DisposeResolved();
    }

    private async Task<T> EnqueueAsync<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var work = new WorkItem<T>(action, cancellationToken);
        await queue.Writer.WriteAsync(work, cancellationToken)
            .ConfigureAwait(false);
        return await work.Completion.ConfigureAwait(false);
    }

    private Task EnqueueAsync(
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken) =>
        EnqueueAsync(
            async token =>
            {
                await action(token).ConfigureAwait(false);
                return true;
            },
            cancellationToken);

    private interface IWorkItem
    {
        Task RunAsync();
    }

    private sealed class WorkItem<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken) : IWorkItem
    {
        private readonly TaskCompletionSource<T> completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<T> Completion => completion.Task;

        public async Task RunAsync()
        {
            if (cancellationToken.IsCancellationRequested)
            {
                completion.TrySetCanceled(cancellationToken);
                return;
            }
            try
            {
                completion.TrySetResult(
                    await action(cancellationToken).ConfigureAwait(false));
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                completion.TrySetCanceled(cancellationToken);
            }
            catch (Exception exception)
            {
                completion.TrySetException(exception);
            }
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
