using System.Runtime.Versioning;
using Steward.Domain;
using Steward.Maintenance.Windows;
using Steward.Node;
using Steward.Orchestration;
using Steward.PortableState;
using Steward.Runtime.Windows;
using Steward.Stack.Local;
using Steward.Tasks.Abstractions;
using Steward.Tasks.Agent;
using Steward.Tasks.Compose;
using Steward.Tasks.Process;
using Steward.Terminal.Windows;
using Steward.Transport;
using Steward.Workloads.Evals;

namespace Steward.Node.Host;

/// <summary>
/// Owns the full set of durable production Node services (journal, executor, spool,
/// terminal, identity, eval store, processor) and can run sessions over any
/// <see cref="ITransportConnection"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProductionNodeRuntime : IAsyncDisposable
{
    private readonly NodeJournal _journal;
    private readonly NodeCommandProcessor _processor;
    private readonly LocalPortableTransferClient _portableTransfer;
    private readonly DirectSessionNodeIdentityClient _identityClient;
    private readonly TerminalSessionService _terminalService;
    private readonly NamedPipeJobHandleKeeper _keeper;
    private readonly WindowsProcessExecutor _executor;

    private ProductionNodeRuntime(
        NodeJournal journal,
        NodeCommandProcessor processor,
        LocalPortableTransferClient portableTransfer,
        DirectSessionNodeIdentityClient identityClient,
        TerminalSessionService terminalService,
        NamedPipeJobHandleKeeper keeper,
        WindowsProcessExecutor executor)
    {
        _journal = journal;
        _processor = processor;
        _portableTransfer = portableTransfer;
        _identityClient = identityClient;
        _terminalService = terminalService;
        _keeper = keeper;
        _executor = executor;
    }

    /// <summary>The Node incarnation identity from the journal.</summary>
    public NodeIncarnationId IncarnationId => _journal.Identity.IncarnationId;

    /// <summary>The host identity this runtime is configured for.</summary>
    public HostId HostId { get; private set; }

    /// <summary>
    /// Creates a fully-wired production Node runtime from validated options.
    /// The caller owns disposal via <see cref="IAsyncDisposable"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static async Task<ProductionNodeRuntime> CreateAsync(
        ValidatedNodeHostOptions options,
        string credentialVaultRoot,
        IPortableObjectStore portableStore,
        LocalPortableTransferClient portableTransfer,
        Action<string>? taskReadinessDiagnostic = null,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "The production Node runtime requires Windows.");

        var boot = LoadBootIdentity($"{options.JournalPath}.boot.json");
        var journal = new NodeJournal(options.JournalPath);
        try
        {
            await journal.InitializeAsync(
                options.IncarnationId, boot.Id, false, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await journal.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        NamedPipeJobHandleKeeper? keeper = null;
        WindowsProcessExecutor? executor = null;
        TerminalSessionService? terminalService = null;
        NodeCommandProcessor? processor = null;
        try
        {
            var executionJournal = new ExecutionJournal(
                options.ExecutionJournalPath);
            keeper = new NamedPipeJobHandleKeeper(
                new(
                    options.KeeperPipeName,
                    TimeSpan.FromSeconds(3),
                    ConnectAttempts: 5));
            executor = new WindowsProcessExecutor(
                executionJournal,
                keeper,
                options.IncarnationId,
                boot.Id.ToString("D"),
                bootIdentityVerified: boot.Verified);
            var evaluations = new SqliteEvaluationStore(
                options.EvaluationDatabasePath);
            var spool = new DiskSpool(new()
            {
                RootPath = options.SpoolRoot,
                HighLimitBytes = options.SpoolHighLimitBytes,
                HardLimitBytes = options.SpoolHardLimitBytes,
                OsReserveBytes = options.SpoolOsReserveBytes
            });
            var uploader = new PortableObjectUploader(portableStore);
            var localPortablePublisher = new SpoolingTaskPortablePublisher(
                spool,
                uploader);
            var portablePublisher = new LocalReplicatingTaskPortablePublisher(
                localPortablePublisher,
                portableStore,
                portableTransfer);
            var terminalJournal = new TerminalJournal(
                options.TerminalJournalPath);
            var terminalRevocations = new DurableTerminalRevocationStore(
                $"{options.TerminalJournalPath}.revocations.db");
            terminalService = new TerminalSessionService(
                terminalJournal,
                options.HostId,
                options.IncarnationId,
                boot.Id.ToString("D"),
                options: new(
                    MaximumConcurrentSessions:
                        options.MaximumTerminalSessions),
                currentRevocationRevision:
                    () => terminalRevocations.CurrentRevision);

            var taskTypes = new List<ITaskType>
            {
                new ProcessTaskType(
                    executor,
                    message => taskReadinessDiagnostic?.Invoke(message)),
                new ComposeTaskType(executor),
                new EvaluationRunnerTaskType(
                    executor,
                    evaluations,
                    evaluations,
                    resultWriter: evaluations),
                new EvaluationReducerTaskType(evaluations)
            };
            if (options.AgentsEnabled)
                taskTypes.Add(new AgentTurnTaskType(
                    executor,
                    new AgentTurnStateStore(
                        $"{options.EvaluationDatabasePath}.agent-turns.db"),
                    options.AgentExecutable!,
                    options.AgentRuntimeProfile));

            var identityClient = new DirectSessionNodeIdentityClient(
                options.HostId);
            var identityVault = new DpapiProtectedIdentityVault(
                Path.Combine(credentialVaultRoot, "node"));
            ITaskIdentityResolver identityResolver =
                new DirectSessionTaskIdentityResolver(
                    identityVault,
                    identityClient);

            processor = new NodeCommandProcessor(
                journal,
                new TaskTypeRegistry(taskTypes),
                new(options.WorkspaceRoot),
                identityResolver: identityResolver,
                portablePublisher: portablePublisher,
                terminal: new NodeTerminalCommandProcessor(
                    terminalService,
                    terminalRevocations),
                rateFeedback: evaluations,
                auxiliaryHandlers: [portableTransfer, identityClient],
                maintenance: new NodeMaintenanceCommandHandler(
                    options.HostId,
                    options.IncarnationId,
                    new NamedPipeLocalMaintenanceForwarder(
                        MaintenanceContract.LocalPipeName,
                        TimeSpan.FromSeconds(30),
                        Path.Combine(
                            Path.GetDirectoryName(options.JournalPath) ??
                                throw new InvalidDataException(
                                    "Node journal has no state root."),
                            "keys",
                            "rdp-dvc.key"))));

            return new ProductionNodeRuntime(
                journal,
                processor,
                portableTransfer,
                identityClient,
                terminalService,
                keeper,
                executor)
            {
                HostId = options.HostId
            };
        }
        catch
        {
            if (processor is not null)
                await processor.DisposeAsync().ConfigureAwait(false);
            if (terminalService is not null)
                await terminalService.DisposeAsync().ConfigureAwait(false);
            executor?.Dispose();
            keeper?.Dispose();
            await journal.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Builds a <see cref="SessionHello"/> using the current journal stream cursors.
    /// </summary>
    public async Task<SessionHello> CreateSessionHelloAsync(
        Guid sessionId,
        IReadOnlySet<string> supportedFeatures,
        IReadOnlySet<string> requiredFeatures,
        TransportLimits limits,
        CancellationToken cancellationToken = default)
    {
        var cursors = await _journal.GetStreamCursorsAsync(cancellationToken)
            .ConfigureAwait(false);
        return new SessionHello(
            sessionId,
            IncarnationId,
            1, 0,
            supportedFeatures,
            requiredFeatures,
            cursors,
            limits);
    }

    /// <summary>
    /// Runs a single Node command-processing session over the supplied connection.
    /// The connection must already be secure and negotiated.
    /// Attaches portable-transfer and identity auxiliary streams for the session lifetime.
    /// </summary>
    public async Task RunSessionAsync(
        ITransportConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        using var portableSession = _portableTransfer.Attach(connection);
        using var identitySession = _identityClient.Attach(connection);
        await _processor.RunSessionAsync(connection, cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await _processor.DisposeAsync().ConfigureAwait(false);
        await _terminalService.DisposeAsync().ConfigureAwait(false);
        _executor.Dispose();
        _keeper.Dispose();
        await _journal.DisposeAsync().ConfigureAwait(false);
    }

    private static RuntimeBootIdentity LoadBootIdentity(string path)
    {
        var evidence = WindowsBootIdentity.Capture();
        if (evidence.Verified && File.Exists(path))
        {
            try
            {
                var stored = System.Text.Json.JsonSerializer
                    .Deserialize<BootRecord>(File.ReadAllText(path));
                if (stored is not null &&
                    stored.Id != Guid.Empty &&
                    stored.Verified &&
                    string.Equals(
                        stored.SystemBootIdentity,
                        evidence.Identity,
                        StringComparison.Ordinal))
                    return new RuntimeBootIdentity(stored.Id, true);
            }
            catch (System.Text.Json.JsonException)
            {
            }
        }
        var record = new BootRecord(
            Guid.NewGuid(),
            evidence.Identity,
            evidence.Verified,
            evidence.Source);
        Directory.CreateDirectory(
            Path.GetDirectoryName(Path.GetFullPath(path))!);
        var pending = $"{path}.{Guid.NewGuid():N}.new";
        File.WriteAllText(
            pending,
            System.Text.Json.JsonSerializer.Serialize(record));
        File.Move(pending, path, true);
        return new RuntimeBootIdentity(record.Id, record.Verified);
    }

    private sealed record RuntimeBootIdentity(Guid Id, bool Verified);

    private sealed record BootRecord(
        Guid Id,
        string? SystemBootIdentity = null,
        bool Verified = false,
        string? Source = null);
}
