using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.Node;
using Steward.Tasks.Abstractions;
using Steward.Transport;

namespace Steward.Orchestration;

public sealed class NodeCommandProcessor : IAsyncDisposable
{
    private readonly NodeJournal journal;
    private readonly ITaskTypeRegistry registry;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan observationInterval;
    private readonly string workspaceRoot;
    private readonly ITaskIdentityResolver identityResolver;
    private readonly ITaskPortablePublisher? portablePublisher;
    private readonly NodeTerminalCommandProcessor? terminal;
    private readonly INodeRateFeedbackSource? rateFeedback;
    private readonly IReadOnlyDictionary<StreamKind, IAuxiliaryTransportStreamHandler>
        auxiliaryHandlers;
    private readonly ConcurrentDictionary<TaskAttemptId, RunningAttempt> attempts = [];
    private readonly ConcurrentDictionary<CommandId, Task> commandTasks = [];
    private readonly ConcurrentDictionary<TaskAttemptId, byte> completedAttempts = [];
    private readonly SemaphoreSlim recoveryGate = new(1, 1);
    private readonly CancellationTokenSource lifetime = new();
    private bool recoveryCompleted;

    public NodeCommandProcessor(
        NodeJournal journal,
        ITaskTypeRegistry registry,
        NodeExecutionOptions options,
        TimeProvider? timeProvider = null,
        TimeSpan? observationInterval = null,
        ITaskIdentityResolver? identityResolver = null,
        ITaskPortablePublisher? portablePublisher = null,
        NodeTerminalCommandProcessor? terminal = null,
        INodeRateFeedbackSource? rateFeedback = null,
        IEnumerable<IAuxiliaryTransportStreamHandler>? auxiliaryHandlers = null)
    {
        this.journal = journal ?? throw new ArgumentNullException(nameof(journal));
        this.registry = registry ?? throw new ArgumentNullException(nameof(registry));
        workspaceRoot = options?.ValidateAndGetRoot() ?? throw new ArgumentNullException(nameof(options));
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.observationInterval = observationInterval ?? TimeSpan.FromMilliseconds(25);
        this.identityResolver = identityResolver ?? new NoIdentityTaskResolver();
        this.portablePublisher = portablePublisher;
        this.terminal = terminal;
        this.rateFeedback = rateFeedback;
        this.auxiliaryHandlers =
            AuxiliaryTransportStreamHandlers.Index(auxiliaryHandlers);
        if (this.observationInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(observationInterval));
    }

    public async Task RunSessionAsync(ITransportConnection connection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (connection.Session.NodeIncarnationId != journal.Identity.IncarnationId)
            throw new InvalidOperationException("Transport session targets another Node incarnation.");
        await journal.BeginSessionAsync(
            connection.Session.SessionId, connection.Session.NodeIncarnationId, cancellationToken).ConfigureAwait(false);
        await RecoverDurableAttemptsAsync(cancellationToken).ConfigureAwait(false);

        using var sessionCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var receive = ReceiveCommandsAsync(connection, sessionCancellation.Token);
        var send = SendFactsAsync(connection, sessionCancellation.Token);
        await Task.WhenAny(receive, send).ConfigureAwait(false);
        sessionCancellation.Cancel();
        try { await Task.WhenAll(receive, send).ConfigureAwait(false); }
        catch (OperationCanceledException) when (sessionCancellation.IsCancellationRequested) { }
    }

    public async Task RecoverDurableAttemptsAsync(CancellationToken cancellationToken = default)
    {
        await recoveryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (recoveryCompleted) return;
            foreach (var persisted in await journal.ReadNonterminalAttemptContextsAsync(cancellationToken)
                         .ConfigureAwait(false))
                await RecoverPersistedAsync(persisted, cancellationToken).ConfigureAwait(false);
            recoveryCompleted = true;
        }
        finally { recoveryGate.Release(); }
    }

    public async Task WaitForAttemptsAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var running = attempts.Values.Select(x => x.Completion).ToArray();
            var commands = commandTasks.Values.ToArray();
            if (running.Length == 0 && commands.Length == 0) return;
            await Task.WhenAll(running.Concat(commands)).WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ReceiveCommandsAsync(ITransportConnection connection, CancellationToken cancellationToken)
    {
        await foreach (var frame in connection.ReceiveAsync(cancellationToken).ConfigureAwait(false))
        {
            if (frame.Stream == StreamKind.Terminal)
            {
                if (terminal is null)
                    throw new OrchestrationMessageException("Terminal capability is unavailable on this Node.");
                await terminal.ProcessAsync(connection, frame, cancellationToken);
                await journal.SetStreamCursorAsync(frame.Stream, frame.Cursor, cancellationToken);
                continue;
            }
            if (auxiliaryHandlers.TryGetValue(frame.Stream, out var handler))
            {
                await handler.HandleAsync(
                    connection, frame, cancellationToken).ConfigureAwait(false);
                if (frame.Stream != StreamKind.Identity)
                    await journal.SetStreamCursorAsync(
                        frame.Stream, frame.Cursor, cancellationToken)
                        .ConfigureAwait(false);
                continue;
            }
            if (frame.Stream != StreamKind.Control)
                throw new OrchestrationMessageException("Node accepts orchestration messages only on Control or Terminal.");
            var decoded = OrchestrationMessageCodec.Decode(frame.Payload);
            switch (decoded.Value)
            {
                case DelegationMessage delegation:
                    await journal.AcceptDelegationAsync(delegation.Delegation, cancellationToken).ConfigureAwait(false);
                    await EmitAsync(OrchestrationMessageKinds.DelegationAccepted,
                        new DelegationAcceptedFact(
                            delegation.Delegation.DelegationId,
                            delegation.Delegation.HostId,
                            delegation.Delegation.NodeIncarnationId),
                        cancellationToken).ConfigureAwait(false);
                    break;
                case ExecuteTaskMessage execute:
                    Track(execute.Command.CommandId, AcceptExecuteAsync(execute));
                    break;
                case CancelTaskMessage cancel:
                    Track(cancel.Command.CommandId, ProcessCancelAsync(cancel));
                    break;
                case FactAcknowledgementMessage acknowledgement:
                    await journal.AcknowledgeFactsAsync(
                        connection.Session.SessionId,
                        connection.Session.NodeIncarnationId,
                        acknowledgement.ThroughCursor,
                        cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    throw new OrchestrationMessageException(
                        $"Message '{decoded.Kind}' is not valid Control-to-Node traffic.");
            }
            await journal.SetStreamCursorAsync(frame.Stream, frame.Cursor, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SendFactsAsync(ITransportConnection connection, CancellationToken cancellationToken)
    {
        var cursor = connection.Session.RemoteResumeCursors.GetValueOrDefault(StreamKind.Events, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            if (rateFeedback is not null)
                foreach (var feedback in await rateFeedback.ReadPendingAsync(100, cancellationToken))
                {
                    await EmitAsync(
                        OrchestrationMessageKinds.RateFeedback, feedback, cancellationToken);
                    await rateFeedback.MarkProcessedAsync(
                        feedback.FeedbackSequence, cancellationToken);
                }
            var facts = await journal.ReadFactsAfterAsync(cursor, 128, cancellationToken).ConfigureAwait(false);
            if (facts.Count == 0)
            {
                await Task.Delay(observationInterval, timeProvider, cancellationToken).ConfigureAwait(false);
                continue;
            }
            foreach (var fact in facts)
            {
                var value = OrchestrationMessageCodec.DecodeJournaledFact(fact.FactType, fact.PayloadJson);
                var payload = OrchestrationMessageCodec.Encode(value, fact.ObservedAt);
                await connection.SendAsync(new(
                    connection.Session.SessionId,
                    connection.Session.NodeIncarnationId,
                    StreamKind.Events,
                    fact.Sequence,
                    fact.Sequence,
                    payload), cancellationToken).ConfigureAwait(false);
                cursor = fact.Sequence;
            }
        }
    }

    private async Task AcceptExecuteAsync(ExecuteTaskMessage message)
    {
        try
        {
            var command = await journal.ReserveOrchestrationCommandAsync(message.Command).ConfigureAwait(false);
            if (!command.IsNew)
            {
                if (command.Outcome.Status == "reserved" &&
                    !attempts.ContainsKey(message.Identity.AttemptId))
                {
                    var persisted = (await journal.ReadNonterminalAttemptContextsAsync().ConfigureAwait(false))
                        .SingleOrDefault(x => x.AttemptId == message.Identity.AttemptId);
                    if (persisted is not null)
                        await RecoverPersistedAsync(persisted, CancellationToken.None).ConfigureAwait(false);
                }
                return;
            }

            var contextJson = JsonSerializer.Serialize(message, StewardJson.Options);
            await journal.RecordAttemptContextAsync(
                message.Identity.AttemptId,
                message.Identity.Generation,
                message.Command.CommandId,
                contextJson).ConfigureAwait(false);
            PreparedTask prepared;
            try
            {
                prepared = Prepare(message);
            }
            catch (Exception exception) when (exception is ArgumentException or
                                             KeyNotFoundException or
                                             UnauthorizedAccessException or IOException)
            {
                var error = OrchestrationErrors.Recovery(exception);
                await RecordRejectedBeforeAuthorityAsync(message, error.Code).ConfigureAwait(false);
                return;
            }
            StartAuthorityReservation reservation;
            try
            {
                reservation = await journal.ReserveStartAuthorityAsync(
                    message.Identity.AttemptId,
                    message.Identity.DelegationId,
                    message.Identity.TaskId,
                    message.Identity.Generation,
                    ToDomain(message.Resources),
                    message.RateRequirements,
                    message.IdentityGrantIds,
                    timeProvider.GetUtcNow()).ConfigureAwait(false);
            }
            catch (DomainRuleViolationException exception)
            {
                await RecordRejectedBeforeAuthorityAsync(
                    message, $"authority.{exception.Code.ToString().ToLowerInvariant()}").ConfigureAwait(false);
                return;
            }
            var delegation = await journal.GetDelegationAsync(message.Identity.DelegationId).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Accepted Delegation disappeared after authority reservation.");
            TaskIdentityLease identityLease;
            try { identityLease = await ResolveIdentitiesAsync(message).ConfigureAwait(false); }
            catch (IdentityResolutionException exception)
            {
                await RecordIdentityFailureAsync(
                    message, reservation, delegation.AuthorityExpiresAt, exception).ConfigureAwait(false);
                return;
            }
            prepared = prepared with
            {
                Context = prepared.Context with { IdentityHandles = identityLease.Handles }
            };
            var running = new RunningAttempt(
                message, prepared.Type, reservation, delegation.AuthorityExpiresAt,
                prepared.Context, identityLease);
            if (!attempts.TryAdd(message.Identity.AttemptId, running))
                throw new InvalidOperationException("TaskAttempt is already active.");
            running.Completion = LaunchAndObserveAsync(running);
            var startOutcome = await running.StartOutcome.Task.ConfigureAwait(false);
            if (startOutcome is not null)
                await journal.SetOrchestrationCommandOutcomeAsync(
                    message.Command.CommandId, startOutcome).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var error = OrchestrationErrors.Recovery(exception);
            await EmitAsync(OrchestrationMessageKinds.TaskRecovery,
                new TaskRecoveryFact(message.Identity, error.Code, error.Detail),
                CancellationToken.None).ConfigureAwait(false);
        }
    }

    private PreparedTask Prepare(ExecuteTaskMessage message)
    {
        var type = registry.Resolve(message.TaskType, message.TaskTypeVersion);
        var canonicalInput = Steward.Scheduling.TaskInput.Parse(
            message.InputMediaType, message.InputSchemaVersion, message.InputJson);
        if (!string.Equals(canonicalInput.CanonicalJson, message.InputJson, StringComparison.Ordinal))
            throw new ArgumentException("Task input is not canonical.", nameof(message));
        using var inputDocument = JsonDocument.Parse(
            canonicalInput.CanonicalJson,
            new JsonDocumentOptions { MaxDepth = Steward.Scheduling.TaskInput.MaximumDepth });
        var input = inputDocument.RootElement.Clone();
        var validation = type.Validate(input);
        if (!validation.IsValid)
            throw new ArgumentException("TaskType validation rejected immutable input.", nameof(message));
        if (!string.Equals(
                message.Workspace,
                message.Identity.AttemptId.ToString(),
                StringComparison.Ordinal))
            throw new ArgumentException(
                "The Task workspace key must equal its attempt identity.",
                nameof(message));
        var workspace = OrchestrationWorkspace.ValidateAttemptPath(
            workspaceRoot,
            Path.Combine(workspaceRoot, message.Workspace));
        return new(type, new(
            message.Identity.AttemptId,
            message.Identity.Generation,
            workspace,
            input));
    }

    private async Task LaunchAndObserveAsync(RunningAttempt running)
    {
        var identity = running.Message.Identity;
        var attempt = CreateAttemptDto(
            identity, TaskAttemptState.Accepted, RecoveryCertainty.Certain, running.AuthorityExpiresAt);
        try
        {
            Directory.CreateDirectory(running.Context.Workspace);
            _ = OrchestrationWorkspace.ValidateAttemptPath(
                workspaceRoot, running.Context.Workspace);
            await journal.RecordAttemptAsync(attempt).ConfigureAwait(false);
            await EmitAsync(OrchestrationMessageKinds.TaskAccepted, new TaskAcceptedFact(identity), CancellationToken.None)
                .ConfigureAwait(false);

            attempt = attempt with { State = TaskAttemptState.Preparing };
            await journal.RecordAttemptAsync(attempt).ConfigureAwait(false);
            if (running.Type.Capabilities.HasFlag(TaskCapabilities.Prepare))
                await running.Type.SetupAsync(running.Context, running.Cancellation.Token).ConfigureAwait(false);
            var readiness = await running.Type.ProbeReadinessAsync(
                running.Context, running.Cancellation.Token).ConfigureAwait(false);
            if (!readiness.IsReady) throw new TaskSetupException();

            attempt = attempt with { State = TaskAttemptState.Launching };
            await journal.RecordAttemptAsync(attempt).ConfigureAwait(false);
            try
            {
                running.Execution = await running.Type.StartAsync(
                    running.Context, running.Cancellation.Token).ConfigureAwait(false);
                ValidateExecutionIdentity(running.Execution, identity);
            }
            catch (OperationCanceledException) when (running.CancelRequested)
            {
                await FinishAsync(running, TaskAttemptState.Cancelled, null, "cancelled").ConfigureAwait(false);
                return;
            }
            catch
            {
                await MarkAmbiguousAsync(running, attempt, "launch.outcome-unknown").ConfigureAwait(false);
                return;
            }

            await MarkRunningAsync(running).ConfigureAwait(false);
            await ObserveLoopAsync(running).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (running.CancelRequested)
        {
            await FinishAsync(running, TaskAttemptState.Cancelled, null, "cancelled").ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
            running.StartOutcome.TrySetResult(null);
        }
        catch (TaskSetupException)
        {
            await FinishAsync(running, TaskAttemptState.Failed, null, "setup.failed").ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var error = OrchestrationErrors.Recovery(exception);
            await MarkAmbiguousAsync(running, attempt, error.Code).ConfigureAwait(false);
        }
        finally
        {
            await running.IdentityLease.DisposeAsync().ConfigureAwait(false);
            completedAttempts[identity.AttemptId] = 0;
            attempts.TryRemove(identity.AttemptId, out _);
        }
    }

    private async Task ObserveLoopAsync(RunningAttempt running)
    {
        while (true)
        {
            if (running.CancelRequested && !running.CancelIssued)
            {
                running.CancelIssued = true;
                await running.Type.CancelAsync(
                    running.Execution!, running.CancelGracePeriod, CancellationToken.None).ConfigureAwait(false);
            }
            var observation = await running.Type.ObserveAsync(
                running.Execution!, lifetime.Token).ConfigureAwait(false);
            await EmitOutputsAsync(running).ConfigureAwait(false);
            if (observation.State == ExecutionState.Exited)
            {
                var terminal = running.CancelRequested
                    ? TaskAttemptState.Cancelled
                    : observation.ExitCode == 0 ? TaskAttemptState.Succeeded : TaskAttemptState.Failed;
                await FinishAsync(
                    running, terminal, observation.ExitCode,
                    terminal == TaskAttemptState.Failed ? "runtime.failed" : "completed").ConfigureAwait(false);
                return;
            }
            if (observation.State == ExecutionState.Interrupted)
            {
                await FinishAsync(
                    running,
                    running.CancelRequested ? TaskAttemptState.Cancelled : TaskAttemptState.Interrupted,
                    observation.ExitCode,
                    running.CancelRequested ? "cancelled" : "runtime.interrupted").ConfigureAwait(false);
                return;
            }
            if (observation.State == ExecutionState.Recovering)
            {
                await MarkAmbiguousAsync(
                    running,
                    CreateAttemptDto(running.Message.Identity, TaskAttemptState.Running,
                        RecoveryCertainty.Certain, running.AuthorityExpiresAt),
                    "runtime.presence-unknown").ConfigureAwait(false);
                return;
            }
            await Task.Delay(observationInterval, timeProvider, lifetime.Token).ConfigureAwait(false);
        }
    }

    private async Task MarkRunningAsync(RunningAttempt running)
    {
        var attempt = CreateAttemptDto(
            running.Message.Identity, TaskAttemptState.Running,
            RecoveryCertainty.Certain, running.AuthorityExpiresAt);
        await journal.RecordAttemptAsync(attempt).ConfigureAwait(false);
        await EmitAsync(
            OrchestrationMessageKinds.TaskRunning,
            new TaskRunningFact(running.Message.Identity),
            CancellationToken.None).ConfigureAwait(false);
        running.StartOutcome.TrySetResult(new CommandOutcome(
            "started",
            JsonSerializer.Serialize(new
            {
                attemptId = running.Message.Identity.AttemptId,
                generation = running.Message.Identity.Generation
            }, StewardJson.Options)));
    }

    private async Task RecoverPersistedAsync(
        JournaledAttemptContext persisted,
        CancellationToken cancellationToken)
    {
        ExecuteTaskMessage message;
        try
        {
            message = JsonSerializer.Deserialize<ExecuteTaskMessage>(
                persisted.ContextJson, StewardJson.Options)
                ?? throw new InvalidDataException("Attempt context is null.");
            _ = OrchestrationMessageCodec.Encode(message, timeProvider.GetUtcNow());
            if (message.Identity.AttemptId != persisted.AttemptId ||
                message.Identity.Generation != persisted.Generation ||
                message.Command.CommandId != persisted.CommandId)
                throw new InvalidDataException("Attempt context identity is inconsistent.");
        }
        catch (Exception exception)
        {
            var error = OrchestrationErrors.Recovery(exception);
            if (TryIdentity(persisted.ContextJson, out var identity))
                await EmitAsync(OrchestrationMessageKinds.TaskRecovery,
                    new TaskRecoveryFact(identity, error.Code, error.Detail), cancellationToken).ConfigureAwait(false);
            return;
        }
        if (attempts.ContainsKey(message.Identity.AttemptId)) return;

        PreparedTask prepared;
        StartAuthorityReservation reservation;
        DelegationDto delegation;
        try
        {
            prepared = Prepare(message);
            reservation = await journal.ReserveStartAuthorityAsync(
                message.Identity.AttemptId,
                message.Identity.DelegationId,
                message.Identity.TaskId,
                message.Identity.Generation,
                ToDomain(message.Resources),
                message.RateRequirements,
                message.IdentityGrantIds,
                timeProvider.GetUtcNow(),
                cancellationToken).ConfigureAwait(false);
            delegation = await journal.GetDelegationAsync(
                message.Identity.DelegationId, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Delegation is missing.");
        }
        catch (Exception exception)
        {
            var error = OrchestrationErrors.Recovery(exception);
            if (persisted.Attempt?.State is null or TaskAttemptState.Reserved or
                TaskAttemptState.Dispatched or TaskAttemptState.Accepted or TaskAttemptState.Preparing)
            {
                await RecordAbsentWithoutReservationAsync(
                    message, persisted.Attempt?.AuthorityExpiresAt ?? message.Command.Deadline,
                    error.Code, cancellationToken).ConfigureAwait(false);
                return;
            }
            await EmitAsync(OrchestrationMessageKinds.TaskRecovery,
                new TaskRecoveryFact(message.Identity, error.Code, error.Detail), cancellationToken).ConfigureAwait(false);
            return;
        }

        TaskIdentityLease recoveredIdentityLease;
        try
        {
            recoveredIdentityLease = await ResolveIdentitiesAsync(
                message, cancellationToken).ConfigureAwait(false);
        }
        catch (IdentityResolutionException exception)
        {
            if (persisted.Attempt?.State is null or TaskAttemptState.Reserved or
                TaskAttemptState.Dispatched or TaskAttemptState.Accepted or TaskAttemptState.Preparing)
                await RecordIdentityFailureAsync(
                    message, reservation, delegation.AuthorityExpiresAt, exception).ConfigureAwait(false);
            else
                await EmitAsync(
                    OrchestrationMessageKinds.TaskRecovery,
                    new TaskRecoveryFact(
                        message.Identity,
                        ProblemCodes.IdentityRenewalUnavailable,
                        "Required task identity could not be renewed during recovery."),
                    cancellationToken).ConfigureAwait(false);
            return;
        }
        var running = new RunningAttempt(
            message, prepared.Type, reservation, delegation.AuthorityExpiresAt,
            prepared.Context, recoveredIdentityLease)
        {
            OutputCursor = persisted.OutputCursor
        };
        running.Context = running.Context with { IdentityHandles = running.IdentityLease.Handles };
        if (!attempts.TryAdd(message.Identity.AttemptId, running)) return;

        var state = persisted.Attempt?.State;
        if (state is null or TaskAttemptState.Reserved or TaskAttemptState.Dispatched
            or TaskAttemptState.Accepted or TaskAttemptState.Preparing)
        {
            running.Completion = FinishKnownAbsentAsync(running);
            return;
        }
        if (prepared.Type is not IRecoverableTaskType recoverable)
        {
            running.Completion = MarkAmbiguousAndRemoveAsync(
                running,
                persisted.Attempt!,
                "runtime.recovery-unsupported");
            return;
        }

        TaskExecutionRecoveryResult recovery;
        try
        {
            recovery = await recoverable.RecoverExecutionAsync(
                prepared.Context,
                journal.Identity.CurrentHostBootId.ToString("D"),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var error = OrchestrationErrors.Recovery(exception);
            running.Completion = MarkAmbiguousAndRemoveAsync(running, persisted.Attempt!, error.Code);
            return;
        }
        switch (recovery.Status)
        {
            case TaskExecutionRecoveryStatus.Present when recovery.Execution is not null:
                ValidateExecutionIdentity(recovery.Execution, message.Identity);
                running.Execution = recovery.Execution;
                await MarkRunningAsync(running).ConfigureAwait(false);
                await journal.SetOrchestrationCommandOutcomeAsync(
                    message.Command.CommandId,
                    new("started", JsonSerializer.Serialize(new
                    {
                        attemptId = message.Identity.AttemptId,
                        recovered = true
                    }, StewardJson.Options)),
                    cancellationToken).ConfigureAwait(false);
                running.Completion = ContinueRecoveredAsync(running);
                break;
            case TaskExecutionRecoveryStatus.Absent:
                running.Completion = FinishKnownAbsentAsync(running);
                break;
            default:
                running.Completion = MarkAmbiguousAndRemoveAsync(
                    running, persisted.Attempt!, StableCode(recovery.Code));
                break;
        }
    }

    private async Task ContinueRecoveredAsync(RunningAttempt running)
    {
        try { await ObserveLoopAsync(running).ConfigureAwait(false); }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (Exception exception)
        {
            var error = OrchestrationErrors.Recovery(exception);
            await MarkAmbiguousAsync(
                running,
                CreateAttemptDto(running.Message.Identity, TaskAttemptState.Running,
                    RecoveryCertainty.Certain, running.AuthorityExpiresAt),
                error.Code).ConfigureAwait(false);
        }
        finally
        {
            await running.IdentityLease.DisposeAsync().ConfigureAwait(false);
            completedAttempts[running.Message.Identity.AttemptId] = 0;
            attempts.TryRemove(running.Message.Identity.AttemptId, out _);
        }
    }

    private async Task FinishKnownAbsentAsync(RunningAttempt running)
    {
        try
        {
            await FinishAsync(
                running, TaskAttemptState.Interrupted, null, "runtime.absent-after-restart").ConfigureAwait(false);
            await journal.SetOrchestrationCommandOutcomeAsync(
                running.Message.Command.CommandId,
                new("failed", """{"code":"runtime.absent-after-restart"}""")).ConfigureAwait(false);
        }
        finally
        {
            await running.IdentityLease.DisposeAsync().ConfigureAwait(false);
            completedAttempts[running.Message.Identity.AttemptId] = 0;
            attempts.TryRemove(running.Message.Identity.AttemptId, out _);
        }
    }

    private async Task RecordAbsentWithoutReservationAsync(
        ExecuteTaskMessage message,
        DateTimeOffset authorityExpiresAt,
        string code,
        CancellationToken cancellationToken)
    {
        var receipt = Receipt(message.Identity, TaskAttemptState.Interrupted, null);
        await journal.RecordAttemptAsync(CreateAttemptDto(
            message.Identity,
            TaskAttemptState.Interrupted,
            RecoveryCertainty.ExecutionAbsent,
            authorityExpiresAt), cancellationToken).ConfigureAwait(false);
        await EmitAsync(
            OrchestrationMessageKinds.TaskTerminal,
            new TaskTerminalFact(
                message.Identity,
                TaskAttemptState.Interrupted,
                null,
                receipt,
                OrchestrationErrors.TerminalDetail("runtime.interrupted")),
            cancellationToken).ConfigureAwait(false);
        await journal.SetOrchestrationCommandOutcomeAsync(
            message.Command.CommandId,
            new("failed", JsonSerializer.Serialize(new { code }, StewardJson.Options)),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task RecordRejectedBeforeAuthorityAsync(
        ExecuteTaskMessage message,
        string code)
    {
        var receipt = Receipt(message.Identity, TaskAttemptState.Failed, null);
        await journal.RecordAttemptAsync(CreateAttemptDto(
            message.Identity,
            TaskAttemptState.Failed,
            RecoveryCertainty.Certain,
            message.Command.Deadline)).ConfigureAwait(false);
        await EmitAsync(
            OrchestrationMessageKinds.TaskTerminal,
            new TaskTerminalFact(
                message.Identity,
                TaskAttemptState.Failed,
                null,
                receipt,
                OrchestrationErrors.TerminalDetail("setup.failed")),
            CancellationToken.None).ConfigureAwait(false);
        await journal.SetOrchestrationCommandOutcomeAsync(
            message.Command.CommandId,
            new("failed", JsonSerializer.Serialize(new { code = StableCode(code) }, StewardJson.Options)))
            .ConfigureAwait(false);
    }

    private async Task RecordIdentityFailureAsync(
        ExecuteTaskMessage message,
        StartAuthorityReservation reservation,
        DateTimeOffset authorityExpiresAt,
        IdentityResolutionException exception)
    {
        var pause = exception.OfflineBehavior == IdentityOfflineBehavior.CheckpointAndPause;
        var state = pause ? TaskAttemptState.Checkpointed : TaskAttemptState.Failed;
        var receipt = Receipt(message.Identity, state, null);
        await journal.RecordAttemptAsync(CreateAttemptDto(
            message.Identity, state,
            RecoveryCertainty.Certain, authorityExpiresAt)).ConfigureAwait(false);
        await journal.CompleteStartReservationAsync(
            reservation.ReservationId,
            OrchestrationMessageKinds.TaskTerminal,
            new TaskTerminalFact(
                message.Identity, state, null, receipt,
                pause
                    ? "Control is disconnected; the Task paused before starting for identity renewal."
                    : "Required task identity could not be renewed or delivered."),
            timeProvider.GetUtcNow()).ConfigureAwait(false);
        await journal.SetOrchestrationCommandOutcomeAsync(
            message.Command.CommandId,
            new(pause ? "paused" : "failed", JsonSerializer.Serialize(new
            {
                code = StableCode(exception.Code),
                problem = ProblemCodes.IdentityRenewalUnavailable
            }, StewardJson.Options))).ConfigureAwait(false);
    }

    private async Task MarkAmbiguousAndRemoveAsync(
        RunningAttempt running,
        TaskAttemptDto attempt,
        string code)
    {
        try { await MarkAmbiguousAsync(running, attempt, code).ConfigureAwait(false); }
        finally { attempts.TryRemove(running.Message.Identity.AttemptId, out _); }
    }

    private async Task ProcessCancelAsync(CancelTaskMessage message)
    {
        try
        {
            await journal.ExecuteCommandAsync(message.Command, async _ =>
            {
                await EmitAsync(OrchestrationMessageKinds.CommandAcknowledged,
                    new CommandAcknowledgedFact(message.Identity, message.Command.CommandId, "cancel"),
                    CancellationToken.None).ConfigureAwait(false);
                if (!attempts.TryGetValue(message.Identity.AttemptId, out var running) ||
                    running.Message.Identity != message.Identity)
                {
                    if (completedAttempts.ContainsKey(message.Identity.AttemptId))
                        return new CommandOutcome("already-terminal", "{}");
                    throw new InvalidOperationException("Active TaskAttempt identity is unavailable.");
                }
                running.CancelRequested = true;
                running.CancelGracePeriod = TimeSpan.FromMilliseconds(message.GracePeriodMilliseconds);
                running.Cancellation.Cancel();
                if (running.Execution is not null && !running.CancelIssued)
                {
                    running.CancelIssued = true;
                    await running.Type.CancelAsync(
                        running.Execution, running.CancelGracePeriod, CancellationToken.None).ConfigureAwait(false);
                }
                return new CommandOutcome("completed", "{}");
            }, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var error = OrchestrationErrors.Recovery(exception);
            await EmitAsync(OrchestrationMessageKinds.TaskRecovery,
                new TaskRecoveryFact(message.Identity, error.Code, error.Detail),
                CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task EmitOutputsAsync(RunningAttempt running)
    {
        if (running.Type is not ITaskOutputSource output || running.Execution is null) return;
        var batch = await output.ReadOutputsAsync(
            running.Execution, running.OutputCursor, 128, CancellationToken.None).ConfigureAwait(false);
        if (batch.NextCursor < running.OutputCursor)
            throw new InvalidDataException("Task output cursor moved backwards.");
        foreach (var item in batch.Outputs)
        {
            var published = portablePublisher is null
                ? new PublishedTaskOutput(item, false)
                : await portablePublisher.PublishAsync(
                    running.Message.Identity,
                    running.Context.Workspace,
                    item,
                    item is TaskRuntimeCheckpoint,
                    CancellationToken.None).ConfigureAwait(false);
            running.HasPortableReceipt |= published.HasPortableReceipt;
            var fact = published.Output switch
            {
                TaskRuntimeProgress progress => (object)new TaskProgressFact(
                    running.Message.Identity, progress.Fraction, progress.Message),
                TaskRuntimeLogCursor log => new TaskLogCursorFact(
                    running.Message.Identity, log.Stream, log.Offset, log.Length, log.ContentHash, log.Truncated),
                TaskRuntimeArtifact artifact => new TaskArtifactFact(
                    running.Message.Identity, artifact.PortableObjectId, artifact.Name, artifact.MediaType,
                    artifact.Reference, artifact.SizeBytes, artifact.ContentHash,
                    published.HasPortableReceipt),
                TaskRuntimeCheckpoint checkpoint => new TaskCheckpointFact(
                    running.Message.Identity, checkpoint.PortableObjectId, checkpoint.Reference,
                    checkpoint.SizeBytes, checkpoint.ContentHash,
                    published.HasPortableReceipt),
                TaskRuntimeAgentActivity activity => new AgentActivityFact(
                    running.Message.Identity, activity.Text),
                TaskRuntimeAgentFinal final => new AgentFinalFact(
                    running.Message.Identity, final.Text, final.Receipt),
                _ => throw new InvalidOperationException("Unknown bounded runtime output.")
            };
            var kind = published.Output switch
            {
                TaskRuntimeProgress => OrchestrationMessageKinds.TaskProgress,
                TaskRuntimeLogCursor => OrchestrationMessageKinds.TaskLogCursor,
                TaskRuntimeArtifact => OrchestrationMessageKinds.TaskArtifact,
                TaskRuntimeCheckpoint => OrchestrationMessageKinds.TaskCheckpoint,
                TaskRuntimeAgentActivity => OrchestrationMessageKinds.AgentActivity,
                TaskRuntimeAgentFinal => OrchestrationMessageKinds.AgentFinal,
                _ => throw new InvalidOperationException("Unknown bounded runtime output.")
            };
            await EmitAsync(kind, fact, CancellationToken.None).ConfigureAwait(false);
        }
        running.OutputCursor = batch.NextCursor;
        await journal.SetAttemptOutputCursorAsync(
            running.Message.Identity.AttemptId, batch.NextCursor).ConfigureAwait(false);
    }

    private async Task FinishAsync(
        RunningAttempt running,
        TaskAttemptState terminal,
        int? exitCode,
        string detailCode)
    {
        if (Interlocked.Exchange(ref running.TerminalWritten, 1) != 0) return;
        string? durableReceipt = null;
        if (running.Type is IDurableTaskResultType durableResult && running.Execution is not null)
            durableReceipt = await durableResult.CommitTerminalResultAsync(
                running.Execution,
                running.Message.Identity.TaskId,
                CancellationToken.None).ConfigureAwait(false);
        var cleanupFailed = false;
        if (running.Type.Capabilities.HasFlag(TaskCapabilities.Cleanup))
        {
            try { await running.Type.CleanupAsync(running.Context, CancellationToken.None).ConfigureAwait(false); }
            catch { cleanupFailed = true; }
        }
        var receipt = string.IsNullOrWhiteSpace(durableReceipt)
            ? Receipt(running.Message.Identity, terminal, exitCode)
            : durableReceipt;
        var attempt = CreateAttemptDto(
            running.Message.Identity, terminal, RecoveryCertainty.Certain, running.AuthorityExpiresAt);
        await journal.RecordAttemptAsync(attempt).ConfigureAwait(false);
        await journal.CompleteStartReservationAsync(
            running.Reservation.ReservationId,
            OrchestrationMessageKinds.TaskTerminal,
            new TaskTerminalFact(
                running.Message.Identity,
                terminal,
                exitCode,
                receipt,
                OrchestrationErrors.TerminalDetail(cleanupFailed ? "cleanup.failed" : detailCode)),
            timeProvider.GetUtcNow()).ConfigureAwait(false);
        if (running.Type is IDurableTaskResultType releasable && running.HasPortableReceipt)
            await releasable.ReleaseDurableStateAsync(
                running.Message.Identity.AttemptId,
                running.Message.Identity.Generation,
                CancellationToken.None).ConfigureAwait(false);
        running.StartOutcome.TrySetResult(new CommandOutcome(
            terminal == TaskAttemptState.Succeeded ? "completed" : "failed",
            JsonSerializer.Serialize(new { terminal, receipt }, StewardJson.Options)));
    }

    private async Task MarkAmbiguousAsync(
        RunningAttempt running,
        TaskAttemptDto attempt,
        string code)
    {
        if (Interlocked.Exchange(ref running.TerminalWritten, 1) != 0) return;
        await journal.RecordAttemptAsync(attempt with
        {
            State = TaskAttemptState.Recovering,
            RecoveryCertainty = RecoveryCertainty.Ambiguous
        }).ConfigureAwait(false);
        await EmitAsync(
            OrchestrationMessageKinds.TaskRecovery,
            new TaskRecoveryFact(
                running.Message.Identity,
                code,
                "Managed execution presence could not be established; automatic relaunch is blocked."),
            CancellationToken.None).ConfigureAwait(false);
        running.StartOutcome.TrySetResult(null);
    }

    private async Task EmitAsync(string kind, object fact, CancellationToken cancellationToken)
    {
        _ = OrchestrationMessageCodec.Encode(fact, timeProvider.GetUtcNow());
        await journal.AppendFactAsync(kind, fact, timeProvider.GetUtcNow(), cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateExecutionIdentity(IExecutionHandle execution, AttemptIdentity identity)
    {
        if (execution.AttemptId != identity.AttemptId || execution.Generation != identity.Generation ||
            execution.ProcessId < 0 || execution.ProcessCreationTimeUtcTicks < 0)
            throw new InvalidDataException("Recovered execution identity does not match its TaskAttempt fence.");
    }

    private static bool TryIdentity(string json, out AttemptIdentity identity)
    {
        try
        {
            identity = JsonSerializer.Deserialize<ExecuteTaskMessage>(json, StewardJson.Options)!.Identity;
            return identity is not null;
        }
        catch
        {
            identity = default!;
            return false;
        }
    }

    private static TaskAttemptDto CreateAttemptDto(
        AttemptIdentity identity,
        TaskAttemptState state,
        RecoveryCertainty certainty,
        DateTimeOffset authorityExpiresAt) =>
        new(identity.AttemptId, identity.TaskId, identity.Generation, identity.HostId,
            identity.NodeIncarnationId, state, certainty, identity.DelegationId, identity.CommandId,
            authorityExpiresAt,
            new("orchestration", "1.0",
                JsonSerializer.SerializeToElement(new { identity.WorkloadId }, StewardJson.Options)));

    private static ResourceRequirements ToDomain(ResourceRequirementsDto value) =>
        new(value.CpuCores, value.MemoryBytes, value.DiskBytes, value.GpuCount,
            value.ProcessCount, value.ContainerCount, value.VmCount, value.ConcurrencyUnits);

    private static string Receipt(AttemptIdentity identity, TaskAttemptState state, int? exitCode) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{identity.AttemptId}:{identity.Generation}:{state}:{exitCode}"))).ToLowerInvariant();

    private static string StableCode(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 128 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_')
            ? value
            : "runtime.reconciliation-required";

    private async ValueTask<TaskIdentityLease> ResolveIdentitiesAsync(
        ExecuteTaskMessage message,
        CancellationToken cancellationToken = default)
    {
        var grants = message.IdentityGrants ?? [];
        if (grants.Any(x =>
            x.WorkloadId != message.Identity.WorkloadId ||
            x.TaskId != message.Identity.TaskId ||
            x.Generation != message.Identity.Generation ||
            x.HostId != message.Identity.HostId ||
            x.NodeIncarnationId != message.Identity.NodeIncarnationId ||
            x.ExpiresAt <= timeProvider.GetUtcNow()))
            throw new IdentityResolutionException(
                "identity.binding-invalid",
                "Task identity grant is expired or bound to another execution.");
        return await identityResolver.ResolveAsync(
            message.Identity, grants, cancellationToken).ConfigureAwait(false);
    }

    private void Track(CommandId commandId, Task task)
    {
        if (!commandTasks.TryAdd(commandId, task)) return;
        _ = RemoveWhenCompleteAsync(commandId, task);
    }

    private async Task RemoveWhenCompleteAsync(CommandId commandId, Task task)
    {
        try { await task.ConfigureAwait(false); }
        finally { commandTasks.TryRemove(commandId, out Task? _); }
    }

    public async ValueTask DisposeAsync()
    {
        lifetime.Cancel();
        try { await WaitForAttemptsAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        lifetime.Dispose();
        recoveryGate.Dispose();
    }

    private sealed record PreparedTask(ITaskType Type, TaskExecutionContext Context);
    private sealed class TaskSetupException : Exception { }

    private sealed class RunningAttempt(
        ExecuteTaskMessage message,
        ITaskType type,
        StartAuthorityReservation reservation,
        DateTimeOffset authorityExpiresAt,
        TaskExecutionContext context,
        TaskIdentityLease identityLease)
    {
        public ExecuteTaskMessage Message { get; } = message;
        public ITaskType Type { get; } = type;
        public StartAuthorityReservation Reservation { get; } = reservation;
        public DateTimeOffset AuthorityExpiresAt { get; } = authorityExpiresAt;
        public TaskExecutionContext Context { get; set; } = context;
        public TaskIdentityLease IdentityLease { get; } = identityLease;
        public CancellationTokenSource Cancellation { get; } = new();
        public TaskCompletionSource<CommandOutcome?> StartOutcome { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IExecutionHandle? Execution { get; set; }
        public Task Completion { get; set; } = Task.CompletedTask;
        public bool CancelRequested { get; set; }
        public bool CancelIssued { get; set; }
        public TimeSpan CancelGracePeriod { get; set; }
        public long OutputCursor { get; set; }
        public bool HasPortableReceipt { get; set; }
        public int TerminalWritten;
    }
}
