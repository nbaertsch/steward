using System.Collections.Concurrent;
using Steward.Domain;

namespace Steward.Agents;

public sealed class StewardAgentService
{
    private readonly IAgentStore _store;
    private readonly IAgentRuntime _runtime;
    private readonly IAgentTaskDispatcher _dispatcher;
    private readonly IContextCompactor _compactor;
    private readonly ContextBudget _budget;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _ownershipLease;
    private readonly ConcurrentDictionary<(StewardAgentId, AgentTurnId), CancellationTokenSource> _active = [];

    public StewardAgentService(
        IAgentStore store,
        IAgentRuntime runtime,
        IAgentTaskDispatcher dispatcher,
        IContextCompactor? compactor = null,
        ContextBudget? budget = null,
        Guid? ownerId = null,
        TimeProvider? timeProvider = null,
        TimeSpan? ownershipLease = null)
    {
        _store = store;
        _runtime = runtime;
        _dispatcher = dispatcher;
        _compactor = compactor ?? new BoundedExtractiveContextCompactor();
        _budget = (budget ?? new(AgentLimits.MaximumContextBytes, 1_000_000)).Validate();
        OwnerId = ownerId ?? Guid.NewGuid();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _ownershipLease = ownershipLease ?? TimeSpan.FromMinutes(2);
    }

    public Guid OwnerId { get; }

    public async Task<AgentDescriptor> CreateAsync(
        StewardAgentId agentId, string? parentRoute = null, CancellationToken cancellationToken = default)
    {
        var descriptor = await _store.CreateAsync(
            agentId, _runtime.Descriptor, parentRoute, cancellationToken).ConfigureAwait(false);
        await EnsureOwnershipAsync(agentId, cancellationToken).ConfigureAwait(false);
        return descriptor;
    }

    public async Task AcquireOwnershipAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default) =>
        await EnsureOwnershipAsync(agentId, cancellationToken).ConfigureAwait(false);

    public Task<AgentTurnRecord> SubmitAsync(
        StewardAgentId agentId, AgentTurnRequest request, CancellationToken cancellationToken = default) =>
        _store.SubmitTurnAsync(agentId, request, cancellationToken);

    public async Task<bool> RunNextAsync(
        StewardAgentId agentId,
        IReadOnlyList<ProtectedCredentialReference>? credentials = null,
        CancellationToken cancellationToken = default)
    {
        await EnsureOwnershipAsync(agentId, cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();
        var turn = await _store.TryClaimNextAsync(
            agentId, OwnerId, now, _runtime.Descriptor.SupportsParallelTurns, cancellationToken).ConfigureAwait(false);
        if (turn is null) return false;
        var key = (agentId, turn.TurnId);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var heartbeatStop = new CancellationTokenSource();
        var heartbeat = RenewOwnershipLoopAsync(agentId, linked, heartbeatStop.Token);
        if (!_active.TryAdd(key, linked))
            throw new AgentConflictException("Turn is already active in this runtime.");
        ManagedAgentExecution? execution = null;
        var terminalReported = false;
        try
        {
            var descriptor = await _store.GetAsync(agentId, linked.Token).ConfigureAwait(false)
                ?? throw new KeyNotFoundException("Agent does not exist.");
            var context = await _store.ReadContextAsync(agentId, linked.Token).ConfigureAwait(false);
            var runningTurn = await _store.GetTurnAsync(agentId, turn.TurnId, linked.Token).ConfigureAwait(false)
                ?? throw new KeyNotFoundException("Turn does not exist.");
            var intent = new AgentTaskIntent(agentId, turn.TurnId, turn.WorkloadId!.Value, turn.TaskId!.Value,
                AgentCommandKind.CodingOperation, turn.Text, turn.Provenance,
                context.Select(x => x.Text).ToArray());
            execution = await _dispatcher.DispatchAsync(intent, linked.Token).ConfigureAwait(false);
            if (execution is null)
            {
                await _store.FailAsync(agentId, turn.TurnId, "dispatch-not-authorized", null, linked.Token)
                    .ConfigureAwait(false);
                return true;
            }
            execution.Validate();
            await _store.SetExecutionAsync(agentId, turn.TurnId, execution, linked.Token).ConfigureAwait(false);
            string? final = null;
            await foreach (var item in _runtime.ExecuteAsync(
                new(descriptor, runningTurn, execution, context, credentials ?? []), linked.Token).ConfigureAwait(false))
            {
                AgentLimits.Text(item.Text,
                    item is AgentFinalResponse ? AgentLimits.MaximumResponseBytes : AgentLimits.MaximumActivityBytes,
                    nameof(item.Text));
                if (item is AgentActivity activity)
                    await _store.AppendActivityAsync(agentId, turn.TurnId, activity, linked.Token).ConfigureAwait(false);
                else if (item is AgentFinalResponse response)
                {
                    if (final is not null) throw new InvalidDataException("Runtime emitted more than one final response.");
                    final = response.Text;
                }
            }
            if (final is null) throw new InvalidDataException("Runtime did not emit a final response.");
            await _store.SavePendingResultAsync(
                agentId, turn.TurnId, execution, final, CancellationToken.None).ConfigureAwait(false);
            if (!await _dispatcher.ReportTerminalAsync(execution,
                new(AgentTerminalKind.Responded, final, null, null), CancellationToken.None).ConfigureAwait(false))
                throw new AgentConflictException("Managed Task already has a terminal outcome.");
            terminalReported = true;
            await _store.MarkPendingResultReportedAsync(
                agentId, turn.TurnId, execution.LeaseId, CancellationToken.None).ConfigureAwait(false);
            await _store.FinalizePendingResultAsync(
                agentId, turn.TurnId, execution.LeaseId, CancellationToken.None).ConfigureAwait(false);
            await _store.CompactContextAsync(
                agentId, _budget, _compactor, CancellationToken.None).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            if (execution is not null && !terminalReported)
                if (await _dispatcher.ReportTerminalAsync(execution,
                    new(AgentTerminalKind.Cancelled, null, "cancelled", null), CancellationToken.None)
                    .ConfigureAwait(false))
                    await _store.CancelAsync(agentId, turn.TurnId, CancellationToken.None).ConfigureAwait(false);
                else
                    await _store.CancelAsync(agentId, turn.TurnId, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        catch (Exception) when (!terminalReported)
        {
            if (execution is not null)
                if (await _dispatcher.ReportTerminalAsync(execution,
                    new(AgentTerminalKind.Failed, null, "agent-runtime-failed", null), CancellationToken.None)
                    .ConfigureAwait(false))
                    await _store.FailAsync(agentId, turn.TurnId, "agent-runtime-failed", null, CancellationToken.None)
                        .ConfigureAwait(false);
                else
                    await _store.FailAsync(agentId, turn.TurnId, "agent-runtime-failed", null, CancellationToken.None)
                        .ConfigureAwait(false);
            return true;
        }
        finally
        {
            heartbeatStop.Cancel();
            try { await heartbeat.ConfigureAwait(false); }
            catch (OperationCanceledException) when (heartbeatStop.IsCancellationRequested) { }
            _active.TryRemove(key, out _);
        }
    }

    public async Task<bool> CancelAsync(
        StewardAgentId agentId, AgentTurnId turnId, CancellationToken cancellationToken = default)
    {
        var turn = await _store.GetTurnAsync(agentId, turnId, cancellationToken).ConfigureAwait(false);
        if (turn is null) return false;
        if (turn.Execution is not null)
            await _dispatcher.CancelAsync(turn.Execution, cancellationToken).ConfigureAwait(false);
        if (_active.TryGetValue((agentId, turnId), out var active))
        {
            active.Cancel();
            return true;
        }
        if (turn.Execution is not null)
            if (!await _dispatcher.ReportTerminalAsync(turn.Execution,
                new(AgentTerminalKind.Cancelled, null, "cancelled", null), cancellationToken).ConfigureAwait(false))
                return false;
        return await _store.CancelAsync(agentId, turnId, cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> ReconcileRecoveringAsync(
        StewardAgentId agentId, CancellationToken cancellationToken = default)
    {
        await EnsureOwnershipAsync(agentId, cancellationToken).ConfigureAwait(false);
        await _store.RecoverAbandonedTurnsAsync(
            agentId, OwnerId, _timeProvider.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        var recovering = await _store.ReadRecoveringTurnsAsync(agentId, cancellationToken).ConfigureAwait(false);
        foreach (var turn in recovering)
        {
            var pending = await _store.GetPendingResultAsync(
                agentId, turn.TurnId, cancellationToken).ConfigureAwait(false);
            if (pending is not null && turn.Execution is not null)
            {
                if (!pending.TerminalReported)
                {
                    var accepted = await _dispatcher.ReportTerminalAsync(turn.Execution,
                        new(AgentTerminalKind.Responded, pending.Response, null, null), cancellationToken)
                        .ConfigureAwait(false);
                    if (accepted)
                        await _store.MarkPendingResultReportedAsync(
                            agentId, turn.TurnId, pending.ExecutionLeaseId, cancellationToken).ConfigureAwait(false);
                    else
                    {
                        var known = await _dispatcher.ReconcileAsync(
                            turn.WorkloadId!.Value, turn.TaskId!.Value, turn.Execution, cancellationToken)
                            .ConfigureAwait(false);
                        if (known.Fact != ManagedExecutionFact.Succeeded)
                        {
                            await _store.ResolveRecoveryAsync(
                                agentId, turn.TurnId, known, cancellationToken).ConfigureAwait(false);
                            continue;
                        }
                        await _store.MarkPendingResultReportedAsync(
                            agentId, turn.TurnId, pending.ExecutionLeaseId, cancellationToken).ConfigureAwait(false);
                    }
                }
                await _store.FinalizePendingResultAsync(
                    agentId, turn.TurnId, pending.ExecutionLeaseId, cancellationToken).ConfigureAwait(false);
                await _store.CompactContextAsync(
                    agentId, _budget, _compactor, cancellationToken).ConfigureAwait(false);
                continue;
            }
            var status = await _dispatcher.ReconcileAsync(
                turn.WorkloadId!.Value, turn.TaskId!.Value, turn.Execution, cancellationToken).ConfigureAwait(false);
            if (turn.Execution is null && status.Execution is not null)
                await _store.SetExecutionAsync(
                    agentId, turn.TurnId, status.Execution, cancellationToken).ConfigureAwait(false);
            var recoveredExecution = turn.Execution ?? status.Execution;
            if (status.Fact == ManagedExecutionFact.Succeeded && recoveredExecution is not null)
            {
                await _store.SavePendingResultAsync(
                    agentId, turn.TurnId, recoveredExecution, status.Response ?? string.Empty, cancellationToken)
                    .ConfigureAwait(false);
                await _store.MarkPendingResultReportedAsync(
                    agentId, turn.TurnId, recoveredExecution.LeaseId, cancellationToken).ConfigureAwait(false);
                await _store.FinalizePendingResultAsync(
                    agentId, turn.TurnId, recoveredExecution.LeaseId, cancellationToken).ConfigureAwait(false);
                await _store.CompactContextAsync(
                    agentId, _budget, _compactor, cancellationToken).ConfigureAwait(false);
            }
            else
                await _store.ResolveRecoveryAsync(agentId, turn.TurnId, status, cancellationToken).ConfigureAwait(false);
        }
        return recovering.Count;
    }

    private async Task EnsureOwnershipAsync(
        StewardAgentId agentId, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        if (await _store.TryRenewRuntimeOwnershipAsync(
            agentId, OwnerId, now, _ownershipLease, cancellationToken).ConfigureAwait(false))
            return;
        if (!await _store.TryAcquireRuntimeOwnershipAsync(
            agentId, OwnerId, now, _ownershipLease, cancellationToken).ConfigureAwait(false))
            throw new AgentConflictException("Another live runtime owns this Agent.");
    }

    private async Task RenewOwnershipLoopAsync(
        StewardAgentId agentId,
        CancellationTokenSource execution,
        CancellationToken cancellationToken)
    {
        var interval = TimeSpan.FromTicks(Math.Max(TimeSpan.FromSeconds(1).Ticks, _ownershipLease.Ticks / 3));
        while (true)
        {
            await Task.Delay(interval, _timeProvider, cancellationToken).ConfigureAwait(false);
            try
            {
                if (await _store.TryRenewRuntimeOwnershipAsync(
                    agentId, OwnerId, _timeProvider.GetUtcNow(), _ownershipLease, cancellationToken)
                    .ConfigureAwait(false))
                    continue;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch { }
            execution.Cancel();
            return;
        }
    }

    public Task<ManagedAgentExecution> DispatchCommandAsync(
        StewardAgentId agentId,
        AgentTurnId turnId,
        AgentCommandKind command,
        string payload,
        TextProvenance provenance,
        CancellationToken cancellationToken = default) =>
        DispatchCommandCoreAsync(agentId, turnId, command, payload, provenance, cancellationToken);

    private async Task<ManagedAgentExecution> DispatchCommandCoreAsync(
        StewardAgentId agentId, AgentTurnId turnId, AgentCommandKind command,
        string payload, TextProvenance provenance, CancellationToken cancellationToken)
    {
        AgentLimits.Text(payload, AgentLimits.MaximumTurnBytes, nameof(payload));
        var turn = await _store.GetTurnAsync(agentId, turnId, cancellationToken).ConfigureAwait(false)
            ?? throw new KeyNotFoundException("Turn does not exist.");
        var execution = await _dispatcher.DispatchAsync(new(agentId, turnId, turn.WorkloadId!.Value, turn.TaskId!.Value,
            command, payload, provenance), cancellationToken).ConfigureAwait(false)
            ?? throw new AgentConflictException("Managed command execution was not authorized.");
        return execution;
    }
}
