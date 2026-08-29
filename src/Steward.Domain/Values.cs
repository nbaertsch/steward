namespace Steward.Domain;

public enum WorkloadDesiredState { Active, Paused, Cancelling, Cancelled }
public enum WorkloadObservedState { Planning, Queued, Running, Paused, Recovering, Succeeded, PartiallySucceeded, Failed, Cancelled }
public enum TaskDesiredState { Ready, Running, Paused, Cancelled }
public enum TaskObservedState { Blocked, Queued, Preparing, Ready, Running, Pausing, Paused, Checkpointing, Cancelling, Recovering, Succeeded, Failed, Cancelled, Interrupted }
public enum TaskAttemptState { Reserved, Dispatched, Accepted, Preparing, Launching, Running, Checkpointed, Succeeded, Failed, Cancelled, Interrupted, Recovering }
public enum InterruptionClass { CheckpointResumable, Restartable, NonInterruptible }
public enum RecoveryCertainty { Certain, ExecutionAbsent, ExecutionPresent, Ambiguous }
public enum StewardAgentState { Creating, Ready, HandlingTurn, Checkpointing, Migrating, Restoring, Suspended, Recovering, Terminated }
public enum AgentTurnState { Queued, Delegated, Running, Responded, Notified, Failed, Cancelled }
public enum HostLifecycleState { Discovered, Provisioning, Bootstrapping, Enrolling, Ready, Draining, Stopped, Starting, Reimaging, Deleting, Deleted, Degraded, Recovering }
public enum HostConnectionState { Unknown, Connected, Disconnected, Revoked }
public enum IdentityRenewalMode { Workload, LocalBroker, None }
public enum IdentityOfflineBehavior { CheckpointAndPause, Fail, ContinueWithoutCapability }
public enum PortableObjectKind { Log, Artifact, TaskCheckpoint, AgentCheckpoint, AgentState }

[Flags]
public enum TaskCapabilities
{
    None = 0,
    Prepare = 1 << 0,
    Execute = 1 << 1,
    Observe = 1 << 2,
    Checkpoint = 1 << 3,
    Pause = 1 << 4,
    Resume = 1 << 5,
    Cancel = 1 << 6,
    Restart = 1 << 7,
    Cleanup = 1 << 8,
    OfflineExecution = 1 << 9,
    Migration = 1 << 10
}

public sealed record ResourceRequirements
{
    public decimal CpuCores { get; }
    public long MemoryBytes { get; }
    public long DiskBytes { get; }
    public int GpuCount { get; }
    public int ProcessCount { get; }
    public int ContainerCount { get; }
    public int VmCount { get; }
    public int ConcurrencyUnits { get; }

    public ResourceRequirements(
        decimal cpuCores = 0,
        long memoryBytes = 0,
        long diskBytes = 0,
        int gpuCount = 0,
        int processCount = 0,
        int containerCount = 0,
        int vmCount = 0,
        int concurrencyUnits = 0)
    {
        if (cpuCores < 0 || memoryBytes < 0 || diskBytes < 0 || gpuCount < 0 ||
            processCount < 0 || containerCount < 0 || vmCount < 0 || concurrencyUnits < 0)
            throw new ArgumentOutOfRangeException(nameof(cpuCores), "Resource values cannot be negative.");

        CpuCores = cpuCores;
        MemoryBytes = memoryBytes;
        DiskBytes = diskBytes;
        GpuCount = gpuCount;
        ProcessCount = processCount;
        ContainerCount = containerCount;
        VmCount = vmCount;
        ConcurrencyUnits = concurrencyUnits;
    }

    public bool FitsWithin(ResourceRequirements limit) =>
        CpuCores <= limit.CpuCores &&
        MemoryBytes <= limit.MemoryBytes &&
        DiskBytes <= limit.DiskBytes &&
        GpuCount <= limit.GpuCount &&
        ProcessCount <= limit.ProcessCount &&
        ContainerCount <= limit.ContainerCount &&
        VmCount <= limit.VmCount &&
        ConcurrencyUnits <= limit.ConcurrencyUnits;
}

public enum DomainErrorCode
{
    IllegalStateTransition,
    RevisionConflict,
    StaleAttemptGeneration,
    AmbiguousExecution,
    DelegationExpired,
    DelegationLimitExceeded,
    CapabilityUnavailable,
    IdentityRenewalUnavailable,
    LifecycleBlockedByActiveWork,
    PortableStateIncomplete
}

public sealed class DomainRuleViolationException : InvalidOperationException
{
    public DomainErrorCode Code { get; }

    public DomainRuleViolationException(DomainErrorCode code, string message) : base(message) => Code = code;
}

internal static class Rule
{
    public static void Require(bool condition, DomainErrorCode code, string message)
    {
        if (!condition)
            throw new DomainRuleViolationException(code, message);
    }

    public static void Transition<T>(T current, T next, IReadOnlyDictionary<T, T[]> legal, string aggregate)
        where T : struct, Enum
    {
        if (!legal.TryGetValue(current, out var targets) || !targets.Contains(next))
            throw new DomainRuleViolationException(
                DomainErrorCode.IllegalStateTransition,
                $"{aggregate} cannot transition from {current} to {next}.");
    }
}
