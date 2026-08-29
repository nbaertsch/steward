using System.Diagnostics.CodeAnalysis;

namespace Steward.Domain;

public interface IStewardId
{
    Guid Value { get; }
}

internal static class IdValue
{
    public static Guid Require(Guid value, string name) =>
        value != Guid.Empty ? value : throw new ArgumentException($"{name} cannot be empty.", nameof(value));

    public static T Parse<T>(string value, Func<Guid, T> factory, string name)
    {
        if (!Guid.TryParseExact(value, "D", out var guid) || guid == Guid.Empty)
            throw new FormatException($"{name} must be a non-empty GUID in D format.");
        return factory(guid);
    }

    public static bool TryParse<T>(string? value, Func<Guid, T> factory, [NotNullWhen(true)] out T? result)
        where T : struct
    {
        if (Guid.TryParseExact(value, "D", out var guid) && guid != Guid.Empty)
        {
            result = factory(guid);
            return true;
        }

        result = null;
        return false;
    }
}

public readonly record struct WorkloadId : IStewardId
{
    public Guid Value { get; }
    public WorkloadId(Guid value) => Value = IdValue.Require(value, nameof(WorkloadId));
    public static WorkloadId New() => new(Guid.NewGuid());
    public static WorkloadId Parse(string value) => IdValue.Parse(value, x => new WorkloadId(x), nameof(WorkloadId));
    public static bool TryParse(string? value, out WorkloadId result) { var ok = IdValue.TryParse(value, x => new WorkloadId(x), out WorkloadId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct PlanRevisionId : IStewardId
{
    public Guid Value { get; }
    public PlanRevisionId(Guid value) => Value = IdValue.Require(value, nameof(PlanRevisionId));
    public static PlanRevisionId New() => new(Guid.NewGuid());
    public static PlanRevisionId Parse(string value) => IdValue.Parse(value, x => new PlanRevisionId(x), nameof(PlanRevisionId));
    public static bool TryParse(string? value, out PlanRevisionId result) { var ok = IdValue.TryParse(value, x => new PlanRevisionId(x), out PlanRevisionId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct TaskId : IStewardId
{
    public Guid Value { get; }
    public TaskId(Guid value) => Value = IdValue.Require(value, nameof(TaskId));
    public static TaskId New() => new(Guid.NewGuid());
    public static TaskId Parse(string value) => IdValue.Parse(value, x => new TaskId(x), nameof(TaskId));
    public static bool TryParse(string? value, out TaskId result) { var ok = IdValue.TryParse(value, x => new TaskId(x), out TaskId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct TaskAttemptId : IStewardId
{
    public Guid Value { get; }
    public TaskAttemptId(Guid value) => Value = IdValue.Require(value, nameof(TaskAttemptId));
    public static TaskAttemptId New() => new(Guid.NewGuid());
    public static TaskAttemptId Parse(string value) => IdValue.Parse(value, x => new TaskAttemptId(x), nameof(TaskAttemptId));
    public static bool TryParse(string? value, out TaskAttemptId result) { var ok = IdValue.TryParse(value, x => new TaskAttemptId(x), out TaskAttemptId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct StewardAgentId : IStewardId
{
    public Guid Value { get; }
    public StewardAgentId(Guid value) => Value = IdValue.Require(value, nameof(StewardAgentId));
    public static StewardAgentId New() => new(Guid.NewGuid());
    public static StewardAgentId Parse(string value) => IdValue.Parse(value, x => new StewardAgentId(x), nameof(StewardAgentId));
    public static bool TryParse(string? value, out StewardAgentId result) { var ok = IdValue.TryParse(value, x => new StewardAgentId(x), out StewardAgentId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct AgentTurnId : IStewardId
{
    public Guid Value { get; }
    public AgentTurnId(Guid value) => Value = IdValue.Require(value, nameof(AgentTurnId));
    public static AgentTurnId New() => new(Guid.NewGuid());
    public static AgentTurnId Parse(string value) => IdValue.Parse(value, x => new AgentTurnId(x), nameof(AgentTurnId));
    public static bool TryParse(string? value, out AgentTurnId result) { var ok = IdValue.TryParse(value, x => new AgentTurnId(x), out AgentTurnId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct HostId : IStewardId
{
    public Guid Value { get; }
    public HostId(Guid value) => Value = IdValue.Require(value, nameof(HostId));
    public static HostId New() => new(Guid.NewGuid());
    public static HostId Parse(string value) => IdValue.Parse(value, x => new HostId(x), nameof(HostId));
    public static bool TryParse(string? value, out HostId result) { var ok = IdValue.TryParse(value, x => new HostId(x), out HostId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct NodeIncarnationId : IStewardId
{
    public Guid Value { get; }
    public NodeIncarnationId(Guid value) => Value = IdValue.Require(value, nameof(NodeIncarnationId));
    public static NodeIncarnationId New() => new(Guid.NewGuid());
    public static NodeIncarnationId Parse(string value) => IdValue.Parse(value, x => new NodeIncarnationId(x), nameof(NodeIncarnationId));
    public static bool TryParse(string? value, out NodeIncarnationId result) { var ok = IdValue.TryParse(value, x => new NodeIncarnationId(x), out NodeIncarnationId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct PoolId : IStewardId
{
    public Guid Value { get; }
    public PoolId(Guid value) => Value = IdValue.Require(value, nameof(PoolId));
    public static PoolId New() => new(Guid.NewGuid());
    public static PoolId Parse(string value) => IdValue.Parse(value, x => new PoolId(x), nameof(PoolId));
    public static bool TryParse(string? value, out PoolId result) { var ok = IdValue.TryParse(value, x => new PoolId(x), out PoolId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct DelegationId : IStewardId
{
    public Guid Value { get; }
    public DelegationId(Guid value) => Value = IdValue.Require(value, nameof(DelegationId));
    public static DelegationId New() => new(Guid.NewGuid());
    public static DelegationId Parse(string value) => IdValue.Parse(value, x => new DelegationId(x), nameof(DelegationId));
    public static bool TryParse(string? value, out DelegationId result) { var ok = IdValue.TryParse(value, x => new DelegationId(x), out DelegationId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct CommandId : IStewardId
{
    public Guid Value { get; }
    public CommandId(Guid value) => Value = IdValue.Require(value, nameof(CommandId));
    public static CommandId New() => new(Guid.NewGuid());
    public static CommandId Parse(string value) => IdValue.Parse(value, x => new CommandId(x), nameof(CommandId));
    public static bool TryParse(string? value, out CommandId result) { var ok = IdValue.TryParse(value, x => new CommandId(x), out CommandId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct IdentityGrantId : IStewardId
{
    public Guid Value { get; }
    public IdentityGrantId(Guid value) => Value = IdValue.Require(value, nameof(IdentityGrantId));
    public static IdentityGrantId New() => new(Guid.NewGuid());
    public static IdentityGrantId Parse(string value) => IdValue.Parse(value, x => new IdentityGrantId(x), nameof(IdentityGrantId));
    public static bool TryParse(string? value, out IdentityGrantId result) { var ok = IdValue.TryParse(value, x => new IdentityGrantId(x), out IdentityGrantId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct PortableObjectId : IStewardId
{
    public Guid Value { get; }
    public PortableObjectId(Guid value) => Value = IdValue.Require(value, nameof(PortableObjectId));
    public static PortableObjectId New() => new(Guid.NewGuid());
    public static PortableObjectId Parse(string value) => IdValue.Parse(value, x => new PortableObjectId(x), nameof(PortableObjectId));
    public static bool TryParse(string? value, out PortableObjectId result) { var ok = IdValue.TryParse(value, x => new PortableObjectId(x), out PortableObjectId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct ProviderOperationId : IStewardId
{
    public Guid Value { get; }
    public ProviderOperationId(Guid value) => Value = IdValue.Require(value, nameof(ProviderOperationId));
    public static ProviderOperationId New() => new(Guid.NewGuid());
    public static ProviderOperationId Parse(string value) => IdValue.Parse(value, x => new ProviderOperationId(x), nameof(ProviderOperationId));
    public static bool TryParse(string? value, out ProviderOperationId result) { var ok = IdValue.TryParse(value, x => new ProviderOperationId(x), out ProviderOperationId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}

public readonly record struct NotificationId : IStewardId
{
    public Guid Value { get; }
    public NotificationId(Guid value) => Value = IdValue.Require(value, nameof(NotificationId));
    public static NotificationId New() => new(Guid.NewGuid());
    public static NotificationId Parse(string value) => IdValue.Parse(value, x => new NotificationId(x), nameof(NotificationId));
    public static bool TryParse(string? value, out NotificationId result) { var ok = IdValue.TryParse(value, x => new NotificationId(x), out NotificationId? parsed); result = parsed.GetValueOrDefault(); return ok; }
    public override string ToString() => Value.ToString("D");
}
