using Steward.Domain;
using Steward.Terminal.Abstractions;

namespace Steward.Cli;

public static class ControlRoutes
{
    public const string Doctor = "doctor";
    public const string OrchestrationDoctor = "doctor/orchestration";
    public const string Operations = "operations";
    public const string Pools = "pools";
    public const string Hosts = "hosts";
    public const string Nodes = "nodes";
    public const string TerminalPolicy = "terminals/policy";

    public static string PoolReconcile(PoolId id) => $"pools/{id}/reconcile";
    public static string Host(HostId id) => $"hosts/{id}";
    public static string HostProvider(HostId id) => $"hosts/{id}/provider";
    public static string HostAction(
        HostId id,
        string action,
        bool? force = null,
        NodeIncarnationId? expectedIncarnation = null)
    {
        var query = new List<string>();
        if (force is not null)
            query.Add($"force={force.Value.ToString().ToLowerInvariant()}");
        if (expectedIncarnation is not null)
            query.Add($"expectedIncarnation={expectedIncarnation}");
        return $"hosts/{id}/{action}" +
            (query.Count == 0 ? string.Empty : $"?{string.Join("&", query)}");
    }

    public static string HostDelete(
        HostId id,
        bool force,
        NodeIncarnationId? expectedIncarnation = null)
    {
        var route = $"{Host(id)}?force={force.ToString().ToLowerInvariant()}";
        return expectedIncarnation is null
            ? route
            : $"{route}&expectedIncarnation={expectedIncarnation}";
    }

    public static string TaskEvents(TaskId id, long after, int limit) =>
        $"tasks/{id}/events?after={after}&limit={limit}";

    public static string Terminal(TerminalSessionId id) => $"terminals/{id}";
    public static string TerminalAction(TerminalSessionId id, string action) =>
        $"{Terminal(id)}/{action}";
}
