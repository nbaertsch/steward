using Steward.Application;
using Steward.Cli;
using Steward.Contracts;
using Steward.DevBox.Windows;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Providers.Abstractions;

namespace Steward.Desktop.Windows;

public enum DesktopConnectionState
{
    Connecting,
    Connected,
    Disconnected,
    Error
}

public sealed record DesktopError(string Code, string Detail);

public sealed record PoolKey(
    string Endpoint,
    string Project,
    string Pool);

public sealed record PoolViewModel(
    PoolKey Key,
    PoolId? PoolId,
    string DisplayName,
    string? Description,
    bool PermissionEligible,
    bool CanReadRemoteConnections,
    string Health,
    string Location,
    int? Cpu,
    int? RamGb,
    int? DiskGb,
    string Image,
    string StopPolicy,
    int CurrentCount,
    bool Registered,
    int? WarmMinimum,
    int? HardMaximum,
    TimeSpan? IdleTimeout,
    TimeSpan? StoppedRetention,
    ProviderBinding? ProviderBinding);

public sealed record NodeViewModel(
    HostId HostId,
    PoolId PoolId,
    NodeIncarnationId NodeIncarnationId,
    string ProviderResourceName,
    PoolMemberState LifecycleState,
    bool Connected,
    string Transport,
    ResourceRequirements Capacity,
    IReadOnlyList<string> Capabilities,
    int AssignedAttemptCount,
    IReadOnlyList<TaskAttemptId> AssignedAttempts,
    bool AssignedAttemptsTruncated,
    int IncompletePortableObjects,
    int CheckpointObjects,
    long LastFactCursor,
    string LastFact,
    DateTimeOffset? LastFactAt,
    DevBoxMemberDetails? DevBox,
    ProviderBinding? ProviderBinding,
    bool CanReadRemoteConnections);

public sealed record DesktopSnapshot(
    long Sequence,
    DateTimeOffset CapturedAt,
    DesktopConnectionState ConnectionState,
    ControlDoctorStatus? Doctor,
    ControlOrchestrationStatus? Orchestration,
    TerminalPolicyStatus? TerminalPolicy,
    DevBoxIdentityStatus Identity,
    bool CanMutate,
    IReadOnlyList<PoolViewModel> Pools,
    IReadOnlyList<NodeViewModel> Nodes,
    OperationsSnapshot Operations,
    DesktopError? Error);

public static class DesktopProjection
{
    public static DesktopSnapshot Create(
        long sequence,
        ControlDoctorStatus doctor,
        ControlOrchestrationStatus orchestration,
        TerminalPolicyStatus terminalPolicy,
        DevBoxIdentityStatus identity,
        bool canMutate,
        DevBoxInventory? inventory,
        IReadOnlyList<PoolRegistration> registrations,
        IReadOnlyList<HostView> hosts,
        IReadOnlyList<NodeEndpointRegistration> nodes,
        OperationsSnapshot operations)
    {
        var projects = (inventory?.Projects ?? [])
            .ToDictionary(
                value => ProjectKey(value.Endpoint, value.Name),
                value => value,
                StringComparer.OrdinalIgnoreCase);
        var registered = registrations
            .GroupBy(
                value => RegistrationKey(value.Provider),
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group.OrderBy(
                    value => value.Policy.PoolId.ToString(),
                    StringComparer.Ordinal).First(),
                StringComparer.OrdinalIgnoreCase);
        var poolValues = new List<PoolViewModel>();
        foreach (var pool in inventory?.Pools ?? [])
        {
            projects.TryGetValue(
                ProjectKey(pool.Endpoint, pool.ProjectName),
                out var project);
            registered.TryGetValue(
                PoolRegistrationKey(pool.Endpoint, pool.ProjectName, pool.Name),
                out var registration);
            poolValues.Add(ToPool(
                pool,
                project,
                registration,
                inventory?.DevBoxes.Count(value =>
                    SameEndpoint(value.Endpoint, pool.Endpoint) &&
                    string.Equals(
                        value.ProjectName,
                        pool.ProjectName,
                        StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(
                        value.PoolName,
                        pool.Name,
                        StringComparison.OrdinalIgnoreCase)) ?? 0));
        }
        foreach (var registration in registrations.Where(value =>
                     poolValues.All(pool =>
                         pool.PoolId != value.Policy.PoolId)))
        {
            poolValues.Add(new(
                new(
                    string.Empty,
                    registration.Provider.Project,
                    registration.Provider.Pool),
                registration.Policy.PoolId,
                registration.Provider.Pool,
                null,
                false,
                false,
                "Not discovered",
                "Unknown",
                null,
                null,
                null,
                "Unavailable until explicit discovery",
                "Unavailable until explicit discovery",
                hosts.Count(value =>
                    value.PoolId == registration.Policy.PoolId),
                true,
                registration.Policy.WarmMinimum,
                registration.Policy.HardMaximum,
                registration.Policy.IdleTimeout,
                registration.Policy.StoppedRetention,
                registration.Provider));
        }

        var nodeLookup = nodes.ToDictionary(value => value.HostId);
        var registrationLookup = registrations.ToDictionary(
            value => value.Policy.PoolId);
        var evidence = operations.NodeEvidence.ToDictionary(
            value => value.NodeIncarnationId);
        var devBoxes = inventory?.DevBoxes ?? [];
        var nodeValues = hosts.Select(host =>
        {
            nodeLookup.TryGetValue(host.HostId, out var node);
            registrationLookup.TryGetValue(host.PoolId, out var registration);
            evidence.TryGetValue(host.NodeIncarnationId, out var nodeEvidence);
            var box = registration is null
                ? null
                : devBoxes.FirstOrDefault(value =>
                    string.Equals(
                        value.ProjectName,
                        registration.Provider.Project,
                        StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(
                        value.PoolName,
                        registration.Provider.Pool,
                        StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(
                        value.Name,
                        host.ProviderResourceName,
                        StringComparison.OrdinalIgnoreCase));
            var canReadRemote = box is not null &&
                projects.TryGetValue(
                    ProjectKey(box.Endpoint, box.ProjectName),
                    out var project) &&
                project.CanReadRemoteConnections;
            return new NodeViewModel(
                host.HostId,
                host.PoolId,
                host.NodeIncarnationId,
                host.ProviderResourceName,
                host.State,
                host.Connected && node?.Enabled == true,
                node is null
                    ? "Unavailable"
                    : $"{node.Transport.Kind}/{node.Transport.Version}",
                node?.Capacity ?? new ResourceRequirements(),
                node?.Capabilities ?? [],
                nodeEvidence?.ActiveAttemptCount ?? 0,
                nodeEvidence?.ActiveAttemptIds ?? [],
                nodeEvidence?.ActiveAttemptsTruncated ?? false,
                nodeEvidence?.IncompletePortableObjects ?? 0,
                nodeEvidence?.CheckpointObjects ?? 0,
                nodeEvidence?.ContiguousCursor ?? 0,
                nodeEvidence?.LastFactKind ?? "No facts",
                nodeEvidence?.LastFactAt,
                box,
                registration?.Provider,
                canReadRemote);
        }).OrderBy(value => value.ProviderResourceName, StringComparer.OrdinalIgnoreCase)
          .ToArray();

        return new(
            sequence,
            operations.CapturedAt,
            doctor.Healthy
                ? DesktopConnectionState.Connected
                : DesktopConnectionState.Error,
            doctor,
            orchestration,
            terminalPolicy,
            identity,
            canMutate,
            poolValues
                .OrderBy(value => value.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            nodeValues,
            operations,
            doctor.Healthy
                ? null
                : new("ControlUnhealthy", "Steward.Control reported an unhealthy durable store."));
    }

    public static bool IsNewer(
        DesktopSnapshot? current,
        DesktopSnapshot candidate) =>
        current is null || candidate.Sequence > current.Sequence;

    public static DesktopSnapshot Reduce(
        DesktopSnapshot? current,
        DesktopSnapshot candidate) =>
        IsNewer(current, candidate)
            ? candidate
            : current!;

    private static PoolViewModel ToPool(
        DevBoxPoolDetails pool,
        DiscoveredDevCenterProject? project,
        PoolRegistration? registration,
        int count) =>
        new(
            new(
                pool.Endpoint.GetLeftPart(UriPartial.Authority),
                pool.ProjectName,
                pool.Name),
            registration?.Policy.PoolId,
            project?.DisplayName is { Length: > 0 } display
                ? $"{display} / {pool.Name}"
                : $"{pool.ProjectName} / {pool.Name}",
            project?.Description,
            project?.CanCreateDevBoxes == true,
            project?.CanReadRemoteConnections == true,
            pool.Health ?? "Unknown",
            pool.Location ?? "Unknown",
            pool.VirtualCpuCount,
            pool.RamGb,
            pool.OsDiskGb,
            string.Join(
                " ",
                new[] { pool.ImageName, pool.ImageVersion, pool.ImageBuild }
                    .Where(value => !string.IsNullOrWhiteSpace(value))),
            pool.StopPolicy is null
                ? "Not reported"
                : $"{pool.StopPolicy.Status}; grace {pool.StopPolicy.GracePeriodMinutes?.ToString() ?? "n/a"} min",
            count,
            registration is not null,
            registration?.Policy.WarmMinimum,
            registration?.Policy.HardMaximum,
            registration?.Policy.IdleTimeout,
            registration?.Policy.StoppedRetention,
            registration?.Provider);

    private static string ProjectKey(Uri endpoint, string project) =>
        $"{endpoint.GetLeftPart(UriPartial.Authority)}|{project}";

    private static string RegistrationKey(ProviderBinding binding) =>
        $"{binding.Project}|{binding.Pool}";

    private static string PoolRegistrationKey(
        Uri endpoint,
        string project,
        string pool) =>
        $"{project}|{pool}";

    private static bool SameEndpoint(Uri left, Uri right) =>
        string.Equals(
            left.GetLeftPart(UriPartial.Authority),
            right.GetLeftPart(UriPartial.Authority),
            StringComparison.OrdinalIgnoreCase);
}

public enum PoolCommand
{
    Register,
    Reconcile,
    InspectMembers
}

public enum NodeCommand
{
    Inspect,
    Reconnect,
    Drain,
    Start,
    Stop,
    Recreate,
    Delete,
    OpenRemoteViewer,
    OpenShell
}

public sealed record CommandAvailability(bool Enabled, string? Reason = null);

public static class CapabilityGate
{
    public static CommandAvailability Pool(
        PoolViewModel pool,
        PoolCommand command,
        ControlOrchestrationStatus orchestration,
        bool canMutate) =>
        command switch
        {
            PoolCommand.Register when pool.Registered =>
                Disabled("Pool is already registered."),
            PoolCommand.Register when !pool.PermissionEligible =>
                Disabled("The signed-in Dev Center project does not grant Dev Box write eligibility."),
            PoolCommand.Register when !orchestration.ProviderLifecycleEnabled =>
                Disabled("Control has no provider lifecycle adapter."),
            PoolCommand.Register when !canMutate =>
                Disabled("The local Control mutation token is unavailable."),
            PoolCommand.Register => Enabled(),
            PoolCommand.Reconcile when !pool.Registered =>
                Disabled("Register the Pool before reconciliation."),
            PoolCommand.Reconcile when !orchestration.ProviderLifecycleEnabled =>
                Disabled("Control has no provider lifecycle adapter."),
            PoolCommand.Reconcile when !canMutate =>
                Disabled("The local Control mutation token is unavailable."),
            PoolCommand.Reconcile => Enabled(),
            PoolCommand.InspectMembers => Enabled(),
            _ => Disabled("Command is unavailable.")
        };

    public static CommandAvailability Node(
        NodeViewModel node,
        NodeCommand command,
        ControlOrchestrationStatus orchestration,
        TerminalPolicyStatus terminalPolicy,
        bool canMutate)
    {
        if (command == NodeCommand.Inspect)
            return Enabled();
        if (command == NodeCommand.Reconnect)
            return Disabled(
                "This Control/Node transport does not advertise an explicit reconnect command.");
        if (command == NodeCommand.OpenRemoteViewer)
            return node.CanReadRemoteConnections &&
                   string.Equals(
                       node.DevBox?.PowerState,
                       "Running",
                       StringComparison.OrdinalIgnoreCase)
                ? Enabled()
                : Disabled(
                    "RDP requires a running discovered Dev Box and remote-connection permission.");
        if (command == NodeCommand.OpenShell)
        {
            var terminal = TerminalGate.Evaluate(
                terminalPolicy,
                node,
                terminalPolicy.AllowedWorkspaceRoots.FirstOrDefault() ?? string.Empty,
                TimeSpan.FromMinutes(30),
                elevationRequested: false);
            return new(terminal.Enabled, terminal.Detail);
        }
        if (!canMutate)
            return Disabled("The local Control mutation token is unavailable.");
        if (!orchestration.ProviderLifecycleEnabled)
            return Disabled("Control has no provider lifecycle adapter.");
        return command switch
        {
            NodeCommand.Start when node.LifecycleState == PoolMemberState.Stopped =>
                Enabled(),
            NodeCommand.Drain when node.LifecycleState is
                PoolMemberState.Warm or PoolMemberState.Assigned =>
                Enabled(),
            NodeCommand.Stop when node.LifecycleState is
                PoolMemberState.Warm or PoolMemberState.Assigned or PoolMemberState.Draining =>
                Enabled(),
            NodeCommand.Recreate when node.LifecycleState is not
                (PoolMemberState.Creating or PoolMemberState.Deleted) =>
                Enabled(),
            NodeCommand.Delete when node.LifecycleState is
                PoolMemberState.Stopped or PoolMemberState.Failed or PoolMemberState.Draining =>
                Enabled(),
            _ => Disabled(
                $"Command is not valid while the member is {node.LifecycleState}.")
        };
    }

    private static CommandAvailability Enabled() => new(true);
    private static CommandAvailability Disabled(string reason) => new(false, reason);
}

public sealed record DestructiveConfirmation(
    NodeCommand Command,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string ProviderResourceName,
    IReadOnlyList<TaskAttemptId> ActiveAttempts,
    int ActiveAttemptCount,
    int IncompletePortableObjects,
    bool ForceRequired,
    string RequiredText,
    string Message);

public static class DestructiveConfirmationFactory
{
    public static DestructiveConfirmation Create(
        NodeViewModel node,
        NodeCommand command)
    {
        if (command is not (
            NodeCommand.Drain or
            NodeCommand.Stop or
            NodeCommand.Recreate or
            NodeCommand.Delete))
            throw new ArgumentOutOfRangeException(
                nameof(command),
                "The command is not destructive.");
        var force = node.AssignedAttemptCount > 0 ||
                    node.IncompletePortableObjects > 0;
        var attemptText = node.AssignedAttemptCount == 0
            ? "none"
            : string.Join(", ", node.AssignedAttempts) +
              (node.AssignedAttemptsTruncated
                  ? $" … and {node.AssignedAttemptCount - node.AssignedAttempts.Count} more"
                  : string.Empty);
        var message =
            $"{command} Host {node.HostId} ({node.ProviderResourceName}), " +
            $"Node incarnation {node.NodeIncarnationId}.\r\n\r\n" +
            $"Active TaskAttempts: {attemptText}\r\n" +
            $"Unreplicated portable objects: {node.IncompletePortableObjects}\r\n\r\n" +
            (force
                ? "This requires an explicit forced operation and may lose the named work or state."
                : "Control reports no active TaskAttempt or incomplete portable state.") +
            $"\r\n\r\nType {node.ProviderResourceName} to authorize this exact operation.";
        return new(
            command,
            node.HostId,
            node.NodeIncarnationId,
            node.ProviderResourceName,
            node.AssignedAttempts,
            node.AssignedAttemptCount,
            node.IncompletePortableObjects,
            force,
            node.ProviderResourceName,
            message);
    }

    public static bool Matches(
        DestructiveConfirmation confirmation,
        string input) =>
        string.Equals(
            confirmation.RequiredText,
            input.Trim(),
            StringComparison.Ordinal);
}
