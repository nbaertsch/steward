using Steward.Application;
using Steward.Cli;
using Steward.DevBox.Windows;
using Steward.Domain;
using Steward.Terminal.Abstractions;

namespace Steward.Desktop.Windows;

public enum ExternalViewerFocusTarget
{
    Steward,
    WindowsApp
}

public enum ExternalViewerInteractionAction
{
    BrokerWindowVisible,
    Show,
    TakeControl,
    ReleaseControl,
    BrokerWindowClosed
}

public sealed record ExternalViewerInteractionState(
    bool BrokerWindowAvailable,
    ExternalViewerFocusTarget LastFocusTarget,
    bool FullscreenLaunchProven)
{
    public static ExternalViewerInteractionState Initial { get; } =
        new(false, ExternalViewerFocusTarget.Steward, false);
}

public static class ExternalViewerInteractionReducer
{
    public static ExternalViewerInteractionState Reduce(
        ExternalViewerInteractionState state,
        ExternalViewerInteractionAction action,
        bool fullscreenLaunchProven = false) =>
        action switch
        {
            ExternalViewerInteractionAction.BrokerWindowVisible =>
                new(
                    true,
                    ExternalViewerFocusTarget.WindowsApp,
                    fullscreenLaunchProven),
            ExternalViewerInteractionAction.Show
                when state.BrokerWindowAvailable =>
                state with
                {
                    LastFocusTarget = ExternalViewerFocusTarget.WindowsApp
                },
            ExternalViewerInteractionAction.TakeControl
                when state.BrokerWindowAvailable =>
                state with
                {
                    LastFocusTarget = ExternalViewerFocusTarget.WindowsApp
                },
            ExternalViewerInteractionAction.ReleaseControl =>
                state with
                {
                    LastFocusTarget = ExternalViewerFocusTarget.Steward
                },
            ExternalViewerInteractionAction.BrokerWindowClosed =>
                state with
                {
                    BrokerWindowAvailable = false,
                    LastFocusTarget = ExternalViewerFocusTarget.Steward
                },
            _ => throw new InvalidOperationException(
                $"External viewer action {action} is invalid without a tracked broker window.")
        };
}

public sealed record TerminalGateResult(
    bool Enabled,
    string? Code = null,
    string? Detail = null,
    bool ElevationGranted = false);

public static class TerminalGate
{
    public static TerminalGateResult Evaluate(
        TerminalPolicyStatus policy,
        NodeViewModel node,
        string workspaceRoot,
        TimeSpan duration,
        bool elevationRequested)
    {
        if (!policy.Enabled)
            return Denied(
                "TerminalPolicyDisabled",
                "Managed terminals are disabled by Control policy.");
        if (!node.Connected ||
            !node.Capabilities.Contains("terminal", StringComparer.Ordinal))
            return Denied(
                "TerminalRouteUnavailable",
                "The selected Node has no connected managed-terminal capability.");
        if (!policy.AllowedHosts.Contains(node.HostId))
            return Denied(
                "TerminalHostDenied",
                "Control policy does not authorize this Host.");
        if (duration <= TimeSpan.Zero || duration > policy.MaximumDuration)
            return Denied(
                "TerminalLeaseDenied",
                "The requested terminal lease exceeds Control policy.");
        if (!IsAllowedWorkspace(policy.AllowedWorkspaceRoots, workspaceRoot))
            return Denied(
                "TerminalWorkspaceDenied",
                "The requested workspace is outside Control policy.");
        if (elevationRequested &&
            !policy.ElevatedHosts.Contains(node.HostId))
            return Denied(
                "TerminalElevationDenied",
                "Control policy does not authorize elevation on this Host.");
        if (elevationRequested &&
            !node.Capabilities.Contains(
                "terminal.elevated-service",
                StringComparer.Ordinal))
            return Denied(
                "TerminalElevationUnavailable",
                "The Node does not advertise elevated managed-terminal execution.");
        return new(true, ElevationGranted: elevationRequested);
    }

    private static bool IsAllowedWorkspace(
        IReadOnlyList<string> allowedRoots,
        string workspace)
    {
        try
        {
            if (!Path.IsPathFullyQualified(workspace))
                return false;
            var candidate = Path.GetFullPath(workspace);
            foreach (var rootValue in allowedRoots)
            {
                var root = Path.GetFullPath(rootValue);
                var relative = Path.GetRelativePath(root, candidate);
                if (relative != ".." &&
                    !Path.IsPathRooted(relative) &&
                    !relative.StartsWith(
                        $"..{Path.DirectorySeparatorChar}",
                        StringComparison.Ordinal))
                    return true;
            }
            return false;
        }
        catch (Exception exception)
            when (exception is
                ArgumentException or
                NotSupportedException or
                PathTooLongException)
        {
            return false;
        }
    }

    private static TerminalGateResult Denied(
        string code,
        string detail) =>
        new(false, code, detail);
}

public sealed record TerminalSessionViewState(
    TerminalAuthority Authority,
    TerminalSessionSnapshot Snapshot,
    long OutputSequence,
    long OutputOffset,
    int Columns,
    int Rows,
    bool Closing);

public sealed class RefreshSequence
{
    private readonly object gate = new();
    private long sequence;

    public long Begin()
    {
        lock (gate)
            return ++sequence;
    }

    public bool IsCurrent(long value)
    {
        lock (gate)
            return value == sequence;
    }

    public bool TryPublish<T>(
        long value,
        T candidate,
        Action<T> publish)
    {
        ArgumentNullException.ThrowIfNull(publish);
        lock (gate)
        {
            if (value != sequence)
                return false;
            publish(candidate);
            return true;
        }
    }
}

public static class SafeErrorMapper
{
    public static DesktopError Map(Exception exception) =>
        exception switch
        {
            ControlApiException control =>
                new(control.Code, control.Detail ?? "Steward.Control rejected the operation."),
            TerminalException terminal =>
                new(
                    terminal.Problem.Code.ToString(),
                    terminal.Problem.Detail),
            OperationCanceledException =>
                new("OperationCancelled", "The operation was cancelled."),
            InvalidDataException =>
                new("InvalidRemoteData", "A remote response failed strict validation."),
            HttpRequestException =>
                new("ControlDisconnected", "Steward.Control is unreachable."),
            Azure.Identity.CredentialUnavailableException =>
                new("DevBoxCredentialUnavailable", "The devbox/default identity is unavailable."),
            Azure.Identity.AuthenticationFailedException =>
                new("DevBoxAuthenticationFailed", "Native WAM authentication failed."),
            Azure.RequestFailedException request =>
                new(
                    "DevBoxRequestFailed",
                    $"The Dev Center developer API returned HTTP {request.Status}."),
            DevBoxRemoteViewerException viewer =>
                new(viewer.Code, viewer.Message),
            _ => new(
                "DesktopOperationFailed",
                "The operation failed. Inspect local structured diagnostics.")
        };
}
