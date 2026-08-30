namespace Steward.Orchestration;

public sealed record NodeExecutionOptions(string WorkspaceRoot)
{
    public string ValidateAndGetRoot()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(WorkspaceRoot);
        if (!Path.IsPathFullyQualified(WorkspaceRoot))
            throw new ArgumentException("Node WorkspaceRoot must be fully qualified.", nameof(WorkspaceRoot));
        var root = Path.GetFullPath(WorkspaceRoot);
        if (new DirectoryInfo(root).Exists &&
            new DirectoryInfo(root).Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new IOException("Node WorkspaceRoot cannot be a reparse point.");
        return root;
    }
}

internal static class OrchestrationWorkspace
{
    public static string ValidateAttemptPath(string configuredRoot, string candidate)
    {
        var root = Path.GetFullPath(configuredRoot);
        if (!Path.IsPathFullyQualified(candidate))
            throw new InvalidOperationException("workspace.path-not-absolute");
        var full = Path.GetFullPath(candidate);
        var relative = Path.GetRelativePath(root, full);
        if (relative is "." or "" ||
            Path.IsPathRooted(relative) ||
            relative.Equals("..", StringComparison.Ordinal) ||
            relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            throw new InvalidOperationException("workspace.path-outside-root");
        RejectExistingReparsePoints(root, full);
        return full;
    }

    private static void RejectExistingReparsePoints(string root, string full)
    {
        var current = root;
        if (Directory.Exists(current) &&
            File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint))
            throw new IOException("workspace.reparse-root");
        foreach (var segment in Path.GetRelativePath(root, full)
                     .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            current = Path.Combine(current, segment);
            if ((Directory.Exists(current) || File.Exists(current)) &&
                File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("workspace.reparse-segment");
        }
    }
}

internal static class OrchestrationErrors
{
    public static (string Code, string Detail) Recovery(Exception exception) => exception switch
    {
        KeyNotFoundException => ("task-type.unavailable", "The required TaskType or durable execution record is unavailable."),
        ArgumentException => ("task-input.invalid", "The immutable Task input or execution boundary is invalid."),
        UnauthorizedAccessException => ("workspace.access-denied", "The managed workspace could not be accessed."),
        IOException => ("runtime.io-failure", "A managed runtime I/O operation failed."),
        _ => ("runtime.reconciliation-required", "Managed execution evidence is incomplete and requires reconciliation.")
    };

    public static string TerminalDetail(string code) => code switch
    {
        "cancelled" => "Task cancellation completed.",
        "setup.failed" => "Task setup or readiness failed.",
        "runtime.failed" => "The managed runtime reported failure.",
        "cleanup.failed" => "Task cleanup did not complete; inspect bounded runtime logs.",
        _ => "Task lifecycle completed."
    };
}
