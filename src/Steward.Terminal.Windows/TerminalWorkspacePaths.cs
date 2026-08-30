using Steward.Terminal.Abstractions;

namespace Steward.Terminal.Windows;

public static class TerminalWorkspacePaths
{
    public static string ValidateRoot(string workspaceRoot)
    {
        try
        {
            if (!Path.IsPathFullyQualified(workspaceRoot) || !Directory.Exists(workspaceRoot))
                throw Rejected("Terminal workspace root does not exist.");
            var canonical = Path.GetFullPath(workspaceRoot);
            if (!Path.TrimEndingDirectorySeparator(canonical)
                    .Equals(Path.TrimEndingDirectorySeparator(workspaceRoot), StringComparison.OrdinalIgnoreCase))
                throw Rejected("Terminal workspace root must be canonical.");
            RejectReparseComponents(canonical);
            return canonical;
        }
        catch (TerminalException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw Rejected("Terminal workspace root is not safely accessible.");
        }
    }

    public static string ValidateWorkingDirectory(string workspaceRoot, string workingDirectory)
    {
        var root = ValidateRoot(workspaceRoot);
        try
        {
            if (!Path.IsPathFullyQualified(workingDirectory) || !Directory.Exists(workingDirectory))
                throw Rejected("Terminal working directory does not exist.");
            var candidate = Path.GetFullPath(workingDirectory);
            var exactRoot = Path.TrimEndingDirectorySeparator(root);
            var exactCandidate = Path.TrimEndingDirectorySeparator(candidate);
            if (!exactCandidate.Equals(exactRoot, StringComparison.OrdinalIgnoreCase) &&
                !exactCandidate.StartsWith(exactRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw Rejected("Terminal working directory escapes the authorized workspace.");
            RejectReparseComponents(candidate);
            return candidate;
        }
        catch (TerminalException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw Rejected("Terminal working directory is not safely accessible.");
        }
    }

    private static void RejectReparseComponents(string path)
    {
        var root = Path.GetPathRoot(path) ?? throw Rejected("Terminal path has no volume root.");
        var relative = Path.GetRelativePath(root, path);
        var current = root;
        if (relative == ".")
            return;
        foreach (var component in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw Rejected("Terminal path traverses a reparse point.");
        }
    }

    private static TerminalException Rejected(string detail) =>
        new(new(TerminalProblemCode.PathRejected, detail, TerminalProblemDisposition.Terminal, false));
}
