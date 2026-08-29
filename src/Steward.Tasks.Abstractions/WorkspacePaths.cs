namespace Steward.Tasks.Abstractions;

public static class WorkspacePaths
{
    private static readonly HashSet<string> WindowsDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public static bool IsSafeRelative(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            Path.IsPathFullyQualified(path) ||
            Path.IsPathRooted(path))
            return false;

        var components = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return components.All(component =>
            component is not (".." or "") &&
            (!OperatingSystem.IsWindows() || !IsWindowsDeviceComponent(component)));
    }

    public static string Resolve(string workspace, string relativePath, bool rejectLeafReparse = true)
    {
        if (!Path.IsPathFullyQualified(workspace)) throw new ArgumentException("Workspace must be absolute.", nameof(workspace));
        if (!Directory.Exists(workspace)) throw new DirectoryNotFoundException(workspace);
        if (!IsSafeRelative(relativePath)) throw new ArgumentException("Path must be a non-empty workspace-relative path.", nameof(relativePath));
        var root = Path.GetFullPath(workspace).TrimEnd(Path.DirectorySeparatorChar);
        var candidate = Path.GetFullPath(Path.Combine(root, relativePath));
        var prefix = root + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Path escapes the workspace.");

        var current = root;
        var segments = Path.GetRelativePath(root, candidate).Split(Path.DirectorySeparatorChar);
        for (var index = 0; index < segments.Length; index++)
        {
            current = Path.Combine(current, segments[index]);
            if (!File.Exists(current) && !Directory.Exists(current)) break;
            var isLeaf = index == segments.Length - 1;
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0 && (!isLeaf || rejectLeafReparse))
                throw new InvalidOperationException("Path traverses a reparse point.");
        }
        return candidate;
    }

    private static bool IsWindowsDeviceComponent(string component)
    {
        var normalized = component.TrimEnd(' ', '.');
        var streamIndex = normalized.IndexOf(':');
        if (streamIndex >= 0) normalized = normalized[..streamIndex];
        var extensionIndex = normalized.IndexOf('.');
        var deviceName = (extensionIndex >= 0 ? normalized[..extensionIndex] : normalized).TrimEnd(' ', '.');
        return WindowsDeviceNames.Contains(deviceName);
    }
}
