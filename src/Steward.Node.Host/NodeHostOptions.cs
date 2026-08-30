using Steward.Domain;

namespace Steward.Node.Host;

public sealed class NodeHostOptions
{
    public string JournalPath { get; set; } = string.Empty;
    public string ExecutionJournalPath { get; set; } = string.Empty;
    public string EvaluationDatabasePath { get; set; } = string.Empty;
    public string WorkspaceRoot { get; set; } = string.Empty;
    public string SpoolRoot { get; set; } = string.Empty;
    public long SpoolHighLimitBytes { get; set; } = 4L * 1024 * 1024 * 1024;
    public long SpoolHardLimitBytes { get; set; } = 8L * 1024 * 1024 * 1024;
    public long SpoolOsReserveBytes { get; set; } = 2L * 1024 * 1024 * 1024;
    public string KeeperPipeName { get; set; } = "Steward.HandleKeeper";
    public string NodeIncarnationId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string TerminalJournalPath { get; set; } = string.Empty;
    public int MaximumTerminalSessions { get; set; } = 32;
    public bool AgentsEnabled { get; set; }
    public string AgentExecutable { get; set; } = string.Empty;
    public string AgentRuntimeProfile { get; set; } = "process-jsonl/1.0";

    public ValidatedNodeHostOptions Validate()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The production Steward Node host requires Windows.");
        var journal = FullFile(JournalPath, nameof(JournalPath));
        var execution = FullFile(ExecutionJournalPath, nameof(ExecutionJournalPath));
        var evaluation = FullFile(EvaluationDatabasePath, nameof(EvaluationDatabasePath));
        if (!Path.IsPathFullyQualified(WorkspaceRoot))
            throw new InvalidOperationException("NodeHost:WorkspaceRoot must be fully qualified.");
        var spoolRoot = string.IsNullOrWhiteSpace(SpoolRoot)
            ? Path.Combine(Path.GetDirectoryName(journal)!, "spool")
            : FullFile(SpoolRoot, nameof(SpoolRoot));
        if (SpoolHighLimitBytes < 0 || SpoolHardLimitBytes <= 0 ||
            SpoolHighLimitBytes > SpoolHardLimitBytes || SpoolOsReserveBytes < 0)
            throw new InvalidOperationException("NodeHost spool bounds are invalid.");
        if (!Domain.NodeIncarnationId.TryParse(NodeIncarnationId, out var incarnation))
            throw new InvalidOperationException("NodeHost:NodeIncarnationId is invalid.");
        if (!Domain.HostId.TryParse(HostId, out var hostId))
            throw new InvalidOperationException("NodeHost:HostId is invalid.");
        var terminalJournal = FullFile(
            string.IsNullOrWhiteSpace(TerminalJournalPath)
                ? Path.Combine(Path.GetDirectoryName(journal)!, "terminal.db")
                : TerminalJournalPath,
            nameof(TerminalJournalPath));
        if (MaximumTerminalSessions is <= 0 or > 256)
            throw new InvalidOperationException("NodeHost maximum terminal sessions is invalid.");
        string? agentExecutable = null;
        if (AgentsEnabled)
        {
            agentExecutable = FullExistingFile(AgentExecutable, nameof(AgentExecutable));
            if (Path.GetExtension(agentExecutable) is ".cmd" or ".bat" or ".ps1" or ".sh" ||
                string.IsNullOrWhiteSpace(AgentRuntimeProfile))
                throw new InvalidOperationException("Node Agent runtime profile is invalid.");
        }
        if (string.IsNullOrWhiteSpace(KeeperPipeName) || KeeperPipeName.Length > 128)
            throw new InvalidOperationException("NodeHost:KeeperPipeName is invalid.");
        return new(journal, execution, evaluation, Path.GetFullPath(WorkspaceRoot),
            spoolRoot, SpoolHighLimitBytes, SpoolHardLimitBytes, SpoolOsReserveBytes,
            KeeperPipeName,
            incarnation, hostId, terminalJournal, MaximumTerminalSessions,
            AgentsEnabled, agentExecutable, AgentRuntimeProfile);
    }

    private static string FullFile(string value, string name)
    {
        Required(value, name);
        if (!Path.IsPathFullyQualified(value))
            throw new InvalidOperationException($"NodeHost:{name} must be fully qualified.");
        return Path.GetFullPath(value);
    }

    private static string FullExistingFile(string value, string name)
    {
        var full = FullFile(value, name);
        if (!File.Exists(full)) throw new InvalidOperationException($"NodeHost:{name} does not exist.");
        return full;
    }

    private static void Required(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"NodeHost:{name} is required.");
    }
}

public sealed record ValidatedNodeHostOptions(
    string JournalPath,
    string ExecutionJournalPath,
    string EvaluationDatabasePath,
    string WorkspaceRoot,
    string SpoolRoot,
    long SpoolHighLimitBytes,
    long SpoolHardLimitBytes,
    long SpoolOsReserveBytes,
    string KeeperPipeName,
    NodeIncarnationId IncarnationId,
    HostId HostId,
    string TerminalJournalPath,
    int MaximumTerminalSessions,
    bool AgentsEnabled,
    string? AgentExecutable,
    string AgentRuntimeProfile);
