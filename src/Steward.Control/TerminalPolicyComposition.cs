using Steward.Application;
using Steward.Domain;

namespace Steward.Control;

public sealed class TerminalPolicyOptions
{
    public bool Enabled { get; set; }
    public List<string> AllowedActors { get; set; } = [];
    public List<string> AllowedHosts { get; set; } = [];
    public List<string> AllowedWorkspaceRoots { get; set; } = [];
    public List<string> ElevatedActors { get; set; } = [];
    public List<string> ElevatedHosts { get; set; } = [];
    public TimeSpan MaximumDuration { get; set; } = TimeSpan.FromMinutes(30);
    public long MaximumInputBytes { get; set; } = 4 * 1024 * 1024;
    public long MaximumOutputBytes { get; set; } = 16 * 1024 * 1024;

    public TerminalControlPolicy Validate()
    {
        if (!Enabled) return TerminalControlPolicy.DenyAll;
        var roots = AllowedWorkspaceRoots.Select(Path.GetFullPath).ToArray();
        if (AllowedActors.Count == 0 || AllowedHosts.Count == 0 || roots.Length == 0 ||
            MaximumDuration <= TimeSpan.Zero ||
            MaximumDuration > Steward.Terminal.Abstractions.TerminalContractLimits.MaximumLeaseDuration ||
            MaximumInputBytes <= 0 || MaximumOutputBytes <= 0)
            throw new InvalidOperationException("Control terminal policy is incomplete or outside bounds.");
        return new(
            AllowedActors.ToHashSet(StringComparer.Ordinal),
            AllowedHosts.Select(HostId.Parse).ToHashSet(),
            roots,
            ElevatedActors.ToHashSet(StringComparer.Ordinal),
            ElevatedHosts.Select(HostId.Parse).ToHashSet(),
            MaximumDuration, MaximumInputBytes, MaximumOutputBytes);
    }
}

public sealed class LocalOsActorContext : ILocalActorContext
{
    public string Actor { get; } =
        $"{Environment.UserDomainName}\\{Environment.UserName}";
}
