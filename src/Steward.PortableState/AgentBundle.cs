using Steward.Domain;

namespace Steward.PortableState;

public sealed record AgentBundleEntry(string Name, string Sha256, long Length);

public sealed record StewardAgentBundle(
    StewardAgentId AgentId,
    IReadOnlyList<PortableObjectId> CheckpointLineage,
    AgentBundleEntry CompactedContext,
    AgentBundleEntry GitBundle,
    AgentBundleEntry DirtyStatePatch,
    AgentBundleEntry EnvironmentManifest,
    AgentBundleEntry PendingTurns)
{
    public void Validate()
    {
        if (CheckpointLineage.Count == 0)
            throw new PortableStateException("An agent bundle requires checkpoint lineage.");
        foreach (var entry in Entries)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(entry.Name);
            PortableObjectDescriptor.ValidateSha256(entry.Sha256);
            if (entry.Length < 0)
                throw new PortableStateException("Agent bundle entry lengths cannot be negative.");
            if (entry.Name.Contains("credential", StringComparison.OrdinalIgnoreCase) ||
                entry.Name.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
                entry.Name.Contains("token", StringComparison.OrdinalIgnoreCase))
                throw new PortableStateException("Agent bundles cannot contain credentials or secrets.");
        }
    }

    private IEnumerable<AgentBundleEntry> Entries =>
        [CompactedContext, GitBundle, DirtyStatePatch, EnvironmentManifest, PendingTurns];
}
