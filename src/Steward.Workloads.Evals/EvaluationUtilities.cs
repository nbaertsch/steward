using System.Text.RegularExpressions;

namespace Steward.Workloads.Evals;

internal static partial class EvaluationTemplate
{
    [GeneratedRegex(@"\{[^{}]+\}", RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();

    internal static string Expand(string template, IReadOnlyDictionary<string, string?> replacements)
    {
        var stripped = Placeholder().Replace(template, string.Empty);
        if (stripped.Contains('{') || stripped.Contains('}'))
            throw new ArgumentException("Command template contains an unresolved or malformed placeholder.");
        return Placeholder().Replace(template, match =>
            replacements.TryGetValue(match.Value, out var replacement)
                ? replacement ?? string.Empty
                : throw new ArgumentException($"Unknown command template placeholder '{match.Value}'."));
    }
}

internal static class EvaluationIdentity
{
    internal static IReadOnlyList<IdentityCapabilityReference> SelectRequired(
        IReadOnlyList<IdentityCapabilityReference> available,
        IReadOnlyList<string> requiredCapabilities,
        string owner)
    {
        var byCapability = available.ToDictionary(x => x.Capability, StringComparer.Ordinal);
        var selected = new List<IdentityCapabilityReference>(requiredCapabilities.Count);
        foreach (var capability in requiredCapabilities)
            if (byCapability.TryGetValue(capability, out var identity)) selected.Add(identity);
            else throw new ArgumentException($"{owner} requires undeclared identity capability '{capability}'.");
        return selected;
    }
}
