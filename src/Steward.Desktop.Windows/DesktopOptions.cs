using Steward.Application;

namespace Steward.Desktop.Windows;

public sealed record DesktopOptions(
    Uri ControlUri,
    bool DiscoverPoolsOnStartup,
    string ConnectionHostPipeName,
    string? ConnectionAuthorizationToken,
    string? DvcEvidenceReference)
{
    public static DesktopOptions Parse(
        IReadOnlyList<string> arguments)
    {
        var control = Environment.GetEnvironmentVariable(
            "STEWARD_CONTROL_URL");
        if (string.IsNullOrWhiteSpace(control))
            control = "http://127.0.0.1:5112/";
        if (!Uri.TryCreate(control, UriKind.Absolute, out var controlUri))
            throw new InvalidOperationException(
                "STEWARD_CONTROL_URL must be an absolute loopback URI.");
        LoopbackBindingValidator.Validate(
            controlUri.AbsoluteUri,
            "Steward Desktop Control client");
        var discover =
            arguments.Contains(
                "--discover-pools",
                StringComparer.Ordinal) ||
            string.Equals(
                Environment.GetEnvironmentVariable(
                    "STEWARD_DESKTOP_DISCOVER_POOLS_ON_STARTUP"),
                "true",
                StringComparison.OrdinalIgnoreCase);
        return new(
            controlUri.AbsoluteUri.EndsWith(
                "/",
                StringComparison.Ordinal)
                ? controlUri
                : new Uri(controlUri.AbsoluteUri + "/"),
            discover,
            Environment.GetEnvironmentVariable(
                "STEWARD_CONNECTION_HOST_PIPE_NAME") is
                { Length: > 0 } pipeName
                ? pipeName
                : "Steward.ConnectionHost.v1",
            Environment.GetEnvironmentVariable(
                "STEWARD_CONNECTION_HOST_CONTROL_AUTHORIZATION_TOKEN"),
            Environment.GetEnvironmentVariable(
                "STEWARD_CONNECTION_HOST_DVC_EVIDENCE_REFERENCE"));
    }
}
