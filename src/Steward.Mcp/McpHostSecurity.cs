using Steward.Application;

namespace Steward.Mcp;

public static class McpHostSecurity
{
    public static void ValidateLoopbackBinding(string configuredUrls) =>
        LoopbackBindingValidator.Validate(configuredUrls, "Steward MCP");
}
