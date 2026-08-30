using System.Net;
using Steward.Contracts;
using Steward.Domain;

namespace Steward.Application;

public static class ApplicationLimits
{
    public const int NameLength = 128;
    public const int IdempotencyKeyLength = 128;
    public const int PlannerDataLength = 32_768;
    public const int PlannerDataDepth = 32;
    public const int NotificationStreamLength = 256;
    public const int NotificationLimit = 50;
}

public sealed class ApplicationContractException(
    string code,
    string detail,
    ProblemDisposition disposition = ProblemDisposition.RequiresNewUserIntent)
    : InvalidOperationException(detail)
{
    public string Code { get; } = code;
    public ProblemDisposition Disposition { get; } = disposition;
}

public static class LoopbackBindingValidator
{
    public static void Validate(string configuredUrls, string serviceName)
    {
        if (string.IsNullOrWhiteSpace(configuredUrls))
            throw Invalid(serviceName, configuredUrls);

        var values = configuredUrls.Split(';', StringSplitOptions.TrimEntries);
        if (values.Length == 0 || values.Any(string.IsNullOrWhiteSpace))
            throw Invalid(serviceName, configuredUrls);

        foreach (var value in values)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                uri.Scheme is not ("http" or "https") ||
                !string.IsNullOrEmpty(uri.UserInfo) ||
                uri.AbsolutePath != "/" ||
                !string.IsNullOrEmpty(uri.Query) ||
                !string.IsNullOrEmpty(uri.Fragment) ||
                !IsLoopbackHost(uri.Host))
            {
                throw Invalid(serviceName, value);
            }
        }
    }

    private static bool IsLoopbackHost(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
        IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);

    private static InvalidOperationException Invalid(string serviceName, string? value) =>
        new($"{serviceName} refuses non-loopback or malformed binding '{value}'. " +
            "Only localhost, 127.0.0.1, and [::1] HTTP(S) bindings are supported.");
}
