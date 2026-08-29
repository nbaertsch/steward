namespace Steward.PortableState;

public enum PortableFailureCode
{
    RemoteAuthority,
    RemoteIntegrity,
    RemoteConflict,
    RemoteUnavailable,
    LocalIntegrity,
    Unknown
}

public sealed record SanitizedPortableError(PortableFailureCode Code, string Detail);

public static class PortableErrorSanitizer
{
    public static SanitizedPortableError Sanitize(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var code = exception switch
        {
            PortableStateException portable when portable.Code != PortableFailureCode.Unknown => portable.Code,
            PortableStateException when exception.Message.Contains("authorit", StringComparison.OrdinalIgnoreCase) =>
                PortableFailureCode.RemoteAuthority,
            PortableStateException when exception.Message.Contains("hash", StringComparison.OrdinalIgnoreCase) ||
                                        exception.Message.Contains("integrity", StringComparison.OrdinalIgnoreCase) =>
                PortableFailureCode.RemoteIntegrity,
            PortableStateException when exception.Message.Contains("exist", StringComparison.OrdinalIgnoreCase) ||
                                        exception.Message.Contains("conflict", StringComparison.OrdinalIgnoreCase) =>
                PortableFailureCode.RemoteConflict,
            IOException => PortableFailureCode.RemoteUnavailable,
            _ => PortableFailureCode.Unknown
        };
        return new(code, $"Portable-state operation failed ({code}).");
    }
}
