namespace Steward.RdCore.Windows;

public sealed record RdCoreIntegrationOptions
{
    public bool Enabled { get; init; }

    public Uri? AvdFeedUri { get; init; }

    public string Account { get; init; } = string.Empty;

    public string ClaimsClientId { get; init; } = string.Empty;

    public string ClaimsRedirectUri { get; init; } = string.Empty;

    public bool ConsumerHandlesClaimsTokenRequest { get; init; } = true;
    public bool ReleaseClaimsOwnershipAfterAvdTokens { get; init; }

    public string ClientIdentifier { get; init; } = "Steward";

    public string ClientVersion { get; init; } = "1.0";

    public ushort ClientBuild { get; init; }

    public TimeSpan OperationTimeout { get; init; } = TimeSpan.FromSeconds(15);

    public int MaximumResources { get; init; } = 256;

    public int MaximumRdpContentBytes { get; init; } = 1024 * 1024;

    public Action<string>? DiagnosticSink { get; init; }

    internal void Report(string stage) =>
        DiagnosticSink?.Invoke(stage);

    internal void Validate(bool requireFeed)
    {
        if (!Enabled)
        {
            throw new InvalidOperationException(
                "The RDCore integration kill-switch is disabled.");
        }

        if (requireFeed &&
            (AvdFeedUri is null ||
             !AvdFeedUri.IsAbsoluteUri ||
             AvdFeedUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException(
                "An absolute HTTPS AVD feed URI is required.",
                nameof(AvdFeedUri));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(Account);
        ArgumentException.ThrowIfNullOrWhiteSpace(ClaimsClientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(ClaimsRedirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(ClientIdentifier);
        ArgumentException.ThrowIfNullOrWhiteSpace(ClientVersion);
        if (OperationTimeout <= TimeSpan.Zero ||
            OperationTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(OperationTimeout),
                "The RDCore operation timeout must be at most one minute.");
        }

        if (MaximumResources is <= 0 or > 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumResources),
                "The RDCore resource bound is unsupported.");
        }

        if (MaximumRdpContentBytes is <= 0 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumRdpContentBytes),
                "The RDCore RDP content bound is unsupported.");
        }
    }

    public override string ToString() =>
        $"RdCoreIntegrationOptions {{ Enabled = {Enabled}, " +
        "SensitiveValues = [REDACTED] }";
}

public sealed record RdCoreClaimsTokenRequest(
    string AuthorityUri,
    string Claims,
    string ClientId,
    string ResourceUri,
    string Scope,
    string UserNameHint,
    string RedirectUri = "")
{
    public override string ToString() =>
        "RdCoreClaimsTokenRequest { Values = [REDACTED] }";
}

public sealed record RdCoreClaimsToken(
    string Token,
    string TokenAuthority,
    string UserName,
    bool AcquiredSilently,
    string AadResourceTenantId,
    string AadDeviceId,
    string AadP2PRootCertificates)
{
    public override string ToString() =>
        "RdCoreClaimsToken { Values = [REDACTED] }";
}

public interface IRdCoreCredentialCallback
{
    ValueTask<RdCoreClaimsToken> AcquireTokenAsync(
        RdCoreClaimsTokenRequest request,
        CancellationToken cancellationToken);
}

public sealed record RdCoreResolvedConnection(
    string SignedRdpText,
    Uri ProviderResourceUri)
{
    public override string ToString() =>
        "RdCoreResolvedConnection { Values = [REDACTED] }";
}
