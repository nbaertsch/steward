using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.Desktop.Windows;

public sealed record ConnectionHostCommandResult(
    bool HostAvailable,
    bool Accepted,
    string Code,
    ConnectionHostStatus? Status,
    IReadOnlyList<ConnectionHostStatus>? Connections = null)
{
    public static ConnectionHostCommandResult Unavailable(string code) =>
        new(false, false, code, null);
}

public interface IConnectionHostPipeGateway
{
    bool ConnectConfigured { get; }

    Task<ConnectionHostCommandResult> StatusAsync(
        string connectionId,
        CancellationToken cancellationToken);

    Task<ConnectionHostCommandResult> ResolveAsync(
        string connectionId,
        Uri providerResource,
        CancellationToken cancellationToken);

    Task<ConnectionHostCommandResult> PrepareAsync(
        string connectionId,
        CancellationToken cancellationToken);

    Task<ConnectionHostCommandResult> ConnectAsync(
        string connectionId,
        CancellationToken cancellationToken);

    Task<ConnectionHostCommandResult> ViewAsync(
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);

    Task<ConnectionHostCommandResult> TakeControlAsync(
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);

    Task<ConnectionHostCommandResult> ReleaseControlAsync(
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken);

    Task<ConnectionHostCommandResult> DisconnectAsync(
        string connectionId,
        long? connectionGeneration,
        CancellationToken cancellationToken);
}

public sealed class ConnectionHostPipeGateway :
    IConnectionHostPipeGateway
{
    private readonly ConnectionHostPipeClient client;
    private string? authorizationToken;
    private readonly string? dvcEvidenceReference;

    public ConnectionHostPipeGateway(
        string pipeName,
        string? authorizationToken,
        string? dvcEvidenceReference,
        TimeSpan? connectTimeout = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        client = new(
            pipeName,
            connectTimeout ?? TimeSpan.FromSeconds(3));
        this.authorizationToken =
            NullIfWhiteSpace(authorizationToken);
        this.dvcEvidenceReference =
            NullIfWhiteSpace(dvcEvidenceReference);
    }

    public bool ConnectConfigured =>
        authorizationToken is not null &&
        dvcEvidenceReference is not null;

    public async Task<ConnectionHostCommandResult> StatusAsync(
        string connectionId,
        CancellationToken cancellationToken)
    {
        ValidateConnectionId(connectionId);
        var response = await SendAsync(
                ConnectionHostOperation.Status,
                connectionId: null,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        var status = response.Connections?.FirstOrDefault(value =>
            string.Equals(
                value.ConnectionId,
                connectionId,
                StringComparison.Ordinal));
        return response with { Status = status };
    }

    public Task<ConnectionHostCommandResult> ResolveAsync(
        string connectionId,
        Uri providerResource,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(providerResource);
        return SendAsync(
            ConnectionHostOperation.Resolve,
            connectionId,
            providerResource: providerResource.AbsoluteUri,
            cancellationToken: cancellationToken);
    }

    public Task<ConnectionHostCommandResult> PrepareAsync(
        string connectionId,
        CancellationToken cancellationToken) =>
        SendAsync(
            ConnectionHostOperation.Prepare,
            connectionId,
            cancellationToken: cancellationToken);

    public async Task<ConnectionHostCommandResult> ConnectAsync(
        string connectionId,
        CancellationToken cancellationToken)
    {
        if (!ConnectConfigured)
            return new(
                true,
                false,
                "CONNECTION_HOST_CONNECT_CONFIGURATION_REQUIRED",
                null);
        var token = authorizationToken;
        authorizationToken = null;
        return await SendAsync(
                ConnectionHostOperation.Connect,
                connectionId,
                authorizationToken: token,
                dvcEvidenceReference: dvcEvidenceReference,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<ConnectionHostCommandResult> ViewAsync(
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken) =>
        SendGenerationAsync(
            ConnectionHostOperation.View,
            connectionId,
            connectionGeneration,
            cancellationToken);

    public Task<ConnectionHostCommandResult> TakeControlAsync(
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken) =>
        SendGenerationAsync(
            ConnectionHostOperation.TakeControl,
            connectionId,
            connectionGeneration,
            cancellationToken);

    public Task<ConnectionHostCommandResult> ReleaseControlAsync(
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken) =>
        SendGenerationAsync(
            ConnectionHostOperation.ReleaseControl,
            connectionId,
            connectionGeneration,
            cancellationToken);

    public Task<ConnectionHostCommandResult> DisconnectAsync(
        string connectionId,
        long? connectionGeneration,
        CancellationToken cancellationToken) =>
        SendAsync(
            ConnectionHostOperation.Disconnect,
            connectionId,
            connectionGeneration: connectionGeneration,
            cancellationToken: cancellationToken);

    public static ConnectionHostCommand CreateCommand(
        ConnectionHostOperation operation,
        string? connectionId = null,
        string? providerResource = null,
        string? authorizationToken = null,
        long? connectionGeneration = null,
        string? dvcEvidenceReference = null) =>
        new(
            ConnectionHostProtocol.CurrentVersion,
            Guid.NewGuid().ToString("N"),
            operation,
            connectionId,
            providerResource,
            authorizationToken,
            connectionGeneration,
            dvcEvidenceReference);

    private Task<ConnectionHostCommandResult> SendGenerationAsync(
        ConnectionHostOperation operation,
        string connectionId,
        long connectionGeneration,
        CancellationToken cancellationToken)
    {
        if (connectionGeneration <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(connectionGeneration),
                "A positive ConnectionHost generation is required.");
        return SendAsync(
            operation,
            connectionId,
            connectionGeneration: connectionGeneration,
            cancellationToken: cancellationToken);
    }

    private async Task<ConnectionHostCommandResult> SendAsync(
        ConnectionHostOperation operation,
        string? connectionId = null,
        string? providerResource = null,
        string? authorizationToken = null,
        long? connectionGeneration = null,
        string? dvcEvidenceReference = null,
        CancellationToken cancellationToken = default)
    {
        if (connectionId is not null)
            ValidateConnectionId(connectionId);
        try
        {
            var response = await client.SendAsync(
                    CreateCommand(
                        operation,
                        connectionId,
                        providerResource,
                        authorizationToken,
                        connectionGeneration,
                        dvcEvidenceReference),
                    cancellationToken)
                .ConfigureAwait(false);
            return new(
                true,
                response.Accepted,
                response.Code,
                response.Status,
                response.Connections);
        }
        catch (Exception exception)
            when (exception is
                IOException or
                TimeoutException or
                OperationCanceledException)
        {
            if (exception is OperationCanceledException &&
                cancellationToken.IsCancellationRequested)
                throw;
            return ConnectionHostCommandResult.Unavailable(
                "CONNECTION_HOST_PIPE_UNAVAILABLE");
        }
    }

    private static void ValidateConnectionId(string connectionId)
    {
        if (string.IsNullOrWhiteSpace(connectionId) ||
            connectionId.Length >
                ConnectionHostProtocol.MaximumConnectionIdCharacters)
            throw new ArgumentException(
                "The ConnectionHost connection ID is invalid.",
                nameof(connectionId));
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;
}

public interface IConnectionIdentityService
{
    Task<DevBoxConnectionIdentityStatus> StatusAsync(
        CancellationToken cancellationToken);

    Task<DevBoxConnectionIdentityStatus> EnrollAsync(
        IntPtr parentWindowHandle,
        CancellationToken cancellationToken);

    Task<DevBoxConnectionIdentityStatus> LogoutAsync(
        CancellationToken cancellationToken);
}

public sealed class ConnectionIdentityService :
    IConnectionIdentityService
{
    private readonly DevBoxConnectionIdentityService identity;

    public ConnectionIdentityService()
    {
        identity = new(new DevBoxConnectionIdentityStore());
    }

    public Task<DevBoxConnectionIdentityStatus> StatusAsync(
        CancellationToken cancellationToken) =>
        identity.StatusAsync(cancellationToken);

    public Task<DevBoxConnectionIdentityStatus> EnrollAsync(
        IntPtr parentWindowHandle,
        CancellationToken cancellationToken)
    {
        if (parentWindowHandle == IntPtr.Zero)
            throw new ArgumentException(
                "Connection enrollment requires a real parent window.",
                nameof(parentWindowHandle));
        return identity.EnrollAsync(
            parentWindowHandle,
            cancellationToken);
    }

    public Task<DevBoxConnectionIdentityStatus> LogoutAsync(
        CancellationToken cancellationToken) =>
        identity.ClearAsync(cancellationToken);
}

public sealed record ConnectionHostStartupSnapshot(
    DevBoxConnectionIdentityStatus Identity,
    ConnectionHostCommandResult Host);

public sealed class ConnectionHostStartupProbe(
    IConnectionHostPipeGateway connectionHost,
    IConnectionIdentityService connectionIdentity)
{
    public async Task<ConnectionHostStartupSnapshot> ProbeAsync(
        CancellationToken cancellationToken)
    {
        var identityTask =
            connectionIdentity.StatusAsync(cancellationToken);
        var hostTask = connectionHost.StatusAsync(
            "desktop-startup-status",
            cancellationToken);
        await Task.WhenAll(identityTask, hostTask).ConfigureAwait(false);
        return new(await identityTask, await hostTask);
    }
}

public enum ConnectionReadinessState
{
    Pending,
    Ready,
    Failed
}

public sealed record AdvancedFallbackObservation(
    string Code,
    DateTimeOffset ObservedAtUtc)
{
    public bool IsTransportEvidence => false;
}

public sealed record ConnectionViewerEvidenceState(
    ConnectionHostCommandResult ConnectionHost,
    AdvancedFallbackObservation? AdvancedFallback)
{
    public ConnectionViewerEvidenceState ObserveAdvancedFallback(
        string code,
        DateTimeOffset observedAtUtc) =>
        this with
        {
            AdvancedFallback = new(code, observedAtUtc)
        };
}

public sealed record ConnectionReadinessStep(
    int Order,
    string Name,
    ConnectionReadinessState State,
    string Evidence);

public sealed record ConnectionHostPresentation(
    string StatusText,
    IReadOnlyList<ConnectionReadinessStep> Readiness,
    CommandAvailability Resolve,
    CommandAvailability Prepare,
    CommandAvailability Connect,
    CommandAvailability View,
    CommandAvailability TakeControl,
    CommandAvailability ReleaseControl,
    CommandAvailability Fullscreen,
    CommandAvailability Disconnect)
{
    public static ConnectionHostPresentation Create(
        ConnectionHostCommandResult result,
        DevBoxConnectionIdentityStatus identity,
        bool connectConfigured)
    {
        var status = result.Status;
        var readyIdentity =
            identity.Outcome == DevBoxConnectionIdentityOutcome.Ready;
        var hostReady = result.HostAvailable;
        var resolved = status?.State is
            RdpDvcSessionState.Resolving or
            RdpDvcSessionState.ConnectingHeadless or
            RdpDvcSessionState.ConnectedTransport or
            RdpDvcSessionState.Viewing or
            RdpDvcSessionState.Controlled or
            RdpDvcSessionState.Reconnecting;
        var prepared =
            status?.Code == "CONNECTION_HOST_PREPARED" ||
            status?.State is
                RdpDvcSessionState.ConnectingHeadless or
                RdpDvcSessionState.ConnectedTransport or
                RdpDvcSessionState.Viewing or
                RdpDvcSessionState.Controlled or
                RdpDvcSessionState.Reconnecting;
        var connected = status?.DvcConnected == true &&
            status.ConnectionGeneration is > 0 &&
            status.State is
                RdpDvcSessionState.ConnectedTransport or
                RdpDvcSessionState.Viewing or
                RdpDvcSessionState.Controlled;
        var viewVerified = connected && status!.ViewSupported;
        var controlVerified = connected && status!.ControlSupported;

        var active = status?.State is
            RdpDvcSessionState.ConnectingHeadless or
            RdpDvcSessionState.ConnectedTransport or
            RdpDvcSessionState.Viewing or
            RdpDvcSessionState.Controlled or
            RdpDvcSessionState.Reconnecting;
        var resolve = !hostReady
            ? Disabled("ConnectionHost pipe is unavailable.")
            : !readyIdentity
                ? Disabled(ConnectionIdentityReason(identity))
                : active
                    ? Disabled("Disconnect the active ConnectionHost generation before resolving again.")
                : Enabled();
        var prepare = status?.State != RdpDvcSessionState.Resolving ||
            status.Code != "CONNECTION_HOST_RESOLVED"
            ? Disabled("Resolve the provider resource first.")
            : !readyIdentity
                ? Disabled(ConnectionIdentityReason(identity))
                : Enabled();
        var connect = status?.State != RdpDvcSessionState.Resolving ||
            status.Code != "CONNECTION_HOST_PREPARED"
            ? Disabled("Prepare the RDCore connection first.")
            : !connectConfigured
                ? Disabled(
                    "Control authorization and an opaque DVC evidence reference are not configured.")
                : Enabled();
        var view = !viewVerified
            ? Disabled(
                "Same-connection View remains disabled until RDCore capability and DVC evidence are verified.")
            : status!.State != RdpDvcSessionState.ConnectedTransport
                ? Disabled("ConnectionHost already has a visible or controlled surface.")
                : Enabled();
        var takeControl = !controlVerified
            ? Disabled(
                "Same-connection Take Control remains disabled until RDCore capability and DVC evidence are verified.")
            : status!.State != RdpDvcSessionState.Viewing
                ? Disabled("Open the verified same-connection view first.")
                : Enabled();
        var release = status?.State != RdpDvcSessionState.Controlled
            ? Disabled("ConnectionHost does not report an active controlled view.")
            : Enabled();
        var disconnect = status is null ||
            status.State is
                RdpDvcSessionState.Absent or
                RdpDvcSessionState.Disconnected
            ? Disabled("No ConnectionHost connection is active.")
            : Enabled();

        return new(
            RenderStatus(result, identity),
            CreateReadiness(
                result,
                identity,
                resolved,
                prepared,
                connected,
                viewVerified,
                controlVerified),
            resolve,
            prepare,
            connect,
            view,
            takeControl,
            release,
            view,
            disconnect);
    }

    private static IReadOnlyList<ConnectionReadinessStep> CreateReadiness(
        ConnectionHostCommandResult result,
        DevBoxConnectionIdentityStatus identity,
        bool resolved,
        bool prepared,
        bool connected,
        bool viewVerified,
        bool controlVerified) =>
    [
        new(
            1,
            "Connection identity",
            identity.Outcome == DevBoxConnectionIdentityOutcome.Ready
                ? ConnectionReadinessState.Ready
                : identity.Outcome ==
                    DevBoxConnectionIdentityOutcome.AccountMismatch
                    ? ConnectionReadinessState.Failed
                    : ConnectionReadinessState.Pending,
            identity.Outcome.ToString()),
        new(
            2,
            "Provider resource resolved",
            Step(result, resolved),
            resolved ? "CONNECTION_HOST_RESOLVED" : "Pending"),
        new(
            3,
            "RDCore and DVC prepared",
            Step(result, prepared),
            prepared ? "CONNECTION_HOST_PREPARED" : "Pending"),
        new(
            4,
            "Headless transport connected",
            Step(result, connected),
            connected ? "RDP_DVC_CONNECTED_TRANSPORT" : "Pending"),
        new(
            5,
            "Authenticated DVC evidence",
            Step(result, connected && result.Status?.DvcConnected == true),
            result.Status?.DvcConnected == true ? "Verified" : "Pending"),
        new(
            6,
            "Same-connection View capability",
            Step(result, viewVerified),
            viewVerified ? "Verified" : "Pending"),
        new(
            7,
            "Same-connection Control capability",
            Step(result, controlVerified),
            controlVerified ? "Verified" : "Pending")
    ];

    private static ConnectionReadinessState Step(
        ConnectionHostCommandResult result,
        bool ready) =>
        ready
            ? ConnectionReadinessState.Ready
            : result.Status?.State == RdpDvcSessionState.Failed ||
              (result.HostAvailable && !result.Accepted &&
               result.Code != "CONNECTION_HOST_STATUS")
                ? ConnectionReadinessState.Failed
                : ConnectionReadinessState.Pending;

    private static string RenderStatus(
        ConnectionHostCommandResult result,
        DevBoxConnectionIdentityStatus identity)
    {
        var status = result.Status;
        return
            $"ConnectionHost pipe: {(result.HostAvailable ? "available" : "unavailable")}\r\n" +
            $"Command evidence: {result.Code}\r\n" +
            $"Connection identity: {identity.Outcome}" +
            (identity.Username is { Length: > 0 } username
                ? $" ({username})"
                : string.Empty) +
            "\r\n" +
            $"State: {status?.State.ToString() ?? "Absent"}\r\n" +
            $"Generation: {status?.ConnectionGeneration?.ToString() ?? "not assigned"}\r\n" +
            $"DVC connected: {status?.DvcConnected == true}\r\n" +
            $"Same-connection View: {status?.ViewSupported == true}\r\n" +
            $"Same-connection Control: {status?.ControlSupported == true}\r\n" +
            $"Runtime evidence: {status?.Code ?? "none"}\r\n" +
            $"Updated: {status?.UpdatedAtUtc.ToLocalTime().ToString("G") ?? "not reported"}";
    }

    private static string ConnectionIdentityReason(
        DevBoxConnectionIdentityStatus identity) =>
        identity.Outcome switch
        {
            DevBoxConnectionIdentityOutcome.AccountMismatch =>
                "The connection identity does not match devbox/default. Sign it out and enroll the matching account.",
            DevBoxConnectionIdentityOutcome.InteractionRequired =>
                "Explicit native WAM connection enrollment is required.",
            _ => "The connection identity is not ready."
        };

    private static CommandAvailability Enabled() => new(true);

    private static CommandAvailability Disabled(string reason) =>
        new(false, reason);
}
