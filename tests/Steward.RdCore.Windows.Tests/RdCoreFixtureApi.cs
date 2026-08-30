using Windows.Foundation;

namespace Microsoft.RemoteDesktop.ClientCore;

public enum LogLevel
{
    None,
    Error,
    Warning,
    Information,
    Verbose
}

public enum ConnectionMode
{
    Full,
    Silent,
    Headless
}

public enum AccessState
{
    Unknown,
    SilentlyConnectable
}

public enum OperationStatus
{
    Success,
    NoResourcesPublished,
    InternalError
}

public interface IConnectedArgs;

public enum DisconnectionReasonCode
{
    None
}

public interface IDisconnectedArgs
{
    uint ClientStackDisconnectCode { get; }

    DisconnectionReasonCode DisconnectCode { get; }

    string ErrorCodeSymbolic { get; }

    string ErrorMessage { get; }

    string ErrorSource { get; }

    uint ServerStackDisconnectCode { get; }
}

public interface IConnectionStatusChangedArgs;

public interface IWTSPluginsLoadedArgs;

public interface IConnectionSettings
{
    ConnectionMode ConnectionMode { get; set; }

    string CloudPCSettingsUri { get; set; }

    bool AllowThirdPartyPlugins { get; set; }

    bool ConsumerHandlesClaimsTokenRequest { get; set; }

    ulong PopupUIParentWindowHandle { get; set; }

    ulong SessionWindowHandle { get; set; }

    bool StartFullscreen { get; set; }
}

public interface IClaimsTokenRequest
{
    bool IsCompleted { get; }

    void ProvideClaimsToken(
        string claimsToken,
        string tokenAuthority,
        string userName,
        bool acquiredSilently,
        string aadResourceTenantId,
        string aadDeviceId,
        string aadP2PRootCertificates);

    void Cancel();
}

public interface IClaimsTokenRequestedArgs
{
    string AuthorityUri { get; }

    string Claims { get; }

    string ClientId { get; }

    string RedirectUri { get; }

    string ResourceUri { get; }

    string Scope { get; }

    string UserNameHint { get; }

    IClaimsTokenRequest Request { get; }

    Deferral GetDeferral();
}

public sealed class ClaimsTokenRequest : IClaimsTokenRequest
{
    public bool IsCompleted { get; private set; }

    public bool WasCanceled { get; private set; }

    public string? Token { get; private set; }

    public void ProvideClaimsToken(
        string claimsToken,
        string tokenAuthority,
        string userName,
        bool acquiredSilently,
        string aadResourceTenantId,
        string aadDeviceId,
        string aadP2PRootCertificates)
    {
        Token = claimsToken;
        IsCompleted = true;
    }

    public void Cancel()
    {
        WasCanceled = true;
        IsCompleted = true;
    }
}

public sealed class ClaimsTokenRequestedArgs(
    IClaimsTokenRequest request) : IClaimsTokenRequestedArgs
{
    public string AuthorityUri => "https://authority.example.com/";

    public string Claims => "claims";

    public string ClientId => "client-id";

    public string RedirectUri => "https://redirect.example.com/";

    public string ResourceUri => "https://resource.example.com/";

    public string Scope => "scope";

    public string UserNameHint => "user@example.com";

    public IClaimsTokenRequest Request { get; } = request;

    public bool DeferralCompleted { get; private set; }

    public Deferral GetDeferral() =>
        new(() => DeferralCompleted = true);
}

public interface IConnection
{
    IConnectionSettings ConnectionSettings { get; set; }

    event TypedEventHandler<IConnection, IConnectedArgs> Connected;

    event TypedEventHandler<IConnection, IDisconnectedArgs> Disconnected;

    event TypedEventHandler<
        IConnection,
        IConnectionStatusChangedArgs> ConnectionStatusChanged;

    event TypedEventHandler<
        IConnection,
        IWTSPluginsLoadedArgs> WTSPluginsLoaded;

    event TypedEventHandler<
        IConnection,
        IClaimsTokenRequestedArgs> ClaimsTokenRequested;

    void Connect();

    void Disconnect();
}

public sealed class ConnectionSettings : IConnectionSettings
{
    public ConnectionMode ConnectionMode { get; set; }

    public string CloudPCSettingsUri { get; set; } = string.Empty;

    public bool AllowThirdPartyPlugins { get; set; }

    public bool ConsumerHandlesClaimsTokenRequest { get; set; }

    public string FirstPartyDVCPlugins { get; set; } = string.Empty;

    public ulong PopupUIParentWindowHandle { get; set; }

    public ulong SessionWindowHandle { get; set; }

    public bool StartFullscreen { get; set; }
}

public sealed class Connection : IConnection
{
    public IConnectionSettings ConnectionSettings { get; set; } =
        new ConnectionSettings();

    public int ConnectCalls { get; private set; }

    public int DisconnectCalls { get; private set; }

    public int ConnectedSubscribers =>
        Connected?.GetInvocationList().Length ?? 0;

    public int DisconnectedSubscribers =>
        Disconnected?.GetInvocationList().Length ?? 0;

    public int WtsPluginsLoadedSubscribers =>
        WTSPluginsLoaded?.GetInvocationList().Length ?? 0;

    public int ClaimsTokenRequestedSubscribers =>
        ClaimsTokenRequested?.GetInvocationList().Length ?? 0;

    public event TypedEventHandler<IConnection, IConnectedArgs>? Connected;

    public event TypedEventHandler<IConnection, IDisconnectedArgs>? Disconnected;

    public event TypedEventHandler<
        IConnection,
        IConnectionStatusChangedArgs>? ConnectionStatusChanged;

    public event TypedEventHandler<
        IConnection,
        IWTSPluginsLoadedArgs>? WTSPluginsLoaded;

    public event TypedEventHandler<
        IConnection,
        IClaimsTokenRequestedArgs>? ClaimsTokenRequested;

    public void Connect() => ConnectCalls++;

    public void Disconnect() => DisconnectCalls++;

    public void RaiseConnected() => Connected?.Invoke(this, null!);

    public void RaiseDisconnected() => Disconnected?.Invoke(this, null!);

    public void RaiseWtsPluginsLoaded() =>
        WTSPluginsLoaded?.Invoke(this, null!);

    public void RaiseClaimsTokenRequested(IClaimsTokenRequestedArgs args) =>
        ClaimsTokenRequested?.Invoke(this, args);

    public void RaiseConnectionStatusChanged() =>
        ConnectionStatusChanged?.Invoke(this, null!);
}

public interface IWorkspaceSettings
{
    Guid? ActivityId { get; set; }

    bool AllowInteractivePrompts { get; set; }

    string FeedUrl { get; set; }

    bool ForceRefresh { get; set; }

    IList<IconFormat> IconFormats { get; set; }

    ulong ParentWindowHandle { get; set; }

    string UserName { get; set; }
}

public sealed class WorkspaceSettings : IWorkspaceSettings
{
    public Guid? ActivityId { get; set; }

    public bool AllowInteractivePrompts { get; set; }

    public string FeedUrl { get; set; } = string.Empty;

    public bool ForceRefresh { get; set; }

    public IList<IconFormat> IconFormats { get; set; } = [];

    public ulong ParentWindowHandle { get; set; }

    public string UserName { get; set; } = string.Empty;
}

public enum IconFormat
{
    Png,
    Ico
}

public readonly struct WorkspaceDescriptor
{
    public WorkspaceDescriptor(
        string id,
        string tenantId,
        string aadTenantId,
        string url,
        string displayName,
        string key,
        bool isAccessibleFromCurrentNetwork)
    {
        Id = id;
        TenantId = tenantId;
        AadTenantId = aadTenantId;
        Url = url;
        DisplayName = displayName;
        Key = key;
        IsAccessibleFromCurrentNetwork = isAccessibleFromCurrentNetwork;
    }

    public readonly string Id;
    public readonly string TenantId;
    public readonly string AadTenantId;
    public readonly string Url;
    public readonly string DisplayName;
    public readonly string Key;
    public readonly bool IsAccessibleFromCurrentNetwork;
}

public readonly struct RdpFile
{
    public RdpFile(string rdpFileContents, string key, string url)
    {
        RdpFileContents = rdpFileContents;
        Key = key;
        Url = url;
    }

    public readonly string RdpFileContents;
    public readonly string Key;
    public readonly string Url;
}

public interface IWorkspaceResource
{
    AccessState AccessState { get; }

    string Id { get; }

    RdpFile RdpFile { get; }
}

public sealed record WorkspaceResource(
    string Id,
    AccessState AccessState,
    RdpFile RdpFile) : IWorkspaceResource;

public interface IResourceListAvailableEventArgs
{
    WorkspaceDescriptor Descriptor { get; }

    IEnumerable<IWorkspaceResource> Resources { get; }
}

public sealed record ResourceListAvailableEventArgs(
    WorkspaceDescriptor Descriptor,
    IEnumerable<IWorkspaceResource> Resources) :
    IResourceListAvailableEventArgs;

public interface IWorkspaceDownloadCompletedEventArgs;

public sealed class WorkspaceDownloadCompletedEventArgs :
    IWorkspaceDownloadCompletedEventArgs;

public interface IFeedDownloadResult
{
    string FeedUrl { get; }

    OperationStatus Status { get; }

    IEnumerable<IWorkspace> Workspaces { get; }
}

public interface IWorkspace
{
    WorkspaceDescriptor Descriptor { get; }

    IEnumerable<IWorkspaceResource> WorkspaceResources { get; }
}

public sealed class FeedDownloadResult(OperationStatus status) :
    IFeedDownloadResult
{
    public string FeedUrl => string.Empty;

    public OperationStatus Status { get; } = status;

    public IEnumerable<IWorkspace> Workspaces => [];
}

public interface IWorkspaceDownloader
{
    IWorkspaceSettings WorkspaceSettings { get; set; }

    event TypedEventHandler<
        IWorkspaceDownloader,
        IResourceListAvailableEventArgs> ResourceListAvailable;

    event TypedEventHandler<
        IWorkspaceDownloader,
        IWorkspaceDownloadCompletedEventArgs> WorkspaceDownloadCompleted;

    event TypedEventHandler<
        IWorkspaceDownloader,
        IWorkspaceDownloadStatusChangedArgs> WorkspaceDownloadStatusChanged;

    IAsyncOperation<IFeedDownloadResult> DownloadAsync();
}

public sealed class WorkspaceDownloader : IWorkspaceDownloader
{
    public static IReadOnlyList<IWorkspaceResource> NextResources { get; set; } =
        [];

    public static OperationStatus NextStatus { get; set; } =
        OperationStatus.Success;

    public static bool ReturnPendingOperation { get; set; }

    public static bool DownloadReturnedNormally { get; private set; }

    public static PendingAsyncOperation<IFeedDownloadResult>? LastPendingOperation
    {
        get;
        private set;
    }

    public IWorkspaceSettings WorkspaceSettings { get; set; } =
        new WorkspaceSettings();

    public int ResourceListSubscribers =>
        ResourceListAvailable?.GetInvocationList().Length ?? 0;

    public int CompletionSubscribers =>
        WorkspaceDownloadCompleted?.GetInvocationList().Length ?? 0;

    public event TypedEventHandler<
        IWorkspaceDownloader,
        IResourceListAvailableEventArgs>? ResourceListAvailable;

    public event TypedEventHandler<
        IWorkspaceDownloader,
        IWorkspaceDownloadCompletedEventArgs>? WorkspaceDownloadCompleted;

    public event TypedEventHandler<
        IWorkspaceDownloader,
        IWorkspaceDownloadStatusChangedArgs>? WorkspaceDownloadStatusChanged;

    public IAsyncOperation<IFeedDownloadResult> DownloadAsync()
    {
        DownloadReturnedNormally = false;
        if (ReturnPendingOperation)
        {
            LastPendingOperation = new(
                new FeedDownloadResult(NextStatus));
            DownloadReturnedNormally = true;
            return LastPendingOperation;
        }

        WorkspaceDownloadStatusChanged?.Invoke(
            this,
            new WorkspaceDownloadStatusChangedArgs(
                WorkspaceDownloadStatus.Downloading));
        ResourceListAvailable?.Invoke(
            this,
            new ResourceListAvailableEventArgs(
                new(
                    "workspace-exact",
                    "tenant",
                    "aad-tenant",
                    "https://feed.example/",
                    "Workspace",
                    "key",
                    true),
                NextResources));
        WorkspaceDownloadCompleted?.Invoke(
            this,
            new WorkspaceDownloadCompletedEventArgs());
        DownloadReturnedNormally = true;
        return new CompletedAsyncOperation<IFeedDownloadResult>(
            new FeedDownloadResult(NextStatus));
    }
}

public enum WorkspaceDownloadStatus
{
    Downloading
}

public interface IWorkspaceDownloadStatusChangedArgs
{
    WorkspaceDownloadStatus CurrentStatus { get; }
}

public sealed class WorkspaceDownloadStatusChangedArgs(
    WorkspaceDownloadStatus currentStatus) :
    IWorkspaceDownloadStatusChangedArgs
{
    public WorkspaceDownloadStatus CurrentStatus { get; } = currentStatus;
}

public sealed class ActivityManager
{
    public static ActivityManager? LastCreated { get; private set; }

    public ActivityManager()
    {
        LastCreated = this;
    }

    public string? InitializedAccount { get; private set; }

    public string? ClaimsClientId { get; private set; }

    public string? ClaimsRedirectUri { get; private set; }

    public Connection? LastConnection { get; private set; }

    public WorkspaceDownloader? LastWorkspaceDownloader { get; private set; }

    public void Initialize(
        string osVersion,
        string userIdentifier,
        string clientIdentifier,
        string clientVersion,
        ushort clientBuild,
        LogLevel logLevel) =>
        InitializedAccount = userIdentifier;

    public void ConfigureClaimsTokenAuthenticationContext(
        string clientAppId,
        string redirectUri)
    {
        ClaimsClientId = clientAppId;
        ClaimsRedirectUri = redirectUri;
    }

    public IConnection CreateConnection(string rdpFileContent)
    {
        LastConnection = new();
        return LastConnection;
    }

    public IWorkspaceDownloader CreateWorkspaceDownloader()
    {
        LastWorkspaceDownloader = new();
        return LastWorkspaceDownloader;
    }

    public Guid GenerateNewActivityId() =>
        Guid.NewGuid();
}

public sealed class CompletedAsyncOperation<TResult>(TResult result) :
    IAsyncOperation<TResult>
{
    private AsyncOperationCompletedHandler<TResult>? completed;

    public uint Id => 1;

    public AsyncStatus Status => AsyncStatus.Completed;

    public Exception ErrorCode =>
        throw new InvalidOperationException("The operation succeeded.");

    public AsyncOperationCompletedHandler<TResult> Completed
    {
        get => completed!;
        set
        {
            completed = value;
            completed?.Invoke(this, AsyncStatus.Completed);
        }
    }

    public void Cancel()
    {
    }

    public void Close()
    {
    }

    public TResult GetResults() => result;
}

public sealed class PendingAsyncOperation<TResult>(TResult result) :
    IAsyncOperation<TResult>
{
    private AsyncOperationCompletedHandler<TResult>? completed;

    public uint Id => 2;

    public AsyncStatus Status { get; private set; } = AsyncStatus.Started;

    public Exception ErrorCode =>
        throw new InvalidOperationException("The operation is pending.");

    public bool CancelCalled { get; private set; }

    public AsyncOperationCompletedHandler<TResult> Completed
    {
        get => completed!;
        set => completed = value;
    }

    public void Cancel()
    {
        CancelCalled = true;
        Status = AsyncStatus.Canceled;
        completed?.Invoke(this, Status);
    }

    public void Close()
    {
    }

    public TResult GetResults() => result;
}
