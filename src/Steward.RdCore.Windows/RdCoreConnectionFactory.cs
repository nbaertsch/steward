using System.Reflection;
using System.Text;
using Steward.DevBox.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdCore.Windows;

public sealed class RdCoreConnectionFactory
{
    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private readonly Func<IRdCoreReflectionSession> sessionFactory;
    private readonly IRdCoreCredentialCallback credentialCallback;
    private readonly RdCoreIntegrationOptions options;

    public RdCoreConnectionFactory(
        RdCoreCapabilityReport capability,
        IRdCoreCredentialCallback credentialCallback,
        RdCoreIntegrationOptions? options = null)
        : this(
            () => new RdCoreLoaderSession(capability),
            credentialCallback,
            options ?? new())
    {
    }

    internal RdCoreConnectionFactory(
        Func<IRdCoreReflectionSession> sessionFactory,
        IRdCoreCredentialCallback credentialCallback,
        RdCoreIntegrationOptions options)
    {
        this.sessionFactory = sessionFactory;
        this.credentialCallback = credentialCallback;
        this.options = options;
    }

    public Task<RdCoreConnectionLease> CreateAsync(
        RdCoreResolvedConnection resolved,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolved);
        options.Validate(requireFeed: false);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateResolvedConnection(resolved);

        var session = sessionFactory();
        var success = false;
        try
        {
            var bindings = RdCoreReflectionBindings.For(session.Assembly);
            var activityManager =
                session.CreateActivityManager(bindings);
            bindings.InitializeActivityManager(activityManager, options);
            var connection = ReflectionInvoke.Call(
                bindings.CreateConnection,
                activityManager,
                resolved.SignedRdpText) ??
                throw new InvalidOperationException(
                    "RDCore returned no connection.");
            options.Report("connection-created");
            ConfigureConnection(bindings, connection, resolved);
            options.Report("connection-configured");
            var lease = new RdCoreConnectionLease(
                session,
                connection,
                bindings,
                credentialCallback,
                options.OperationTimeout,
                options.DiagnosticSink,
                options.ReleaseClaimsOwnershipAfterAvdTokens);
            success = true;
            return Task.FromResult(lease);
        }
        finally
        {
            if (!success)
            {
                session.Dispose();
            }
        }
    }

    private void ValidateResolvedConnection(RdCoreResolvedConnection resolved)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resolved.SignedRdpText);
        if (StrictUtf8.GetByteCount(resolved.SignedRdpText) >
            options.MaximumRdpContentBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(resolved),
                "The resolved RDP content exceeds the configured bound.");
        }

        var classified = DevBoxRemoteViewingValidator.ClassifyProviderRdpUri(
            resolved.ProviderResourceUri);
        if (classified.Kind != DevBoxProviderRdpKind.WindowsAppResource)
        {
            throw new ArgumentException(
                "The provider resource must be an exact ms-avd resource.",
                nameof(resolved));
        }
    }

    private void ConfigureConnection(
        RdCoreReflectionBindings bindings,
        object connection,
        RdCoreResolvedConnection resolved)
    {
        var settings = ReflectionInvoke.GetRequired(
            bindings.ConnectionSettings,
            connection);
        bindings.ConnectionMode.SetValue(
            settings,
            bindings.SilentConnectionMode);
        bindings.CloudPCSettingsUri.SetValue(
            settings,
            resolved.ProviderResourceUri.OriginalString);
        bindings.AllowThirdPartyPlugins.SetValue(settings, true);
        bindings.ConsumerHandlesClaimsTokenRequest.SetValue(
            settings,
            options.ConsumerHandlesClaimsTokenRequest);
        bindings.PopupUIParentWindowHandle.SetValue(settings, 0UL);
        bindings.SessionWindowHandle.SetValue(settings, 0UL);
        bindings.StartFullscreen.SetValue(settings, false);
        bindings.ConnectionSettings.SetValue(connection, settings);

        if (!Equals(
                bindings.ConnectionMode.GetValue(settings),
                bindings.SilentConnectionMode) ||
            !string.Equals(
                bindings.CloudPCSettingsUri.GetValue(settings) as string,
                resolved.ProviderResourceUri.OriginalString,
                StringComparison.Ordinal) ||
            !Equals(
                bindings.AllowThirdPartyPlugins.GetValue(settings),
                true) ||
            !Equals(
                bindings.ConsumerHandlesClaimsTokenRequest.GetValue(settings),
                options.ConsumerHandlesClaimsTokenRequest) ||
            !Equals(
                bindings.PopupUIParentWindowHandle.GetValue(settings),
                0UL) ||
            !Equals(
                bindings.SessionWindowHandle.GetValue(settings),
                0UL) ||
            !Equals(bindings.StartFullscreen.GetValue(settings), false))
        {
            throw new InvalidOperationException(
                "RDCore did not retain the required silent connection settings.");
        }
    }
}

public sealed class RdCoreConnectionLease : IAsyncDisposable, IDisposable
{
    private readonly IRdCoreReflectionSession session;
    private readonly object connection;
    private readonly RdCoreReflectionBindings bindings;
    private readonly IRdCoreCredentialCallback credentialCallback;
    private readonly TimeSpan operationTimeout;
    private readonly Action<string>? diagnosticSink;
    private readonly bool releaseClaimsOwnershipAfterAvdTokens;
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource connected =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource disconnected =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource credentialFailure =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ReflectionEventSubscription connectedSubscription;
    private readonly ReflectionEventSubscription disconnectedSubscription;
    private readonly ReflectionEventSubscription pluginsSubscription;
    private readonly ReflectionEventSubscription claimsSubscription;
    private int state = (int)RdCoreConnectionState.Resolving;
    private int wtsPluginsLoaded;
    private int avdTokensProvided;
    private bool disposed;

    internal RdCoreConnectionLease(
        IRdCoreReflectionSession session,
        object connection,
        RdCoreReflectionBindings bindings,
        IRdCoreCredentialCallback credentialCallback,
        TimeSpan operationTimeout,
        Action<string>? diagnosticSink = null,
        bool releaseClaimsOwnershipAfterAvdTokens = false)
    {
        this.session = session;
        this.connection = connection;
        this.bindings = bindings;
        this.credentialCallback = credentialCallback;
        this.operationTimeout = operationTimeout;
        this.diagnosticSink = diagnosticSink;
        this.releaseClaimsOwnershipAfterAvdTokens =
            releaseClaimsOwnershipAfterAvdTokens;
        connectedSubscription = new(
            bindings.Connected,
            connection,
            (_, _) =>
            {
                SetState(RdCoreConnectionState.Connected);
                diagnosticSink?.Invoke("connection-event-connected");
                connected.TrySetResult();
                Connected?.Invoke(this, EventArgs.Empty);
            });
        disconnectedSubscription = new(
            bindings.Disconnected,
            connection,
            (_, args) =>
            {
                SetState(RdCoreConnectionState.Disconnected);
                diagnosticSink?.Invoke(
                    args is null
                        ? "connection-event-disconnected-no-args"
                        : "connection-event-disconnected-" +
                          SafeDisconnect(bindings, args));
                disconnected.TrySetResult();
                Disconnected?.Invoke(this, EventArgs.Empty);
            });
        pluginsSubscription = new(
            bindings.WtsPluginsLoaded,
            connection,
            (_, _) =>
            {
                Interlocked.Exchange(ref wtsPluginsLoaded, 1);
                diagnosticSink?.Invoke(
                    "connection-event-wts-plugins-loaded");
                WtsPluginsLoaded?.Invoke(this, EventArgs.Empty);
            });
        claimsSubscription = new(
            bindings.ClaimsTokenRequested,
            connection,
            (_, args) =>
            {
                if (args is not null)
                {
                    ObserveCredentialTask(ProvideClaimsTokenAsync(args));
                }
            });
    }

    public RdCoreConnectionState State =>
        (RdCoreConnectionState)Volatile.Read(ref state);

    public bool WereWtsPluginsLoaded =>
        Volatile.Read(ref wtsPluginsLoaded) != 0;

    public event EventHandler? Connected;

    public event EventHandler? Disconnected;

    public event EventHandler? WtsPluginsLoaded;

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        SetState(RdCoreConnectionState.Connecting);
        diagnosticSink?.Invoke("connection-connect-invoked");
        ReflectionInvoke.Call(bindings.Connect, connection);
        await AwaitSignalAsync(connected.Task, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task DisconnectAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ReflectionInvoke.Call(bindings.Disconnect, connection);
        await AwaitSignalAsync(disconnected.Task, cancellationToken)
            .ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        lifetime.Cancel();
        claimsSubscription.Dispose();
        pluginsSubscription.Dispose();
        disconnectedSubscription.Dispose();
        connectedSubscription.Dispose();
        lifetime.Dispose();
        session.Dispose();
        GC.SuppressFinalize(this);
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private async Task AwaitSignalAsync(
        Task signal,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            lifetime.Token);
        timeout.CancelAfter(operationTimeout);
        var completed = await Task.WhenAny(signal, credentialFailure.Task)
            .WaitAsync(timeout.Token)
            .ConfigureAwait(false);
        await completed.ConfigureAwait(false);
    }

    private async Task ProvideClaimsTokenAsync(object args)
    {
        var requestObject = ReflectionInvoke.GetRequired(
            bindings.ClaimsRequest,
            args);
        var deferral = ReflectionInvoke.Call(
            bindings.ClaimsGetDeferral,
            args) ??
            throw new InvalidOperationException(
                "RDCore returned no claims-token deferral.");
        var provided = false;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                lifetime.Token);
            timeout.CancelAfter(operationTimeout);
            var request = new RdCoreClaimsTokenRequest(
                GetString(bindings.ClaimsAuthorityUri, args),
                GetString(bindings.Claims, args),
                GetString(bindings.ClaimsClientId, args),
                GetString(bindings.ClaimsResourceUri, args),
                GetString(bindings.ClaimsScope, args),
                GetString(bindings.ClaimsUserNameHint, args),
                GetString(bindings.ClaimsRedirectUri, args));
            var token = await credentialCallback.AcquireTokenAsync(
                request,
                timeout.Token).ConfigureAwait(false);
            diagnosticSink?.Invoke(
                IsCloudLogin(request)
                    ? "connection-cloud-login-token-provided"
                    : "connection-avd-token-provided");
            if (!IsCloudLogin(request) &&
                releaseClaimsOwnershipAfterAvdTokens &&
                Interlocked.Increment(ref avdTokensProvided) == 1)
            {
                var settings = ReflectionInvoke.GetRequired(
                    bindings.ConnectionSettings,
                    connection);
                ReflectionInvoke.Set(
                    bindings.ConsumerHandlesClaimsTokenRequest,
                    settings,
                    false);
                ReflectionInvoke.Set(
                    bindings.ConnectionSettings,
                    connection,
                    settings);
                diagnosticSink?.Invoke(
                    "connection-native-cloud-login-ownership");
            }
            ReflectionInvoke.Call(
                bindings.ProvideClaimsToken,
                requestObject,
                token.Token,
                token.TokenAuthority,
                token.UserName,
                token.AcquiredSilently,
                token.AadResourceTenantId,
                token.AadDeviceId,
                token.AadP2PRootCertificates);
            provided = true;
        }
        finally
        {
            if (!provided)
            {
                ReflectionInvoke.Call(
                    bindings.CancelClaimsTokenRequest,
                    requestObject);
            }

            ReflectionInvoke.Call(bindings.CompleteDeferral, deferral);
        }
    }

    private void ObserveCredentialTask(Task task)
    {
        _ = task.ContinueWith(
            completed =>
            {
                if (completed.Exception is { } exception)
                {
                    credentialFailure.TrySetException(
                        exception.InnerExceptions);
                    SetState(RdCoreConnectionState.Failed);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted |
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static string GetString(PropertyInfo property, object target) =>
        property.GetValue(target) as string ?? string.Empty;

    private static bool IsCloudLogin(
        RdCoreClaimsTokenRequest request) =>
        request.ResourceUri.StartsWith(
            "ms-device-service:",
            StringComparison.OrdinalIgnoreCase);

    private static string SafeDisconnect(
        RdCoreReflectionBindings bindings,
        object args)
    {
        var reason = ReflectionInvoke.Get(
                bindings.DisconnectCode,
                args)
            ?.ToString() ?? "unknown";
        var client = ReflectionInvoke.Get(
                bindings.ClientStackDisconnectCode,
                args)
            ?.ToString() ?? "unknown";
        var server = ReflectionInvoke.Get(
                bindings.ServerStackDisconnectCode,
                args)
            ?.ToString() ?? "unknown";
        var symbolic = ReflectionInvoke.Get(
                bindings.DisconnectErrorSymbolic,
                args)
            ?.ToString() ?? "none";
        symbolic = new string(symbolic
            .Take(96)
            .Select(character =>
                char.IsAsciiLetterOrDigit(character) ||
                character is '-' or '_'
                    ? character
                    : '_')
            .ToArray());
        return $"{reason}-client-{client}-server-{server}-{symbolic}";
    }

    private void SetState(RdCoreConnectionState value) =>
        Volatile.Write(ref state, (int)value);
}
