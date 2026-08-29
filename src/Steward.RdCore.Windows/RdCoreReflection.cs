using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace Steward.RdCore.Windows;

internal interface IRdCoreReflectionSession : IDisposable
{
    Assembly Assembly { get; }

    object CreateActivityManager(
        RdCoreReflectionBindings bindings) =>
        bindings.CreateActivityManager();

    void InitializeIconVector(
        RdCoreReflectionBindings bindings)
    {
    }
}

internal sealed class RdCoreLoaderSession : IRdCoreReflectionSession
{
    private readonly CollectibleRdCoreAssemblyLoader loader;

    public RdCoreLoaderSession(RdCoreCapabilityReport capability)
    {
        loader = CollectibleRdCoreAssemblyLoader.Create(capability);
        Assembly = loader.LoadProjectedAssembly();
    }

    public Assembly Assembly { get; }

    public object CreateActivityManager(
        RdCoreReflectionBindings bindings)
    {
        var native = loader.ActivateActivityManager();
        try
        {
            return bindings.CreateActivityManagerFromAbi(native);
        }

        finally
        {
            _ = Marshal.Release(native);
        }
    }

    public void InitializeIconVector(
        RdCoreReflectionBindings bindings) =>
        bindings.InitializeIconVector();

    public void Dispose() => loader.Dispose();
}

internal sealed class RdCoreReflectionBindings
{
    private const string Namespace = "Microsoft.RemoteDesktop.ClientCore.";
    private static readonly ConditionalWeakTable<
        Assembly,
        RdCoreReflectionBindings> Cache = new();

    private RdCoreReflectionBindings(Assembly assembly)
    {
        ActivityManagerType = RequireType(assembly, "ActivityManager");
        ActivityManagerConstructor =
            ActivityManagerType.GetConstructor(Type.EmptyTypes) ??
            throw Missing("ActivityManager constructor");
        Initialize = RequireMethod(
            ActivityManagerType,
            "Initialize",
            "System.Void",
            "System.String",
            "System.String",
            "System.String",
            "System.String",
            "System.UInt16",
            Namespace + "LogLevel");
        ConfigureClaimsTokenAuthenticationContext = RequireMethod(
            ActivityManagerType,
            "ConfigureClaimsTokenAuthenticationContext",
            "System.Void",
            "System.String",
            "System.String");
        CreateConnection = RequireMethod(
            ActivityManagerType,
            "CreateConnection",
            Namespace + "IConnection",
            "System.String");
        CreateWorkspaceDownloader = RequireMethod(
            ActivityManagerType,
            "CreateWorkspaceDownloader",
            Namespace + "IWorkspaceDownloader");
        GenerateNewActivityId = RequireMethod(
            ActivityManagerType,
            "GenerateNewActivityId",
            "System.Guid");

        var workspaceDownloader = RequireType(assembly, "IWorkspaceDownloader");
        DownloadAsync = RequireMethod(
            workspaceDownloader,
            "DownloadAsync",
            "Windows.Foundation.IAsyncOperation`1[" +
            Namespace + "IFeedDownloadResult]");
        WorkspaceSettings = RequireProperty(
            workspaceDownloader,
            "WorkspaceSettings",
            Namespace + "IWorkspaceSettings",
            canWrite: true);
        ResourceListAvailable = RequireEvent(
            workspaceDownloader,
            "ResourceListAvailable");
        WorkspaceDownloadCompleted = RequireEvent(
            workspaceDownloader,
            "WorkspaceDownloadCompleted");
        WorkspaceDownloadStatusChanged = RequireEvent(
            workspaceDownloader,
            "WorkspaceDownloadStatusChanged");
        var workspaceStatusArgs = RequireType(
            assembly,
            "IWorkspaceDownloadStatusChangedArgs");
        WorkspaceDownloadCurrentStatus = RequireProperty(
            workspaceStatusArgs,
            "CurrentStatus",
            Namespace + "WorkspaceDownloadStatus",
            canWrite: false);
        var feedDownloadResult = RequireType(assembly, "IFeedDownloadResult");
        FeedDownloadStatus = RequireProperty(
            feedDownloadResult,
            "Status",
            Namespace + "OperationStatus",
            canWrite: false);

        var workspaceSettings = RequireType(assembly, "IWorkspaceSettings");
        FeedUrl = RequireProperty(
            workspaceSettings,
            "FeedUrl",
            "System.String",
            canWrite: true);
        UserName = RequireProperty(
            workspaceSettings,
            "UserName",
            "System.String",
            canWrite: true);
        ParentWindowHandle = RequireProperty(
            workspaceSettings,
            "ParentWindowHandle",
            "System.UInt64",
            canWrite: true);
        ForceRefresh = RequireProperty(
            workspaceSettings,
            "ForceRefresh",
            "System.Boolean",
            canWrite: true);
        AllowInteractivePrompts = RequireProperty(
            workspaceSettings,
            "AllowInteractivePrompts",
            "System.Boolean",
            canWrite: true);
        ActivityId = RequireProperty(
            workspaceSettings,
            "ActivityId",
            "System.Nullable`1[System.Guid]",
            canWrite: true);
        IconFormats = RequireProperty(
            workspaceSettings,
            "IconFormats",
            "System.Collections.Generic.IList`1[" +
            Namespace + "IconFormat]",
            canWrite: true);
        var iconFormat = RequireType(assembly, "IconFormat");
        IconFormatPng = Enum.Parse(iconFormat, "Png");
        IconFormatIco = Enum.Parse(iconFormat, "Ico");

        var resourceListArgs = RequireType(
            assembly,
            "IResourceListAvailableEventArgs");
        ResourceListDescriptor = RequireProperty(
            resourceListArgs,
            "Descriptor",
            Namespace + "WorkspaceDescriptor",
            canWrite: false);
        ResourceListResources = RequireProperty(
            resourceListArgs,
            "Resources",
            "System.Collections.Generic.IEnumerable`1[" +
            Namespace + "IWorkspaceResource]",
            canWrite: false);
        var workspaceDescriptor = RequireType(assembly, "WorkspaceDescriptor");
        WorkspaceDescriptorId = RequireField(
            workspaceDescriptor,
            "Id",
            "System.String");

        var workspaceResource = RequireType(assembly, "IWorkspaceResource");
        ResourceId = RequireProperty(
            workspaceResource,
            "Id",
            "System.String",
            canWrite: false);
        ResourceAccessState = RequireProperty(
            workspaceResource,
            "AccessState",
            Namespace + "AccessState",
            canWrite: false);
        ResourceRdpFile = RequireProperty(
            workspaceResource,
            "RdpFile",
            Namespace + "RdpFile",
            canWrite: false);
        var rdpFile = RequireType(assembly, "RdpFile");
        RdpFileContents = RequireField(
            rdpFile,
            "RdpFileContents",
            "System.String");
        RdpFileUrl = RequireField(rdpFile, "Url", "System.String");

        var connection = RequireType(assembly, "IConnection");
        Connect = RequireMethod(connection, "Connect", "System.Void");
        Disconnect = RequireMethod(connection, "Disconnect", "System.Void");
        ConnectionSettings = RequireProperty(
            connection,
            "ConnectionSettings",
            Namespace + "IConnectionSettings",
            canWrite: true);
        Connected = RequireEvent(connection, "Connected");
        Disconnected = RequireEvent(connection, "Disconnected");
        var disconnectedArgs = RequireType(
            assembly,
            "IDisconnectedArgs");
        DisconnectCode = RequireProperty(
            disconnectedArgs,
            "DisconnectCode",
            Namespace + "DisconnectionReasonCode",
            canWrite: false);
        ClientStackDisconnectCode = RequireProperty(
            disconnectedArgs,
            "ClientStackDisconnectCode",
            "System.UInt32",
            canWrite: false);
        ServerStackDisconnectCode = RequireProperty(
            disconnectedArgs,
            "ServerStackDisconnectCode",
            "System.UInt32",
            canWrite: false);
        DisconnectErrorSymbolic = RequireProperty(
            disconnectedArgs,
            "ErrorCodeSymbolic",
            "System.String",
            canWrite: false);
        WtsPluginsLoaded = RequireEvent(connection, "WTSPluginsLoaded");
        ClaimsTokenRequested = RequireEvent(connection, "ClaimsTokenRequested");

        var settings = RequireType(assembly, "IConnectionSettings");
        ConnectionMode = RequireProperty(
            settings,
            "ConnectionMode",
            Namespace + "ConnectionMode",
            canWrite: true);
        CloudPCSettingsUri = RequireProperty(
            settings,
            "CloudPCSettingsUri",
            "System.String",
            canWrite: true);
        AllowThirdPartyPlugins = RequireProperty(
            settings,
            "AllowThirdPartyPlugins",
            "System.Boolean",
            canWrite: true);
        ConsumerHandlesClaimsTokenRequest = RequireProperty(
            settings,
            "ConsumerHandlesClaimsTokenRequest",
            "System.Boolean",
            canWrite: true);
        PopupUIParentWindowHandle = RequireProperty(
            settings,
            "PopupUIParentWindowHandle",
            "System.UInt64",
            canWrite: true);
        SessionWindowHandle = RequireProperty(
            settings,
            "SessionWindowHandle",
            "System.UInt64",
            canWrite: true);
        StartFullscreen = RequireProperty(
            settings,
            "StartFullscreen",
            "System.Boolean",
            canWrite: true);

        var claimsArgs = RequireType(assembly, "IClaimsTokenRequestedArgs");
        ClaimsAuthorityUri = RequireProperty(
            claimsArgs,
            "AuthorityUri",
            "System.String",
            canWrite: false);
        Claims = RequireProperty(
            claimsArgs,
            "Claims",
            "System.String",
            canWrite: false);
        ClaimsClientId = RequireProperty(
            claimsArgs,
            "ClientId",
            "System.String",
            canWrite: false);
        ClaimsRedirectUri = RequireProperty(
            claimsArgs,
            "RedirectUri",
            "System.String",
            canWrite: false);
        ClaimsResourceUri = RequireProperty(
            claimsArgs,
            "ResourceUri",
            "System.String",
            canWrite: false);
        ClaimsScope = RequireProperty(
            claimsArgs,
            "Scope",
            "System.String",
            canWrite: false);
        ClaimsUserNameHint = RequireProperty(
            claimsArgs,
            "UserNameHint",
            "System.String",
            canWrite: false);
        ClaimsRequest = RequireProperty(
            claimsArgs,
            "Request",
            Namespace + "IClaimsTokenRequest",
            canWrite: false);
        ClaimsGetDeferral = RequireMethod(
            claimsArgs,
            "GetDeferral",
            "Windows.Foundation.Deferral");
        CompleteDeferral = RequireMethod(
            ClaimsGetDeferral.ReturnType,
            "Complete",
            "System.Void");

        var claimsRequest = RequireType(assembly, "IClaimsTokenRequest");
        ProvideClaimsToken = RequireMethod(
            claimsRequest,
            "ProvideClaimsToken",
            "System.Void",
            "System.String",
            "System.String",
            "System.String",
            "System.Boolean",
            "System.String",
            "System.String",
            "System.String");
        CancelClaimsTokenRequest = RequireMethod(
            claimsRequest,
            "Cancel",
            "System.Void");

        var connectionMode = RequireType(assembly, "ConnectionMode");
        SilentConnectionMode = Enum.Parse(connectionMode, "Silent");
        LogLevelNone = Enum.Parse(RequireType(assembly, "LogLevel"), "None");
    }

    public Type ActivityManagerType { get; }
    public ConstructorInfo ActivityManagerConstructor { get; }
    public MethodInfo Initialize { get; }
    public MethodInfo ConfigureClaimsTokenAuthenticationContext { get; }
    public MethodInfo CreateConnection { get; }
    public MethodInfo CreateWorkspaceDownloader { get; }
    public MethodInfo GenerateNewActivityId { get; }
    public MethodInfo DownloadAsync { get; }
    public PropertyInfo WorkspaceSettings { get; }
    public EventInfo ResourceListAvailable { get; }
    public EventInfo WorkspaceDownloadCompleted { get; }
    public EventInfo WorkspaceDownloadStatusChanged { get; }
    public PropertyInfo WorkspaceDownloadCurrentStatus { get; }
    public PropertyInfo FeedDownloadStatus { get; }
    public PropertyInfo FeedUrl { get; }
    public PropertyInfo UserName { get; }
    public PropertyInfo ParentWindowHandle { get; }
    public PropertyInfo ForceRefresh { get; }
    public PropertyInfo AllowInteractivePrompts { get; }
    public PropertyInfo ActivityId { get; }
    public PropertyInfo IconFormats { get; }
    public object IconFormatPng { get; }
    public object IconFormatIco { get; }
    public PropertyInfo ResourceListDescriptor { get; }
    public PropertyInfo ResourceListResources { get; }
    public FieldInfo WorkspaceDescriptorId { get; }
    public PropertyInfo ResourceId { get; }
    public PropertyInfo ResourceAccessState { get; }
    public PropertyInfo ResourceRdpFile { get; }
    public FieldInfo RdpFileContents { get; }
    public FieldInfo RdpFileUrl { get; }
    public MethodInfo Connect { get; }
    public MethodInfo Disconnect { get; }
    public PropertyInfo ConnectionSettings { get; }
    public EventInfo Connected { get; }
    public EventInfo Disconnected { get; }
    public PropertyInfo DisconnectCode { get; }
    public PropertyInfo ClientStackDisconnectCode { get; }
    public PropertyInfo ServerStackDisconnectCode { get; }
    public PropertyInfo DisconnectErrorSymbolic { get; }
    public EventInfo WtsPluginsLoaded { get; }
    public EventInfo ClaimsTokenRequested { get; }
    public PropertyInfo ConnectionMode { get; }
    public PropertyInfo CloudPCSettingsUri { get; }
    public PropertyInfo AllowThirdPartyPlugins { get; }
    public PropertyInfo ConsumerHandlesClaimsTokenRequest { get; }
    public PropertyInfo PopupUIParentWindowHandle { get; }
    public PropertyInfo SessionWindowHandle { get; }
    public PropertyInfo StartFullscreen { get; }
    public PropertyInfo ClaimsAuthorityUri { get; }
    public PropertyInfo Claims { get; }
    public PropertyInfo ClaimsClientId { get; }
    public PropertyInfo ClaimsRedirectUri { get; }
    public PropertyInfo ClaimsResourceUri { get; }
    public PropertyInfo ClaimsScope { get; }
    public PropertyInfo ClaimsUserNameHint { get; }
    public PropertyInfo ClaimsRequest { get; }
    public MethodInfo ClaimsGetDeferral { get; }
    public MethodInfo CompleteDeferral { get; }
    public MethodInfo ProvideClaimsToken { get; }
    public MethodInfo CancelClaimsTokenRequest { get; }
    public object SilentConnectionMode { get; }
    public object LogLevelNone { get; }

    public static RdCoreReflectionBindings For(Assembly assembly) =>
        Cache.GetValue(assembly, static value => new(value));

    public object CreateActivityManager()
    {
        try
        {
            return ActivityManagerConstructor.Invoke(parameters: null);
        }

        catch (TargetInvocationException exception)
            when (exception.InnerException is not null)
        {
            ReflectionInvoke.ThrowInnermost(exception);
            throw;
        }
    }

    public object CreateActivityManagerFromAbi(nint native)
    {
        var fromAbi = ActivityManagerType.GetMethod(
            "FromAbi",
            BindingFlags.Public | BindingFlags.Static,
            [typeof(nint)]) ??
            throw Missing("ActivityManager.FromAbi");
        try
        {
            return fromAbi.Invoke(
                       null,
                       [native]) ??
                   throw new InvalidOperationException(
                       "RDCore ActivityManager.FromAbi returned null.");
        }

        catch (TargetInvocationException exception)
            when (exception.InnerException is not null)
        {
            ReflectionInvoke.ThrowInnermost(exception);
            throw;
        }
    }

    public void InitializeIconVector()
    {
        var iconVector = ActivityManagerType.Assembly.GetType(
            "WinRT.GenericTypeInstantiations." +
            "Windows_Foundation_Collections_IVector_1_" +
            "Microsoft_RemoteDesktop_ClientCore_IconFormat",
            throwOnError: false) ?? throw Missing(
            "IconFormat vector generic initializer");
        var initialize = iconVector.GetMethod(
            "EnsureInitialized",
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.Static) ?? throw Missing(
            "IconFormat vector EnsureInitialized");
        _ = ReflectionInvoke.Call(initialize, null);
    }

    public void InitializeActivityManager(
        object activityManager,
        RdCoreIntegrationOptions options)
    {
        ReflectionInvoke.Call(
            Initialize,
            activityManager,
            Environment.OSVersion.VersionString,
            string.Empty,
            options.ClientIdentifier,
            options.ClientVersion,
            options.ClientBuild,
            LogLevelNone);
        ReflectionInvoke.Call(
            ConfigureClaimsTokenAuthenticationContext,
            activityManager,
            options.ClaimsClientId,
            options.ClaimsRedirectUri);
    }

    private static Type RequireType(Assembly assembly, string typeName) =>
        assembly.GetType(Namespace + typeName, throwOnError: false) ??
        throw Missing(typeName);

    private static MethodInfo RequireMethod(
        Type type,
        string name,
        string returnType,
        params string[] parameterTypes) =>
        type.GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .SingleOrDefault(method =>
                string.Equals(method.Name, name, StringComparison.Ordinal) &&
                string.Equals(
                    FormatType(method.ReturnType),
                    returnType,
                    StringComparison.Ordinal) &&
                method.GetParameters()
                    .Select(parameter => FormatType(parameter.ParameterType))
                    .SequenceEqual(parameterTypes, StringComparer.Ordinal)) ??
        throw Missing($"{type.FullName}.{name}");

    private static PropertyInfo RequireProperty(
        Type type,
        string name,
        string propertyType,
        bool canWrite)
    {
        var property = type.GetProperty(
            name,
            BindingFlags.Instance | BindingFlags.Public);
        return property is not null &&
            string.Equals(
                FormatType(property.PropertyType),
                propertyType,
                StringComparison.Ordinal) &&
            property.CanRead &&
            (!canWrite || property.CanWrite)
            ? property
            : throw Missing($"{type.FullName}.{name}");
    }

    private static EventInfo RequireEvent(Type type, string name) =>
        type.GetEvent(name, BindingFlags.Instance | BindingFlags.Public) ??
        throw Missing($"{type.FullName}.{name}");

    private static FieldInfo RequireField(
        Type type,
        string name,
        string fieldType)
    {
        var field = type.GetField(name, BindingFlags.Instance | BindingFlags.Public);
        return field is not null &&
            string.Equals(
                FormatType(field.FieldType),
                fieldType,
                StringComparison.Ordinal)
            ? field
            : throw Missing($"{type.FullName}.{name}");
    }

    private static string FormatType(Type type)
    {
        if (!type.IsGenericType)
        {
            return type.FullName ?? type.Name;
        }

        return (type.GetGenericTypeDefinition().FullName ?? type.Name) +
            "[" +
            string.Join(",", type.GetGenericArguments().Select(FormatType)) +
            "]";
    }

    private static MissingMemberException Missing(string member) =>
        new($"The fingerprinted RDCore member '{member}' was unavailable.");
}

internal static class ReflectionInvoke
{
    public static object? Call(
        MethodInfo method,
        object? target,
        params object?[]? arguments)
    {
        try
        {
            return method.Invoke(target, arguments);
        }
        catch (TargetInvocationException exception)
            when (exception.InnerException is not null)
        {
            ReflectionInvoke.ThrowInnermost(exception);
            throw;
        }
    }

    public static object GetRequired(PropertyInfo property, object target)
    {
        try
        {
            return property.GetValue(target) ??
                throw new InvalidOperationException(
                    $"RDCore returned null for required property '{property.Name}'.");
        }

        catch (TargetInvocationException exception)
            when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    public static object? Get(PropertyInfo property, object target)
    {
        try
        {
            return property.GetValue(target);
        }
        catch (TargetInvocationException exception)
            when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    public static void Set(
        PropertyInfo property,
        object target,
        object? value)
    {
        try
        {
            property.SetValue(target, value);
        }
        catch (TargetInvocationException exception)
            when (exception.InnerException is not null)
        {
            ReflectionInvoke.ThrowInnermost(exception);
        }
    }

    internal static void ThrowInnermost(
        TargetInvocationException exception)
    {
        Exception current = exception;
        while (current is TargetInvocationException
               {
                   InnerException: not null
               } wrapper)
            current = wrapper.InnerException!;
        ExceptionDispatchInfo.Capture(current).Throw();
    }
}

internal sealed class ReflectionEventSubscription : IDisposable
{
    private readonly EventInfo eventInfo;
    private readonly object source;
    private readonly object relay;
    private readonly Delegate handler;
    private bool disposed;

    public ReflectionEventSubscription(
        EventInfo eventInfo,
        object source,
        Action<object?, object?> callback)
    {
        this.eventInfo = eventInfo;
        this.source = source;
        handler = ReflectionDelegateFactory.Create(
            eventInfo.EventHandlerType ??
            throw new MissingMemberException(
                $"Event '{eventInfo.Name}' has no handler type."),
            callback,
            out relay);
        eventInfo.AddEventHandler(source, handler);
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        eventInfo.RemoveEventHandler(source, handler);
        GC.KeepAlive(relay);
    }
}

internal static class ReflectedAsyncOperation
{
    public static async Task<object?> AwaitAsync(
        object operation,
        CancellationToken cancellationToken)
    {
        if (operation is Task task)
        {
            await task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return task.GetType().IsGenericType
                ? task.GetType().GetProperty("Result")!.GetValue(task)
                : null;
        }

        var type = operation.GetType();
        var completed = type.GetProperty(
            "Completed",
            BindingFlags.Instance | BindingFlags.Public) ??
            throw new MissingMemberException(
                "The RDCore asynchronous operation has no Completed property.");
        var getResults = type.GetMethod(
            "GetResults",
            BindingFlags.Instance | BindingFlags.Public,
            Type.EmptyTypes) ??
            throw new MissingMemberException(
                "The RDCore asynchronous operation has no GetResults method.");
        var cancel = type.GetMethod(
            "Cancel",
            BindingFlags.Instance | BindingFlags.Public,
            Type.EmptyTypes);
        var completion = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = ReflectionDelegateFactory.Create(
            completed.PropertyType,
            (_, status) => Complete(
                operation,
                getResults,
                completion,
                status),
            out var relay);
        ReflectionInvoke.Set(completed, operation, handler);
        using var registration = cancellationToken.Register(
            () =>
            {
                if (cancel is not null)
                {
                    ReflectionInvoke.Call(cancel, operation);
                }

                completion.TrySetCanceled(cancellationToken);
            });
        object? result;
        try
        {
            result = await completion.Task.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (cancel is not null)
            {
                ReflectionInvoke.Call(cancel, operation);
            }

            throw;
        }

        GC.KeepAlive(relay);
        return result;
    }

    private static void Complete(
        object operation,
        MethodInfo getResults,
        TaskCompletionSource<object?> completion,
        object? status)
    {
        switch (status?.ToString())
        {
            case "Completed":
                completion.TrySetResult(
                    ReflectionInvoke.Call(getResults, operation));
                break;
            case "Canceled":
                completion.TrySetCanceled();
                break;
            default:
                completion.TrySetException(
                    new InvalidOperationException(
                        "The RDCore asynchronous operation failed."));
                break;
        }
    }
}

internal static class ReflectionDelegateFactory
{
    public static Delegate Create(
        Type delegateType,
        Action<object?, object?> callback,
        out object relay)
    {
        var invoke = delegateType.GetMethod("Invoke") ??
            throw new MissingMethodException(
                "The reflected callback delegate has no Invoke method.");
        var parameters = invoke.GetParameters();
        if (parameters.Length != 2)
        {
            throw new InvalidOperationException(
                "The reflected callback delegate must have two parameters.");
        }

        var relayType = typeof(TwoParameterRelay<,>).MakeGenericType(
            parameters[0].ParameterType,
            parameters[1].ParameterType);
        relay = Activator.CreateInstance(relayType, callback) ??
            throw new InvalidOperationException(
                "The reflected callback relay could not be created.");
        var handle = relayType.GetMethod(
            nameof(TwoParameterRelay<object, object>.Handle))!;
        return Delegate.CreateDelegate(delegateType, relay, handle);
    }

    private sealed class TwoParameterRelay<TSender, TArgs>(
        Action<object?, object?> callback)
    {
        public void Handle(TSender sender, TArgs args) =>
            callback(sender, args);
    }
}
