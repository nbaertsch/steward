using System.Collections;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using Steward.DevBox.Windows;

namespace Steward.RdCore.Windows;

public sealed class RdCoreAvdResourceCatalog : IDevBoxAvdResourceCatalog
{
    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private readonly Func<IRdCoreReflectionSession> sessionFactory;
    private readonly RdCoreIntegrationOptions options;

    public RdCoreAvdResourceCatalog(
        RdCoreCapabilityReport capability,
        RdCoreIntegrationOptions? options = null)
        : this(
            () => new RdCoreLoaderSession(capability),
            options ?? new())
    {
    }

    internal RdCoreAvdResourceCatalog(
        Func<IRdCoreReflectionSession> sessionFactory,
        RdCoreIntegrationOptions options)
    {
        this.sessionFactory = sessionFactory;
        this.options = options;
    }

    public async Task<IReadOnlyList<DevBoxAvdResourceDescriptor>> ListAsync(
        CancellationToken cancellationToken)
    {
        options.Validate(requireFeed: true);
        options.Report("catalog-options-valid");
        cancellationToken.ThrowIfCancellationRequested();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(options.OperationTimeout);
        IRdCoreReflectionSession session;
        try
        {
            session = sessionFactory();
        }
        catch (Exception exception)
        {
            options.Report(
                $"catalog-session-failed-{exception.GetType().Name}-" +
                $"0x{exception.HResult:X8}-reason-" +
                SafeReason(exception.Message));
            throw;
        }
        using (session)
        {
        options.Report("catalog-session-created");
        var bindings = RdCoreReflectionBindings.For(session.Assembly);
        options.Report("catalog-bindings-created");
        object activityManager;
        try
        {
            activityManager = session.CreateActivityManager(bindings);
        }
        catch (Exception exception)
        {
            options.Report(
                $"catalog-activity-manager-failed-" +
                $"{exception.GetType().Name}-" +
                $"0x{exception.HResult:X8}" +
                (exception is RdCoreLoadException load
                    ? $"-{load.Code}" +
                      (load.Detail is { Length: > 0 and <= 128 } detail &&
                       detail.All(character =>
                           char.IsAsciiLetterOrDigit(character) ||
                           character is '.' or '-' or '_')
                          ? $"-{detail}"
                          : string.Empty)
                    : exception is DllNotFoundException
                      {
                          InnerException: System.ComponentModel.Win32Exception
                          win32
                      }
                        ? $"-win32-{win32.NativeErrorCode}"
                        : string.Empty) +
                ExceptionChain(exception) +
                $"-reason-{SafeReason(exception.Message)}");
            throw;
        }
        options.Report("catalog-activity-manager-created");
        bindings.InitializeActivityManager(activityManager, options);
        options.Report("catalog-activity-manager-initialized");
        var downloader = ReflectionInvoke.Call(
            bindings.CreateWorkspaceDownloader,
            activityManager) ??
            throw new InvalidOperationException(
                "RDCore returned no workspace downloader.");
        try
        {
            session.InitializeIconVector(bindings);
            ConfigureWorkspace(
                bindings,
                activityManager,
                downloader);
        }
        catch (Exception exception)
        {
            options.Report(
                $"catalog-workspace-failed-" +
                $"{exception.GetType().Name}-" +
                $"0x{exception.HResult:X8}" +
                ExceptionChain(exception) +
                $"-reason-{SafeReason(exception.Message)}");
            throw;
        }
        options.Report("catalog-workspace-configured");

        var resources = new List<DevBoxAvdResourceDescriptor>();
        var sync = new object();
        var acceptCallbacks = true;
        var callbackErrors = new BoundedCallbackErrorSlot();
        using var resourceSubscription = new ReflectionEventSubscription(
            bindings.ResourceListAvailable,
            downloader,
            (_, args) =>
            {
                lock (sync)
                {
                    if (acceptCallbacks)
                    {
                        CaptureCallbackError(
                            callbackErrors,
                            () =>
                            {
                                if (args is null)
                                {
                                    throw new InvalidDataException(
                                        "RDCore returned null resource-list " +
                                        "event data.");
                                }

                                AddResources(
                                    bindings,
                                    args,
                                    resources,
                                    sync);
                            });
                    }
                }
            });
        using var completionSubscription = new ReflectionEventSubscription(
            bindings.WorkspaceDownloadCompleted,
            downloader,
            (_, args) =>
            {
                lock (sync)
                {
                    if (acceptCallbacks)
                    {
                        CaptureCallbackError(
                            callbackErrors,
                            () =>
                            {
                                if (args is null)
                                {
                                    throw new InvalidDataException(
                                        "RDCore returned null workspace-" +
                                        "completion event data.");
                                }
                            });
                    }
                }
            });
        using var statusSubscription = new ReflectionEventSubscription(
            bindings.WorkspaceDownloadStatusChanged,
            downloader,
            (_, args) =>
            {
                if (args is null)
                    return;
                var status = ReflectionInvoke.Get(
                        bindings.WorkspaceDownloadCurrentStatus,
                        args)
                    ?.ToString();
                if (!string.IsNullOrWhiteSpace(status) &&
                    status.All(character =>
                        char.IsAsciiLetterOrDigit(character) ||
                        character is '-' or '_'))
                    options.Report(
                        $"catalog-workspace-status-{status}");
            });

        var operation = ReflectionInvoke.Call(bindings.DownloadAsync, downloader) ??
            throw new InvalidOperationException(
                "RDCore returned no workspace download operation.");
        options.Report("catalog-download-started");
        object? result;
        try
        {
            result = await ReflectedAsyncOperation.AwaitAsync(
                operation,
                timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (callbackErrors.HasError)
        {
            try
            {
                callbackErrors.ThrowIfCaptured();
            }
            catch (Exception exception)
            {
                ReportFailure(
                    "catalog-callback",
                    exception);
                throw;
            }
            throw;
        }
        catch (Exception exception)
        {
            ReportFailure("catalog-download", exception);
            throw;
        }
        finally
        {
            lock (sync)
            {
                acceptCallbacks = false;
            }
        }

        resourceSubscription.Dispose();
        completionSubscription.Dispose();
        statusSubscription.Dispose();
        try
        {
            callbackErrors.ThrowIfCaptured();
        }
        catch (Exception exception)
        {
            ReportFailure("catalog-callback", exception);
            throw;
        }
        options.Report("catalog-download-completed");
        if (result is null)
        {
            throw new InvalidDataException(
                "RDCore returned no feed download result.");
        }

        var status = bindings.FeedDownloadStatus.GetValue(result)?.ToString();
        options.Report($"catalog-feed-status-{status ?? "null"}");
        if (status is not ("Success" or "NoResourcesPublished"))
        {
            throw new InvalidDataException(
                "RDCore returned an unsuccessful or unknown feed status.");
        }

        lock (sync)
        {
            if (status == "NoResourcesPublished" && resources.Count != 0)
            {
                throw new InvalidDataException(
                    "RDCore returned resources with a no-resources status.");
            }

            return resources.ToArray();
        }
        }
    }

    private static string ExceptionChain(Exception exception)
    {
        var result = new StringBuilder();
        var current = exception.InnerException;
        for (var depth = 0; current is not null && depth < 3; depth++)
        {
            result.Append("-inner-");
            result.Append(current.GetType().Name);
            result.Append("-0x");
            result.Append(current.HResult.ToString("X8"));
            result.Append("-reason-");
            result.Append(SafeReason(current.Message));
            current = current.InnerException;
        }

        return result.ToString();
    }

    private void ReportFailure(string stage, Exception exception) =>
        options.Report(
            $"{stage}-failed-{exception.GetType().Name}-" +
            $"0x{exception.HResult:X8}" +
            ExceptionChain(exception) +
            $"-reason-{SafeReason(exception.Message)}");

    private static string SafeReason(string message)
    {
        var result = new StringBuilder();
        foreach (var character in message.Take(160))
        {
            result.Append(
                char.IsAsciiLetterOrDigit(character) ||
                character is ' ' or '.' or '-' or '_' or ':'
                    ? character
                    : '_');
        }
        return result
            .ToString()
            .Replace("  ", " ", StringComparison.Ordinal)
            .Trim()
            .Replace(' ', '_');
    }

    private void ConfigureWorkspace(
        RdCoreReflectionBindings bindings,
        object activityManager,
        object downloader)
    {
        var settings = ReflectionInvoke.GetRequired(
            bindings.WorkspaceSettings,
            downloader);
        options.Report("workspace-settings-read");
        ReflectionInvoke.Set(
            bindings.FeedUrl,
            settings,
            options.AvdFeedUri!.AbsoluteUri);
        options.Report("workspace-feed-set");
        ReflectionInvoke.Set(
            bindings.UserName,
            settings,
            options.Account);
        options.Report("workspace-user-set");
        ReflectionInvoke.Set(
            bindings.ParentWindowHandle,
            settings,
            0UL);
        options.Report("workspace-parent-set");
        ReflectionInvoke.Set(
            bindings.ForceRefresh,
            settings,
            true);
        options.Report("workspace-refresh-set");
        ReflectionInvoke.Set(
            bindings.AllowInteractivePrompts,
            settings,
            false);
        options.Report("workspace-prompts-set");
        var activityId = ReflectionInvoke.Call(
            bindings.GenerateNewActivityId,
            activityManager) ?? throw new InvalidOperationException(
            "RDCore returned no workspace activity ID.");
        options.Report("workspace-activity-generated");
        ReflectionInvoke.Set(
            bindings.ActivityId,
            settings,
            activityId);
        options.Report("workspace-activity-set");
        var iconList = Activator.CreateInstance(
            typeof(List<>).MakeGenericType(
                bindings.IconFormatPng.GetType())) ??
            throw new InvalidOperationException(
                "RDCore icon format list could not be created.");
        options.Report("workspace-icons-created");
        if (iconList is not IList icons)
            throw new InvalidOperationException(
                "RDCore icon format list is not mutable.");
        _ = icons.Add(bindings.IconFormatPng);
        _ = icons.Add(bindings.IconFormatIco);
        options.Report("workspace-icons-filled");
        ReflectionInvoke.Set(
            bindings.IconFormats,
            settings,
            iconList);
        options.Report("workspace-icons-set");
        ReflectionInvoke.Set(
            bindings.WorkspaceSettings,
            downloader,
            settings);
        options.Report("workspace-settings-committed");

        if (!string.Equals(
                ReflectionInvoke.Get(bindings.FeedUrl, settings) as string,
                options.AvdFeedUri.AbsoluteUri,
                StringComparison.Ordinal) ||
            !string.Equals(
                ReflectionInvoke.Get(bindings.UserName, settings) as string,
                options.Account,
                StringComparison.Ordinal) ||
            !Equals(
                ReflectionInvoke.Get(
                    bindings.ParentWindowHandle,
                    settings),
                0UL) ||
            !Equals(ReflectionInvoke.Get(bindings.ForceRefresh, settings), true) ||
            !Equals(
                ReflectionInvoke.Get(
                    bindings.AllowInteractivePrompts,
                    settings),
                false))
        {
            throw new InvalidOperationException(
                "RDCore did not retain the required silent workspace settings.");
        }
    }

    private void AddResources(
        RdCoreReflectionBindings bindings,
        object args,
        List<DevBoxAvdResourceDescriptor> destination,
        object sync)
    {
        var descriptor = ReflectionInvoke.GetRequired(
            bindings.ResourceListDescriptor,
            args);
        var workspaceId =
            bindings.WorkspaceDescriptorId.GetValue(descriptor) as string;
        var resourceValues = ReflectionInvoke.GetRequired(
            bindings.ResourceListResources,
            args);
        if (string.IsNullOrWhiteSpace(workspaceId) ||
            resourceValues is not IEnumerable enumerable)
        {
            throw new InvalidDataException(
                "RDCore returned an invalid workspace resource list.");
        }

        foreach (var resource in enumerable)
        {
            if (resource is null)
            {
                throw new InvalidDataException(
                    "RDCore returned a null workspace resource.");
            }

            var mapped = MapResource(bindings, workspaceId, resource);
            lock (sync)
            {
                if (destination.Count >= options.MaximumResources)
                {
                    throw new InvalidDataException(
                        "RDCore returned more resources than the configured bound.");
                }

                if (destination.Any(item =>
                        string.Equals(
                            item.WorkspaceId,
                            mapped.WorkspaceId,
                            StringComparison.Ordinal) &&
                        string.Equals(
                            item.ResourceId,
                            mapped.ResourceId,
                            StringComparison.Ordinal)))
                {
                    throw new InvalidDataException(
                        "RDCore returned a duplicate workspace resource.");
                }

                destination.Add(mapped);
            }
        }
    }

    private DevBoxAvdResourceDescriptor MapResource(
        RdCoreReflectionBindings bindings,
        string workspaceId,
        object resource)
    {
        var resourceId = bindings.ResourceId.GetValue(resource) as string;
        var accessState = bindings.ResourceAccessState.GetValue(resource);
        var rdpFile = ReflectionInvoke.GetRequired(
            bindings.ResourceRdpFile,
            resource);
        var rdpContent = bindings.RdpFileContents.GetValue(rdpFile) as string;
        var rdpUrl = bindings.RdpFileUrl.GetValue(rdpFile) as string;
        if (string.IsNullOrWhiteSpace(resourceId))
        {
            throw new InvalidDataException(
                "RDCore returned a resource without an identifier.");
        }

        var hasContent = !string.IsNullOrEmpty(rdpContent);
        var hasUrl = !string.IsNullOrEmpty(rdpUrl);
        if (hasContent == hasUrl)
        {
            throw new InvalidDataException(
                "RDCore returned an ambiguous RDP content source.");
        }

        if (hasContent)
        {
            var content = StrictUtf8.GetBytes(rdpContent!);
            if (content.Length > options.MaximumRdpContentBytes)
            {
                throw new InvalidDataException(
                    "RDCore returned RDP content above the configured bound.");
            }

            return new(
                workspaceId,
                resourceId,
                MapEndpointState(accessState),
                BrokerRdpContentUri: null,
                content);
        }

        if (!Uri.TryCreate(rdpUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.UserInfo.Length != 0 ||
            uri.OriginalString.Length >
                DevBoxRemoteViewingValidator.MaximumActivationUriCharacters)
        {
            throw new InvalidDataException(
                "RDCore returned an invalid broker RDP content link.");
        }

        return new(
            workspaceId,
            resourceId,
            MapEndpointState(accessState),
            uri,
            ReadOnlyMemory<byte>.Empty);
    }

    private static DevBoxAvdEndpointDeviceState MapEndpointState(object? state) =>
        state?.ToString() switch
        {
            "Unavailable" => DevBoxAvdEndpointDeviceState.Unavailable,
            "Available" => DevBoxAvdEndpointDeviceState.Available,
            "StartOnConnect" => DevBoxAvdEndpointDeviceState.StartOnConnect,
            "SilentlyConnectable" or "SilentlyConnectible" =>
                DevBoxAvdEndpointDeviceState.SilentlyConnectible,
            "Unhealthy" => DevBoxAvdEndpointDeviceState.Unhealthy,
            _ => DevBoxAvdEndpointDeviceState.Unknown
        };

    private static void CaptureCallbackError(
        BoundedCallbackErrorSlot errors,
        Action callback)
    {
        try
        {
            callback();
        }
        catch (InvalidDataException exception)
        {
            errors.TryCapture(exception);
        }
        catch (InvalidOperationException exception)
        {
            errors.TryCapture(exception);
        }
        catch (ArgumentException exception)
        {
            errors.TryCapture(exception);
        }
        catch (TargetInvocationException exception)
        {
            errors.TryCapture(exception.InnerException ?? exception);
        }
        catch (MissingMemberException exception)
        {
            errors.TryCapture(exception);
        }
    }

    private sealed class BoundedCallbackErrorSlot
    {
        private readonly TaskCompletionSource<Exception> error =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool HasError => error.Task.IsCompletedSuccessfully;

        public void TryCapture(Exception exception) =>
            error.TrySetResult(exception);

        public void ThrowIfCaptured()
        {
            if (error.Task.IsCompletedSuccessfully)
            {
                ExceptionDispatchInfo.Capture(error.Task.Result).Throw();
            }
        }
    }
}
