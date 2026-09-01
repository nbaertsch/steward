using System.Diagnostics;
using Steward.Application;
using Steward.Cli;
using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Providers.Abstractions;
using Steward.Transport.Rdp.Windows;

namespace Steward.Desktop.Windows;

public interface IStewardDesktopView
{
    IntPtr NativeWindowHandle { get; }
    void Render(DesktopSnapshot snapshot);
    void SetCommandBusy(string commandKey, bool busy);
    void ShowError(DesktopError error);
    void ShowProviderInspection(NodeViewModel node, ProviderResource? resource);
    void ShowTaskEvents(
        TaskId taskId,
        IReadOnlyList<PersistedNodeFact> events);
    void ShowInformation(string message);
    void ShowConnectionHostStartup(
        DevBoxConnectionIdentityStatus identity,
        ConnectionHostCommandResult host);
    void OpenConnectionHost(
        NodeViewModel node,
        DevBoxConnectionIdentityStatus identity,
        ConnectionHostCommandResult host,
        bool connectConfigured);
    void ShowConnectionHostStatus(
        DevBoxConnectionIdentityStatus identity,
        ConnectionHostCommandResult host,
        bool connectConfigured);
    void ShowAdvancedRemoteViewer(
        DevBoxRemoteViewingResource resource);
    void ShowRemoteViewerLaunch(
        DevBoxRemoteViewerLaunchResult result);
    void ShowRemoteViewerSession(
        DevBoxExternalViewerSessionStatus status);
    void ShowDvcRegistrationStatus(
        DvcPluginRegistrationStatus status);
    void OpenTerminal(
        NodeViewModel node,
        ManagedTerminalController terminal);
}

public sealed class StewardDesktopController : IDisposable
{
    private readonly IStewardControlClient control;
    private readonly IDevBoxDesktopGateway devBox;
    private readonly IConnectionHostPipeGateway connectionHost;
    private readonly IConnectionIdentityService connectionIdentity;
    private readonly IStewardDesktopView view;
    private readonly RefreshSequence refreshSequence = new();
    private CancellationTokenSource refreshCancellation = new();
    private DevBoxInventory? inventory;
    private DesktopSnapshot? current;
    private bool disposed;

    public StewardDesktopController(
        IStewardControlClient control,
        IDevBoxDesktopGateway devBox,
        IConnectionHostPipeGateway connectionHost,
        IConnectionIdentityService connectionIdentity,
        IStewardDesktopView view)
    {
        this.control = control;
        this.devBox = devBox;
        this.connectionHost = connectionHost;
        this.connectionIdentity = connectionIdentity;
        this.view = view;
    }

    public DesktopSnapshot? Current => current;

    public async Task InitializeConnectionHostAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var snapshot = await new ConnectionHostStartupProbe(
                connectionHost,
                connectionIdentity)
            .ProbeAsync(cancellationToken);
        view.ShowConnectionHostStartup(
            snapshot.Identity,
            snapshot.Host);
    }

    public async Task RefreshAsync(
        bool discoverPools,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var sequence = refreshSequence.Begin();
        await refreshCancellation.CancelAsync();
        refreshCancellation.Dispose();
        refreshCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        var token = refreshCancellation.Token;
        view.SetCommandBusy("refresh", true);
        try
        {
            var identityTask = devBox.StatusAsync(token);
            var doctorTask = control.DoctorAsync(token);
            var orchestrationTask = control.OrchestrationDoctorAsync(token);
            var terminalTask = control.GetTerminalPolicyAsync(token);
            var poolsTask = control.ListPoolsAsync(token);
            var hostsTask = control.ListHostsAsync(token);
            var nodesTask = control.ListNodesAsync(token);
            var operationsTask = control.GetOperationsAsync(token);
            var mutationTask = control.HasMutationTokenAsync(token).AsTask();
            await Task.WhenAll(
                identityTask,
                doctorTask,
                orchestrationTask,
                terminalTask,
                poolsTask,
                hostsTask,
                nodesTask,
                operationsTask,
                mutationTask);
            var identity = await identityTask;
            if (discoverPools && identity.SignedIn)
                inventory = await devBox.DiscoverAsync(token);
            var candidate = DesktopProjection.Create(
                sequence,
                await doctorTask,
                await orchestrationTask,
                await terminalTask,
                identity,
                await mutationTask,
                inventory,
                await poolsTask,
                await hostsTask,
                await nodesTask,
                await operationsTask);
            _ = refreshSequence.TryPublish(
                sequence,
                candidate,
                snapshot =>
                {
                    current = snapshot;
                    view.Render(snapshot);
                });
        }
        catch (OperationCanceledException)
            when (token.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (IsOperational(exception))
        {
            if (!refreshSequence.IsCurrent(sequence))
                return;
            var error = SafeErrorMapper.Map(exception);
            view.ShowError(error);
            if (current is not null)
            {
                current = current with
                {
                    Sequence = sequence,
                    ConnectionState =
                        error.Code == "ControlDisconnected"
                            ? DesktopConnectionState.Disconnected
                            : DesktopConnectionState.Error,
                    Error = error
                };
                view.Render(current);
            }
            else
            {
                var disconnected = new DesktopSnapshot(
                    sequence,
                    DateTimeOffset.UtcNow,
                    error.Code == "ControlDisconnected"
                        ? DesktopConnectionState.Disconnected
                        : DesktopConnectionState.Error,
                    null,
                    null,
                    null,
                    new(
                        DevBoxIdentityConstants.CurrentVersion,
                        DevBoxIdentityConstants.ContextName,
                        false,
                        null,
                        null,
                        null,
                        null),
                    false,
                    [],
                    [],
                    new(
                        DateTimeOffset.UtcNow,
                        [],
                        [],
                        [],
                        [],
                        [],
                        [],
                        []),
                    error);
                current = disconnected;
                view.Render(disconnected);
            }
        }
        finally
        {
            if (refreshSequence.IsCurrent(sequence))
                view.SetCommandBusy("refresh", false);
        }
    }

    public Task DiscoverPoolsAsync(
        CancellationToken cancellationToken = default) =>
        RefreshAsync(discoverPools: true, cancellationToken);

    public async Task LoginAsync(CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            "login",
            async token =>
            {
                _ = await devBox.LoginAsync(view.NativeWindowHandle, token);
                await RefreshAsync(discoverPools: false, token);
            },
            cancellationToken);
    }

    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            "logout",
            async token =>
            {
                _ = await devBox.LogoutAsync(token);
                inventory = null;
                await RefreshAsync(discoverPools: false, token);
            },
            cancellationToken);
    }

    public async Task RegisterPoolAsync(
        PoolViewModel pool,
        int warmMinimum,
        int hardMaximum,
        TimeSpan idleTimeout,
        TimeSpan stoppedRetention,
        CancellationToken cancellationToken = default)
    {
        var binding = new ProviderBinding(
            "azure-dev-box",
            pool.Key.Project,
            pool.Key.Pool);
        var registration = new PoolRegistration(
            new(
                PoolId.New(),
                warmMinimum,
                hardMaximum,
                idleTimeout,
                stoppedRetention),
            binding);
        await RunCommandAsync(
            $"pool-register:{pool.Key.Project}:{pool.Key.Pool}",
            async token =>
            {
                _ = await control.RegisterPoolAsync(registration, token);
                await RefreshAsync(discoverPools: false, token);
            },
            cancellationToken);
    }

    public async Task ReconcilePoolAsync(
        PoolViewModel pool,
        CancellationToken cancellationToken = default)
    {
        if (pool.PoolId is null)
            throw new InvalidOperationException(
                "Only registered Pools can be reconciled.");
        await RunCommandAsync(
            $"pool-reconcile:{pool.PoolId}",
            async token =>
            {
                _ = await control.ReconcilePoolAsync(
                    pool.PoolId.Value,
                    new([], DateTimeOffset.UtcNow),
                    token);
                await RefreshAsync(discoverPools: false, token);
            },
            cancellationToken);
    }

    public async Task InspectHostAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            $"host-inspect:{node.HostId}",
            async token =>
            {
                var resource = await control.InspectHostAsync(
                    node.HostId,
                    token);
                view.ShowProviderInspection(node, resource);
            },
            cancellationToken);
    }

    public async Task ExecuteHostCommandAsync(
        NodeViewModel node,
        NodeCommand command,
        bool force,
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            $"host:{node.HostId}:{command}",
            async token =>
            {
                switch (command)
                {
                    case NodeCommand.Start:
                        _ = await control.StartHostAsync(
                            node.HostId,
                            node.NodeIncarnationId,
                            token);
                        break;
                    case NodeCommand.Drain:
                        _ = await control.DrainHostAsync(
                            node.HostId,
                            node.NodeIncarnationId,
                            force,
                            token);
                        break;
                    case NodeCommand.Stop:
                        _ = await control.StopHostAsync(
                            node.HostId,
                            node.NodeIncarnationId,
                            force,
                            token);
                        break;
                    case NodeCommand.Recreate:
                        _ = await control.RecreateHostAsync(
                            node.HostId,
                            node.NodeIncarnationId,
                            force,
                            token);
                        break;
                    case NodeCommand.Delete:
                        _ = await control.DeleteHostAsync(
                            node.HostId,
                            node.NodeIncarnationId,
                            force,
                            token);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(
                            nameof(command),
                            "The command is not a Host lifecycle operation.");
                }
                await RefreshAsync(discoverPools: false, token);
            },
            cancellationToken);
    }

    public async Task OpenRemoteViewerAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default)
    {
        if (node.DevBox is null)
            throw new InvalidOperationException(
                "The selected Host is not a discovered Dev Box.");
        await RunCommandAsync(
            $"remote-viewer:{node.HostId}",
            async token =>
            {
                var identityTask =
                    connectionIdentity.StatusAsync(token);
                var hostTask = connectionHost.StatusAsync(
                    ConnectionId(node),
                    token);
                await Task.WhenAll(identityTask, hostTask);
                view.OpenConnectionHost(
                    node,
                    await identityTask,
                    await hostTask,
                    connectionHost.ConnectConfigured);
            },
            cancellationToken);
    }

    public Task RefreshConnectionHostAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default) =>
        RunConnectionHostCommandAsync(
            $"connection-host-status:{node.HostId}",
            node,
            token => connectionHost.StatusAsync(
                ConnectionId(node),
                token),
            cancellationToken);

    public async Task EnrollConnectionIdentityAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            "connection-identity-enroll",
            async token =>
            {
                _ = await connectionIdentity.EnrollAsync(
                    view.NativeWindowHandle,
                    token);
                await PublishConnectionHostAsync(
                    node,
                    await connectionHost.StatusAsync(
                        ConnectionId(node),
                        token),
                    token);
            },
            cancellationToken);
    }

    public async Task LogoutConnectionIdentityAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            "connection-identity-logout",
            async token =>
            {
                _ = await connectionIdentity.LogoutAsync(token);
                await PublishConnectionHostAsync(
                    node,
                    await connectionHost.StatusAsync(
                        ConnectionId(node),
                        token),
                    token);
            },
            cancellationToken);
    }

    public Task ResolveConnectionHostAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default)
    {
        if (node.DevBox is null)
            throw new InvalidOperationException(
                "The selected Host is not a discovered Dev Box.");
        return RunConnectionHostCommandAsync(
            $"connection-host-resolve:{node.HostId}",
            node,
            async token =>
            {
                using var provider =
                    await devBox.GetConnectionHostProviderResourceAsync(
                        node.DevBox.Endpoint,
                        node.DevBox.ProjectName,
                        node.DevBox.Name,
                        token);
                return await connectionHost.ResolveAsync(
                    ConnectionId(node),
                    provider.Value,
                    token);
            },
            cancellationToken);
    }

    public Task PrepareConnectionHostAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default) =>
        RunConnectionHostCommandAsync(
            $"connection-host-prepare:{node.HostId}",
            node,
            token => connectionHost.PrepareAsync(
                ConnectionId(node),
                token),
            cancellationToken);

    public Task ConnectConnectionHostAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default) =>
        RunConnectionHostCommandAsync(
            $"connection-host-connect:{node.HostId}",
            node,
            token => connectionHost.ConnectAsync(
                ConnectionId(node),
                token),
            cancellationToken);

    public Task ViewConnectionHostAsync(
        NodeViewModel node,
        long generation,
        CancellationToken cancellationToken = default) =>
        RunConnectionHostCommandAsync(
            $"connection-host-view:{node.HostId}:{generation}",
            node,
            token => connectionHost.ViewAsync(
                ConnectionId(node),
                generation,
                token),
            cancellationToken);

    public Task TakeConnectionHostControlAsync(
        NodeViewModel node,
        long generation,
        CancellationToken cancellationToken = default) =>
        RunConnectionHostCommandAsync(
            $"connection-host-control:{node.HostId}:{generation}",
            node,
            token => connectionHost.TakeControlAsync(
                ConnectionId(node),
                generation,
                token),
            cancellationToken);

    public Task ReleaseConnectionHostControlAsync(
        NodeViewModel node,
        long generation,
        CancellationToken cancellationToken = default) =>
        RunConnectionHostCommandAsync(
            $"connection-host-release:{node.HostId}:{generation}",
            node,
            token => connectionHost.ReleaseControlAsync(
                ConnectionId(node),
                generation,
                token),
            cancellationToken);

    public Task DisconnectConnectionHostAsync(
        NodeViewModel node,
        long? generation,
        CancellationToken cancellationToken = default) =>
        RunConnectionHostCommandAsync(
            $"connection-host-disconnect:{node.HostId}",
            node,
            token => connectionHost.DisconnectAsync(
                ConnectionId(node),
                generation,
                token),
            cancellationToken);

    public async Task LoadAdvancedRemoteViewerAsync(
        NodeViewModel node,
        CancellationToken cancellationToken = default)
    {
        if (node.DevBox is null)
            throw new InvalidOperationException(
                "The selected Host is not a discovered Dev Box.");
        await RunCommandAsync(
            $"advanced-remote-viewer:{node.HostId}",
            async token =>
            {
                var resource =
                    await devBox.GetRemoteViewingResourceAsync(
                        node.DevBox.Endpoint,
                        node.DevBox.ProjectName,
                        node.DevBox.Name,
                        token);
                view.ShowAdvancedRemoteViewer(resource);
            },
            cancellationToken);
    }

    public async Task LaunchAdvancedRemoteViewerAsync(
        DevBoxRemoteViewingResource resource,
        DevBoxRemoteViewerTarget target,
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            $"remote-viewer-launch:{target}",
            async token =>
            {
                var result = await devBox.LaunchRemoteViewerAsync(
                    resource.Handle,
                    target,
                    token);
                view.ShowRemoteViewerLaunch(result);
            },
            cancellationToken);
    }

    private Task RunConnectionHostCommandAsync(
        string commandKey,
        NodeViewModel node,
        Func<CancellationToken, Task<ConnectionHostCommandResult>> action,
        CancellationToken cancellationToken) =>
        RunCommandAsync(
            commandKey,
            async token => await PublishConnectionHostAsync(
                node,
                await action(token),
                token),
            cancellationToken);

    private async Task PublishConnectionHostAsync(
        NodeViewModel node,
        ConnectionHostCommandResult result,
        CancellationToken cancellationToken)
    {
        _ = node;
        var identity = await connectionIdentity.StatusAsync(
            cancellationToken);
        view.ShowConnectionHostStatus(
            identity,
            result,
            connectionHost.ConnectConfigured);
    }

    private static string ConnectionId(NodeViewModel node) =>
        node.HostId.ToString();

    public void RefreshRemoteViewerSession(
        DevBoxExternalViewerSessionHandle handle)
    {
        try
        {
            view.ShowRemoteViewerSession(
                devBox.GetRemoteViewerSessionStatus(handle));
        }
        catch (DevBoxRemoteViewerException exception)
        {
            view.ShowError(SafeErrorMapper.Map(exception));
        }
    }

    public async Task SurfaceRemoteViewerAsync(
        DevBoxExternalViewerSessionHandle handle,
        DevBoxExternalViewerIntent intent,
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            $"remote-viewer-surface:{intent}",
            token =>
            {
                token.ThrowIfCancellationRequested();
                view.ShowRemoteViewerSession(
                    devBox.SurfaceRemoteViewer(
                        handle,
                        intent));
                return Task.CompletedTask;
            },
            cancellationToken);
    }

    public async Task RegisterDvcPluginAsync(
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            "dvc-plugin-register",
            token =>
            {
                token.ThrowIfCancellationRequested();
                view.ShowDvcRegistrationStatus(
                    devBox.RegisterDvcPlugin());
                return Task.CompletedTask;
            },
            cancellationToken);
    }

    public async Task LoadTaskEventsAsync(
        TaskId taskId,
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            $"task-events:{taskId}",
            async token =>
            {
                var events = await control.ReadTaskEventsAsync(
                    taskId,
                    0,
                    500,
                    token);
                view.ShowTaskEvents(taskId, events);
            },
            cancellationToken);
    }

    public async Task DownloadArtifactAsync(
        PortableObjectId artifactId,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        await RunCommandAsync(
            $"artifact-download:{artifactId}",
            async token =>
            {
                var result = await control.DownloadArtifactAsync(
                    artifactId,
                    destinationPath,
                    cancellationToken: token);
                view.ShowInformation(
                    $"Downloaded {result.BytesWritten:N0} bytes to {result.LocalPath}.");
            },
            cancellationToken);
    }

    public void OpenTerminal(NodeViewModel node)
    {
        var policy = current?.TerminalPolicy
            ?? throw new InvalidOperationException(
                "Terminal policy has not been loaded.");
        view.OpenTerminal(
            node,
            new ManagedTerminalController(control, node, policy));
    }

    private async Task RunCommandAsync(
        string commandKey,
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        view.SetCommandBusy(commandKey, true);
        try
        {
            await action(cancellationToken);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (IsOperational(exception))
        {
            Trace.TraceError(
                "Steward Desktop operation {0} failed with {1}.",
                commandKey,
                exception.GetType().Name);
            view.ShowError(SafeErrorMapper.Map(exception));
        }
        finally
        {
            view.SetCommandBusy(commandKey, false);
        }
    }

    private static bool IsOperational(Exception exception) =>
        exception is
            ControlApiException or
            Steward.Terminal.Abstractions.TerminalException or
            HttpRequestException or
            InvalidDataException or
            InvalidOperationException or
            IOException or
            UnauthorizedAccessException or
            Azure.Identity.CredentialUnavailableException or
            Azure.Identity.AuthenticationFailedException or
            Azure.RequestFailedException or
            DevBoxRemoteViewerException;

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        refreshCancellation.Cancel();
        refreshCancellation.Dispose();
        devBox.Dispose();
        GC.SuppressFinalize(this);
    }
}
