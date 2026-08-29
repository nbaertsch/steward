using Steward.Application;
using Steward.ConnectionHost.Windows;
using Steward.Orchestration;
using Steward.Providers.Abstractions;
using Steward.DevBox.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.Desktop.Windows;

internal sealed class MainForm : Form, IStewardDesktopView
{
    private readonly CancellationTokenSource lifetime = new();
    private readonly HashSet<string> busyCommands = new(StringComparer.Ordinal);
    private readonly ToolStripButton refresh = new("Refresh");
    private readonly ToolStripButton discover = new("Discover Pools");
    private readonly ToolStripButton login = new("Sign in");
    private readonly ToolStripButton logout = new("Sign out");
    private readonly ToolStripLabel identity = new("devbox/default: checking…");
    private readonly ToolStripLabel connectionIdentity =
        new("devbox/connection: checking…");
    private readonly ToolStrip mainToolbar = new()
    {
        GripStyle = ToolStripGripStyle.Hidden,
        AccessibleName = "Steward commands"
    };
    private readonly StatusStrip statusBar = new();
    private readonly ToolStripStatusLabel connectionStatus = new("Connecting to Control…");
    private readonly ToolStripStatusLabel operationStatus =
        new() { Spring = true, TextAlign = System.Drawing.ContentAlignment.MiddleRight };
    private readonly TabControl tabs = new() { Dock = DockStyle.Fill };
    private readonly TabPage poolsTab = new("Pools");
    private readonly TabPage nodesTab = new("Nodes");
    private readonly TabPage operationsTab = new("Operations");
    private readonly TabPage healthTab = new("Health");
    private readonly TabPage remoteViewerTab = new("Remote Viewer");
    private readonly TabPage shellTab = new("Managed Shell");
    private readonly ListView pools = ListView(
        ("Pool", 260),
        ("Health", 100),
        ("Location", 100),
        ("Count", 70),
        ("Registration", 110));
    private readonly ListView nodes = ListView(
        ("Host / provider resource", 260),
        ("Lifecycle", 100),
        ("Connection", 100),
        ("Assigned", 75),
        ("Last fact", 170));
    private readonly TextBox poolDetails = DetailsText("Pool details");
    private readonly TextBox nodeDetails = DetailsText("Node details");
    private readonly TextBox healthDetails = DetailsText("Steward health");
    private readonly DataGridView workloadGrid = Grid(
        "Workloads",
        ("Workload", 250),
        ("Type", 120),
        ("Desired", 90),
        ("Observed", 100),
        ("Progress", 130));
    private readonly DataGridView taskGrid = Grid(
        "Tasks",
        ("Task", 250),
        ("Type", 110),
        ("Desired", 90),
        ("Observed", 100),
        ("Generation", 80),
        ("Resources", 230));
    private readonly DataGridView artifactGrid = Grid(
        "Artifacts",
        ("Artifact", 250),
        ("Kind", 110),
        ("Size", 100),
        ("Complete", 75),
        ("Created", 150),
        ("SHA-256", 300));
    private readonly DataGridView agentGrid = Grid(
        "Agents",
        ("Agent", 250),
        ("Runtime", 160),
        ("Revision", 80),
        ("Ack cursor", 100),
        ("Recent notices", 100),
        ("Notice kinds", 220),
        ("Placement", 90),
        ("Frozen", 70));
    private readonly DataGridView eventGrid = Grid(
        "Task events",
        ("Sequence", 80),
        ("Node incarnation", 250),
        ("Kind", 230),
        ("Processed", 160));
    private readonly RemoteViewerPane remoteViewer = new();
    private readonly Panel shellHost = new() { Dock = DockStyle.Fill };
    private StewardDesktopController? controller;
    private DesktopSnapshot? snapshot;
    private ManagedTerminalPane? terminalPane;
    private bool closingReady;

    public MainForm()
    {
        Text = "Steward";
        AccessibleName = "Steward operations";
        MinimumSize = new(980, 680);
        Size = new(1440, 900);
        StartPosition = FormStartPosition.CenterScreen;
        KeyPreview = true;
        AutoScaleMode = AutoScaleMode.Dpi;

        mainToolbar.Items.AddRange(
        [
            refresh,
            discover,
            new ToolStripSeparator(),
            login,
            logout,
            new ToolStripSeparator(),
            identity,
            new ToolStripSeparator(),
            connectionIdentity
        ]);
        mainToolbar.Dock = DockStyle.Top;
        statusBar.Items.AddRange([connectionStatus, operationStatus]);
        statusBar.Dock = DockStyle.Bottom;
        tabs.TabPages.AddRange(
        [
            poolsTab,
            nodesTab,
            operationsTab,
            healthTab,
            remoteViewerTab,
            shellTab
        ]);
        Controls.Add(tabs);
        Controls.Add(mainToolbar);
        Controls.Add(statusBar);
        BuildPoolsTab();
        BuildNodesTab();
        BuildOperationsTab();
        pools.AccessibleName = "Steward Pools";
        nodes.AccessibleName = "Steward Nodes and members";
        healthTab.Controls.Add(healthDetails);
        remoteViewerTab.Controls.Add(remoteViewer);
        shellHost.Controls.Add(new Label
        {
            Dock = DockStyle.Fill,
            TextAlign = System.Drawing.ContentAlignment.MiddleCenter,
            Text =
                "Open a managed shell from a Node context menu.\r\n" +
                "Steward terminal authority and the Node ConPTY runtime are required."
        });
        shellTab.Controls.Add(shellHost);

        refresh.Click += async (_, _) =>
            await RequireController().RefreshAsync(false, lifetime.Token);
        discover.Click += async (_, _) =>
            await RequireController().DiscoverPoolsAsync(lifetime.Token);
        login.Click += async (_, _) =>
            await RequireController().LoginAsync(lifetime.Token);
        logout.Click += async (_, _) =>
            await RequireController().LogoutAsync(lifetime.Token);
        pools.SelectedIndexChanged += (_, _) => RenderSelectedPool();
        nodes.SelectedIndexChanged += (_, _) => RenderSelectedNode();
        pools.MouseDoubleClick += (_, eventArgs) =>
        {
            if (eventArgs.Button == MouseButtons.Left)
                InspectPoolMembers();
        };
        nodes.MouseDoubleClick += async (_, eventArgs) =>
        {
            if (eventArgs.Button == MouseButtons.Left &&
                busyCommands.Count == 0 &&
                SelectedNode() is { } node)
                await RequireController().InspectHostAsync(
                    node,
                    lifetime.Token);
        };
        taskGrid.SelectionChanged += (_, _) =>
            operationStatus.Text = SelectedTask() is null
                ? string.Empty
                : "Use the Task context menu to load bounded events.";
        remoteViewer.ConnectionHostActionRequested +=
            async (_, eventArgs) =>
                await ExecuteConnectionHostActionAsync(eventArgs);
        remoteViewer.AdvancedLaunchRequested += async (_, eventArgs) =>
            await RequireController().LaunchAdvancedRemoteViewerAsync(
                eventArgs.Resource,
                eventArgs.Target,
                lifetime.Token);
        remoteViewer.DvcRegistrationRequested += async (_, _) =>
            await RequireController().RegisterDvcPluginAsync(
                lifetime.Token);
        KeyDown += async (_, eventArgs) =>
        {
            if (eventArgs.KeyCode == Keys.F5 &&
                     eventArgs.Modifiers == Keys.None &&
                     busyCommands.Count == 0)
            {
                await RequireController().RefreshAsync(false, lifetime.Token);
                eventArgs.Handled = true;
            }
            else if (eventArgs.KeyCode == Keys.D &&
                     eventArgs.Modifiers == Keys.Control &&
                     discover.Enabled)
            {
                await RequireController().DiscoverPoolsAsync(lifetime.Token);
                eventArgs.Handled = true;
            }
            else if (eventArgs.KeyCode == Keys.L &&
                     eventArgs.Modifiers == Keys.Control &&
                     login.Enabled)
            {
                await RequireController().LoginAsync(lifetime.Token);
                eventArgs.Handled = true;
            }
        };
        FormClosing += OnClosing;
    }

    public IntPtr NativeWindowHandle => Handle;

    public void AttachController(StewardDesktopController value)
    {
        controller = value;
    }

    public void Render(DesktopSnapshot value)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => Render(value));
            return;
        }
        if (!DesktopProjection.IsNewer(snapshot, value) &&
            snapshot?.Sequence != value.Sequence)
            return;
        snapshot = value;
        RenderIdentity(value);
        RenderPools(value);
        RenderNodes(value);
        RenderOperations(value.Operations);
        RenderHealth(value);
        connectionStatus.Text = value.ConnectionState switch
        {
            DesktopConnectionState.Connected =>
                $"Control connected — snapshot {value.CapturedAt:HH:mm:ss}",
            DesktopConnectionState.Disconnected =>
                $"Control disconnected — {value.Error?.Code}",
            DesktopConnectionState.Error =>
                $"Control error — {value.Error?.Code}",
            _ => "Connecting to Control…"
        };
        UpdateCommands();
    }

    public void SetCommandBusy(string commandKey, bool busy)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => SetCommandBusy(commandKey, busy));
            return;
        }
        if (busy)
            busyCommands.Add(commandKey);
        else
            busyCommands.Remove(commandKey);
        operationStatus.Text = busyCommands.Count == 0
            ? string.Empty
            : $"Running: {string.Join(", ", busyCommands.Take(2))}";
        UpdateCommands();
    }

    public void ShowError(DesktopError error)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => ShowError(error));
            return;
        }
        operationStatus.Text = $"{error.Code}: {error.Detail}";
        using var dialog = new Form
        {
            Text = $"Steward — {error.Code}",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new(16)
        };
        var layout = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 2
        };
        layout.Controls.Add(new Label
        {
            Text = $"{error.Code}\r\n\r\n{error.Detail}",
            AutoSize = true,
            MaximumSize = new(620, 0)
        });
        var closeButton = new Button
        {
            Text = "Close",
            AutoSize = true,
            DialogResult = DialogResult.OK,
            Anchor = AnchorStyles.Right
        };
        layout.Controls.Add(closeButton);
        dialog.Controls.Add(layout);
        dialog.AcceptButton = closeButton;
        dialog.ShowDialog(this);
    }

    public void ShowProviderInspection(
        NodeViewModel node,
        ProviderResource? resource)
    {
        if (resource is null)
        {
            nodeDetails.Text =
                NodeDetails(node) +
                "\r\n\r\nProvider inspection: resource not found.";
            return;
        }
        var metadata = string.Join(
            "\r\n",
            resource.Metadata
                .OrderBy(value => value.Key, StringComparer.Ordinal)
                .Select(value =>
                    $"{value.Key}: {SafeMetadata(value.Key, value.Value)}"));
        nodeDetails.Text =
            NodeDetails(node) +
            $"\r\n\r\nProvider status: {resource.Status}\r\n" +
            $"Provider resource ID: {resource.ProviderResourceId}\r\n" +
            metadata;
    }

    public void ShowTaskEvents(
        Steward.Domain.TaskId taskId,
        IReadOnlyList<PersistedNodeFact> events)
    {
        eventGrid.Rows.Clear();
        foreach (var value in events.Take(500))
        {
            var row = eventGrid.Rows.Add(
                value.Sequence,
                value.NodeIncarnationId,
                value.Kind,
                value.ProcessedAt.ToLocalTime().ToString("G"));
            eventGrid.Rows[row].Tag = value;
        }
        operationStatus.Text =
            $"{events.Count} bounded event records for Task {taskId}; raw payload is not rendered.";
    }

    public void ShowInformation(string message)
    {
        operationStatus.Text = message;
    }

    public void ShowConnectionHostStartup(
        DevBoxConnectionIdentityStatus identityStatus,
        ConnectionHostCommandResult host)
    {
        connectionIdentity.Text =
            $"devbox/connection: {identityStatus.Outcome}; " +
            $"host {(host.HostAvailable ? "available" : "unavailable")}";
    }

    public void OpenConnectionHost(
        NodeViewModel node,
        DevBoxConnectionIdentityStatus identityStatus,
        ConnectionHostCommandResult host,
        bool connectConfigured)
    {
        tabs.SelectedTab = remoteViewerTab;
        remoteViewer.ShowConnection(
            node,
            identityStatus,
            host,
            connectConfigured);
        ShowConnectionHostStartup(identityStatus, host);
    }

    public void ShowConnectionHostStatus(
        DevBoxConnectionIdentityStatus identityStatus,
        ConnectionHostCommandResult host,
        bool connectConfigured)
    {
        remoteViewer.ShowStatus(
            identityStatus,
            host,
            connectConfigured);
        ShowConnectionHostStartup(identityStatus, host);
        operationStatus.Text =
            $"{host.Code}; ConnectionHost status only.";
    }

    public void ShowAdvancedRemoteViewer(
        DevBoxRemoteViewingResource resource)
    {
        remoteViewer.ShowAdvancedResource(resource);
        operationStatus.Text =
            "Advanced interactive fallback loaded; not transport evidence.";
    }

    public void ShowRemoteViewerLaunch(
        DevBoxRemoteViewerLaunchResult result)
    {
        remoteViewer.ShowLaunchResult(result);
        operationStatus.Text =
            $"{result.Code}; advanced external fallback only.";
    }

    public void ShowRemoteViewerSession(
        DevBoxExternalViewerSessionStatus value)
    {
        remoteViewer.ShowSessionStatus(value);
        operationStatus.Text =
            $"{value.Code}; advanced external broker-window state only.";
    }

    public void ShowDvcRegistrationStatus(
        DvcPluginRegistrationStatus value)
    {
        remoteViewer.ShowDvcRegistrationStatus(value);
        operationStatus.Text =
            $"{value.Code}; activation remains pending live evidence.";
    }

    public void OpenTerminal(
        NodeViewModel node,
        ManagedTerminalController terminal)
    {
        if (snapshot?.TerminalPolicy is not { } policy)
        {
            _ = terminal.DisposeAsync();
            ShowError(new(
                "TerminalPolicyUnavailable",
                "Terminal policy has not been loaded."));
            return;
        }
        using var dialog = new TerminalOpenDialog(node, policy, terminal);
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            _ = terminal.DisposeAsync();
            return;
        }
        _ = OpenTerminalPaneAsync(terminal, dialog.Options);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            lifetime.Cancel();
            lifetime.Dispose();
        }
        base.Dispose(disposing);
    }

    private async Task OpenTerminalPaneAsync(
        ManagedTerminalController terminal,
        TerminalOpenOptions options)
    {
        if (terminalPane is not null)
            await terminalPane.ShutdownAsync();
        shellHost.Controls.Clear();
        terminalPane = new ManagedTerminalPane(terminal);
        shellHost.Controls.Add(terminalPane);
        tabs.SelectedTab = shellTab;
        try
        {
            await terminalPane.OpenAsync(options, lifetime.Token);
        }
        catch (Exception exception) when (Operational(exception))
        {
            ShowError(SafeErrorMapper.Map(exception));
            await terminalPane.ShutdownAsync();
        }
    }

    private void BuildPoolsTab()
    {
        var split = Split(pools, poolDetails);
        poolsTab.Controls.Add(split);
        pools.ContextMenuStrip = new ContextMenuStrip();
        pools.ContextMenuStrip.Opening += (_, _) => BuildPoolMenu();
    }

    private void BuildNodesTab()
    {
        var split = Split(nodes, nodeDetails);
        nodesTab.Controls.Add(split);
        nodes.ContextMenuStrip = new ContextMenuStrip();
        nodes.ContextMenuStrip.Opening += (_, _) => BuildNodeMenu();
    }

    private void BuildOperationsTab()
    {
        var operationTabs = new TabControl { Dock = DockStyle.Fill };
        operationTabs.TabPages.Add(GridTab("Workloads", workloadGrid));
        operationTabs.TabPages.Add(GridTab("Tasks & events", TaskEventsPane()));
        operationTabs.TabPages.Add(GridTab("Artifacts", artifactGrid));
        operationTabs.TabPages.Add(GridTab("Agents", agentGrid));
        operationsTab.Controls.Add(operationTabs);
        taskGrid.ContextMenuStrip = new ContextMenuStrip();
        taskGrid.ContextMenuStrip.Opening += (_, _) =>
        {
            var menu = taskGrid.ContextMenuStrip!;
            menu.Items.Clear();
            var task = SelectedTask();
            menu.Items.Add(new ToolStripMenuItem(
                "Load bounded events",
                null,
                async (_, _) =>
                {
                    if (task is not null)
                        await RequireController().LoadTaskEventsAsync(
                            task.Payload.TaskId,
                            lifetime.Token);
                })
            {
                Enabled = task is not null && busyCommands.Count == 0
            });
        };
        artifactGrid.ContextMenuStrip = new ContextMenuStrip();
        artifactGrid.ContextMenuStrip.Opening += (_, _) =>
        {
            var menu = artifactGrid.ContextMenuStrip!;
            menu.Items.Clear();
            var artifact = SelectedArtifact();
            menu.Items.Add(new ToolStripMenuItem(
                "Download…",
                null,
                async (_, _) => await DownloadSelectedArtifactAsync(artifact))
            {
                Enabled = artifact?.Complete == true &&
                    busyCommands.Count == 0
            });
        };
    }

    private Control TaskEventsPane()
    {
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 260
        };
        split.Panel1.Controls.Add(taskGrid);
        split.Panel2.Controls.Add(eventGrid);
        return split;
    }

    private void BuildPoolMenu()
    {
        var menu = pools.ContextMenuStrip!;
        menu.Items.Clear();
        var pool = SelectedPool();
        if (pool is null || snapshot?.Orchestration is null)
            return;
        AddMenuItem(
            menu,
            "Register / configure…",
            CapabilityGate.Pool(
                pool,
                PoolCommand.Register,
                snapshot.Orchestration,
                snapshot.CanMutate),
            async () =>
            {
                using var dialog = new PoolRegistrationDialog(pool);
                if (dialog.ShowDialog(this) == DialogResult.OK)
                    await RequireController().RegisterPoolAsync(
                        pool,
                        dialog.WarmMinimum,
                        dialog.HardMaximum,
                        dialog.IdleTimeout,
                        dialog.StoppedRetention,
                        lifetime.Token);
            });
        AddMenuItem(
            menu,
            "Reconcile / scale to registered policy",
            CapabilityGate.Pool(
                pool,
                PoolCommand.Reconcile,
                snapshot.Orchestration,
                snapshot.CanMutate),
            () => RequireController().ReconcilePoolAsync(
                pool,
                lifetime.Token));
        AddMenuItem(
            menu,
            "Inspect members",
            CapabilityGate.Pool(
                pool,
                PoolCommand.InspectMembers,
                snapshot.Orchestration,
                snapshot.CanMutate),
            () =>
            {
                InspectPoolMembers();
                return Task.CompletedTask;
            });
    }

    private void BuildNodeMenu()
    {
        var menu = nodes.ContextMenuStrip!;
        menu.Items.Clear();
        var node = SelectedNode();
        if (node is null ||
            snapshot?.Orchestration is null ||
            snapshot.TerminalPolicy is null)
            return;
        AddNodeItem(menu, node, NodeCommand.Inspect, "Inspect provider");
        AddNodeItem(menu, node, NodeCommand.Reconnect, "Reconnect");
        menu.Items.Add(new ToolStripSeparator());
        AddNodeItem(menu, node, NodeCommand.Start, "Start");
        AddNodeItem(menu, node, NodeCommand.Drain, "Drain…");
        AddNodeItem(menu, node, NodeCommand.Stop, "Stop…");
        AddNodeItem(menu, node, NodeCommand.Recreate, "Recreate…");
        AddNodeItem(menu, node, NodeCommand.Delete, "Delete…");
        menu.Items.Add(new ToolStripSeparator());
        AddNodeItem(
            menu,
            node,
            NodeCommand.OpenRemoteViewer,
            "Open ConnectionHost");
        AddNodeItem(menu, node, NodeCommand.OpenShell, "Open managed shell");
    }

    private void AddNodeItem(
        ContextMenuStrip menu,
        NodeViewModel node,
        NodeCommand command,
        string text)
    {
        var availability = CapabilityGate.Node(
            node,
            command,
            snapshot!.Orchestration!,
            snapshot.TerminalPolicy!,
            snapshot.CanMutate);
        AddMenuItem(
            menu,
            text,
            availability,
            async () =>
            {
                if (command == NodeCommand.Inspect)
                {
                    await RequireController().InspectHostAsync(
                        node,
                        lifetime.Token);
                    return;
                }
                if (command == NodeCommand.OpenRemoteViewer)
                {
                    await RequireController().OpenRemoteViewerAsync(
                        node,
                        lifetime.Token);
                    return;
                }
                if (command == NodeCommand.OpenShell)
                {
                    RequireController().OpenTerminal(node);
                    return;
                }
                if (command == NodeCommand.Reconnect)
                    return;
                if (command == NodeCommand.Start)
                {
                    await RequireController().ExecuteHostCommandAsync(
                        node,
                        command,
                        false,
                        lifetime.Token);
                    return;
                }
                var confirmation =
                    DestructiveConfirmationFactory.Create(node, command);
                using var dialog = new DestructiveActionDialog(confirmation);
                if (dialog.ShowDialog(this) == DialogResult.OK)
                    await RequireController().ExecuteHostCommandAsync(
                        node,
                        command,
                        confirmation.ForceRequired,
                        lifetime.Token);
            });
    }

    private void AddMenuItem(
        ContextMenuStrip menu,
        string text,
        CommandAvailability availability,
        Func<Task> action)
    {
        var item = new ToolStripMenuItem(text)
        {
            Enabled = availability.Enabled && busyCommands.Count == 0,
            ToolTipText = busyCommands.Count > 0
                ? "Another Steward command is running."
                : availability.Reason ?? string.Empty
        };
        item.Click += async (_, _) => await action();
        menu.Items.Add(item);
    }

    private Task ExecuteConnectionHostActionAsync(
        ConnectionHostActionEventArgs eventArgs) =>
        eventArgs.Action switch
        {
            ConnectionHostUiAction.Status =>
                RequireController().RefreshConnectionHostAsync(
                    eventArgs.Node,
                    lifetime.Token),
            ConnectionHostUiAction.EnrollIdentity =>
                RequireController().EnrollConnectionIdentityAsync(
                    eventArgs.Node,
                    lifetime.Token),
            ConnectionHostUiAction.LogoutIdentity =>
                RequireController().LogoutConnectionIdentityAsync(
                    eventArgs.Node,
                    lifetime.Token),
            ConnectionHostUiAction.Resolve =>
                RequireController().ResolveConnectionHostAsync(
                    eventArgs.Node,
                    lifetime.Token),
            ConnectionHostUiAction.Prepare =>
                RequireController().PrepareConnectionHostAsync(
                    eventArgs.Node,
                    lifetime.Token),
            ConnectionHostUiAction.Connect =>
                RequireController().ConnectConnectionHostAsync(
                    eventArgs.Node,
                    lifetime.Token),
            ConnectionHostUiAction.View =>
                RequireController().ViewConnectionHostAsync(
                    eventArgs.Node,
                    RequiredGeneration(eventArgs),
                    lifetime.Token),
            ConnectionHostUiAction.TakeControl =>
                RequireController().TakeConnectionHostControlAsync(
                    eventArgs.Node,
                    RequiredGeneration(eventArgs),
                    lifetime.Token),
            ConnectionHostUiAction.ReleaseControl =>
                RequireController().ReleaseConnectionHostControlAsync(
                    eventArgs.Node,
                    RequiredGeneration(eventArgs),
                    lifetime.Token),
            ConnectionHostUiAction.Fullscreen =>
                RequireController().ViewConnectionHostAsync(
                    eventArgs.Node,
                    RequiredGeneration(eventArgs),
                    lifetime.Token),
            ConnectionHostUiAction.Disconnect =>
                RequireController().DisconnectConnectionHostAsync(
                    eventArgs.Node,
                    eventArgs.ConnectionGeneration,
                    lifetime.Token),
            ConnectionHostUiAction.LoadAdvancedFallback =>
                RequireController().LoadAdvancedRemoteViewerAsync(
                    eventArgs.Node,
                    lifetime.Token),
            _ => throw new ArgumentOutOfRangeException(
                nameof(eventArgs),
                eventArgs.Action,
                "The ConnectionHost UI action is unsupported.")
        };

    private static long RequiredGeneration(
        ConnectionHostActionEventArgs eventArgs) =>
        eventArgs.ConnectionGeneration ??
        throw new InvalidOperationException(
            "The ConnectionHost command requires a generation.");

    private void RenderIdentity(DesktopSnapshot value)
    {
        identity.Text = value.Identity.SignedIn
            ? $"devbox/default: {value.Identity.Username} " +
              $"(expires {value.Identity.TokenExpiresOn?.ToLocalTime():t})"
            : $"devbox/default: signed out" +
              (value.Identity.Problem is null
                  ? string.Empty
                  : " — silent status unavailable");
        login.Enabled = !value.Identity.SignedIn &&
            busyCommands.Count == 0;
        logout.Enabled = value.Identity.SignedIn &&
            busyCommands.Count == 0;
        discover.Enabled = value.Identity.SignedIn &&
            busyCommands.Count == 0;
    }

    private void RenderPools(DesktopSnapshot value)
    {
        var selected = SelectedPool()?.Key;
        pools.BeginUpdate();
        pools.Items.Clear();
        foreach (var pool in value.Pools)
        {
            var item = new ListViewItem(pool.DisplayName) { Tag = pool };
            item.SubItems.Add(pool.Health);
            item.SubItems.Add(pool.Location);
            item.SubItems.Add(pool.CurrentCount.ToString());
            item.SubItems.Add(pool.Registered ? "Registered" : "Discovered");
            pools.Items.Add(item);
            if (selected == pool.Key)
                item.Selected = true;
        }
        pools.EndUpdate();
        RenderSelectedPool();
    }

    private void RenderNodes(DesktopSnapshot value)
    {
        var selected = SelectedNode()?.HostId;
        nodes.BeginUpdate();
        nodes.Items.Clear();
        foreach (var node in value.Nodes)
        {
            var item = new ListViewItem(
                $"{node.ProviderResourceName}  ({node.HostId})")
            {
                Tag = node
            };
            item.SubItems.Add(node.LifecycleState.ToString());
            item.SubItems.Add(node.Connected ? "Connected" : "Disconnected");
            item.SubItems.Add(node.AssignedAttemptCount.ToString());
            item.SubItems.Add(node.LastFact);
            nodes.Items.Add(item);
            if (selected == node.HostId)
                item.Selected = true;
        }
        nodes.EndUpdate();
        RenderSelectedNode();
    }

    private void RenderOperations(OperationsSnapshot operations)
    {
        workloadGrid.Rows.Clear();
        foreach (var workload in operations.Workloads.Take(1000))
        {
            var taskValues = operations.Tasks
                .Where(value =>
                    value.Payload.WorkloadId ==
                    workload.Payload.WorkloadId)
                .ToArray();
            var terminal = taskValues.Count(value =>
                value.Payload.ObservedState is
                    Steward.Domain.TaskObservedState.Succeeded or
                    Steward.Domain.TaskObservedState.Failed or
                    Steward.Domain.TaskObservedState.Cancelled);
            var row = workloadGrid.Rows.Add(
                workload.Payload.WorkloadId,
                workload.Payload.WorkloadType,
                workload.Payload.DesiredState,
                workload.Payload.ObservedState,
                $"{terminal}/{taskValues.Length} terminal");
            workloadGrid.Rows[row].Tag = workload;
        }
        taskGrid.Rows.Clear();
        foreach (var task in operations.Tasks.Take(1000))
        {
            var resource = task.Payload.Resources;
            var row = taskGrid.Rows.Add(
                task.Payload.TaskId,
                task.Payload.TaskType,
                task.Payload.DesiredState,
                task.Payload.ObservedState,
                task.Payload.AcceptedGeneration,
                $"{resource.CpuCores} CPU; " +
                $"{resource.MemoryBytes / 1024 / 1024:N0} MiB; " +
                $"{resource.DiskBytes / 1024 / 1024:N0} MiB disk");
            taskGrid.Rows[row].Tag = task;
        }
        artifactGrid.Rows.Clear();
        foreach (var artifact in operations.Artifacts.Take(1000))
        {
            var row = artifactGrid.Rows.Add(
                artifact.PortableObjectId,
                artifact.Kind,
                $"{artifact.SizeBytes:N0} B",
                artifact.Complete,
                artifact.CreatedAt.ToLocalTime().ToString("G"),
                artifact.ContentHash);
            artifactGrid.Rows[row].Tag = artifact;
        }
        agentGrid.Rows.Clear();
        foreach (var agent in operations.Agents.Take(1000))
        {
            var notices = operations.AgentNotifications
                .Where(value => value.AgentId == agent.AgentId)
                .ToArray();
            var row = agentGrid.Rows.Add(
                agent.AgentId,
                $"{agent.RuntimeName}/{agent.RuntimeVersion}",
                agent.Revision,
                agent.NotificationCursor,
                notices.Length,
                string.Join(
                    ", ",
                    notices.Select(value => value.Kind)
                        .Distinct(StringComparer.Ordinal)
                        .Take(5)),
                agent.PlacementGeneration,
                agent.Frozen);
            agentGrid.Rows[row].Tag = agent;
        }
    }

    private void RenderHealth(DesktopSnapshot value)
    {
        var unavailable = value.Orchestration?.UnavailableCapabilities.Count > 0
            ? string.Join(
                "\r\n",
                value.Orchestration.UnavailableCapabilities
                    .Select(capability => $"  • {capability}"))
            : "  none";
        healthDetails.Text =
            $"Control state: {value.ConnectionState}\r\n" +
            $"Healthy: {value.Doctor?.Healthy}\r\n" +
            $"Schema: {value.Doctor?.SchemaVersion}\r\n" +
            $"Journal mode: {value.Doctor?.JournalMode}\r\n" +
            $"Foreign keys: {value.Doctor?.ForeignKeys}\r\n" +
            $"Integrity: {value.Doctor?.Integrity}\r\n\r\n" +
            $"Transport enabled: {value.Orchestration?.TransportEnabled}\r\n" +
            $"Configured Nodes: {value.Orchestration?.ConfiguredNodes}\r\n" +
            $"Durable scheduler/rates/Pool: " +
            $"{value.Orchestration?.DurableSchedulerReady}/" +
            $"{value.Orchestration?.DurableRatesReady}/" +
            $"{value.Orchestration?.DurablePoolReady}\r\n" +
            $"Provider lifecycle: {value.Orchestration?.ProviderLifecycleEnabled}\r\n" +
            $"Portable downloads: {value.Orchestration?.PortableStateConfiguredOnControl}\r\n" +
            $"Agent execution adapter: {value.Orchestration?.AgentExecutionAdapterEnabled}\r\n" +
            $"Terminal policy enabled: {value.TerminalPolicy?.Enabled}\r\n" +
            $"Mutation authorization present: {value.CanMutate}\r\n\r\n" +
            $"Unavailable capabilities:\r\n{unavailable}";
    }

    private void RenderSelectedPool()
    {
        poolDetails.Text = SelectedPool() is { } pool
            ? PoolDetails(pool)
            : "Select a Pool. Right-click for capability-gated actions.";
    }

    private void RenderSelectedNode()
    {
        nodeDetails.Text = SelectedNode() is { } node
            ? NodeDetails(node)
            : "Select a Node/member. Right-click for capability-gated actions.";
    }

    private static string PoolDetails(PoolViewModel pool) =>
        $"Project: {pool.Key.Project}\r\n" +
        $"Pool: {pool.Key.Pool}\r\n" +
        $"Dev Center endpoint: {(pool.Key.Endpoint.Length == 0 ? "not discovered" : pool.Key.Endpoint)}\r\n" +
        $"Description: {pool.Description ?? "Not reported"}\r\n" +
        $"Permission eligible: {pool.PermissionEligible}\r\n" +
        $"Remote connection permission: {pool.CanReadRemoteConnections}\r\n" +
        $"Health: {pool.Health}\r\n" +
        $"Location: {pool.Location}\r\n" +
        $"Capacity: {pool.Cpu?.ToString() ?? "?"} CPU; " +
        $"{pool.RamGb?.ToString() ?? "?"} GiB RAM; " +
        $"{pool.DiskGb?.ToString() ?? "?"} GiB disk\r\n" +
        $"Image: {(pool.Image.Length == 0 ? "Not reported" : pool.Image)}\r\n" +
        $"Provider stop policy: {pool.StopPolicy}\r\n" +
        $"Current discovered members: {pool.CurrentCount}\r\n\r\n" +
        $"Steward registration: {(pool.Registered ? pool.PoolId : "not registered")}\r\n" +
        $"Warm minimum: {pool.WarmMinimum?.ToString() ?? "n/a"}\r\n" +
        $"Hard maximum: {pool.HardMaximum?.ToString() ?? "n/a"}\r\n" +
        $"Idle timeout: {pool.IdleTimeout?.ToString() ?? "n/a"}\r\n" +
        $"Stopped retention: {pool.StoppedRetention?.ToString() ?? "n/a"}";

    private static string NodeDetails(NodeViewModel node) =>
        $"HostId: {node.HostId}\r\n" +
        $"Node incarnation: {node.NodeIncarnationId}\r\n" +
        $"PoolId: {node.PoolId}\r\n" +
        $"Provider resource: {node.ProviderResourceName}\r\n" +
        $"Lifecycle: {node.LifecycleState}\r\n" +
        $"Connection: {(node.Connected ? "connected" : "disconnected")}\r\n" +
        $"Transport: {node.Transport}\r\n" +
        $"Capacity: {node.Capacity.CpuCores} CPU; " +
        $"{node.Capacity.MemoryBytes / 1024 / 1024:N0} MiB RAM; " +
        $"{node.Capacity.DiskBytes / 1024 / 1024:N0} MiB disk; " +
        $"{node.Capacity.ConcurrencyUnits} concurrency\r\n" +
        $"Capabilities: {string.Join(", ", node.Capabilities)}\r\n" +
        $"Assigned active attempts ({node.AssignedAttemptCount}): " +
        $"{(node.AssignedAttemptCount == 0 ? "none" : string.Join(", ", node.AssignedAttempts))}" +
        $"{(node.AssignedAttemptsTruncated ? " … list truncated" : string.Empty)}\r\n" +
        $"Control-visible incomplete portable objects: {node.IncompletePortableObjects}\r\n" +
        $"Control-visible checkpoints: {node.CheckpointObjects}\r\n" +
        $"Node-local spool: not reported by the current transport contract\r\n" +
        $"Last contiguous fact cursor: {node.LastFactCursor}\r\n" +
        $"Last fact: {node.LastFact} at " +
        $"{node.LastFactAt?.ToLocalTime().ToString("G") ?? "n/a"}";

    private async Task DownloadSelectedArtifactAsync(
        ArtifactOperationsView? artifact)
    {
        if (artifact is null)
            return;
        using var dialog = new SaveFileDialog
        {
            Title = $"Download Steward artifact {artifact.PortableObjectId}",
            FileName = artifact.PortableObjectId.ToString(),
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        await RequireController().DownloadArtifactAsync(
            artifact.PortableObjectId,
            dialog.FileName,
            lifetime.Token);
    }

    private void InspectPoolMembers()
    {
        if (SelectedPool()?.PoolId is not { } poolId)
            return;
        tabs.SelectedTab = nodesTab;
        foreach (ListViewItem item in nodes.Items)
            if (item.Tag is NodeViewModel node &&
                node.PoolId == poolId)
            {
                item.Selected = true;
                item.Focused = true;
                item.EnsureVisible();
                break;
            }
    }

    private void UpdateCommands()
    {
        refresh.Enabled = busyCommands.Count == 0;
        if (snapshot is not null)
            RenderIdentity(snapshot);
    }

    private async void OnClosing(object? sender, FormClosingEventArgs eventArgs)
    {
        if (closingReady)
            return;
        eventArgs.Cancel = true;
        lifetime.Cancel();
        if (terminalPane is not null)
            await terminalPane.ShutdownAsync();
        controller?.Dispose();
        closingReady = true;
        Close();
    }

    private StewardDesktopController RequireController() =>
        controller ?? throw new InvalidOperationException(
            "Steward Desktop controller is not attached.");

    private PoolViewModel? SelectedPool() =>
        pools.SelectedItems.Count == 1
            ? pools.SelectedItems[0].Tag as PoolViewModel
            : null;

    private NodeViewModel? SelectedNode() =>
        nodes.SelectedItems.Count == 1
            ? nodes.SelectedItems[0].Tag as NodeViewModel
            : null;

    private Steward.Contracts.ContractEnvelope<Steward.Contracts.TaskDto>?
        SelectedTask() =>
        taskGrid.SelectedRows.Count == 1
            ? taskGrid.SelectedRows[0].Tag as
                Steward.Contracts.ContractEnvelope<Steward.Contracts.TaskDto>
            : null;

    private ArtifactOperationsView? SelectedArtifact() =>
        artifactGrid.SelectedRows.Count == 1
            ? artifactGrid.SelectedRows[0].Tag as ArtifactOperationsView
            : null;

    private static SplitContainer Split(Control left, Control right)
    {
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            SplitterDistance = 620,
            FixedPanel = FixedPanel.None
        };
        split.Panel1.Controls.Add(left);
        split.Panel2.Controls.Add(right);
        return split;
    }

    private static TabPage GridTab(string title, Control content)
    {
        var tab = new TabPage(title);
        tab.Controls.Add(content);
        return tab;
    }

    private static ListView ListView(
        params (string Text, int Width)[] columns)
    {
        var value = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            HideSelection = false,
            MultiSelect = false,
            GridLines = true
        };
        foreach (var column in columns)
            value.Columns.Add(column.Text, column.Width);
        return value;
    }

    private static DataGridView Grid(
        string accessibleName,
        params (string Text, int Width)[] columns)
    {
        var value = new DataGridView
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToOrderColumns = true,
            AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
            RowHeadersVisible = false,
            AccessibleName = accessibleName
        };
        foreach (var column in columns)
            value.Columns.Add(new DataGridViewTextBoxColumn
            {
                HeaderText = column.Text,
                Width = column.Width,
                SortMode = DataGridViewColumnSortMode.Automatic
            });
        return value;
    }

    private static TextBox DetailsText(string accessibleName) =>
        new()
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = new("Segoe UI", 9),
            AccessibleName = accessibleName
        };

    private static string SafeMetadata(string key, string value)
    {
        var sensitive = new[]
        {
            "token",
            "secret",
            "credential",
            "opaque",
            "signed",
            "connectionurl",
            "connectionuri"
        };
        return sensitive.Any(fragment =>
            key.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            ? "[withheld]"
            : value;
    }

    private static bool Operational(Exception exception) =>
        exception is
            Steward.Cli.ControlApiException or
            Steward.Terminal.Abstractions.TerminalException or
            HttpRequestException or
            InvalidDataException or
            InvalidOperationException;
}
