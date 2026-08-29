using Steward.DevBox.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.Desktop.Windows;

internal enum ConnectionHostUiAction
{
    Status,
    EnrollIdentity,
    LogoutIdentity,
    Resolve,
    Prepare,
    Connect,
    View,
    TakeControl,
    ReleaseControl,
    Fullscreen,
    Disconnect,
    LoadAdvancedFallback
}

internal sealed class ConnectionHostActionEventArgs(
    NodeViewModel node,
    ConnectionHostUiAction action,
    long? connectionGeneration = null) : EventArgs
{
    public NodeViewModel Node { get; } = node;
    public ConnectionHostUiAction Action { get; } = action;
    public long? ConnectionGeneration { get; } = connectionGeneration;
}

internal sealed class RemoteViewerLaunchEventArgs(
    DevBoxRemoteViewingResource resource,
    DevBoxRemoteViewerTarget target) : EventArgs
{
    public DevBoxRemoteViewingResource Resource { get; } = resource;
    public DevBoxRemoteViewerTarget Target { get; } = target;
}

internal sealed class RemoteViewerPane : UserControl
{
    private readonly Label heading = new()
    {
        Text = "No ConnectionHost connection selected",
        AutoSize = true,
        Font = new(
            "Segoe UI",
            10,
            System.Drawing.FontStyle.Bold)
    };
    private readonly Label identityState = new()
    {
        Text = "Connection identity: not checked",
        AutoSize = true,
        Padding = new(0, 4, 0, 4)
    };
    private readonly TextBox details = new()
    {
        ReadOnly = true,
        Multiline = true,
        ScrollBars = ScrollBars.Vertical,
        Dock = DockStyle.Fill,
        BorderStyle = BorderStyle.FixedSingle,
        BackColor = SystemColors.Window,
        AccessibleName = "ConnectionHost status, generation, and evidence"
    };
    private readonly Label commandReasons = new()
    {
        AutoSize = true,
        MaximumSize = new(1100, 0),
        Padding = new(0, 4, 0, 8)
    };
    private readonly Button status = Button("Refresh Status");
    private readonly Button enroll = Button("Enroll connection identity");
    private readonly Button logout = Button("Sign out connection identity");
    private readonly Button resolve = Button("Resolve");
    private readonly Button prepare = Button("Prepare");
    private readonly Button connect = Button("Connect");
    private readonly Button view = Button("View");
    private readonly Button takeControl = Button("Take Control");
    private readonly Button releaseControl = Button("Release Control");
    private readonly Button fullscreen = Button("Fullscreen");
    private readonly Button disconnect = Button("Disconnect");
    private readonly GroupBox fallbackGroup = new()
    {
        Text = "Advanced Interactive Fallback — not transport evidence",
        Dock = DockStyle.Bottom,
        AutoSize = true,
        Padding = new(12)
    };
    private readonly Button loadFallback =
        Button("Load advanced fallback resource");
    private readonly Button windowsApp =
        Button("Launch external Windows App fallback…");
    private readonly Button web =
        Button("Launch external browser fallback…");
    private readonly Button registerDvc =
        Button("Register DVC plugin");
    private readonly Label fallbackState = new()
    {
        AutoSize = true,
        MaximumSize = new(1100, 0),
        Text =
            "External fallback is isolated from ConnectionHost state. " +
            "It never proves transport, generation, DVC, View, Control, or fullscreen capability."
    };

    private NodeViewModel? node;
    private DevBoxConnectionIdentityStatus? connectionIdentity;
    private ConnectionHostCommandResult host =
        ConnectionHostCommandResult.Unavailable(
            "CONNECTION_HOST_STATUS_NOT_CHECKED");
    private ConnectionHostPresentation? presentation;
    private DevBoxRemoteViewingResource? fallbackResource;
    private bool connectConfigured;

    public RemoteViewerPane()
    {
        Dock = DockStyle.Fill;
        Padding = new(24);

        var primaryActions = new FlowLayoutPanel
        {
            AutoSize = true,
            Dock = DockStyle.Top,
            Padding = new(0, 8, 0, 8)
        };
        primaryActions.Controls.AddRange(
        [
            status,
            enroll,
            logout,
            resolve,
            prepare,
            connect,
            view,
            takeControl,
            releaseControl,
            fullscreen,
            disconnect
        ]);

        var fallbackActions = new FlowLayoutPanel
        {
            AutoSize = true,
            Dock = DockStyle.Top,
            Padding = new(0, 8, 0, 8)
        };
        fallbackActions.Controls.AddRange(
        [
            loadFallback,
            windowsApp,
            web,
            registerDvc
        ]);
        fallbackGroup.Controls.Add(fallbackState);
        fallbackGroup.Controls.Add(fallbackActions);
        fallbackState.Dock = DockStyle.Top;
        fallbackActions.BringToFront();

        Controls.Add(details);
        Controls.Add(commandReasons);
        Controls.Add(primaryActions);
        Controls.Add(identityState);
        Controls.Add(heading);
        Controls.Add(fallbackGroup);
        heading.Dock = DockStyle.Top;
        identityState.Dock = DockStyle.Top;
        primaryActions.BringToFront();
        commandReasons.Dock = DockStyle.Top;
        commandReasons.BringToFront();
        fallbackGroup.BringToFront();

        status.Click += (_, _) => Request(ConnectionHostUiAction.Status);
        enroll.Click += (_, _) =>
            Request(ConnectionHostUiAction.EnrollIdentity);
        logout.Click += (_, _) =>
            Request(ConnectionHostUiAction.LogoutIdentity);
        resolve.Click += (_, _) => Request(ConnectionHostUiAction.Resolve);
        prepare.Click += (_, _) => Request(ConnectionHostUiAction.Prepare);
        connect.Click += (_, _) => Request(ConnectionHostUiAction.Connect);
        view.Click += (_, _) =>
            Request(ConnectionHostUiAction.View, RequireGeneration());
        takeControl.Click += (_, _) =>
            Request(ConnectionHostUiAction.TakeControl, RequireGeneration());
        releaseControl.Click += (_, _) =>
            Request(ConnectionHostUiAction.ReleaseControl, RequireGeneration());
        fullscreen.Click += (_, _) =>
            Request(ConnectionHostUiAction.Fullscreen, RequireGeneration());
        disconnect.Click += (_, _) =>
            Request(
                ConnectionHostUiAction.Disconnect,
                host.Status?.ConnectionGeneration);
        loadFallback.Click += (_, _) =>
            Request(ConnectionHostUiAction.LoadAdvancedFallback);
        windowsApp.Click += (_, _) =>
            RequestFallbackLaunch(DevBoxRemoteViewerTarget.WindowsApp);
        web.Click += (_, _) =>
            RequestFallbackLaunch(DevBoxRemoteViewerTarget.WebBrowser);
        registerDvc.Click += (_, _) =>
            DvcRegistrationRequested?.Invoke(this, EventArgs.Empty);
        UpdateCommands();
    }

    public event EventHandler<ConnectionHostActionEventArgs>?
        ConnectionHostActionRequested;
    public event EventHandler<RemoteViewerLaunchEventArgs>?
        AdvancedLaunchRequested;
    public event EventHandler? DvcRegistrationRequested;

    public void ShowConnection(
        NodeViewModel value,
        DevBoxConnectionIdentityStatus identity,
        ConnectionHostCommandResult result,
        bool isConnectConfigured)
    {
        node = value;
        fallbackResource = null;
        fallbackState.Text =
            "External fallback is isolated from ConnectionHost state. " +
            "It never proves transport, generation, DVC, View, Control, or fullscreen capability.";
        heading.Text =
            $"ConnectionHost — {value.ProviderResourceName}";
        ShowStatus(identity, result, isConnectConfigured);
    }

    public void ShowStatus(
        DevBoxConnectionIdentityStatus identity,
        ConnectionHostCommandResult result,
        bool isConnectConfigured)
    {
        connectionIdentity = identity;
        host = result;
        connectConfigured = isConnectConfigured;
        presentation = ConnectionHostPresentation.Create(
            result,
            identity,
            connectConfigured);
        identityState.Text =
            $"Connection identity: {identity.Outcome}" +
            (identity.Username is { Length: > 0 } username
                ? $" — {username}"
                : string.Empty) +
            (identity.Problem is { Length: > 0 } problem
                ? $" — {problem}"
                : string.Empty);
        details.Text =
            presentation.StatusText +
            "\r\n\r\nOrdered DVC readiness\r\n" +
            string.Join(
                "\r\n",
                presentation.Readiness
                    .OrderBy(value => value.Order)
                    .Select(value =>
                        $"{value.Order}. [{value.State}] {value.Name}: {value.Evidence}"));
        UpdateCommands();
    }

    public void ShowAdvancedResource(
        DevBoxRemoteViewingResource resource)
    {
        fallbackResource = resource;
        fallbackState.Text =
            $"Advanced fallback loaded: {resource.EvidenceCode}. " +
            "No URI is displayed. External launch remains optional, requires confirmation, " +
            "and is never ConnectionHost transport evidence.";
        UpdateCommands();
    }

    public void ShowLaunchResult(
        DevBoxRemoteViewerLaunchResult result)
    {
        fallbackState.Text =
            $"Advanced fallback result: {result.Code} at " +
            $"{result.RequestedAtUtc.ToLocalTime():G}. " +
            "This external broker result did not alter ConnectionHost state, generation, or evidence.";
    }

    public void ShowSessionStatus(
        DevBoxExternalViewerSessionStatus value)
    {
        fallbackState.Text =
            $"Advanced fallback broker state: {value.State}; {value.Code}. " +
            "This is external-window state only and is not transport evidence.";
    }

    public void ShowDvcRegistrationStatus(
        DvcPluginRegistrationStatus value)
    {
        fallbackState.Text =
            $"DVC registration: {value.Code}. Registration alone is not " +
            "ConnectionHost activation or authenticated session evidence.";
        registerDvc.Enabled = !value.Registered;
    }

    private void Request(
        ConnectionHostUiAction action,
        long? generation = null)
    {
        if (node is null)
            return;
        ConnectionHostActionRequested?.Invoke(
            this,
            new(node, action, generation));
    }

    private void RequestFallbackLaunch(
        DevBoxRemoteViewerTarget target)
    {
        if (fallbackResource is null)
            return;
        var targetName = target == DevBoxRemoteViewerTarget.WindowsApp
            ? "Windows App"
            : "the default browser";
        var confirmation = MessageBox.Show(
            this,
            $"Launch {targetName} as an external interactive fallback?\r\n\r\n" +
            "This may expose a separately interactive remote viewer. It is not " +
            "ConnectionHost transport evidence and cannot enable Steward View, " +
            "Take Control, fullscreen, generation, or DVC readiness.",
            "Confirm advanced interactive fallback",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);
        if (confirmation != DialogResult.Yes)
            return;
        AdvancedLaunchRequested?.Invoke(
            this,
            new(fallbackResource, target));
    }

    private long RequireGeneration() =>
        host.Status?.ConnectionGeneration ??
        throw new InvalidOperationException(
            "ConnectionHost has not assigned a connection generation.");

    private void UpdateCommands()
    {
        status.Enabled = node is not null;
        enroll.Enabled =
            node is not null &&
            connectionIdentity?.Outcome !=
                DevBoxConnectionIdentityOutcome.Ready;
        logout.Enabled =
            node is not null &&
            connectionIdentity?.Enrolled == true;
        Apply(resolve, presentation?.Resolve);
        Apply(prepare, presentation?.Prepare);
        Apply(connect, presentation?.Connect);
        Apply(view, presentation?.View);
        Apply(takeControl, presentation?.TakeControl);
        Apply(releaseControl, presentation?.ReleaseControl);
        Apply(fullscreen, presentation?.Fullscreen);
        Apply(disconnect, presentation?.Disconnect);
        loadFallback.Enabled = node?.DevBox is not null;
        windowsApp.Enabled =
            fallbackResource?.WindowsAppAvailable == true;
        web.Enabled =
            fallbackResource?.WebBrowserAvailable == true;
        registerDvc.Enabled =
            fallbackResource is not null &&
            !fallbackResource.DvcPluginRegistered;

        var reasons = new[]
        {
            Reason("Resolve", presentation?.Resolve),
            Reason("Prepare", presentation?.Prepare),
            Reason("Connect", presentation?.Connect),
            Reason("View", presentation?.View),
            Reason("Take Control", presentation?.TakeControl),
            Reason("Fullscreen", presentation?.Fullscreen)
        }.Where(value => value is not null);
        commandReasons.Text = string.Join("\r\n", reasons!);
    }

    private static string? Reason(
        string command,
        CommandAvailability? availability) =>
        availability is { Enabled: false, Reason: { Length: > 0 } reason }
            ? $"{command} disabled: {reason}"
            : null;

    private static void Apply(
        Button button,
        CommandAvailability? availability)
    {
        button.Enabled = availability?.Enabled == true;
        button.AccessibleDescription =
            availability?.Enabled == true
                ? "Command is available for the current ConnectionHost status."
                : availability?.Reason ?? "No ConnectionHost connection is selected.";
    }

    private static Button Button(string text) =>
        new()
        {
            Text = text,
            AutoSize = true,
            AccessibleName = text
        };
}
