using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace Steward.Rdp.Windows;

public sealed record RdpSessionTimeouts(
    TimeSpan Connection,
    TimeSpan Login,
    TimeSpan GatewayObservation)
{
    public static RdpSessionTimeouts Default { get; } =
        new(TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2), TimeSpan.FromSeconds(10));
}

public sealed record GatewayUseObservation(
    bool Observed,
    string? RemoteEndpoint);

public interface IGatewayUseProbe
{
    Task<GatewayUseObservation> ObserveAsync(
        string gatewayHostname,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

[SupportedOSPlatform("windows")]
public sealed class MstscActiveXSession
{
    private readonly IGatewayUseProbe _gatewayProbe;

    public MstscActiveXSession(IGatewayUseProbe? gatewayProbe = null)
    {
        _gatewayProbe = gatewayProbe ?? new ProcessGatewayUseProbe();
    }

    public Task<RdpSessionResult> ConnectAsync(
        RdpConnectionProfile profile,
        RdpSessionTimeouts? timeouts = null,
        Action<RdpDiagnosticEvent>? eventObserver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var completion = new TaskCompletionSource<RdpSessionResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                using var host = new RdpHostForm(
                    profile,
                    timeouts ?? RdpSessionTimeouts.Default,
                    _gatewayProbe,
                    completion,
                    eventObserver,
                    cancellationToken);
                Application.Run(host);
            }
            catch (Exception exception)
            {
                completion.TrySetException(exception);
            }
        })
        {
            IsBackground = true,
            Name = "Steward mstscax acceptance gate"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task;
    }
}

[SupportedOSPlatform("windows")]
internal sealed class RdpHostForm : Form
{
    private readonly RdpConnectionProfile _profile;
    private readonly RdpSessionTimeouts _timeouts;
    private readonly IGatewayUseProbe _gatewayProbe;
    private readonly TaskCompletionSource<RdpSessionResult> _completion;
    private readonly Action<RdpDiagnosticEvent>? _eventObserver;
    private readonly CancellationToken _cancellationToken;
    private readonly List<RdpDiagnosticEvent> _events = [];
    private readonly System.Windows.Forms.Timer _phaseTimer = new();
    private CancellationTokenRegistration _cancellationRegistration;
    private MstscActiveXControl? _control;
    private bool _connected;
    private bool _loginComplete;
    private int? _disconnectReason;
    private int? _extendedDisconnectReason;
    private int? _fatalErrorCode;
    private int? _logonErrorCode;
    private bool _finishing;

    public RdpHostForm(
        RdpConnectionProfile profile,
        RdpSessionTimeouts timeouts,
        IGatewayUseProbe gatewayProbe,
        TaskCompletionSource<RdpSessionResult> completion,
        Action<RdpDiagnosticEvent>? eventObserver,
        CancellationToken cancellationToken)
    {
        _profile = profile;
        _timeouts = timeouts;
        _gatewayProbe = gatewayProbe;
        _completion = completion;
        _eventObserver = eventObserver;
        _cancellationToken = cancellationToken;

        Text = "Steward RDP acceptance gate";
        ShowInTaskbar = false;
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        Location = new(-32000, -32000);
        ClientSize = new(1, 1);
        WindowState = FormWindowState.Minimized;
    }

    protected override void OnLoad(EventArgs eventArgs)
    {
        base.OnLoad(eventArgs);
        try
        {
            _control = new MstscActiveXControl
            {
                Dock = DockStyle.Fill,
                Width = 1,
                Height = 1
            };
            Controls.Add(_control);
            _control.CreateControl();
            _control.Connected += OnConnected;
            _control.LoginComplete += OnLoginComplete;
            _control.Disconnected += OnDisconnected;
            _control.FatalError += OnFatalError;
            _control.LogonError += OnLogonError;
            RdpActiveXConfigurator.Apply(_profile, _control.Configuration);
            Record("ConfigurationApplied");
            _phaseTimer.Tick += OnPhaseTimeout;
            StartTimer(_timeouts.Connection);
            _cancellationRegistration = _cancellationToken.Register(
                () =>
                {
                    if (!IsDisposed && IsHandleCreated)
                        BeginInvoke(() => Finish(RdpFailureKind.Cancelled, false, null));
                });
            _control.Connect();
        }
        catch (Exception exception)
        {
            _completion.TrySetException(
                new InvalidOperationException(
                    "mstscax initialization or configuration failed.",
                    exception));
            Close();
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _phaseTimer.Dispose();
            _cancellationRegistration.Dispose();
            if (_control is not null)
            {
                try
                {
                    _control.Disconnect();
                }
                catch (COMException)
                {
                }
                _control.Dispose();
            }
        }
        base.Dispose(disposing);
    }

    private void OnConnected()
    {
        _connected = true;
        Record("OnConnected");
        StartTimer(_timeouts.Login);
    }

    private async void OnLoginComplete()
    {
        _loginComplete = true;
        Record("OnLoginComplete");
        _phaseTimer.Stop();
        try
        {
            var observation = await _gatewayProbe.ObserveAsync(
                _profile.GatewayHostname,
                _timeouts.GatewayObservation,
                _cancellationToken);
            Finish(
                observation.Observed
                    ? RdpFailureKind.None
                    : RdpFailureKind.GatewayNotObserved,
                observation.Observed,
                observation.RemoteEndpoint);
        }
        catch (OperationCanceledException) when (_cancellationToken.IsCancellationRequested)
        {
            Finish(RdpFailureKind.Cancelled, false, null);
        }
        catch (Exception exception)
        {
            Record("GatewayProbeError", exception.HResult);
            Finish(RdpFailureKind.GatewayNotObserved, false, null);
        }
    }

    private void OnDisconnected(int disconnectReason)
    {
        _disconnectReason = disconnectReason;
        _extendedDisconnectReason = _control?.ExtendedDisconnectReason;
        Record("OnDisconnected", disconnectReason, _extendedDisconnectReason);
        if (!_loginComplete)
            Finish(RdpFailureKind.Disconnected, false, null);
    }

    private void OnFatalError(int errorCode)
    {
        _fatalErrorCode = errorCode;
        Record("OnFatalError", errorCode);
        Finish(RdpFailureKind.Fatal, false, null);
    }

    private void OnLogonError(int errorCode)
    {
        _logonErrorCode = errorCode;
        Record("OnLogonError", errorCode);
    }

    private void OnPhaseTimeout(object? sender, EventArgs eventArgs)
    {
        Finish(
            _connected
                ? RdpFailureKind.LoginTimeout
                : RdpFailureKind.ConnectionTimeout,
            false,
            null);
    }

    private void StartTimer(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue)
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                "RDP timeout must be positive and fit a WinForms timer.");
        _phaseTimer.Stop();
        _phaseTimer.Interval = checked((int)timeout.TotalMilliseconds);
        _phaseTimer.Start();
    }

    private void Finish(
        RdpFailureKind failureKind,
        bool gatewayObserved,
        string? gatewayRemoteEndpoint)
    {
        if (_finishing)
            return;
        _finishing = true;
        _phaseTimer.Stop();
        var classified = failureKind == RdpFailureKind.None
            ? RdpFailureClassifier.Classify(
                _connected,
                _loginComplete,
                gatewayObserved,
                _disconnectReason,
                _fatalErrorCode,
                false)
            : failureKind;
        _completion.TrySetResult(
            new(
                classified == RdpFailureKind.None,
                classified,
                _disconnectReason,
                _extendedDisconnectReason,
                _fatalErrorCode,
                _logonErrorCode,
                gatewayObserved,
                gatewayRemoteEndpoint,
                _events.ToArray()));
        Close();
    }

    private void Record(string name, int? code = null, int? extendedCode = null)
    {
        var diagnostic = new RdpDiagnosticEvent(
            name,
            DateTimeOffset.UtcNow,
            code,
            extendedCode);
        _events.Add(diagnostic);
        _eventObserver?.Invoke(diagnostic);
    }
}

[SupportedOSPlatform("windows")]
internal sealed class MstscActiveXControl : AxHost
{
    private const string ClientClassId = "1DF7C823-B2D4-4B54-975A-F2AC5D7CF8B8";
    private IConnectionPoint? _connectionPoint;
    private int _connectionCookie;
    private IMsRdpClient10? _client;
    private MstscEventSink? _sink;

    public MstscActiveXControl()
        : base(ClientClassId)
    {
    }

    public event Action? Connected;
    public event Action? LoginComplete;
    public event Action<int>? Disconnected;
    public event Action<int>? FatalError;
    public event Action<int>? LogonError;

    public IRdpActiveXConfigurationTarget Configuration { get; private set; } =
        null!;

    public int? ExtendedDisconnectReason
    {
        get
        {
            try
            {
                return _client?.ExtendedDisconnectReason;
            }
            catch (COMException)
            {
                return null;
            }
        }
    }

    public void Connect() =>
        (_client ?? throw new InvalidOperationException("mstscax is not initialized."))
        .Connect();

    public void Disconnect()
    {
        _client?.Disconnect();
    }

    protected override void AttachInterfaces()
    {
        var ocx = GetOcx() ??
            throw new InvalidOperationException("mstscax did not create its COM control.");
        var client = ocx as IMsRdpClient10 ??
            throw new NotSupportedException(
                "The installed mstscax control does not expose IMsRdpClient10.");
        var extended = ocx as IMsRdpExtendedSettings ??
            throw new NotSupportedException(
                "The installed mstscax control does not expose IMsRdpExtendedSettings.");
        _client = client;
        Configuration = new MstscConfigurationTarget(
            client,
            client.AdvancedSettings8,
            client.TransportSettings4,
            extended);
    }

    protected override void CreateSink()
    {
        var container = GetOcx() as IConnectionPointContainer ??
            throw new NotSupportedException(
                "The installed mstscax control has no event connection point container.");
        var eventId = typeof(IMsTscAxEventsSink).GUID;
        container.FindConnectionPoint(ref eventId, out var connectionPoint);
        _connectionPoint = connectionPoint ??
            throw new NotSupportedException(
                "The installed mstscax control has no IMsTscAxEvents connection point.");
        _sink = new MstscEventSink(this);
        _connectionPoint.Advise(_sink, out _connectionCookie);
    }

    protected override void DetachSink()
    {
        if (_connectionPoint is not null && _connectionCookie != 0)
        {
            _connectionPoint.Unadvise(_connectionCookie);
            _connectionCookie = 0;
        }
        _connectionPoint = null;
        _sink = null;
    }

    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    private sealed class MstscEventSink(MstscActiveXControl owner)
        : IMsTscAxEventsSink
    {
        public void OnConnected() => owner.Connected?.Invoke();
        public void OnLoginComplete() => owner.LoginComplete?.Invoke();
        public void OnDisconnected(int disconnectReason) =>
            owner.Disconnected?.Invoke(disconnectReason);
        public void OnFatalError(int errorCode) =>
            owner.FatalError?.Invoke(errorCode);
        public void OnLogonError(int errorCode) =>
            owner.LogonError?.Invoke(errorCode);
    }
}

internal sealed class MstscConfigurationTarget(
    IMsRdpClient10 client,
    IMsRdpClientAdvancedSettings8 advanced,
    IMsRdpClientTransportSettings4 transport,
    IMsRdpExtendedSettings extended)
    : IRdpActiveXConfigurationTarget
{
    public string Server { set => client.Server = value; }
    public string GatewayHostname { set => transport.GatewayHostname = value; }
    public uint GatewayUsageMethod { set => transport.GatewayUsageMethod = value; }
    public uint GatewayProfileUsageMethod { set => transport.GatewayProfileUsageMethod = value; }
    public uint GatewayCredentialsSource { set => transport.GatewayCredsSource = value; }
    public uint GatewayBrokeringType { set => transport.GatewayBrokeringType = value; }
    public bool GatewayCredentialSharing { set => transport.GatewayCredSharing = value; }
    public bool DisableCredentialsDelegation { set => SetExtendedBoolean("DisableCredentialsDelegation", value); }
    public string LoadBalanceInfo { set => advanced.LoadBalanceInfo = value; }
    public bool EnableRdsAadAuth { set => SetExtendedBoolean("EnableRdsAadAuth", value); }
    public bool EnableCredSspSupport { set => advanced.EnableCredSspSupport = value; }
    public bool EnableAutoReconnect { set => advanced.EnableAutoReconnect = value; }
    public int MaximumReconnectAttempts { set => advanced.MaxReconnectAttempts = value; }
    public bool RedirectClipboard { set => advanced.RedirectClipboard = value; }
    public bool RedirectDrives { set => advanced.RedirectDrives = value; }
    public bool RedirectPrinters { set => advanced.RedirectPrinters = value; }
    public bool RedirectPorts { set => advanced.RedirectPorts = value; }
    public bool RedirectSmartCards { set => advanced.RedirectSmartCards = value; }
    public bool RedirectDevices { set => advanced.RedirectDevices = value; }
    public bool RedirectPointOfServiceDevices { set => advanced.RedirectPOSDevices = value; }
    public bool RedirectDirectX { set => advanced.RedirectDirectX = value; }
    public uint AudioRedirectionMode { set => advanced.AudioRedirectionMode = value; }
    public bool AudioCaptureRedirection { set => advanced.AudioCaptureRedirectionMode = value; }
    public uint VideoPlaybackMode { set => advanced.VideoPlaybackMode = value; }
    public uint PerformanceFlags { set => advanced.PerformanceFlags = checked((int)value); }

    private void SetExtendedBoolean(string name, bool enabled)
    {
        object value = enabled;
        extended.put_Property(name, ref value);
    }
}
