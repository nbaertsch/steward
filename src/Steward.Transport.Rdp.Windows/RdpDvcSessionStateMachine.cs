namespace Steward.Transport.Rdp.Windows;

public enum RdpDvcSessionState
{
    Absent,
    Resolving,
    ConnectingHeadless,
    ConnectedTransport,
    Viewing,
    Controlled,
    Reconnecting,
    Disconnected,
    Failed
}

public sealed record RdpDvcSessionSnapshot(
    RdpDvcSessionState State,
    long? ConnectionGeneration,
    bool DvcConnected,
    bool VisibleSurfaceAuthorized,
    string Code)
{
    public override string ToString() =>
        $"RdpDvcSessionSnapshot {{ State = {State} }}";
}

public sealed class RdpDvcSessionTransitionException(
    string code,
    string message) : InvalidOperationException(message)
{
    public string Code { get; } = code;
}

public sealed class RdpHeadlessViolationException(
    string code,
    string message) : InvalidOperationException(message)
{
    public string Code { get; } = code;
}

public sealed class RdpDvcSessionStateMachine
{
    private readonly object sync = new();
    private RdpDvcSessionState _state =
        RdpDvcSessionState.Absent;
    private long? _connectionGeneration;
    private bool _dvcConnected;
    private bool _visibleSurfaceAuthorized;
    private string _code = "RDP_DVC_ABSENT";

    public RdpDvcSessionSnapshot Snapshot
    {
        get
        {
            lock (sync)
                return SnapshotCore();
        }
    }

    public RdpDvcSessionSnapshot BeginResolving()
    {
        lock (sync)
        {
            if (_state is not
                (RdpDvcSessionState.Absent or
                 RdpDvcSessionState.Disconnected or
                 RdpDvcSessionState.Failed))
                throw InvalidTransition();
            _connectionGeneration = null;
            _dvcConnected = false;
            _visibleSurfaceAuthorized = false;
            return Transition(
                RdpDvcSessionState.Resolving,
                "RDP_DVC_RESOLVING");
        }
    }

    public RdpDvcSessionSnapshot BeginConnectingHeadless()
    {
        lock (sync)
        {
            RequireState(RdpDvcSessionState.Resolving);
            return Transition(
                RdpDvcSessionState.ConnectingHeadless,
                "RDP_DVC_CONNECTING_HEADLESS");
        }
    }

    public RdpDvcSessionSnapshot ConfirmConnectedTransport(
        RdCoreDvcConfigurationResult verifiedEvidence)
    {
        lock (sync)
        {
            ArgumentNullException.ThrowIfNull(verifiedEvidence);
            if (_state is not
                (RdpDvcSessionState.ConnectingHeadless or
                 RdpDvcSessionState.Reconnecting))
                throw InvalidTransition();
            if (!verifiedEvidence.Accepted ||
                !string.Equals(
                    verifiedEvidence.Code,
                    RdCoreDvcContract.EvidenceVerifiedCode,
                    StringComparison.Ordinal) ||
                verifiedEvidence.ConnectionGeneration is not { } generation)
                throw new RdpDvcSessionTransitionException(
                    "RDP_DVC_VERIFIED_EVIDENCE_REQUIRED",
                    "Connected transport requires verified RDCore/DVC evidence.");
            if (_connectionGeneration is { } previous &&
                generation <= previous)
                throw new RdpDvcSessionTransitionException(
                    "RDP_DVC_CONNECTION_GENERATION_NOT_ADVANCED",
                    "A reconnected transport requires a newer connection generation.");
            _connectionGeneration = generation;
            _dvcConnected = true;
            _visibleSurfaceAuthorized = false;
            return Transition(
                RdpDvcSessionState.ConnectedTransport,
                "RDP_DVC_CONNECTED_TRANSPORT");
        }
    }

    public RdpDvcSessionSnapshot View(
        long connectionGeneration)
    {
        lock (sync)
        {
            RequireState(RdpDvcSessionState.ConnectedTransport);
            RequireCurrentGeneration(connectionGeneration);
            _visibleSurfaceAuthorized = true;
            return Transition(
                RdpDvcSessionState.Viewing,
                "RDP_DVC_VIEWING");
        }
    }

    public RdpDvcSessionSnapshot TakeControl(
        long connectionGeneration)
    {
        lock (sync)
        {
            if (_state is not (
                    RdpDvcSessionState.ConnectedTransport or
                    RdpDvcSessionState.Viewing))
                throw InvalidTransition();
            RequireCurrentGeneration(connectionGeneration);
            _visibleSurfaceAuthorized = true;
            return Transition(
                RdpDvcSessionState.Controlled,
                "RDP_DVC_CONTROLLED");
        }
    }

    public RdpDvcSessionSnapshot ReleaseControl(
        long connectionGeneration)
    {
        lock (sync)
        {
            RequireState(RdpDvcSessionState.Controlled);
            RequireCurrentGeneration(connectionGeneration);
            _visibleSurfaceAuthorized = false;
            return Transition(
                RdpDvcSessionState.ConnectedTransport,
                "RDP_DVC_CONTROL_RELEASED_TRANSPORT_PRESERVED");
        }
    }

    public RdpDvcSessionSnapshot CloseVisibleSurface(
        long connectionGeneration)
    {
        lock (sync)
        {
            if (_state is not
                (RdpDvcSessionState.Viewing or
                 RdpDvcSessionState.Controlled))
                throw InvalidTransition();
            RequireCurrentGeneration(connectionGeneration);
            _visibleSurfaceAuthorized = false;
            return Transition(
                RdpDvcSessionState.ConnectedTransport,
                "RDP_DVC_UI_CLOSED_TRANSPORT_PRESERVED");
        }
    }

    public RdpDvcSessionSnapshot ObserveVisibleSurface(
        long connectionGeneration)
    {
        lock (sync)
        {
            if (!_visibleSurfaceAuthorized ||
                _state is not
                    (RdpDvcSessionState.Viewing or
                     RdpDvcSessionState.Controlled) ||
                !_connectionGeneration.HasValue ||
                connectionGeneration != _connectionGeneration.Value)
            {
                _state = RdpDvcSessionState.Failed;
                _dvcConnected = false;
                _visibleSurfaceAuthorized = false;
                _code = "RDP_DVC_FATAL_UNEXPECTED_VISIBLE_SURFACE";
                throw new RdpHeadlessViolationException(
                    _code,
                    "A visible RDP surface appeared without an explicit View transition.");
            }
            return SnapshotCore();
        }
    }

    public RdpDvcSessionSnapshot BeginReconnecting(
        long connectionGeneration)
    {
        lock (sync)
        {
            if (_state is not
                (RdpDvcSessionState.ConnectedTransport or
                 RdpDvcSessionState.Viewing or
                 RdpDvcSessionState.Controlled))
                throw InvalidTransition();
            RequireCurrentGeneration(connectionGeneration);
            _dvcConnected = false;
            _visibleSurfaceAuthorized = false;
            return Transition(
                RdpDvcSessionState.Reconnecting,
                "RDP_DVC_RECONNECTING");
        }
    }

    public RdpDvcSessionSnapshot Disconnect()
    {
        lock (sync)
        {
            if (_state is
                (RdpDvcSessionState.Absent or
                 RdpDvcSessionState.Disconnected or
                 RdpDvcSessionState.Failed))
                throw InvalidTransition();
            _dvcConnected = false;
            _visibleSurfaceAuthorized = false;
            return Transition(
                RdpDvcSessionState.Disconnected,
                "RDP_DVC_DISCONNECTED");
        }
    }

    public RdpDvcSessionSnapshot Fail(string code)
    {
        lock (sync)
        {
            ArgumentException.ThrowIfNullOrEmpty(code);
            if (_state is
                (RdpDvcSessionState.Disconnected or
                 RdpDvcSessionState.Failed))
                throw InvalidTransition();
            _dvcConnected = false;
            _visibleSurfaceAuthorized = false;
            return Transition(
                RdpDvcSessionState.Failed,
                code);
        }
    }

    private void RequireCurrentGeneration(long generation)
    {
        if (!_connectionGeneration.HasValue ||
            generation != _connectionGeneration.Value)
            throw new RdpDvcSessionTransitionException(
                "RDP_DVC_CONNECTION_GENERATION_MISMATCH",
                "The operation does not belong to the current connection generation.");
    }

    private void RequireState(RdpDvcSessionState expected)
    {
        if (_state != expected)
            throw InvalidTransition();
    }

    private RdpDvcSessionTransitionException InvalidTransition() =>
        new(
            "RDP_DVC_INVALID_STATE_TRANSITION",
            $"The requested transition is invalid from {_state}.");

    private RdpDvcSessionSnapshot Transition(
        RdpDvcSessionState state,
        string code)
    {
        _state = state;
        _code = code;
        return SnapshotCore();
    }

    private RdpDvcSessionSnapshot SnapshotCore() =>
        new(
            _state,
            _connectionGeneration,
            _dvcConnected,
            _visibleSurfaceAuthorized,
            _code);
}
