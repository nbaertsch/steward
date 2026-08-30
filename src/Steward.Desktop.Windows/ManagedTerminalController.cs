using System.Text;
using System.Text.RegularExpressions;
using Steward.Application;
using Steward.Cli;
using Steward.Terminal.Abstractions;

namespace Steward.Desktop.Windows;

public interface IManagedTerminalView
{
    void SetState(TerminalSessionViewState state);
    void AppendOutput(string text, string provenance);
    void ShowError(DesktopError error);
}

public sealed record TerminalOpenOptions(
    string WorkspaceRoot,
    TimeSpan Duration,
    TerminalShellKind ShellKind,
    bool ElevationRequested,
    int Columns,
    int Rows);

public sealed partial class ManagedTerminalController : IAsyncDisposable
{
    private readonly IStewardControlClient control;
    private readonly NodeViewModel node;
    private readonly TerminalPolicyStatus policy;
    private readonly SemaphoreSlim operationGate = new(1, 1);
    private TerminalSessionViewState? state;
    private IManagedTerminalView? view;
    private bool disposed;

    public ManagedTerminalController(
        IStewardControlClient control,
        NodeViewModel node,
        TerminalPolicyStatus policy)
    {
        this.control = control;
        this.node = node;
        this.policy = policy;
    }

    public TerminalGateResult Evaluate(TerminalOpenOptions options) =>
        TerminalGate.Evaluate(
            policy,
            node,
            options.WorkspaceRoot,
            options.Duration,
            options.ElevationRequested);

    public async Task OpenAsync(
        TerminalOpenOptions options,
        IManagedTerminalView terminalView,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var allowed = Evaluate(options);
        if (!allowed.Enabled)
            throw new InvalidOperationException(
                $"{allowed.Code}: {allowed.Detail}");
        view = terminalView;
        var authority = await control.IssueTerminalAuthorityAsync(
            new(
                node.HostId,
                node.NodeIncarnationId,
                policy.Actor,
                options.WorkspaceRoot,
                null,
                options.Duration,
                TerminalTranscriptMode.Metadata,
                options.ElevationRequested,
                Math.Min(policy.MaximumInputBytes, 4L * 1024 * 1024),
                Math.Min(policy.MaximumOutputBytes, 16L * 1024 * 1024)),
            cancellationToken);
        var executable = ShellExecutable(options.ShellKind);
        var response = await control.OpenTerminalAsync(
            new(
                TerminalContractLimits.SchemaVersion,
                RequestId("open"),
                authority,
                options.ShellKind,
                executable,
                ShellArguments(options.ShellKind),
                options.WorkspaceRoot,
                options.Columns,
                options.Rows),
            cancellationToken);
        var snapshot = response.Snapshot
            ?? throw new InvalidDataException(
                "Managed terminal open returned no session snapshot.");
        state = new(
            authority,
            snapshot,
            0,
            0,
            options.Columns,
            options.Rows,
            false);
        terminalView.SetState(state);
        terminalView.AppendOutput(
            $"Managed terminal {authority.SessionId} opened on Host {node.HostId}; " +
            $"identity={snapshot.ExecutionIdentity}; lease expires {authority.ExpiresAt:O}; " +
            $"elevated={authority.ElevationGranted}; transcript=metadata.\r\n",
            "Steward");
    }

    public async Task SendLineAsync(
        string line,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(line))
            return;
        var bytes = Encoding.UTF8.GetBytes(line + "\r\n");
        await operationGate.WaitAsync(cancellationToken);
        try
        {
            var current = RequireOpen();
            var response = await control.SendTerminalInputAsync(
                current.Authority.SessionId,
                new(
                    current.Authority.SessionId,
                    Context(current.Authority),
                    RequestId("input"),
                    current.Snapshot.Revision,
                    bytes),
                cancellationToken);
            var snapshot = response.Snapshot
                ?? throw new InvalidDataException(
                    "Managed terminal input returned no session snapshot.");
            state = current with { Snapshot = snapshot };
            view?.SetState(state);
        }
        finally
        {
            Array.Clear(bytes);
            operationGate.Release();
        }
    }

    public async Task PollOutputAsync(
        CancellationToken cancellationToken = default)
    {
        if (state is null || state.Closing)
            return;
        await operationGate.WaitAsync(cancellationToken);
        try
        {
            var current = RequireOpen();
            var response = await control.ReadTerminalOutputAsync(
                current.Authority.SessionId,
                new(
                    current.Authority.SessionId,
                    Context(current.Authority),
                    current.OutputSequence,
                    current.OutputOffset,
                    128,
                    256 * 1024,
                    false),
                cancellationToken);
            var sequence = current.OutputSequence;
            var offset = current.OutputOffset;
            foreach (var output in response.Output)
            {
                sequence = output.Sequence;
                offset = checked(output.Offset + output.Length);
                if (output.GapBefore)
                    view?.AppendOutput(
                        "\r\n[Steward: bounded output gap]\r\n",
                        "Steward");
                if (output.ContentAvailability ==
                    TerminalOutputContentAvailability.Available &&
                    !output.Data.IsEmpty)
                    view?.AppendOutput(
                        SanitizeTerminalText(
                            Encoding.UTF8.GetString(output.Data.Span)),
                        output.Historical ? "Node retained output" : "Node live output");
                else if (output.Length > 0)
                    view?.AppendOutput(
                        $"\r\n[Steward: {output.Length} output bytes " +
                        $"{output.ContentAvailability}]\r\n",
                        "Steward");
            }
            state = current with
            {
                OutputSequence = sequence,
                OutputOffset = offset
            };
            view?.SetState(state);
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async Task ResizeAsync(
        int columns,
        int rows,
        CancellationToken cancellationToken = default)
    {
        TerminalContractLimits.ValidateSize(columns, rows);
        await operationGate.WaitAsync(cancellationToken);
        try
        {
            var current = RequireOpen();
            if (current.Columns == columns && current.Rows == rows)
                return;
            var response = await control.ResizeTerminalAsync(
                current.Authority.SessionId,
                new(
                    current.Authority.SessionId,
                    Context(current.Authority),
                    RequestId("resize"),
                    current.Snapshot.Revision,
                    columns,
                    rows),
                cancellationToken);
            var snapshot = response.Snapshot
                ?? throw new InvalidDataException(
                    "Managed terminal resize returned no session snapshot.");
            state = current with
            {
                Snapshot = snapshot,
                Columns = columns,
                Rows = rows
            };
            view?.SetState(state);
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async Task CloseAsync(
        CancellationToken cancellationToken = default)
    {
        await operationGate.WaitAsync(cancellationToken);
        try
        {
            if (state is null || state.Closing)
                return;
            var current = state;
            state = current with { Closing = true };
            view?.SetState(state);
            var response = await control.CloseTerminalAsync(
                current.Authority.SessionId,
                new(
                    current.Authority.SessionId,
                    Context(current.Authority),
                    RequestId("close"),
                    current.Snapshot.Revision,
                    TimeSpan.FromSeconds(3)),
                cancellationToken);
            if (response.Snapshot is not null)
                state = current with
                {
                    Snapshot = response.Snapshot,
                    Closing = true
                };
            await control.RevokeTerminalAsync(
                current.Authority.SessionId,
                cancellationToken);
            view?.SetState(state);
        }
        finally
        {
            operationGate.Release();
        }
    }

    private TerminalSessionViewState RequireOpen() =>
        state is { Closing: false } current
            ? current
            : throw new InvalidOperationException(
                "The managed terminal is not open.");

    private static TerminalOperationContext Context(
        TerminalAuthority authority) =>
        new(
            authority.HostId,
            authority.NodeIncarnationId,
            authority.Actor,
            authority.RevocationRevision);

    private static string RequestId(string operation) =>
        $"desktop-{operation}-{Guid.NewGuid():N}";

    private static string ShellExecutable(TerminalShellKind shell) =>
        shell switch
        {
            TerminalShellKind.PowerShell =>
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TerminalShellKind.Pwsh =>
                @"C:\Program Files\PowerShell\7\pwsh.exe",
            TerminalShellKind.CommandPrompt =>
                @"C:\Windows\System32\cmd.exe",
            _ => throw new ArgumentOutOfRangeException(nameof(shell))
        };

    private static IReadOnlyList<string> ShellArguments(
        TerminalShellKind shell) =>
        shell switch
        {
            TerminalShellKind.PowerShell or TerminalShellKind.Pwsh =>
                ["-NoLogo"],
            TerminalShellKind.CommandPrompt => ["/Q"],
            _ => throw new ArgumentOutOfRangeException(nameof(shell))
        };

    private static string SanitizeTerminalText(string value)
    {
        var withoutAnsi = AnsiEscape().Replace(value, string.Empty);
        return new string(withoutAnsi
            .Where(character =>
                character is '\r' or '\n' or '\t' ||
                !char.IsControl(character))
            .ToArray());
    }

    [GeneratedRegex(@"\x1B(?:[@-_][0-?]*[ -/]*[@-~]|\[[0-?]*[ -/]*[@-~])")]
    private static partial Regex AnsiEscape();

    public async ValueTask DisposeAsync()
    {
        if (disposed)
            return;
        if (state is { Closing: false })
        {
            try
            {
                await CloseAsync();
            }
            catch (Exception exception)
                when (exception is
                    ControlApiException or
                    HttpRequestException or
                    InvalidDataException)
            {
                view?.ShowError(SafeErrorMapper.Map(exception));
            }
        }
        disposed = true;
        operationGate.Dispose();
        GC.SuppressFinalize(this);
    }
}
