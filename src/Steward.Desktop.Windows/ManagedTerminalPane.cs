namespace Steward.Desktop.Windows;

internal sealed class ManagedTerminalPane : UserControl, IManagedTerminalView
{
    private const int MaximumRenderedCharacters = 1_000_000;
    private readonly ManagedTerminalController controller;
    private readonly ToolStripLabel status = new("Opening managed terminal…");
    private readonly ToolStripLabel provenance = new("Output provenance: pending");
    private readonly ToolStripButton close = new("Close and Revoke");
    private readonly RichTextBox output = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        BackColor = System.Drawing.Color.FromArgb(20, 20, 20),
        ForeColor = System.Drawing.Color.Gainsboro,
        Font = new("Consolas", 10),
        DetectUrls = false,
        WordWrap = false,
        AccessibleName = "Managed remote terminal output"
    };
    private readonly TextBox input = new()
    {
        Dock = DockStyle.Bottom,
        AccessibleName = "Managed remote terminal input",
        PlaceholderText = "Enter a command and press Enter; input is not retained by the UI"
    };
    private readonly System.Windows.Forms.Timer poll = new() { Interval = 750 };
    private readonly System.Windows.Forms.Timer resize = new() { Interval = 300 };
    private readonly CancellationTokenSource lifetime = new();
    private bool polling;
    private bool closing;

    public ManagedTerminalPane(ManagedTerminalController controller)
    {
        this.controller = controller;
        Dock = DockStyle.Fill;
        var toolbar = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden };
        toolbar.Items.AddRange(
        [
            close,
            new ToolStripSeparator(),
            status,
            new ToolStripSeparator(),
            provenance
        ]);
        toolbar.Dock = DockStyle.Top;
        Controls.Add(output);
        Controls.Add(input);
        Controls.Add(toolbar);
        toolbar.BringToFront();
        close.Click += async (_, _) => await CloseAsync();
        input.KeyDown += async (_, eventArgs) =>
        {
            if (eventArgs.KeyCode != Keys.Enter ||
                eventArgs.Modifiers != Keys.None)
                return;
            eventArgs.SuppressKeyPress = true;
            var line = input.Text;
            input.Clear();
            if (line.Length == 0)
                return;
            try
            {
                await controller.SendLineAsync(line, lifetime.Token);
            }
            catch (Exception exception) when (Operational(exception))
            {
                ShowError(SafeErrorMapper.Map(exception));
            }
        };
        poll.Tick += async (_, _) => await PollAsync();
        resize.Tick += async (_, _) =>
        {
            resize.Stop();
            await ResizeTerminalAsync();
        };
        output.SizeChanged += (_, _) =>
        {
            resize.Stop();
            resize.Start();
        };
    }

    public async Task OpenAsync(
        TerminalOpenOptions options,
        CancellationToken cancellationToken)
    {
        await controller.OpenAsync(options, this, cancellationToken);
        poll.Start();
        input.Focus();
    }

    public async Task ShutdownAsync()
    {
        if (closing)
            return;
        closing = true;
        poll.Stop();
        resize.Stop();
        lifetime.Cancel();
        try
        {
            await controller.DisposeAsync();
        }
        finally
        {
            status.Text = "Managed terminal closed";
            input.Enabled = false;
            close.Enabled = false;
        }
    }

    public void SetState(TerminalSessionViewState state)
    {
        status.Text =
            $"{state.Snapshot.State}; Host {state.Authority.HostId}; " +
            $"lease {state.Authority.ExpiresAt:HH:mm:ss}; " +
            $"elevated={state.Authority.ElevationGranted}; " +
            $"bytes in/out={state.Snapshot.InputBytes}/{state.Snapshot.OutputBytes}";
        close.Enabled = !state.Closing;
        input.Enabled = !state.Closing;
    }

    public void AppendOutput(string text, string outputProvenance)
    {
        provenance.Text = $"Output provenance: {outputProvenance}";
        output.AppendText(text);
        if (output.TextLength > MaximumRenderedCharacters)
        {
            var remove = output.TextLength - MaximumRenderedCharacters;
            output.Select(0, remove);
            output.SelectedText = string.Empty;
        }
        output.SelectionStart = output.TextLength;
        output.ScrollToCaret();
    }

    public void ShowError(DesktopError error)
    {
        AppendOutput(
            $"\r\n[Steward {error.Code}: {error.Detail}]\r\n",
            "Steward");
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            poll.Dispose();
            resize.Dispose();
            lifetime.Dispose();
        }
        base.Dispose(disposing);
    }

    private async Task PollAsync()
    {
        if (polling || closing)
            return;
        polling = true;
        try
        {
            await controller.PollOutputAsync(lifetime.Token);
        }
        catch (OperationCanceledException)
            when (lifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (Operational(exception))
        {
            ShowError(SafeErrorMapper.Map(exception));
            poll.Stop();
        }
        finally
        {
            polling = false;
        }
    }

    private async Task ResizeTerminalAsync()
    {
        if (closing)
            return;
        var columns = Math.Clamp(
            output.ClientSize.Width / Math.Max(1, TextRenderer.MeasureText("M", output.Font).Width),
            20,
            500);
        var rows = Math.Clamp(
            output.ClientSize.Height / Math.Max(1, output.Font.Height),
            5,
            300);
        try
        {
            await controller.ResizeAsync(columns, rows, lifetime.Token);
        }
        catch (OperationCanceledException)
            when (lifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (Operational(exception))
        {
            ShowError(SafeErrorMapper.Map(exception));
        }
    }

    private async Task CloseAsync()
    {
        if (closing)
            return;
        closing = true;
        poll.Stop();
        resize.Stop();
        try
        {
            await controller.CloseAsync(CancellationToken.None);
            await controller.DisposeAsync();
        }
        catch (Exception exception) when (Operational(exception))
        {
            ShowError(SafeErrorMapper.Map(exception));
        }
        finally
        {
            status.Text = "Managed terminal closed";
            input.Enabled = false;
            close.Enabled = false;
        }
    }

    private static bool Operational(Exception exception) =>
        exception is
            Steward.Cli.ControlApiException or
            Steward.Terminal.Abstractions.TerminalException or
            HttpRequestException or
            InvalidDataException or
            InvalidOperationException;
}
