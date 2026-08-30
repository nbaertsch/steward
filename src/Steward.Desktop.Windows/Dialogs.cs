using Steward.Application;
using Steward.Terminal.Abstractions;

namespace Steward.Desktop.Windows;

internal sealed class PoolRegistrationDialog : Form
{
    private readonly NumericUpDown warm = Number(1, 0, 10);
    private readonly NumericUpDown maximum = Number(10, 1, 10);
    private readonly NumericUpDown idleMinutes = Number(90, 1, 10_080);
    private readonly NumericUpDown retentionDays = Number(7, 0, 365);
    private readonly Button register = new()
    {
        Text = "Register Pool",
        AutoSize = true,
        DialogResult = DialogResult.OK
    };

    public PoolRegistrationDialog(PoolViewModel pool)
    {
        Text = $"Register {pool.DisplayName}";
        AccessibleName = Text;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new(16);

        var layout = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 2,
            RowCount = 7,
            Dock = DockStyle.Fill
        };
        layout.ColumnStyles.Add(new(SizeType.AutoSize));
        layout.ColumnStyles.Add(new(SizeType.Absolute, 260));
        AddRow(layout, 0, "Project / Pool", new Label
        {
            Text = $"{pool.Key.Project} / {pool.Key.Pool}",
            AutoSize = true
        });
        AddRow(layout, 1, "Warm minimum", warm);
        AddRow(layout, 2, "Hard maximum", maximum);
        AddRow(layout, 3, "Idle timeout (minutes)", idleMinutes);
        AddRow(layout, 4, "Stopped retention (days)", retentionDays);
        layout.Controls.Add(new Label
        {
            Text =
                "Registration uses the existing Dev Center project and Pool. " +
                "It does not create or administer provider infrastructure.",
            AutoSize = true,
            MaximumSize = new(520, 0),
            Padding = new(0, 8, 0, 8)
        }, 0, 5);
        layout.SetColumnSpan(layout.GetControlFromPosition(0, 5)!, 2);
        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill
        };
        buttons.Controls.Add(register);
        buttons.Controls.Add(new Button
        {
            Text = "Cancel",
            AutoSize = true,
            DialogResult = DialogResult.Cancel
        });
        layout.Controls.Add(buttons, 0, 6);
        layout.SetColumnSpan(buttons, 2);
        Controls.Add(layout);
        AcceptButton = register;
        CancelButton = buttons.Controls.OfType<Button>()
            .Single(button => button.DialogResult == DialogResult.Cancel);
        warm.ValueChanged += (_, _) => ValidateValues();
        maximum.ValueChanged += (_, _) => ValidateValues();
        ValidateValues();
    }

    public int WarmMinimum => Decimal.ToInt32(warm.Value);
    public int HardMaximum => Decimal.ToInt32(maximum.Value);
    public TimeSpan IdleTimeout => TimeSpan.FromMinutes(
        Decimal.ToDouble(idleMinutes.Value));
    public TimeSpan StoppedRetention => TimeSpan.FromDays(
        Decimal.ToDouble(retentionDays.Value));

    private void ValidateValues()
    {
        register.Enabled = warm.Value <= maximum.Value;
        register.AccessibleDescription = register.Enabled
            ? "Registers this Pool with the displayed Steward policy."
            : "Warm minimum cannot exceed hard maximum.";
    }

    private static NumericUpDown Number(
        decimal value,
        decimal minimum,
        decimal maximum) =>
        new()
        {
            Value = value,
            Minimum = minimum,
            Maximum = maximum,
            Width = 120,
            ThousandsSeparator = true
        };

    private static void AddRow(
        TableLayoutPanel layout,
        int row,
        string label,
        Control value)
    {
        layout.Controls.Add(new Label
        {
            Text = label,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Padding = new(0, 5, 10, 5)
        }, 0, row);
        value.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        layout.Controls.Add(value, 1, row);
    }
}

internal sealed class DestructiveActionDialog : Form
{
    private readonly TextBox confirmation = new()
    {
        Width = 420,
        AccessibleName = "Exact Host confirmation"
    };
    private readonly Button execute;

    public DestructiveActionDialog(DestructiveConfirmation value)
    {
        Text = $"{value.Command} exact Host";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new(16);
        execute = new()
        {
            Text = value.ForceRequired
                ? $"Force {value.Command}"
                : value.Command.ToString(),
            AutoSize = true,
            Enabled = false,
            DialogResult = DialogResult.OK
        };
        var layout = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 4
        };
        layout.Controls.Add(new Label
        {
            Text = value.Message,
            AutoSize = true,
            MaximumSize = new(640, 0)
        }, 0, 0);
        layout.Controls.Add(confirmation, 0, 1);
        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            Padding = new(0, 12, 0, 0)
        };
        buttons.Controls.Add(execute);
        buttons.Controls.Add(new Button
        {
            Text = "Cancel",
            AutoSize = true,
            DialogResult = DialogResult.Cancel
        });
        layout.Controls.Add(buttons, 0, 2);
        Controls.Add(layout);
        confirmation.TextChanged += (_, _) =>
            execute.Enabled = DestructiveConfirmationFactory.Matches(
                value,
                confirmation.Text);
        AcceptButton = execute;
        CancelButton = buttons.Controls.OfType<Button>()
            .Single(button => button.DialogResult == DialogResult.Cancel);
    }
}

internal sealed class TerminalOpenDialog : Form
{
    private readonly ComboBox workspace = new()
    {
        DropDownStyle = ComboBoxStyle.DropDown,
        Width = 460
    };
    private readonly NumericUpDown leaseMinutes = new()
    {
        Minimum = 1,
        Maximum = 480,
        Value = 30,
        Width = 100
    };
    private readonly ComboBox shell = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        Width = 220
    };
    private readonly CheckBox elevated = new()
    {
        Text = "Request elevated Node service execution",
        AutoSize = true
    };
    private readonly Button open = new()
    {
        Text = "Open Managed Terminal",
        AutoSize = true,
        DialogResult = DialogResult.OK
    };
    private readonly Label validation = new()
    {
        AutoSize = true,
        ForeColor = System.Drawing.Color.Firebrick
    };
    private readonly ManagedTerminalController terminal;

    public TerminalOpenDialog(
        NodeViewModel node,
        TerminalPolicyStatus policy,
        ManagedTerminalController terminal)
    {
        this.terminal = terminal;
        Text = $"Managed terminal — {node.ProviderResourceName}";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new(16);
        workspace.Items.AddRange(policy.AllowedWorkspaceRoots.Cast<object>().ToArray());
        if (workspace.Items.Count > 0)
            workspace.SelectedIndex = 0;
        shell.Items.AddRange(Enum.GetValues<TerminalShellKind>()
            .Cast<object>()
            .ToArray());
        shell.SelectedItem = TerminalShellKind.PowerShell;
        leaseMinutes.Maximum = Math.Max(
            1,
            Math.Min(480, (decimal)policy.MaximumDuration.TotalMinutes));
        leaseMinutes.Value = Math.Min(30, leaseMinutes.Maximum);
        elevated.Enabled = policy.ElevatedHosts.Contains(node.HostId) &&
            node.Capabilities.Contains(
                "terminal.elevated-service",
                StringComparer.Ordinal);
        elevated.AccessibleDescription = elevated.Enabled
            ? "Elevation still requires explicit authorization by Control and Node policy."
            : "Elevation is not authorized for this Host.";

        var layout = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 2,
            RowCount = 7
        };
        AddRow(layout, 0, "Workspace", workspace);
        AddRow(layout, 1, "Lease (minutes)", leaseMinutes);
        AddRow(layout, 2, "Shell", shell);
        layout.Controls.Add(elevated, 0, 3);
        layout.SetColumnSpan(elevated, 2);
        layout.Controls.Add(new Label
        {
            Text =
                "Input is sent only through Steward terminal authority. " +
                "The UI does not retain entered commands; transcript policy is metadata-only.",
            AutoSize = true,
            MaximumSize = new(600, 0),
            Padding = new(0, 8, 0, 4)
        }, 0, 4);
        layout.SetColumnSpan(layout.GetControlFromPosition(0, 4)!, 2);
        layout.Controls.Add(validation, 0, 5);
        layout.SetColumnSpan(validation, 2);
        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft
        };
        buttons.Controls.Add(open);
        buttons.Controls.Add(new Button
        {
            Text = "Cancel",
            AutoSize = true,
            DialogResult = DialogResult.Cancel
        });
        layout.Controls.Add(buttons, 0, 6);
        layout.SetColumnSpan(buttons, 2);
        Controls.Add(layout);
        AcceptButton = open;
        CancelButton = buttons.Controls.OfType<Button>()
            .Single(button => button.DialogResult == DialogResult.Cancel);
        workspace.TextChanged += (_, _) => ValidateOptions();
        leaseMinutes.ValueChanged += (_, _) => ValidateOptions();
        shell.SelectedIndexChanged += (_, _) => ValidateOptions();
        elevated.CheckedChanged += (_, _) => ValidateOptions();
        ValidateOptions();
    }

    public TerminalOpenOptions Options => new(
        workspace.Text,
        TimeSpan.FromMinutes(Decimal.ToDouble(leaseMinutes.Value)),
        (TerminalShellKind)shell.SelectedItem!,
        elevated.Checked,
        120,
        30);

    private void ValidateOptions()
    {
        if (shell.SelectedItem is null)
        {
            open.Enabled = false;
            validation.Text = "Select a shell.";
            return;
        }
        var result = terminal.Evaluate(Options);
        open.Enabled = result.Enabled;
        validation.Text = result.Enabled
            ? string.Empty
            : $"{result.Code}: {result.Detail}";
    }

    private static void AddRow(
        TableLayoutPanel layout,
        int row,
        string label,
        Control control)
    {
        layout.Controls.Add(new Label
        {
            Text = label,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Padding = new(0, 6, 12, 6)
        }, 0, row);
        control.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        layout.Controls.Add(control, 1, row);
    }
}
