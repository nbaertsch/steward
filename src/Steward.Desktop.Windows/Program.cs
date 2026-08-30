using Steward.Cli;

namespace Steward.Desktop.Windows;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        System.Windows.Forms.Application.SetUnhandledExceptionMode(
            UnhandledExceptionMode.CatchException);
        System.Windows.Forms.Application.ThreadException += (_, eventArgs) =>
        {
            System.Diagnostics.Trace.TraceError(
                "Unhandled Steward Desktop UI failure: {0}",
                eventArgs.Exception.GetType().Name);
            MessageBox.Show(
                "DesktopUnexpectedError\r\n\r\n" +
                "The UI operation failed. Inspect local structured diagnostics.",
                "Steward",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        };

        var options = DesktopOptions.Parse(args);
        using var http = new HttpClient
        {
            BaseAddress = options.ControlUri,
            Timeout = TimeSpan.FromSeconds(60)
        };
        using var form = new MainForm();
        var raw = new ControlClient(http);
        using var controller = new StewardDesktopController(
            new StewardControlClient(raw),
            new DevBoxDesktopGateway(),
            new ConnectionHostPipeGateway(
                options.ConnectionHostPipeName,
                options.ConnectionAuthorizationToken,
                options.DvcEvidenceReference),
            new ConnectionIdentityService(),
            form);
        form.AttachController(controller);
        form.Shown += async (_, _) =>
        {
            await controller.InitializeConnectionHostAsync();
            await controller.RefreshAsync(
                options.DiscoverPoolsOnStartup);
        };
        System.Windows.Forms.Application.Run(form);
    }
}
