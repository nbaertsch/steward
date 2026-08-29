namespace Steward.DevBox.LiveAcceptance;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        try
        {
            var configuration = LiveHarnessConfiguration.Parse(
                args,
                LiveHarnessConfiguration.ReadEnvironment());
            if (!configuration.AllowBillableCreate)
            {
                Console.Error.WriteLine(
                    "NOT RUN: this harness creates one billable Dev Box. Pass --allow-billable-create or set STEWARD_DEVBOX_LIVE_ACCEPTANCE to the documented consent phrase.");
                return 64;
            }

            Console.WriteLine(
                configuration.RecoverAcceptedCreate
                    ? "LIVE/RECOVERY: resume the exact previously accepted " +
                      "Dev Box; no create will be submitted."
                    : "LIVE/BILLABLE: one Dev Box create will be submitted " +
                      "through the typed Dev Center developer SDK.");
            Console.WriteLine(
                configuration.DeleteEvidenceBox
                    ? "Cleanup was explicitly requested and occurs only after the gateway gate passes."
                    : "Cleanup was not requested; the evidence box will be preserved.");
            var runner = new LiveAcceptanceRunner(configuration);
            var exitCode = await runner.RunAsync(cancellation.Token)
                .ConfigureAwait(false);
            Console.WriteLine(
                exitCode == 2
                    ? "PENDING: gateway evidence may have passed; run the separate no-cloud DVC reconnect acceptance extension."
                    : $"FINISHED: exit code {exitCode}.");
            return exitCode;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine(
                "CANCELLED: durable state is preserved and no failed box was deleted.");
            return 130;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"FAILED ({exception.GetType().Name}): details are intentionally suppressed to prevent signed URL or token disclosure. Durable state/evidence is preserved.");
            return 1;
        }
    }
}
