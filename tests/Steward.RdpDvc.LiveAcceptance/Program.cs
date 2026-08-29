namespace Steward.RdpDvc.LiveAcceptance;

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

        LiveAcceptanceOptions? options = null;
        try
        {
            var environment = LiveAcceptanceOptions.ReadEnvironment();
            if (!LiveAcceptanceOptions.HasRequiredConsentValue(
                    args,
                    environment))
            {
                Console.Error.WriteLine(
                    "NOT RUN: both exact live-connect and cloud-read consent phrases are required.");
                return 64;
            }
            options = LiveAcceptanceOptions.Parse(
                args,
                environment);

            await using var composition =
                await LiveAcceptanceComposition.CreateAsync(
                        options,
                        cancellation.Token)
                    .ConfigureAwait(false);
            var evidence = await composition.Runner.RunAsync(
                    cancellation.Token)
                .ConfigureAwait(false);
            await AcceptanceEvidenceStore.SaveAsync(
                    options.EvidenceDirectory,
                    evidence,
                    composition.SensitiveValues,
                    CancellationToken.None)
                .ConfigureAwait(false);
            Console.WriteLine(
                $"PASS: two headless RDCore generations verified; evidence run {evidence.RunId}.");
            return 0;
        }
        catch (OperationCanceledException)
            when (cancellation.IsCancellationRequested)
        {
            Console.Error.WriteLine("CANCELLED: sensitive details suppressed.");
            return 130;
        }
        catch (Exception exception)
        {
            if (options is not null)
            {
                await AcceptanceEvidenceStore.TrySaveFailureAsync(
                        options.EvidenceDirectory,
                        exception.GetType().Name,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }
            Console.Error.WriteLine(
                $"FAILED: {exception.GetType().Name}; sensitive details suppressed.");
            return 1;
        }
    }
}
