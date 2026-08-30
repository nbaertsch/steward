using System.Runtime.InteropServices;
using Steward.RdpDvc.Client.Windows;
using Steward.Transport.Rdp.Windows;

[assembly: ComVisible(true)]

return await ProgramEntry.RunAsync(args);

internal static class ProgramEntry
{
    internal static async Task<int> RunAsync(string[] arguments)
    {
        var earlyLog = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "Steward",
            "rdp-dvc-client",
            "embedding-early.log");
        var earlyEmbedding =
            arguments.Length == 1 &&
            Is(arguments[0], "-Embedding");
        if (earlyEmbedding)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(earlyLog)!);
            File.AppendAllText(
                earlyLog,
                $"started{Environment.NewLine}");
        }
        try
        {
            if (arguments.Length == 1 &&
                Is(arguments[0], "/register"))
            {
                var executable = Environment.ProcessPath ??
                    throw new InvalidOperationException(
                        "The executable path is unavailable.");
                new RdpDvcPluginRegistration(
                        new CurrentUserRegistryStore(),
                        new WindowsRdpDvcExecutableValidator())
                    .Register(executable);
                Console.WriteLine(
                    $"Registered Steward DVC v{StewardRdpDvc.ProtocolVersion} per-user.");
                return 0;
            }
            if (arguments.Length == 1 &&
                Is(arguments[0], "/unregister"))
            {
                new RdpDvcPluginRegistration(
                        new CurrentUserRegistryStore(),
                        new WindowsRdpDvcExecutableValidator())
                    .Unregister();
                Console.WriteLine(
                    "Unregistered only the Steward DVC per-user entries.");
                return 0;
            }
            var embedding =
                arguments.Length == 1 &&
                Is(arguments[0], "-Embedding");
            var diagnostics =
                arguments.Length == 0 ||
                arguments.Length == 1 &&
                Is(arguments[0], "--diagnostics");
            if (!embedding && !diagnostics)
            {
                Console.Error.WriteLine(
                    "Usage: Steward.RdpDvc.Client.Windows.exe /register | /unregister | -Embedding | --diagnostics");
                return 64;
            }

            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };
            string evidencePipe;
            string evidenceKeyFile;
            string? embeddingLog = null;
            if (embedding)
            {
                File.AppendAllText(
                    earlyLog,
                    $"loading-config{Environment.NewLine}");
                var configuration =
                    RdpDvcEmbeddingConfigurationStore.Load();
                evidencePipe = configuration.EvidencePipeName;
                evidenceKeyFile = configuration.EvidenceKeyFile;
                embeddingLog = configuration.DiagnosticLogFile;
            }
            else
            {
                evidencePipe = RequireSetting(
                    "STEWARD_DVC_EVIDENCE_PIPE_NAME");
                evidenceKeyFile = RequireExistingFile(
                    "STEWARD_DVC_EVIDENCE_KEY_FILE");
            }
            Action<string> log = embedding
                ? message => File.AppendAllText(
                    embeddingLog!,
                    $"StewardDVC {message}{Environment.NewLine}")
                : static message =>
                    Console.WriteLine($"StewardDVC {message}");
            await using var evidencePublisher =
                AuthenticatedRdpDvcEvidencePublisher.FromProtectedFile(
                    evidencePipe,
                    evidenceKeyFile);
            await using var broker = new ClientDvcBroker(log);
            var lifetime = new ComServerLifetime();
            var factory = new StewardClassFactory(
                () =>
                {
                    var evidence =
                        evidencePublisher.CreateLifecycleSession();
                    evidence.PublishAsync(
                            RdpDvcEvidencePublicationEvent
                                .StewardComClassActivated)
                        .AsTask()
                        .GetAwaiter()
                        .GetResult();
                    lifetime.PluginCreated();
                    return new StewardDvcPlugin(
                        broker,
                        evidence,
                        log,
                        lifetime.PluginTerminated);
                });
            if (embedding)
                File.AppendAllText(
                    earlyLog,
                    $"registering-class{Environment.NewLine}");
            using var server = new ComLocalServer(factory, log);
            if (embedding)
                File.AppendAllText(
                    earlyLog,
                    $"class-registered{Environment.NewLine}");
            log(
                $"READY CLSID={StewardRdpDvc.PluginClsid:B} CHANNEL={StewardRdpDvc.ChannelName} VERSION={StewardRdpDvc.ProtocolVersion}");
            try
            {
                if (embedding)
                    await lifetime.WaitForShutdownAsync(
                        cancellation.Token);
                else
                    await Task.Delay(
                        Timeout.InfiniteTimeSpan,
                        cancellation.Token);
            }
            catch (OperationCanceledException)
                when (cancellation.IsCancellationRequested)
            {
            }
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Steward DVC client failed: {exception.GetType().Name}.");
            return 1;
        }
    }

    private static bool Is(string value, string expected) =>
        string.Equals(
            value,
            expected,
            StringComparison.OrdinalIgnoreCase);

    private static string RequireSetting(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException(
                $"Required production setting '{name}' is missing.");

    private static string RequireExistingFile(string name)
    {
        var configured = RequireSetting(name);
        if (!Path.IsPathFullyQualified(configured))
            throw new InvalidOperationException(
                $"Required production key file '{name}' must be absolute.");
        var path = Path.GetFullPath(configured);
        if (
            !File.Exists(path) ||
            File.GetAttributes(path)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException(
                $"Required production key file '{name}' is unavailable.");
        return path;
    }
}
