using System.Diagnostics;
using System.Text.Json;
using Steward.Providers.DevBox;

var arguments = Arguments.Parse(args);
var sourceRoot = Path.GetFullPath(arguments.SourceRoot);
var outputDirectory = Path.GetFullPath(arguments.OutputDirectory);
var serverProject = Path.Combine(
    sourceRoot,
    "src",
    "Steward.RdpDvc.Server.Windows",
    "Steward.RdpDvc.Server.Windows.csproj");
var keeperProject = Path.Combine(
    sourceRoot,
    "src",
    "Steward.HandleKeeper",
    "Steward.HandleKeeper.csproj");
if (!File.Exists(serverProject) || !File.Exists(keeperProject))
    throw new InvalidOperationException(
        "Steward RDP DVC server or Handle Keeper project was not found.");

Directory.CreateDirectory(outputDirectory);
var publishDirectory = Path.Combine(outputDirectory, ".rdp-dvc-publish");
if (Directory.Exists(publishDirectory))
    Directory.Delete(publishDirectory, recursive: true);

try
{
    await PublishAsync(
        arguments.DotNetPath,
        serverProject,
        publishDirectory).ConfigureAwait(false);
    await PublishAsync(
        arguments.DotNetPath,
        keeperProject,
        publishDirectory).ConfigureAwait(false);
    var bundle = RdpDvcBootstrapBundle.CreateFromPublishDirectory(
        publishDirectory,
        arguments.Version);
    var packagePath = Path.Combine(
        outputDirectory,
        $"steward-rdp-dvc-{arguments.Version}.zip");
    await File.WriteAllBytesAsync(
        packagePath,
        bundle.Archive.ToArray()).ConfigureAwait(false);
    await File.WriteAllTextAsync(
        packagePath + ".sha256",
        bundle.ArchiveSha256 + Environment.NewLine).ConfigureAwait(false);
    await File.WriteAllTextAsync(
        packagePath + ".manifest.json",
        JsonSerializer.Serialize(
            bundle.Manifest,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true
            }) + Environment.NewLine).ConfigureAwait(false);

    Console.WriteLine(
        $"Created {Path.GetFileName(packagePath)} ({bundle.Archive.ToMemory().Length} bytes, SHA-256 {bundle.ArchiveSha256}).");
}
finally
{
    if (Directory.Exists(publishDirectory))
        Directory.Delete(publishDirectory, recursive: true);
}

static async Task PublishAsync(
    string dotnetPath,
    string project,
    string outputDirectory)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = dotnetPath,
        UseShellExecute = false
    };
    foreach (var argument in new[]
             {
                 "publish",
                 project,
                 "--configuration",
                 "Release",
                 "--self-contained",
                 "false",
                 "--output",
                 outputDirectory,
                 "-p:UseAppHost=false",
                 "-p:DebugSymbols=false",
                 "-p:DebugType=None"
             })
        startInfo.ArgumentList.Add(argument);

    using var process = Process.Start(startInfo)
        ?? throw new InvalidOperationException("Unable to start dotnet publish.");
    await process.WaitForExitAsync().ConfigureAwait(false);
    if (process.ExitCode != 0)
        throw new InvalidOperationException(
            $"dotnet publish failed with exit code {process.ExitCode}.");
}

internal sealed record Arguments(
    string SourceRoot,
    string OutputDirectory,
    string Version,
    string DotNetPath)
{
    internal static Arguments Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length ||
                args[index] is not (
                    "--source-root" or
                    "--output" or
                    "--version" or
                    "--dotnet") ||
                !values.TryAdd(args[index], args[index + 1]))
                throw new ArgumentException(
                    "Usage: --source-root PATH --output PATH --version VERSION [--dotnet PATH]");
        }
        var sourceRoot = Required(values, "--source-root");
        var output = Required(values, "--output");
        var version = Required(values, "--version");
        RdpDvcBootstrapBundle.ValidateVersion(version);
        var dotnet = values.GetValueOrDefault("--dotnet") ??
                     Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ??
                     "dotnet";
        return new(sourceRoot, output, version, dotnet);
    }

    private static string Required(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var value) &&
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException(
                $"Required argument '{name}' is missing.");
}
