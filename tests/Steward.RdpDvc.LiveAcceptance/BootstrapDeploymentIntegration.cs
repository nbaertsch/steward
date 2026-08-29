using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Steward.ConnectionHost.Windows;
using Steward.Domain;
using Steward.Providers.DevBox;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.LiveAcceptance;

internal sealed record ValidatedBootstrapDeployment(
    DevBoxRdpDvcBootstrapReceipt Receipt,
    IReadOnlyList<RemoteBootstrapGeneration> Generations,
    string ReceiptSha256,
    bool DeployInvoked);

internal interface IBootstrapDeployInvoker
{
    Task InvokeAsync(
        LiveAcceptanceOptions options,
        CancellationToken cancellationToken);
}

internal sealed class BootstrapDeployCliInvoker : IBootstrapDeployInvoker
{
    private const string ToolConsent =
        "I_UNDERSTAND_THIS_MUTATES_THE_RETAINED_DEV_BOX_CUSTOMIZATION";

    public async Task InvokeAsync(
        LiveAcceptanceOptions options,
        CancellationToken cancellationToken)
    {
        if (!options.InvokeBootstrapDeploy ||
            options.BootstrapDeployExecutable is null ||
            options.BootstrapDeployArgumentsFile is null ||
            options.BootstrapDeployToolSha256 is null ||
            !string.Equals(
                options.BootstrapDeployConsent,
                LiveAcceptanceOptions.RequiredBootstrapDeployConsent,
                StringComparison.Ordinal))
            throw new InvalidOperationException(
                "Bootstrap deployment invocation is not independently authorized.");
        var executable = RequireExistingPlainFile(
            options.BootstrapDeployExecutable);
        var argumentsPath = RequireExistingPlainFile(
            options.BootstrapDeployArgumentsFile);
        var arguments = await LoadArgumentsAsync(
                argumentsPath,
                cancellationToken)
            .ConfigureAwait(false);
        var toolPath = ValidateInvocation(
            options,
            executable,
            arguments);
        var toolHash = Convert.ToHexString(
            SHA256.HashData(File.ReadAllBytes(toolPath)));
        if (!string.Equals(
                toolHash,
                options.BootstrapDeployToolSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "The bootstrap deployment CLI hash does not match the pinned tool.");

        using var process = new Process
        {
            StartInfo = new()
            {
                FileName = executable,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            },
            EnableRaisingEvents = true
        };
        foreach (var argument in arguments)
            process.StartInfo.ArgumentList.Add(argument);
        process.OutputDataReceived += static (_, _) => { };
        process.ErrorDataReceived += static (_, _) => { };
        if (!process.Start())
            throw new InvalidOperationException(
                "The bootstrap deployment CLI did not start.");
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        using var timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(options.BootstrapDeployTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token)
                .ConfigureAwait(false);
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: false);
                await process.WaitForExitAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
            }
            throw;
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                "The bootstrap deployment CLI failed; output was suppressed.");
    }

    private static async Task<string[]> LoadArgumentsAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var bytes = await File.ReadAllBytesAsync(path, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var arguments = JsonSerializer.Deserialize<string[]>(bytes) ??
                throw new InvalidDataException(
                    "Bootstrap deployment arguments are empty.");
            if (arguments.Length is 0 or > 128 ||
                arguments.Any(argument =>
                    string.IsNullOrWhiteSpace(argument) ||
                    argument.Length > 8192 ||
                    argument.Any(char.IsControl) ||
                    argument.Contains(
                        "ms-avd:",
                        StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException(
                    "Bootstrap deployment arguments are invalid or contain a provider resource.");
            return arguments;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string ValidateInvocation(
        LiveAcceptanceOptions options,
        string executable,
        IReadOnlyList<string> arguments)
    {
        var fileName = Path.GetFileName(executable);
        var offset = 0;
        var toolPath = executable;
        if (string.Equals(
                fileName,
                "dotnet.exe",
                StringComparison.OrdinalIgnoreCase))
        {
            if (arguments.Count == 0 ||
                !string.Equals(
                    Path.GetFileName(arguments[0]),
                    "Steward.DevBox.BootstrapDeploy.dll",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException(
                    "dotnet must invoke the exact bootstrap deployment assembly.");
            toolPath = RequireExistingPlainFile(arguments[0]);
            offset = 1;
        }
        else if (!string.Equals(
                     fileName,
                     "Steward.DevBox.BootstrapDeploy.exe",
                     StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Only the Steward bootstrap deployment CLI may be invoked.");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = offset; index < arguments.Count; index += 2)
        {
            if (index + 1 >= arguments.Count ||
                !arguments[index].StartsWith("--", StringComparison.Ordinal) ||
                !values.TryAdd(arguments[index], arguments[index + 1]))
                throw new InvalidDataException(
                    "Bootstrap deployment arguments must be distinct name/value pairs.");
        }
        if (!values.TryGetValue("--endpoint", out var endpoint) ||
            !Uri.TryCreate(endpoint, UriKind.Absolute, out var parsedEndpoint) ||
            new Uri(
                parsedEndpoint.GetLeftPart(UriPartial.Authority)
                    .TrimEnd('/') + "/") != options.DevBoxEndpoint)
            throw new InvalidDataException(
                "Bootstrap deployment endpoint does not match live acceptance.");
        RequireExact(values, "--project", options.Project);
        RequireExact(values, "--user", options.User);
        RequireExact(values, "--devbox", options.DevBox);
        RequireGuid(
            values,
            "--operation-id",
            options.BootstrapOperationId);
        RequireGuid(
            values,
            "--session-id",
            options.SessionId);
        RequireGuid(values, "--host-id", options.HostId.Value);
        RequireGuid(
            values,
            "--incarnation-id",
            options.NodeIncarnationId.Value);
        RequireExact(
            values,
            "--attested-receipt",
            Path.GetFullPath(options.BootstrapReceiptFile),
            path: true);
        RequireExact(
            values,
            "--node-identity",
            options.NodeIdentity);
        RequireExact(
            values,
            "--control-identity",
            options.ControlIdentity);
        RequireExact(values, "--consent", ToolConsent);
        return toolPath;
    }

    private static void RequireExact(
        IReadOnlyDictionary<string, string> values,
        string name,
        string expected,
        bool path = false)
    {
        if (!values.TryGetValue(name, out var value) ||
            !string.Equals(
                path ? Path.GetFullPath(value) : value,
                expected,
                path
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal))
            throw new InvalidDataException(
                $"Bootstrap deployment argument '{name}' does not match live acceptance.");
    }

    private static void RequireGuid(
        IReadOnlyDictionary<string, string> values,
        string name,
        Guid expected)
    {
        if (!values.TryGetValue(name, out var value) ||
            !Guid.TryParse(value, out var parsed) ||
            parsed != expected)
            throw new InvalidDataException(
                $"Bootstrap deployment argument '{name}' does not match live acceptance.");
    }

    private static string RequireExistingPlainFile(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath) ||
            File.GetAttributes(fullPath)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new FileNotFoundException(
                "Bootstrap deployment input is unavailable.");
        return fullPath;
    }
}

internal static class BootstrapDeploymentReceiptLoader
{
    internal static async Task<ValidatedBootstrapDeployment>
        PrepareAsync(
        LiveAcceptanceOptions options,
        ReadOnlyMemory<byte> nodePublicKey,
        ReadOnlyMemory<byte> controlPublicKey,
        IBootstrapDeployInvoker deployInvoker,
        CancellationToken cancellationToken)
    {
        if (options.InvokeBootstrapDeploy)
            await deployInvoker.InvokeAsync(options, cancellationToken)
                .ConfigureAwait(false);
        var bytes = await File.ReadAllBytesAsync(
                options.BootstrapReceiptFile,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var attested =
                await DevBoxRdpDvcBootstrapReceipts.LoadAttestedAsync(
                        options.BootstrapReceiptFile,
                        cancellationToken)
                    .ConfigureAwait(false);
            var confirmed = await File.ReadAllBytesAsync(
                    options.BootstrapReceiptFile,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                if (!bytes.AsSpan().SequenceEqual(confirmed))
                    throw new InvalidDataException(
                        "Bootstrap deployment receipt changed during verification.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(confirmed);
            }
            var nonces = attested.Receipt.ConnectionNonces;
            if (nonces.Count != 2 ||
                nonces.Any(static nonce => nonce == Guid.Empty) ||
                nonces.Distinct().Count() != 2)
                throw new InvalidDataException(
                    "Bootstrap deployment receipt must preauthorize exactly two fresh nonces.");
            var receipt = DevBoxRdpDvcBootstrapReceipts.Verify(
                attested,
                new(
                    new ProviderOperationId(
                        options.BootstrapOperationId),
                    options.BootstrapBundleVersion,
                    options.BootstrapArchiveSha256,
                    options.SessionId,
                    options.HostId,
                    options.NodeIncarnationId,
                    nonces),
                options.NodeIdentity,
                nodePublicKey.Span,
                options.ControlIdentity,
                controlPublicKey.Span);
            ValidatePreConnectionReadiness(receipt);
            var generations = receipt.ConnectionNonces
                .Select((nonce, index) => new RemoteBootstrapGeneration(
                    DeriveEvidenceReference(
                        receipt.OperationId.Value,
                        index,
                        nonce),
                    nonce))
                .ToArray();
            return new(
                receipt,
                generations,
                RemoteBootstrapEvidenceLoader.Hash(bytes),
                options.InvokeBootstrapDeploy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void ValidatePreConnectionReadiness(
        DevBoxRdpDvcBootstrapReceipt receipt)
    {
        var remote = receipt.RemoteReadiness;
        var validDeploymentState = receipt.PreConnectReady
            ? !remote.EndpointProcessRunning &&
              remote.ScheduledTaskState.Equals(
                  "Queued",
                  StringComparison.OrdinalIgnoreCase) &&
              remote.RemoteState == "waitingForActiveRdpSession"
            : !remote.EndpointProcessRunning &&
              remote.ScheduledTaskState.Equals(
                  "Running",
                  StringComparison.OrdinalIgnoreCase) &&
              remote.RemoteState == "deploymentPending";
        if (!receipt.SecretsExcluded ||
            !validDeploymentState ||
            remote.ProcessId != 0 ||
            remote.NextGeneration != 0 ||
            receipt.ObservedAtUtc >
                DateTimeOffset.UtcNow.AddMinutes(5) ||
            receipt.ObservedAtUtc <
                DateTimeOffset.UtcNow.Subtract(TimeSpan.FromHours(24)))
            throw new InvalidDataException(
                "Bootstrap receipt must attest the exact running deployment without fabricating remote DVC readiness.");
    }

    private static string DeriveEvidenceReference(
        Guid operationId,
        int index,
        Guid nonce)
    {
        var material = Encoding.UTF8.GetBytes(
            $"{operationId:N}:{index}:{nonce:N}");
        try
        {
            return "rdcore-" +
                Convert.ToHexString(SHA256.HashData(material))
                    .ToLowerInvariant()[..48];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }
    }
}
