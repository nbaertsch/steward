using System.Globalization;
using System.Reflection;
using System.Text.Json;
using Steward.Application;
using Steward.Contracts;
using Steward.Domain;
#if WINDOWS
using Steward.DevBox.Windows;
#endif
using Steward.Orchestration;
using Steward.Terminal.Abstractions;

namespace Steward.Cli;

public sealed class CliUsageException(string message)
    : InvalidOperationException(message);

public static class CliApplication
{
    public static async Task<int> RunAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken,
        HttpMessageHandler? handler = null,
        object? devBoxCommands = null)
    {
        try
        {
            var parsed = Arguments.Parse(arguments);
#if WINDOWS
            if (parsed.Command.StartsWith("identity-devbox-", StringComparison.Ordinal) &&
                !parsed.Command.StartsWith(
                    "identity-devbox-connection-",
                    StringComparison.Ordinal) ||
                parsed.Command == "devbox-discover")
            {
                var commands = devBoxCommands as IDevBoxCommandService ?? new DevBoxCommandService();
                object devBoxResult = parsed.Command switch
                {
                    "identity-devbox-login" =>
                        await commands.LoginAsync(cancellationToken),
                    "identity-devbox-status" => await commands.StatusAsync(cancellationToken),
                    "identity-devbox-logout" => await commands.LogoutAsync(cancellationToken),
                    "devbox-discover" => await commands.DiscoverAsync(cancellationToken),
                    _ => throw new CliUsageException($"Unknown command '{parsed.Command}'.")
                };
                await output.WriteLineAsync(JsonSerializer.Serialize(devBoxResult, StewardJson.Options));
                return 0;
            }
            if (parsed.Command.StartsWith(
                    "identity-devbox-connection-",
                    StringComparison.Ordinal))
            {
                var commands = new DevBoxConnectionCommandService();
                object connectionResult = parsed.Command switch
                {
                    "identity-devbox-connection-enroll" =>
                        await commands.EnrollAsync(cancellationToken),
                    "identity-devbox-connection-status" =>
                        await commands.StatusAsync(cancellationToken),
                    "identity-devbox-connection-logout" =>
                        await commands.LogoutAsync(cancellationToken),
                    _ => throw new CliUsageException(
                        $"Unknown command '{parsed.Command}'.")
                };
                await output.WriteLineAsync(
                    JsonSerializer.Serialize(
                        connectionResult,
                        StewardJson.Options));
                return 0;
            }
#endif
            using var httpClient = handler is null
                ? new HttpClient()
                : new HttpClient(handler, disposeHandler: false);
            httpClient.BaseAddress = parsed.Endpoint;
            var control = new ControlClient(httpClient);

            var result = await ExecuteAsync(
                parsed.Command,
                parsed.Values,
                control,
                cancellationToken);
            if (result.HasValue)
            {
                await output.WriteLineAsync(
                    JsonSerializer.Serialize(result.Value, StewardJson.Options));
            }
            return 0;
        }
        catch (CliUsageException exception)
        {
            await error.WriteLineAsync(exception.Message);
            await error.WriteLineAsync(Usage);
            return 2;
        }
        catch (ControlApiException exception)
        {
            await error.WriteLineAsync(exception.Message);
            return 3;
        }
        catch (HttpRequestException exception)
        {
            await error.WriteLineAsync($"Unable to reach Steward.Control: {exception.Message}");
            return 4;
        }
#if WINDOWS
        catch (Azure.Identity.AuthenticationFailedException exception)
        {
            await error.WriteLineAsync($"Dev Box authentication failed: {exception.Message}");
            return 5;
        }
#endif
        catch (InvalidDataException exception)
        {
            await error.WriteLineAsync(exception.Message);
            return 5;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await error.WriteLineAsync("Operation cancelled.");
            return 130;
        }
    }

    private static async Task<JsonElement?> ExecuteAsync(
        string command,
        IReadOnlyDictionary<string, string> values,
        ControlClient control,
        CancellationToken cancellationToken)
    {
        switch (command)
        {
            case "doctor":
                return await control.DoctorAsync(cancellationToken);
            case "doctor-orchestration":
                return await control.OrchestrationDoctorAsync(cancellationToken);

            case "backup-export":
                return await control.ExportBackupAsync(
                    new(AbsolutePath(values, "destination-directory")), cancellationToken);
            case "backup-validate":
                return await control.ValidateBackupAsync(
                    new(
                        AbsolutePath(values, "database-path"),
                        AbsolutePath(values, "manifest-path")),
                    cancellationToken);
            case "backup-restore":
                return await control.RestoreBackupAsync(
                    new(
                        AbsolutePath(values, "database-path"),
                        AbsolutePath(values, "manifest-path"),
                        AbsolutePath(values, "destination-path")),
                    cancellationToken);

            case "workload-create":
            {
                var plannerData = ParseJson(Required(values, "planner-data"));
                return await control.CreateWorkloadAsync(
                    new(
                        Required(values, "type"),
                        Required(values, "planner-kind"),
                        Required(values, "planner-version"),
                        plannerData,
                        values.GetValueOrDefault("idempotency-key")),
                    cancellationToken);
            }

            case "workload-submit-harbor":
            case "workload-submit-saber":
            case "workload-submit-process":
            case "workload-submit-compose":
                return await control.SubmitWorkloadAsync(
                    new(
                        command["workload-submit-".Length..],
                        ParseInput(Required(values, "input")),
                        ParseId<PoolId>(values, "pool-id"),
                        BoundedText(values, "idempotency-key", 128),
                        OptionalId<WorkloadId>(values, "workload-id"),
                        OptionalId<PlanRevisionId>(values, "plan-revision-id")),
                    cancellationToken);

            case "workload-get":
            case "workload-status":
                return await control.GetWorkloadAsync(
                    ParseId<WorkloadId>(values, "id"), cancellationToken);
            case "workload-cancel":
                return await control.CancelWorkloadAsync(
                    ParseId<WorkloadId>(values, "id"), cancellationToken);

            case "task-get":
            case "task-status":
                return await control.GetTaskAsync(ParseId<TaskId>(values, "id"), cancellationToken);
            case "task-events":
                return await control.ReadTaskEventsAsync(
                    ParseId<TaskId>(values, "id"),
                    NonNegativeLong(values, "after", 0),
                    BoundedInt(values, "limit", 50, 1, 100),
                    cancellationToken);
            case "task-retry":
                return await control.RetryTaskAsync(
                    ParseId<WorkloadId>(values, "workload-id"),
                    ParseId<TaskId>(values, "task-id"),
                    cancellationToken);
            case "task-recovery-absent":
                return await control.ResolveTaskRecoveryAbsentAsync(
                    ParseId<WorkloadId>(values, "workload-id"),
                    ParseId<TaskId>(values, "task-id"),
                    BoundedInt(values, "generation", 0, 1, int.MaxValue),
                    cancellationToken);

            case "attempt-get":
            case "attempt-status":
                return await control.GetAttemptAsync(
                    ParseId<TaskAttemptId>(values, "id"), cancellationToken);

            case "artifact-get":
                return await control.GetArtifactAsync(
                    ParseId<PortableObjectId>(values, "id"), cancellationToken);
            case "artifact-download":
            {
                var result = await control.DownloadArtifactAsync(
                    ParseId<PortableObjectId>(values, "id"),
                    Path.GetFullPath(BoundedText(values, "output", 32_767)),
                    BoundedLong(values, "max-bytes", 256L * 1024 * 1024, 1, 1024L * 1024 * 1024),
                    cancellationToken);
                return JsonSerializer.SerializeToElement(result, StewardJson.Options);
            }

            case "pool-list":
                return await control.ListPoolsAsync(cancellationToken);
            case "pool-get":
                return await control.GetPoolAsync(ParseId<PoolId>(values, "id"), cancellationToken);
            case "pool-register":
                return await control.RegisterPoolAsync(
                    ParseJson<PoolRegistration>(values, "request"), cancellationToken);
            case "pool-reconcile":
                return await control.ReconcilePoolAsync(
                    ParseId<PoolId>(values, "id"),
                    ParseJson<ReconcilePoolRequest>(values, "request"),
                    cancellationToken);

            case "host-list":
                return await control.ListHostsAsync(cancellationToken);
            case "host-get":
                return await control.GetHostAsync(ParseId<HostId>(values, "id"), cancellationToken);
            case "host-inspect":
                return await control.InspectHostAsync(ParseId<HostId>(values, "id"), cancellationToken);
            case "host-start":
                return await control.StartHostAsync(ParseId<HostId>(values, "id"), cancellationToken);
            case "host-drain":
                return await control.DrainHostAsync(
                    ParseId<HostId>(values, "id"), Boolean(values, "force", false), cancellationToken);
            case "host-stop":
                return await control.StopHostAsync(
                    ParseId<HostId>(values, "id"), Boolean(values, "force", false), cancellationToken);
            case "host-recreate":
                return await control.RecreateHostAsync(
                    ParseId<HostId>(values, "id"), Boolean(values, "force", false), cancellationToken);
            case "host-delete":
                return await control.DeleteHostAsync(
                    ParseId<HostId>(values, "id"), Boolean(values, "force", false), cancellationToken);

            case "node-list":
                return await control.ListNodesAsync(cancellationToken);
            case "node-register":
                return await control.RegisterNodeAsync(
                    ParseJson<RegisterNodeRequest>(values, "request"), cancellationToken);

            case "agent-create":
                return await control.CreateAgentAsync(new(
                    OptionalId<StewardAgentId>(values, "id"),
                    OptionalBoundedText(values, "parent-route", 512)), cancellationToken);
            case "agent-get":
            case "agent-status":
                return await control.GetAgentAsync(
                    ParseId<StewardAgentId>(values, "id"), cancellationToken);
            case "agent-turn":
                return await control.SubmitAgentTurnAsync(
                    ParseId<StewardAgentId>(values, "id"),
                    new(
                        BoundedText(values, "text", 65_536),
                        ClientRequestId: OptionalBoundedText(values, "client-request-id", 256),
                        TurnId: OptionalId<AgentTurnId>(values, "turn-id")),
                    cancellationToken);
            case "agent-turn-cancel":
                return await control.CancelAgentTurnAsync(
                    ParseId<StewardAgentId>(values, "agent-id"),
                    ParseId<AgentTurnId>(values, "turn-id"),
                    cancellationToken);
            case "agent-run-next":
                return await control.RunNextAgentTurnAsync(
                    ParseId<StewardAgentId>(values, "id"), cancellationToken);
            case "agent-notifications-read":
                return await control.ReadAgentNotificationsAsync(
                    ParseId<StewardAgentId>(values, "id"),
                    NonNegativeLong(values, "after", 0),
                    BoundedInt(values, "limit", 50, 1, 100),
                    cancellationToken);
            case "agent-notifications-ack":
                return await control.AcknowledgeAgentNotificationsAsync(
                    ParseId<StewardAgentId>(values, "id"),
                    NonNegativeLong(values, "cursor"),
                    cancellationToken);
            case "agent-migrate":
                return await control.MigrateAgentAsync(
                    ParseId<StewardAgentId>(values, "id"),
                    ParseJson<AgentMigrationRequest>(values, "request"),
                    cancellationToken);

            case "notifications-read":
                return await control.ReadNotificationsAsync(
                    BoundedText(values, "stream", 256),
                    NonNegativeLong(values, "after", 0),
                    BoundedInt(values, "limit", 50, 1, 50),
                    cancellationToken);

            case "notifications-ack":
                await control.AcknowledgeNotificationsAsync(
                    BoundedText(values, "stream", 256),
                    NonNegativeLong(values, "cursor"),
                    cancellationToken);
                return null;

            case "terminal-authority-issue":
                return await control.IssueTerminalAuthorityAsync(
                    ParseJsonFile<IssueTerminalAuthorityRequest>(values), cancellationToken);
            case "terminal-open":
            {
                var request = ParseJsonFile<TerminalOpenRequest>(values);
                TerminalContractLimits.ValidateRequestId(request.RequestId);
                return await control.OpenTerminalAsync(request, cancellationToken);
            }
            case "terminal-get":
                return await control.GetTerminalAsync(ParseTerminalId(values), cancellationToken);
            case "terminal-input":
            {
                var request = ParseJsonFile<TerminalInputRequest>(values);
                TerminalContractLimits.ValidateRequestId(request.RequestId);
                if (request.Data.Length > 65_536)
                    throw new CliUsageException("Terminal input is limited to 65536 bytes per command.");
                return await control.SendTerminalInputAsync(ParseTerminalId(values), request, cancellationToken);
            }
            case "terminal-resize":
            {
                var request = ParseJsonFile<TerminalResizeRequest>(values);
                TerminalContractLimits.ValidateRequestId(request.RequestId);
                return await control.ResizeTerminalAsync(ParseTerminalId(values), request, cancellationToken);
            }
            case "terminal-output":
            {
                var request = ParseJsonFile<TerminalOutputReadRequest>(values);
                if (request.AfterSequence < 0 || request.AfterOffset < 0 ||
                    request.MaximumItems is < 1 or > 50 ||
                    request.MaximumBytes is < 1 or > 65_536)
                    throw new CliUsageException("Terminal output cursor or page bound is invalid.");
                return await control.ReadTerminalOutputAsync(ParseTerminalId(values), request, cancellationToken);
            }
            case "terminal-close":
            {
                var request = ParseJsonFile<TerminalCloseRequest>(values);
                TerminalContractLimits.ValidateRequestId(request.RequestId);
                return await control.CloseTerminalAsync(ParseTerminalId(values), request, cancellationToken);
            }
            case "terminal-revoke":
                return await control.RevokeTerminalAsync(ParseTerminalId(values), cancellationToken);

            default:
                throw new CliUsageException($"Unknown command '{command}'.");
        }
    }

    private static JsonElement ParseJson(string value)
        => ParseBoundedJson(value, 32_768, "planner-data");

    private static JsonElement ParseInput(string value)
        => ParseBoundedJson(value, 65_536, "input");

    private static JsonElement ParseBoundedJson(string value, int maximum, string name)
    {
        if (value.Length > maximum)
            throw new CliUsageException($"--{name} must be at most {maximum} characters.");
        try
        {
            using var document = JsonDocument.Parse(value, new JsonDocumentOptions { MaxDepth = 32 });
            return document.RootElement.Clone();
        }
        catch (JsonException exception)
        {
            throw new CliUsageException(
                $"--{name} must be valid JSON: {exception.Message}");
        }
    }

    private static T ParseJson<T>(
            IReadOnlyDictionary<string, string> values,
            string name)
        {
            var json = Required(values, name);
            if (json.Length > 65_536)
                throw new CliUsageException($"--{name} must be at most 65536 characters.");
            try
            {
                return JsonSerializer.Deserialize<T>(json, StewardJson.Options)
                    ?? throw new JsonException("JSON value was null.");
            }
            catch (JsonException exception)
            {
                throw new CliUsageException($"--{name} must be valid {typeof(T).Name} JSON: {exception.Message}");
            }
        }

    private static T ParseJsonFile<T>(IReadOnlyDictionary<string, string> values)
    {
        var path = Required(values, "request-file");
        if (!Path.IsPathFullyQualified(path))
            throw new CliUsageException("--request-file must be an absolute local path.");
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 65_536)
                throw new CliUsageException("--request-file is unavailable or exceeds 65536 bytes.");
            return JsonSerializer.Deserialize<T>(File.ReadAllText(path), StewardJson.Options)
                ?? throw new JsonException("JSON value was null.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new CliUsageException($"--request-file must contain valid {typeof(T).Name} JSON.");
        }
    }

    private static TerminalSessionId ParseTerminalId(
        IReadOnlyDictionary<string, string> values) =>
        TerminalSessionId.TryParse(Required(values, "id"), out var id)
            ? id
            : throw new CliUsageException("--id must be a non-empty TerminalSession GUID.");

    private static T ParseId<T>(
            IReadOnlyDictionary<string, string> values,
            string name)
            where T : struct, IStewardId
        {
            var text = Required(values, name);
            try
            {
                var value = (T)Activator.CreateInstance(typeof(T), Guid.Parse(text))!;
                if (value.Value == Guid.Empty) throw new FormatException();
                return value;
            }
            catch (Exception exception) when (exception is FormatException or TargetInvocationException)
            {
                var typeName = typeof(T).Name;
                if (typeName.EndsWith("Id", StringComparison.Ordinal))
                    typeName = typeName[..^2];
                throw new CliUsageException(
                    $"--{name} must be a non-empty {typeName} GUID.");
            }
        }

    private static T? OptionalId<T>(
            IReadOnlyDictionary<string, string> values,
            string name)
            where T : struct, IStewardId =>
            values.ContainsKey(name) ? ParseId<T>(values, name) : null;

    private static string BoundedText(
            IReadOnlyDictionary<string, string> values,
            string name,
            int maximum)
        {
            var value = Required(values, name);
            if (value.Length > maximum)
                throw new CliUsageException($"--{name} must be at most {maximum} characters.");
            return value;
        }

        private static string? OptionalBoundedText(
            IReadOnlyDictionary<string, string> values,
            string name,
            int maximum) =>
            values.ContainsKey(name) ? BoundedText(values, name, maximum) : null;

    private static bool Boolean(
            IReadOnlyDictionary<string, string> values,
            string name,
            bool defaultValue)
        {
            if (!values.TryGetValue(name, out var value)) return defaultValue;
            return bool.TryParse(value, out var result)
                ? result
                : throw new CliUsageException($"--{name} must be true or false.");
    }

    private static string Required(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new CliUsageException($"--{name} is required.");

    private static string AbsolutePath(
        IReadOnlyDictionary<string, string> values,
        string name)
    {
        var value = BoundedText(values, name, 32_767);
        if (!Path.IsPathFullyQualified(value) || value.IndexOf('\0') >= 0)
            throw new CliUsageException($"--{name} must be an absolute local path.");
        return Path.GetFullPath(value);
    }

    private static long NonNegativeLong(
        IReadOnlyDictionary<string, string> values,
        string name,
        long? defaultValue = null)
    {
        if (!values.TryGetValue(name, out var value))
        {
            return defaultValue
                ?? throw new CliUsageException($"--{name} is required.");
        }
        if (!long.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var result) ||
            result < 0)
        {
            throw new CliUsageException($"--{name} must be a non-negative integer.");
        }
        return result;
    }

    private static int BoundedInt(
        IReadOnlyDictionary<string, string> values,
        string name,
        int defaultValue,
        int minimum,
        int maximum)
    {
        if (!values.TryGetValue(name, out var value))
        {
            return defaultValue;
        }
        if (!int.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var result) ||
            result < minimum ||
            result > maximum)
        {
            throw new CliUsageException(
                $"--{name} must be between {minimum} and {maximum}.");
        }
        return result;
    }

    private static long BoundedLong(
        IReadOnlyDictionary<string, string> values,
        string name,
        long defaultValue,
        long minimum,
        long maximum)
    {
        if (!values.TryGetValue(name, out var value)) return defaultValue;
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var result) ||
            result < minimum || result > maximum)
            throw new CliUsageException($"--{name} must be between {minimum} and {maximum}.");
        return result;
    }

    private const string Usage = """
        Usage:
          steward doctor [--endpoint URL]
          steward identity devbox login
          steward identity devbox {status|logout}
          steward identity devbox connection {enroll|status|logout}
          steward devbox discover
          steward backup export --destination-directory ABSOLUTE_PATH
          steward backup validate --database-path ABSOLUTE_PATH --manifest-path ABSOLUTE_PATH
          steward backup restore --database-path ABSOLUTE_PATH --manifest-path ABSOLUTE_PATH --destination-path ABSOLUTE_PATH
          steward workload create --type TYPE --planner-kind KIND --planner-version VERSION --planner-data JSON [--idempotency-key KEY] [--endpoint URL]
          steward workload submit {harbor|saber|process|compose} --input JSON --pool-id ID --idempotency-key KEY
          steward workload {get|status|cancel} --id WORKLOAD_ID
          steward task {get|status|events} --id TASK_ID [--after CURSOR] [--limit COUNT]
          steward task retry --workload-id ID --task-id ID
          steward task recovery absent --workload-id ID --task-id ID --generation NUMBER
          steward attempt {get|status} --id ATTEMPT_ID
          steward artifact get --id PORTABLE_OBJECT_ID
          steward artifact download --id PORTABLE_OBJECT_ID --output LOCAL_PATH [--max-bytes COUNT]
          steward pool list | steward pool {register|reconcile} --request JSON [--id POOL_ID]
          steward host {list|get|inspect|start|drain|stop|recreate|delete} [--id HOST_ID] [--force BOOL]
          steward node list | steward node register --request JSON
          steward agent {create|get|status|run-next} [--id AGENT_ID]
          steward agent turn --id AGENT_ID --text TEXT [--client-request-id ID] [--turn-id ID]
          steward agent turn cancel --agent-id ID --turn-id ID
          steward agent notifications {read|ack} --id AGENT_ID [--after CURSOR] [--limit COUNT] [--cursor CURSOR]
          steward agent migrate --id AGENT_ID --request JSON
          steward terminal authority issue --request-file ABSOLUTE_JSON_FILE
          steward terminal open --request-file ABSOLUTE_JSON_FILE
          steward terminal get --id SESSION_ID
          steward terminal {input|resize|output|close} --id SESSION_ID --request-file ABSOLUTE_JSON_FILE
          steward terminal revoke --id SESSION_ID
          steward notifications read --stream STREAM [--after CURSOR] [--limit COUNT] [--endpoint URL]
          steward notifications ack --stream STREAM --cursor CURSOR [--endpoint URL]
        """;

    private sealed record Arguments(
        Uri Endpoint,
        string Command,
        IReadOnlyDictionary<string, string> Values)
    {
        public static Arguments Parse(IReadOnlyList<string> arguments)
        {
            if (arguments.Count == 0)
            {
                throw new CliUsageException("A command is required.");
            }

            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            var words = new List<string>();
            for (var index = 0; index < arguments.Count; index++)
            {
                var current = arguments[index];
                if (!current.StartsWith("--", StringComparison.Ordinal))
                {
                    words.Add(current);
                    continue;
                }

                var name = current[2..];
                if (name.Length == 0 || index + 1 >= arguments.Count)
                {
                    throw new CliUsageException($"Option '{current}' requires a value.");
                }
                if (!values.TryAdd(name, arguments[++index]))
                {
                    throw new CliUsageException($"Option '--{name}' was provided more than once.");
                }
                if (name.Contains("token", StringComparison.OrdinalIgnoreCase))
                    throw new CliUsageException(
                        "Mutation tokens may only be supplied through environment or file references.");
            }

            var command = string.Join('-', words).ToLowerInvariant();
            if (command.Length == 0)
            {
                throw new CliUsageException("A command is required.");
            }

            var endpointText = values.Remove("endpoint", out var configured)
                ? configured
                : Environment.GetEnvironmentVariable("STEWARD_CONTROL_URL")
                  ?? "http://127.0.0.1:5112/";
            if (!Uri.TryCreate(endpointText, UriKind.Absolute, out var endpoint) ||
                endpoint.Scheme is not ("http" or "https"))
            {
                throw new CliUsageException("--endpoint must be an absolute HTTP or HTTPS URL.");
            }
            if (!endpoint.AbsoluteUri.EndsWith("/", StringComparison.Ordinal))
            {
                endpoint = new Uri(endpoint.AbsoluteUri + "/", UriKind.Absolute);
            }
            return new(endpoint, command, values);
        }
    }
}
