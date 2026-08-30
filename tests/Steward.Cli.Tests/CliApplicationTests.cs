using System.Net;
using System.Text;
using System.Text.Json;
using Steward.Cli;
using Steward.Application;
using Steward.Contracts;
using Steward.Domain;
using Steward.DevBox.Windows;
using Steward.Terminal.Abstractions;

namespace Steward.Cli.Tests;

public sealed class CliApplicationTests
{
    private const string Id = "11111111-1111-1111-1111-111111111111";

    [Fact]
    public async Task Devbox_commands_use_native_service_without_control_http()
    {
        var called = false;
        var handler = new StubHandler(_ =>
        {
            called = true;
            return Json(HttpStatusCode.OK, new { });
        });
        var service = new FakeDevBoxCommands();

        var login = await RunAsync(
            ["identity", "devbox", "login"], handler, service);
        var status = await RunAsync(["identity", "devbox", "status"], handler, service);
        var discover = await RunAsync(["devbox", "discover"], handler, service);
        var logout = await RunAsync(["identity", "devbox", "logout"], handler, service);

        Assert.All(new[] { login, status, discover, logout }, x => Assert.Equal(0, x.ExitCode));
        Assert.False(called);
        Assert.True(service.LoginCalled);
        Assert.Contains("\"contextName\":\"devbox/default\"", discover.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Doctor_prints_control_response()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, new { healthy = true }));
        var result = await RunAsync(["doctor"], handler);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("\"healthy\":true", result.Output, StringComparison.Ordinal);
        Assert.Empty(result.Error);
    }

    [Fact]
    public async Task Workload_create_sends_typed_request()
    {
        string? requestBody = null;
        var handler = new StubHandler(async request =>
        {
            requestBody = await request.Content!.ReadAsStringAsync();
            return Json(HttpStatusCode.Created, new { created = true });
        });
        var result = await RunAsync(
            [
                "workload", "create",
                "--type", "harbor",
                "--planner-kind", "eval",
                "--planner-version", "1.0.0",
                "--planner-data", """{"suite":"smoke"}"""
            ],
            handler);

        Assert.Equal(0, result.ExitCode);
        using var body = JsonDocument.Parse(requestBody!);
        Assert.Equal("harbor", body.RootElement.GetProperty("workloadType").GetString());
        Assert.Equal("smoke", body.RootElement
            .GetProperty("plannerData")
            .GetProperty("suite")
            .GetString());
    }

    [Fact]
    public async Task Workload_create_sends_idempotency_key_in_header_and_body()
    {
        string? header = null;
        string? requestBody = null;
        var handler = new StubHandler(async request =>
        {
            header = request.Headers.GetValues("Idempotency-Key").Single();
            requestBody = await request.Content!.ReadAsStringAsync();
            return Json(HttpStatusCode.Created, new { created = true });
        });
        var result = await RunAsync(
            [
                "workload", "create",
                "--type", "harbor",
                "--planner-kind", "eval",
                "--planner-version", "1.0.0",
                "--planner-data", "{}",
                "--idempotency-key", "retry-1"
            ],
            handler);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("retry-1", header);
        Assert.Equal("retry-1",
            JsonDocument.Parse(requestBody!).RootElement.GetProperty("idempotencyKey").GetString());
    }

    [Fact]
    public async Task Invalid_usage_does_not_call_control()
    {
        var called = false;
        var handler = new StubHandler(_ =>
        {
            called = true;
            return Json(HttpStatusCode.OK, new { });
        });
        var result = await RunAsync(["workload", "get", "--id", "bad"], handler);
        Assert.Equal(2, result.ExitCode);
        Assert.Contains("non-empty Workload GUID", result.Error, StringComparison.Ordinal);
        Assert.False(called);
    }

    [Fact]
    public async Task Notification_cursor_is_bounded_and_acknowledged()
    {
        var paths = new List<string>();
        var handler = new StubHandler(request =>
        {
            paths.Add(request.RequestUri!.PathAndQuery);
            return request.Method == HttpMethod.Get
                ? Json(HttpStatusCode.OK, Array.Empty<object>())
                : new HttpResponseMessage(HttpStatusCode.NoContent);
        });

        Assert.Equal(0, (await RunAsync(
            ["notifications", "read", "--stream", "agent:1", "--after", "8", "--limit", "25"],
            handler)).ExitCode);
        Assert.Equal(0, (await RunAsync(
            ["notifications", "ack", "--stream", "agent:1", "--cursor", "9"],
            handler)).ExitCode);
        Assert.Contains("/notifications/agent%3A1?after=8&limit=25", paths);
        Assert.Contains("/notifications/agent%3A1/ack/9", paths);
    }

    [Fact]
    public async Task Control_error_has_distinct_exit_code()
    {
        var handler = new StubHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Conflict)
            {
                Content = new StringContent("""{"code":"RevisionConflict"}""")
            });
        var result = await RunAsync(["doctor"], handler);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("RevisionConflict", result.Error, StringComparison.Ordinal);
    }

    public static TheoryData<string[], string, string> SimpleRoutes => new()
    {
        { ["doctor", "orchestration"], "GET", "/doctor/orchestration" },
        { ["workload", "status", "--id", Id], "GET", $"/workloads/{Id}" },
        { ["workload", "cancel", "--id", Id], "POST", $"/workloads/{Id}/cancel" },
        { ["task", "get", "--id", Id], "GET", $"/tasks/{Id}" },
        { ["task", "events", "--id", Id, "--after", "2", "--limit", "10"], "GET", $"/tasks/{Id}/events?after=2&limit=10" },
        { ["task", "retry", "--workload-id", Id, "--task-id", Id], "POST", $"/workloads/{Id}/tasks/{Id}/retry" },
        { ["task", "recovery", "absent", "--workload-id", Id, "--task-id", Id, "--generation", "2"], "POST", $"/workloads/{Id}/tasks/{Id}/recovery/absent/2" },
        { ["attempt", "status", "--id", Id], "GET", $"/attempts/{Id}" },
        { ["artifact", "get", "--id", Id], "GET", $"/artifacts/{Id}" },
        { ["pool", "list"], "GET", "/pools" },
        { ["host", "list"], "GET", "/hosts" },
        { ["host", "get", "--id", Id], "GET", $"/hosts/{Id}" },
        { ["host", "inspect", "--id", Id], "GET", $"/hosts/{Id}/provider" },
        { ["host", "start", "--id", Id], "POST", $"/hosts/{Id}/start" },
        { ["host", "drain", "--id", Id, "--force", "true"], "POST", $"/hosts/{Id}/drain?force=true" },
        { ["host", "stop", "--id", Id], "POST", $"/hosts/{Id}/stop?force=false" },
        { ["host", "recreate", "--id", Id], "POST", $"/hosts/{Id}/recreate?force=false" },
        { ["host", "delete", "--id", Id], "DELETE", $"/hosts/{Id}?force=false" },
        { ["node", "list"], "GET", "/nodes" },
        { ["terminal", "get", "--id", Id], "GET", $"/terminals/{Id}" },
        { ["terminal", "revoke", "--id", Id], "POST", $"/terminals/{Id}/revoke" },
        { ["agent", "create", "--id", Id], "POST", "/agents" },
        { ["agent", "status", "--id", Id], "GET", $"/agents/{Id}" },
        { ["agent", "turn", "--id", Id, "--text", "hello"], "POST", $"/agents/{Id}/turns" },
        { ["agent", "turn", "cancel", "--agent-id", Id, "--turn-id", Id], "POST", $"/agents/{Id}/turns/{Id}/cancel" },
        { ["agent", "run-next", "--id", Id], "POST", $"/agents/{Id}/run-next" },
        { ["agent", "notifications", "read", "--id", Id, "--after", "3", "--limit", "4"], "GET", $"/agents/{Id}/notifications?after=3&limit=4" },
        { ["agent", "notifications", "ack", "--id", Id, "--cursor", "4"], "POST", $"/agents/{Id}/notifications/ack/4" }
    };

    [Theory]
    [MemberData(nameof(SimpleRoutes))]
    public async Task Commands_map_to_documented_routes(
        string[] arguments, string method, string path)
    {
        HttpRequestMessage? observed = null;
        var handler = new StubHandler(request =>
        {
            observed = request;
            return Json(
                request.Method == HttpMethod.Get ? HttpStatusCode.OK : HttpStatusCode.Accepted,
                request.RequestUri!.AbsolutePath == "/pools" ? Array.Empty<object>() : new { ok = true });
        });

        var result = await RunAsync(arguments, handler);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(method, observed!.Method.Method);
        Assert.Equal(path, observed.RequestUri!.PathAndQuery);
    }

    [Theory]
    [InlineData("harbor")]
    [InlineData("saber")]
    [InlineData("process")]
    [InlineData("compose")]
    public async Task Typed_workload_submission_uses_executable_route(string kind)
    {
        JsonElement body = default;
        var handler = new StubHandler(async request =>
        {
            body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync()).RootElement.Clone();
            return Json(HttpStatusCode.Created, new { ok = true });
        });
        var result = await RunAsync(
            ["workload", "submit", kind, "--input", "{}", "--pool-id", Id,
                "--idempotency-key", "request-1"], handler);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(kind, body.GetProperty("kind").GetString());
        Assert.Equal("request-1", body.GetProperty("idempotencyKey").GetString());
    }

    [Fact]
    public async Task Mutation_token_file_is_forwarded_but_cli_token_option_is_rejected()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "token-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "mutation-token");
        await File.WriteAllTextAsync(path, "local-control-token");
        var oldFile = Environment.GetEnvironmentVariable(
            EnvironmentOrFileMutationTokenProvider.TokenFileEnvironmentVariable);
        var oldToken = Environment.GetEnvironmentVariable(
            EnvironmentOrFileMutationTokenProvider.TokenEnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable(
                EnvironmentOrFileMutationTokenProvider.TokenEnvironmentVariable, null);
            Environment.SetEnvironmentVariable(
                EnvironmentOrFileMutationTokenProvider.TokenFileEnvironmentVariable, path);
            string? token = null;
            var handler = new StubHandler(request =>
            {
                token = request.Headers.GetValues(ControlClient.MutationTokenHeader).Single();
                return Json(HttpStatusCode.Accepted, new { accepted = true });
            });
            Assert.Equal(0, (await RunAsync(
                ["workload", "cancel", "--id", Id], handler)).ExitCode);
            Assert.Equal("local-control-token", token);

            var called = false;
            var rejected = await RunAsync(
                ["doctor", "--mutation-token", "forbidden"],
                new StubHandler(_ =>
                {
                    called = true;
                    return Json(HttpStatusCode.OK, new { });
                }));
            Assert.Equal(2, rejected.ExitCode);
            Assert.False(called);
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                EnvironmentOrFileMutationTokenProvider.TokenFileEnvironmentVariable, oldFile);
            Environment.SetEnvironmentVariable(
                EnvironmentOrFileMutationTokenProvider.TokenEnvironmentVariable, oldToken);
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task Bounds_reject_events_and_agent_text_before_http()
    {
        var called = false;
        var handler = new StubHandler(_ =>
        {
            called = true;
            return Json(HttpStatusCode.OK, new { });
        });
        Assert.Equal(2, (await RunAsync(
            ["task", "events", "--id", Id, "--limit", "101"], handler)).ExitCode);
        Assert.Equal(2, (await RunAsync(
            ["agent", "turn", "--id", Id, "--text", new string('x', 65_537)], handler)).ExitCode);
        Assert.False(called);
    }

    [Fact]
    public async Task Terminal_commands_use_structured_files_and_exact_routes()
    {
        var directory = Path.Combine(
            AppContext.BaseDirectory, "terminal-cli-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var session = new TerminalSessionId(Guid.Parse(Id));
        var host = HostId.New();
        var node = NodeIncarnationId.New();
        var now = DateTimeOffset.UtcNow;
        var authority = new TerminalAuthority(
            TerminalContractLimits.SchemaVersion, session, host, node, "local-user",
            @"C:\workspace", null, now, now, now.AddMinutes(5), TimeSpan.FromMinutes(5),
            1_048_576, 16_777_216, TerminalTranscriptMode.Metadata, 0,
            TerminalFileTransferCapabilities.None, false, false, 0);
        var context = new TerminalOperationContext(host, node, "local-user", 0);
        var cases = new (string[] Words, object Request, string Route)[]
        {
            (["terminal", "authority", "issue"], new IssueTerminalAuthorityRequest(
                host, node, "local-user", @"C:\workspace", null, TimeSpan.FromMinutes(5)), "/terminals/authorities"),
            (["terminal", "open"], new TerminalOpenRequest(
                TerminalContractLimits.SchemaVersion, "open-1", authority, TerminalShellKind.PowerShell,
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", [],
                @"C:\workspace", 100, 30), "/terminals/open"),
            (["terminal", "input", "--id", Id], new TerminalInputRequest(
                session, context, "input-1", 1, new byte[] { 1 }), $"/terminals/{Id}/input"),
            (["terminal", "resize", "--id", Id], new TerminalResizeRequest(
                session, context, "resize-1", 2, 100, 30), $"/terminals/{Id}/resize"),
            (["terminal", "output", "--id", Id], new TerminalOutputReadRequest(
                session, context, 0, 0, 10, 4096, false), $"/terminals/{Id}/output"),
            (["terminal", "close", "--id", Id], new TerminalCloseRequest(
                session, context, "close-1", 3, TimeSpan.FromSeconds(1)), $"/terminals/{Id}/close")
        };
        try
        {
            foreach (var (words, request, route) in cases)
            {
                var file = Path.Combine(directory, $"{Guid.NewGuid():N}.json");
                await File.WriteAllTextAsync(file, JsonSerializer.Serialize(request, StewardJson.Options));
                string? actual = null;
                var handler = new StubHandler(message =>
                {
                    actual = message.RequestUri!.AbsolutePath;
                    return Json(HttpStatusCode.OK, new { ok = true });
                });
                var arguments = words.Concat(["--request-file", file]).ToArray();
                var result = await RunAsync(arguments, handler);
                Assert.Equal(0, result.ExitCode);
                Assert.Equal(route, actual);
            }
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task Artifact_download_writes_only_explicit_safe_local_file()
    {
        var directory = Path.Combine(
            AppContext.BaseDirectory, "artifact-cli-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var destination = Path.Combine(directory, "artifact.bin");
        try
        {
            var handler = new StubHandler(request =>
            {
                Assert.Equal($"/artifacts/{Id}/download", request.RequestUri!.AbsolutePath);
                var content = new ByteArrayContent("artifact-bytes"u8.ToArray());
                content.Headers.ContentType = new("application/octet-stream");
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = content
                };
            });
            var result = await RunAsync(
                ["artifact", "download", "--id", Id, "--output", destination], handler);
            Assert.Equal(0, result.ExitCode);
            Assert.Equal("artifact-bytes", await File.ReadAllTextAsync(destination));
            Assert.Contains("\"bytesWritten\":14", result.Output, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    public static TheoryData<string[]> BackupRelativeCases => new()
    {
        new[] { "backup", "export", "--destination-directory", "relative" },
        new[] { "backup", "validate", "--database-path", "relative.db", "--manifest-path", "manifest.json" },
        new[] { "backup", "restore", "--database-path", "relative.db", "--manifest-path", "manifest.json", "--destination-path", "restored.db" }
    };

    [Theory]
    [MemberData(nameof(BackupRelativeCases))]
    public async Task Backup_commands_reject_relative_paths_before_http(string[] arguments)
    {
        var called = false;
        var result = await RunAsync(arguments, new StubHandler(_ =>
        {
            called = true;
            return Json(HttpStatusCode.OK, new { });
        }));
        Assert.Equal(2, result.ExitCode);
        Assert.False(called);
        Assert.Contains("absolute local path", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Backup_commands_map_structured_routes_and_mutation_header()
    {
        var oldToken = Environment.GetEnvironmentVariable(
            EnvironmentOrFileMutationTokenProvider.TokenEnvironmentVariable);
        var oldFile = Environment.GetEnvironmentVariable(
            EnvironmentOrFileMutationTokenProvider.TokenFileEnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable(
                EnvironmentOrFileMutationTokenProvider.TokenEnvironmentVariable, "backup-token");
            Environment.SetEnvironmentVariable(
                EnvironmentOrFileMutationTokenProvider.TokenFileEnvironmentVariable, null);
            var requests = new List<(string Path, string Token, JsonElement Body)>();
            var handler = new StubHandler(async request =>
            {
                requests.Add((
                    request.RequestUri!.AbsolutePath,
                    request.Headers.GetValues(ControlClient.MutationTokenHeader).Single(),
                    JsonDocument.Parse(await request.Content!.ReadAsStringAsync()).RootElement.Clone()));
                return Json(HttpStatusCode.OK, new { ok = true });
            });

            Assert.Equal(0, (await RunAsync(
                ["backup", "export", "--destination-directory", @"C:\backups"], handler)).ExitCode);
            Assert.Equal(0, (await RunAsync(
                ["backup", "validate", "--database-path", @"C:\backups\control.db",
                    "--manifest-path", @"C:\backups\manifest.json"], handler)).ExitCode);
            Assert.Equal(0, (await RunAsync(
                ["backup", "restore", "--database-path", @"C:\backups\control.db",
                    "--manifest-path", @"C:\backups\manifest.json",
                    "--destination-path", @"C:\restore\control.db"], handler)).ExitCode);

            Assert.Equal(
                ["/backups/export", "/backups/validate", "/backups/restore"],
                requests.Select(x => x.Path));
            Assert.All(requests, request => Assert.Equal("backup-token", request.Token));
            Assert.Equal(@"C:\backups",
                requests[0].Body.GetProperty("destinationDirectory").GetString());
            Assert.Equal(@"C:\restore\control.db",
                requests[2].Body.GetProperty("destinationPath").GetString());
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                EnvironmentOrFileMutationTokenProvider.TokenEnvironmentVariable, oldToken);
            Environment.SetEnvironmentVariable(
                EnvironmentOrFileMutationTokenProvider.TokenFileEnvironmentVariable, oldFile);
        }
    }

    private static async Task<Result> RunAsync(
        IReadOnlyList<string> arguments,
        HttpMessageHandler handler,
        IDevBoxCommandService? devBoxCommands = null)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exitCode = await CliApplication.RunAsync(
            arguments,
            output,
            error,
            CancellationToken.None,
            handler,
            devBoxCommands);
        return new(exitCode, output.ToString(), error.ToString());
    }

    private static HttpResponseMessage Json(
        HttpStatusCode status,
        object value) =>
        new(status)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(value, StewardJson.Options),
                Encoding.UTF8,
                "application/json")
        };

    private sealed class StubHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handle)
        : HttpMessageHandler
    {
        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handle)
            : this(request => Task.FromResult(handle(request)))
        {
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            handle(request);
    }

    private sealed class FakeDevBoxCommands : IDevBoxCommandService
    {
        public bool LoginCalled { get; private set; }

        public Task<DevBoxIdentityStatus> LoginAsync(
            CancellationToken cancellationToken)
        {
            LoginCalled = true;
            return StatusAsync(cancellationToken);
        }

        public Task<DevBoxIdentityStatus> StatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new DevBoxIdentityStatus(
                1, DevBoxIdentityConstants.ContextName, true, Id, "user@example.test",
                DateTimeOffset.UnixEpoch, null));

        public Task<DevBoxIdentityStatus> LogoutAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new DevBoxIdentityStatus(
                1, DevBoxIdentityConstants.ContextName, false, null, null, null, null));

        public Task<DevBoxInventory> DiscoverAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new DevBoxInventory(
                1, DevBoxIdentityConstants.ContextName, Id, "user@example.test", [], [], []));
    }

    private sealed record Result(int ExitCode, string Output, string Error);
}
