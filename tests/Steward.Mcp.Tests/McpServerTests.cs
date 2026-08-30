using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Steward.Agents;
using Steward.Application;
using Steward.Cli;
using Steward.Contracts;
using Steward.Domain;
using Steward.Mcp;
using Steward.Terminal.Abstractions;

namespace Steward.Mcp.Tests;

public sealed class McpServerTests
{
    private static readonly string[] ExpectedTools =
    [
        "acknowledge_agent_notifications",
        "acknowledge_notifications",
        "agent_run_next",
        "cancel_agent_turn",
        "cancel_workload",
        "close_terminal",
        "create_agent",
        "delete_host",
        "doctor",
        "drain_host",
        "get_agent",
        "get_artifact",
        "get_artifact_download",
        "get_attempt",
        "get_host",
        "get_pool",
        "get_task",
        "get_terminal",
        "get_workload",
        "issue_terminal_authority",
        "list_hosts",
        "list_pools",
        "migrate_agent",
        "open_terminal",
        "orchestration_doctor",
        "read_agent_notifications",
        "read_notifications",
        "read_task_events",
        "read_terminal_output",
        "reconcile_pool",
        "recreate_host",
        "resize_terminal",
        "resolve_task_recovery",
        "retry_task",
        "revoke_terminal",
        "send_terminal_input",
        "start_host",
        "stop_host",
        "submit_agent_turn",
        "submit_workload"
    ];

    [Fact]
    public async Task Discovery_exposes_exact_agent_safe_allowlist()
    {
        await using var fixture = new McpFixture();
        await using var client = await fixture.ConnectAsync();
        var tools = await client.ListToolsAsync();

        Assert.Equal(ExpectedTools, tools.Select(tool => tool.Name).Order());
        Assert.DoesNotContain(tools, tool =>
            new[] { "shell", "token", "credential", "database", "sql", "backup", "restore" }
                .Any(value => tool.Name.Contains(value, StringComparison.OrdinalIgnoreCase)));
        Assert.Contains(tools, tool => tool.Name == "submit_workload" &&
            tool.Description!.Contains("untrusted inert data", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Tools_use_control_routes_and_bound_untrusted_output_without_secrets()
    {
        await using var fixture = new McpFixture();
        await using var client = await fixture.ConnectAsync();
        var workload = Guid.NewGuid().ToString();

        var result = ToolJson(await client.CallToolAsync("get_workload",
            new Dictionary<string, object?> { ["workloadId"] = workload }));
        Assert.True(result.RootElement.GetProperty("success").GetBoolean());
        var data = result.RootElement.GetProperty("result").GetProperty("dataJson").GetString()!;
        Assert.Contains("UNTRUSTED_OUTPUT", data, StringComparison.Ordinal);
        Assert.DoesNotContain("databasePath", data, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("bearerToken", data, StringComparison.OrdinalIgnoreCase);
        Assert.True(data.Length <= 65_536);
        Assert.Contains(fixture.Handler.Requests, request =>
            request.Method == HttpMethod.Get && request.PathAndQuery == $"/workloads/{workload}");
    }

    [Fact]
    public async Task Pagination_and_text_inputs_are_bounded_before_http()
    {
        await using var fixture = new McpFixture();
        await using var client = await fixture.ConnectAsync();
        var task = Guid.NewGuid().ToString();
        var agent = Guid.NewGuid().ToString();

        var events = ToolJson(await client.CallToolAsync("read_task_events",
            new Dictionary<string, object?>
            {
                ["taskId"] = task,
                ["afterCursor"] = 0,
                ["limit"] = 51
            }));
        Assert.Equal("InvalidArgument", events.RootElement.GetProperty("code").GetString());

        var turn = ToolJson(await client.CallToolAsync("submit_agent_turn",
            new Dictionary<string, object?>
            {
                ["agentId"] = agent,
                ["text"] = new string('x', 65_537)
            }));
        Assert.Equal("InvalidArgument", turn.RootElement.GetProperty("code").GetString());
        Assert.DoesNotContain(fixture.Handler.Requests, request =>
            request.PathAndQuery.Contains("/events", StringComparison.Ordinal) ||
            request.PathAndQuery.Contains("/turns", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Stable_control_problem_code_is_preserved()
    {
        await using var fixture = new McpFixture();
        fixture.Handler.ErrorCode = "NotFound";
        await using var client = await fixture.ConnectAsync();
        var result = ToolJson(await client.CallToolAsync("get_artifact",
            new Dictionary<string, object?> { ["artifactId"] = Guid.NewGuid().ToString() }));
        Assert.False(result.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("NotFound", result.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Mutation_tools_forward_token_from_provider_without_output_exposure()
    {
        await using var fixture = new McpFixture("local-secret-value");
        await using var client = await fixture.ConnectAsync();
        var result = ToolJson(await client.CallToolAsync("cancel_workload",
            new Dictionary<string, object?> { ["workloadId"] = Guid.NewGuid().ToString() }));
        Assert.True(result.RootElement.GetProperty("success").GetBoolean());
        Assert.Contains(fixture.Handler.Requests, request =>
            request.MutationToken == "local-secret-value");
        Assert.DoesNotContain("local-secret-value", result.RootElement.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_and_pool_mutations_require_configured_token()
    {
        await using var fixture = new McpFixture();
        await using var client = await fixture.ConnectAsync();
        var host = Guid.NewGuid().ToString();
        var pool = Guid.NewGuid().ToString();

        var hostResult = ToolJson(await client.CallToolAsync("start_host",
            new Dictionary<string, object?> { ["hostId"] = host }));
        var poolResult = ToolJson(await client.CallToolAsync("reconcile_pool",
            new Dictionary<string, object?>
            {
                ["poolId"] = pool,
                ["demands"] = Array.Empty<object>()
            }));
        Assert.Equal("MutationTokenRequired", hostResult.RootElement.GetProperty("code").GetString());
        Assert.Equal("MutationTokenRequired", poolResult.RootElement.GetProperty("code").GetString());
        Assert.DoesNotContain(fixture.Handler.Requests, request =>
            request.PathAndQuery.Contains(host, StringComparison.Ordinal) ||
            request.PathAndQuery.Contains(pool, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Added_parity_tools_use_existing_bounded_routes()
    {
        await using var fixture = new McpFixture("configured-token");
        await using var client = await fixture.ConnectAsync();
        var host = Guid.NewGuid().ToString();
        var pool = Guid.NewGuid().ToString();
        var agent = Guid.NewGuid().ToString();

        await client.CallToolAsync("orchestration_doctor");
        await client.CallToolAsync("reconcile_pool", new Dictionary<string, object?>
        {
            ["poolId"] = pool,
            ["demands"] = new[] { new { demandId = "demand-1" } }
        });
        await client.CallToolAsync("start_host",
            new Dictionary<string, object?> { ["hostId"] = host });
        foreach (var tool in new[] { "drain_host", "stop_host", "recreate_host", "delete_host" })
            await client.CallToolAsync(tool,
                new Dictionary<string, object?> { ["hostId"] = host, ["force"] = false });
        await client.CallToolAsync("agent_run_next",
            new Dictionary<string, object?> { ["agentId"] = agent });
        await client.CallToolAsync("read_notifications", new Dictionary<string, object?>
        {
            ["stream"] = "agent:test", ["afterCursor"] = 2, ["limit"] = 3
        });
        await client.CallToolAsync("acknowledge_notifications", new Dictionary<string, object?>
        {
            ["stream"] = "agent:test", ["throughCursor"] = 4
        });

        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == "/doctor/orchestration");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/pools/{pool}/reconcile");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/hosts/{host}/start");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/hosts/{host}/drain?force=false");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/hosts/{host}/stop?force=false");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/hosts/{host}/recreate?force=false");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/hosts/{host}?force=false");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/agents/{agent}/run-next");
        Assert.Contains(fixture.Handler.Requests,
            x => x.PathAndQuery == "/notifications/agent%3Atest?after=2&limit=3");
        Assert.Contains(fixture.Handler.Requests,
            x => x.PathAndQuery == "/notifications/agent%3Atest/ack/4");
    }

    [Fact]
    public async Task Agent_migration_accepts_only_bounded_structured_checkpoint()
    {
        await using var fixture = new McpFixture("configured-token");
        await using var client = await fixture.ConnectAsync();
        var agent = StewardAgentId.New();
        var migration = new AgentMigrationRequest(
            HostId.New(),
            HostId.New(),
            new GitArtifact("application/x-git-bundle", [], new string('a', 64)),
            new GitArtifact("text/x-diff", [], new string('b', 64)),
            new AgentEnvironmentManifest([], []),
            []);
        var result = ToolJson(await client.CallToolAsync("migrate_agent",
            new Dictionary<string, object?>
            {
                ["agentId"] = agent.ToString(),
                ["request"] = JsonSerializer.SerializeToElement(migration, StewardJson.Options)
            }));
        Assert.True(result.RootElement.GetProperty("success").GetBoolean());
        Assert.Contains(fixture.Handler.Requests,
            x => x.PathAndQuery == $"/agents/{agent}/migrate");

        migration = migration with
        {
            GitBundle = migration.GitBundle with { Content = new byte[16_385] }
        };
        var rejected = ToolJson(await client.CallToolAsync("migrate_agent",
            new Dictionary<string, object?>
            {
                ["agentId"] = agent.ToString(),
                ["request"] = JsonSerializer.SerializeToElement(migration, StewardJson.Options)
            }));
        Assert.Equal("InvalidArgument", rejected.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Terminal_tools_match_routes_and_enforce_output_bounds()
    {
        await using var fixture = new McpFixture("configured-token");
        await using var client = await fixture.ConnectAsync();
        var session = TerminalSessionId.New();
        var host = HostId.New();
        var node = NodeIncarnationId.New();
        var now = DateTimeOffset.UtcNow;
        var authority = new TerminalAuthority(
            TerminalContractLimits.SchemaVersion,
            session,
            host,
            node,
            "local-user",
            @"C:\workspace",
            null,
            now,
            now,
            now.AddMinutes(5),
            TimeSpan.FromMinutes(5),
            1_048_576,
            16_777_216,
            TerminalTranscriptMode.Metadata,
            0,
            TerminalFileTransferCapabilities.None,
            false,
            false,
            0);
        await client.CallToolAsync("issue_terminal_authority", new Dictionary<string, object?>
        {
            ["hostId"] = host.ToString(),
            ["nodeIncarnationId"] = node.ToString(),
            ["actor"] = "local-user",
            ["workspaceRoot"] = @"C:\workspace",
            ["durationSeconds"] = 300,
            ["elevationRequested"] = false
        });
        await client.CallToolAsync("open_terminal", new Dictionary<string, object?>
        {
            ["request"] = JsonSerializer.SerializeToElement(new TerminalOpenRequest(
                TerminalContractLimits.SchemaVersion, "open-1", authority,
                TerminalShellKind.PowerShell, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                [], @"C:\workspace", 120, 40), StewardJson.Options)
        });
        await client.CallToolAsync("get_terminal",
            new Dictionary<string, object?> { ["sessionId"] = session.ToString() });
        Assert.True(ToolJson(await client.CallToolAsync("send_terminal_input", new Dictionary<string, object?>
        {
            ["sessionId"] = session.ToString(),
            ["hostId"] = host.ToString(),
            ["nodeIncarnationId"] = node.ToString(),
            ["actor"] = "local-user",
            ["currentRevocationRevision"] = 0,
            ["requestId"] = "input-1",
            ["expectedRevision"] = 1,
            ["dataBase64"] = Convert.ToBase64String([1, 2])
        })).RootElement.GetProperty("success").GetBoolean());
        Assert.True(ToolJson(await client.CallToolAsync("resize_terminal", new Dictionary<string, object?>
        {
            ["sessionId"] = session.ToString(),
            ["hostId"] = host.ToString(),
            ["nodeIncarnationId"] = node.ToString(),
            ["actor"] = "local-user",
            ["currentRevocationRevision"] = 0,
            ["requestId"] = "resize-1",
            ["expectedRevision"] = 2,
            ["columns"] = 100,
            ["rows"] = 30
        })).RootElement.GetProperty("success").GetBoolean());
        Assert.True(ToolJson(await client.CallToolAsync("read_terminal_output", new Dictionary<string, object?>
        {
            ["sessionId"] = session.ToString(),
            ["hostId"] = host.ToString(),
            ["nodeIncarnationId"] = node.ToString(),
            ["actor"] = "local-user",
            ["currentRevocationRevision"] = 0,
            ["afterSequence"] = 0,
            ["afterOffset"] = 0,
            ["maximumItems"] = 10,
            ["maximumBytes"] = 4096,
            ["follow"] = false
        })).RootElement.GetProperty("success").GetBoolean());
        Assert.True(ToolJson(await client.CallToolAsync("close_terminal", new Dictionary<string, object?>
        {
            ["sessionId"] = session.ToString(),
            ["hostId"] = host.ToString(),
            ["nodeIncarnationId"] = node.ToString(),
            ["actor"] = "local-user",
            ["currentRevocationRevision"] = 0,
            ["requestId"] = "close-1",
            ["expectedRevision"] = 3,
            ["gracePeriodSeconds"] = 1
        })).RootElement.GetProperty("success").GetBoolean());
        await client.CallToolAsync("revoke_terminal",
            new Dictionary<string, object?> { ["sessionId"] = session.ToString() });

        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == "/terminals/authorities");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == "/terminals/open");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/terminals/{session}");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/terminals/{session}/input");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/terminals/{session}/resize");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/terminals/{session}/output");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/terminals/{session}/close");
        Assert.Contains(fixture.Handler.Requests, x => x.PathAndQuery == $"/terminals/{session}/revoke");

        var rejected = ToolJson(await client.CallToolAsync("read_terminal_output",
            new Dictionary<string, object?>
            {
                ["sessionId"] = session.ToString(),
                ["hostId"] = host.ToString(),
                ["nodeIncarnationId"] = node.ToString(),
                ["actor"] = "local-user",
                ["currentRevocationRevision"] = 0,
                ["afterSequence"] = 0,
                ["afterOffset"] = 0,
                ["maximumItems"] = 51,
                ["maximumBytes"] = 65_537,
                ["follow"] = false
            }));
        Assert.Equal("InvalidArgument", rejected.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Artifact_download_tool_returns_only_opaque_reference()
    {
        await using var fixture = new McpFixture();
        await using var client = await fixture.ConnectAsync();
        var id = Guid.NewGuid().ToString();
        var result = ToolJson(await client.CallToolAsync("get_artifact_download",
            new Dictionary<string, object?> { ["artifactId"] = id }));
        var data = result.RootElement.GetProperty("result").GetProperty("dataJson").GetString()!;
        Assert.Contains($"steward-artifact:{id}", data, StringComparison.Ordinal);
        Assert.DoesNotContain("?", data, StringComparison.Ordinal);
        Assert.DoesNotContain("sas", data, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(fixture.Handler.Requests,
            x => x.PathAndQuery == $"/artifacts/{id}/download");
    }

    [Fact]
    public async Task Rejects_unapproved_host_header_and_has_no_cors()
    {
        await using var fixture = new McpFixture();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp");
        request.Headers.Host = "example.com";
        request.Content = new StringContent("{}", Encoding.UTF8, "application/json");
        using var response = await fixture.Factory.CreateClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Theory]
    [InlineData("http://*:5113")]
    [InlineData("http://+:5113")]
    [InlineData("http://0.0.0.0:5113")]
    [InlineData("http://[::]:5113")]
    [InlineData("http://localhost:5113;;http://127.0.0.1:5113")]
    public void Rejects_non_loopback_and_malformed_bindings(string url) =>
        Assert.Throws<InvalidOperationException>(() => McpHostSecurity.ValidateLoopbackBinding(url));

    private static JsonDocument ToolJson(CallToolResult result)
    {
        Assert.False(result.IsError ?? false);
        return JsonDocument.Parse(Assert.Single(result.Content.OfType<TextContentBlock>()).Text);
    }

    private sealed class McpFixture : IAsyncDisposable
    {
        public RecordingHandler Handler { get; } = new();
        public WebApplicationFactory<Program> Factory { get; }

        public McpFixture(string? mutationToken = null)
        {
            var control = new ControlClient(
                new HttpClient(Handler) { BaseAddress = new Uri("http://localhost") },
                new FixedTokenProvider(mutationToken));
            Factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting(WebHostDefaults.ServerUrlsKey, "http://127.0.0.1:5113");
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<ControlClient>();
                    services.AddSingleton(control);
                });
            });
        }

        public Task<McpClient> ConnectAsync()
        {
            var http = Factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("http://localhost")
            });
            return McpClient.CreateAsync(new HttpClientTransport(
                new()
                {
                    Endpoint = new Uri("http://localhost/mcp"),
                    TransportMode = HttpTransportMode.StreamableHttp,
                    Name = "Steward MCP tests"
                }, http));
        }

        public ValueTask DisposeAsync() => Factory.DisposeAsync();
    }

    private sealed class FixedTokenProvider(string? value) : IControlMutationTokenProvider
    {
        public ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(value);
    }

    public sealed record RecordedRequest(HttpMethod Method, string PathAndQuery, string? MutationToken);

    public sealed class RecordingHandler : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];
        public string? ErrorCode { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new(
                request.Method,
                request.RequestUri!.PathAndQuery,
                request.Headers.TryGetValues(ControlClient.MutationTokenHeader, out var values)
                    ? values.Single() : null));
            if (ErrorCode is not null)
                return Task.FromResult(Json(HttpStatusCode.NotFound,
                    new { code = ErrorCode, detail = "safe detail" }));
            if (request.Method == HttpMethod.Get && request.RequestUri.AbsolutePath.StartsWith(
                    "/workloads/", StringComparison.Ordinal))
                return Task.FromResult(Json(HttpStatusCode.OK, new
                {
                    status = "Running",
                    output = "UNTRUSTED_OUTPUT",
                    databasePath = @"C:\private\control.db",
                    bearerToken = "never-return",
                    log = new string('z', 70_000)
                }));
            if (request.Method == HttpMethod.Get)
                return Task.FromResult(Json(HttpStatusCode.OK, Array.Empty<object>()));
            return Task.FromResult(Json(HttpStatusCode.Accepted, new { accepted = true }));
        }

        private static HttpResponseMessage Json(HttpStatusCode status, object value) => new(status)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
        };
    }
}
