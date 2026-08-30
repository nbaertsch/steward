using ModelContextProtocol.AspNetCore;
using Steward.Application;
using Steward.Cli;
using Steward.Mcp;

var builder = WebApplication.CreateBuilder(args);

var configuredUrls = builder.Configuration["urls"]
    ?? Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
if (string.IsNullOrWhiteSpace(configuredUrls))
{
    configuredUrls = "http://127.0.0.1:5113";
    builder.WebHost.UseUrls(configuredUrls);
}

McpHostSecurity.ValidateLoopbackBinding(configuredUrls);

var controlUrl = builder.Configuration["Mcp:ControlUrl"] ?? "http://127.0.0.1:5112/";
LoopbackBindingValidator.Validate(controlUrl, "Steward MCP Control client");
builder.Services.AddSingleton<IControlMutationTokenProvider, EnvironmentOrFileMutationTokenProvider>();
builder.Services.AddHttpClient<ControlClient>(client => client.BaseAddress = new Uri(controlUrl));
builder.Services.AddHostFiltering(options =>
    options.AllowedHosts = ["localhost", "127.0.0.1", "[::1]"]);
builder.Services
    .AddMcpServer()
    .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
    .WithTools<StewardTools>();

var app = builder.Build();

app.UseHostFiltering();
app.MapMcp("/mcp");

await app.RunAsync();

public partial class Program;
