using Steward.Node.Host;
using Steward.Stack.Local;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddOptions<NodeHostOptions>()
    .Bind(builder.Configuration.GetSection("NodeHost"));
builder.Services.AddStewardLocalStack(builder.Configuration);
builder.Services.AddStewardLocalNodeTransport();
builder.Services.AddHostedService<ProductionNodeWorker>();
await builder.Build().RunAsync();
