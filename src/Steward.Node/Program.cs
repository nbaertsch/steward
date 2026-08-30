using Steward.Node;
using Steward.Transport;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.Configure<NodeSessionOptions>(builder.Configuration.GetSection("Node"));
builder.Services.AddSingleton(sp =>
{
    var configured = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<NodeSessionOptions>>().Value;
    return new NodeJournal(configured.JournalPath);
});
builder.Services.AddSingleton<INodeClock, SystemNodeClock>();
builder.Services.AddSingleton<IJitterSource, SystemJitterSource>();
builder.Services.AddSingleton<IHostBootIdentityProvider, UnverifiedProcessBootIdentityProvider>();
builder.Services.AddSingleton<ITransportCarrier>(_ =>
{
    var secure = new VerifiedSessionSecurity(true, true, "node", "control", "in-memory-development");
    return InMemoryDuplexCarrier.CreatePair(secure, secure).First;
});
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
