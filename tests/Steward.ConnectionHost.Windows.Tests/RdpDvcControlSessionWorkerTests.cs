using System.IO.Pipes;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;
using Steward.Scheduling;
using Steward.Stack.Local;
using Steward.Transport;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class RdpDvcControlSessionWorkerTests : IDisposable
{
    private readonly string root = Path.Combine(AppContext.BaseDirectory,
        "control-generation-worker", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Replay_sends_ready_then_typed_generation_rejection()
    {
        await using var fixture = await WorkerFixture.CreateAsync(root);
        await fixture.RunAcceptedAsync(fixture.Attachment(2));
        AssertRejected(await fixture.RunAttemptAsync(fixture.Attachment(2)));
    }

    [Fact]
    public async Task Session_rebinding_sends_ready_then_typed_generation_rejection()
    {
        await using var fixture = await WorkerFixture.CreateAsync(root);
        await fixture.SeedHighWaterAsync(
            fixture.Attachment(1, Guid.NewGuid()));
        AssertRejected(await fixture.RunAttemptAsync(fixture.Attachment(2)));
    }

    [Fact]
    public async Task Generation_rollback_sends_ready_then_typed_generation_rejection()
    {
        await using var fixture = await WorkerFixture.CreateAsync(root);
        await fixture.RunAcceptedAsync(fixture.Attachment(3));
        AssertRejected(await fixture.RunAttemptAsync(fixture.Attachment(2)));
    }

    private static void AssertRejected(
        IReadOnlyList<ReconnectCarrierControlMessage> responses)
    {
        Assert.Collection(responses,
            ready => Assert.Equal(ReconnectCarrierControlPhase.RelayReady,
                ready.Phase),
            failed =>
            {
                Assert.Equal(ReconnectCarrierControlPhase.Failed, failed.Phase);
                Assert.Equal(ReconnectCarrierFailure.GenerationRejected,
                    failed.Failure);
            });
        Assert.DoesNotContain(responses, x => x.Phase ==
            ReconnectCarrierControlPhase.SecureSessionAuthenticated);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(root)) Directory.Delete(root, true);
    }

    private sealed class WorkerFixture : IAsyncDisposable
    {
        private readonly ECDsa controlKey;
        private readonly ECDsa nodeKey;
        private readonly RdpDvcControlSessionWorker worker;
        private readonly ControlOrchestrator orchestrator;
        private readonly SqliteControlStore store;
        private readonly string pipeName;
        private readonly NodeEndpointRegistration endpoint;

        private WorkerFixture(ECDsa controlKey, ECDsa nodeKey,
            RdpDvcControlSessionWorker worker, ControlOrchestrator orchestrator,
            SqliteControlStore store, string pipeName,
            NodeEndpointRegistration endpoint)
        {
            this.controlKey = controlKey;
            this.nodeKey = nodeKey;
            this.worker = worker;
            this.orchestrator = orchestrator;
            this.store = store;
            this.pipeName = pipeName;
            this.endpoint = endpoint;
        }

        public static async Task<WorkerFixture> CreateAsync(string root)
        {
            Directory.CreateDirectory(root);
            var controlKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var nodeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var controlPrivate = Path.Combine(root, "control.pk8.pem");
            var nodePublic = Path.Combine(root, "node.spki.pem");
            await File.WriteAllTextAsync(controlPrivate,
                controlKey.ExportPkcs8PrivateKeyPem());
            await File.WriteAllTextAsync(nodePublic,
                nodeKey.ExportSubjectPublicKeyInfoPem());
            var store = new SqliteControlStore(Path.Combine(root, "control.db"));
            var schedulerStore = new InMemorySchedulerStateStore();
            var orchestrator = new ControlOrchestrator(store,
                new CompositeScheduler(schedulerStore), schedulerStore,
                new(new(100, TimeSpan.FromHours(1), TimeSpan.FromMinutes(5),
                    1024 * 1024, 4)));
            await orchestrator.InitializeAsync();
            var sessionId = Guid.NewGuid();
            var endpoint = new NodeEndpointRegistration(HostId.New(),
                NodeIncarnationId.New(), PoolId.New(),
                LocalStackOptions.TransportBinding(new LocalDirectTransportBinding(
                    LocalDirectDialDirection.ControlDialsNode,
                    new Uri("ws://127.0.0.1:45123/steward/"), sessionId)),
                "node", nodePublic, new ResourceRequirements(1), [], [],
                DateTimeOffset.UtcNow);
            var registrations = new ControlNodeRegistrationStore(store);
            await registrations.RegisterAsync(endpoint);
            var pipeName = "Steward.Control.Worker." + Guid.NewGuid().ToString("N");
            var options = new ValidatedLocalStackOptions(root, root, root, true,
                "control", controlPrivate, [endpoint], 64 * 1024, 8, true,
                pipeName);
            var identity = new DirectSessionControlIdentityHandler(
                new LocalControlIdentityGrantCatalog(
                    new InMemoryProtectedIdentityVault(),
                    new LocalIdentityGrantStore(Path.Combine(root, "identity.db"))));
            var worker = new RdpDvcControlSessionWorker(options, store,
                registrations, orchestrator, new ControlTerminalRouter(),
                new ControlTerminalRevocationStore(store), identity, [],
                new ControlNodeLivenessRegistry(),
                NullLogger<RdpDvcControlSessionWorker>.Instance);
            await worker.StartAsync(CancellationToken.None);
            return new(controlKey, nodeKey, worker, orchestrator, store,
                pipeName, endpoint);
        }

        public ReconnectCarrierAttachment Attachment(long generation,
            Guid? sessionId = null)
        {
            var configured = endpoint.Transport
                .DeserializeData<LocalDirectTransportBinding>()!.SessionId!.Value;
            return new(sessionId ?? configured,
                new(2, endpoint.HostId, endpoint.NodeIncarnationId, generation,
                    Guid.NewGuid(), 42,
                    Convert.ToHexString(RandomNumberGenerator.GetBytes(32)))
                { RouteId = endpoint.HostId.Value });
        }

        public async Task RunAcceptedAsync(ReconnectCarrierAttachment attachment)
        {
            var responses = await RunAttemptAsync(attachment);
            Assert.Collection(responses,
                x => Assert.Equal(ReconnectCarrierControlPhase.RelayReady, x.Phase),
                x => Assert.Equal(
                    ReconnectCarrierControlPhase.SecureSessionAuthenticated,
                    x.Phase));
        }

        public async Task SeedHighWaterAsync(ReconnectCarrierAttachment attachment)
        {
            await using var connection = await store.OpenConnectionAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS control_reconnect_high_water(
                    host_id TEXT NOT NULL,node_incarnation_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,generation INTEGER NOT NULL,
                    attempt_id TEXT NOT NULL,updated_at TEXT NOT NULL,
                    PRIMARY KEY(host_id,node_incarnation_id));
                INSERT INTO control_reconnect_high_water(
                    host_id,node_incarnation_id,session_id,generation,
                    attempt_id,updated_at)
                VALUES($host,$incarnation,$session,$generation,$attempt,$updated);
                """;
            command.Parameters.AddWithValue("$host", attachment.HostId.ToString());
            command.Parameters.AddWithValue("$incarnation",
                attachment.NodeIncarnationId.ToString());
            command.Parameters.AddWithValue("$session",
                attachment.SessionId.ToString("D"));
            command.Parameters.AddWithValue("$generation",
                attachment.Binding.ReconnectGeneration);
            command.Parameters.AddWithValue("$attempt",
                attachment.AttemptId.ToString("D"));
            command.Parameters.AddWithValue("$updated",
                DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync();
        }

        public async Task<IReadOnlyList<ReconnectCarrierControlMessage>>
            RunAttemptAsync(ReconnectCarrierAttachment attachment)
        {
            await using var responses = new NamedPipeServerStream(
                ReconnectCarrierAttachmentCodec.AcknowledgementPipeName(
                    pipeName, attachment.AttemptId), PipeDirection.In, 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await using var carrier = new NamedPipeClientStream(".", pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await carrier.ConnectAsync();
            await RdpDvcControlCarrierAttachmentCodec.WriteAsync(carrier,
                attachment);
            await responses.WaitForConnectionAsync();
            var observed = new List<ReconnectCarrierControlMessage>
            {
                await ReconnectCarrierControlMessageCodec.ReadAsync(responses)
            };
            Assert.Equal(ReconnectCarrierControlPhase.RelayReady,
                observed[0].Phase);
            await using var secure = new SecureStreamCarrier(
                new SingleStreamConnector(carrier),
                new(TransportEndpointRole.Node,
                    new EcdsaEndpointSigningKey("node",
                        ECDsa.Create(nodeKey.ExportParameters(true))),
                    new("control", controlKey.ExportSubjectPublicKeyInfo()),
                    HandshakeTimeout: TimeSpan.FromSeconds(5)));
            await using var connection = await secure.ConnectAsync(
                await HelloAsync(attachment));
            observed.Add(await ReconnectCarrierControlMessageCodec.ReadAsync(
                responses));
            return observed;
        }

        public async ValueTask DisposeAsync()
        {
            await worker.StopAsync(CancellationToken.None);
            worker.Dispose();
            controlKey.Dispose();
            nodeKey.Dispose();
        }

        private async Task<SessionHello> HelloAsync(
            ReconnectCarrierAttachment attachment) => new(
                attachment.SessionId, endpoint.NodeIncarnationId, 1, 0,
                new HashSet<string> { "rdp-dvc-secure", "orchestration-v1",
                    "terminal-v1", "direct-identity-v1", "portable-transfer-v1",
                    "rdp-dvc-reconnect-v2" },
                new HashSet<string> { "orchestration-v1", "rdp-dvc-reconnect-v2" },
                new Dictionary<StreamKind, long>
                {
                    [StreamKind.Events] = await orchestrator.GetNodeCursorAsync(
                        endpoint.NodeIncarnationId),
                    [StreamKind.Terminal] = 0
                }, new(64 * 1024, 8), attachment.Binding);
    }

    private sealed class SingleStreamConnector(Stream stream) :
        ITransportStreamConnector
    {
        private int used;
        public ValueTask<Stream> ConnectStreamAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref used, 1) != 0)
                throw new InvalidOperationException("The stream is single-use.");
            return ValueTask.FromResult(stream);
        }
    }
}
