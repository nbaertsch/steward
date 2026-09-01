using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Node;
using Steward.Orchestration;
using Steward.Transport;

namespace Steward.Orchestration.Tests;

public sealed class IdentityDeliveryTests
{
    [Fact]
    public async Task Direct_delivery_enforces_every_binding_and_removes_node_handle_after_attempt()
    {
        using var fixture = new IdentityFixture();
        var grant = await fixture.ResolveReferenceAsync();
        Assert.NotEqual(Guid.Empty, grant.UseId);

        var invalid = new[]
        {
            grant with { WorkloadId = WorkloadId.New() },
            grant with { TaskId = TaskId.New() },
            grant with { Generation = grant.Generation + 1 },
            grant with { HostId = HostId.New() },
            grant with { NodeIncarnationId = NodeIncarnationId.New() },
            grant with { Audience = grant.Audience + "/other" },
            grant with { Scopes = ["other.scope"] },
            grant with { ExpiresAt = grant.ExpiresAt.AddSeconds(-1) },
            grant with { UseId = Guid.NewGuid() }
        };
        foreach (var changed in invalid)
            await Assert.ThrowsAsync<IdentityResolutionException>(
                () => fixture.DeliverDirectAsync(changed));

        await using var lease = await fixture.Resolver.ResolveAsync(
            fixture.Identity, [grant], CancellationToken.None);
        var handle = Assert.Single(lease.Handles);
        string? revealed = null;
        Assert.True(fixture.NodeVault.TryReveal(handle, new TestMaterialConsumer(value => revealed = value)));
        Assert.Equal(IdentityFixture.Secret, revealed);

        await lease.DisposeAsync();
        Assert.False(fixture.NodeVault.TryReveal(handle, new TestMaterialConsumer(_ => { })));
        Assert.Empty(Directory.GetFiles(fixture.NodeVaultRoot));
    }

    [Fact]
    public async Task Grant_delivery_is_single_use_and_revocation_fails_closed()
    {
        using (var fixture = new IdentityFixture())
        {
            var grant = await fixture.ResolveReferenceAsync();
            await using var lease = await fixture.Resolver.ResolveAsync(
                fixture.Identity, [grant], CancellationToken.None);
            var replay = await Assert.ThrowsAsync<IdentityResolutionException>(
                async () => await fixture.Resolver.ResolveAsync(
                    fixture.Identity, [grant], CancellationToken.None));
            Assert.Equal("identity.use-invalid", replay.Code);
        }

        using (var fixture = new IdentityFixture())
        {
            var grant = await fixture.ResolveReferenceAsync();
            Assert.True(fixture.Catalog.Revoke(fixture.Registration.IdentityGrantId));
            var revoked = await Assert.ThrowsAsync<IdentityResolutionException>(
                async () => await fixture.Resolver.ResolveAsync(
                    fixture.Identity, [grant], CancellationToken.None));
            Assert.Equal("identity.revoked", revoked.Code);
            Assert.Empty(Directory.GetFiles(fixture.ControlVaultRoot));
        }
    }

    [Fact]
    public async Task Expired_grant_is_neither_resolved_nor_delivered()
    {
        using var fixture = new IdentityFixture();
        var grant = await fixture.ResolveReferenceAsync();
        fixture.Time.Set(fixture.Registration.ExpiresAt.AddTicks(1));

        Assert.Null(await fixture.Catalog.ResolveAsync(
            fixture.Registration.IdentityGrantId,
            fixture.Identity.WorkloadId,
            fixture.Identity.TaskId,
            fixture.Identity.Generation,
            fixture.Identity.HostId,
            fixture.Identity.NodeIncarnationId,
            CancellationToken.None));
        var expired = await Assert.ThrowsAsync<IdentityResolutionException>(
            async () => await fixture.Resolver.ResolveAsync(
                fixture.Identity, [grant], CancellationToken.None));
        Assert.Equal("identity.binding-invalid", expired.Code);
        Assert.Equal(0, fixture.Client.DeliveryCount);
        fixture.RestartControl();
        Assert.Empty(Directory.GetFiles(fixture.ControlVaultRoot, "*.identity"));
    }

    [Fact]
    public async Task Wire_messages_expose_only_reference_and_authenticated_ciphertext()
    {
        using var fixture = new IdentityFixture();
        var grant = await fixture.ResolveReferenceAsync();
        await using var lease = await fixture.Resolver.ResolveAsync(
            fixture.Identity, [grant], CancellationToken.None);

        var request = Assert.IsType<DirectIdentityDeliveryRequest>(fixture.Client.LastRequest);
        var response = Assert.IsType<EncryptedIdentityDelivery>(fixture.Client.LastResponse);
        var requestBytes = OrchestrationMessageCodec.Encode(request, fixture.Time.GetUtcNow());
        var responseBytes = OrchestrationMessageCodec.Encode(response, fixture.Time.GetUtcNow());
        var secretBytes = Encoding.UTF8.GetBytes(IdentityFixture.Secret);
        Assert.False(Contains(requestBytes.Span, secretBytes));
        Assert.False(Contains(responseBytes.Span, secretBytes));
        Assert.DoesNotContain("secret", Encoding.UTF8.GetString(responseBytes.Span),
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            typeof(EncryptedIdentityDelivery).GetProperties(),
            property => property.Name.Contains("material", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("provider", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(
            OrchestrationMessageKinds.IdentityDeliveryRequest,
            OrchestrationMessageCodec.Decode(requestBytes).Kind);
        Assert.Equal(
            OrchestrationMessageKinds.IdentityDelivery,
            OrchestrationMessageCodec.Decode(responseBytes).Kind);
        Assert.Throws<OrchestrationMessageException>(() =>
            OrchestrationMessageCodec.DecodeJournaledFact(
                OrchestrationMessageKinds.IdentityDelivery,
                Encoding.UTF8.GetString(responseBytes.Span)));
    }

    [Theory]
    [InlineData(IdentityOfflineBehavior.Fail, "identity.control-disconnected.fail")]
    [InlineData(IdentityOfflineBehavior.CheckpointAndPause, "identity.control-disconnected.pause")]
    public async Task Renewal_requires_connected_Control_and_returns_explicit_offline_disposition(
        IdentityOfflineBehavior behavior,
        string expectedCode)
    {
        using var fixture = new IdentityFixture(behavior);
        var grant = await fixture.ResolveReferenceAsync();
        fixture.Client.IsControlConnected = false;

        var offline = await Assert.ThrowsAsync<IdentityResolutionException>(
            async () => await fixture.Resolver.ResolveAsync(
                fixture.Identity, [grant], CancellationToken.None));
        Assert.Equal(expectedCode, offline.Code);
        Assert.Equal(behavior, offline.OfflineBehavior);
        Assert.Equal(0, fixture.Client.DeliveryCount);
    }

    [Fact]
    public async Task Grant_and_DPAPI_handle_survive_restart_before_and_after_resolve()
    {
        using var fixture = new IdentityFixture();
        fixture.RestartControl();
        var first = await fixture.ResolveReferenceAsync();

        fixture.RestartControl();
        var afterResolve = await fixture.ResolveReferenceAsync();
        Assert.Equal(first.UseId, afterResolve.UseId);
        await using var lease = await fixture.Resolver.ResolveAsync(
            fixture.Identity, [afterResolve], CancellationToken.None);
        string? material = null;
        Assert.True(fixture.NodeVault.TryReveal(
            Assert.Single(lease.Handles), new TestMaterialConsumer(value => material = value)));
        Assert.Equal(IdentityFixture.Secret, material);
    }

    [Fact]
    public async Task Consumed_use_and_cap_survive_restart()
    {
        using var fixture = new IdentityFixture();
        var grant = await fixture.ResolveReferenceAsync();
        await using (var lease = await fixture.Resolver.ResolveAsync(
                         fixture.Identity, [grant], CancellationToken.None))
        {
            Assert.Single(lease.Handles);
        }

        fixture.RestartControl();
        var exhausted = await fixture.Catalog.ResolveAsync(
            fixture.Registration.IdentityGrantId,
            fixture.Identity.WorkloadId,
            fixture.Identity.TaskId,
            fixture.Identity.Generation,
            fixture.Identity.HostId,
            fixture.Identity.NodeIncarnationId,
            CancellationToken.None);
        Assert.Null(exhausted);
        var replay = await Assert.ThrowsAsync<IdentityResolutionException>(
            async () => await fixture.Resolver.ResolveAsync(
                fixture.Identity, [grant], CancellationToken.None));
        Assert.Equal("identity.use-invalid", replay.Code);

        using var connection = new SqliteConnection(
            $"Data Source={fixture.StorePath};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*), MAX(consumed), MAX(attempt_id)
            FROM local_identity_uses
            WHERE grant_id = $grant_id;
            """;
        command.Parameters.AddWithValue("$grant_id", fixture.Registration.IdentityGrantId.ToString());
        using var reader = command.ExecuteReader();
        Assert.True(reader.Read());
        Assert.Equal(1, reader.GetInt32(0));
        Assert.Equal(1, reader.GetInt32(1));
        Assert.Equal(fixture.Identity.AttemptId.ToString(), reader.GetString(2));
    }

    [Fact]
    public async Task Multi_use_grant_allocates_fresh_uses_and_preserves_cap_across_restart()
    {
        using var fixture = new IdentityFixture(maximumUses: 2);
        var first = await fixture.ResolveReferenceAsync();
        await using (var lease = await fixture.Resolver.ResolveAsync(
                         fixture.Identity,
                         [first],
                         CancellationToken.None))
        {
            Assert.Single(lease.Handles);
        }

        fixture.RestartControl();
        var second = await fixture.ResolveReferenceAsync();
        Assert.NotEqual(first.UseId, second.UseId);
        await using (var lease = await fixture.Resolver.ResolveAsync(
                         fixture.Identity,
                         [second],
                         CancellationToken.None))
        {
            Assert.Single(lease.Handles);
        }

        fixture.RestartControl();
        Assert.Null(await fixture.Catalog.ResolveAsync(
            fixture.Registration.IdentityGrantId,
            fixture.Identity.WorkloadId,
            fixture.Identity.TaskId,
            fixture.Identity.Generation,
            fixture.Identity.HostId,
            fixture.Identity.NodeIncarnationId,
            CancellationToken.None));

        using var connection = new SqliteConnection(
            $"Data Source={fixture.StorePath};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*), SUM(consumed), COUNT(DISTINCT use_id)
            FROM local_identity_uses
            WHERE grant_id = $grant_id;
            """;
        command.Parameters.AddWithValue(
            "$grant_id",
            fixture.Registration.IdentityGrantId.ToString());
        using var reader = command.ExecuteReader();
        Assert.True(reader.Read());
        Assert.Equal(2, reader.GetInt32(0));
        Assert.Equal(2, reader.GetInt32(1));
        Assert.Equal(2, reader.GetInt32(2));
    }

    [Fact]
    public async Task Revocation_survives_restart_and_removes_protected_secret()
    {
        using var fixture = new IdentityFixture();
        var grant = await fixture.ResolveReferenceAsync();
        Assert.True(fixture.Catalog.Revoke(fixture.Registration.IdentityGrantId));

        fixture.RestartControl();
        Assert.Null(await fixture.Catalog.ResolveAsync(
            fixture.Registration.IdentityGrantId,
            fixture.Identity.WorkloadId,
            fixture.Identity.TaskId,
            fixture.Identity.Generation,
            fixture.Identity.HostId,
            fixture.Identity.NodeIncarnationId,
            CancellationToken.None));
        var revoked = await Assert.ThrowsAsync<IdentityResolutionException>(
            () => fixture.DeliverDirectAsync(grant));
        Assert.Equal("identity.revoked", revoked.Code);
        Assert.Empty(Directory.GetFiles(fixture.ControlVaultRoot, "*.identity"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Missing_or_corrupt_protected_secret_fails_closed_after_restart(bool corrupt)
    {
        using var fixture = new IdentityFixture();
        var grant = await fixture.ResolveReferenceAsync();
        var secretFile = Assert.Single(
            Directory.GetFiles(fixture.ControlVaultRoot, "*.identity"));
        if (corrupt)
            await File.WriteAllBytesAsync(secretFile, new byte[96]);
        else
            File.Delete(secretFile);

        fixture.RestartControl();
        var unavailable = await Assert.ThrowsAsync<IdentityResolutionException>(
            async () => await fixture.Resolver.ResolveAsync(
                fixture.Identity, [grant], CancellationToken.None));
        Assert.Equal("identity.unavailable", unavailable.Code);
    }

    [Fact]
    public async Task Store_uses_versioned_WAL_FULL_schema_and_never_contains_secret()
    {
        using var fixture = new IdentityFixture();
        _ = await fixture.ResolveReferenceAsync();

        using (var connection = new SqliteConnection(
                   $"Data Source={fixture.StorePath};Mode=ReadOnly;Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT
                    (SELECT schema_version FROM local_identity_schema WHERE singleton = 1),
                    (SELECT COUNT(*) FROM pragma_table_info('local_identity_grants')
                     WHERE name IN ('handle_id', 'revoked', 'maximum_uses')),
                    (SELECT COUNT(*) FROM pragma_table_info('local_identity_uses')
                     WHERE name IN ('use_id', 'consumed', 'attempt_id'));
                """;
            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal(LocalIdentityGrantStore.SchemaVersion, reader.GetString(0));
            Assert.Equal(3, reader.GetInt32(1));
            Assert.Equal(3, reader.GetInt32(2));
        }
        using (var connection = new SqliteConnection(
                   $"Data Source={fixture.StorePath};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA journal_mode; PRAGMA synchronous;";
            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal("wal", reader.GetString(0), ignoreCase: true);
            Assert.True(reader.NextResult());
            Assert.True(reader.Read());
            Assert.Equal(2, reader.GetInt32(0));
        }
        foreach (var path in Directory.GetFiles(Path.GetDirectoryName(fixture.StorePath)!))
            Assert.False(Contains(
                await File.ReadAllBytesAsync(path),
                Encoding.UTF8.GetBytes(IdentityFixture.Secret)));
    }

    [Fact]
    public async Task Identity_stream_adapter_delivers_ephemerally_and_detach_reports_offline()
    {
        using var fixture = new IdentityFixture();
        var grant = await fixture.ResolveReferenceAsync();
        var carriers = InMemoryDuplexCarrier.CreatePair(
            new(true, true, "node", "control", "identity-channel"),
            new(true, true, "control", "node", "identity-channel"));
        var hello = new SessionHello(
            Guid.NewGuid(),
            fixture.Identity.NodeIncarnationId,
            1,
            0,
            new HashSet<string>(),
            new HashSet<string>(),
            new Dictionary<StreamKind, long>(),
            new TransportLimits());
        var nodeConnect = carriers.First.ConnectAsync(hello).AsTask();
        var controlConnect = carriers.Second.ConnectAsync(hello).AsTask();
        await using var node = await nodeConnect;
        await using var control = await controlConnect;
        var nodeClient = new DirectSessionNodeIdentityClient(fixture.Identity.HostId);
        var controlHandler = new DirectSessionControlIdentityStreamHandler(
            fixture.Identity.HostId,
            new DirectSessionControlIdentityHandler(fixture.Catalog),
            fixture.Time);
        using var attachment = nodeClient.Attach(node);
        var resolver = new DirectSessionTaskIdentityResolver(
            fixture.NodeVault, nodeClient, fixture.Time);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var controlPump = PumpIdentityAsync(
            control, controlHandler, cancellation.Token);
        var nodePump = PumpIdentityAsync(
            node, nodeClient, cancellation.Token);

        await using var lease = await resolver.ResolveAsync(
            fixture.Identity, [grant], cancellation.Token);
        string? revealed = null;
        Assert.True(fixture.NodeVault.TryReveal(
            Assert.Single(lease.Handles), new TestMaterialConsumer(value => revealed = value)));
        Assert.Equal(IdentityFixture.Secret, revealed);
        attachment.Dispose();
        Assert.False(nodeClient.IsControlConnected);
        var offline = await Assert.ThrowsAsync<IdentityResolutionException>(
            async () => await resolver.ResolveAsync(
                fixture.Identity, [grant], CancellationToken.None));
        Assert.Equal("identity.control-disconnected.fail", offline.Code);

        cancellation.Cancel();
        await IgnoreCancellationAsync(controlPump);
        await IgnoreCancellationAsync(nodePump);
    }

    [Fact]
    public async Task Node_processor_does_not_persist_Identity_stream_cursor_or_payload()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory, "identity-cursor", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var incarnation = NodeIncarnationId.New();
            var journal = new NodeJournal(Path.Combine(root, "node.db"));
            await journal.InitializeAsync(incarnation, Guid.NewGuid());
            var handler = new CountingIdentityHandler();
            var processor = new NodeCommandProcessor(
                journal,
                new RejectingTaskRegistry(),
                new(Path.Combine(root, "workspaces")),
                auxiliaryHandlers: [handler]);
            var carriers = InMemoryDuplexCarrier.CreatePair(
                new(true, true, "node", "control", "identity-channel"),
                new(true, true, "control", "node", "identity-channel"));
            var hello = new SessionHello(
                Guid.NewGuid(),
                incarnation,
                1,
                0,
                new HashSet<string>(),
                new HashSet<string>(),
                new Dictionary<StreamKind, long>(),
                new TransportLimits());
            var nodeConnect = carriers.First.ConnectAsync(hello).AsTask();
            var controlConnect = carriers.Second.ConnectAsync(hello).AsTask();
            await using var node = await nodeConnect;
            await using var control = await controlConnect;
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var run = processor.RunSessionAsync(node, cancellation.Token);
            var marker = Encoding.UTF8.GetBytes("must-not-be-journaled");
            await control.SendAsync(new(
                hello.SessionId,
                incarnation,
                StreamKind.Identity,
                1,
                1,
                marker), cancellation.Token);
            while (handler.Count == 0)
                await Task.Delay(10, cancellation.Token);
            cancellation.Cancel();
            await IgnoreCancellationAsync(run);

            var cursors = await journal.GetStreamCursorsAsync();
            Assert.Equal(0, cursors.GetValueOrDefault(StreamKind.Identity, 0));
            await processor.DisposeAsync();
            await journal.DisposeAsync();
            // Force a full WAL checkpoint and close all pooled connections so
            // the raw .db file contains all committed data and no stale WAL
            // pages remain that could cause false negatives during the byte scan.
            var dbPath = Path.Combine(root, "node.db");
            using (var checkpoint = new SqliteConnection($"Data Source={dbPath}"))
            {
                await checkpoint.OpenAsync();
                using var cmd = checkpoint.CreateCommand();
                cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
                await cmd.ExecuteNonQueryAsync();
            }
            SqliteConnection.ClearAllPools();
            await using var database = new FileStream(
                dbPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var databaseBytes = new byte[database.Length];
            await database.ReadExactlyAsync(databaseBytes);
            Assert.False(Contains(databaseBytes, marker));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); }
            catch (IOException) { }
        }
    }

    private static async Task PumpIdentityAsync(
        ITransportConnection connection,
        IAuxiliaryTransportStreamHandler handler,
        CancellationToken cancellationToken)
    {
        await foreach (var frame in connection.ReceiveAsync(cancellationToken))
        {
            Assert.Equal(StreamKind.Identity, frame.Stream);
            await handler.HandleAsync(connection, frame, cancellationToken);
        }
    }

    private static async Task IgnoreCancellationAsync(Task task)
    {
        try { await task; }
        catch (OperationCanceledException) { }
    }

    private static bool Contains(ReadOnlySpan<byte> value, ReadOnlySpan<byte> expected)
    {
        if (expected.IsEmpty || expected.Length > value.Length)
            return false;
        for (var offset = 0; offset <= value.Length - expected.Length; offset++)
            if (value.Slice(offset, expected.Length).SequenceEqual(expected))
                return true;
        return false;
    }

    private sealed class TestMaterialConsumer(Action<string> consume)
        : IProtectedMaterialConsumer
    {
        public void Consume(ReadOnlySpan<char> material) =>
            consume(new string(material));
    }
    private sealed class IdentityFixture : IDisposable
    {
        public const string Secret = "local-secret-material-9ddf290e";
        private readonly string root;

        public IdentityFixture(
            IdentityOfflineBehavior offlineBehavior = IdentityOfflineBehavior.Fail,
            int maximumUses = 1)
        {
            root = Path.Combine(
                AppContext.BaseDirectory, "direct-identity", Guid.NewGuid().ToString("N"));
            ControlVaultRoot = Path.Combine(root, "control");
            NodeVaultRoot = Path.Combine(root, "node");
            StorePath = Path.Combine(root, "catalog", "identity.db");
            Time = new MutableTimeProvider(DateTimeOffset.UtcNow);
            ControlVault = new DpapiProtectedIdentityVault(ControlVaultRoot);
            NodeVault = new DpapiProtectedIdentityVault(NodeVaultRoot);
            Store = new LocalIdentityGrantStore(StorePath);
            Catalog = new LocalControlIdentityGrantCatalog(ControlVault, Store, Time);
            Identity = new(
                WorkloadId.New(),
                PlanRevisionId.New(),
                TaskId.New(),
                TaskAttemptId.New(),
                3,
                HostId.New(),
                NodeIncarnationId.New(),
                DelegationId.New(),
                CommandId.New());
            Registration = new(
                IdentityGrantId.New(),
                Identity.WorkloadId,
                Identity.TaskId,
                Identity.Generation,
                Identity.HostId,
                Identity.NodeIncarnationId,
                "local-test",
                "https://inference.example",
                ["models.read", "models.run"],
                Time.GetUtcNow().AddHours(1),
                maximumUses,
                IdentityRenewalMode.LocalBroker,
                offlineBehavior);
            Catalog.Register(Registration, Secret);
            Binding = new(
                Guid.NewGuid(),
                Identity.HostId,
                Identity.NodeIncarnationId,
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
            Client = new LoopbackClient(
                Binding,
                new DirectSessionControlIdentityHandler(Catalog));
            Resolver = new DirectSessionTaskIdentityResolver(NodeVault, Client, Time);
        }

        public string ControlVaultRoot { get; }
        public string NodeVaultRoot { get; }
        public string StorePath { get; }
        public DpapiProtectedIdentityVault ControlVault { get; private set; }
        public DpapiProtectedIdentityVault NodeVault { get; }
        public LocalIdentityGrantStore Store { get; private set; }
        public LocalControlIdentityGrantCatalog Catalog { get; private set; }
        public LocalControlIdentityGrantRegistration Registration { get; }
        public AttemptIdentity Identity { get; }
        public DirectIdentitySessionBinding Binding { get; }
        public LoopbackClient Client { get; private set; }
        public DirectSessionTaskIdentityResolver Resolver { get; private set; }
        public MutableTimeProvider Time { get; }

        public async Task<TaskIdentityGrantReference> ResolveReferenceAsync() =>
            await Catalog.ResolveAsync(
                Registration.IdentityGrantId,
                Identity.WorkloadId,
                Identity.TaskId,
                Identity.Generation,
                Identity.HostId,
                Identity.NodeIncarnationId,
                CancellationToken.None) ??
            throw new InvalidOperationException("Fixture grant was unavailable.");

        public async Task DeliverDirectAsync(TaskIdentityGrantReference grant)
        {
            using var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            await Client.DeliverAsync(
                new(Guid.NewGuid(), Identity, grant, recipient.ExportSubjectPublicKeyInfo()),
                CancellationToken.None);
        }

        public void RestartControl()
        {
            ControlVault = new DpapiProtectedIdentityVault(ControlVaultRoot);
            Store = new LocalIdentityGrantStore(StorePath);
            Catalog = new LocalControlIdentityGrantCatalog(ControlVault, Store, Time);
            Client = new LoopbackClient(
                Binding,
                new DirectSessionControlIdentityHandler(Catalog));
            Resolver = new DirectSessionTaskIdentityResolver(NodeVault, Client, Time);
        }

        public void Dispose()
        {
            Catalog.Revoke(Registration.IdentityGrantId);
            SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); }
            catch (DirectoryNotFoundException) { }
        }
    }

    private sealed class LoopbackClient(
        DirectIdentitySessionBinding binding,
        DirectSessionControlIdentityHandler handler) : IDirectIdentityDeliveryClient
    {
        public bool IsControlConnected { get; set; } = true;
        public DirectIdentitySessionBinding Binding { get; } = binding;
        public int DeliveryCount { get; private set; }
        public DirectIdentityDeliveryRequest? LastRequest { get; private set; }
        public EncryptedIdentityDelivery? LastResponse { get; private set; }

        public async ValueTask<EncryptedIdentityDelivery> DeliverAsync(
            DirectIdentityDeliveryRequest request,
            CancellationToken cancellationToken)
        {
            if (!IsControlConnected)
                throw new InvalidOperationException("Disconnected client was invoked.");
            DeliveryCount++;
            LastRequest = request;
            LastResponse = await handler.HandleAsync(Binding, request, cancellationToken);
            return LastResponse;
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset value) : TimeProvider
    {
        private DateTimeOffset value = value;
        public override DateTimeOffset GetUtcNow() => value;
        public void Set(DateTimeOffset newValue) => value = newValue;
    }

    private sealed class CountingIdentityHandler : IAuxiliaryTransportStreamHandler
    {
        private int count;
        public int Count => Volatile.Read(ref count);
        public StreamKind Stream => StreamKind.Identity;

        public ValueTask HandleAsync(
            ITransportConnection connection,
            TransportFrame frame,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref count);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RejectingTaskRegistry : ITaskTypeRegistry
    {
        public Steward.Tasks.Abstractions.ITaskType Resolve(string name, string version) =>
            throw new KeyNotFoundException();
    }
}
