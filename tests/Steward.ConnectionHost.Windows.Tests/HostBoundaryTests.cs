using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Steward.ConnectionHost.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class HostBoundaryTests
{
    [Fact]
    public void Production_connection_host_has_no_control_signing_key_or_secure_terminator()
    {
        var repository = FindRepository();
        var program = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "Steward.ConnectionHost.Windows",
            "Program.cs"));
        var carrier = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "Steward.ConnectionHost.Windows",
            "ProductionRdCoreConnectionRuntime.cs"));

        Assert.DoesNotContain(
            "CONTROL_SIGNING_PRIVATE_KEY",
            program,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "controlSigningPrivateKeyFile",
            carrier,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "SecureStreamConnectionAcceptor",
            carrier,
            StringComparison.Ordinal);
        Assert.Contains(
            "IRdpDvcOpaqueControlBridge",
            carrier,
            StringComparison.Ordinal);
    }
    [Fact]
    public void Production_connection_host_has_no_loopback_signing_transport()
    {
        var repository = FindRepository();
        var production = Directory.GetFiles(
                Path.Combine(
                    repository,
                    "src",
                    "Steward.ConnectionHost.Windows"),
                "*.cs",
                SearchOption.TopDirectoryOnly)
            .Select(File.ReadAllText)
            .ToArray();

        Assert.DoesNotContain(
            production,
            source => source.Contains(
                "RdpDvcLoopbackTransportBridge",
                StringComparison.Ordinal));
        Assert.DoesNotContain(
            production,
            source => source.Contains(
                "BridgeSigningPrivateKeyFile",
                StringComparison.Ordinal));
    }
    [Fact]
    public void Control_reports_secure_authentication_only_after_signed_handshake()
    {
        var repository = FindRepository();
        var worker = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "Steward.Stack.Local",
            "RdpDvcControlSessionWorker.cs"));
        var relayReady = worker.IndexOf(
            "ReconnectCarrierControlMessage.RelayReady(",
            StringComparison.Ordinal);
        var remoteHandshake = worker.IndexOf(
            "terminator.AcceptAsync(",
            StringComparison.Ordinal);
        var secureAuthenticated = worker.IndexOf(
            ".SecureSessionAuthenticated(",
            StringComparison.Ordinal);

        Assert.True(relayReady >= 0);
        Assert.True(remoteHandshake >= 0);
        Assert.True(secureAuthenticated >= 0);
        Assert.True(relayReady < remoteHandshake);
        Assert.True(remoteHandshake < secureAuthenticated);
    }
    [Fact]
    public async Task Windows_app_startup_lock_honors_cancellation()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "startup.lock");
            await using var held = new FileStream(
                path,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None);
            using var cancellation = new CancellationTokenSource(
                TimeSpan.FromMilliseconds(100));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => Task.Run(
                    () => WindowsAppOutOfProcOverride.AcquireLock(
                        path,
                        cancellation.Token)));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Metadata_uses_current_user_acl_and_no_fixed_temp_file()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "connections.json");
            var store = new AtomicJsonConnectionMetadataStore(path);

            await store.SaveAsync(
                [],
                CancellationToken.None);

            Assert.Empty(
                Directory.GetFiles(directory, "*.new"));
            Assert.False(
                File.GetAttributes(path)
                    .HasFlag(FileAttributes.ReparsePoint));
            var current = WindowsIdentity.GetCurrent().User;
            var owner = new FileInfo(path)
                .GetAccessControl()
                .GetOwner(typeof(SecurityIdentifier));
            Assert.Equal(current, owner);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Sqlite_metadata_roundtrips_transactionally()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "connections.db");
            var store = new SqliteConnectionMetadataStore(path);
            var expected = new DurableConnectionMetadata(
                ConnectionHostProtocol.CurrentVersion,
                "connection-1",
                RdpDvcSessionState.ConnectedTransport,
                42,
                "runtime-1",
                false,
                true,
                "CONNECTED",
                DateTimeOffset.UtcNow);

            await store.SaveAsync(
                [expected],
                CancellationToken.None);
            var actual = Assert.Single(
                await store.LoadAsync(CancellationToken.None));

            Assert.Equal(expected, actual);
            Assert.True(File.Exists(path));
            Assert.True(File.Exists(path + "-wal"));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Sqlite_metadata_imports_legacy_json_once()
    {
        var directory = TestDirectory();
        try
        {
            var legacyPath = Path.Combine(directory, "connections.v1.json");
            var databasePath = Path.Combine(
                directory,
                "Steward.ConnectionHost.b1",
                "connections.v1.db");
            var expected = new DurableConnectionMetadata(
                ConnectionHostProtocol.CurrentVersion,
                "connection-legacy",
                RdpDvcSessionState.Reconnecting,
                9,
                "runtime-legacy",
                false,
                false,
                "RECONNECTING",
                DateTimeOffset.UtcNow);
            await new AtomicJsonConnectionMetadataStore(legacyPath)
                .SaveAsync([expected], CancellationToken.None);

            var store = new SqliteConnectionMetadataStore(
                databasePath,
                legacyPath);
            var actual = Assert.Single(
                await store.LoadAsync(CancellationToken.None));

            Assert.Equal(expected, actual);
            Assert.False(File.Exists(legacyPath));
            Assert.True(File.Exists(legacyPath + ".migrated"));
            var reopened = new SqliteConnectionMetadataStore(
                databasePath,
                legacyPath);
            Assert.Equal(
                expected,
                Assert.Single(
                    await reopened.LoadAsync(CancellationToken.None)));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Sqlite_recovery_state_is_normalized_and_outbox_survives_restart()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "connections.db");
            var store = new SqliteConnectionMetadataStore(path);
            var desired = new DesiredConnectionRecord(
                ConnectionHostProtocol.CurrentVersion,
                "connection-normalized",
                new("https://project-1.devcenter.azure.com/"),
                "project-1",
                "me",
                "devbox-1",
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                true,
                DateTimeOffset.UtcNow);
            await store.UpsertDesiredAsync(desired, CancellationToken.None);
            await store.SaveAsync(
                [new(
                    ConnectionHostProtocol.CurrentVersion,
                    desired.ConnectionId,
                    RdpDvcSessionState.Disconnected,
                    null,
                    null,
                    false,
                    false,
                    "RECOVERY_PENDING",
                    DateTimeOffset.UtcNow)],
                CancellationToken.None);
            var restarted = new SqliteConnectionMetadataStore(path);

            Assert.Equal(
                desired,
                Assert.Single(await restarted.LoadDesiredAsync(
                    CancellationToken.None)));
            Assert.NotEmpty(await restarted.ReadPendingTransitionsAsync(
                100,
                CancellationToken.None));
            await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(
                $"Data Source={path}");
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name";
            var tables = new List<string>();
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                tables.Add(reader.GetString(0));
            Assert.Contains("desired_connections", tables);
            Assert.Contains("connection_attempts", tables);
            Assert.Contains("connection_routes", tables);
            Assert.Contains("control_attachments", tables);
            Assert.Contains("presentation_leases", tables);
            Assert.Contains("connection_transition_outbox", tables);
            Assert.DoesNotContain("connection_metadata", tables);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }
    [Fact]
    public async Task Durable_routes_reject_stale_generation_and_cross_route_replay()
    {
        var directory = TestDirectory();
        try
        {
            var store = new SqliteConnectionMetadataStore(
                Path.Combine(directory, "routes.db"));
            var host = Steward.Domain.HostId.New();
            var incarnation = Steward.Domain.NodeIncarnationId.New();
            var current = new Steward.Transport.ReconnectCarrierAttachment(
                Guid.NewGuid(),
                new(
                    2,
                    host,
                    incarnation,
                    12,
                    Guid.NewGuid(),
                    42,
                    Convert.ToHexString(RandomNumberGenerator.GetBytes(32)))
                {
                    RouteId = Guid.NewGuid()
                });
            await store.RecordAuthenticatedRouteAsync(
                new("connection-route", 8),
                current,
                CancellationToken.None);
            var replay = current with
            {
                Binding = current.Binding with
                {
                    AttemptId = Guid.NewGuid(),
                    RouteId = Guid.NewGuid()
                }
            };

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.RecordAuthenticatedRouteAsync(
                    new("connection-route", 7),
                    replay,
                    CancellationToken.None));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.RecordAuthenticatedRouteAsync(
                    new("connection-route", 8),
                    replay,
                    CancellationToken.None));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }
    [Fact]
    public void Per_connection_dvc_routes_are_distinct_and_cleanup_is_isolated()
    {
        var directory = TestDirectory();
        try
        {
            var key = Path.Combine(directory, "evidence.key");
            File.WriteAllBytes(key, RandomNumberGenerator.GetBytes(32));
            var configuration = new RdpDvcPerConnectionConfiguration(
                directory,
                "Steward.ConnectionHost.v1.DvcBroker",
                "Steward.Evidence.v1",
                key);

            var first = configuration.Create("connection-a");
            var second = configuration.Create("connection-b");
            var firstConfig =
                RdpDvcEmbeddingConfigurationStore.Load(
                    first.ConfigurationPath);
            var secondConfig =
                RdpDvcEmbeddingConfigurationStore.Load(
                    second.ConfigurationPath);

            Assert.NotEqual(first.BrokerPipeName, second.BrokerPipeName);
            Assert.NotEqual(
                first.ConfigurationPath,
                second.ConfigurationPath);
            Assert.Equal(
                first.BrokerPipeName,
                firstConfig.BrokerPipeName);
            Assert.Equal(
                second.BrokerPipeName,
                secondConfig.BrokerPipeName);
            Assert.NotEqual(
                firstConfig.DiagnosticLogFile,
                secondConfig.DiagnosticLogFile);
            File.WriteAllText(
                firstConfig.DiagnosticLogFile,
                "first");
            File.WriteAllText(
                secondConfig.DiagnosticLogFile,
                "second");
            RdpDvcEmbeddingConfigurationStore.Delete(
                first.ConfigurationPath);
            Assert.False(File.Exists(first.ConfigurationPath));
            Assert.True(File.Exists(second.ConfigurationPath));
            Assert.True(File.Exists(firstConfig.DiagnosticLogFile));
            Assert.True(File.Exists(secondConfig.DiagnosticLogFile));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Opaque_control_bridge_relays_bytes_after_local_control_attachment()
    {
        var pipeName = "Steward.Control.Carrier." +
            Guid.NewGuid().ToString("N");
        var remotePipeName = "Steward.Remote.Carrier." +
            Guid.NewGuid().ToString("N");
        await using var remoteServer = new NamedPipeServerStream(
            remotePipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await using var remoteClient = new NamedPipeClientStream(
            ".",
            remotePipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var remoteConnected = remoteServer.WaitForConnectionAsync();
        await remoteClient.ConnectAsync(CancellationToken.None);
        await remoteConnected;
        await using var control = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var binding = new Steward.Transport.ReconnectTransportBinding(
            2,
            Steward.Domain.HostId.New(),
            Steward.Domain.NodeIncarnationId.New(),
            9,
            Guid.NewGuid(),
            42,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        var attachment = new Steward.Transport.ReconnectCarrierAttachment(
            Guid.NewGuid(),
            binding);
        var bridge = new RdpDvcOpaqueControlPipeBridge(
            new(
                pipeName,
                TimeSpan.FromSeconds(5),
                4096));
        var attaching = bridge.AttachAsync(
            remoteClient,
            attachment,
            new("connection-a", 1),
            CancellationToken.None);
        await control.WaitForConnectionAsync();
        var actual = await Steward.Transport
            .ReconnectCarrierAttachmentCodec.ReadAsync(
                control,
                CancellationToken.None);
        Assert.Equal(attachment, actual);
        Assert.False(attaching.IsCompleted);
        var beforeAttachment = "before-authentication"u8.ToArray();
        var beforeAttachmentWrite =
            remoteServer.WriteAsync(beforeAttachment).AsTask();
        var premature = new byte[beforeAttachment.Length];
        using (var noRelayBeforeAttachment =
               new CancellationTokenSource(TimeSpan.FromMilliseconds(250)))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => control.ReadExactlyAsync(
                        premature,
                        noRelayBeforeAttachment.Token)
                    .AsTask());
        await using var acknowledgement = new NamedPipeClientStream(
            ".",
            RdpDvcOpaqueControlPipeBridge.AcknowledgementPipeName(
                pipeName,
                binding.AttemptId),
            PipeDirection.Out,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await acknowledgement.ConnectAsync(CancellationToken.None);
        await Steward.Transport.ReconnectCarrierControlMessageCodec
            .WriteAsync(
                acknowledgement,
                Steward.Transport.ReconnectCarrierControlMessage
                    .RelayReady(binding.AttemptId));
        await beforeAttachmentWrite;
        var authenticated = new byte[beforeAttachment.Length];
        await control.ReadExactlyAsync(authenticated);
        Assert.Equal(beforeAttachment, authenticated);
        Assert.False(attaching.IsCompleted);
        await Steward.Transport.ReconnectCarrierControlMessageCodec
            .WriteAsync(
                acknowledgement,
                Steward.Transport.ReconnectCarrierControlMessage
                    .SecureSessionAuthenticated(binding.AttemptId));
        await using var lease = await attaching;
        var outbound = "node-to-control"u8.ToArray();
        await remoteServer.WriteAsync(outbound);
        var received = new byte[outbound.Length];
        await control.ReadExactlyAsync(received);
        Assert.Equal(outbound, received);
        var inbound = "control-to-node"u8.ToArray();
        await control.WriteAsync(inbound);
        received = new byte[inbound.Length];
        await remoteServer.ReadExactlyAsync(received);
        Assert.Equal(inbound, received);
    }
    [Fact]
    public void Retained_v1_migration_requires_explicit_1_0_23_state()
    {
        var route = new RdpDvcEvidenceRoute(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            0,
            Guid.NewGuid(),
            ProtocolVersion: 1)
        {
            RetainedV1Endpoint = new(
                "1.0.23",
                FiniteNonceStateRetained: true)
        };
        var current = route with
        {
            ProtocolVersion = 2,
            RetainedV1Endpoint = null
        };

        Assert.Equal(
            RdpDvcLocalCarrierMode.RetainedV1Migration,
            RdpDvcLocalCarrierCompatibility.Select(route));
        Assert.Equal(
            RdpDvcLocalCarrierMode.ReconnectV2,
            RdpDvcLocalCarrierCompatibility.Select(current));
        Assert.Throws<InvalidDataException>(() =>
            RdpDvcLocalCarrierCompatibility.Select(
                route with { RetainedV1Endpoint = null }));
        Assert.Throws<InvalidDataException>(() =>
            RdpDvcLocalCarrierCompatibility.Select(
                route with
                {
                    RetainedV1Endpoint = new(
                        "2.0.0",
                        FiniteNonceStateRetained: true)
                }));
        Assert.Throws<InvalidDataException>(() =>
            RdpDvcLocalCarrierCompatibility.Select(
                current with
                {
                    RetainedV1Endpoint = route.RetainedV1Endpoint
                }));
    }
    [Fact]
    public async Task Connection_generation_reservation_is_durable_monotonic_and_isolated()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "connection-generation.db");
            var store = new SqliteConnectionGenerationStore(path);

            Assert.Equal(
                1,
                await store.ReserveAsync(
                    "connection-a",
                    CancellationToken.None));
            Assert.Equal(
                2,
                await new SqliteConnectionGenerationStore(path)
                    .ReserveAsync(
                        "connection-a",
                        CancellationToken.None));
            Assert.Equal(
                1,
                await new SqliteConnectionGenerationStore(path)
                    .ReserveAsync(
                        "connection-b",
                        CancellationToken.None));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }
    [Fact]
    public async Task Reconnect_high_water_is_durable_and_connection_isolated()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "reconnect-high-water.db");
            var sessionId = Guid.NewGuid();
            var hostId = Steward.Domain.HostId.New();
            var incarnation = Steward.Domain.NodeIncarnationId.New();
            var first = new RdpDvcCarrierAttemptIdentity(
                sessionId,
                hostId,
                incarnation,
                1,
                Guid.NewGuid(),
                42);
            var store = new SqliteConnectionReconnectHighWaterStore(path);

            await store.ObserveAsync(
                "connection-a",
                first,
                CancellationToken.None);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new SqliteConnectionReconnectHighWaterStore(path)
                    .ObserveAsync(
                        "connection-a",
                        first,
                        CancellationToken.None));
            await new SqliteConnectionReconnectHighWaterStore(path)
                .ObserveAsync(
                    "connection-a",
                    first with
                    {
                        ReconnectGeneration = 2,
                        AttemptId = Guid.NewGuid()
                    },
                    CancellationToken.None);
            await new SqliteConnectionReconnectHighWaterStore(path)
                .ObserveAsync(
                    "connection-b",
                    first,
                    CancellationToken.None);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new SqliteConnectionReconnectHighWaterStore(path)
                    .ObserveAsync(
                        "connection-a",
                        first with
                        {
                            RouteId = Guid.NewGuid(),
                            ReconnectGeneration = 3,
                            AttemptId = Guid.NewGuid()
                        },
                        CancellationToken.None));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new SqliteConnectionReconnectHighWaterStore(path)
                    .ObserveAsync(
                        "connection-a",
                        first with
                        {
                            HostId = Steward.Domain.HostId.New(),
                            ReconnectGeneration = 3,
                            AttemptId = Guid.NewGuid()
                        },
                        CancellationToken.None));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }
    [Fact]
    public async Task Pipe_reports_bounded_protocol_error_for_malformed_frame()
    {
        var pipeName = "Steward.ConnectionHost.Malformed." +
            Guid.NewGuid().ToString("N");
        var options = new ConnectionHostOptions
        {
            PipeName = pipeName,
            CommandTimeout = TimeSpan.FromSeconds(5)
        };
        await using var host = BoundaryHost.Create(options);
        await host.InitializeAsync();
        using var stop = new CancellationTokenSource();
        var server = new ConnectionHostPipeServer(options, host)
            .RunAsync(stop.Token);
        await using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            TokenImpersonationLevel.Identification);
        await client.ConnectAsync(CancellationToken.None);
        var invalidLength = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(
            invalidLength,
            ConnectionHostProtocol.MaximumMessageBytes + 1);
        await client.WriteAsync(
            invalidLength,
            CancellationToken.None);
        await client.FlushAsync(CancellationToken.None);

        var response = await ConnectionHostProtocol.ReadResponseAsync(
            client,
            CancellationToken.None);
        stop.Cancel();
        await server;

        Assert.False(response.Accepted);
        Assert.Equal("invalid", response.RequestId);
        Assert.Equal("CONNECTION_HOST_PROTOCOL_INVALID", response.Code);
    }

    [Fact]
    public void Evidence_key_file_is_dpapi_protected_and_current_user_only()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "evidence.key");
            var key = RandomNumberGenerator.GetBytes(32);

            CurrentUserProtectedDataFile.Write(
                path,
                AuthenticatedRdpDvcEvidencePublisher.KeyFilePurpose,
                key);

            var protectedValue = File.ReadAllBytes(path);
            var cleartext = CurrentUserProtectedDataFile.Read(
                path,
                AuthenticatedRdpDvcEvidencePublisher.KeyFilePurpose);
            var owner = new FileInfo(path)
                .GetAccessControl()
                .GetOwner(typeof(SecurityIdentifier));
            Assert.False(protectedValue.AsSpan().IndexOf(key) >= 0);
            Assert.Equal(key, cleartext);
            Assert.Equal(WindowsIdentity.GetCurrent().User, owner);
            CryptographicOperations.ZeroMemory(cleartext);
            CryptographicOperations.ZeroMemory(key);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Ticket_store_binds_runtime_identity_without_secrets()
    {
        var directory = TestDirectory();
        try
        {
            var store = new DpapiRdpDvcEvidenceTicketStore(directory);
            var reference = "bound-ticket-reference";
            var route = new RdpDvcEvidenceRoute(
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                0,
                Guid.NewGuid());
            Assert.Throws<InvalidDataException>(() =>
                store.Write(
                    "unmarked-v1-ticket",
                    route with { ProtocolVersion = 1 }));
        store.Write(reference, route);
            var identity = new RdpDvcEvidenceTicketIdentity(
                reference,
                "connection",
                "runtime",
                19,
                route);

            await store.BindAsync(identity, CancellationToken.None);
            Assert.Equal(identity, store.ReadBound(reference));
            var bound = identity with
            {
                Route = route.BindWtsSession(42)
            };
            store.BindWtsSession(bound);
            var restored = store.ReadBound(reference);

            Assert.Equal(bound, restored);
            Assert.False(File.Exists(
                Path.Combine(directory, reference + ".ticket")));
            var protectedText = Convert.ToHexString(
                await File.ReadAllBytesAsync(
                    Path.Combine(directory, reference + ".bound")));
            Assert.DoesNotContain(
                Convert.ToHexString(
                    System.Text.Encoding.UTF8.GetBytes("connection")),
                protectedText,
                StringComparison.Ordinal);
            Assert.Throws<InvalidOperationException>(
                () => store.BindWtsSession(
                    bound with
                    {
                        Route = route.BindWtsSession(43)
                    }));
            await store.ReleaseAsync(reference);
            Assert.False(File.Exists(
                Path.Combine(directory, reference + ".bound")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string TestDirectory()
    {
        var directory = Path.Combine(
            AppContext.BaseDirectory,
            "connection-host-boundary-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static class BoundaryHost
    {
        public static ConnectionHostOrchestrator Create(
            ConnectionHostOptions options) =>
            new(
                options,
                new UnusedIdentity(),
                new DisabledDevBoxConnectionResolver(),
                new UnusedCompatibility(),
                new UnusedRegistration(),
                new DisabledRdCoreConnectionRuntime(),
                new SingleUseControlConnectAuthorizationValidator(),
                new MemoryMetadataStore());
    }

    private sealed class UnusedIdentity :
        Steward.DevBox.Windows.IDevBoxConnectionIdentityGate
    {
        public Task<Steward.DevBox.Windows.DevBoxConnectionIdentityStatus>
            StatusAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedCompatibility :
        IRdCoreCompatibilityInspector
    {
        public RdCoreCompatibilitySnapshot Inspect() =>
            throw new NotSupportedException();
    }

    private sealed class UnusedRegistration :
        IDvcRegistrationSnapshotProvider
    {
        public Steward.Transport.Rdp.Windows.DvcPluginRegistrationStatus
            GetStatus() =>
            throw new NotSupportedException();
    }

    private sealed class MemoryMetadataStore : IConnectionMetadataStore
    {
        public Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DurableConnectionMetadata>>([]);

        public Task SaveAsync(
            IReadOnlyCollection<DurableConnectionMetadata> connections,
            CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private static string FindRepository()
    {
        foreach (var seed in new[]
                 {
                     Directory.GetCurrentDirectory(),
                     AppContext.BaseDirectory
                 })
        {
            var current = new DirectoryInfo(Path.GetFullPath(seed));
            while (current is not null)
            {
                if (File.Exists(
                        Path.Combine(current.FullName, "Steward.slnx")) &&
                    Directory.Exists(
                        Path.Combine(current.FullName, ".git")))
                    return current.FullName;
                current = current.Parent;
            }
        }
        throw new DirectoryNotFoundException(
            "The Switchyard repository root was not found.");
    }
}
