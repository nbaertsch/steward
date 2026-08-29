using Steward.Domain;
using Steward.Node.Host;
using Steward.PortableState;
using Steward.Stack.Local;
using Steward.Transport;

namespace Steward.Orchestration.Tests;

public sealed class ProductionNodeRuntimeTests
{
    [Fact]
    public async Task Runtime_creates_processor_and_runs_session_over_in_memory_transport()
    {
        if (!OperatingSystem.IsWindows()) return;
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "node-runtime-test",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = CreateNodeHostOptions(root);
            var validated = options.Validate();
            var portableStore = CreatePortableStore(
                Path.Combine(root, "objects"));
            var portableTransfer = new LocalPortableTransferClient();

            await using var runtime = await ProductionNodeRuntime.CreateAsync(
                validated,
                Path.Combine(root, "credentials"),
                portableStore,
                portableTransfer,
                cancellationToken: CancellationToken.None);

            Assert.Equal(validated.IncarnationId, runtime.IncarnationId);
            Assert.Equal(validated.HostId, runtime.HostId);

            // Build an in-memory transport pair for control<->node.
            var sessionId = Guid.NewGuid();
            var securityNode = new VerifiedSessionSecurity(
                true, true, "node-identity", "control-identity", "binding-token");
            var securityControl = new VerifiedSessionSecurity(
                true, true, "control-identity", "node-identity", "binding-token");
            var (nodeCarrier, controlCarrier) =
                InMemoryDuplexCarrier.CreatePair(securityNode, securityControl);

            var nodeHello = await runtime.CreateSessionHelloAsync(
                sessionId,
                new HashSet<string>(StringComparer.Ordinal)
                {
                    "orchestration-v1", "reconciliation-v1", "resume-cursors-v1"
                },
                new HashSet<string>(StringComparer.Ordinal),
                new TransportLimits(64 * 1024, 8),
                CancellationToken.None);
            Assert.Equal(sessionId, nodeHello.SessionId);
            Assert.Equal(validated.IncarnationId, nodeHello.NodeIncarnationId);

            // Connect both sides.
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var nodeConnecting = nodeCarrier.ConnectAsync(nodeHello, timeout.Token);
            var controlHello = new SessionHello(
                sessionId,
                validated.IncarnationId,
                1, 0,
                new HashSet<string>(StringComparer.Ordinal)
                {
                    "orchestration-v1", "reconciliation-v1", "resume-cursors-v1"
                },
                new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<StreamKind, long>(),
                new TransportLimits(64 * 1024, 8));
            var controlConnecting = controlCarrier.ConnectAsync(controlHello, timeout.Token);
            await using var nodeConnection = await nodeConnecting;
            await using var controlConnection = await controlConnecting;

            // Start the node session and immediately close the control side
            // to trigger a clean session end.
            using var sessionCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var sessionTask = runtime.RunSessionAsync(
                nodeConnection, sessionCts.Token);

            // Close the control connection to end the node session.
            await controlConnection.DisposeAsync();
            try
            {
                await sessionTask;
            }
            catch (OperationCanceledException) { }

            // If we got here without exceptions, the runtime ran successfully.
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task CreateSessionHelloAsync_includes_journal_cursors()
    {
        if (!OperatingSystem.IsWindows()) return;
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "node-hello-test",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = CreateNodeHostOptions(root);
            var validated = options.Validate();
            var portableStore = CreatePortableStore(
                Path.Combine(root, "objects"));
            var portableTransfer = new LocalPortableTransferClient();

            await using var runtime = await ProductionNodeRuntime.CreateAsync(
                validated,
                Path.Combine(root, "credentials"),
                portableStore,
                portableTransfer,
                cancellationToken: CancellationToken.None);

            var hello = await runtime.CreateSessionHelloAsync(
                Guid.NewGuid(),
                new HashSet<string>(StringComparer.Ordinal) { "rdp-dvc-secure" },
                new HashSet<string>(StringComparer.Ordinal),
                new TransportLimits(64 * 1024, 8),
                CancellationToken.None);

            Assert.NotEqual(Guid.Empty, hello.SessionId);
            Assert.Equal(1, hello.ProtocolMajor);
            Assert.NotNull(hello.ResumeCursors);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Session_binding_validation_rejects_mismatched_session()
    {
        var session = new NegotiatedSession(
            Guid.NewGuid(),
            NodeIncarnationId.New(),
            1, 0,
            new HashSet<string>(),
            new Dictionary<StreamKind, long>(),
            new Dictionary<StreamKind, long>(),
            new TransportLimits(),
            new VerifiedSessionSecurity(
                true, true, "node", "control", "binding"));
        var wrongSessionId = Guid.NewGuid();

        var error = Assert.Throws<TransportProtocolException>(() =>
            DvcSessionValidator.ValidateSessionBinding(
                session,
                wrongSessionId,
                session.NodeIncarnationId,
                "node",
                "control"));
        Assert.Equal(TransportError.SessionBindingMismatch, error.Error);
    }

    [Fact]
    public void Session_binding_validation_rejects_mismatched_incarnation()
    {
        var session = new NegotiatedSession(
            Guid.NewGuid(),
            NodeIncarnationId.New(),
            1, 0,
            new HashSet<string>(),
            new Dictionary<StreamKind, long>(),
            new Dictionary<StreamKind, long>(),
            new TransportLimits(),
            new VerifiedSessionSecurity(
                true, true, "node", "control", "binding"));

        var error = Assert.Throws<TransportProtocolException>(() =>
            DvcSessionValidator.ValidateSessionBinding(
                session,
                session.SessionId,
                NodeIncarnationId.New(),
                "node",
                "control"));
        Assert.Equal(TransportError.SessionBindingMismatch, error.Error);
    }

    [Fact]
    public void Session_binding_validation_accepts_matching_identities()
    {
        var sessionId = Guid.NewGuid();
        var incarnation = NodeIncarnationId.New();
        var hostId = HostId.New();
        var session = new NegotiatedSession(
            sessionId,
            incarnation,
            1, 0,
            new HashSet<string>(),
            new Dictionary<StreamKind, long>(),
            new Dictionary<StreamKind, long>(),
            new TransportLimits(),
            new VerifiedSessionSecurity(
                true, true, "node", "control", "binding"));

        // Should not throw.
        DvcSessionValidator.ValidateSessionBinding(
            session, sessionId, incarnation, "node", "control");
    }

    [Fact]
    public void Session_binding_validation_rejects_mismatched_transport_identity()
    {
        var sessionId = Guid.NewGuid();
        var incarnation = NodeIncarnationId.New();
        var session = new NegotiatedSession(
            sessionId,
            incarnation,
            1, 0,
            new HashSet<string>(),
            new Dictionary<StreamKind, long>(),
            new Dictionary<StreamKind, long>(),
            new TransportLimits(),
            new VerifiedSessionSecurity(
                true, true, "node", "unexpected-control", "binding"));

        var error = Assert.Throws<TransportProtocolException>(() =>
            DvcSessionValidator.ValidateSessionBinding(
                session,
                sessionId,
                incarnation,
                "node",
                "control"));
        Assert.Equal(TransportError.SessionBindingMismatch, error.Error);
    }

    [Fact]
    public void ServerOptions_parses_node_host_config_arguments()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "options-parse-test",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // Create dummy files for required paths.
            var authKeyFile = Path.Combine(root, "auth.key");
            var nonceFile = Path.Combine(root, "nonce.seq");
            var receiptFile = Path.Combine(root, "readiness.json");
            var configFile = Path.Combine(root, "node-host.json");
            var nodeSigningFile = Path.Combine(root, "node-signing.pk8");
            var controlSigningFile = Path.Combine(root, "control-signing.spki");
            File.WriteAllBytes(authKeyFile, new byte[32]);
            File.WriteAllBytes(nonceFile, new byte[1]);
            File.WriteAllText(configFile, "{}");
            using (var nodeSigning = System.Security.Cryptography.ECDsa.Create(
                       System.Security.Cryptography.ECCurve.NamedCurves.nistP256))
                File.WriteAllBytes(
                    nodeSigningFile,
                    nodeSigning.ExportPkcs8PrivateKey());
            using (var controlSigning = System.Security.Cryptography.ECDsa.Create(
                       System.Security.Cryptography.ECCurve.NamedCurves.nistP256))
                File.WriteAllBytes(
                    controlSigningFile,
                    controlSigning.ExportSubjectPublicKeyInfo());

            var args = new[]
            {
                "--session-id", Guid.NewGuid().ToString(),
                "--host-id", Guid.NewGuid().ToString(),
                "--incarnation-id", Guid.NewGuid().ToString(),
                "--auth-key-file", authKeyFile,
                "--nonce-sequence-file", nonceFile,
                "--readiness-receipt-file", receiptFile,
                "--node-signing-key-file", nodeSigningFile,
                "--node-identity", "node",
                "--control-signing-key-file", controlSigningFile,
                "--control-identity", "control",
                "--node-host-config", configFile,
                "--portable-state-root", Path.Combine(root, "objects"),
                "--credential-vault-root", Path.Combine(root, "creds")
            };

            var options = Steward.RdpDvc.Server.Windows.ServerOptions.Parse(args);

            Assert.Equal(configFile, options.NodeHostConfigFile);
            Assert.Equal(
                Path.GetFullPath(Path.Combine(root, "objects")),
                options.PortableStateRoot);
            Assert.Equal(
                Path.GetFullPath(Path.Combine(root, "creds")),
                options.CredentialVaultRoot);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public void ServerOptions_requires_portable_state_root_with_config()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "options-validation-test",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var authKeyFile = Path.Combine(root, "auth.key");
            var nonceFile = Path.Combine(root, "nonce.seq");
            var receiptFile = Path.Combine(root, "readiness.json");
            var configFile = Path.Combine(root, "node-host.json");
            File.WriteAllBytes(authKeyFile, new byte[32]);
            File.WriteAllBytes(nonceFile, new byte[1]);
            File.WriteAllText(configFile, "{}");

            var args = new[]
            {
                "--session-id", Guid.NewGuid().ToString(),
                "--host-id", Guid.NewGuid().ToString(),
                "--incarnation-id", Guid.NewGuid().ToString(),
                "--auth-key-file", authKeyFile,
                "--nonce-sequence-file", nonceFile,
                "--readiness-receipt-file", receiptFile,
                "--node-host-config", configFile
            };

            Assert.Throws<ArgumentException>(() =>
                Steward.RdpDvc.Server.Windows.ServerOptions.Parse(args));
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public void ServerOptions_requires_signed_transport_with_node_host_config()
    {
        var root = Path.Combine(
            AppContext.BaseDirectory,
            "options-secure-node-test",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var authKeyFile = Path.Combine(root, "auth.key");
            var nonceFile = Path.Combine(root, "nonce.seq");
            var configFile = Path.Combine(root, "node-host.json");
            File.WriteAllBytes(authKeyFile, new byte[32]);
            File.WriteAllBytes(nonceFile, new byte[1]);
            File.WriteAllText(configFile, "{}");

            var args = new[]
            {
                "--session-id", Guid.NewGuid().ToString(),
                "--host-id", Guid.NewGuid().ToString(),
                "--incarnation-id", Guid.NewGuid().ToString(),
                "--auth-key-file", authKeyFile,
                "--nonce-sequence-file", nonceFile,
                "--readiness-receipt-file",
                Path.Combine(root, "readiness.json"),
                "--node-host-config", configFile,
                "--portable-state-root", Path.Combine(root, "objects"),
                "--credential-vault-root", Path.Combine(root, "creds")
            };

            Assert.Throws<ArgumentException>(() =>
                Steward.RdpDvc.Server.Windows.ServerOptions.Parse(args));
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    private static NodeHostOptions CreateNodeHostOptions(string root) =>
        new()
        {
            JournalPath = Path.Combine(root, "node.db"),
            ExecutionJournalPath = Path.Combine(root, "execution.db"),
            EvaluationDatabasePath = Path.Combine(root, "evaluation.db"),
            WorkspaceRoot = Path.Combine(root, "workspaces"),
            SpoolRoot = Path.Combine(root, "spool"),
            KeeperPipeName = $"StewardTest_{Guid.NewGuid():N}",
            NodeIncarnationId = NodeIncarnationId.New().ToString(),
            HostId = HostId.New().ToString(),
            TerminalJournalPath = Path.Combine(root, "terminal.db"),
            MaximumTerminalSessions = 4,
            AgentsEnabled = false
        };

    private static IPortableObjectStore CreatePortableStore(string root)
    {
        var metadata = LocalStackOptions.PortableStateBinding(new
        {
            rootPath = root
        });
        return new LocalStackContentAddressedObjectStore(metadata);
    }
}
