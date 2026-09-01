using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Steward.Contracts;
using Steward.RdpDvc.Server.Windows;
using Steward.Transport;

namespace Steward.RdpDvc.Server.Windows.Tests;

public sealed class ReconnectLedgerTests : IDisposable
{
    private readonly string root = Path.Combine(
        AppContext.BaseDirectory,
        "reconnect-ledger",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task V2_health_is_read_only_monotonic_and_has_no_terminal_exhaustion()
    {
        var path = Path.Combine(root, EndpointStateFiles.V2Health);
        Directory.CreateDirectory(root);
        var endpoint = EndpointIdentity.Create();
        var key = RandomNumberGenerator.GetBytes(32);
        var store = new DvcEndpointV2HealthStore(
            path,
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            "node",
            "control",
            key);
        var attemptId = Guid.NewGuid();

        await store.WriteAsync(
            EndpointV2HealthState.Authenticated,
            generation: 42,
            attemptId,
            wtsSessionId: 7,
            CancellationToken.None);
        var health = await store.LoadAsync(CancellationToken.None);

        Assert.Equal(EndpointV2HealthState.Authenticated, health!.Observation.State);
        Assert.Equal(42, health.Observation.ReconnectGeneration);
        Assert.Equal(attemptId, health.Observation.AttemptId);
        Assert.Equal(health.Observation,
            EndpointV2HealthAuthenticator.Verify(health, key));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.WriteAsync(
                EndpointV2HealthState.WaitingForReconnect,
                generation: 41,
                Guid.NewGuid(),
                wtsSessionId: null,
                CancellationToken.None));
        Assert.DoesNotContain(
            "Exhausted",
            string.Join(',', Enum.GetNames<EndpointV2HealthState>()),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Completed",
            string.Join(',', Enum.GetNames<EndpointV2HealthState>()),
            StringComparison.Ordinal);
    }
    [Fact]
    public async Task V2_health_rejects_field_forgery_in_the_transport_cache()
    {
        var path = Path.Combine(root, EndpointStateFiles.V2Health);
        Directory.CreateDirectory(root);
        var endpoint = EndpointIdentity.Create();
        var key = RandomNumberGenerator.GetBytes(32);
        var store = new DvcEndpointV2HealthStore(
            path,
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            "node",
            "control",
            key);
        await store.WriteAsync(
            EndpointV2HealthState.Authenticated,
            generation: 9,
            Guid.NewGuid(),
            wtsSessionId: 3,
            CancellationToken.None);
        var original = await File.ReadAllTextAsync(path);
        var forged = original.Replace(
            $"\"processId\":{Environment.ProcessId}",
            $"\"processId\":{Environment.ProcessId + 1}",
            StringComparison.Ordinal);
        Assert.NotEqual(original, forged);
        await File.WriteAllTextAsync(path, forged);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.LoadAsync(CancellationToken.None));
    }
    [Fact]
    public async Task V2_health_rejects_wrong_authenticator_and_accepts_fresh_authentic_record()
    {
        var path = Path.Combine(root, EndpointStateFiles.V2Health);
        Directory.CreateDirectory(root);
        var endpoint = EndpointIdentity.Create();
        var key = RandomNumberGenerator.GetBytes(32);
        var store = new DvcEndpointV2HealthStore(
            path,
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            "node",
            "control",
            key);
        await store.WriteAsync(
            EndpointV2HealthState.Authenticated,
            generation: 11,
            Guid.NewGuid(),
            wtsSessionId: Process.GetCurrentProcess().SessionId,
            CancellationToken.None);

        var authentic = await store.LoadAsync(CancellationToken.None);
        Assert.NotNull(authentic);
        Assert.Equal(authentic.Observation,
            EndpointV2HealthAuthenticator.Verify(authentic, key));
        Assert.Throws<InvalidDataException>(() =>
            EndpointV2HealthAuthenticator.Verify(
                authentic,
                RandomNumberGenerator.GetBytes(32)));
    }
    [Fact]
    public void Server_options_select_v2_ledger_without_finite_nonce_inventory()
    {
        var key = Path.Combine(root, "carrier.key");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(key, new byte[32]);
        var ledger = Path.Combine(root, "reconnect.db");
        var receipt = Path.Combine(root, "health.json");
        var nodeKey = Path.Combine(root, "node.key");
        var controlKey = Path.Combine(root, "control.key");
        File.WriteAllText(nodeKey, "node-key");
        File.WriteAllText(controlKey, "control-key");

        var options = ServerOptions.Parse(
        [
            "--session-id", Guid.NewGuid().ToString("D"),
            "--host-id", Guid.NewGuid().ToString("D"),
            "--incarnation-id", Guid.NewGuid().ToString("D"),
            "--auth-key-file", key,
            "--reconnect-ledger-file", ledger,
            "--readiness-receipt-file", receipt,
            "--node-signing-key-file", nodeKey,
            "--node-identity", "node",
            "--control-signing-key-file", controlKey,
            "--control-identity", "control"
        ]);

        Assert.Equal(ledger, options.ReconnectLedgerFile);
        Assert.Null(options.NonceSequenceFile);
    }

    [Fact]
    public void V2_server_options_require_full_signed_secure_transport()
    {
        var key = Path.Combine(root, "carrier.key");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(key, new byte[32]);

        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(
        [
            "--session-id", Guid.NewGuid().ToString("D"),
            "--host-id", Guid.NewGuid().ToString("D"),
            "--incarnation-id", Guid.NewGuid().ToString("D"),
            "--auth-key-file", key,
            "--reconnect-ledger-file", Path.Combine(root, "reconnect.db"),
            "--readiness-receipt-file", Path.Combine(root, "health.json")
        ]));
    }
    [Fact]
    public void Server_options_reject_ambiguous_v1_and_v2_state()
    {
        var key = Path.Combine(root, "carrier.key");
        var nonce = Path.Combine(root, "nonce.json");
        Directory.CreateDirectory(root);
        File.WriteAllBytes(key, new byte[32]);
        File.WriteAllText(nonce, "{}");

        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(
        [
            "--session-id", Guid.NewGuid().ToString("D"),
            "--host-id", Guid.NewGuid().ToString("D"),
            "--incarnation-id", Guid.NewGuid().ToString("D"),
            "--auth-key-file", key,
            "--nonce-sequence-file", nonce,
            "--reconnect-ledger-file", Path.Combine(root, "reconnect.db"),
            "--readiness-receipt-file", Path.Combine(root, "health.json")
        ]));
    }
    [Fact]
    public void V1_server_options_require_signed_exact_retained_migration()
    {
        var files = CreateV1MigrationFiles("1.0.23");

        var options = ServerOptions.Parse(
        [
            "--session-id", files.SessionId.ToString("D"),
            "--host-id", files.HostId.ToString("D"),
            "--incarnation-id", files.IncarnationId.ToString("D"),
            "--auth-key-file", files.AuthenticationKeyFile,
            "--nonce-sequence-file", files.NonceFile,
            "--v1-migration-authorization-file", files.AuthorizationFile,
            "--readiness-receipt-file", files.ReadinessFile,
            "--node-signing-key-file", files.NodeSigningKeyFile,
            "--node-identity", "node",
            "--control-signing-key-file", files.ControlSigningKeyFile,
            "--control-identity", "control"
        ]);

        Assert.Equal(files.NonceFile, options.NonceSequenceFile);
        Assert.Equal(
            files.AuthorizationFile,
            options.V1MigrationAuthorizationFile);
        Assert.Null(options.ReconnectLedgerFile);
    }

    [Fact]
    public void V1_server_options_reject_unmarked_nonce_inventory()
    {
        var files = CreateV1MigrationFiles("1.0.23");

        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(
        [
            "--session-id", files.SessionId.ToString("D"),
            "--host-id", files.HostId.ToString("D"),
            "--incarnation-id", files.IncarnationId.ToString("D"),
            "--auth-key-file", files.AuthenticationKeyFile,
            "--nonce-sequence-file", files.NonceFile,
            "--readiness-receipt-file", files.ReadinessFile,
            "--node-signing-key-file", files.NodeSigningKeyFile,
            "--node-identity", "node",
            "--control-signing-key-file", files.ControlSigningKeyFile,
            "--control-identity", "control"
        ]));
    }

    [Fact]
    public void V1_server_options_reject_signed_downgrade_marker()
    {
        var files = CreateV1MigrationFiles("1.0.22");

        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(
        [
            "--session-id", files.SessionId.ToString("D"),
            "--host-id", files.HostId.ToString("D"),
            "--incarnation-id", files.IncarnationId.ToString("D"),
            "--auth-key-file", files.AuthenticationKeyFile,
            "--nonce-sequence-file", files.NonceFile,
            "--v1-migration-authorization-file", files.AuthorizationFile,
            "--readiness-receipt-file", files.ReadinessFile,
            "--node-signing-key-file", files.NodeSigningKeyFile,
            "--node-identity", "node",
            "--control-signing-key-file", files.ControlSigningKeyFile,
            "--control-identity", "control"
        ]));
    }
    [Fact]
    public async Task Ten_thousand_reservations_are_durable_and_monotonic()
    {
        var path = DatabasePath();
        var endpoint = EndpointIdentity.Create();
        ReconnectAttempt? latest = null;

        var ledger = new ReconnectLedger(path);
        for (var index = 1; index <= 10_000; index++)
        {
            if (index % 1_000 == 0)
                ledger = new ReconnectLedger(path);
            latest = await ledger.ReserveAsync(
                endpoint.SessionId,
                endpoint.HostId,
                endpoint.NodeIncarnationId,
                Guid.NewGuid(),
                DateTimeOffset.UtcNow);
            Assert.Equal(index, latest.Generation);
        }

        var restored = await new ReconnectLedger(path).LoadAsync(
            latest!.Generation);
        Assert.Equal(latest, restored);
    }

    [Fact]
    public async Task Crash_after_each_boundary_resumes_without_generation_reset()
    {
        var path = DatabasePath();
        var endpoint = EndpointIdentity.Create();
        var attemptId = Guid.NewGuid();
        var reserved = await new ReconnectLedger(path).ReserveAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            attemptId,
            DateTimeOffset.UtcNow);
        var transitions = new[]
        {
            (ReconnectAttemptState.Reserved,
                ReconnectAttemptState.CarrierAuthenticated),
            (ReconnectAttemptState.CarrierAuthenticated,
                ReconnectAttemptState.SecureAuthenticated),
            (ReconnectAttemptState.SecureAuthenticated,
                ReconnectAttemptState.Online),
            (ReconnectAttemptState.Online,
                ReconnectAttemptState.Closed)
        };

        foreach (var (expected, next) in transitions)
        {
            var ledger = new ReconnectLedger(path);
            var current = await ledger.LoadAsync(reserved.Generation);
            Assert.Equal(expected, current!.State);
            await ledger.TransitionAsync(
                endpoint.SessionId,
                endpoint.HostId,
                endpoint.NodeIncarnationId,
                reserved.Generation,
                attemptId,
                expected,
                next,
                DateTimeOffset.UtcNow);
        }

        var nextAttempt = await new ReconnectLedger(path).ReserveAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            Guid.NewGuid(),
            DateTimeOffset.UtcNow);
        Assert.Equal(reserved.Generation + 1, nextAttempt.Generation);
    }

    [Fact]
    public async Task New_reservation_abandons_crash_left_online_attempt()
    {
        var path = DatabasePath();
        var endpoint = EndpointIdentity.Create();
        var attemptId = Guid.NewGuid();
        var ledger = new ReconnectLedger(path);
        var first = await ledger.ReserveAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            attemptId,
            DateTimeOffset.UtcNow);
        await ledger.TransitionAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            first.Generation,
            attemptId,
            ReconnectAttemptState.Reserved,
            ReconnectAttemptState.CarrierAuthenticated,
            DateTimeOffset.UtcNow);
        await ledger.TransitionAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            first.Generation,
            attemptId,
            ReconnectAttemptState.CarrierAuthenticated,
            ReconnectAttemptState.SecureAuthenticated,
            DateTimeOffset.UtcNow);
        await ledger.TransitionAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            first.Generation,
            attemptId,
            ReconnectAttemptState.SecureAuthenticated,
            ReconnectAttemptState.Online,
            DateTimeOffset.UtcNow);

        _ = await new ReconnectLedger(path).ReserveAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            Guid.NewGuid(),
            DateTimeOffset.UtcNow);
        var abandoned = await new ReconnectLedger(path).LoadAsync(
            first.Generation);

        Assert.Equal(ReconnectAttemptState.Abandoned, abandoned!.State);
    }
    [Fact]
    public async Task Replay_cross_identity_and_invalid_transition_fail_closed()
    {
        var path = DatabasePath();
        var endpoint = EndpointIdentity.Create();
        var attemptId = Guid.NewGuid();
        var ledger = new ReconnectLedger(path);
        var reserved = await ledger.ReserveAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            attemptId,
            DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ledger.TransitionAsync(
                endpoint.SessionId,
                endpoint.HostId,
                endpoint.NodeIncarnationId,
                reserved.Generation,
                Guid.NewGuid(),
                ReconnectAttemptState.Reserved,
                ReconnectAttemptState.CarrierAuthenticated,
                DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            ledger.TransitionAsync(
                endpoint.SessionId,
                endpoint.HostId,
                endpoint.NodeIncarnationId,
                reserved.Generation,
                attemptId,
                ReconnectAttemptState.Reserved,
                ReconnectAttemptState.Online,
                DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ledger.ReserveAsync(
                endpoint.SessionId,
                Guid.NewGuid(),
                endpoint.NodeIncarnationId,
                Guid.NewGuid(),
                DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task Seven_day_outage_consumes_no_generation()
    {
        var path = DatabasePath();
        var endpoint = EndpointIdentity.Create();
        var attemptId = Guid.NewGuid();
        var observedAt = DateTimeOffset.UtcNow;
        var first = await new ReconnectLedger(path).ReserveAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            attemptId,
            observedAt);

        var restored = await new ReconnectLedger(path).LoadAsync(
            first.Generation);
        Assert.Equal(first, restored);
        var authenticated = await new ReconnectLedger(path).TransitionAsync(
            endpoint.SessionId,
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            first.Generation,
            attemptId,
            ReconnectAttemptState.Reserved,
            ReconnectAttemptState.CarrierAuthenticated,
            observedAt.AddDays(7));

        Assert.Equal(first.Generation, authenticated.Generation);
    }

    [Fact]
    public void Reconnect_classifier_retries_typed_transport_failures_but_not_invariants()
    {
        Assert.True(Program.IsRecoverableV2AttemptFailure(
            new TransportDisconnectedException("DVC closed.")));
        Assert.True(Program.IsRecoverableV2AttemptFailure(
            new TransientTransportException("DVC unavailable.")));
        Assert.False(Program.IsRecoverableV2AttemptFailure(
            new InvalidOperationException("ledger invariant")));
    }

    [Fact]
    public void Reconnect_backoff_uses_a_bounded_delay_after_clean_close()
    {
        var cleanClose = Enumerable.Range(0, 64)
            .Select(_ => Program.CreateReconnectDelay(0))
            .ToArray();
        var firstFailure = Enumerable.Range(0, 64)
            .Select(_ => Program.CreateReconnectDelay(1))
            .ToArray();
        var capped = Enumerable.Range(0, 64)
            .Select(_ => Program.CreateReconnectDelay(20))
            .ToArray();

        Assert.All(cleanClose, AssertBaseDelay);
        Assert.True(cleanClose.Distinct().Count() > 1);
        Assert.All(firstFailure, AssertBaseDelay);
        Assert.True(firstFailure.Distinct().Count() > 1);
        Assert.All(capped, value => Assert.InRange(
            value,
            TimeSpan.FromSeconds(15),
            TimeSpan.FromSeconds(30)));
        Assert.True(capped.Distinct().Count() > 1);
    }

    [Fact]
    public void Ten_thousand_clean_attempt_completions_never_exhaust_backoff()
    {
        for (var attempt = 0; attempt < 10_000; attempt++)
            AssertBaseDelay(Program.CreateReconnectDelay(0));
    }

    private V1MigrationFiles CreateV1MigrationFiles(string endpointVersion)
    {
        Directory.CreateDirectory(root);
        var sessionId = Guid.NewGuid();
        var hostId = Guid.NewGuid();
        var incarnationId = Guid.NewGuid();
        var authenticationKeyFile = Path.Combine(root, Guid.NewGuid() + ".key");
        var nonceFile = Path.Combine(root, Guid.NewGuid() + ".nonces.json");
        var authorizationFile = Path.Combine(root, Guid.NewGuid() + ".migration.json");
        var nodeSigningKeyFile = Path.Combine(root, Guid.NewGuid() + ".node.pk8");
        var controlSigningKeyFile = Path.Combine(root, Guid.NewGuid() + ".control.spki");
        var readinessFile = Path.Combine(root, Guid.NewGuid() + ".health.json");
        File.WriteAllBytes(authenticationKeyFile, RandomNumberGenerator.GetBytes(32));
        var nonceState = new DvcConnectionNonceSequence(
            1,
            sessionId,
            hostId,
            incarnationId,
            [Guid.NewGuid(), Guid.NewGuid()],
            1);
        var nonceBytes = JsonSerializer.SerializeToUtf8Bytes(
            nonceState,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        File.WriteAllBytes(nonceFile, nonceBytes);
        using var node = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var control = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllBytes(nodeSigningKeyFile, node.ExportPkcs8PrivateKey());
        File.WriteAllBytes(
            controlSigningKeyFile,
            control.ExportSubjectPublicKeyInfo());
        var body = new
        {
            version = 1,
            retainedEndpointVersion = endpointVersion,
            sessionId,
            hostId,
            nodeIncarnationId = incarnationId,
            nonceCount = nonceState.Nonces.Count,
            nextIndex = nonceState.NextIndex,
            inventorySha256 = Convert.ToHexString(SHA256.HashData(nonceBytes))
        };
        var canonical = JsonSerializer.SerializeToUtf8Bytes(body);
        var authorization = new
        {
            body,
            signature = Convert.ToBase64String(node.SignData(
                canonical,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence))
        };
        File.WriteAllBytes(
            authorizationFile,
            JsonSerializer.SerializeToUtf8Bytes(authorization));
        return new(
            sessionId,
            hostId,
            incarnationId,
            authenticationKeyFile,
            nonceFile,
            authorizationFile,
            nodeSigningKeyFile,
            controlSigningKeyFile,
            readinessFile);
    }

    private sealed record V1MigrationFiles(
        Guid SessionId,
        Guid HostId,
        Guid IncarnationId,
        string AuthenticationKeyFile,
        string NonceFile,
        string AuthorizationFile,
        string NodeSigningKeyFile,
        string ControlSigningKeyFile,
        string ReadinessFile);
    private static void AssertBaseDelay(TimeSpan value) =>
        Assert.InRange(
            value,
            TimeSpan.FromMilliseconds(125),
            TimeSpan.FromMilliseconds(250));
    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private string DatabasePath()
    {
        Directory.CreateDirectory(root);
        return Path.Combine(root, "reconnect.db");
    }

    private sealed record EndpointIdentity(
        Guid SessionId,
        Guid HostId,
        Guid NodeIncarnationId)
    {
        public static EndpointIdentity Create() =>
            new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
    }
}

