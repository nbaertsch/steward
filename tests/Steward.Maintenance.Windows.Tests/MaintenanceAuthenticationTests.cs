using System.Buffers.Binary;
using System.Security.Cryptography;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class MaintenanceAuthenticationTests
{
    [Fact]
    public void Authenticates_and_rejects_forgery_and_stale_while_identifying_replay()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = DateTimeOffset.Parse("2026-08-31T20:00:00Z");
        var time = new FixedTimeProvider(now);
        var authenticator = new MaintenanceRequestAuthenticator(
            signingKey.ExportSubjectPublicKeyInfo(),
            time,
            TimeSpan.FromMinutes(5));
        var replay = new InMemoryMaintenanceReplayStore(8);
        var body = MaintenanceContractTests.Request(
            new CollectDiagnosticsOperation(1, DiagnosticKind.MaintenanceAndEndpointHealth, 4096),
            issuedAtUtc: now).Body;
        var signed = Sign(body, signingKey);

        var accepted = authenticator.Authenticate(signed, replay);
        var replayed = authenticator.Authenticate(signed, replay);
        Assert.False(accepted.IsReplay);
        Assert.True(replayed.IsReplay);
        var forgedBody = body with { RequestId = Guid.NewGuid() };
        var forged = Sign(forgedBody, wrongKey);
        var forgedError = Assert.Throws<MaintenanceProtocolException>(() =>
            authenticator.Authenticate(forged, replay));
        Assert.Equal("authentication_failed", forgedError.Code);

        var staleBody = body with
        {
            RequestId = Guid.NewGuid(),
            IssuedAtUtc = now - TimeSpan.FromMinutes(6)
        };
        var stale = Sign(staleBody, signingKey);
        var staleError = Assert.Throws<MaintenanceProtocolException>(() =>
            authenticator.Authenticate(stale, replay));
        Assert.Equal("request_expired", staleError.Code);
    }

    [Fact]
    public void Fresh_session_challenge_authenticates_at_send_time_not_enqueue_time()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = DateTimeOffset.Parse("2026-09-01T17:00:00Z");
        var time = new FixedTimeProvider(now);
        var sessionKey = RandomNumberGenerator.GetBytes(32);
        var session = new MaintenanceSessionAuthenticator(
            sessionKey,
            time,
            TimeSpan.FromSeconds(15));
        var authenticator = new MaintenanceRequestAuthenticator(
            signingKey.ExportSubjectPublicKeyInfo(),
            time,
            TimeSpan.FromMinutes(5));
        var request = MaintenanceContractTests.Request(
            new CollectDiagnosticsOperation(
                1,
                DiagnosticKind.MaintenanceAndEndpointHealth,
                4096),
            issuedAtUtc: now - TimeSpan.FromDays(1));
        var signed = Sign(request.Body, signingKey);
        var challenge = session.CreateChallenge();
        var proof = MaintenanceSessionAuthenticator.CreateProof(
            challenge,
            signed,
            sessionKey,
            clientProcessId: 401,
            wtsSessionId: 3);

        session.Verify(
            challenge,
            signed,
            proof,
            expectedClientProcessId: 401,
            expectedWtsSessionId: 3);
        var result = authenticator.AuthenticateForSession(
            signed,
            new InMemoryMaintenanceReplayStore(8));

        Assert.False(result.IsReplay);
    }

    [Fact]
    public void Session_challenge_rejects_expiry_wrong_PID_session_and_authenticator()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = DateTimeOffset.Parse("2026-09-01T17:00:00Z");
        var time = new MutableTimeProvider(now);
        var sessionKey = RandomNumberGenerator.GetBytes(32);
        var session = new MaintenanceSessionAuthenticator(
            sessionKey,
            time,
            TimeSpan.FromSeconds(15));
        var signed = Sign(
            MaintenanceContractTests.Request(
                new RepairEndpointOperation(
                    1,
                    RepairTarget.RdpDvcEndpointTask),
                issuedAtUtc: now).Body,
            signingKey);
        var challenge = session.CreateChallenge();
        var proof = MaintenanceSessionAuthenticator.CreateProof(
            challenge,
            signed,
            sessionKey,
            clientProcessId: 401,
            wtsSessionId: 3);

        Assert.Throws<MaintenanceProtocolException>(() => session.Verify(
            challenge,
            signed,
            proof,
            expectedClientProcessId: 402,
            expectedWtsSessionId: 3));
        Assert.Throws<MaintenanceProtocolException>(() => session.Verify(
            challenge,
            signed,
            proof,
            expectedClientProcessId: 401,
            expectedWtsSessionId: 4));
        var wrongProof = MaintenanceSessionAuthenticator.CreateProof(
            challenge,
            signed,
            RandomNumberGenerator.GetBytes(32),
            clientProcessId: 401,
            wtsSessionId: 3);
        Assert.Throws<MaintenanceProtocolException>(() => session.Verify(
            challenge,
            signed,
            wrongProof,
            expectedClientProcessId: 401,
            expectedWtsSessionId: 3));
        time.UtcNow = now + TimeSpan.FromSeconds(16);
        Assert.Throws<MaintenanceProtocolException>(() => session.Verify(
            challenge,
            signed,
            proof,
            expectedClientProcessId: 401,
            expectedWtsSessionId: 3));
    }
    [Fact]
    public async Task Framing_rejects_zero_oversized_truncated_and_trailing_frames()
    {
        foreach (var length in new[] { 0, MaintenanceIpcProtocol.AbsoluteMaximumFrameBytes + 1 })
        {
            var prefix = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(prefix, length);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                MaintenanceIpcProtocol.ReadRequestAsync(
                    new MemoryStream(prefix),
                    4096,
                    default).AsTask());
        }

        var truncated = new byte[6];
        BinaryPrimitives.WriteInt32LittleEndian(truncated, 10);
        await Assert.ThrowsAnyAsync<EndOfStreamException>(() =>
            MaintenanceIpcProtocol.ReadRequestAsync(
                new MemoryStream(truncated),
                4096,
                default).AsTask());

        var valid = MaintenanceContract.Serialize(MaintenanceContractTests.Request(
            new CollectDiagnosticsOperation(1, DiagnosticKind.MaintenanceAndEndpointHealth, 4096)));
        var framed = new byte[4 + valid.Length + 1];
        BinaryPrimitives.WriteInt32LittleEndian(framed, valid.Length + 1);
        valid.CopyTo(framed.AsSpan(4));
        framed[^1] = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MaintenanceIpcProtocol.ReadRequestAsync(
                new MemoryStream(framed),
                1024,
                default).AsTask());
    }

    [Fact]
    public void Ipc_options_are_strictly_bounded()
    {
        _ = new MaintenanceIpcOptions(
            "Steward.Maintenance.v1",
            64 * 1024,
            4,
            TimeSpan.FromSeconds(10));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MaintenanceIpcOptions(
            "Steward.Maintenance.v1",
            MaintenanceIpcProtocol.AbsoluteMaximumFrameBytes + 1,
            4,
            TimeSpan.FromSeconds(10)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MaintenanceIpcOptions(
            "Steward.Maintenance.v1",
            4096,
            17,
            TimeSpan.FromSeconds(10)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MaintenanceIpcOptions(
            "Steward.Maintenance.v1",
            4096,
            4,
            TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public void Replay_rejection_survives_store_restart_and_tampering_fails_closed()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "steward-maintenance-replay-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "replay.journal");
            var key = RandomNumberGenerator.GetBytes(32);
            var now = DateTimeOffset.UtcNow;
            var requestId = Guid.NewGuid();
            var first = new FileMaintenanceReplayStore(path, key, 16);
            Assert.True(first.TryAccept(requestId, now.AddMinutes(5), now));
            var restarted = new FileMaintenanceReplayStore(path, key, 16);
            Assert.False(restarted.TryAccept(requestId, now.AddMinutes(5), now));

            var bytes = File.ReadAllBytes(path);
            bytes[^1] ^= 0x1;
            File.WriteAllBytes(path, bytes);
            Assert.Throws<InvalidDataException>(() =>
                restarted.TryAccept(Guid.NewGuid(), now.AddMinutes(5), now));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    internal static AuthenticatedMaintenanceRequest Sign(
        MaintenanceRequestBody body,
        ECDsa key) =>
        new(
            body,
            Convert.ToBase64String(key.SignData(
                MaintenanceContract.Canonicalize(body),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence)));

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        internal DateTimeOffset UtcNow { get; set; } = utcNow;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}

