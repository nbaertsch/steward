using System.Security.Cryptography;
using Steward.Maintenance.Windows;

namespace Steward.Maintenance.Windows.Tests;

public sealed class EndpointInstallerHandoffTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "steward-installer-handoff-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void Handoff_intent_is_durable_before_trigger_and_restart_preserves_CAS_generation()
    {
        Directory.CreateDirectory(root);
        var key = RandomNumberGenerator.GetBytes(32);
        var path = Path.Combine(root, "handoff.journal");
        var intent = Intent();
        var first = new FileEndpointInstallerHandoffStore(path, key);

        var prepared = first.Prepare(intent);

        Assert.Equal(EndpointInstallerHandoffPhase.IntentCommitted, prepared.Phase);
        Assert.Equal((ulong)1, prepared.Generation);
        var restarted = new FileEndpointInstallerHandoffStore(path, key);
        Assert.Equal(prepared, restarted.Current);

        var triggered = restarted.MarkTriggered(
            intent.TransactionId,
            intent.OwnerCapability,
            expectedGeneration: 1);
        Assert.Equal(EndpointInstallerHandoffPhase.Triggered, triggered.Phase);
        Assert.Equal((ulong)2, triggered.Generation);
        Assert.Equal(triggered, new FileEndpointInstallerHandoffStore(path, key).Current);
    }

    [Fact]
    public void Handoff_replay_is_idempotent_and_stale_generation_or_second_transaction_is_rejected()
    {
        Directory.CreateDirectory(root);
        var key = RandomNumberGenerator.GetBytes(32);
        var store = new FileEndpointInstallerHandoffStore(
            Path.Combine(root, "handoff.journal"),
            key);
        var intent = Intent();
        var prepared = store.Prepare(intent);

        Assert.Equal(prepared, store.Prepare(intent));
        var triggered = store.MarkTriggered(
            intent.TransactionId,
            intent.OwnerCapability,
            prepared.Generation);
        Assert.Equal(triggered, store.MarkTriggered(
            intent.TransactionId,
            intent.OwnerCapability,
            prepared.Generation));
        Assert.Throws<EndpointInstallerHandoffException>(() =>
            store.MarkTriggered(
                intent.TransactionId,
                EndpointOwnerCapability.Create(),
                triggered.Generation));
        Assert.Throws<EndpointInstallerHandoffException>(() =>
            store.Prepare(intent with { TransactionId = Guid.NewGuid() }));
    }

    [Theory]
    [InlineData((int)EndpointInstallerReceiptOutcome.Committed)]
    [InlineData((int)EndpointInstallerReceiptOutcome.RolledBack)]
    public void Terminal_receipt_is_bound_to_transaction_capability_digest_and_product_identity(
        int outcomeValue)
    {
        Directory.CreateDirectory(root);
        var key = RandomNumberGenerator.GetBytes(32);
        var path = Path.Combine(root, "handoff.journal");
        var store = new FileEndpointInstallerHandoffStore(path, key);
        var intent = Intent();
        var prepared = store.Prepare(intent);
        var triggered = store.MarkTriggered(
            intent.TransactionId,
            intent.OwnerCapability,
            prepared.Generation);
        var receipt = EndpointInstallerHandoffReceipt.Create(
            intent,
            (EndpointInstallerReceiptOutcome)outcomeValue,
            installerExitCode: outcomeValue ==
                (int)EndpointInstallerReceiptOutcome.Committed ? 0 : 1603);

        var terminal = store.RecordReceipt(
            receipt,
            expectedGeneration: triggered.Generation);

        Assert.Equal(
            (EndpointInstallerReceiptOutcome)outcomeValue ==
                EndpointInstallerReceiptOutcome.Committed
                ? EndpointInstallerHandoffPhase.Committed
                : EndpointInstallerHandoffPhase.RolledBack,
            terminal.Phase);
        Assert.Equal(terminal, new FileEndpointInstallerHandoffStore(path, key).Current);

        var mismatched = receipt with { MsiSha256 = new string('F', 64) };
        Assert.Throws<EndpointInstallerHandoffException>(() =>
            store.RecordReceipt(mismatched, terminal.Generation));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private static EndpointInstallerHandoffIntent Intent() => new(
        1,
        Guid.Parse("11111111-1111-1111-1111-111111111111"),
        17,
        EndpointOwnerCapability.Create(),
        "1.2.3",
        new string('A', 64),
        4096,
        Guid.Parse("22222222-2222-2222-2222-222222222222"),
        Guid.Parse("37C34E0A-E245-48A4-B07C-78E2955A7E65"),
        "release-1.2.3-aaaaaaaaaaaaaaaa",
        new string('B', 64),
        EndpointInstallerHandoffAction.InstallEndpoint);
}
