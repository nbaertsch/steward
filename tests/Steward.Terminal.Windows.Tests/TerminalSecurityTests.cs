using System.Diagnostics;
using Steward.Domain;
using Steward.Terminal.Abstractions;
using Steward.Terminal.Windows;

namespace Steward.Terminal.Windows.Tests;

public sealed class TerminalSecurityTests : IAsyncLifetime
{
    private readonly string directory = Path.Combine(
        Path.GetTempPath(), "steward-terminal-security-tests", Guid.NewGuid().ToString("N"));

    public Task InitializeAsync()
    {
        Directory.CreateDirectory(directory);
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Authority_binding_expiry_revocation_and_incarnation_are_enforced()
    {
        var host = HostId.New();
        var node = NodeIncarnationId.New();
        var context = new TerminalOperationContext(host, node, "actor", 0);

        await using (var service = CreateService(host, node, () => 0))
        {
            var mismatch = Request(Authority(host, node) with { Actor = "other" });
            var actorError = await Assert.ThrowsAsync<TerminalException>(() =>
                service.OpenAsync(mismatch, context).AsTask());
            Assert.Equal(TerminalProblemCode.AuthorityMismatch, actorError.Problem.Code);

            var incarnation = Request(Authority(host, NodeIncarnationId.New()));
            var incarnationError = await Assert.ThrowsAsync<TerminalException>(() =>
                service.OpenAsync(incarnation, context).AsTask());
            Assert.Equal(TerminalProblemCode.AuthorityMismatch, incarnationError.Problem.Code);

            var expiredAuthority = Authority(host, node) with
            {
                IssuedAt = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(10),
                NotBefore = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(10),
                ExpiresAt = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(1)
            };
            var expired = await Assert.ThrowsAsync<TerminalException>(() =>
                service.OpenAsync(Request(expiredAuthority), context).AsTask());
            Assert.Equal(TerminalProblemCode.AuthorityExpired, expired.Problem.Code);

            var futureAuthority = Authority(host, node) with
            {
                NotBefore = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(1)
            };
            var future = await Assert.ThrowsAsync<TerminalException>(() =>
                service.OpenAsync(Request(futureAuthority), context).AsTask());
            Assert.Equal(TerminalProblemCode.AuthorityNotYetValid, future.Problem.Code);
        }

        await using (var revokedService = CreateService(host, node, () => 2))
        {
            var revoked = await Assert.ThrowsAsync<TerminalException>(() =>
                revokedService.OpenAsync(Request(Authority(host, node) with { RevocationRevision = 1 }),
                    context).AsTask());
            Assert.Equal(TerminalProblemCode.AuthorityRevoked, revoked.Problem.Code);
        }
    }

    [Fact]
    public async Task Requested_but_ungranted_elevation_is_never_launched()
    {
        var host = HostId.New();
        var node = NodeIncarnationId.New();
        await using var service = CreateService(host, node, () => 0);
        var authority = Authority(host, node) with { ElevationRequested = true, ElevationGranted = false };
        var error = await Assert.ThrowsAsync<TerminalException>(() =>
            service.OpenAsync(Request(authority), Context(authority)).AsTask());
        Assert.Equal(TerminalProblemCode.ElevationUnavailable, error.Problem.Code);
        Assert.Null(Journal().Find(authority.SessionId));

        var granted = Authority(host, node) with { ElevationRequested = true, ElevationGranted = true };
        var grantedError = await Assert.ThrowsAsync<TerminalException>(() =>
            service.OpenAsync(Request(granted), Context(granted)).AsTask());
        Assert.Equal(TerminalProblemCode.ElevationUnavailable, grantedError.Problem.Code);
        Assert.False(grantedError.Problem.SideEffectMayHaveOccurred);
    }

    [Fact]
    public void Traversal_and_reparse_escape_are_rejected()
    {
        Assert.Throws<TerminalException>(() =>
            TerminalWorkspacePaths.ValidateWorkingDirectory(directory, Path.GetFullPath(Path.Combine(directory, ".."))));

        var outside = Path.GetDirectoryName(directory)!;
        var link = Path.Combine(directory, "link");
        var process = Process.Start(new ProcessStartInfo(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            $"/d /c mklink /J \"{link}\" \"{outside}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false
        })!;
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        var error = Assert.Throws<TerminalException>(() =>
            TerminalWorkspacePaths.ValidateWorkingDirectory(directory, link));
        Assert.Equal(TerminalProblemCode.PathRejected, error.Problem.Code);
    }

    [Fact]
    public void Malformed_contracts_are_rejected()
    {
        var authority = Authority(HostId.New(), NodeIncarnationId.New());
        var nul = Request(authority) with { Arguments = ["ok", "bad\0argument"] };
        var error = Assert.Throws<TerminalException>(() => TerminalContractLimits.ValidateOpen(nul));
        Assert.Equal(TerminalProblemCode.InvalidRequest, error.Problem.Code);

        var credentialActor = authority with { Actor = "https://user:password@example.invalid/" };
        var secretError = Assert.Throws<TerminalException>(() =>
            TerminalContractLimits.ValidateAuthorityShape(credentialActor));
        Assert.Equal(TerminalProblemCode.InvalidRequest, secretError.Problem.Code);
    }

    [Fact]
    public async Task File_transfer_is_explicitly_denied()
    {
        var host = HostId.New();
        var node = NodeIncarnationId.New();
        var authority = Authority(host, node);
        var journal = Journal();
        var request = Request(authority);
        journal.CreateRequested(request, "fingerprint", "boot", DateTimeOffset.UtcNow);
        await using var service = new TerminalSessionService(journal, host, node, "new-boot");
        var error = await Assert.ThrowsAsync<TerminalException>(() =>
            service.DownloadFileAsync(authority.SessionId, Context(authority)).AsTask());
        Assert.Equal(TerminalProblemCode.CapabilityDenied, error.Problem.Code);
    }

    private TerminalSessionService CreateService(HostId host, NodeIncarnationId node, Func<long> revision) =>
        new(Journal(), host, node, "boot", currentRevocationRevision: revision);

    private TerminalJournal Journal() => new(Path.Combine(directory, "journal.db"));

    private TerminalAuthority Authority(HostId host, NodeIncarnationId node)
    {
        var now = DateTimeOffset.UtcNow;
        return new(TerminalContractLimits.SchemaVersion, TerminalSessionId.New(), host, node, "actor",
            directory, null, now - TimeSpan.FromSeconds(1), now - TimeSpan.FromSeconds(1),
            now + TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(10), 1024 * 1024, 1024 * 1024,
            TerminalTranscriptMode.None, 0, TerminalFileTransferCapabilities.None, false, false, 0);
    }

    private TerminalOpenRequest Request(TerminalAuthority authority) =>
        new(TerminalContractLimits.SchemaVersion, "request-" + Guid.NewGuid().ToString("N"), authority,
            TerminalShellKind.PowerShell, PowerShell(), ["-NoLogo", "-NoProfile"], directory, 80, 25);

    private static TerminalOperationContext Context(TerminalAuthority authority) =>
        new(authority.HostId, authority.NodeIncarnationId, authority.Actor, authority.RevocationRevision);

    private static string PowerShell() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");

    public Task DisposeAsync()
    {
        var link = Path.Combine(directory, "link");
        try
        {
            if (Directory.Exists(link))
                Directory.Delete(link);
            Directory.Delete(directory, true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        return Task.CompletedTask;
    }
}
