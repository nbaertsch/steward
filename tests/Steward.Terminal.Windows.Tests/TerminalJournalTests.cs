using System.Text;
using Steward.Domain;
using Steward.Terminal.Abstractions;
using Steward.Terminal.Windows;

namespace Steward.Terminal.Windows.Tests;

public sealed class TerminalJournalTests : IDisposable
{
    private readonly string directory = Path.Combine(
        Path.GetTempPath(), "steward-terminal-journal-tests", Guid.NewGuid().ToString("N"));

    public TerminalJournalTests() => Directory.CreateDirectory(directory);

    [Fact]
    public void Journal_is_wal_full_and_rejects_unknown_schema()
    {
        var path = Path.Combine(directory, "journal.db");
        _ = new TerminalJournal(path);
        using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA journal_mode;";
            Assert.Equal("wal", command.ExecuteScalar()?.ToString(), ignoreCase: true);
            command.CommandText = "PRAGMA synchronous;";
            Assert.Equal(2L, Convert.ToInt64(command.ExecuteScalar()));
        }

        var unknown = Path.Combine(directory, "unknown.db");
        using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={unknown}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version=999;";
            command.ExecuteNonQuery();
        }
        Assert.Throws<TerminalJournalSchemaException>(() => new TerminalJournal(unknown));
    }

    [Fact]
    public void Idempotency_replays_identical_intent_and_rejects_conflict()
    {
        var journal = CreateJournal();
        var request = Request(TerminalTranscriptMode.None);
        var first = journal.CreateRequested(request, "fingerprint-a", "boot", DateTimeOffset.UtcNow);
        var replay = journal.CreateRequested(request, "fingerprint-a", "boot", DateTimeOffset.UtcNow);
        Assert.Equal(first, replay);

        var error = Assert.Throws<TerminalException>(() =>
            journal.CreateRequested(request, "fingerprint-b", "boot", DateTimeOffset.UtcNow));
        Assert.Equal(TerminalProblemCode.IdempotencyConflict, error.Problem.Code);
    }

    [Theory]
    [InlineData(TerminalTranscriptMode.None, 0, false)]
    [InlineData(TerminalTranscriptMode.Metadata, 2, false)]
    [InlineData(TerminalTranscriptMode.Full, 2, true)]
    public void Transcript_policy_is_explicit(
        TerminalTranscriptMode mode,
        int expectedRecords,
        bool expectsContent)
    {
        var journal = CreateJournal();
        var request = Request(mode);
        var snapshot = journal.CreateRequested(request, "fingerprint", "boot", DateTimeOffset.UtcNow);
        snapshot = journal.SetOpening(snapshot.SessionId, snapshot.Revision, DateTimeOffset.UtcNow);
        snapshot = journal.SetOpen(snapshot.SessionId, snapshot.Revision, Environment.ProcessId,
            DateTime.UtcNow.Ticks, "test", DateTimeOffset.UtcNow);
        var input = Encoding.UTF8.GetBytes("secret-shaped-input");
        snapshot = journal.AccountInput(snapshot.SessionId, snapshot.Revision, input,
            new string('A', 64), DateTimeOffset.UtcNow, true);
        journal.AppendOutput(snapshot.SessionId, 1, 0, "output"u8, new string('B', 64), DateTimeOffset.UtcNow);

        var transcript = journal.ReadTranscript(snapshot.SessionId);
        Assert.Equal(expectedRecords, transcript.Count);
        Assert.All(transcript, record => Assert.Equal(expectsContent, record.Content is not null));
        var durable = journal.Get(snapshot.SessionId);
        Assert.Equal(expectsContent ? input.Length + 6 : 0, durable.TranscriptBytes);
        Assert.True(durable.UnmanagedMutationSuspected);
        Assert.Equal("terminal-input-conservative-policy", durable.MutationEvidence);
    }

    [Fact]
    public void Transcript_content_is_bounded_without_guessing_redaction()
    {
        var journal = CreateJournal();
        var request = Request(TerminalTranscriptMode.Full, maximumTranscriptBytes: 4);
        var snapshot = journal.CreateRequested(request, "fingerprint", "boot", DateTimeOffset.UtcNow);
        snapshot = journal.SetOpening(snapshot.SessionId, snapshot.Revision, DateTimeOffset.UtcNow);
        snapshot = journal.SetOpen(snapshot.SessionId, snapshot.Revision, Environment.ProcessId,
            DateTime.UtcNow.Ticks, "test", DateTimeOffset.UtcNow);
        journal.AppendOutput(snapshot.SessionId, 1, 0, "abcdef"u8, new string('C', 64), DateTimeOffset.UtcNow);

        var record = Assert.Single(journal.ReadTranscript(snapshot.SessionId));
        Assert.Null(record.Content);
        Assert.True(journal.Get(snapshot.SessionId).TranscriptTruncated);
    }

    [Fact]
    public void Restart_records_ambiguous_opening_and_incarnation_interruption()
    {
        var journal = CreateJournal();
        var request = Request(TerminalTranscriptMode.None);
        var opening = journal.CreateRequested(request, "a", "boot", DateTimeOffset.UtcNow);
        journal.SetOpening(opening.SessionId, opening.Revision, DateTimeOffset.UtcNow);
        var reconciled = Assert.Single(journal.ReconcileAfterRestart(
            request.Authority.NodeIncarnationId, "boot", DateTimeOffset.UtcNow));
        Assert.Equal(TerminalSessionState.Recovering, reconciled.State);
        Assert.Equal("opening-outcome-ambiguous", reconciled.InterruptionReason);

        var interrupted = Assert.Single(journal.ReconcileAfterRestart(
            NodeIncarnationId.New(), "other-boot", DateTimeOffset.UtcNow));
        Assert.Equal(TerminalSessionState.Interrupted, interrupted.State);
        Assert.Equal("node-incarnation-changed", interrupted.InterruptionReason);
        Assert.Null(journal.Find(TerminalSessionId.New()));
    }

    [Fact]
    public void Exact_revision_is_required()
    {
        var journal = CreateJournal();
        var request = Request(TerminalTranscriptMode.None);
        var snapshot = journal.CreateRequested(request, "a", "boot", DateTimeOffset.UtcNow);
        var error = Assert.Throws<TerminalException>(() =>
            journal.SetOpening(snapshot.SessionId, 99, DateTimeOffset.UtcNow));
        Assert.Equal(TerminalProblemCode.RevisionConflict, error.Problem.Code);
    }

    [Fact]
    public void Operational_spool_is_distinct_from_transcript_and_cursor_replay_is_bounded()
    {
        var journal = CreateJournal();
        var request = Request(TerminalTranscriptMode.None, operationalSpoolBytes: 1024);
        var snapshot = journal.CreateRequested(request, "a", "boot", DateTimeOffset.UtcNow);
        snapshot = journal.SetOpening(snapshot.SessionId, snapshot.Revision, DateTimeOffset.UtcNow);
        snapshot = journal.SetOpen(snapshot.SessionId, snapshot.Revision, Environment.ProcessId,
            DateTime.UtcNow.Ticks, "test", DateTimeOffset.UtcNow);
        journal.AppendOutput(snapshot.SessionId, 1, 0, "replay-me"u8, new string('D', 64), DateTimeOffset.UtcNow);
        var firstEos = journal.AppendEndOfStream(snapshot.SessionId, DateTimeOffset.UtcNow);
        var replayedEos = journal.AppendEndOfStream(snapshot.SessionId, DateTimeOffset.UtcNow);
        Assert.Equal(firstEos.Sequence, replayedEos.Sequence);

        Assert.Empty(journal.ReadTranscript(snapshot.SessionId));
        var context = new TerminalOperationContext(snapshot.HostId, snapshot.NodeIncarnationId, snapshot.Actor, 0);
        var page = journal.ReadOutput(new(snapshot.SessionId, context, 0, 0, 10, 1024, false),
            DateTimeOffset.UtcNow);
        Assert.Equal(2, page.Count);
        Assert.Equal("replay-me", Encoding.UTF8.GetString(page[0].Data.Span));
        Assert.True(page[1].EndOfStream);
        Assert.Equal(page[0].Sequence + 1, page[1].Sequence);

        var resumed = journal.ReadOutput(new(snapshot.SessionId, context, page[0].Sequence,
            page[0].Offset + page[0].Length, 10, 1024, false), DateTimeOffset.UtcNow);
        Assert.Single(resumed);
        Assert.True(resumed[0].EndOfStream);
        Assert.Equal(page[1].Sequence, resumed[0].Sequence);
    }

    [Fact]
    public void No_spool_policy_truthfully_reports_unavailable_history()
    {
        var journal = CreateJournal();
        var request = Request(TerminalTranscriptMode.None);
        var snapshot = journal.CreateRequested(request, "a", "boot", DateTimeOffset.UtcNow);
        snapshot = journal.SetOpening(snapshot.SessionId, snapshot.Revision, DateTimeOffset.UtcNow);
        snapshot = journal.SetOpen(snapshot.SessionId, snapshot.Revision, Environment.ProcessId,
            DateTime.UtcNow.Ticks, "test", DateTimeOffset.UtcNow);
        journal.AppendOutput(snapshot.SessionId, 1, 0, "discarded"u8, new string('E', 64), DateTimeOffset.UtcNow);
        var context = new TerminalOperationContext(snapshot.HostId, snapshot.NodeIncarnationId, snapshot.Actor, 0);
        var unavailable = Assert.Single(journal.ReadOutput(
            new(snapshot.SessionId, context, 0, 0, 10, 1024, false), DateTimeOffset.UtcNow));
        Assert.Equal(TerminalOutputContentAvailability.NotRetained, unavailable.ContentAvailability);
        Assert.True(unavailable.GapBefore);
        Assert.Equal(0, unavailable.Data.Length);
    }

    private TerminalJournal CreateJournal() => new(Path.Combine(directory, Guid.NewGuid() + ".db"));

    private TerminalOpenRequest Request(
        TerminalTranscriptMode mode,
        long maximumTranscriptBytes = 1024,
        long operationalSpoolBytes = 0)
    {
        var now = DateTimeOffset.UtcNow;
        var authority = new TerminalAuthority(
            TerminalContractLimits.SchemaVersion,
            TerminalSessionId.New(),
            HostId.New(),
            NodeIncarnationId.New(),
            "test-actor",
            directory,
            new(TaskAttemptId.New(), 1),
            now - TimeSpan.FromMinutes(1),
            now - TimeSpan.FromMinutes(1),
            now + TimeSpan.FromMinutes(10),
            TimeSpan.FromMinutes(20),
            1024,
            1024,
            mode,
            maximumTranscriptBytes,
            TerminalFileTransferCapabilities.None,
            false,
            false,
            0,
            operationalSpoolBytes == 0 ? TimeSpan.Zero : TimeSpan.FromMinutes(5),
            operationalSpoolBytes);
        return new(TerminalContractLimits.SchemaVersion, "request-" + Guid.NewGuid().ToString("N"), authority,
            TerminalShellKind.PowerShell, PowerShell(), [], directory, 80, 25);
    }

    private static string PowerShell() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");

    public void Dispose()
    {
        try { Directory.Delete(directory, true); }
        catch (IOException) { }
        GC.SuppressFinalize(this);
    }
}
