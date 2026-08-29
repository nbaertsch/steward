using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;
using Steward.Terminal.Abstractions;

namespace Steward.Application;

public sealed record IssueTerminalAuthorityRequest(
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string Actor,
    string WorkspaceRoot,
    TerminalTaskBinding? Task,
    TimeSpan Duration,
    TerminalTranscriptMode TranscriptMode = TerminalTranscriptMode.Metadata,
    bool ElevationRequested = false,
    long MaximumInputBytes = 4 * 1024 * 1024,
    long MaximumOutputBytes = 16 * 1024 * 1024);

public sealed record TerminalControlPolicy(
    IReadOnlySet<string> AllowedActors,
    IReadOnlySet<HostId> AllowedHosts,
    IReadOnlyList<string> AllowedWorkspaceRoots,
    IReadOnlySet<string> ElevatedActors,
    IReadOnlySet<HostId> ElevatedHosts,
    TimeSpan MaximumDuration,
    long MaximumInputBytes,
    long MaximumOutputBytes)
{
    public static TerminalControlPolicy DenyAll { get; } =
        new(new HashSet<string>(), new HashSet<HostId>(), [],
            new HashSet<string>(), new HashSet<HostId>(),
            TimeSpan.FromMinutes(30), 4 * 1024 * 1024, 16 * 1024 * 1024);
}

public interface ILocalActorContext
{
    string Actor { get; }
}

public sealed class TerminalApplicationService(
    SqliteControlStore store,
    ControlTerminalRouter router,
    ControlTerminalRevocationStore revocations,
    ControlNodeRegistrationStore nodes,
    TerminalControlPolicy policy,
    ILocalActorContext actor,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<TerminalAuthority> IssueAsync(
        IssueTerminalAuthorityRequest request,
        CancellationToken cancellationToken = default)
    {
        var now = clock.GetUtcNow();
        var registrations = await nodes.ListAsync(cancellationToken);
        var node = registrations.SingleOrDefault(x =>
            x.HostId == request.HostId &&
            x.NodeIncarnationId == request.NodeIncarnationId &&
            x.Enabled)
            ?? throw new ApplicationContractException(
                "TerminalHostUnavailable", "Selected Host and Node registration is unavailable.");
        if (!policy.AllowedActors.Contains(actor.Actor) ||
            !policy.AllowedHosts.Contains(request.HostId))
            throw new ApplicationContractException(
                "TerminalAuthorityDenied", "Terminal actor or Host is not allowed.");
        var workspace = Path.GetFullPath(request.WorkspaceRoot);
        if (!policy.AllowedWorkspaceRoots.Any(root => IsContained(root, workspace)))
            throw new ApplicationContractException(
                "TerminalWorkspaceDenied", "Terminal workspace is outside allowed roots.");
        if (request.Duration <= TimeSpan.Zero || request.Duration > policy.MaximumDuration ||
            request.MaximumInputBytes <= 0 || request.MaximumInputBytes > policy.MaximumInputBytes ||
            request.MaximumOutputBytes <= 0 || request.MaximumOutputBytes > policy.MaximumOutputBytes)
            throw new ApplicationContractException(
                "TerminalBoundsDenied", "Terminal duration or byte bounds exceed policy.");
        if (request.Task is { } task)
        {
            var attempt = await store.GetTaskAttemptAsync(task.TaskAttemptId, cancellationToken)
                ?? throw new ApplicationContractException(
                    "TerminalTaskBindingInvalid", "Bound TaskAttempt does not exist.");
            if (attempt.Payload.HostId != request.HostId ||
                attempt.Payload.NodeIncarnationId != request.NodeIncarnationId ||
                attempt.Payload.Generation != task.Generation)
                throw new ApplicationContractException(
                    "TerminalTaskBindingInvalid", "Bound TaskAttempt identity does not match the Host.");
        }
        var elevationGranted = request.ElevationRequested &&
            policy.ElevatedActors.Contains(actor.Actor) &&
            policy.ElevatedHosts.Contains(request.HostId) &&
            node.Capabilities.Contains("terminal.elevated-service", StringComparer.Ordinal);
        if (request.ElevationRequested && !elevationGranted)
            throw new ApplicationContractException(
                "TerminalElevationDenied", "Elevated terminal policy or Node capability denied the request.");
        var authority = new TerminalAuthority(
            TerminalContractLimits.SchemaVersion, TerminalSessionId.New(),
            request.HostId, request.NodeIncarnationId, actor.Actor,
            workspace, request.Task,
            now, now, now + request.Duration, request.Duration,
            request.MaximumInputBytes, request.MaximumOutputBytes,
            request.TranscriptMode,
            request.TranscriptMode == TerminalTranscriptMode.Full ? request.MaximumOutputBytes : 0,
            TerminalFileTransferCapabilities.None,
            request.ElevationRequested, elevationGranted, 0,
            TimeSpan.FromMinutes(30), 16 * 1024 * 1024);
        TerminalContractLimits.ValidateAuthorityShape(authority);
        await SaveAsync(authority, false, cancellationToken);
        return authority;
    }

    public Task<TerminalWireResponse> OpenAsync(
        TerminalOpenRequest request, CancellationToken cancellationToken = default) =>
        SendAsync(request.Authority, "open",
            new TerminalOpenCommand(request, Context(request.Authority)), cancellationToken);

    public async Task<TerminalWireResponse> GetAsync(
        TerminalSessionId id, CancellationToken cancellationToken = default)
    {
        var authority = await GetAuthorityAsync(id, cancellationToken);
        return await SendAsync(authority, "get",
            new TerminalGetCommand(id, Context(authority)), cancellationToken);
    }

    public async Task<TerminalWireResponse> InputAsync(
        TerminalSessionId id, TerminalInputRequest request, CancellationToken cancellationToken = default)
    {
        var authority = await GetAuthorityAsync(id, cancellationToken);
        return await SendAsync(authority, "input",
            request with { Context = Context(authority) }, cancellationToken);
    }

    public async Task<TerminalWireResponse> ResizeAsync(
        TerminalSessionId id, TerminalResizeRequest request, CancellationToken cancellationToken = default)
    {
        var authority = await GetAuthorityAsync(id, cancellationToken);
        return await SendAsync(authority, "resize",
            request with { Context = Context(authority) }, cancellationToken);
    }

    public async Task<TerminalWireResponse> OutputAsync(
        TerminalSessionId id, TerminalOutputReadRequest request, CancellationToken cancellationToken = default)
    {
        var authority = await GetAuthorityAsync(id, cancellationToken);
        return await SendAsync(authority, "output",
            request with { Context = Context(authority), Follow = false }, cancellationToken);
    }

    public async Task<TerminalWireResponse> CloseAsync(
        TerminalSessionId id, TerminalCloseRequest request, CancellationToken cancellationToken = default)
    {
        var authority = await GetAuthorityAsync(id, cancellationToken);
        return await SendAsync(authority, "close",
            request with { Context = Context(authority) }, cancellationToken);
    }

    public async Task RevokeAsync(
        TerminalSessionId id, CancellationToken cancellationToken = default)
    {
        var authority = await GetAuthorityAsync(id, cancellationToken);
        var nextRevision = authority.RevocationRevision + 1;
        await SaveAsync(authority with { RevocationRevision = nextRevision },
            true, cancellationToken);
        await revocations.EnqueueAsync(
            authority.HostId, authority.NodeIncarnationId, id, nextRevision, cancellationToken);
        try
        {
            var current = await router.SendAsync(
                authority.HostId, "get",
                new TerminalGetCommand(id, Context(authority)), cancellationToken);
            if (current.Snapshot is { } snapshot)
            {
                var value = TerminalWireCodec.FromElement<TerminalSessionSnapshot>(snapshot)!;
                if (value.State is TerminalSessionState.Open or TerminalSessionState.Opening)
                    await router.SendAsync(
                        authority.HostId, "close",
                        new TerminalCloseRequest(
                            id, Context(authority), $"revoke-{nextRevision}",
                            value.Revision, TimeSpan.Zero), cancellationToken);
            }
        }
        catch (InvalidOperationException) { }
    }

    private async Task<TerminalWireResponse> SendAsync(
        TerminalAuthority authority, string operation, object payload, CancellationToken token)
    {
        if (await IsRevokedAsync(authority.SessionId, token))
            throw new ApplicationContractException(
                "TerminalAuthorityRevoked", "Terminal authority is revoked.");
        var response = await router.SendAsync(authority.HostId, operation, payload, token);
        if (response.Problem is not null)
            throw new ApplicationContractException(
                response.Problem.Code.ToString(), response.Problem.Detail,
                response.Problem.Disposition == TerminalProblemDisposition.RetrySafe
                    ? ProblemDisposition.RetrySafe : ProblemDisposition.RequiresReconciliation);
        return response;
    }

    private async Task SaveAsync(TerminalAuthority value, bool revoked, CancellationToken token)
    {
        await using var connection = await store.OpenConnectionAsync(token);
        await using var command = connection.CreateCommand();
        command.CommandText = """
          CREATE TABLE IF NOT EXISTS terminal_authorities(
            session_id TEXT PRIMARY KEY,host_id TEXT NOT NULL,node_incarnation_id TEXT NOT NULL,
            authority_json TEXT NOT NULL,revoked INTEGER NOT NULL,updated_at TEXT NOT NULL);
          INSERT INTO terminal_authorities(session_id,host_id,node_incarnation_id,authority_json,revoked,updated_at)
          VALUES($id,$host,$node,$json,$revoked,$now)
          ON CONFLICT(session_id) DO UPDATE SET authority_json=excluded.authority_json,
            revoked=excluded.revoked,updated_at=excluded.updated_at;
          """;
        command.Parameters.AddWithValue("$id", value.SessionId.ToString());
        command.Parameters.AddWithValue("$host", value.HostId.ToString());
        command.Parameters.AddWithValue("$node", value.NodeIncarnationId.ToString());
        command.Parameters.AddWithValue("$json", TerminalWireCodec.Element(value).GetRawText());
        command.Parameters.AddWithValue("$revoked", revoked);
        command.Parameters.AddWithValue("$now", clock.GetUtcNow().ToString("O"));
        await command.ExecuteNonQueryAsync(token);
    }

    private async Task<TerminalAuthority> GetAuthorityAsync(TerminalSessionId id, CancellationToken token)
    {
        await using var connection = await store.OpenConnectionAsync(token);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT authority_json FROM terminal_authorities WHERE session_id=$id";
        command.Parameters.AddWithValue("$id", id.ToString());
        var json = (string?)await command.ExecuteScalarAsync(token)
            ?? throw new KeyNotFoundException("Terminal authority does not exist.");
        using var document = JsonDocument.Parse(json);
        return TerminalWireCodec.FromElement<TerminalAuthority>(document.RootElement)!;
    }

    private async Task<bool> IsRevokedAsync(TerminalSessionId id, CancellationToken token)
    {
        await using var connection = await store.OpenConnectionAsync(token);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT revoked FROM terminal_authorities WHERE session_id=$id";
        command.Parameters.AddWithValue("$id", id.ToString());
        return Convert.ToInt32(await command.ExecuteScalarAsync(token)) != 0;
    }

    private static TerminalOperationContext Context(TerminalAuthority authority) =>
        new(authority.HostId, authority.NodeIncarnationId, authority.Actor, authority.RevocationRevision);

    private static bool IsContained(string root, string path)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(root), path);
        return relative != ".." && !Path.IsPathRooted(relative) &&
            !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
    }
}
