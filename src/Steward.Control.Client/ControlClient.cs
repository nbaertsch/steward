using System.Net.Http.Json;
using System.Text.Json;
using Steward.Application;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Terminal.Abstractions;

namespace Steward.Cli;

internal sealed record CreateWorkloadCommand(
    string WorkloadType,
    string PlannerKind,
    string PlannerVersion,
    JsonElement PlannerData,
    string? IdempotencyKey = null);

public sealed record ArtifactDownloadResult(
    PortableObjectId ArtifactId,
    string LocalPath,
    string? MediaType,
    long BytesWritten);

public sealed record ArtifactDownloadReference(
    PortableObjectId ArtifactId,
    bool Available,
    string OpaqueReference,
    string? MediaType,
    long? ContentLength);

public sealed class ControlApiException(
    int statusCode,
    string responseBody,
    string? code = null,
    string? detail = null)
    : InvalidOperationException(
        $"Steward.Control returned HTTP {statusCode}: {code ?? "HttpError"}" +
        (detail is null ? string.Empty : $" - {detail}"))
{
    public int StatusCode { get; } = statusCode;
    public string ResponseBody { get; } = responseBody;
    public string Code { get; } = code ?? "HttpError";
    public string? Detail { get; } = detail;
}

public interface IControlMutationTokenProvider
{
    ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken = default);
}

public sealed class EnvironmentOrFileMutationTokenProvider : IControlMutationTokenProvider
{
    public const string TokenEnvironmentVariable = "STEWARD_CONTROL_MUTATION_TOKEN";
    public const string TokenFileEnvironmentVariable = "STEWARD_CONTROL_MUTATION_TOKEN_FILE";
    public const int MaximumTokenLength = 4_096;

    public async ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        var direct = Environment.GetEnvironmentVariable(TokenEnvironmentVariable);
        var file = Environment.GetEnvironmentVariable(TokenFileEnvironmentVariable);
        if (!string.IsNullOrEmpty(direct) && !string.IsNullOrEmpty(file))
            throw new InvalidOperationException("Configure only one Steward mutation-token reference.");
        if (!string.IsNullOrEmpty(file))
        {
            if (!Path.IsPathFullyQualified(file))
                throw new InvalidOperationException("The Steward mutation-token file reference must be absolute.");
            try
            {
                var info = new FileInfo(file);
                if (!info.Exists || info.Length > MaximumTokenLength + 2)
                    throw new InvalidOperationException("The Steward mutation-token file is unavailable or oversized.");
                direct = await File.ReadAllTextAsync(file, cancellationToken);
            }
            catch (IOException)
            {
                throw new InvalidOperationException("The Steward mutation-token file is unavailable.");
            }
            catch (UnauthorizedAccessException)
            {
                throw new InvalidOperationException("The Steward mutation-token file is unavailable.");
            }
        }
        if (direct is null)
            return null;
        var value = direct.Trim();
        if (value.Length is 0 or > MaximumTokenLength ||
            value.Any(char.IsControl))
            throw new InvalidOperationException("The Steward mutation-token reference is invalid.");
        return value;
    }
}

public sealed class ControlClient(
    HttpClient httpClient,
    IControlMutationTokenProvider? mutationTokens = null)
{
    public const string MutationTokenHeader = "X-Steward-Mutation-Token";
    private readonly IControlMutationTokenProvider tokens =
        mutationTokens ?? new EnvironmentOrFileMutationTokenProvider();

    public async ValueTask<bool> HasMutationTokenAsync(
        CancellationToken cancellationToken = default) =>
        await tokens.GetTokenAsync(cancellationToken) is not null;

    internal Task<JsonElement> DoctorAsync(CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.Doctor, cancellationToken);

    internal Task<JsonElement> OrchestrationDoctorAsync(CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.OrchestrationDoctor, cancellationToken);

    internal Task<JsonElement> ExportBackupAsync(
        ExportBackupRequest request, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, "backups/export", request, cancellationToken);

    internal Task<JsonElement> ValidateBackupAsync(
        ValidateBackupRequest request, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, "backups/validate", request, cancellationToken);

    internal Task<JsonElement> RestoreBackupAsync(
        RestoreBackupRequest request, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, "backups/restore", request, cancellationToken);

    internal Task<JsonElement> CreateWorkloadAsync(
        CreateWorkloadCommand command,
        CancellationToken cancellationToken = default) =>
        SendAsync(HttpMethod.Post, "workload-drafts", command, cancellationToken,
            command.IdempotencyKey);

    internal Task<JsonElement> SubmitWorkloadAsync(
        SubmitWorkloadRequest request,
        CancellationToken cancellationToken = default) =>
        SendAsync(HttpMethod.Post, "workloads", request, cancellationToken, request.IdempotencyKey);

    internal Task<JsonElement> GetWorkloadAsync(
        WorkloadId workloadId,
        CancellationToken cancellationToken = default) =>
        GetAsync($"workloads/{workloadId}", cancellationToken);

    internal Task<JsonElement> CancelWorkloadAsync(
        WorkloadId workloadId,
        CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, $"workloads/{workloadId}/cancel", null, cancellationToken);

    internal Task<JsonElement> GetTaskAsync(TaskId id, CancellationToken cancellationToken = default) =>
        GetAsync($"tasks/{id}", cancellationToken);

    internal Task<JsonElement> ReadTaskEventsAsync(
        TaskId id, long after, int limit, CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.TaskEvents(id, after, limit), cancellationToken);

    internal Task<JsonElement> RetryTaskAsync(
        WorkloadId workload, TaskId task, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, $"workloads/{workload}/tasks/{task}/retry", null, cancellationToken);

    internal Task<JsonElement> ResolveTaskRecoveryAbsentAsync(
        WorkloadId workload, TaskId task, int generation,
        CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post,
            $"workloads/{workload}/tasks/{task}/recovery/absent/{generation}", null, cancellationToken);

    internal Task<JsonElement> GetAttemptAsync(
        TaskAttemptId id, CancellationToken cancellationToken = default) =>
        GetAsync($"attempts/{id}", cancellationToken);

    internal Task<JsonElement> GetArtifactAsync(
        PortableObjectId id, CancellationToken cancellationToken = default) =>
        GetAsync($"artifacts/{id}", cancellationToken);

    public async Task<ArtifactDownloadResult> DownloadArtifactAsync(
        PortableObjectId id,
        string destinationPath,
        long maximumBytes = 256L * 1024 * 1024,
        CancellationToken cancellationToken = default)
    {
        if (!Path.IsPathFullyQualified(destinationPath) || maximumBytes <= 0)
            throw new ArgumentException("Artifact destination and byte bound are invalid.");
        if (File.Exists(destinationPath))
            throw new IOException("Artifact destination already exists.");
        using var response = await httpClient.GetAsync(
            $"artifacts/{id}/download", HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
        if (response.Content.Headers.ContentLength is long length && length > maximumBytes)
            throw new IOException("Artifact download exceeds the configured local byte bound.");
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var destination = new FileStream(
            destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81_920, true);
        var buffer = new byte[81_920];
        long written = 0;
        try
        {
            int read;
            while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
            {
                written += read;
                if (written > maximumBytes)
                    throw new IOException("Artifact download exceeds the configured local byte bound.");
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
        }
        catch
        {
            await destination.DisposeAsync();
            File.Delete(destinationPath);
            throw;
        }
        return new(id, destinationPath, response.Content.Headers.ContentType?.MediaType, written);
    }

    public async Task<ArtifactDownloadReference> GetArtifactDownloadReferenceAsync(
        PortableObjectId id,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync(
            $"artifacts/{id}/download", HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
        return new(
            id,
            true,
            $"steward-artifact:{id}",
            response.Content.Headers.ContentType?.MediaType,
            response.Content.Headers.ContentLength);
    }

    internal Task<JsonElement> ListPoolsAsync(CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.Pools, cancellationToken);

    internal async Task<JsonElement> GetPoolAsync(
        PoolId id, CancellationToken cancellationToken = default)
    {
        var pools = await ListPoolsAsync(cancellationToken);
        foreach (var pool in pools.EnumerateArray())
        {
            if (pool.TryGetProperty("policy", out var policy) &&
                policy.TryGetProperty("poolId", out var poolId) &&
                string.Equals(IdText(poolId), id.ToString(), StringComparison.OrdinalIgnoreCase))
                return pool.Clone();
        }
        throw new ControlApiException(404, "", "NotFound", "The Pool was not found.");
    }

    internal Task<JsonElement> RegisterPoolAsync(
        PoolRegistration registration, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, ControlRoutes.Pools, registration, cancellationToken);

    internal Task<JsonElement> ReconcilePoolAsync(
        PoolId id, ReconcilePoolRequest request, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, ControlRoutes.PoolReconcile(id), request, cancellationToken);

    internal Task<JsonElement> ListHostsAsync(CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.Hosts, cancellationToken);

    internal Task<JsonElement> GetHostAsync(HostId id, CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.Host(id), cancellationToken);

    internal Task<JsonElement> InspectHostAsync(HostId id, CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.HostProvider(id), cancellationToken);

    internal Task<JsonElement> StartHostAsync(
        HostId id,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null) =>
        MutateAsync(
            HttpMethod.Post,
            ControlRoutes.HostAction(id, "start", expectedIncarnation: expectedIncarnation),
            null,
            cancellationToken);

    internal Task<JsonElement> DrainHostAsync(
        HostId id,
        bool force,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null) =>
        MutateAsync(HttpMethod.Post, ControlRoutes.HostAction(
                id, "drain", force, expectedIncarnation),
            null, cancellationToken);

    internal Task<JsonElement> StopHostAsync(
        HostId id,
        bool force,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null) =>
        MutateAsync(HttpMethod.Post, ControlRoutes.HostAction(
                id, "stop", force, expectedIncarnation),
            null, cancellationToken);

    internal Task<JsonElement> RecreateHostAsync(
        HostId id,
        bool force,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null) =>
        MutateAsync(HttpMethod.Post, ControlRoutes.HostAction(
                id, "recreate", force, expectedIncarnation),
            null, cancellationToken);

    internal Task<JsonElement> DeleteHostAsync(
        HostId id,
        bool force,
        CancellationToken cancellationToken = default,
        NodeIncarnationId? expectedIncarnation = null) =>
        MutateAsync(HttpMethod.Delete, ControlRoutes.HostDelete(
                id, force, expectedIncarnation),
            null, cancellationToken);

    internal Task<JsonElement> ListNodesAsync(CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.Nodes, cancellationToken);

    internal Task<JsonElement> RegisterNodeAsync(
        RegisterNodeRequest request, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, "nodes", request, cancellationToken);

    internal Task<JsonElement> CreateAgentAsync(
        CreateAgentRequest request, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, "agents", request, cancellationToken);

    internal Task<JsonElement> GetAgentAsync(
        StewardAgentId id, CancellationToken cancellationToken = default) =>
        GetAsync($"agents/{id}", cancellationToken);

    internal Task<JsonElement> SubmitAgentTurnAsync(
        StewardAgentId id, SubmitAgentTurnRequest request,
        CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, $"agents/{id}/turns", request, cancellationToken);

    internal Task<JsonElement> CancelAgentTurnAsync(
        StewardAgentId agent, AgentTurnId turn,
        CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, $"agents/{agent}/turns/{turn}/cancel", null, cancellationToken);

    internal Task<JsonElement> RunNextAgentTurnAsync(
        StewardAgentId id, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, $"agents/{id}/run-next", null, cancellationToken);

    internal Task<JsonElement> ReadAgentNotificationsAsync(
        StewardAgentId id, long after, int limit,
        CancellationToken cancellationToken = default) =>
        GetAsync($"agents/{id}/notifications?after={after}&limit={limit}", cancellationToken);

    internal Task<JsonElement> AcknowledgeAgentNotificationsAsync(
        StewardAgentId id, long cursor, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, $"agents/{id}/notifications/ack/{cursor}", null, cancellationToken);

    internal Task<JsonElement> MigrateAgentAsync(
        StewardAgentId id, AgentMigrationRequest request,
        CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post, $"agents/{id}/migrate", request, cancellationToken);

    internal Task<JsonElement> ReadNotificationsAsync(
        string stream, long after, int limit, CancellationToken cancellationToken = default) =>
        GetAsync($"notifications/{Uri.EscapeDataString(stream)}?after={after}&limit={limit}",
            cancellationToken);

    internal Task<JsonElement> AcknowledgeNotificationsAsync(
        string stream, long cursor, CancellationToken cancellationToken = default) =>
        MutateAsync(HttpMethod.Post,
            $"notifications/{Uri.EscapeDataString(stream)}/ack/{cursor}", null, cancellationToken);

    internal Task<JsonElement> IssueTerminalAuthorityAsync(
        IssueTerminalAuthorityRequest request, CancellationToken token = default) =>
        MutateAsync(HttpMethod.Post, "terminals/authorities", request, token);
    internal Task<JsonElement> OpenTerminalAsync(
        TerminalOpenRequest request, CancellationToken token = default) =>
        MutateAsync(HttpMethod.Post, "terminals/open", request, token);
    internal Task<JsonElement> GetTerminalAsync(
        TerminalSessionId id, CancellationToken token = default) =>
        GetAsync($"terminals/{id}", token);
    internal Task<JsonElement> SendTerminalInputAsync(
        TerminalSessionId id, TerminalInputRequest request, CancellationToken token = default) =>
        MutateAsync(HttpMethod.Post, $"terminals/{id}/input", request, token);
    internal Task<JsonElement> ResizeTerminalAsync(
        TerminalSessionId id, TerminalResizeRequest request, CancellationToken token = default) =>
        MutateAsync(HttpMethod.Post, $"terminals/{id}/resize", request, token);
    internal Task<JsonElement> ReadTerminalOutputAsync(
        TerminalSessionId id, TerminalOutputReadRequest request, CancellationToken token = default) =>
        MutateAsync(HttpMethod.Post, $"terminals/{id}/output", request, token);
    internal Task<JsonElement> CloseTerminalAsync(
        TerminalSessionId id, TerminalCloseRequest request, CancellationToken token = default) =>
        MutateAsync(HttpMethod.Post, $"terminals/{id}/close", request, token);
    internal Task<JsonElement> RevokeTerminalAsync(
        TerminalSessionId id, CancellationToken token = default) =>
        MutateAsync(HttpMethod.Post, $"terminals/{id}/revoke", null, token);

    internal Task<JsonElement> GetOperationsAsync(
        CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.Operations, cancellationToken);

    internal Task<JsonElement> GetTerminalPolicyAsync(
        CancellationToken cancellationToken = default) =>
        GetAsync(ControlRoutes.TerminalPolicy, cancellationToken);

    private async Task<JsonElement> GetAsync(string path, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(path, cancellationToken);
        return await ReadJsonAsync(response, cancellationToken);
    }

    private Task<JsonElement> MutateAsync(
        HttpMethod method, string path, object? body, CancellationToken cancellationToken) =>
        SendAsync(method, path, body, cancellationToken);

    private async Task<JsonElement> SendAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken,
        string? idempotencyKey = null)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = JsonContent.Create(body, options: StewardJson.Options);
        if (idempotencyKey is not null)
            request.Headers.Add("Idempotency-Key", idempotencyKey);
        var mutationToken = await tokens.GetTokenAsync(cancellationToken);
        if (mutationToken is not null)
            request.Headers.Add(MutationTokenHeader, mutationToken);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        return await ReadJsonAsync(response, cancellationToken);
    }

    private static async Task<JsonElement> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            string? code = null;
            string? detail = null;
            try
            {
                using var problem = JsonDocument.Parse(body);
                code = problem.RootElement.TryGetProperty("code", out var value) ? value.GetString() : null;
                detail = problem.RootElement.TryGetProperty("detail", out value) ? value.GetString() : null;
            }
            catch (JsonException)
            {
            }
            throw new ControlApiException((int)response.StatusCode, body, code, detail);
        }
        if (response.Content.Headers.ContentLength == 0 ||
            response.StatusCode is System.Net.HttpStatusCode.Accepted or System.Net.HttpStatusCode.NoContent)
            return JsonSerializer.SerializeToElement(new { accepted = true }, StewardJson.Options);
        return await response.Content.ReadFromJsonAsync<JsonElement>(
            StewardJson.Options, cancellationToken);
    }

    private static async Task EnsureSuccessAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode) return;
        _ = await ReadJsonAsync(response, cancellationToken);
    }

    private static string? IdText(JsonElement value) =>
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : value.ValueKind == JsonValueKind.Object &&
              value.TryGetProperty("value", out var nested)
                ? nested.GetString()
                : null;
}
