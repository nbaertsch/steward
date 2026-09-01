using System.Text.Json;
using Microsoft.AspNetCore.HostFiltering;
using Steward.Application;
using Steward.Contracts;
using Steward.DevBox.Windows;
using Steward.Domain;
using Steward.Maintenance.Windows;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;
using Steward.Stack.Local;
using Steward.Terminal.Abstractions;

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(
        new TerminalSessionIdJsonConverter());
    options.SerializerOptions.Converters.Add(
        new StewardIdJsonConverterFactory());
});
if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException(
        "The Steward Local Stack Control host requires Windows.");

var configuredUrls = builder.Configuration["urls"]
    ?? Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
if (string.IsNullOrWhiteSpace(configuredUrls))
{
    configuredUrls = "http://127.0.0.1:5112";
    builder.WebHost.UseUrls(configuredUrls);
}

LoopbackBindingValidator.Validate(configuredUrls, "Steward Control");

var databasePath = builder.Configuration["Control:DatabasePath"];
if (string.IsNullOrWhiteSpace(databasePath))
    databasePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Steward", "control.db");
var tokenPath = builder.Configuration["Control:LocalSessionTokenPath"]
    ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(databasePath))!, "control.session");

builder.Services.AddSingleton(new SqliteControlStore(databasePath));
builder.Services.AddSingleton(new Steward.Control.LocalMutationSecurity(tokenPath));
builder.Services.AddSingleton<WorkloadApplicationService>();
builder.Services.AddSingleton<OutboxApplicationService>();
builder.Services.AddSingleton<NotificationApplicationService>();
builder.Services.AddSingleton<DoctorApplicationService>();
builder.Services.AddSingleton<BackupApplicationService>();
var devBoxIdentity = new DevBoxIdentityService(new DevBoxIdentityStore());
builder.Services.AddStewardLocalStack(
    builder.Configuration,
    new DevBoxSilentTokenCredential(devBoxIdentity));
Steward.Control.OrchestrationComposition.AddStewardOrchestration(
    builder.Services, builder.Configuration, databasePath);
builder.Services.AddStewardLocalControlTransport();
builder.Services.AddHostFiltering(options =>
    options.AllowedHosts = ["localhost", "127.0.0.1", "[::1]"]);

var app = builder.Build();
await app.Services.GetRequiredService<SqliteControlStore>().InitializeAsync(app.Lifetime.ApplicationStopping);
app.UseHostFiltering();
app.Use(async (context, next) =>
{
    if (context.Request.Method is not ("GET" or "HEAD" or "OPTIONS") &&
        !context.RequestServices.GetRequiredService<Steward.Control.LocalMutationSecurity>()
            .Authorize(context.Request))
    {
        context.Response.StatusCode = 403;
        await context.Response.WriteAsJsonAsync(new ProblemDto(
            "LocalSessionRequired", "LocalSessionRequired",
            "A valid local Steward session token and absent browser Origin are required.",
            ProblemDisposition.RequiresNewUserIntent, false));
        return;
    }
    try { await next(context); }
    catch (Steward.Application.ApplicationContractException exception)
    {
        context.Response.StatusCode = exception.Disposition == ProblemDisposition.RetrySafe ? 503 : 400;
        await context.Response.WriteAsJsonAsync(new ProblemDto(
            exception.Code, exception.Code, exception.Message, exception.Disposition, false));
    }
    catch (KeyNotFoundException)
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsJsonAsync(new ProblemDto(
            "NotFound", "NotFound", "The requested Steward resource was not found.",
            ProblemDisposition.Terminal, false));
    }
    catch (Exception exception)
    {
        app.Logger.LogError(exception, "Unhandled Control request failure.");
        context.Response.StatusCode = 500;
        await context.Response.WriteAsJsonAsync(new ProblemDto(
            "InternalError", "InternalError", "The operation failed; inspect local structured diagnostics.",
            ProblemDisposition.RequiresReconciliation, true));
    }
});

app.MapGet("/health", async (DoctorApplicationService doctor, CancellationToken token) =>
{
    var result = await doctor.CheckAsync(token);
    return result.Healthy ? Results.Ok(result) : Results.Json(result, statusCode: 503);
});
app.MapGet("/doctor", async (DoctorApplicationService doctor, CancellationToken token) =>
    Results.Ok(await doctor.CheckAsync(token)));
app.MapGet("/doctor/orchestration", (
    Steward.Control.OrchestrationDoctorService doctor) =>
    Results.Ok(doctor.Check()));
app.MapGet("/operations", async (
    int? limit,
    OperationsApplicationService operations,
    CancellationToken token) =>
    Results.Ok(await operations.GetAsync(
        Math.Clamp(limit ?? 1000, 1, 5000),
        token)));
app.MapPost("/backups/export", async (
    ExportBackupRequest request,
    BackupApplicationService service,
    CancellationToken token) =>
    Results.Ok(await service.ExportAsync(request, token)));
app.MapPost("/backups/validate", async (
    ValidateBackupRequest request,
    BackupApplicationService service,
    CancellationToken token) =>
    Results.Ok(await service.ValidateAsync(request, token)));
app.MapPost("/backups/restore", async (
    RestoreBackupRequest request,
    BackupApplicationService service,
    CancellationToken token) =>
{
    await service.RestoreAsync(request, token);
    return Results.NoContent();
});

app.MapPost("/maintenance/operations", async (
    LocalMaintenanceSubmission request,
    ControlMaintenanceDispatcher dispatcher,
    CancellationToken token) =>
{
    var accepted = await dispatcher.DispatchAsync(request, token);
    return Results.Accepted(
        $"/maintenance/operations/{accepted.Request.Body.OperationId:D}",
        new
        {
            accepted.Request.Body.RequestId,
            accepted.Request.Body.OperationId,
            accepted.HostId,
            accepted.NodeIncarnationId,
            status = MaintenanceOperationStatus.Accepted
        });
});

app.MapGet("/maintenance/operations/{operationId:guid}", async (
    Guid operationId,
    ControlOrchestrator orchestrator,
    CancellationToken token) =>
{
    var result = await orchestrator.GetMaintenanceResultAsync(
        operationId,
        token);
    return result is null
        ? Results.Accepted(
            $"/maintenance/operations/{operationId:D}",
            new { operationId, status = MaintenanceOperationStatus.Accepted })
        : Results.Ok(result);
});

app.MapPost("/workload-drafts", async (
    CreateWorkloadRequest request,
    HttpRequest httpRequest,
    WorkloadApplicationService service,
    CancellationToken token) =>
{
    try
    {
        var headerKey = httpRequest.Headers["Idempotency-Key"].FirstOrDefault();
        if (headerKey is not null &&
            request.IdempotencyKey is not null &&
            !string.Equals(headerKey, request.IdempotencyKey, StringComparison.Ordinal))
            throw new ApplicationContractException(
                "InvalidArgument",
                "Header and body idempotency keys must match.");
        var created = await service.CreateAsync(
            request with { IdempotencyKey = headerKey ?? request.IdempotencyKey },
            token);
        return Results.Created($"/workloads/{created.Payload.WorkloadId}", created);
    }
    catch (ApplicationContractException exception)
    {
        return Problem(
            exception.Code,
            exception.Message,
            exception.Code == "IdempotencyConflict" ? StatusCodes.Status409Conflict : StatusCodes.Status400BadRequest,
            exception.Disposition);
    }
    catch (PersistenceException exception)
    {
        return Problem(
            exception.Code.ToString(),
            exception.Message,
            StatusCodes.Status409Conflict,
            ProblemDisposition.RequiresNewUserIntent);
    }
});
app.MapPost("/workloads", async (
    JsonElement request,
    HttpRequest httpRequest,
    Steward.Application.ExecutableWorkloadApplicationService executable,
    WorkloadApplicationService drafts,
    CancellationToken token) =>
{
    try
    {
        if (!request.TryGetProperty("kind", out _))
        {
            var draftRequest = request.Deserialize<CreateWorkloadRequest>(StewardJson.Options)
                ?? throw new Steward.Application.ApplicationContractException(
                    "InvalidArgument", "Workload draft request is invalid.");
            var headerKey = httpRequest.Headers["Idempotency-Key"].FirstOrDefault();
            var createdDraft = await drafts.CreateAsync(draftRequest with
            {
                IdempotencyKey = headerKey ?? draftRequest.IdempotencyKey
            }, token);
            httpRequest.HttpContext.Response.Headers["X-Steward-Workload-Mode"] = "draft-only";
            return Results.Created($"/workload-drafts/{createdDraft.Payload.WorkloadId}", createdDraft);
        }
        var submission = request.Deserialize<Steward.Application.SubmitWorkloadRequest>(StewardJson.Options)
            ?? throw new Steward.Application.ApplicationContractException(
                "InvalidArgument", "Executable workload request is invalid.");
        var submissionHeader = httpRequest.Headers["Idempotency-Key"].FirstOrDefault();
        if (submissionHeader is not null &&
            !string.Equals(submissionHeader, submission.IdempotencyKey, StringComparison.Ordinal))
            throw new Steward.Application.ApplicationContractException(
                "InvalidArgument", "Header and body idempotency keys must match.");
        var created = await executable.SubmitAsync(submission, token);
        return Results.Created($"/workloads/{created.Payload.WorkloadId}", created);
    }
    catch (Steward.Application.ApplicationContractException exception)
    {
        return Problem(exception.Code, exception.Message,
            exception.Disposition == ProblemDisposition.RetrySafe ? 503 : 400,
            exception.Disposition);
    }
    catch (Steward.Persistence.Sqlite.PersistenceException exception)
    {
        return Problem(exception.Code.ToString(),
            "The idempotency key or immutable Workload plan conflicts with durable state.",
            409, ProblemDisposition.RequiresNewUserIntent);
    }
    catch (Steward.Scheduling.SchedulerRevisionConflictException)
    {
        return Problem(ProblemCodes.RevisionConflict,
            "The idempotency key or immutable Workload plan conflicts with durable state.",
            409, ProblemDisposition.RequiresNewUserIntent);
    }
});
app.MapGet("/workloads/{id}", async (
    string id, WorkloadApplicationService service, CancellationToken token) =>
{
    if (!WorkloadId.TryParse(id, out var workloadId))
        return Problem("InvalidWorkloadId", "The workload ID is invalid.", 400);
    var result = await service.GetAsync(workloadId, token);
    return result is null
        ? Problem("NotFound", "The workload was not found.", 404)
        : Results.Ok(result);
});
app.MapGet("/tasks/{id}", async (
    string id, SqliteControlStore store, CancellationToken token) =>
{
    if (!TaskId.TryParse(id, out var taskId))
        return Problem("InvalidTaskId", "The Task ID is invalid.", 400);
    var value = await store.GetTaskAsync(taskId, token);
    return value is null ? Problem("NotFound", "The Task was not found.", 404) : Results.Ok(value);
});
app.MapGet("/attempts/{id}", async (
    string id, SqliteControlStore store, CancellationToken token) =>
{
    if (!TaskAttemptId.TryParse(id, out var attemptId))
        return Problem("InvalidAttemptId", "The TaskAttempt ID is invalid.", 400);
    var value = await store.GetTaskAttemptAsync(attemptId, token);
    return value is null ? Problem("NotFound", "The TaskAttempt was not found.", 404) : Results.Ok(value);
});
app.MapGet("/tasks/{id}/events", async (
    string id, long? after, int? limit,
    Steward.Orchestration.ControlOrchestrator orchestrator,
    CancellationToken token) =>
{
    if (!TaskId.TryParse(id, out var taskId))
        return Problem("InvalidTaskId", "The Task ID is invalid.", 400);
    return Results.Ok(await orchestrator.ReadTaskFactsAsync(
        taskId, after ?? 0, Math.Clamp(limit ?? 100, 1, 1000), token));
});
app.MapGet("/artifacts/{id}", async (
    string id, SqliteControlStore store, CancellationToken token) =>
{
    if (!PortableObjectId.TryParse(id, out var objectId))
        return Problem("InvalidPortableObjectId", "The PortableObject ID is invalid.", 400);
    var value = await store.GetPortableObjectAsync(objectId, token);
    return value is null ? Problem("NotFound", "The artifact was not found.", 404) : Results.Ok(value);
});
app.MapGet("/artifacts/{id}/download", async (
    string id, IServiceProvider services, CancellationToken token) =>
{
    if (!PortableObjectId.TryParse(id, out var objectId))
        return Problem("InvalidPortableObjectId", "The PortableObject ID is invalid.", 400);
    var downloads = services.GetService<Steward.Control.ControlPortableDownloadService>();
    if (downloads is null)
        return Problem(ProblemCodes.CapabilityUnavailable,
            "Control portable downloads are not configured.", 503, ProblemDisposition.Terminal);
    var value = await downloads.OpenAsync(objectId, token);
    return Results.Stream(value.Content, value.MediaType, enableRangeProcessing: false);
});
app.MapPost("/workloads/{workload}/cancel", async (
    string workload, Steward.Orchestration.ControlOrchestrator orchestrator, CancellationToken token) =>
{
    if (!WorkloadId.TryParse(workload, out var workloadId))
        return Problem("InvalidWorkloadId", "The Workload ID is invalid.", 400);
    await orchestrator.CancelAsync(workloadId, TimeSpan.FromSeconds(10), token);
    return Results.Accepted();
});
app.MapPost("/workloads/{workload}/tasks/{task}/retry", async (
    string workload, string task,
    Steward.Orchestration.ControlOrchestrator orchestrator,
    CancellationToken token) =>
{
    if (!WorkloadId.TryParse(workload, out var workloadId) ||
        !TaskId.TryParse(task, out var taskId))
        return Problem("InvalidArgument", "The Workload or Task ID is invalid.", 400);
    await orchestrator.RetryAsync(workloadId, taskId, DateTimeOffset.UtcNow, token);
    return Results.Accepted();
});
app.MapPost("/workloads/{workload}/tasks/{task}/recovery/absent/{generation:int}", async (
    string workload, string task, int generation,
    Steward.Orchestration.ControlOrchestrator orchestrator,
    CancellationToken token) =>
{
    if (!WorkloadId.TryParse(workload, out var workloadId) ||
        !TaskId.TryParse(task, out var taskId) || generation <= 0)
        return Problem("InvalidArgument", "The recovery identity is invalid.", 400);
    await orchestrator.ResolveRecoveryAbsentAsync(
        workloadId, taskId, generation, DateTimeOffset.UtcNow, token);
    return Results.Accepted();
});
app.MapPost("/pools", async (
    Steward.Application.PoolRegistration request,
    Steward.Application.HostPoolApplicationService service,
    CancellationToken token) =>
{
    await service.RegisterPoolAsync(request, token);
    return Results.Created($"/pools/{request.Policy.PoolId}", request);
});
app.MapGet("/pools", async (
    Steward.Application.HostPoolApplicationService service,
    CancellationToken token) => Results.Ok(await service.ListPoolsAsync(token)));
app.MapPost("/pools/{id}/reconcile", async (
    string id,
    Steward.Application.ReconcilePoolRequest request,
    Steward.Application.HostPoolApplicationService service,
    CancellationToken token) =>
{
    if (!PoolId.TryParse(id, out var poolId))
        return Problem("InvalidPoolId", "The Pool ID is invalid.", 400);
    return Results.Ok(await service.ReconcileAsync(
        poolId, request.Demands, request.ObservedAt ?? DateTimeOffset.UtcNow, token));
});
app.MapGet("/hosts", async (
    Steward.Application.HostPoolApplicationService service,
    CancellationToken token) => Results.Ok(await service.ListHostsAsync(cancellationToken: token)));
app.MapGet("/nodes", async (
    Steward.Orchestration.ControlNodeRegistrationStore registrations,
    CancellationToken token) => Results.Ok(await registrations.ListAsync(token)));
app.MapPost("/nodes", async (
    Steward.Orchestration.RegisterNodeRequest request,
    Steward.Orchestration.ControlNodeRegistrationStore registrations,
    CancellationToken token) =>
{
    var registration = request.ToRegistration();
    await registrations.RegisterAsync(registration, token);
    return Results.Created($"/nodes/{registration.NodeIncarnationId}", registration);
});
app.MapGet("/hosts/{id}", async (
    string id,
    Steward.Application.HostPoolApplicationService service,
    CancellationToken token) =>
{
    if (!HostId.TryParse(id, out var hostId))
        return Problem("InvalidHostId", "The Host ID is invalid.", 400);
    var host = (await service.ListHostsAsync(cancellationToken: token))
        .SingleOrDefault(x => x.HostId == hostId);
    return host is null ? Problem("NotFound", "The Host was not found.", 404) : Results.Ok(host);
});
app.MapGet("/hosts/{id}/provider", async (
    string id, Steward.Application.HostPoolApplicationService service, CancellationToken token) =>
{
    if (!HostId.TryParse(id, out var hostId))
        return Problem("InvalidHostId", "The Host ID is invalid.", 400);
    var value = await service.InspectAsync(hostId, token);
    return value is null ? Problem("NotFound", "The provider Host was not found.", 404) : Results.Ok(value);
});
app.MapPost("/provider-operations/reconcile", async (
    Steward.Application.ReconcileProviderOperationRequest request,
    Steward.Application.HostPoolApplicationService service,
    CancellationToken token) =>
    Results.Ok(await service.ReconcileOperationAsync(request, token)));
app.MapPost("/hosts/{id}/start", async (
    string id, string? expectedIncarnation,
    Steward.Application.HostPoolApplicationService service, CancellationToken token) =>
    HostId.TryParse(id, out var hostId)
        ? ParseExpectedIncarnation(expectedIncarnation, out var incarnation, out var problem)
            ? Results.Ok(await service.StartAsync(
                hostId, token, incarnation))
            : problem
        : Problem("InvalidHostId", "The Host ID is invalid.", 400));
app.MapPost("/hosts/{id}/drain", async (
    string id, bool? force, string? expectedIncarnation,
    Steward.Application.HostPoolApplicationService service, CancellationToken token) =>
    HostId.TryParse(id, out var hostId)
        ? ParseExpectedIncarnation(expectedIncarnation, out var incarnation, out var problem)
            ? Results.Ok(await service.DrainAsync(
                hostId, force ?? false, token, incarnation))
            : problem
        : Problem("InvalidHostId", "The Host ID is invalid.", 400));
app.MapPost("/hosts/{id}/stop", async (
    string id, bool? force, string? expectedIncarnation,
    Steward.Application.HostPoolApplicationService service, CancellationToken token) =>
    HostId.TryParse(id, out var hostId)
        ? ParseExpectedIncarnation(expectedIncarnation, out var incarnation, out var problem)
            ? Results.Ok(await service.StopAsync(
                hostId, force ?? false, token, incarnation))
            : problem
        : Problem("InvalidHostId", "The Host ID is invalid.", 400));
app.MapPost("/hosts/{id}/recreate", async (
    string id, bool? force, string? expectedIncarnation,
    Steward.Application.HostPoolApplicationService service, CancellationToken token) =>
    HostId.TryParse(id, out var hostId)
        ? ParseExpectedIncarnation(expectedIncarnation, out var incarnation, out var problem)
            ? Results.Ok(await service.RecreateAsync(
                hostId, force ?? false, token, incarnation))
            : problem
        : Problem("InvalidHostId", "The Host ID is invalid.", 400));
app.MapDelete("/hosts/{id}", async (
    string id, bool? force, string? expectedIncarnation,
    Steward.Application.HostPoolApplicationService service, CancellationToken token) =>
    HostId.TryParse(id, out var hostId)
        ? ParseExpectedIncarnation(expectedIncarnation, out var incarnation, out var problem)
            ? Results.Ok(await service.DeleteAsync(
                hostId, force ?? false, token, incarnation))
            : problem
        : Problem("InvalidHostId", "The Host ID is invalid.", 400));
app.MapPost("/agents", async (
    Steward.Application.CreateAgentRequest request,
    Steward.Application.AgentApplicationService service,
    CancellationToken token) =>
{
    var agent = await service.CreateAsync(request, token);
    return Results.Created($"/agents/{agent.AgentId}", agent);
});
app.MapGet("/agents/{id}", async (
    string id, Steward.Application.AgentApplicationService service, CancellationToken token) =>
{
    if (!StewardAgentId.TryParse(id, out var agentId))
        return Problem("InvalidAgentId", "The Agent ID is invalid.", 400);
    var agent = await service.GetAsync(agentId, token);
    return agent is null ? Problem("NotFound", "The Agent was not found.", 404) : Results.Ok(agent);
});
app.MapPost("/agents/{id}/turns", async (
    string id, Steward.Application.SubmitAgentTurnRequest request,
    Steward.Application.AgentApplicationService service, CancellationToken token) =>
{
    if (!StewardAgentId.TryParse(id, out var agentId))
        return Problem("InvalidAgentId", "The Agent ID is invalid.", 400);
    return Results.Accepted(value: await service.SubmitTurnAsync(agentId, request, token));
});
app.MapPost("/agents/{agent}/turns/{turn}/cancel", async (
    string agent, string turn, Steward.Application.AgentApplicationService service, CancellationToken token) =>
{
    if (!StewardAgentId.TryParse(agent, out var agentId) ||
        !AgentTurnId.TryParse(turn, out var turnId))
        return Problem("InvalidArgument", "The Agent or turn ID is invalid.", 400);
    return await service.CancelTurnAsync(agentId, turnId, token)
        ? Results.Accepted()
        : Problem("NotFound", "The Agent turn was not found.", 404);
});
app.MapPost("/agents/{id}/run-next", async (
    string id, Steward.Application.AgentApplicationService service, CancellationToken token) =>
{
    if (!StewardAgentId.TryParse(id, out var agentId))
        return Problem("InvalidAgentId", "The Agent ID is invalid.", 400);
    try { return Results.Ok(new { processed = await service.ProcessNextAsync(agentId, token) }); }
    catch (Steward.Application.ApplicationContractException exception)
    {
        return Problem(exception.Code, exception.Message, 503, exception.Disposition);
    }
});
app.MapGet("/agents/{id}/notifications", async (
    string id, long? after, int? limit,
    Steward.Application.AgentApplicationService service, CancellationToken token) =>
{
    if (!StewardAgentId.TryParse(id, out var agentId))
        return Problem("InvalidAgentId", "The Agent ID is invalid.", 400);
    return Results.Ok(await service.ReadNotificationsAsync(
        agentId, after ?? 0, Math.Clamp(limit ?? 50, 1, 100), token));
});
app.MapPost("/agents/{id}/notifications/ack/{cursor:long}", async (
    string id, long cursor,
    Steward.Application.AgentApplicationService service, CancellationToken token) =>
{
    if (!StewardAgentId.TryParse(id, out var agentId))
        return Problem("InvalidAgentId", "The Agent ID is invalid.", 400);
    await service.AcknowledgeNotificationsAsync(agentId, cursor, token);
    return Results.NoContent();
});
app.MapPost("/agents/{id}/migrate", async (
    string id, Steward.Application.AgentMigrationRequest request,
    Steward.Application.AgentApplicationService service, CancellationToken token) =>
{
    if (!StewardAgentId.TryParse(id, out var agentId))
        return Problem("InvalidAgentId", "The Agent ID is invalid.", 400);
    try
    {
        return Results.Ok(await service.MigrateAsync(agentId, request, token));
    }
    catch (Steward.Application.ApplicationContractException exception)
    {
        return Problem(exception.Code, exception.Message, 503, exception.Disposition);
    }
});
app.MapPost("/terminals/authorities", async (
    Steward.Application.IssueTerminalAuthorityRequest request,
    Steward.Application.TerminalApplicationService service,
    CancellationToken token) =>
    Results.Created("/terminals", await service.IssueAsync(request, token)));
app.MapGet("/terminals/policy", (
    TerminalPolicyStatusService service) =>
    Results.Ok(service.Get()));
app.MapPost("/terminals/open", async (
    Steward.Terminal.Abstractions.TerminalOpenRequest request,
    Steward.Application.TerminalApplicationService service,
    CancellationToken token) => Results.Ok(await service.OpenAsync(request, token)));
app.MapGet("/terminals/{id}", async (
    string id, Steward.Application.TerminalApplicationService service, CancellationToken token) =>
    Steward.Terminal.Abstractions.TerminalSessionId.TryParse(id, out var sessionId)
        ? Results.Ok(await service.GetAsync(sessionId, token))
        : Problem("InvalidTerminalSessionId", "Terminal session ID is invalid.", 400));
app.MapPost("/terminals/{id}/input", async (
    string id, Steward.Terminal.Abstractions.TerminalInputRequest request,
    Steward.Application.TerminalApplicationService service, CancellationToken token) =>
    Steward.Terminal.Abstractions.TerminalSessionId.TryParse(id, out var sessionId)
        ? Results.Ok(await service.InputAsync(sessionId, request, token))
        : Problem("InvalidTerminalSessionId", "Terminal session ID is invalid.", 400));
app.MapPost("/terminals/{id}/resize", async (
    string id, Steward.Terminal.Abstractions.TerminalResizeRequest request,
    Steward.Application.TerminalApplicationService service, CancellationToken token) =>
    Steward.Terminal.Abstractions.TerminalSessionId.TryParse(id, out var sessionId)
        ? Results.Ok(await service.ResizeAsync(sessionId, request, token))
        : Problem("InvalidTerminalSessionId", "Terminal session ID is invalid.", 400));
app.MapPost("/terminals/{id}/output", async (
    string id, Steward.Terminal.Abstractions.TerminalOutputReadRequest request,
    Steward.Application.TerminalApplicationService service, CancellationToken token) =>
    Steward.Terminal.Abstractions.TerminalSessionId.TryParse(id, out var sessionId)
        ? Results.Ok(await service.OutputAsync(sessionId, request, token))
        : Problem("InvalidTerminalSessionId", "Terminal session ID is invalid.", 400));
app.MapPost("/terminals/{id}/close", async (
    string id, Steward.Terminal.Abstractions.TerminalCloseRequest request,
    Steward.Application.TerminalApplicationService service, CancellationToken token) =>
    Steward.Terminal.Abstractions.TerminalSessionId.TryParse(id, out var sessionId)
        ? Results.Ok(await service.CloseAsync(sessionId, request, token))
        : Problem("InvalidTerminalSessionId", "Terminal session ID is invalid.", 400));
app.MapPost("/terminals/{id}/revoke", async (
    string id, Steward.Application.TerminalApplicationService service, CancellationToken token) =>
{
    if (!Steward.Terminal.Abstractions.TerminalSessionId.TryParse(id, out var sessionId))
        return Problem("InvalidTerminalSessionId", "Terminal session ID is invalid.", 400);
    await service.RevokeAsync(sessionId, token);
    return Results.NoContent();
});
app.MapGet("/outbox", async (
    int? limit, OutboxApplicationService service, CancellationToken token) =>
    Results.Ok(await service.ReadAsync(limit ?? 100, token)));
app.MapPost("/outbox/{sequence:long}/ack", async (
    long sequence, OutboxApplicationService service, CancellationToken token) =>
{
    await service.AcknowledgeAsync(sequence, token);
    return Results.NoContent();
});
app.MapGet("/notifications/{stream}", async (
    string stream, long? after, int? limit, NotificationApplicationService service, CancellationToken token) =>
{
    try
    {
        return Results.Ok(await service.ReadAsync(stream, after ?? 0, limit ?? 50, token));
    }
    catch (ApplicationContractException exception)
    {
        return Problem(exception.Code, exception.Message, 400, exception.Disposition);
    }
});
app.MapPost("/notifications/{stream}/ack/{cursor:long}", async (
    string stream, long cursor, NotificationApplicationService service, CancellationToken token) =>
{
    try
    {
        await service.AcknowledgeAsync(stream, cursor, token);
        return Results.NoContent();
    }
    catch (ApplicationContractException exception)
    {
        return Problem(exception.Code, exception.Message, 400, exception.Disposition);
    }
});

static IResult Problem(
    string code,
    string detail,
    int status,
    ProblemDisposition disposition = ProblemDisposition.RequiresNewUserIntent) =>
    Results.Json(
        new ProblemDto(code, code, detail, disposition, false),
        statusCode: status);

static bool ParseExpectedIncarnation(
    string? value,
    out NodeIncarnationId? incarnation,
    out IResult problem)
{
    if (value is null)
    {
        incarnation = null;
        problem = Results.Empty;
        return true;
    }
    if (NodeIncarnationId.TryParse(value, out var parsed))
    {
        incarnation = parsed;
        problem = Results.Empty;
        return true;
    }
    incarnation = null;
    problem = Problem(
        "InvalidNodeIncarnationId",
        "The expected Node incarnation ID is invalid.",
        400);
    return false;
}

await app.RunAsync();

public partial class Program;
