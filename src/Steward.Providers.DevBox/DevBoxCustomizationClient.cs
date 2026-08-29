using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;

namespace Steward.Providers.DevBox;

public enum DevBoxCustomizationExecutionAccount
{
    System,
    User
}

public sealed record DevBoxCustomizationTaskRequest(
    string Name,
    string DisplayName,
    IReadOnlyDictionary<string, string> Parameters,
    DevBoxCustomizationExecutionAccount RunAs,
    int TimeoutInSeconds)
{
    public DevBoxCustomizationTaskRequest Validate()
    {
        if (string.IsNullOrWhiteSpace(Name) ||
            Name.Length > 256 ||
            string.IsNullOrWhiteSpace(DisplayName) ||
            DisplayName.Length > 256 ||
            Parameters.Count > 32 ||
            Parameters.Any(item =>
                string.IsNullOrWhiteSpace(item.Key) ||
                item.Key.Length > 128 ||
                item.Value.Length > 64 * 1024) ||
            !Enum.IsDefined(RunAs) ||
            TimeoutInSeconds is <= 0 or > 7_200)
            throw new ArgumentException(
                "Dev Box customization task is invalid or exceeds its bound.");
        return this;
    }
}

public sealed record DevBoxCustomizationTaskResult(
    Guid Id,
    string Name,
    string? DisplayName,
    string Status,
    Uri LogUri);

public sealed record DevBoxCustomizationGroupResult(
    string Name,
    Uri Uri,
    string Status,
    DateTimeOffset? StartTime,
    DateTimeOffset? EndTime,
    IReadOnlyList<DevBoxCustomizationTaskResult> Tasks);

public sealed record DevBoxCustomizationGroupSummary(
    string Name,
    Uri Uri,
    string Status,
    DateTimeOffset? StartTime,
    DateTimeOffset? EndTime);

public sealed record DevBoxCustomizationHttpResponse(
    int Status,
    BinaryData Content);

public interface IDevBoxCustomizationTransport
{
    Task<DevBoxCustomizationHttpResponse> SendAsync(
        RequestMethod method,
        Uri uri,
        BinaryData? content,
        CancellationToken cancellationToken);
}

public sealed class AzurePipelineDevBoxCustomizationTransport(
    HttpPipeline pipeline) : IDevBoxCustomizationTransport
{
    public async Task<DevBoxCustomizationHttpResponse> SendAsync(
        RequestMethod method,
        Uri uri,
        BinaryData? content,
        CancellationToken cancellationToken)
    {
        using var message = pipeline.CreateMessage(
            new RequestContext
            {
                CancellationToken = cancellationToken
            });
        message.Request.Method = method;
        message.Request.Uri.Reset(uri);
        message.Request.Headers.SetValue(
            "Accept",
            "application/json");
        if (content is not null)
        {
            message.Request.Content = RequestContent.Create(content);
            message.Request.Headers.SetValue(
                "Content-Type",
                "application/json");
        }
        await pipeline.SendAsync(message, cancellationToken)
            .ConfigureAwait(false);
        return new(
            message.Response.Status,
            message.Response.Content ?? BinaryData.FromBytes([]));
    }
}

public sealed class DevBoxCustomizationClient
{
    public const string ApiVersion = "2025-02-01";
    public const int MaximumResponseBytes = 4 * 1024 * 1024;
    private readonly Uri _endpoint;
    private readonly IDevBoxCustomizationTransport _transport;
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web);

    public DevBoxCustomizationClient(
        Uri endpoint,
        IDevBoxCustomizationTransport transport)
    {
        ValidateEndpoint(endpoint);
        _endpoint = new(
            endpoint.GetLeftPart(UriPartial.Authority) + "/",
            UriKind.Absolute);
        _transport = transport ??
            throw new ArgumentNullException(nameof(transport));
    }

    public async Task<DevBoxCustomizationGroupResult> ApplyAsync(
        string project,
        string user,
        string devBox,
        string group,
        IReadOnlyList<DevBoxCustomizationTaskRequest> tasks,
        CancellationToken cancellationToken)
    {
        ValidateIdentifier(project, nameof(project));
        ValidateUser(user);
        ValidateIdentifier(devBox, nameof(devBox));
        ValidateIdentifier(group, nameof(group));
        if (tasks.Count is 0 or > 16)
            throw new ArgumentException(
                "A customization group must contain 1..16 tasks.",
                nameof(tasks));
        var validated = tasks.Select(task => task.Validate()).ToArray();
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new ApplyRequest(
                validated.Select(task => new TaskRequest(
                    task.Name,
                    task.DisplayName,
                    task.Parameters,
                    task.RunAs.ToString(),
                    task.TimeoutInSeconds)).ToArray()),
            Json);
        if (payload.Length > 256 * 1024)
            throw new ArgumentException(
                "Customization request exceeds its bound.",
                nameof(tasks));
        var groupUri = GroupUri(project, user, devBox, group);
        var response = await _transport.SendAsync(
            RequestMethod.Put,
            groupUri,
            BinaryData.FromBytes(payload),
            cancellationToken).ConfigureAwait(false);
        return ParseGroup(
            response,
            group,
            groupUri,
            requireTaskResults: false);
    }

    public async Task<DevBoxCustomizationGroupResult> GetAsync(
        string project,
        string user,
        string devBox,
        string group,
        CancellationToken cancellationToken)
    {
        ValidateIdentifier(project, nameof(project));
        ValidateUser(user);
        ValidateIdentifier(devBox, nameof(devBox));
        ValidateIdentifier(group, nameof(group));
        var groupUri = GroupUri(project, user, devBox, group);
        var response = await _transport.SendAsync(
            RequestMethod.Get,
            groupUri,
            null,
            cancellationToken).ConfigureAwait(false);
        return ParseGroup(
            response,
            group,
            groupUri,
            requireTaskResults: true);
    }

    public async Task<IReadOnlyList<DevBoxCustomizationGroupSummary>> ListAsync(
        string project,
        string user,
        string devBox,
        CancellationToken cancellationToken)
    {
        ValidateIdentifier(project, nameof(project));
        ValidateUser(user);
        ValidateIdentifier(devBox, nameof(devBox));
        var requestUri = new Uri(
            _endpoint,
            $"projects/{Escape(project)}/users/{Escape(user)}/" +
            $"devboxes/{Escape(devBox)}/customizationGroups" +
            $"?api-version={ApiVersion}");
        var results = new List<DevBoxCustomizationGroupSummary>();
        var visited = new HashSet<string>(StringComparer.Ordinal);
        for (var page = 0; requestUri is not null && page < 100; page++)
        {
            ValidateServiceUri(requestUri);
            if (!visited.Add(requestUri.AbsoluteUri))
                throw new InvalidDataException(
                    "Customization group pagination contains a cycle.");
            var response = await _transport.SendAsync(
                    RequestMethod.Get,
                    requestUri,
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
            EnsureSuccess(response);
            var bytes = response.Content.ToMemory();
            if (bytes.Length is 0 or > MaximumResponseBytes)
                throw new InvalidDataException(
                    "Customization group list is empty or exceeds its bound.");
            PagedGroupResponse value;
            try
            {
                value = JsonSerializer.Deserialize<PagedGroupResponse>(
                            bytes.Span,
                            Json)
                        ?? throw new InvalidDataException(
                            "Customization group list is empty.");
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException(
                    "Customization group list is invalid.",
                    exception);
            }
            foreach (var group in value.Value ?? [])
            {
                if (string.IsNullOrWhiteSpace(group.Name) ||
                    string.IsNullOrWhiteSpace(group.Status) ||
                    !Uri.TryCreate(group.Uri, UriKind.Absolute, out var uri))
                    throw new InvalidDataException(
                        "Customization group list contains an invalid identity.");
                ValidateServiceUri(uri);
                results.Add(new(
                    group.Name,
                    uri,
                    group.Status,
                    group.StartTime,
                    group.EndTime));
            }
            if (string.IsNullOrWhiteSpace(value.NextLink))
                return results;
            if (!Uri.TryCreate(
                    value.NextLink,
                    UriKind.Absolute,
                    out var next))
                throw new InvalidDataException(
                    "Customization group continuation URI is invalid.");
            requestUri = next;
        }
        throw new InvalidDataException(
            "Customization group pagination exceeded its bound.");
    }

    public async Task<string> GetTaskLogAsync(
        Uri logUri,
        CancellationToken cancellationToken)
    {
        ValidateServiceUri(logUri);
        var separator = string.IsNullOrEmpty(logUri.Query)
            ? "?"
            : "&";
        var response = await _transport.SendAsync(
            RequestMethod.Get,
            new Uri(
                logUri.AbsoluteUri +
                separator +
                $"api-version={ApiVersion}"),
            null,
            cancellationToken).ConfigureAwait(false);
        EnsureSuccess(response);
        var bytes = response.Content.ToMemory();
        if (bytes.Length > MaximumResponseBytes)
            throw new InvalidDataException(
                "Customization task log exceeds its bound.");
        try
        {
            return JsonSerializer.Deserialize<string>(bytes.Span, Json)
                ?? string.Empty;
        }
        catch (JsonException)
        {
            return System.Text.Encoding.UTF8.GetString(bytes.Span);
        }
    }

    private DevBoxCustomizationGroupResult ParseGroup(
        DevBoxCustomizationHttpResponse response,
        string expectedName,
        Uri expectedUri,
        bool requireTaskResults)
    {
        EnsureSuccess(response);
        var bytes = response.Content.ToMemory();
        if (bytes.Length is 0 or > MaximumResponseBytes)
            throw new InvalidDataException(
                "Customization response is empty or exceeds its bound.");
        GroupResponse value;
        try
        {
            value = JsonSerializer.Deserialize<GroupResponse>(
                bytes.Span,
                Json)
                ?? throw new InvalidDataException(
                    "Customization response is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Customization response is invalid.",
                exception);
        }
        var resolvedName = string.IsNullOrWhiteSpace(value.Name)
            ? expectedName
            : value.Name;
        if (!string.Equals(
                resolvedName,
                expectedName,
                StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(value.Status) ||
            !Uri.TryCreate(value.Uri, UriKind.Absolute, out var groupUri))
            throw new InvalidDataException(
                $"Customization group identity is invalid " +
                $"(name={!string.IsNullOrWhiteSpace(value.Name)}, " +
                $"status={!string.IsNullOrWhiteSpace(value.Status)}, " +
                $"uri={Uri.TryCreate(value.Uri, UriKind.Absolute, out _)}, " +
                $"other={(value.Additional is null ? string.Empty : string.Join(',', value.Additional.Keys))}).");
        ValidateServiceUri(groupUri);
        if (!string.Equals(
                groupUri.AbsolutePath.TrimEnd('/'),
                expectedUri.AbsolutePath.TrimEnd('/'),
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Customization group URI does not match the requested group.");
        var tasks = new List<DevBoxCustomizationTaskResult>();
        foreach (var task in value.Tasks ?? [])
        {
            var hasLogUri = Uri.TryCreate(
                task.LogUri,
                UriKind.Absolute,
                out var parsedLogUri);
            var valid = Guid.TryParse(task.Id, out var id) &&
                !string.IsNullOrWhiteSpace(task.Name) &&
                !string.IsNullOrWhiteSpace(task.Status) &&
                hasLogUri;
            if (!valid)
            {
                if (!requireTaskResults)
                    continue;
                throw new InvalidDataException(
                    $"Customization task identity is invalid " +
                    $"(id={Guid.TryParse(task.Id, out _)}, " +
                    $"name={!string.IsNullOrWhiteSpace(task.Name)}, " +
                    $"status={!string.IsNullOrWhiteSpace(task.Status)}, " +
                    $"logUri={Uri.TryCreate(task.LogUri, UriKind.Absolute, out _)}, " +
                    $"other={(task.Additional is null ? string.Empty : string.Join(',', task.Additional.Keys))}, " +
                    $"groupOther={(value.Additional is null ? string.Empty : string.Join(',', value.Additional.Keys))}).");
            }
            if (!Guid.TryParse(task.Id, out id) ||
                string.IsNullOrWhiteSpace(task.Name) ||
                string.IsNullOrWhiteSpace(task.Status) ||
                parsedLogUri is null)
                throw new InvalidDataException(
                    "Customization task identity changed during validation.");
            ValidateServiceUri(parsedLogUri);
            tasks.Add(new DevBoxCustomizationTaskResult(
                id,
                task.Name,
                task.DisplayName,
                task.Status,
                parsedLogUri));
        }
        return new(
            resolvedName,
            groupUri,
            value.Status,
            value.StartTime,
            value.EndTime,
            tasks);
    }

    private Uri GroupUri(
        string project,
        string user,
        string devBox,
        string group) =>
        new(
            _endpoint,
            $"projects/{Escape(project)}/users/{Escape(user)}/" +
            $"devboxes/{Escape(devBox)}/customizationGroups/" +
            $"{Escape(group)}?api-version={ApiVersion}");

    private void ValidateServiceUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.Port != 443 ||
            uri.UserInfo.Length != 0 ||
            !string.Equals(
                uri.IdnHost,
                _endpoint.IdnHost,
                StringComparison.OrdinalIgnoreCase) ||
            !uri.AbsolutePath.StartsWith(
                "/projects/",
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Customization URI is outside the Dev Center boundary.");
    }

    private static void EnsureSuccess(
        DevBoxCustomizationHttpResponse response)
    {
        if (response.Status is >= 200 and < 300)
            return;
        if (response.Status is 401 or 403)
            throw new InvalidOperationException(
                "The devbox/default identity cannot perform customization.");
        throw new RequestFailedException(
            response.Status,
            "Dev Box customization request failed.");
    }

    private static void ValidateEndpoint(Uri endpoint)
    {
        if (!endpoint.IsAbsoluteUri ||
            endpoint.Scheme != Uri.UriSchemeHttps ||
            endpoint.Port != 443 ||
            endpoint.UserInfo.Length != 0 ||
            endpoint.AbsolutePath != "/" ||
            !endpoint.IdnHost.EndsWith(
                ".devcenter.azure.com",
                StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                "Dev Center endpoint is invalid.",
                nameof(endpoint));
    }

    private static void ValidateIdentifier(string value, string name)
    {
        if (value.Length is < 3 or > 63 ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.'))
            throw new ArgumentException(
                "Dev Box identifier is invalid.",
                name);
    }

    private static void ValidateUser(string value)
    {
        if (string.Equals(value, "me", StringComparison.Ordinal))
            return;
        if (!Guid.TryParse(value, out _))
            throw new ArgumentException(
                "Dev Box user must be 'me' or a GUID.",
                nameof(value));
    }

    private static string Escape(string value) =>
        Uri.EscapeDataString(value);

    private sealed record ApplyRequest(
        [property: JsonPropertyName("tasks")]
        IReadOnlyList<TaskRequest> Tasks);

    private sealed record TaskRequest(
        [property: JsonPropertyName("name")]
        string Name,
        [property: JsonPropertyName("displayName")]
        string DisplayName,
        [property: JsonPropertyName("parameters")]
        IReadOnlyDictionary<string, string> Parameters,
        [property: JsonPropertyName("runAs")]
        string RunAs,
        [property: JsonPropertyName("timeoutInSeconds")]
        int TimeoutInSeconds);

    private sealed class GroupResponse
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("uri")]
        public string Uri { get; init; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; init; } = string.Empty;

        [JsonPropertyName("startTime")]
        public DateTimeOffset? StartTime { get; init; }

        [JsonPropertyName("endTime")]
        public DateTimeOffset? EndTime { get; init; }

        [JsonPropertyName("tasks")]
        public IReadOnlyList<TaskResponse>? Tasks { get; init; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Additional { get; init; }
    }

    private sealed class PagedGroupResponse
    {
        [JsonPropertyName("value")]
        public IReadOnlyList<GroupResponse>? Value { get; init; }

        [JsonPropertyName("nextLink")]
        public string? NextLink { get; init; }
    }

    private sealed class TaskResponse
    {
        [JsonPropertyName("id")]
        public string Id { get; init; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("displayName")]
        public string? DisplayName { get; init; }

        [JsonPropertyName("status")]
        public string Status { get; init; } = string.Empty;

        [JsonPropertyName("logUri")]
        public string LogUri { get; init; } = string.Empty;

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Additional { get; init; }
    }
}
