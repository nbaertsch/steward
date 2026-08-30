using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Steward.Domain;

namespace Steward.Scheduling;

public enum AggregateFailurePolicy { FailFast, Continue, PartialSuccess }
public enum ExpiredRateBehavior { Pause, ConservativeFloor }

public sealed class TaskInput
{
    public const int MaximumUtf8Bytes = 64 * 1024;
    public const int MaximumDepth = 64;
    public static TaskInput Empty { get; } = Parse("application/json", "1.0", "{}");

    public string MediaType { get; }
    public string SchemaVersion { get; }
    public string CanonicalJson { get; }

    private TaskInput(string mediaType, string schemaVersion, string canonicalJson)
    {
        MediaType = mediaType;
        SchemaVersion = schemaVersion;
        CanonicalJson = canonicalJson;
    }

    public static TaskInput Parse(string mediaType, string schemaVersion, string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mediaType);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaVersion);
        ArgumentNullException.ThrowIfNull(json);
        if (!string.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Task input must use the provider-neutral application/json media type.", nameof(mediaType));
        var source = Encoding.UTF8.GetBytes(json);
        if (source.Length > MaximumUtf8Bytes) throw new ArgumentException("Task input exceeds the UTF-8 size limit.", nameof(json));
        using var document = JsonDocument.Parse(source, new JsonDocumentOptions
        {
            MaxDepth = MaximumDepth,
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false
        });
        var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
            WriteCanonical(writer, document.RootElement, 0);
        if (buffer.Length > MaximumUtf8Bytes) throw new ArgumentException("Canonical Task input exceeds the UTF-8 size limit.", nameof(json));
        return new(mediaType.ToLowerInvariant(), schemaVersion, Encoding.UTF8.GetString(buffer.ToArray()));
    }

    public static TaskInput FromJsonElement(string mediaType, string schemaVersion, JsonElement value) =>
        Parse(mediaType, schemaVersion, value.GetRawText());

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element, int depth)
    {
        if (depth > MaximumDepth) throw new ArgumentException("Task input exceeds the JSON depth limit.", nameof(element));
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(x => x.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(writer, property.Value, depth + 1);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray()) WriteCanonical(writer, item, depth + 1);
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;
            case JsonValueKind.Number:
                writer.WriteRawValue(NormalizeNumber(element.GetRawText()), skipInputValidation: false);
                break;
            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;
            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;
            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
            default:
                throw new ArgumentException("Unsupported JSON value.", nameof(element));
        }
    }

    private static string NormalizeNumber(string value)
    {
        var negative = value[0] == '-';
        var unsigned = negative ? value[1..] : value;
        var exponentIndex = unsigned.IndexOfAny(['e', 'E']);
        var mantissa = exponentIndex < 0 ? unsigned : unsigned[..exponentIndex];
        var exponent = exponentIndex < 0 ? BigInteger.Zero : BigInteger.Parse(unsigned[(exponentIndex + 1)..], CultureInfo.InvariantCulture);
        var decimalIndex = mantissa.IndexOf('.');
        var fractionalDigits = decimalIndex < 0 ? 0 : mantissa.Length - decimalIndex - 1;
        var digits = mantissa.Replace(".", "", StringComparison.Ordinal).TrimStart('0');
        if (digits.Length == 0) return "0";
        var power = exponent - fractionalDigits;
        while (digits.Length > 1 && digits[^1] == '0')
        {
            digits = digits[..^1];
            power++;
        }
        var scientificExponent = power + digits.Length - 1;
        var coefficient = digits.Length == 1 ? digits : $"{digits[0]}.{digits[1..]}";
        return $"{(negative ? "-" : "")}{coefficient}e{scientificExponent.ToString(CultureInfo.InvariantCulture)}";
    }
}

public sealed record ExternalRateRequirement(string Scope, decimal Amount)
{
    public ExternalRateRequirement Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Scope);
        if (Amount <= 0) throw new ArgumentOutOfRangeException(nameof(Amount));
        return this;
    }
}

public sealed record TaskPlanNode(
    TaskId TaskId,
    string LogicalKey,
    string TaskType,
    string TaskTypeVersion,
    ResourceRequirements Resources,
    TaskInput Input,
    IReadOnlyList<TaskId> Dependencies,
    IReadOnlySet<string> RequiredHostCapabilities,
    string? SetupFingerprint,
    string? AffinityKey,
    HostId? RequiredHostId,
    int RetryCap,
    InterruptionClass InterruptionClass,
    IReadOnlyList<ExternalRateRequirement> ExternalRates,
    string ResultReductionKey,
    IReadOnlyList<IdentityGrantId>? IdentityGrantIds = null,
    bool IdentityGrantsRenewableAcrossGenerations = false)
{
    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(LogicalKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(TaskType);
        ArgumentException.ThrowIfNullOrWhiteSpace(TaskTypeVersion);
        ArgumentException.ThrowIfNullOrWhiteSpace(ResultReductionKey);
        ArgumentNullException.ThrowIfNull(Input);
        if (RetryCap < 0 || RetryCap > WorkloadPlanLimits.MaximumRetries)
            throw new ArgumentOutOfRangeException(nameof(RetryCap));
        if (Dependencies.Count > WorkloadPlanLimits.MaximumDependenciesPerTask)
            throw new ArgumentException("A Task has too many dependencies.", nameof(Dependencies));
        if (Dependencies.Distinct().Count() != Dependencies.Count)
            throw new ArgumentException("A Task cannot contain duplicate dependencies.", nameof(Dependencies));
        if (RequiredHostCapabilities.Count > WorkloadPlanLimits.MaximumCapabilitiesPerTask)
            throw new ArgumentException("A Task has too many Host capability requirements.", nameof(RequiredHostCapabilities));
        if (ExternalRates.Count > WorkloadPlanLimits.MaximumRateRequirementsPerTask)
            throw new ArgumentException("A Task has too many external-rate requirements.", nameof(ExternalRates));
        foreach (var rate in ExternalRates) rate.Validate();
        if (ExternalRates.Select(x => x.Scope).Distinct(StringComparer.Ordinal).Count() != ExternalRates.Count)
            throw new ArgumentException("External-rate scopes must be unique.", nameof(ExternalRates));
        if ((IdentityGrantIds?.Count ?? 0) > WorkloadPlanLimits.MaximumIdentityGrantsPerTask)
            throw new ArgumentException("A Task has too many identity grants.", nameof(IdentityGrantIds));
    }
}

public static class WorkloadPlanLimits
{
    public const int MaximumTasks = 10_000;
    public const int MaximumDependenciesPerTask = 256;
    public const int MaximumCapabilitiesPerTask = 64;
    public const int MaximumRateRequirementsPerTask = 32;
    public const int MaximumIdentityGrantsPerTask = 64;
    public const int MaximumRetries = 100;
}

public sealed class WorkloadPlan
{
    public const string CurrentSchemaVersion = "1.0";
    public WorkloadId WorkloadId { get; }
    public PlanRevisionId PlanRevisionId { get; }
    public string SchemaVersion { get; }
    public string PlannerType { get; }
    public string PlannerVersion { get; }
    public AggregateFailurePolicy FailurePolicy { get; }
    public int MaximumConcurrency { get; }
    public IReadOnlyList<TaskPlanNode> Tasks { get; }
    public string DeterministicHash { get; }

    public WorkloadPlan(
        WorkloadId workloadId,
        PlanRevisionId planRevisionId,
        string schemaVersion,
        string plannerType,
        string plannerVersion,
        IEnumerable<TaskPlanNode> tasks,
        AggregateFailurePolicy failurePolicy = AggregateFailurePolicy.FailFast,
        int? maximumConcurrency = null)
    {
        if (schemaVersion != CurrentSchemaVersion)
            throw new NotSupportedException($"Workload plan schema '{schemaVersion}' is unsupported.");
        ArgumentException.ThrowIfNullOrWhiteSpace(plannerType);
        ArgumentException.ThrowIfNullOrWhiteSpace(plannerVersion);
        var nodes = tasks?.ToArray() ?? throw new ArgumentNullException(nameof(tasks));
        if (nodes.Length is 0 or > WorkloadPlanLimits.MaximumTasks)
            throw new ArgumentException($"A plan must have 1..{WorkloadPlanLimits.MaximumTasks} Tasks.", nameof(tasks));
        var concurrency = maximumConcurrency ?? nodes.Length;
        if (concurrency <= 0 || concurrency > WorkloadPlanLimits.MaximumTasks)
            throw new ArgumentOutOfRangeException(nameof(maximumConcurrency),
                $"Maximum concurrency must be between 1 and {WorkloadPlanLimits.MaximumTasks}.");
        foreach (var node in nodes) node.Validate();
        if (nodes.Select(x => x.TaskId).Distinct().Count() != nodes.Length)
            throw new ArgumentException("Task IDs must be unique.", nameof(tasks));
        if (nodes.Select(x => x.LogicalKey).Distinct(StringComparer.Ordinal).Count() != nodes.Length)
            throw new ArgumentException("Task logical keys must be unique.", nameof(tasks));
        var ids = nodes.Select(x => x.TaskId).ToHashSet();
        if (nodes.SelectMany(x => x.Dependencies).Any(x => !ids.Contains(x)))
            throw new ArgumentException("Every dependency must name a Task in the plan.", nameof(tasks));
        EnsureAcyclic(nodes);

        WorkloadId = workloadId;
        PlanRevisionId = planRevisionId;
        SchemaVersion = schemaVersion;
        PlannerType = plannerType;
        PlannerVersion = plannerVersion;
        FailurePolicy = failurePolicy;
        MaximumConcurrency = concurrency;
        Tasks = nodes.OrderBy(x => x.TaskId.ToString(), StringComparer.Ordinal).ToArray();
        DeterministicHash = ComputeHash();
    }

    private static void EnsureAcyclic(IReadOnlyList<TaskPlanNode> nodes)
    {
        var incoming = nodes.ToDictionary(x => x.TaskId, x => x.Dependencies.Count);
        var outgoing = nodes.SelectMany(x => x.Dependencies.Select(d => (Dependency: d, Child: x.TaskId)))
            .ToLookup(x => x.Dependency, x => x.Child);
        var ready = new SortedSet<TaskId>(incoming.Where(x => x.Value == 0).Select(x => x.Key),
            Comparer<TaskId>.Create((a, b) => StringComparer.Ordinal.Compare(a.ToString(), b.ToString())));
        var visited = 0;
        while (ready.Count > 0)
        {
            var id = ready.Min;
            ready.Remove(id);
            visited++;
            foreach (var child in outgoing[id])
                if (--incoming[child] == 0) ready.Add(child);
        }
        if (visited != nodes.Count) throw new ArgumentException("Task dependency graph contains a cycle.", nameof(nodes));
    }

    private string ComputeHash()
    {
        var text = new StringBuilder();
        Append(text, SchemaVersion); Append(text, WorkloadId.ToString()); Append(text, PlanRevisionId.ToString());
        Append(text, PlannerType); Append(text, PlannerVersion); Append(text, FailurePolicy.ToString());
        Append(text, MaximumConcurrency.ToString(CultureInfo.InvariantCulture));
        foreach (var task in Tasks)
        {
            Append(text, task.TaskId.ToString()); Append(text, task.LogicalKey); Append(text, task.TaskType);
            Append(text, task.TaskTypeVersion); Append(text, task.ResultReductionKey);
            Append(text, task.Input.MediaType); Append(text, task.Input.SchemaVersion); Append(text, task.Input.CanonicalJson);
            Append(text, task.RetryCap.ToString(CultureInfo.InvariantCulture)); Append(text, task.InterruptionClass.ToString());
            Append(text, task.RequiredHostId?.ToString() ?? ""); Append(text, task.SetupFingerprint ?? ""); Append(text, task.AffinityKey ?? "");
            Append(text, task.Resources.CpuCores.ToString(CultureInfo.InvariantCulture));
            Append(text, task.Resources.MemoryBytes.ToString(CultureInfo.InvariantCulture));
            Append(text, task.Resources.DiskBytes.ToString(CultureInfo.InvariantCulture));
            Append(text, task.Resources.GpuCount.ToString(CultureInfo.InvariantCulture));
            Append(text, task.Resources.ProcessCount.ToString(CultureInfo.InvariantCulture));
            Append(text, task.Resources.ContainerCount.ToString(CultureInfo.InvariantCulture));
            Append(text, task.Resources.VmCount.ToString(CultureInfo.InvariantCulture));
            Append(text, task.Resources.ConcurrencyUnits.ToString(CultureInfo.InvariantCulture));
            Append(text, $"dependencies:{task.Dependencies.Count}");
            foreach (var value in task.Dependencies.Select(x => x.ToString()).Order(StringComparer.Ordinal)) Append(text, value);
            Append(text, $"capabilities:{task.RequiredHostCapabilities.Count}");
            foreach (var value in task.RequiredHostCapabilities.Order(StringComparer.Ordinal)) Append(text, value);
            Append(text, $"rates:{task.ExternalRates.Count}");
            foreach (var value in task.ExternalRates.OrderBy(x => x.Scope, StringComparer.Ordinal))
            { Append(text, value.Scope); Append(text, value.Amount.ToString(CultureInfo.InvariantCulture)); }
            var grants = task.IdentityGrantIds ?? [];
            Append(text, $"grants:{grants.Count}");
            foreach (var value in grants.Select(x => x.ToString()).Order(StringComparer.Ordinal)) Append(text, value);
            Append(text, task.IdentityGrantsRenewableAcrossGenerations ? "renewable-grants" : "generation-bound-grants");
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString()))).ToLowerInvariant();
    }

    private static void Append(StringBuilder builder, string value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(value);
}
