using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;

namespace Steward.Workloads.Evals;

internal sealed record HarnessCommandProfile(
    string HarnessName,
    string HarnessVersion,
    string ProfileVersion,
    string Executable,
    IReadOnlyList<string> ArgumentTemplate,
    bool RequiresDocker = false,
    IReadOnlyList<string>? RequiredIdentityCapabilities = null)
{
    private static readonly ImmutableHashSet<string> Tokens =
        ["{caseId}", "{dataset}", "{datasetHash}", "{modelProfile}", "{repositoryCommit}",
         "{harnessCommit}", "{resultLocation}", "{outputLocation}", "{generation}"];

    public HarnessCommandProfile Validate(string expectedHarness)
    {
        if (!string.Equals(HarnessName, expectedHarness, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Profile is for '{HarnessName}', not '{expectedHarness}'.");
        EvaluationSource.Required(HarnessVersion, "Harness version");
        EvaluationSource.Required(ProfileVersion, "Profile version");
        if (!Path.IsPathFullyQualified(Executable)) throw new ArgumentException("Harness executable must be an absolute path.");
        if (new[] { ".cmd", ".bat", ".ps1", ".sh" }.Contains(Path.GetExtension(Executable), StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("Harness executable cannot be a shell script.");
        if (ArgumentTemplate.Count is < 1 or > 128) throw new ArgumentException("Argument template must contain 1..128 entries.");
        foreach (var argument in ArgumentTemplate)
        {
            if (argument is null) throw new ArgumentException("Argument template cannot contain null.");
            var start = argument.IndexOf('{');
            while (start >= 0)
            {
                var end = argument.IndexOf('}', start);
                if (end < 0 || !Tokens.Contains(argument[start..(end + 1)]))
                    throw new ArgumentException($"Unknown command template token in '{argument}'.");
                start = argument.IndexOf('{', end + 1);
            }
        }
        if (!ArgumentTemplate.Any(x => x.Contains("{caseId}", StringComparison.Ordinal)))
            throw new ArgumentException("Argument template must include {caseId}.");
        if ((RequiredIdentityCapabilities ?? []).Any(string.IsNullOrWhiteSpace) ||
            (RequiredIdentityCapabilities ?? []).Distinct(StringComparer.Ordinal).Count() !=
            (RequiredIdentityCapabilities?.Count ?? 0))
            throw new ArgumentException("Harness identity capability names must be non-empty and unique.");
        return this;
    }
}

internal abstract class EvaluationHarnessAdapterBase : IEvaluationHarnessAdapter
{
    public const string AttemptGenerationToken = "__STEWARD_ATTEMPT_GENERATION__";
    private readonly HarnessCommandProfile profile;

    protected EvaluationHarnessAdapterBase(
        HarnessCommandProfile profile, string harnessName, IEvaluationResultParser? resultParser = null)
    {
        profile.Validate(harnessName);
        this.profile = profile with
        {
            ArgumentTemplate = profile.ArgumentTemplate.ToImmutableArray(),
            RequiredIdentityCapabilities = profile.RequiredIdentityCapabilities?.ToImmutableArray()
        };
        HarnessName = harnessName;
        ResultParser = resultParser ?? new JsonLinesEvaluationResultParser();
    }

    public string HarnessName { get; }
    public string HarnessVersion => profile.HarnessVersion;
    public string ProfileVersion => profile.ProfileVersion;
    public bool RequiresDocker => profile.RequiresDocker;
    public IEvaluationResultParser ResultParser { get; }

    public virtual void Validate(EvaluationWorkloadInput input)
    {
        input.Validate();
        if (!string.Equals(input.Runtime.RuntimeVersion, HarnessVersion, StringComparison.Ordinal))
            throw new NotSupportedException(
                $"{HarnessName} harness version '{input.Runtime.RuntimeVersion}' is unsupported by profile '{ProfileVersion}' for '{HarnessVersion}'.");
        if (RequiresDocker && !input.Runtime.RequiresDocker)
            throw new ArgumentException($"{HarnessName} profile '{ProfileVersion}' requires Docker.");
        EvaluationIdentity.SelectRequired(input.IdentityCapabilities, profile.RequiredIdentityCapabilities ?? [],
            $"{HarnessName} harness profile");
    }

    public EvaluationCommand CreateCommand(EvaluationWorkloadInput input, EvaluationCase evaluationCase, int generation)
    {
        if (generation < 0) throw new ArgumentOutOfRangeException(nameof(generation));
        return CreateCommandCore(input, evaluationCase, generation.ToString(CultureInfo.InvariantCulture));
    }

    public EvaluationCommand CreateCommandTemplate(EvaluationWorkloadInput input, EvaluationCase evaluationCase) =>
        CreateCommandCore(input, evaluationCase, AttemptGenerationToken);

    private EvaluationCommand CreateCommandCore(
        EvaluationWorkloadInput input, EvaluationCase evaluationCase, string generation)
    {
        Validate(input);
        var replacements = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["{caseId}"] = evaluationCase.CaseId,
            ["{dataset}"] = input.Dataset.Identity,
            ["{datasetHash}"] = input.Dataset.ContentHash,
            ["{modelProfile}"] = input.ModelProfileReference,
            ["{repositoryCommit}"] = input.Repository.ResolvedCommit,
            ["{harnessCommit}"] = input.Harness.ResolvedCommit,
            ["{resultLocation}"] = input.Locations.ResultLocation,
            ["{outputLocation}"] = input.Locations.OutputLocation,
            ["{generation}"] = generation
        };
        var arguments = profile.ArgumentTemplate.Select(argument =>
            EvaluationTemplate.Expand(argument, replacements)).ToArray();
        var identities = EvaluationIdentity.SelectRequired(
            input.IdentityCapabilities, profile.RequiredIdentityCapabilities ?? [], $"{HarnessName} harness profile");
        return new(profile.Executable, arguments, null, identities.ToDictionary(
            x => x.Capability, x => x.Reference, StringComparer.Ordinal));
    }
}

internal sealed class HarborEvaluationAdapter : EvaluationHarnessAdapterBase
{
    public HarborEvaluationAdapter(HarnessCommandProfile profile, IEvaluationResultParser? parser = null)
        : base(profile, "harbor", parser ?? new HarborEvaluationResultParser()) { }
}

internal sealed class SaberEvaluationAdapter : EvaluationHarnessAdapterBase
{
    public SaberEvaluationAdapter(HarnessCommandProfile profile, IEvaluationResultParser? parser = null)
        : base(profile, "saber", parser ?? new SaberEvaluationResultParser()) { }
}

public sealed record EvaluationResultContext(
    int AttemptGeneration,
    string HarnessVersion,
    string Commit,
    string DatasetHash,
    string ModelProfile);

public enum EvaluationCaseStatus { Passed, Failed, Skipped, Error }
public enum EvaluationFailureClassification { None, Harness, Infrastructure, InferenceThrottle, Task }

public sealed record EvaluationCaseResult(
    string CaseId,
    int AttemptGeneration,
    string HarnessVersion,
    string Commit,
    string DatasetHash,
    string ModelProfile,
    EvaluationCaseStatus Status,
    decimal? Score,
    IReadOnlyDictionary<string, decimal> Metrics,
    IReadOnlyList<string> ArtifactReferences,
    EvaluationFailureClassification FailureClassification,
    string ReceiptHash)
{
    public static EvaluationCaseResult Create(
        string caseId, EvaluationResultContext context, EvaluationCaseStatus status, decimal? score,
        IReadOnlyDictionary<string, decimal>? metrics = null, IReadOnlyList<string>? artifactReferences = null,
        EvaluationFailureClassification failureClassification = EvaluationFailureClassification.None)
    {
        EvaluationSource.Required(caseId, "Case ID");
        if (caseId.Length > 512) throw new ArgumentException("Case ID exceeds its size bound.");
        if (context.AttemptGeneration < 0) throw new ArgumentOutOfRangeException(nameof(context));
        EvaluationSource.Required(context.HarnessVersion, "Harness version");
        EvaluationSource.Required(context.Commit, "Repository commit");
        EvaluationSource.Required(context.DatasetHash, "Dataset hash");
        EvaluationSource.Required(context.ModelProfile, "Model profile");
        if (failureClassification == EvaluationFailureClassification.InferenceThrottle)
            throw new ArgumentException("Inference throttling is rate feedback, not a terminal case result.");
        if (status is EvaluationCaseStatus.Passed or EvaluationCaseStatus.Skipped &&
            failureClassification != EvaluationFailureClassification.None)
            throw new ArgumentException("Successful or skipped results cannot carry a failure classification.");
        if (status is EvaluationCaseStatus.Failed or EvaluationCaseStatus.Error &&
            failureClassification == EvaluationFailureClassification.None)
            throw new ArgumentException("Failed or errored results require a failure classification.");
        var sortedMetrics = (metrics ?? new Dictionary<string, decimal>())
            .ToImmutableSortedDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        var sortedArtifacts = (artifactReferences ?? []).Order(StringComparer.Ordinal).ToImmutableArray();
        if (sortedMetrics.Count > EvaluationLimits.MaximumMetricsPerResult) throw new ArgumentException("Too many metrics.");
        if (sortedArtifacts.Length > EvaluationLimits.MaximumArtifactsPerResult) throw new ArgumentException("Too many artifacts.");
        if (sortedMetrics.Keys.Any(x => string.IsNullOrWhiteSpace(x) || x.Length > EvaluationLimits.MaximumMetricNameLength))
            throw new ArgumentException("Metric names must be non-empty and bounded.");
        if (sortedArtifacts.Any(x => x.Length > EvaluationLimits.MaximumArtifactReferenceLength))
            throw new ArgumentException("Artifact reference exceeds its size bound.");
        foreach (var artifact in sortedArtifacts) EvaluationLocations.ValidateLocation(artifact, "Artifact reference");
        var receipt = EvaluationHash.Sha256(EvaluationJson.Serialize(new
        {
            caseId,
            context.AttemptGeneration,
            context.HarnessVersion,
            context.Commit,
            context.DatasetHash,
            context.ModelProfile,
            status = status.ToString(),
            score,
            metrics = sortedMetrics,
            artifactReferences = sortedArtifacts,
            failureClassification = failureClassification.ToString()
        }));
        return new(caseId, context.AttemptGeneration, context.HarnessVersion, context.Commit, context.DatasetHash,
            context.ModelProfile, status, score, sortedMetrics, sortedArtifacts, failureClassification, receipt);
    }

    public bool HasValidReceipt() =>
        string.Equals(ReceiptHash, Create(CaseId,
            new(AttemptGeneration, HarnessVersion, Commit, DatasetHash, ModelProfile), Status, Score,
            Metrics, ArtifactReferences, FailureClassification).ReceiptHash, StringComparison.Ordinal);
}

public class JsonLinesEvaluationResultParser : IEvaluationResultParser
{
    public EvaluationProgress? ParseProgress(string line)
    {
        using var document = Parse(line);
        var root = document.RootElement;
        if (!IsType(root, "progress")) return null;
        var caseId = RequiredString(root, "caseId");
        if (caseId.Length > 512) throw new FormatException("Progress case ID exceeds its size bound.");
        if (!root.TryGetProperty("fraction", out var fractionValue) || !fractionValue.TryGetDouble(out var fraction) ||
            double.IsNaN(fraction) || fraction is < 0 or > 1)
            throw new FormatException("Progress fraction must be between zero and one.");
        string? text = null;
        if (root.TryGetProperty("message", out var message))
        {
            if (message.ValueKind != JsonValueKind.String) throw new FormatException("Progress message must be a string.");
            text = message.GetString();
            if (text?.Length > EvaluationLimits.MaximumProgressMessageLength)
                throw new FormatException("Progress message exceeds its size bound.");
        }
        return new(caseId, fraction, text);
    }

    public EvaluationCaseResult? ParseResult(string line, EvaluationResultContext context)
    {
        using var document = Parse(line);
        var root = document.RootElement;
        if (!IsType(root, "result")) return null;
        var caseId = RequiredString(root, "caseId");
        if (caseId.Length > 512) throw new FormatException("Result case ID exceeds its size bound.");
        if (!root.TryGetProperty("attemptGeneration", out var generation) ||
            !generation.TryGetInt32(out var returnedGeneration) || returnedGeneration != context.AttemptGeneration ||
            RequiredString(root, "harnessVersion") != context.HarnessVersion ||
            RequiredString(root, "commit") != context.Commit ||
            RequiredString(root, "datasetHash") != context.DatasetHash ||
            RequiredString(root, "modelProfile") != context.ModelProfile)
            throw new FormatException("Result immutable context does not match the executing Task.");
        if (!Enum.TryParse<EvaluationCaseStatus>(RequiredString(root, "status"), true, out var status) ||
            !Enum.IsDefined(status))
            throw new FormatException("Unknown evaluation status.");
        var classification = EvaluationFailureClassification.None;
        if (root.TryGetProperty("failureClassification", out var failure))
        {
            if (failure.ValueKind != JsonValueKind.String ||
                !Enum.TryParse(failure.GetString(), true, out classification) ||
                !Enum.IsDefined(classification))
                throw new FormatException("Unknown failure classification.");
        }
        decimal? score = null;
        if (root.TryGetProperty("score", out var scoreValue) && scoreValue.ValueKind != JsonValueKind.Null)
        {
            if (scoreValue.ValueKind != JsonValueKind.Number || !scoreValue.TryGetDecimal(out var parsedScore))
                throw new FormatException("Score must be a finite decimal.");
            score = parsedScore;
        }
        var metrics = new Dictionary<string, decimal>(StringComparer.Ordinal);
        if (root.TryGetProperty("metrics", out var metricObject))
        {
            if (metricObject.ValueKind != JsonValueKind.Object) throw new FormatException("Metrics must be an object.");
            foreach (var metric in metricObject.EnumerateObject())
            {
                if (metrics.Count >= EvaluationLimits.MaximumMetricsPerResult ||
                    metric.Name.Length > EvaluationLimits.MaximumMetricNameLength)
                    throw new FormatException("Metrics exceed their count or name bounds.");
                if (metric.Value.ValueKind != JsonValueKind.Number || !metric.Value.TryGetDecimal(out var metricValue))
                    throw new FormatException("Metric values must be finite decimals.");
                metrics.Add(metric.Name, metricValue);
            }
        }
        var artifacts = new List<string>();
        if (root.TryGetProperty("artifacts", out var artifactArray))
        {
            if (artifactArray.ValueKind != JsonValueKind.Array) throw new FormatException("Artifacts must be an array.");
            foreach (var artifact in artifactArray.EnumerateArray())
            {
                if (artifacts.Count >= EvaluationLimits.MaximumArtifactsPerResult ||
                    artifact.ValueKind != JsonValueKind.String ||
                    artifact.GetString() is not { } value ||
                    value.Length > EvaluationLimits.MaximumArtifactReferenceLength)
                    throw new FormatException("Artifact references exceed their type, count, or size bounds.");
                artifacts.Add(value);
            }
        }
        return EvaluationCaseResult.Create(caseId, context, status, score, metrics, artifacts, classification);
    }

    public EvaluationFailureNotice? ParseFailure(string line)
    {
        using var document = Parse(line);
        var root = document.RootElement;
        if (!IsType(root, "failure")) return null;
        if (!Enum.TryParse<EvaluationFailureSignal>(RequiredString(root, "signal"), true, out var signal) ||
            !Enum.IsDefined(signal))
            throw new FormatException("Unknown evaluation failure signal.");
        DateTimeOffset? retryAfter = null;
        if (root.TryGetProperty("retryAfter", out var retry))
        {
            if (retry.ValueKind != JsonValueKind.String || retry.GetString() is not { Length: <= 64 } retryText ||
                !DateTimeOffset.TryParse(retryText, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
                throw new FormatException("RetryAfter must be an ISO-8601 timestamp.");
            retryAfter = parsed.ToUniversalTime();
        }
        if (signal is EvaluationFailureSignal.Http429 or EvaluationFailureSignal.InferenceThrottle)
        {
            if (retryAfter is null || retryAfter < DateTimeOffset.UtcNow.AddMinutes(-1) ||
                retryAfter > DateTimeOffset.UtcNow.AddHours(24))
                throw new FormatException("Inference throttle requires a bounded RetryAfter timestamp.");
        }
        return new(signal, retryAfter);
    }

    private static JsonDocument Parse(string line)
    {
        if (string.IsNullOrWhiteSpace(line) ||
            System.Text.Encoding.UTF8.GetByteCount(line) > EvaluationLimits.MaximumJsonLineBytes)
            throw new FormatException("Result line is empty or too large.");
        try { return JsonDocument.Parse(line, EvaluationJson.DocumentOptions); }
        catch (JsonException exception) { throw new FormatException("Malformed harness JSON line.", exception); }
    }

    private static bool IsType(JsonElement root, string expected)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new FormatException("Harness record must be an object.");
        if (!root.TryGetProperty("type", out var type)) return false;
        if (type.ValueKind != JsonValueKind.String) throw new FormatException("Harness record type must be a string.");
        return string.Equals(type.GetString(), expected, StringComparison.Ordinal);
    }

    private static string RequiredString(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString())) throw new FormatException($"{property} is required.");
        return value.GetString()!;
    }
}

public sealed class HarborEvaluationResultParser : JsonLinesEvaluationResultParser;
public sealed class SaberEvaluationResultParser : JsonLinesEvaluationResultParser;
