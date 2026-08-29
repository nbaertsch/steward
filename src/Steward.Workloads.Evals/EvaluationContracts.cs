using System.Collections.Immutable;
using System.Text.RegularExpressions;
using System.Text.Json;
using Steward.Domain;
using Steward.Scheduling;

namespace Steward.Workloads.Evals;

public static class EvaluationLimits
{
    // Leaves room below WorkloadPlan's 10,000-node bound for setup and reduction nodes.
    public const int MaximumCases = 9_900;
    public const int MaximumFilters = 128;
    public const int MaximumIdentityCapabilities = 32;
    public const int MaximumInventoryBytes = 8 * 1024 * 1024;
    public const int MaximumMetricsPerResult = 256;
    public const int MaximumArtifactsPerResult = 256;
    public const int MaximumJsonLineBytes = 1024 * 1024;
    public const int MaximumProgressMessageLength = 4096;
    public const int MaximumMetricNameLength = 256;
    public const int MaximumArtifactReferenceLength = 1024;
}

public enum SourceCommitKind { GitSha1, GitSha256 }

public sealed record EvaluationSource(
    Uri? Uri,
    string RequestedRef,
    string ResolvedCommit,
    string? RegisteredLocalSource = null,
    SourceCommitKind CommitKind = SourceCommitKind.GitSha1)
{
    public void Validate(string name)
    {
        if ((Uri is null) == string.IsNullOrWhiteSpace(RegisteredLocalSource))
            throw new ArgumentException($"{name} must specify exactly one URI or registered local source.");
        if (Uri is not null && (!Uri.IsAbsoluteUri || !string.Equals(Uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException($"{name} URI must use HTTPS.");
        if (Uri?.AbsoluteUri.Length > 2048) throw new ArgumentException($"{name} URI is too long.");
        if (Uri is not null && (!string.IsNullOrEmpty(Uri.UserInfo) || !string.IsNullOrEmpty(Uri.Query) ||
                                !string.IsNullOrEmpty(Uri.Fragment)))
            throw new ArgumentException($"{name} URI must not contain userinfo, query, or fragment components.");
        Required(RequestedRef, $"{name} requested ref");
        Required(ResolvedCommit, $"{name} resolved commit");
        if (RegisteredLocalSource is not null &&
            (RegisteredLocalSource.Length > 256 || RegisteredLocalSource.Contains(':') ||
             RegisteredLocalSource.Split('/', '\\').Any(x => x is "" or "." or "..")))
            throw new ArgumentException($"{name} registered local source must be a bounded opaque identifier.");
        if (!IsValidCommit(ResolvedCommit, CommitKind))
            throw new ArgumentException($"{name} resolved commit must be a full {CommitKind} hexadecimal hash.");
    }

    internal object ToDto() => new
    {
        uri = Uri?.AbsoluteUri,
        requestedRef = RequestedRef,
        resolvedCommit = ResolvedCommit,
        registeredLocalSource = RegisteredLocalSource,
        commitKind = CommitKind.ToString()
    };

    internal static void Required(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException($"{name} is required.");
    }

    internal static bool IsValidCommit(string? value, SourceCommitKind? kind = null) =>
        value is not null && (kind is null ? value.Length is 40 or 64 :
            value.Length == (kind == SourceCommitKind.GitSha1 ? 40 : 64)) && value.All(Uri.IsHexDigit);
}

public sealed record EvaluationDataset(string Identity, string ContentHash)
{
    private static readonly Regex Digest = new(
        "^(sha256|blake3):[a-fA-F0-9]{64}$|^sha512:[a-fA-F0-9]{128}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public void Validate()
    {
        EvaluationSource.Required(Identity, "Dataset identity");
        EvaluationSource.Required(ContentHash, "Dataset hash");
        if (!IsValidDigest(ContentHash))
            throw new ArgumentException("Dataset hash must be an algorithm-prefixed sha256, sha512, or blake3 digest.");
    }

    internal static bool IsValidDigest(string? value) => value is not null && Digest.IsMatch(value);
}

public sealed record IdentityCapabilityReference(string Reference, string Capability)
{
    public void Validate()
    {
        EvaluationSource.Required(Reference, "Identity capability reference");
        EvaluationSource.Required(Capability, "Identity capability");
        if (Reference.Length > 1024 || Capability.Length > 256)
            throw new ArgumentException("Identity reference or capability exceeds its size bound.");
        if (!System.Uri.TryCreate(Reference, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, "identity", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new ArgumentException("Identity references must be typed identity:// URIs without userinfo, query, or fragments.");
    }
}

public sealed record EvaluationResourcePolicy(
    decimal CpuCores = 1,
    long MemoryBytes = 2L * 1024 * 1024 * 1024,
    long DiskBytes = 2L * 1024 * 1024 * 1024,
    int GpuCount = 0,
    int ProcessCount = 1,
    int ContainerCount = 0,
    int ConcurrencyUnits = 1)
{
    internal ResourceRequirements ToRequirements() =>
        new(CpuCores, MemoryBytes, DiskBytes, GpuCount, ProcessCount, ContainerCount, 0, ConcurrencyUnits);
}

public sealed record EvaluationShardPolicy(
    int MaximumConcurrency,
    int PreferredCasesPerHost,
    bool PreferOneHost = false)
{
    public void Validate()
    {
        if (MaximumConcurrency is < 1 or > EvaluationLimits.MaximumCases)
            throw new ArgumentOutOfRangeException(nameof(MaximumConcurrency));
        if (PreferredCasesPerHost is < 1 or > EvaluationLimits.MaximumCases)
            throw new ArgumentOutOfRangeException(nameof(PreferredCasesPerHost));
    }
}

public sealed record EvaluationLocations(string ResultLocation, string OutputLocation)
{
    public void Validate()
    {
        EvaluationSource.Required(ResultLocation, "Result location");
        EvaluationSource.Required(OutputLocation, "Output location");
        ValidateLocation(ResultLocation, "Result location");
        ValidateLocation(OutputLocation, "Output location");
    }

    internal static void ValidateLocation(string value, string name)
    {
        if (value.Length > 1024 || value.Any(char.IsControl))
            throw new ArgumentException($"{name} exceeds its size bound or contains control characters.");
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            if (!string.Equals(uri.Scheme, "portable", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo) ||
                !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) ||
                Uri.UnescapeDataString(uri.AbsolutePath).Split('/', StringSplitOptions.RemoveEmptyEntries).Any(x => x is "." or ".."))
                throw new ArgumentException($"{name} must be workspace-relative or use a portable:// URI.");
            return;
        }
        if (Path.IsPathFullyQualified(value) || value.StartsWith(@"\\", StringComparison.Ordinal) || value.Contains(':'))
            throw new ArgumentException($"{name} cannot be absolute or device-qualified.");
        var segments = value.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Any(x => x is "." or ".." || IsDeviceName(x) ||
            x.EndsWith(' ') || x.EndsWith('.') || x.IndexOfAny(['<', '>', '"', '|', '?', '*']) >= 0))
            throw new ArgumentException($"{name} must be a safe workspace-relative path.");
    }

    private static bool IsDeviceName(string segment)
    {
        var name = segment.Split('.')[0];
        return name.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
               Regex.IsMatch(name, "^(COM|LPT)[1-9]$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}

public sealed record EvaluationRuntimeRequirements(
    string RuntimeVersion,
    string SetupVersion,
    bool RequiresDocker = false,
    string? ComposeFile = null)
{
    public void Validate()
    {
        EvaluationSource.Required(RuntimeVersion, "Runtime version");
        EvaluationSource.Required(SetupVersion, "Setup version");
        if (ComposeFile is not null && (Path.IsPathFullyQualified(ComposeFile) || ComposeFile.Split('/', '\\').Contains("..")))
            throw new ArgumentException("Compose file must be a safe workspace-relative path.");
    }
}

public sealed record EvaluationCase(string CaseId, JsonElement Definition)
{
    public static EvaluationCase Create(string caseId, object definition) =>
        new(caseId, JsonSerializer.SerializeToElement(definition, EvaluationJson.Options));
}

public sealed class NormalizedHarnessInventory
{
    public string ContentHash { get; }
    public ImmutableArray<EvaluationCase> Cases { get; }

    public NormalizedHarnessInventory(IEnumerable<EvaluationCase> cases)
    {
        ArgumentNullException.ThrowIfNull(cases);
        var values = cases.ToArray();
        if (values.Length is < 1 or > EvaluationLimits.MaximumCases)
            throw new ArgumentException($"Inventory must contain 1..{EvaluationLimits.MaximumCases} cases.", nameof(cases));
        foreach (var item in values)
        {
            EvaluationSource.Required(item.CaseId, "Case ID");
            if (item.CaseId.Length > 512) throw new ArgumentException("Case ID exceeds 512 characters.", nameof(cases));
            if (item.Definition.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
                throw new ArgumentException("Case definition is required.", nameof(cases));
        }
        if (values.Select(x => x.CaseId).Distinct(StringComparer.Ordinal).Count() != values.Length)
            throw new ArgumentException("Inventory case IDs must be unique.", nameof(cases));

        Cases = values.OrderBy(x => x.CaseId, StringComparer.Ordinal)
            .Select(x => new EvaluationCase(x.CaseId, EvaluationJson.CanonicalElement(x.Definition)))
            .ToImmutableArray();
        var canonical = EvaluationJson.Serialize(Cases.Select(x => new { caseId = x.CaseId, definition = x.Definition }));
        if (System.Text.Encoding.UTF8.GetByteCount(canonical) > EvaluationLimits.MaximumInventoryBytes)
            throw new ArgumentException("Normalized inventory exceeds its size bound.", nameof(cases));
        ContentHash = EvaluationHash.Sha256(canonical);
    }

    public static NormalizedHarnessInventory Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (System.Text.Encoding.UTF8.GetByteCount(json) > EvaluationLimits.MaximumInventoryBytes)
            throw new ArgumentException("Inventory exceeds its size bound.", nameof(json));
        try
        {
            using var document = JsonDocument.Parse(json, EvaluationJson.DocumentOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                throw new ArgumentException("Inventory must be a JSON array.", nameof(json));
            var cases = new List<EvaluationCase>();
            foreach (var item in document.RootElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object ||
                    !item.TryGetProperty("caseId", out var caseId) || caseId.ValueKind != JsonValueKind.String ||
                    !item.TryGetProperty("definition", out var definition))
                    throw new ArgumentException("Each inventory item requires string caseId and definition.", nameof(json));
                cases.Add(new(caseId.GetString()!, definition.Clone()));
                if (cases.Count > EvaluationLimits.MaximumCases)
                    throw new ArgumentException($"Inventory exceeds {EvaluationLimits.MaximumCases} cases.", nameof(json));
            }
            return new(cases);
        }
        catch (JsonException exception)
        {
            throw new ArgumentException("Inventory JSON is malformed.", nameof(json), exception);
        }
    }
}

public sealed record EvaluationWorkloadInput(
    EvaluationSource Harness,
    EvaluationSource Repository,
    EvaluationDataset Dataset,
    string EvaluationSet,
    IReadOnlyList<string> TaskFilters,
    string ModelProfileReference,
    EvaluationShardPolicy ShardPolicy,
    EvaluationLocations Locations,
    EvaluationRuntimeRequirements Runtime,
    IReadOnlyList<IdentityCapabilityReference> IdentityCapabilities,
    NormalizedHarnessInventory Inventory,
    EvaluationResourcePolicy? CaseResources = null,
    string InferenceRateScope = "inference",
    decimal InferenceUnitsPerCase = 1)
{
    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(Harness); Harness.Validate("Harness source");
        ArgumentNullException.ThrowIfNull(Repository); Repository.Validate("Repository source");
        ArgumentNullException.ThrowIfNull(Dataset); Dataset.Validate();
        EvaluationSource.Required(EvaluationSet, "Evaluation set");
        EvaluationSource.Required(ModelProfileReference, "Model profile reference");
        if (!Uri.TryCreate(ModelProfileReference, UriKind.Absolute, out var profile) ||
            !string.Equals(profile.Scheme, "inference-profile", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(profile.Host) || !string.IsNullOrEmpty(profile.UserInfo) ||
            !string.IsNullOrEmpty(profile.Query) || !string.IsNullOrEmpty(profile.Fragment))
            throw new ArgumentException("Model profile must be an inference-profile:// reference without credentials or decorations.");
        ArgumentNullException.ThrowIfNull(ShardPolicy); ShardPolicy.Validate();
        ArgumentNullException.ThrowIfNull(Locations); Locations.Validate();
        ArgumentNullException.ThrowIfNull(Runtime); Runtime.Validate();
        ArgumentNullException.ThrowIfNull(Inventory);
        ArgumentNullException.ThrowIfNull(TaskFilters);
        ArgumentNullException.ThrowIfNull(IdentityCapabilities);
        if (TaskFilters.Count > EvaluationLimits.MaximumFilters) throw new ArgumentException("Too many task filters.");
        if (TaskFilters.Any(string.IsNullOrWhiteSpace)) throw new ArgumentException("Task filters cannot be blank.");
        if (IdentityCapabilities.Count > EvaluationLimits.MaximumIdentityCapabilities) throw new ArgumentException("Too many identity capabilities.");
        foreach (var reference in IdentityCapabilities) reference.Validate();
        if (IdentityCapabilities.Select(x => x.Capability).Distinct(StringComparer.Ordinal).Count() != IdentityCapabilities.Count)
            throw new ArgumentException("Identity capabilities must be unique.");
        EvaluationSource.Required(InferenceRateScope, "Inference rate scope");
        if (InferenceUnitsPerCase <= 0) throw new ArgumentOutOfRangeException(nameof(InferenceUnitsPerCase));
        _ = (CaseResources ?? new()).ToRequirements();
    }

    internal EvaluationWorkloadInput Snapshot() => this with
    {
        Harness = Harness with { ResolvedCommit = Harness.ResolvedCommit.ToLowerInvariant() },
        Repository = Repository with { ResolvedCommit = Repository.ResolvedCommit.ToLowerInvariant() },
        Dataset = Dataset with { ContentHash = Dataset.ContentHash.ToLowerInvariant() },
        TaskFilters = TaskFilters.ToImmutableArray(),
        IdentityCapabilities = IdentityCapabilities.ToImmutableArray()
    };
}

public sealed record EvaluationPlanRequest(
    WorkloadId WorkloadId,
    PlanRevisionId PlanRevisionId,
    EvaluationWorkloadInput Input,
    IReadOnlyList<CompletedEvaluationResult>? CompletedResults = null);

public sealed record CompletedEvaluationResult(EvaluationCaseResult Result, string PortableResultReference)
{
    public void Validate(EvaluationResultContext expected)
    {
        ArgumentNullException.ThrowIfNull(Result);
        if (!Result.HasValidReceipt()) throw new ArgumentException("Completed result receipt hash is invalid.");
        if (Result.AttemptGeneration < 0) throw new ArgumentException("Completed result generation cannot be negative.");
        if (Result.HarnessVersion != expected.HarnessVersion || Result.Commit != expected.Commit ||
            Result.DatasetHash != expected.DatasetHash || Result.ModelProfile != expected.ModelProfile)
            throw new ArgumentException("Completed result immutable context does not match the workload.");
        if (Result.FailureClassification == EvaluationFailureClassification.InferenceThrottle)
            throw new ArgumentException("Inference-throttled attempts are not completed case results.");
        if (Result.FailureClassification == EvaluationFailureClassification.Infrastructure)
            throw new ArgumentException("Retryable infrastructure results are not completed case results.");
        EvaluationLocations.ValidateLocation(PortableResultReference, "Portable result reference");
    }
}

public sealed record EvaluationCommand(
    string Executable,
    IReadOnlyList<string> Arguments,
    string? WorkingDirectory,
    IReadOnlyDictionary<string, string>? EnvironmentReferences = null);

public sealed record EvaluationProgress(string CaseId, double Fraction, string? Message);

public interface IEvaluationResultParser
{
    EvaluationProgress? ParseProgress(string line);
    EvaluationCaseResult? ParseResult(string line, EvaluationResultContext context);
    EvaluationFailureNotice? ParseFailure(string line) => null;
}

public interface IEvaluationHarnessAdapter
{
    string HarnessName { get; }
    string HarnessVersion { get; }
    string ProfileVersion { get; }
    bool RequiresDocker { get; }
    void Validate(EvaluationWorkloadInput input);
    EvaluationCommand CreateCommand(EvaluationWorkloadInput input, EvaluationCase evaluationCase, int generation);
    EvaluationCommand CreateCommandTemplate(EvaluationWorkloadInput input, EvaluationCase evaluationCase);
    IEvaluationResultParser ResultParser { get; }
}

internal static class EvaluationJson
{
    internal static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
    internal static readonly JsonDocumentOptions DocumentOptions = new() { MaxDepth = 64, CommentHandling = JsonCommentHandling.Disallow };

    internal static string Serialize<T>(T value) =>
        TaskInput.Parse("application/json", "1.0", JsonSerializer.Serialize(value, Options)).CanonicalJson;

    internal static JsonElement CanonicalElement(JsonElement value)
    {
        using var document = JsonDocument.Parse(TaskInput.Parse("application/json", "1.0", value.GetRawText()).CanonicalJson);
        return document.RootElement.Clone();
    }
}

internal static class EvaluationHash
{
    internal static string Sha256(string value) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    internal static Guid DeterministicGuid(string value)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))[..16];
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes);
    }
}
