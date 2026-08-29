using System.Collections.Immutable;

namespace Steward.Workloads.Evals;

public enum EvaluationFailureSignal
{
    Success,
    Http429,
    InferenceThrottle,
    Infrastructure,
    DeterministicAssertion,
    Harness,
    Task,
    Setup
}

public sealed record EvaluationFailureNotice(EvaluationFailureSignal Signal, DateTimeOffset? RetryAfter);

public interface IEvaluationRateFeedbackSink
{
    ValueTask ReportThrottleAsync(string scope, DateTimeOffset retryAfter, CancellationToken cancellationToken);
}

public sealed record EvaluationRetryDecision(
    bool RetryCase,
    bool ReportRateFeedback,
    bool IsCaseFailure,
    bool QuarantineSetupFingerprint,
    EvaluationFailureClassification Classification);

public static class EvaluationRetryPolicy
{
    public static EvaluationRetryDecision Classify(EvaluationFailureSignal signal) => signal switch
    {
        EvaluationFailureSignal.Success => new(false, false, false, false, EvaluationFailureClassification.None),
        EvaluationFailureSignal.Http429 or EvaluationFailureSignal.InferenceThrottle =>
            new(true, true, false, false, EvaluationFailureClassification.InferenceThrottle),
        EvaluationFailureSignal.Infrastructure =>
            new(true, false, false, false, EvaluationFailureClassification.Infrastructure),
        EvaluationFailureSignal.Setup =>
            new(false, false, true, true, EvaluationFailureClassification.Infrastructure),
        EvaluationFailureSignal.DeterministicAssertion =>
            new(false, false, true, false, EvaluationFailureClassification.Task),
        EvaluationFailureSignal.Harness =>
            new(false, false, true, false, EvaluationFailureClassification.Harness),
        EvaluationFailureSignal.Task =>
            new(false, false, true, false, EvaluationFailureClassification.Task),
        _ => throw new ArgumentOutOfRangeException(nameof(signal))
    };
}

public sealed record EvaluationManifestEntry(
    string CaseId,
    int AttemptGeneration,
    EvaluationCaseStatus Status,
    decimal? Score,
    IReadOnlyDictionary<string, decimal> Metrics,
    IReadOnlyList<string> ArtifactReferences,
    EvaluationFailureClassification FailureClassification,
    string ReceiptHash);

public sealed record EvaluationExportManifest(
    string HarnessVersion,
    string Commit,
    string DatasetHash,
    string ModelProfile,
    ImmutableArray<EvaluationManifestEntry> Cases,
    string ManifestHash);

public static class EvaluationResultReducer
{
    public static EvaluationExportManifest Reduce(
        IEnumerable<EvaluationCaseResult> results,
        IEnumerable<string> expectedCaseIds)
    {
        ArgumentNullException.ThrowIfNull(results);
        ArgumentNullException.ThrowIfNull(expectedCaseIds);
        var values = results.ToArray();
        if (values.Length == 0) throw new ArgumentException("At least one result is required.", nameof(results));
        var expectedValues = expectedCaseIds.ToArray();
        var expected = expectedValues.ToHashSet(StringComparer.Ordinal);
        if (expected.Count == 0) throw new ArgumentException("Expected case set cannot be empty.", nameof(expectedCaseIds));
        if (expected.Count != expectedValues.Length)
            throw new ArgumentException("Expected case IDs must be unique.", nameof(expectedCaseIds));
        if (values.Any(x => !x.HasValidReceipt()))
            throw new ArgumentException("A result receipt hash is invalid.", nameof(results));
        var first = values[0];
        if (values.Any(x => x.HarnessVersion != first.HarnessVersion || x.Commit != first.Commit ||
                            x.DatasetHash != first.DatasetHash || x.ModelProfile != first.ModelProfile))
            throw new ArgumentException("Results with different immutable evaluation inputs cannot be reduced.", nameof(results));
        var actual = values.Select(x => x.CaseId).ToHashSet(StringComparer.Ordinal);
        if (!actual.SetEquals(expected))
            throw new ArgumentException("Result cases do not exactly match the expected selected case set.", nameof(results));
        if (values.GroupBy(x => (x.CaseId, x.AttemptGeneration))
            .Any(group => group.Select(x => x.ReceiptHash).Distinct(StringComparer.Ordinal).Count() > 1))
            throw new ArgumentException("Conflicting receipts exist for the same case generation.", nameof(results));

        var selected = values.GroupBy(x => x.CaseId, StringComparer.Ordinal)
            .Select(group => group.GroupBy(x => x.AttemptGeneration)
                .Select(generation => generation.First())
                .OrderByDescending(x => x.AttemptGeneration).First())
            .OrderBy(x => x.CaseId, StringComparer.Ordinal)
            .Select(x => new EvaluationManifestEntry(x.CaseId, x.AttemptGeneration, x.Status, x.Score,
                x.Metrics.ToImmutableSortedDictionary(y => y.Key, y => y.Value, StringComparer.Ordinal),
                x.ArtifactReferences.Order(StringComparer.Ordinal).ToImmutableArray(), x.FailureClassification, x.ReceiptHash))
            .ToImmutableArray();
        var hash = EvaluationHash.Sha256(EvaluationJson.Serialize(new
        {
            first.HarnessVersion, first.Commit, first.DatasetHash, first.ModelProfile, cases = selected
        }));
        return new(first.HarnessVersion, first.Commit, first.DatasetHash, first.ModelProfile, selected, hash);
    }
}
