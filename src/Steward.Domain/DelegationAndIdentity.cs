namespace Steward.Domain;

public sealed record AttemptGenerationRange
{
    public TaskId TaskId { get; }
    public int Minimum { get; }
    public int Maximum { get; }

    public AttemptGenerationRange(TaskId taskId, int minimum, int maximum)
    {
        if (minimum <= 0 || maximum < minimum)
            throw new ArgumentOutOfRangeException(nameof(minimum));
        TaskId = taskId;
        Minimum = minimum;
        Maximum = maximum;
    }

    public bool Contains(int generation) => generation >= Minimum && generation <= Maximum;
}

public sealed record RateLimit
{
    public string Scope { get; }
    public decimal MaximumAmount { get; }

    public RateLimit(string scope, decimal maximumAmount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        if (maximumAmount < 0)
            throw new ArgumentOutOfRangeException(nameof(maximumAmount));
        Scope = scope;
        MaximumAmount = maximumAmount;
    }
}

public sealed class IdentityGrant
{
    public IdentityGrantId Id { get; }
    public HostId HostId { get; }
    public NodeIncarnationId NodeIncarnationId { get; }
    public string Audience { get; }
    public IReadOnlySet<string> Scopes { get; }
    public DateTimeOffset ExpiresAt { get; }
    public int MaximumUses { get; }
    public IdentityRenewalMode RenewalMode { get; }
    public IdentityOfflineBehavior OfflineBehavior { get; }

    public IdentityGrant(
        IdentityGrantId id,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        string audience,
        IEnumerable<string> scopes,
        DateTimeOffset expiresAt,
        int maximumUses,
        IdentityRenewalMode renewalMode,
        IdentityOfflineBehavior offlineBehavior)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        var scopeSet = scopes.Where(x => !string.IsNullOrWhiteSpace(x)).ToHashSet(StringComparer.Ordinal);
        if (scopeSet.Count == 0)
            throw new ArgumentException("At least one scope is required.", nameof(scopes));
        if (maximumUses <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumUses));

        Id = id;
        HostId = hostId;
        NodeIncarnationId = nodeIncarnationId;
        Audience = audience;
        Scopes = scopeSet;
        ExpiresAt = expiresAt;
        MaximumUses = maximumUses;
        RenewalMode = renewalMode;
        OfflineBehavior = offlineBehavior;
    }

    public bool CanRenewWhileControlOffline =>
        RenewalMode == IdentityRenewalMode.Workload;

    public IdentityOfflineBehavior BehaviorAt(DateTimeOffset time) =>
        time < ExpiresAt ? IdentityOfflineBehavior.ContinueWithoutCapability : OfflineBehavior;
}

public sealed class Delegation
{
    private readonly IReadOnlyDictionary<TaskId, AttemptGenerationRange> _generationRanges;
    private readonly IReadOnlyDictionary<string, decimal> _rateLimits;
    private readonly HashSet<IdentityGrantId> _identityGrants;

    public DelegationId Id { get; }
    public HostId HostId { get; }
    public NodeIncarnationId NodeIncarnationId { get; }
    public PlanRevisionId PlanRevisionId { get; }
    public ResourceRequirements ResourceLimit { get; }
    public int ConcurrencyLimit { get; }
    public DateTimeOffset AcceptedAt { get; }
    public DateTimeOffset NoNewStartsAfter { get; }
    public DateTimeOffset DrainAt { get; }
    public DateTimeOffset AuthorityExpiresAt { get; }

    public Delegation(
        DelegationId id,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        PlanRevisionId planRevisionId,
        IEnumerable<AttemptGenerationRange> generationRanges,
        ResourceRequirements resourceLimit,
        int concurrencyLimit,
        IEnumerable<RateLimit> rateLimits,
        IEnumerable<IdentityGrantId> identityGrants,
        DateTimeOffset acceptedAt,
        DateTimeOffset noNewStartsAfter,
        DateTimeOffset drainAt,
        DateTimeOffset authorityExpiresAt)
    {
        var ranges = generationRanges.ToArray();
        if (ranges.Length == 0 || ranges.Select(x => x.TaskId).Distinct().Count() != ranges.Length)
            throw new ArgumentException("Delegation requires unique allowed Task generation ranges.", nameof(generationRanges));
        if (concurrencyLimit <= 0)
            throw new ArgumentOutOfRangeException(nameof(concurrencyLimit));
        if (!(acceptedAt <= noNewStartsAfter && noNewStartsAfter <= drainAt && drainAt <= authorityExpiresAt))
            throw new ArgumentException("Delegation times must be ordered.");

        var rates = rateLimits.ToArray();
        if (rates.Select(x => x.Scope).Distinct(StringComparer.Ordinal).Count() != rates.Length)
            throw new ArgumentException("Rate-limit scopes must be unique.", nameof(rateLimits));

        Id = id;
        HostId = hostId;
        NodeIncarnationId = nodeIncarnationId;
        PlanRevisionId = planRevisionId;
        _generationRanges = ranges.ToDictionary(x => x.TaskId);
        ResourceLimit = resourceLimit;
        ConcurrencyLimit = concurrencyLimit;
        _rateLimits = rates.ToDictionary(x => x.Scope, x => x.MaximumAmount, StringComparer.Ordinal);
        _identityGrants = identityGrants.ToHashSet();
        AcceptedAt = acceptedAt;
        NoNewStartsAfter = noNewStartsAfter;
        DrainAt = drainAt;
        AuthorityExpiresAt = authorityExpiresAt;
    }

    public void AuthorizeStart(
        TaskId taskId,
        int generation,
        ResourceRequirements resources,
        int currentConcurrency,
        IReadOnlyDictionary<string, decimal>? requestedRates,
        IEnumerable<IdentityGrantId>? requestedIdentityGrants,
        DateTimeOffset now)
    {
        Rule.Require(now >= AcceptedAt && now < NoNewStartsAfter, DomainErrorCode.DelegationExpired, "Delegation does not permit new starts at this time.");
        Rule.Require(now < AuthorityExpiresAt, DomainErrorCode.DelegationExpired, "Delegated authority has expired.");
        Rule.Require(_generationRanges.TryGetValue(taskId, out var range) && range.Contains(generation),
            DomainErrorCode.DelegationLimitExceeded, "Task or attempt generation is outside delegated authority.");
        Rule.Require(currentConcurrency >= 0 && currentConcurrency < ConcurrencyLimit,
            DomainErrorCode.DelegationLimitExceeded, "Delegation concurrency limit is exhausted.");
        Rule.Require(resources.FitsWithin(ResourceLimit), DomainErrorCode.DelegationLimitExceeded, "Requested resources exceed the delegation envelope.");

        foreach (var rate in requestedRates ?? new Dictionary<string, decimal>())
            Rule.Require(rate.Value >= 0 && _rateLimits.TryGetValue(rate.Key, out var maximum) && rate.Value <= maximum,
                DomainErrorCode.DelegationLimitExceeded, $"Rate request '{rate.Key}' exceeds delegated authority.");
        foreach (var grant in requestedIdentityGrants ?? [])
            Rule.Require(_identityGrants.Contains(grant), DomainErrorCode.DelegationLimitExceeded, "Identity grant is not included in the delegation.");
    }

    public bool MustDrain(DateTimeOffset now) => now >= DrainAt;
    public bool HasAuthority(DateTimeOffset now) => now >= AcceptedAt && now < AuthorityExpiresAt;
}
