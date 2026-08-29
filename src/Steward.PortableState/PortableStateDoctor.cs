namespace Steward.PortableState;

public sealed record PortableStateDeploymentSettings(
    bool ImmutableCreateEnabled,
    bool AtomicCommitEnabled,
    TimeSpan? RecoveryRetention);

public interface IPortableStateDeploymentInspector
{
    Task<PortableStateDeploymentSettings> InspectAsync(CancellationToken cancellationToken = default);
}

public sealed record DoctorFinding(string Code, bool Passed, string Detail);

public sealed class PortableStateDoctor
{
    private readonly IPortableStateDeploymentInspector _inspector;

    public PortableStateDoctor(IPortableStateDeploymentInspector inspector) =>
        _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));

    public async Task<IReadOnlyList<DoctorFinding>> CheckAsync(CancellationToken cancellationToken = default)
    {
        var settings = await _inspector.InspectAsync(cancellationToken).ConfigureAwait(false);
        return
        [
            new(
                "portable-state-immutable-create",
                settings.ImmutableCreateEnabled,
                settings.ImmutableCreateEnabled
                    ? "Immutable create is enabled."
                    : "Immutable create is a portable-state deployment prerequisite."),
            new(
                "portable-state-atomic-commit",
                settings.AtomicCommitEnabled,
                settings.AtomicCommitEnabled
                    ? $"Atomic commit is enabled (recovery retention: {settings.RecoveryRetention})."
                    : "Atomic commit is a portable-state deployment prerequisite.")
        ];
    }
}
