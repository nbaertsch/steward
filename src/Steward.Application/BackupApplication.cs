using Steward.Persistence.Sqlite;

namespace Steward.Application;

public sealed record ExportBackupRequest(string DestinationDirectory);
public sealed record ValidateBackupRequest(string DatabasePath, string ManifestPath);
public sealed record RestoreBackupRequest(
    string DatabasePath,
    string ManifestPath,
    string DestinationPath);

public sealed class BackupApplicationService(SqliteControlStore store)
{
    public Task<BackupExport> ExportAsync(
        ExportBackupRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new SqliteBackupService(store).ExportAsync(
            FullPath(request.DestinationDirectory, nameof(request.DestinationDirectory)),
            cancellationToken);
    }

    public Task<BackupManifest> ValidateAsync(
        ValidateBackupRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return SqliteBackupService.ValidateAsync(
            FullPath(request.DatabasePath, nameof(request.DatabasePath)),
            FullPath(request.ManifestPath, nameof(request.ManifestPath)),
            cancellationToken);
    }

    public Task RestoreAsync(
        RestoreBackupRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var destination = FullPath(request.DestinationPath, nameof(request.DestinationPath));
        if (string.Equals(destination, Path.GetFullPath(store.DatabasePath),
                StringComparison.OrdinalIgnoreCase))
            throw new ApplicationContractException(
                "InvalidArgument",
                "Restore cannot target the live Control database.");
        return SqliteBackupService.RestoreAsync(
            FullPath(request.DatabasePath, nameof(request.DatabasePath)),
            FullPath(request.ManifestPath, nameof(request.ManifestPath)),
            destination,
            cancellationToken);
    }

    private static string FullPath(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 32_767 ||
            value.IndexOf('\0') >= 0 ||
            !Path.IsPathFullyQualified(value))
            throw new ApplicationContractException(
                "InvalidArgument", $"{name} must be a bounded absolute local path.");
        return Path.GetFullPath(value);
    }
}
