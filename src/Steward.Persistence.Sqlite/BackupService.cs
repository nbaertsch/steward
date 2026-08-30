using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;

namespace Steward.Persistence.Sqlite;

public sealed class SqliteBackupService(SqliteControlStore store)
{
    public async Task<BackupExport> ExportAsync(
        string destinationDirectory, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationDirectory);
        var directory = Path.GetFullPath(destinationDirectory);
        Directory.CreateDirectory(directory);
        var stamp = DateTimeOffset.UtcNow;
        var baseName = $"steward-{stamp:yyyyMMddTHHmmssfffZ}";
        var databasePath = Path.Combine(directory, $"{baseName}.db");
        var manifestPath = Path.Combine(directory, $"{baseName}.manifest.json");
        if (File.Exists(databasePath) || File.Exists(manifestPath))
            throw new IOException("Backup destination already exists.");

        await using (var source = await store.OpenConnectionAsync(cancellationToken))
        await using (var destination = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        }.ToString()))
        {
            await destination.OpenAsync(cancellationToken);
            source.BackupDatabase(destination);
        }

        var objects = await ReadPortableObjectsAsync(databasePath, cancellationToken);
        var manifest = new BackupManifest(
            1,
            await store.GetSchemaVersionAsync(cancellationToken),
            stamp,
            Path.GetFileName(databasePath),
            await ComputeSha256Async(databasePath, cancellationToken),
            objects);
        await File.WriteAllTextAsync(manifestPath,
            JsonSerializer.Serialize(manifest, StewardJson.Options), cancellationToken);
        return new(databasePath, manifestPath, manifest);
    }

    public static async Task<BackupManifest> ValidateAsync(
        string databasePath, string manifestPath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(databasePath) || !File.Exists(manifestPath))
            throw InvalidBackup("The backup database and manifest must both exist.");

        BackupManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<BackupManifest>(
                await File.ReadAllTextAsync(manifestPath, cancellationToken), StewardJson.Options)
                ?? throw InvalidBackup("Backup manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw InvalidBackup("Backup manifest is invalid JSON.", exception);
        }

        if (manifest.ManifestVersion != 1)
            throw InvalidBackup($"Unsupported backup manifest version {manifest.ManifestVersion}.");
        if (!string.Equals(Path.GetFileName(databasePath), manifest.DatabaseFile, StringComparison.Ordinal))
            throw InvalidBackup("Backup database filename does not match the manifest.");
        var hash = await ComputeSha256Async(databasePath, cancellationToken);
        if (!string.Equals(hash, manifest.DatabaseSha256, StringComparison.OrdinalIgnoreCase))
            throw InvalidBackup("Backup database SHA-256 does not match the manifest.");
        if (manifest.SchemaVersion != SchemaMigrator.CurrentVersion)
            throw InvalidBackup($"Backup schema version {manifest.SchemaVersion} is unsupported.");

        try
        {
            var connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = Path.GetFullPath(databasePath),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false
            }.ToString();
            await using var connection = new SqliteConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            var command = connection.CreateCommand();
            command.CommandText = """
                SELECT schema_version FROM schema_metadata WHERE singleton=1;
                """;
            var version = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
            if (version != manifest.SchemaVersion)
                throw InvalidBackup("Database schema version does not match the manifest.");
            command.CommandText = "PRAGMA integrity_check;";
            var integrity = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken));
            if (!string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase))
                throw InvalidBackup($"SQLite integrity check failed: {integrity}.");
        }
        catch (SqliteException exception)
        {
            throw InvalidBackup("Backup database is not a valid readable Steward SQLite store.", exception);
        }
        return manifest;
    }

    public static async Task RestoreAsync(
        string databasePath,
        string manifestPath,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        await ValidateAsync(databasePath, manifestPath, cancellationToken);
        var destination = Path.GetFullPath(destinationPath);
        if (File.Exists(destination))
            throw new IOException("Restore destination already exists; a live store is never overwritten.");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        await using var source = new FileStream(databasePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        await using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await source.CopyToAsync(target, cancellationToken);
        await target.FlushAsync(cancellationToken);
    }

    private static async Task<IReadOnlyList<PortableObjectReference>> ReadPortableObjectsAsync(
        string databasePath, CancellationToken cancellationToken)
    {
        var result = new List<PortableObjectReference>();
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false
        }.ToString();
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = """
            SELECT portable_object_id,content_hash,size_bytes,store_receipt
            FROM portable_objects WHERE complete=1 ORDER BY portable_object_id;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(new(PortableObjectId.Parse(reader.GetString(0)), reader.GetString(1), reader.GetInt64(2),
                reader.IsDBNull(3) ? null : reader.GetString(3)));
        return result;
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
    }

    private static PersistenceException InvalidBackup(string message, Exception? inner = null) =>
        new(PersistenceErrorCode.InvalidBackup, message, inner);
}
