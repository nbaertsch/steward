using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Steward.Maintenance.Windows;

internal sealed record EndpointSqliteCounterSnapshot(
    string Column,
    long Maximum);

internal sealed record EndpointSqliteTableSnapshot(
    string Name,
    long RowCount,
    string LogicalSha256,
    IReadOnlyList<EndpointSqliteCounterSnapshot> Counters);

internal sealed record EndpointSqliteSnapshot(
    string BackupPath,
    bool IntegrityVerified,
    IReadOnlyList<EndpointSqliteTableSnapshot> Tables);

internal static class EndpointSqlitePreservation
{
    internal static EndpointSqliteSnapshot Capture(
        string sourcePath,
        string backupPath)
    {
        EndpointUpdateFileValidator.EnsureRegularFile(sourcePath);
        var destination = Path.GetFullPath(backupPath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination) ??
            throw new InvalidDataException(
                "SQLite preservation backup has no parent."));
        EndpointUpdateFileValidator.EnsureRegularFileIfPresent(destination);
        if (File.Exists(destination))
            File.Delete(destination);
        try
        {
            using var source = Open(sourcePath, SqliteOpenMode.ReadOnly);
            using var backup = Open(destination, SqliteOpenMode.ReadWriteCreate);
            source.BackupDatabase(backup);
            using var checkpoint = backup.CreateCommand();
            checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            checkpoint.ExecuteNonQuery();
        }
        catch (SqliteException exception)
        {
            throw new EndpointUpdateException(
                "sqlite_backup_failed",
                $"SQLite preservation backup failed: {exception.SqliteErrorCode}.");
        }
        EndpointUpdateFileValidator.EnsureRegularFile(destination);
        return Analyze(destination, destination);
    }

    internal static void AssertNondecreasing(
        EndpointSqliteSnapshot prior,
        string currentPath)
    {
        ArgumentNullException.ThrowIfNull(prior);
        var current = Analyze(currentPath, prior.BackupPath);
        foreach (var priorTable in prior.Tables)
        {
            var currentTable = current.Tables.SingleOrDefault(value =>
                string.Equals(value.Name, priorTable.Name,
                    StringComparison.Ordinal));
            if (currentTable is null ||
                currentTable.RowCount < priorTable.RowCount)
                throw PreservationFailure();
            foreach (var priorCounter in priorTable.Counters)
            {
                var currentCounter = currentTable.Counters.SingleOrDefault(
                    value => string.Equals(
                        value.Column,
                        priorCounter.Column,
                        StringComparison.Ordinal));
                if (currentCounter is null ||
                    currentCounter.Maximum < priorCounter.Maximum)
                    throw PreservationFailure();
            }
            if (currentTable.RowCount == priorTable.RowCount &&
                currentTable.Counters.SequenceEqual(priorTable.Counters) &&
                !FixedHashEquals(
                    currentTable.LogicalSha256,
                    priorTable.LogicalSha256))
                throw PreservationFailure();
        }
    }

    private static EndpointSqliteSnapshot Analyze(
        string path,
        string backupPath)
    {
        EndpointUpdateFileValidator.EnsureRegularFile(path);
        try
        {
            using var connection = Open(path, SqliteOpenMode.ReadOnly);
            using var transaction = connection.BeginTransaction();
            using (var integrity = connection.CreateCommand())
            {
                integrity.Transaction = transaction;
                integrity.CommandText = "PRAGMA integrity_check;";
                var result = Convert.ToString(
                    integrity.ExecuteScalar(),
                    CultureInfo.InvariantCulture);
                if (!string.Equals(result, "ok", StringComparison.Ordinal))
                    throw new EndpointUpdateException(
                        "sqlite_integrity_failed",
                        "Preserved SQLite state failed integrity verification.");
            }
            var tables = new List<EndpointSqliteTableSnapshot>();
            using var list = connection.CreateCommand();
            list.Transaction = transaction;
            list.CommandText = """
                SELECT name,sql
                FROM sqlite_schema
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """;
            using var reader = list.ExecuteReader();
            var schema = new List<(string Name, string Sql)>();
            while (reader.Read())
                schema.Add((reader.GetString(0), reader.GetString(1)));
            reader.Close();
            foreach (var table in schema)
                tables.Add(AnalyzeTable(
                    connection,
                    transaction,
                    table.Name,
                    table.Sql));
            transaction.Commit();
            return new EndpointSqliteSnapshot(
                backupPath,
                true,
                tables);
        }
        catch (EndpointUpdateException)
        {
            throw;
        }
        catch (SqliteException exception)
        {
            throw new EndpointUpdateException(
                "sqlite_integrity_failed",
                $"Preserved SQLite state is unavailable: {exception.SqliteErrorCode}.");
        }
    }

    private static EndpointSqliteTableSnapshot AnalyzeTable(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string table,
        string schema)
    {
        var columns = new List<(string Name, string Type)>();
        using (var info = connection.CreateCommand())
        {
            info.Transaction = transaction;
            info.CommandText = $"PRAGMA table_info({Quote(table)});";
            using var reader = info.ExecuteReader();
            while (reader.Read())
                columns.Add((reader.GetString(1), reader.GetString(2)));
        }
        using var count = connection.CreateCommand();
        count.Transaction = transaction;
        count.CommandText = $"SELECT COUNT(*) FROM {Quote(table)};";
        var rows = Convert.ToInt64(
            count.ExecuteScalar(),
            CultureInfo.InvariantCulture);
        var counters = columns
            .Where(column => IsCounter(column.Name, column.Type))
            .Select(column => new EndpointSqliteCounterSnapshot(
                column.Name,
                ReadMaximum(connection, transaction, table, column.Name)))
            .ToArray();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, table);
        Append(hash, schema);
        foreach (var column in columns)
        {
            Append(hash, column.Name);
            Append(hash, column.Type);
        }
        if (columns.Count > 0)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            var order = string.Join(",", columns.Select(value =>
                Quote(value.Name)));
            command.CommandText =
                $"SELECT * FROM {Quote(table)} ORDER BY {order};";
            using var reader = command.ExecuteReader();
            while (reader.Read())
                for (var index = 0; index < reader.FieldCount; index++)
                    AppendValue(hash, reader, index);
        }
        return new EndpointSqliteTableSnapshot(
            table,
            rows,
            Convert.ToHexString(hash.GetHashAndReset()),
            counters);
    }

    private static long ReadMaximum(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string table,
        string column)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"SELECT COALESCE(MAX({Quote(column)}),0) FROM {Quote(table)};";
        var value = Convert.ToInt64(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
        if (value < 0)
            throw new EndpointUpdateException(
                "sqlite_counter_invalid",
                "Preserved SQLite monotonic counter is negative.");
        return value;
    }

    private static bool IsCounter(string name, string type)
    {
        if (!type.Contains("INT", StringComparison.OrdinalIgnoreCase))
            return false;
        return new[]
        {
            "cursor", "sequence", "generation", "revision", "index",
            "version", "count"
        }.Any(part => name.Contains(part, StringComparison.OrdinalIgnoreCase));
    }

    private static SqliteConnection Open(
        string path,
        SqliteOpenMode mode)
    {
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = Path.GetFullPath(path),
                Mode = mode,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
                DefaultTimeout = 30
            }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA busy_timeout=30000;";
        command.ExecuteNonQuery();
        return connection;
    }

    private static string Quote(string identifier) =>
        "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) +
        "\"";

    private static void Append(
        IncrementalHash hash,
        string value) =>
        Append(hash, Encoding.UTF8.GetBytes(value));

    private static void Append(
        IncrementalHash hash,
        ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static void AppendValue(
        IncrementalHash hash,
        SqliteDataReader reader,
        int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            Append(hash, "null");
            return;
        }
        var value = reader.GetValue(ordinal);
        switch (value)
        {
            case long integer:
                Append(hash, "integer");
                Span<byte> integerBytes = stackalloc byte[sizeof(long)];
                BinaryPrimitives.WriteInt64LittleEndian(
                    integerBytes,
                    integer);
                Append(hash, integerBytes);
                break;
            case double real:
                Append(hash, "real");
                Span<byte> realBytes = stackalloc byte[sizeof(long)];
                BinaryPrimitives.WriteInt64LittleEndian(
                    realBytes,
                    BitConverter.DoubleToInt64Bits(real));
                Append(hash, realBytes);
                break;
            case byte[] blob:
                Append(hash, "blob");
                Append(hash, blob);
                break;
            default:
                Append(hash, "text");
                Append(hash, Convert.ToString(
                    value,
                    CultureInfo.InvariantCulture) ?? string.Empty);
                break;
        }
    }

    private static bool FixedHashEquals(string left, string right)
    {
        var first = Convert.FromHexString(left);
        var second = Convert.FromHexString(right);
        try
        {
            return CryptographicOperations.FixedTimeEquals(first, second);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }

    private static EndpointUpdateException PreservationFailure() =>
        new(
            "sqlite_preservation_failed",
            "Preserved SQLite journals or counters moved backward.");
}
