using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Tasks.Abstractions;

namespace Steward.Orchestration;

[SupportedOSPlatform("windows")]
public sealed class LocalIdentityGrantStore
{
    public const string SchemaVersion = "1.1";
    private readonly string connectionString;

    public LocalIdentityGrantStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        if (!Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException("The Local identity database path must be absolute.", nameof(databasePath));
        DatabasePath = Path.GetFullPath(databasePath);
        var directory = Path.GetDirectoryName(DatabasePath)
            ?? throw new ArgumentException("The Local identity database has no parent directory.", nameof(databasePath));
        LocalIdentityStorageSecurity.PrepareDirectory(directory);
        if (File.Exists(DatabasePath) &&
            !LocalIdentityStorageSecurity.IsSafeRegularFile(DatabasePath))
            throw new IOException("The Local identity database cannot be a reparse point.");
        if (File.Exists(DatabasePath))
            LocalIdentityStorageSecurity.RestrictFile(DatabasePath);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = false
        }.ToString();
        Initialize();
        LocalIdentityStorageSecurity.RestrictFile(DatabasePath);
    }

    public string DatabasePath { get; }

    internal void Register(
        LocalControlIdentityGrantRegistration registration,
        ProtectedIdentityHandle handle,
        DateTimeOffset now)
    {
        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO local_identity_grants(
                grant_id, workload_id, task_id, generation, host_id, node_incarnation_id,
                provider, audience, scopes_json, expires_at, maximum_uses, renewal_mode,
                offline_behavior, handle_id, handle_provider, handle_expires_at,
                revoked, created_at, revoked_at)
            VALUES(
                $grant_id, $workload_id, $task_id, $generation, $host_id, $node_incarnation_id,
                $provider, $audience, $scopes_json, $expires_at, $maximum_uses, $renewal_mode,
                $offline_behavior, $handle_id, $handle_provider, $handle_expires_at,
                0, $created_at, NULL);
            """;
        AddRegistration(command, registration);
        command.Parameters.AddWithValue("$handle_id", handle.HandleId.ToString("D"));
        command.Parameters.AddWithValue("$handle_provider", handle.Provider);
        command.Parameters.AddWithValue("$handle_expires_at", Format(handle.ExpiresAt));
        command.Parameters.AddWithValue("$created_at", Format(now));
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    internal TaskIdentityGrantReference? ResolveOrReserve(
        IdentityGrantId grantId,
        WorkloadId workloadId,
        TaskId taskId,
        int generation,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        DateTimeOffset now)
    {
        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var grant = ReadGrant(connection, transaction, grantId);
        if (grant is null ||
            grant.Revoked ||
            grant.Registration.ExpiresAt <= now ||
            grant.Registration.WorkloadId != workloadId ||
            grant.Registration.TaskId != taskId ||
            grant.Registration.Generation != generation ||
            grant.Registration.HostId != hostId ||
            grant.Registration.NodeIncarnationId != nodeIncarnationId)
        {
            transaction.Commit();
            return null;
        }

        var use = ReadAvailableUse(
            connection, transaction, grantId, workloadId, taskId, generation, hostId, nodeIncarnationId);
        if (use is null)
        {
            using var count = connection.CreateCommand();
            count.Transaction = transaction;
            count.CommandText = """
                SELECT COUNT(*)
                FROM local_identity_uses
                WHERE grant_id = $grant_id;
                """;
            count.Parameters.AddWithValue("$grant_id", grantId.ToString());
            if (Convert.ToInt32(count.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) >=
                grant.Registration.MaximumUses)
            {
                transaction.Commit();
                return null;
            }

            use = new(Guid.NewGuid(), false);
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO local_identity_uses(
                    grant_id, workload_id, task_id, generation, host_id, node_incarnation_id,
                    use_id, consumed, reserved_at, consumed_at, plan_revision_id,
                    attempt_id, delegation_id, command_id)
                VALUES(
                    $grant_id, $workload_id, $task_id, $generation, $host_id, $node_incarnation_id,
                    $use_id, 0, $reserved_at, NULL, NULL, NULL, NULL, NULL);
                """;
            AddBinding(insert, grantId, workloadId, taskId, generation, hostId, nodeIncarnationId);
            insert.Parameters.AddWithValue("$use_id", use.UseId.ToString("D"));
            insert.Parameters.AddWithValue("$reserved_at", Format(now));
            insert.ExecuteNonQuery();
        }
        transaction.Commit();
        return LocalIdentityGrantBinding.Reference(grant, use.UseId);
    }

    internal StoredLocalIdentityGrant Consume(
        DirectIdentityDeliveryRequest request,
        DateTimeOffset now)
    {
        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var grant = ReadGrant(connection, transaction, request.Grant.IdentityGrantId);
        if (grant is null || grant.Revoked)
            throw Failure("identity.revoked", "Task identity grant is unavailable or revoked.");
        if (grant.Registration.ExpiresAt <= now)
            throw Failure("identity.expired", "Task identity grant has expired.");
        var expected = LocalIdentityGrantBinding.Reference(grant, request.Grant.UseId);
        if (!LocalIdentityGrantBinding.ExactlyMatches(request, expected))
            throw Failure(
                "identity.binding-invalid",
                "Task identity delivery is not bound to this exact execution.");

        var use = ReadUse(
            connection,
            transaction,
            request.Grant.IdentityGrantId,
            request.Identity.WorkloadId,
            request.Identity.TaskId,
            request.Identity.Generation,
            request.Identity.HostId,
            request.Identity.NodeIncarnationId,
            request.Grant.UseId);
        if (use is null || use.Consumed)
            throw Failure("identity.use-invalid", "Task identity grant use is unavailable.");

        using var consume = connection.CreateCommand();
        consume.Transaction = transaction;
        consume.CommandText = """
            UPDATE local_identity_uses
            SET consumed = 1,
                consumed_at = $consumed_at,
                plan_revision_id = $plan_revision_id,
                attempt_id = $attempt_id,
                delegation_id = $delegation_id,
                command_id = $command_id
            WHERE grant_id = $grant_id
              AND workload_id = $workload_id
              AND task_id = $task_id
              AND generation = $generation
              AND host_id = $host_id
              AND node_incarnation_id = $node_incarnation_id
              AND use_id = $use_id
              AND consumed = 0;
            """;
        AddBinding(
            consume,
            request.Grant.IdentityGrantId,
            request.Identity.WorkloadId,
            request.Identity.TaskId,
            request.Identity.Generation,
            request.Identity.HostId,
            request.Identity.NodeIncarnationId);
        consume.Parameters.AddWithValue("$use_id", request.Grant.UseId.ToString("D"));
        consume.Parameters.AddWithValue("$consumed_at", Format(now));
        consume.Parameters.AddWithValue("$plan_revision_id", request.Identity.PlanRevisionId.ToString());
        consume.Parameters.AddWithValue("$attempt_id", request.Identity.AttemptId.ToString());
        consume.Parameters.AddWithValue("$delegation_id", request.Identity.DelegationId.ToString());
        consume.Parameters.AddWithValue("$command_id", request.Identity.CommandId.ToString());
        if (consume.ExecuteNonQuery() != 1)
            throw Failure("identity.use-invalid", "Task identity grant use is unavailable.");
        transaction.Commit();
        return grant;
    }

    internal ProtectedIdentityHandle? Revoke(IdentityGrantId grantId, DateTimeOffset now)
    {
        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction(deferred: false);
        var grant = ReadGrant(connection, transaction, grantId);
        if (grant is null || grant.Revoked)
        {
            transaction.Commit();
            return null;
        }
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE local_identity_grants
            SET revoked = 1, revoked_at = $revoked_at
            WHERE grant_id = $grant_id AND revoked = 0;
            """;
        command.Parameters.AddWithValue("$grant_id", grantId.ToString());
        command.Parameters.AddWithValue("$revoked_at", Format(now));
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("Identity grant revocation was not atomic.");
        transaction.Commit();
        return grant.Handle;
    }

    internal IReadOnlyList<ProtectedIdentityHandle> ReadInactiveHandles(DateTimeOffset now)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT handle_id, handle_provider, handle_expires_at
            FROM local_identity_grants
            WHERE revoked = 1 OR handle_expires_at <= $now;
            """;
        command.Parameters.AddWithValue("$now", Format(now));
        using var reader = command.ExecuteReader();
        var handles = new List<ProtectedIdentityHandle>();
        while (reader.Read())
            handles.Add(ReadHandle(reader));
        return handles;
    }

    private void Initialize()
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using (var journal = connection.CreateCommand())
        {
            journal.CommandText = "PRAGMA journal_mode=WAL;";
            if (!string.Equals(
                    Convert.ToString(journal.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture),
                    "wal",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Local identity SQLite store requires WAL mode.");
        }
        Configure(connection);
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS local_identity_schema(
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                schema_version TEXT NOT NULL
            );
            INSERT OR IGNORE INTO local_identity_schema(singleton, schema_version)
            VALUES(1, '1.1');

            CREATE TABLE IF NOT EXISTS local_identity_grants(
                grant_id TEXT PRIMARY KEY,
                workload_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                host_id TEXT NOT NULL,
                node_incarnation_id TEXT NOT NULL,
                provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 256),
                audience TEXT NOT NULL CHECK(length(audience) BETWEEN 1 AND 4096),
                scopes_json TEXT NOT NULL CHECK(length(scopes_json) BETWEEN 2 AND 65536),
                expires_at TEXT NOT NULL,
                maximum_uses INTEGER NOT NULL CHECK(maximum_uses > 0),
                renewal_mode INTEGER NOT NULL,
                offline_behavior INTEGER NOT NULL,
                handle_id TEXT NOT NULL UNIQUE,
                handle_provider TEXT NOT NULL CHECK(length(handle_provider) BETWEEN 1 AND 256),
                handle_expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
                created_at TEXT NOT NULL,
                revoked_at TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS local_identity_uses(
                grant_id TEXT NOT NULL,
                workload_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                host_id TEXT NOT NULL,
                node_incarnation_id TEXT NOT NULL,
                use_id TEXT NOT NULL UNIQUE,
                consumed INTEGER NOT NULL CHECK(consumed IN (0, 1)),
                reserved_at TEXT NOT NULL,
                consumed_at TEXT NULL,
                plan_revision_id TEXT NULL,
                attempt_id TEXT NULL,
                delegation_id TEXT NULL,
                command_id TEXT NULL,
                PRIMARY KEY(grant_id, use_id),
                FOREIGN KEY(grant_id) REFERENCES local_identity_grants(grant_id)
                    ON DELETE RESTRICT
            );

            CREATE INDEX IF NOT EXISTS ix_local_identity_uses_grant
            ON local_identity_uses(grant_id);
            CREATE INDEX IF NOT EXISTS ix_local_identity_uses_binding
            ON local_identity_uses(
                grant_id, workload_id, task_id, generation, host_id,
                node_incarnation_id, consumed, reserved_at);
            PRAGMA user_version=2;
            """;
        command.ExecuteNonQuery();
        Migrate(connection);
        using var version = connection.CreateCommand();
        version.CommandText = "SELECT schema_version FROM local_identity_schema WHERE singleton = 1;";
        if (!string.Equals(Convert.ToString(version.ExecuteScalar()), SchemaVersion, StringComparison.Ordinal))
            throw new InvalidOperationException("Unsupported Local identity store schema version.");
    }

    private SqliteConnection OpenConnection()
    {
        var directory = Path.GetDirectoryName(DatabasePath)!;
        LocalIdentityStorageSecurity.EnsureSafeDirectory(directory);
        if (File.Exists(DatabasePath) &&
            !LocalIdentityStorageSecurity.IsSafeRegularFile(DatabasePath))
            throw new IOException("The Local identity database cannot be a reparse point.");
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        Configure(connection);
        return connection;
    }

    private static void Configure(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA foreign_keys=ON;
            PRAGMA synchronous=FULL;
            PRAGMA busy_timeout=5000;
            """;
        command.ExecuteNonQuery();
    }

    private static StoredLocalIdentityGrant? ReadGrant(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IdentityGrantId grantId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT grant_id, workload_id, task_id, generation, host_id, node_incarnation_id,
                   provider, audience, scopes_json, expires_at, maximum_uses, renewal_mode,
                   offline_behavior, handle_id, handle_provider, handle_expires_at, revoked
            FROM local_identity_grants
            WHERE grant_id = $grant_id;
            """;
        command.Parameters.AddWithValue("$grant_id", grantId.ToString());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return null;
        var scopes = JsonSerializer.Deserialize<string[]>(reader.GetString(8), StewardJson.Options)
            ?? throw new InvalidDataException("Persisted Local identity scopes are invalid.");
        var registration = new LocalControlIdentityGrantRegistration(
            IdentityGrantId.Parse(reader.GetString(0)),
            WorkloadId.Parse(reader.GetString(1)),
            TaskId.Parse(reader.GetString(2)),
            reader.GetInt32(3),
            HostId.Parse(reader.GetString(4)),
            NodeIncarnationId.Parse(reader.GetString(5)),
            reader.GetString(6),
            reader.GetString(7),
            scopes,
            ParseTime(reader.GetString(9)),
            reader.GetInt32(10),
            (IdentityRenewalMode)reader.GetInt32(11),
            (IdentityOfflineBehavior)reader.GetInt32(12)).Validate();
        var handle = new ProtectedIdentityHandle(
            Guid.ParseExact(reader.GetString(13), "D"),
            reader.GetString(14),
            ParseTime(reader.GetString(15)));
        if (!string.Equals(handle.Provider, registration.Provider, StringComparison.Ordinal) ||
            handle.ExpiresAt != registration.ExpiresAt)
            throw new InvalidDataException("Persisted Local identity handle binding is invalid.");
        return new(registration, handle, reader.GetInt32(16) != 0);
    }

    private static StoredUse? ReadAvailableUse(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IdentityGrantId grantId,
        WorkloadId workloadId,
        TaskId taskId,
        int generation,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT use_id, consumed
            FROM local_identity_uses
            WHERE grant_id = $grant_id
              AND workload_id = $workload_id
              AND task_id = $task_id
              AND generation = $generation
              AND host_id = $host_id
              AND node_incarnation_id = $node_incarnation_id
              AND consumed = 0
            ORDER BY reserved_at DESC
            LIMIT 1;
            """;
        AddBinding(command, grantId, workloadId, taskId, generation, hostId, nodeIncarnationId);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new(Guid.ParseExact(reader.GetString(0), "D"), reader.GetInt32(1) != 0)
            : null;
    }

    private static StoredUse? ReadUse(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IdentityGrantId grantId,
        WorkloadId workloadId,
        TaskId taskId,
        int generation,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        Guid useId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT use_id, consumed
            FROM local_identity_uses
            WHERE grant_id = $grant_id
              AND workload_id = $workload_id
              AND task_id = $task_id
              AND generation = $generation
              AND host_id = $host_id
              AND node_incarnation_id = $node_incarnation_id
              AND use_id = $use_id;
            """;
        AddBinding(
            command,
            grantId,
            workloadId,
            taskId,
            generation,
            hostId,
            nodeIncarnationId);
        command.Parameters.AddWithValue("$use_id", useId.ToString("D"));
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new(
                Guid.ParseExact(reader.GetString(0), "D"),
                reader.GetInt32(1) != 0)
            : null;
    }

    private static void Migrate(SqliteConnection connection)
    {
        using var read = connection.CreateCommand();
        read.CommandText = """
            SELECT schema_version
            FROM local_identity_schema
            WHERE singleton = 1;
            """;
        var version = Convert.ToString(
            read.ExecuteScalar(),
            System.Globalization.CultureInfo.InvariantCulture);
        if (string.Equals(version, SchemaVersion, StringComparison.Ordinal))
            return;
        if (!string.Equals(version, "1.0", StringComparison.Ordinal))
            throw new InvalidOperationException(
                "Unsupported Local identity store schema version.");

        using var transaction = connection.BeginTransaction(deferred: false);
        using var migrate = connection.CreateCommand();
        migrate.Transaction = transaction;
        migrate.CommandText = """
            CREATE TABLE local_identity_uses_v11(
                grant_id TEXT NOT NULL,
                workload_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                host_id TEXT NOT NULL,
                node_incarnation_id TEXT NOT NULL,
                use_id TEXT NOT NULL UNIQUE,
                consumed INTEGER NOT NULL CHECK(consumed IN (0, 1)),
                reserved_at TEXT NOT NULL,
                consumed_at TEXT NULL,
                plan_revision_id TEXT NULL,
                attempt_id TEXT NULL,
                delegation_id TEXT NULL,
                command_id TEXT NULL,
                PRIMARY KEY(grant_id, use_id),
                FOREIGN KEY(grant_id) REFERENCES local_identity_grants(grant_id)
                    ON DELETE RESTRICT
            );
            INSERT INTO local_identity_uses_v11(
                grant_id, workload_id, task_id, generation, host_id,
                node_incarnation_id, use_id, consumed, reserved_at,
                consumed_at, plan_revision_id, attempt_id, delegation_id,
                command_id)
            SELECT
                grant_id, workload_id, task_id, generation, host_id,
                node_incarnation_id, use_id, consumed, reserved_at,
                consumed_at, plan_revision_id, attempt_id, delegation_id,
                command_id
            FROM local_identity_uses;
            DROP TABLE local_identity_uses;
            ALTER TABLE local_identity_uses_v11
                RENAME TO local_identity_uses;
            CREATE INDEX ix_local_identity_uses_grant
            ON local_identity_uses(grant_id);
            CREATE INDEX ix_local_identity_uses_binding
            ON local_identity_uses(
                grant_id, workload_id, task_id, generation, host_id,
                node_incarnation_id, consumed, reserved_at);
            UPDATE local_identity_schema
            SET schema_version = '1.1'
            WHERE singleton = 1;
            PRAGMA user_version=2;
            """;
        migrate.ExecuteNonQuery();
        transaction.Commit();
    }

    private static ProtectedIdentityHandle ReadHandle(SqliteDataReader reader) => new(
        Guid.ParseExact(reader.GetString(0), "D"),
        reader.GetString(1),
        ParseTime(reader.GetString(2)));

    private static void AddRegistration(
        SqliteCommand command,
        LocalControlIdentityGrantRegistration registration)
    {
        command.Parameters.AddWithValue("$grant_id", registration.IdentityGrantId.ToString());
        command.Parameters.AddWithValue("$workload_id", registration.WorkloadId.ToString());
        command.Parameters.AddWithValue("$task_id", registration.TaskId.ToString());
        command.Parameters.AddWithValue("$generation", registration.Generation);
        command.Parameters.AddWithValue("$host_id", registration.HostId.ToString());
        command.Parameters.AddWithValue("$node_incarnation_id", registration.NodeIncarnationId.ToString());
        command.Parameters.AddWithValue("$provider", registration.Provider);
        command.Parameters.AddWithValue("$audience", registration.Audience);
        command.Parameters.AddWithValue(
            "$scopes_json",
            JsonSerializer.Serialize(registration.Scopes, StewardJson.Options));
        command.Parameters.AddWithValue("$expires_at", Format(registration.ExpiresAt));
        command.Parameters.AddWithValue("$maximum_uses", registration.MaximumUses);
        command.Parameters.AddWithValue("$renewal_mode", (int)registration.RenewalMode);
        command.Parameters.AddWithValue("$offline_behavior", (int)registration.OfflineBehavior);
    }

    private static void AddBinding(
        SqliteCommand command,
        IdentityGrantId grantId,
        WorkloadId workloadId,
        TaskId taskId,
        int generation,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId)
    {
        command.Parameters.AddWithValue("$grant_id", grantId.ToString());
        command.Parameters.AddWithValue("$workload_id", workloadId.ToString());
        command.Parameters.AddWithValue("$task_id", taskId.ToString());
        command.Parameters.AddWithValue("$generation", generation);
        command.Parameters.AddWithValue("$host_id", hostId.ToString());
        command.Parameters.AddWithValue("$node_incarnation_id", nodeIncarnationId.ToString());
    }

    private static string Format(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTime(string value) =>
        DateTimeOffset.ParseExact(
            value,
            "O",
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind);

    private static IdentityResolutionException Failure(string code, string detail) =>
        new(code, detail);

    private sealed record StoredUse(Guid UseId, bool Consumed);
}

internal sealed record StoredLocalIdentityGrant(
    LocalControlIdentityGrantRegistration Registration,
    ProtectedIdentityHandle Handle,
    bool Revoked);

internal static class LocalIdentityGrantBinding
{
    internal static TaskIdentityGrantReference Reference(
        StoredLocalIdentityGrant grant,
        Guid useId) => new(
        grant.Registration.IdentityGrantId,
        grant.Registration.WorkloadId,
        grant.Registration.TaskId,
        grant.Registration.Generation,
        grant.Registration.HostId,
        grant.Registration.NodeIncarnationId,
        grant.Registration.Audience,
        grant.Registration.Scopes,
        grant.Registration.ExpiresAt,
        grant.Registration.RenewalMode,
        useId,
        grant.Registration.OfflineBehavior);

    internal static bool ExactlyMatches(
        DirectIdentityDeliveryRequest request,
        TaskIdentityGrantReference expected)
    {
        var actual = request.Grant;
        return actual.IdentityGrantId == expected.IdentityGrantId &&
               actual.WorkloadId == expected.WorkloadId &&
               actual.TaskId == expected.TaskId &&
               actual.Generation == expected.Generation &&
               actual.HostId == expected.HostId &&
               actual.NodeIncarnationId == expected.NodeIncarnationId &&
               string.Equals(actual.Audience, expected.Audience, StringComparison.Ordinal) &&
               actual.Scopes.SequenceEqual(expected.Scopes, StringComparer.Ordinal) &&
               actual.ExpiresAt == expected.ExpiresAt &&
               actual.RenewalMode == expected.RenewalMode &&
               actual.UseId == expected.UseId &&
               actual.OfflineBehavior == expected.OfflineBehavior &&
               request.Identity.WorkloadId == expected.WorkloadId &&
               request.Identity.TaskId == expected.TaskId &&
               request.Identity.Generation == expected.Generation &&
               request.Identity.HostId == expected.HostId &&
               request.Identity.NodeIncarnationId == expected.NodeIncarnationId;
    }
}

[SupportedOSPlatform("windows")]
internal static class LocalIdentityStorageSecurity
{
    internal static void PrepareDirectory(string path)
    {
        EnsureNoReparseSegments(path, requireLeaf: false);
        Directory.CreateDirectory(path);
        EnsureSafeDirectory(path);
        var identity = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("The current Windows identity has no SID.");
        var security = new DirectorySecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    internal static void EnsureSafeDirectory(string path)
    {
        if (!Directory.Exists(path))
            throw new IOException("Local identity storage cannot use a reparse-point directory.");
        EnsureNoReparseSegments(path, requireLeaf: true);
    }

    internal static bool IsSafeRegularFile(string path)
    {
        if (!File.Exists(path))
            return false;
        var attributes = File.GetAttributes(path);
        return !attributes.HasFlag(FileAttributes.Directory) &&
               !attributes.HasFlag(FileAttributes.ReparsePoint);
    }

    internal static void RestrictFile(string path)
    {
        if (!IsSafeRegularFile(path))
            throw new IOException("Local identity storage requires a regular file.");
        var identity = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("The current Windows identity has no SID.");
        var security = new FileSecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static void EnsureNoReparseSegments(string path, bool requireLeaf)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full)
            ?? throw new IOException("Local identity storage path has no root.");
        var current = root;
        foreach (var segment in full[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (!Directory.Exists(current))
                continue;
            if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Local identity storage cannot traverse reparse points.");
        }
        if (requireLeaf && !Directory.Exists(full))
            throw new IOException("Local identity storage directory is unavailable.");
    }
}
