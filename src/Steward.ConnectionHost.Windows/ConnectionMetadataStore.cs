using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Steward.Transport;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public sealed record DurableConnectionMetadata(
    int Version,
    string ConnectionId,
    RdpDvcSessionState State,
    long? ConnectionGeneration,
    string? RuntimeConnectionId,
    bool ViewSupported,
    bool ControlSupported,
    string Code,
    DateTimeOffset UpdatedAtUtc);

public sealed record DesiredConnectionRecord(
    int Version,
    string ConnectionId,
    Uri DevBoxEndpoint,
    string Project,
    string User,
    string DevBox,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    bool DesiredHeadless,
    DateTimeOffset UpdatedAtUtc)
{
    public DesiredConnectionRecord Validate()
    {
        if (Version != ConnectionHostProtocol.CurrentVersion ||
            string.IsNullOrWhiteSpace(ConnectionId) ||
            ConnectionId.Length >
                ConnectionHostProtocol.MaximumConnectionIdCharacters ||
            ConnectionId.Any(char.IsControl) ||
            DevBoxEndpoint is null ||
            !DevBoxEndpoint.IsAbsoluteUri ||
            DevBoxEndpoint.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(DevBoxEndpoint.UserInfo) ||
            !string.IsNullOrEmpty(DevBoxEndpoint.Query) ||
            !string.IsNullOrEmpty(DevBoxEndpoint.Fragment) ||
            string.IsNullOrWhiteSpace(Project) || Project.Length > 128 ||
            string.IsNullOrWhiteSpace(User) || User.Length > 128 ||
            string.IsNullOrWhiteSpace(DevBox) || DevBox.Length > 128 ||
            Project.Any(char.IsControl) ||
            User.Any(char.IsControl) ||
            DevBox.Any(char.IsControl) ||
            SessionId == Guid.Empty ||
            HostId == Guid.Empty ||
            NodeIncarnationId == Guid.Empty)
            throw new InvalidDataException(
                "The desired ConnectionHost identity is invalid.");
        return this with { UpdatedAtUtc = UpdatedAtUtc.ToUniversalTime() };
    }
}

public sealed record ConnectionTransitionRecord(
    long Sequence,
    string ConnectionId,
    RdpDvcSessionState State,
    long? ConnectionGeneration,
    string Code,
    DateTimeOffset CreatedAtUtc);

public sealed record ConnectionAttemptRecord(
    Guid AttemptId,
    string ConnectionId,
    long? ConnectionGeneration,
    string State,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? CompletedAtUtc);

public sealed record ConnectionRouteContext(
    string ConnectionId,
    long ConnectionGeneration)
{
    public ConnectionRouteContext Validate()
    {
        if (string.IsNullOrWhiteSpace(ConnectionId) ||
            ConnectionId.Length >
                ConnectionHostProtocol.MaximumConnectionIdCharacters ||
            ConnectionGeneration <= 0)
            throw new ArgumentException(
                "The ConnectionHost route context is invalid.");
        return this;
    }
}

public enum PresentationLeaseMode
{
    View = 1,
    Control = 2
}
public interface IConnectionRecoveryStore : IConnectionMetadataStore
{
    Task<IReadOnlyList<DesiredConnectionRecord>> LoadDesiredAsync(
        CancellationToken cancellationToken);

    Task UpsertDesiredAsync(
        DesiredConnectionRecord desired,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ConnectionTransitionRecord>>
        ReadPendingTransitionsAsync(
            int limit,
            CancellationToken cancellationToken);

    Task AcknowledgeTransitionAsync(
        long sequence,
        CancellationToken cancellationToken);

    Task RecordAttemptAsync(
        ConnectionAttemptRecord attempt,
        CancellationToken cancellationToken);

    Task RecordAuthenticatedRouteAsync(
        ConnectionRouteContext context,
        IRdpDvcControlCarrierAttachment attachment,
        CancellationToken cancellationToken);

    Task DetachControlAsync(
        Guid attemptId,
        CancellationToken cancellationToken);

    Task SetPresentationLeaseAsync(
        ConnectionRouteContext context,
        PresentationLeaseMode mode,
        bool active,
        CancellationToken cancellationToken);
}
public interface IConnectionMetadataStore
{
    Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
        CancellationToken cancellationToken);

    Task SaveAsync(
        IReadOnlyCollection<DurableConnectionMetadata> connections,
        CancellationToken cancellationToken);
}

public sealed class AtomicJsonConnectionMetadataStore :
    IConnectionMetadataStore
{
    private const int MaximumStoreBytes = 1024 * 1024;
    private readonly string path;
    private readonly string directory;

    public AtomicJsonConnectionMetadataStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new ArgumentException(
                "The connection metadata path must be absolute.",
                nameof(path));
        this.path = Path.GetFullPath(path);
        directory = Path.GetDirectoryName(this.path) ??
            throw new ArgumentException(
                "The connection metadata path has no directory.",
                nameof(path));
        PrepareDirectory(directory);
    }

    public async Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return [];
        EnsureSafeDirectory(directory);
        if (!IsSafeRegularFile(path))
            throw new InvalidDataException(
                "The connection metadata file is unsafe.");
        var info = new FileInfo(path);
        if (info.Length is <= 0 or > MaximumStoreBytes)
            throw new InvalidDataException(
                "The connection metadata store has an invalid size.");
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var values = await JsonSerializer.DeserializeAsync(
                stream,
                ConnectionHostJsonContext.Default
                    .ListDurableConnectionMetadata,
                cancellationToken)
            .ConfigureAwait(false) ?? [];
        if (values.Count > ConnectionHostProtocol.MaximumConnections)
            throw new InvalidDataException(
                "The connection metadata store exceeds its bound.");
        return values;
    }

    public async Task SaveAsync(
        IReadOnlyCollection<DurableConnectionMetadata> connections,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connections);
        if (connections.Count > ConnectionHostProtocol.MaximumConnections)
            throw new InvalidDataException(
                "The connection metadata store exceeds its bound.");
        PrepareDirectory(directory);
        if (File.Exists(path) && !IsSafeRegularFile(path))
            throw new IOException(
                "The connection metadata target is unsafe.");
        var replacement = Path.Combine(
            directory,
            $".{Path.GetFileName(path)}." +
            $"{RandomNumberGenerator.GetHexString(16)}.new");
        try
        {
            await using (var stream = new FileStream(
                             replacement,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             16 * 1024,
                             FileOptions.Asynchronous |
                             FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(
                        stream,
                        connections,
                        ConnectionHostJsonContext.Default
                            .IReadOnlyCollectionDurableConnectionMetadata,
                        cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            RestrictFile(replacement);
            if (File.Exists(path) && !IsSafeRegularFile(path))
                throw new IOException(
                    "The connection metadata target became unsafe.");
            File.Move(replacement, path, overwrite: true);
            RestrictFile(path);
        }
        finally
        {
            if (File.Exists(replacement))
                File.Delete(replacement);
        }
    }

    private static void PrepareDirectory(string directory)
    {
        EnsureNoReparseSegments(directory, requireLeaf: false);
        Directory.CreateDirectory(directory);
        EnsureSafeDirectory(directory);
        var identity = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new DirectorySecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    private static void EnsureSafeDirectory(string directory)
    {
        if (!Directory.Exists(directory))
            throw new IOException(
                "The connection metadata directory is unavailable.");
        EnsureNoReparseSegments(directory, requireLeaf: true);
    }

    private static bool IsSafeRegularFile(string file)
    {
        var attributes = File.GetAttributes(file);
        return !attributes.HasFlag(FileAttributes.Directory) &&
            !attributes.HasFlag(FileAttributes.ReparsePoint);
    }

    private static void RestrictFile(string file)
    {
        if (!IsSafeRegularFile(file))
            throw new IOException(
                "Connection metadata requires a regular file.");
        var identity = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new FileSecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(file).SetAccessControl(security);
    }

    private static void EnsureNoReparseSegments(
        string path,
        bool requireLeaf)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ??
            throw new IOException(
                "The connection metadata path has no root.");
        var current = root;
        foreach (var segment in full[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (Directory.Exists(current) &&
                File.GetAttributes(current)
                    .HasFlag(FileAttributes.ReparsePoint))
                throw new IOException(
                    "Connection metadata cannot traverse reparse points.");
        }
        if (requireLeaf && !Directory.Exists(full))
            throw new IOException(
                "The connection metadata directory is unavailable.");
    }
}

public sealed class SqliteConnectionMetadataStore :
    IConnectionRecoveryStore
{
    private const int CurrentSchemaVersion = 3;
    private readonly string databasePath;
    private readonly string connectionString;
    private readonly string? legacyJsonPath;

    public SqliteConnectionMetadataStore(
        string databasePath,
        string? legacyJsonPath = null)
    {
        if (string.IsNullOrWhiteSpace(databasePath) ||
            !Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException(
                "The connection metadata database path must be absolute.",
                nameof(databasePath));
        this.databasePath = Path.GetFullPath(databasePath);
        var directory = Path.GetDirectoryName(this.databasePath) ??
            throw new ArgumentException(
                "The connection metadata database path has no directory.",
                nameof(databasePath));
        Directory.CreateDirectory(directory);
        if (File.GetAttributes(directory).HasFlag(
                FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "The connection metadata directory cannot be a reparse point.");
        if (legacyJsonPath is not null)
        {
            if (!Path.IsPathFullyQualified(legacyJsonPath))
                throw new ArgumentException(
                    "The legacy connection metadata path must be absolute.",
                    nameof(legacyJsonPath));
            this.legacyJsonPath = Path.GetFullPath(legacyJsonPath);
        }
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = this.databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString();
        Initialize();
        RestrictDatabaseFiles();
    }

    public async Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
        CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT connection_id,state,connection_generation,
                   runtime_connection_id,view_supported,control_supported,
                   code,updated_at
            FROM runtime_connections
            ORDER BY connection_id
            """;
        var values = new List<DurableConnectionMetadata>();
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (values.Count >= ConnectionHostProtocol.MaximumConnections)
                throw new InvalidDataException(
                    "The connection metadata database exceeds its bound.");
            values.Add(new(
                ConnectionHostProtocol.CurrentVersion,
                reader.GetString(0),
                (RdpDvcSessionState)reader.GetInt32(1),
                reader.IsDBNull(2) ? null : reader.GetInt64(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.GetBoolean(4),
                reader.GetBoolean(5),
                reader.GetString(6),
                DateTimeOffset.Parse(reader.GetString(7))));
        }
        return values;
    }

    public async Task SaveAsync(
        IReadOnlyCollection<DurableConnectionMetadata> connections,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ValidateCollection(connections);
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(
            deferred: false);
        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM runtime_connections";
            await delete.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        foreach (var value in connections)
        {
            await InsertRuntimeAsync(
                connection,
                transaction,
                value,
                cancellationToken).ConfigureAwait(false);
            await using var outbox = connection.CreateCommand();
            outbox.Transaction = transaction;
            outbox.CommandText = """
                INSERT OR IGNORE INTO connection_transition_outbox(
                    connection_id,state,connection_generation,code,
                    created_at,acknowledged_at)
                VALUES($id,$state,$generation,$code,$updated,NULL)
                """;
            BindRuntimeIdentity(outbox, value);
            await outbox.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken)
            .ConfigureAwait(false);
        RestrictDatabaseFiles();
    }

    public async Task<IReadOnlyList<DesiredConnectionRecord>>
        LoadDesiredAsync(CancellationToken cancellationToken)
    {
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT connection_id,devbox_endpoint,project,user_name,
                   devbox_name,session_id,host_id,node_incarnation_id,
                   desired_headless,updated_at
            FROM desired_connections
            ORDER BY connection_id
            """;
        var values = new List<DesiredConnectionRecord>();
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            values.Add(new DesiredConnectionRecord(
                ConnectionHostProtocol.CurrentVersion,
                reader.GetString(0),
                new Uri(reader.GetString(1), UriKind.Absolute),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                Guid.Parse(reader.GetString(5)),
                Guid.Parse(reader.GetString(6)),
                Guid.Parse(reader.GetString(7)),
                reader.GetBoolean(8),
                DateTimeOffset.Parse(reader.GetString(9))).Validate());
        return values;
    }

    public async Task UpsertDesiredAsync(
        DesiredConnectionRecord desired,
        CancellationToken cancellationToken)
    {
        desired = desired.Validate();
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO desired_connections(
                connection_id,devbox_endpoint,project,user_name,devbox_name,
                session_id,host_id,node_incarnation_id,desired_headless,
                updated_at)
            VALUES(
                $id,$endpoint,$project,$user,$devbox,$session,$host,
                $incarnation,$desired,$updated)
            ON CONFLICT(connection_id) DO UPDATE SET
                devbox_endpoint=excluded.devbox_endpoint,
                project=excluded.project,
                user_name=excluded.user_name,
                devbox_name=excluded.devbox_name,
                session_id=excluded.session_id,
                host_id=excluded.host_id,
                node_incarnation_id=excluded.node_incarnation_id,
                desired_headless=excluded.desired_headless,
                updated_at=excluded.updated_at
            """;
        command.Parameters.AddWithValue("$id", desired.ConnectionId);
        command.Parameters.AddWithValue(
            "$endpoint",
            desired.DevBoxEndpoint.AbsoluteUri);
        command.Parameters.AddWithValue("$project", desired.Project);
        command.Parameters.AddWithValue("$user", desired.User);
        command.Parameters.AddWithValue("$devbox", desired.DevBox);
        command.Parameters.AddWithValue(
            "$session",
            desired.SessionId.ToString("D"));
        command.Parameters.AddWithValue("$host", desired.HostId.ToString("D"));
        command.Parameters.AddWithValue(
            "$incarnation",
            desired.NodeIncarnationId.ToString("D"));
        command.Parameters.AddWithValue("$desired", desired.DesiredHeadless);
        command.Parameters.AddWithValue(
            "$updated",
            desired.UpdatedAtUtc.ToUniversalTime().ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ConnectionTransitionRecord>>
        ReadPendingTransitionsAsync(
            int limit,
            CancellationToken cancellationToken)
    {
        if (limit is <= 0 or > 1000)
            throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT sequence,connection_id,state,connection_generation,
                   code,created_at
            FROM connection_transition_outbox
            WHERE acknowledged_at IS NULL
            ORDER BY sequence
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$limit", limit);
        var values = new List<ConnectionTransitionRecord>();
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            values.Add(new(
                reader.GetInt64(0),
                reader.GetString(1),
                (RdpDvcSessionState)reader.GetInt32(2),
                reader.IsDBNull(3) ? null : reader.GetInt64(3),
                reader.GetString(4),
                DateTimeOffset.Parse(reader.GetString(5))));
        return values;
    }

    public async Task AcknowledgeTransitionAsync(
        long sequence,
        CancellationToken cancellationToken)
    {
        if (sequence <= 0)
            throw new ArgumentOutOfRangeException(nameof(sequence));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE connection_transition_outbox
            SET acknowledged_at=$now
            WHERE sequence=$sequence AND acknowledged_at IS NULL
            """;
        command.Parameters.AddWithValue("$sequence", sequence);
        command.Parameters.AddWithValue(
            "$now",
            DateTimeOffset.UtcNow.ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new InvalidOperationException(
                "The ConnectionHost transition is absent or already acknowledged.");
    }

    public async Task RecordAttemptAsync(
        ConnectionAttemptRecord attempt,
        CancellationToken cancellationToken)
    {
        if (attempt.AttemptId == Guid.Empty ||
            string.IsNullOrWhiteSpace(attempt.ConnectionId) ||
            string.IsNullOrWhiteSpace(attempt.State) ||
            attempt.ConnectionGeneration is <= 0 ||
            attempt.CompletedAtUtc < attempt.StartedAtUtc)
            throw new ArgumentException(
                "The ConnectionHost attempt record is invalid.",
                nameof(attempt));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO connection_attempts(
                attempt_id,connection_id,connection_generation,state,
                started_at,completed_at)
            VALUES($attempt,$connection,$generation,$state,$started,$completed)
            ON CONFLICT(attempt_id) DO UPDATE SET
                connection_generation=excluded.connection_generation,
                state=excluded.state,
                completed_at=excluded.completed_at
            """;
        command.Parameters.AddWithValue(
            "$attempt",
            attempt.AttemptId.ToString("D"));
        command.Parameters.AddWithValue("$connection", attempt.ConnectionId);
        command.Parameters.AddWithValue(
            "$generation",
            attempt.ConnectionGeneration is null
                ? DBNull.Value
                : attempt.ConnectionGeneration.Value);
        command.Parameters.AddWithValue("$state", attempt.State);
        command.Parameters.AddWithValue(
            "$started",
            attempt.StartedAtUtc.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue(
            "$completed",
            attempt.CompletedAtUtc is null
                ? DBNull.Value
                : attempt.CompletedAtUtc.Value.ToUniversalTime().ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task RecordAuthenticatedRouteAsync(
        ConnectionRouteContext context,
        IRdpDvcControlCarrierAttachment attachment,
        CancellationToken cancellationToken)
    {
        context = context.Validate();
        ArgumentNullException.ThrowIfNull(attachment);
        var reconnectGeneration =
            attachment.ReconnectGeneration.GetValueOrDefault();
        await using var connection = Open();
        await using var transaction = connection.BeginTransaction(
            deferred: false);
        await using (var current = connection.CreateCommand())
        {
            current.Transaction = transaction;
            current.CommandText = """
                SELECT connection_generation,route_id,host_id,
                       node_incarnation_id,attempt_id,wts_session_id,
                       active,reconnect_generation
                FROM connection_routes
                WHERE connection_id=$connection
                ORDER BY connection_generation DESC
                LIMIT 1
                """;
            current.Parameters.AddWithValue(
                "$connection",
                context.ConnectionId);
            await using var reader = await current.ExecuteReaderAsync(
                cancellationToken).ConfigureAwait(false);
            if (await reader.ReadAsync(cancellationToken)
                    .ConfigureAwait(false))
            {
                var generation = reader.GetInt64(0);
                var sameBaseRoute =
                    reader.GetString(1) == attachment.RouteId.ToString("D") &&
                    reader.GetString(2) == attachment.HostId.ToString() &&
                    reader.GetString(3) ==
                        attachment.NodeIncarnationId.ToString();
                var previousReconnectGeneration = reader.GetInt64(7);
                var sameAttempt =
                    sameBaseRoute &&
                    reader.GetString(4) ==
                        attachment.AttemptId.ToString("D") &&
                    reader.GetInt32(5) == attachment.RdpSessionId &&
                    previousReconnectGeneration == reconnectGeneration;
                var active = reader.GetBoolean(6);
                if (context.ConnectionGeneration < generation ||
                    context.ConnectionGeneration == generation &&
                    !sameAttempt &&
                    (active ||
                     !sameBaseRoute ||
                     reconnectGeneration <=
                        previousReconnectGeneration))
                    throw new InvalidOperationException(
                        "A stale, replayed, concurrent, or crossed ConnectionHost route was rejected.");
            }
        }
        await using (var route = connection.CreateCommand())
        {
            route.Transaction = transaction;
            route.CommandText = """
                UPDATE connection_routes SET active=0
                WHERE connection_id=$connection;
                INSERT INTO connection_routes(
                    connection_id,connection_generation,route_id,host_id,
                    node_incarnation_id,attempt_id,wts_session_id,
                    reconnect_generation,active,updated_at)
                VALUES(
                    $connection,$generation,$route,$host,$incarnation,
                    $attempt,$wts,$reconnect,1,$updated)
                ON CONFLICT(connection_id,connection_generation) DO UPDATE SET
                    route_id=excluded.route_id,
                    host_id=excluded.host_id,
                    node_incarnation_id=excluded.node_incarnation_id,
                    attempt_id=excluded.attempt_id,
                    wts_session_id=excluded.wts_session_id,
                    reconnect_generation=excluded.reconnect_generation,
                    active=1,
                    updated_at=excluded.updated_at;
                """;
            route.Parameters.AddWithValue(
                "$connection",
                context.ConnectionId);
            route.Parameters.AddWithValue(
                "$generation",
                context.ConnectionGeneration);
            route.Parameters.AddWithValue(
                "$route",
                attachment.RouteId.ToString("D"));
            route.Parameters.AddWithValue(
                "$host",
                attachment.HostId.ToString());
            route.Parameters.AddWithValue(
                "$incarnation",
                attachment.NodeIncarnationId.ToString());
            route.Parameters.AddWithValue(
                "$attempt",
                attachment.AttemptId.ToString("D"));
            route.Parameters.AddWithValue(
                "$wts",
                attachment.RdpSessionId);
            route.Parameters.AddWithValue(
                "$reconnect",
                reconnectGeneration);
            route.Parameters.AddWithValue(
                "$updated",
                DateTimeOffset.UtcNow.ToString("O"));
            await route.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        await using (var attachmentCommand = connection.CreateCommand())
        {
            attachmentCommand.Transaction = transaction;
            attachmentCommand.CommandText = """
                INSERT INTO control_attachments(
                    attempt_id,connection_id,route_id,attached_at,detached_at)
                VALUES($attempt,$connection,$route,$attached,NULL)
                ON CONFLICT(attempt_id) DO UPDATE SET
                    connection_id=excluded.connection_id,
                    route_id=excluded.route_id,
                    attached_at=excluded.attached_at,
                    detached_at=NULL
                """;
            attachmentCommand.Parameters.AddWithValue(
                "$attempt",
                attachment.AttemptId.ToString("D"));
            attachmentCommand.Parameters.AddWithValue(
                "$connection",
                context.ConnectionId);
            attachmentCommand.Parameters.AddWithValue(
                "$route",
                attachment.RouteId.ToString("D"));
            attachmentCommand.Parameters.AddWithValue(
                "$attached",
                DateTimeOffset.UtcNow.ToString("O"));
            await attachmentCommand.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken)
            .ConfigureAwait(false);
    }
    public async Task DetachControlAsync(
        Guid attemptId,
        CancellationToken cancellationToken)
    {
        if (attemptId == Guid.Empty)
            throw new ArgumentException(
                "The Control attachment attempt ID is invalid.",
                nameof(attemptId));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE control_attachments
            SET detached_at=COALESCE(detached_at,$detached)
            WHERE attempt_id=$attempt;
            UPDATE connection_routes
            SET active=0,updated_at=$detached
            WHERE attempt_id=$attempt;
            """;
        command.Parameters.AddWithValue(
            "$attempt",
            attemptId.ToString("D"));
        command.Parameters.AddWithValue(
            "$detached",
            DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task SetPresentationLeaseAsync(
        ConnectionRouteContext context,
        PresentationLeaseMode mode,
        bool active,
        CancellationToken cancellationToken)
    {
        context = context.Validate();
        if (!Enum.IsDefined(mode))
            throw new ArgumentOutOfRangeException(nameof(mode));
        await using var connection = Open();
        await using var command = connection.CreateCommand();
        command.CommandText = active
            ? """
              INSERT INTO presentation_leases(
                  connection_id,connection_generation,mode,acquired_at,
                  released_at)
              VALUES($connection,$generation,$mode,$now,NULL)
              ON CONFLICT(connection_id,connection_generation,mode)
              DO UPDATE SET acquired_at=excluded.acquired_at,released_at=NULL
              """
            : """
              UPDATE presentation_leases
              SET released_at=COALESCE(released_at,$now)
              WHERE connection_id=$connection
                AND connection_generation=$generation
                AND mode=$mode
              """;
        command.Parameters.AddWithValue(
            "$connection",
            context.ConnectionId);
        command.Parameters.AddWithValue(
            "$generation",
            context.ConnectionGeneration);
        command.Parameters.AddWithValue("$mode", mode.ToString());
        command.Parameters.AddWithValue(
            "$now",
            DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
    }
    private void Initialize()
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction(
            deferred: false);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS connection_metadata_schema(
                version INTEGER NOT NULL);
            INSERT INTO connection_metadata_schema(version)
            SELECT 0
            WHERE NOT EXISTS(
                SELECT 1 FROM connection_metadata_schema);
            """;
        command.ExecuteNonQuery();
        command.CommandText =
            "SELECT version FROM connection_metadata_schema LIMIT 1";
        var version = Convert.ToInt32(command.ExecuteScalar());
        if (version is < 0 or > CurrentSchemaVersion)
            throw new InvalidDataException(
                $"Connection metadata schema {version} is unsupported.");
        CreateNormalizedTables(command);
        if (version < 3 &&
            !ColumnExists(
                connection,
                transaction,
                "connection_routes",
                "reconnect_generation"))
        {
            command.CommandText = """
                ALTER TABLE connection_routes
                ADD COLUMN reconnect_generation INTEGER NOT NULL DEFAULT 0;
                """;
            command.ExecuteNonQuery();
        }
        if (version == 1 && TableExists(connection, transaction, "connection_metadata"))
            MigrateSerializedRuntime(connection, transaction);
        command.CommandText =
            "UPDATE connection_metadata_schema SET version=3";
        command.ExecuteNonQuery();
        transaction.Commit();
        ImportLegacyJson();
    }

    private static void CreateNormalizedTables(SqliteCommand command)
    {
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS runtime_connections(
                connection_id TEXT PRIMARY KEY NOT NULL,
                state INTEGER NOT NULL,
                connection_generation INTEGER,
                runtime_connection_id TEXT,
                view_supported INTEGER NOT NULL,
                control_supported INTEGER NOT NULL,
                code TEXT NOT NULL,
                updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS desired_connections(
                connection_id TEXT PRIMARY KEY NOT NULL,
                devbox_endpoint TEXT NOT NULL,
                project TEXT NOT NULL,
                user_name TEXT NOT NULL,
                devbox_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                node_incarnation_id TEXT NOT NULL,
                desired_headless INTEGER NOT NULL,
                updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS connection_attempts(
                attempt_id TEXT PRIMARY KEY NOT NULL,
                connection_id TEXT NOT NULL,
                connection_generation INTEGER,
                state TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT);
            CREATE TABLE IF NOT EXISTS connection_routes(
                connection_id TEXT NOT NULL,
                connection_generation INTEGER NOT NULL,
                route_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                node_incarnation_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                wts_session_id INTEGER NOT NULL,
                reconnect_generation INTEGER NOT NULL,
                active INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(connection_id,connection_generation));
            CREATE TABLE IF NOT EXISTS control_attachments(
                attempt_id TEXT PRIMARY KEY NOT NULL,
                connection_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                attached_at TEXT NOT NULL,
                detached_at TEXT);
            CREATE TABLE IF NOT EXISTS presentation_leases(
                connection_id TEXT NOT NULL,
                connection_generation INTEGER NOT NULL,
                mode TEXT NOT NULL,
                acquired_at TEXT NOT NULL,
                released_at TEXT,
                PRIMARY KEY(connection_id,connection_generation,mode));
            CREATE TABLE IF NOT EXISTS connection_transition_outbox(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id TEXT NOT NULL,
                state INTEGER NOT NULL,
                connection_generation INTEGER,
                code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT,
                UNIQUE(connection_id,state,connection_generation,code,created_at));
            """;
        command.ExecuteNonQuery();
    }

    private static bool TableExists(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string name)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name=$name
            """;
        command.Parameters.AddWithValue("$name", name);
        return Convert.ToInt32(command.ExecuteScalar()) == 1;
    }

    private static bool ColumnExists(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string table,
        string column)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA table_info({table})";
        using var reader = command.ExecuteReader();
        while (reader.Read())
            if (string.Equals(
                    reader.GetString(1),
                    column,
                    StringComparison.Ordinal))
                return true;
        return false;
    }
    private static void MigrateSerializedRuntime(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        var values = new List<DurableConnectionMetadata>();
        using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText =
                "SELECT metadata_json FROM connection_metadata ORDER BY connection_id";
            using var reader = read.ExecuteReader();
            while (reader.Read())
                values.Add(JsonSerializer.Deserialize(
                    reader.GetString(0),
                    ConnectionHostJsonContext.Default.DurableConnectionMetadata)
                    ?? throw new InvalidDataException(
                        "The legacy connection metadata database is invalid."));
        }
        foreach (var value in values)
            InsertRuntimeAsync(
                    connection,
                    transaction,
                    value,
                    CancellationToken.None)
                .GetAwaiter().GetResult();
        using var drop = connection.CreateCommand();
        drop.Transaction = transaction;
        drop.CommandText = "DROP TABLE connection_metadata";
        drop.ExecuteNonQuery();
    }

    private void ImportLegacyJson()
    {
        if (legacyJsonPath is null || !File.Exists(legacyJsonPath))
            return;
        using var connection = Open();
        using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM runtime_connections";
        if (Convert.ToInt64(count.ExecuteScalar()) != 0)
            return;
        var legacy = new AtomicJsonConnectionMetadataStore(legacyJsonPath)
            .LoadAsync(CancellationToken.None)
            .GetAwaiter().GetResult();
        ValidateCollection(legacy);
        using var transaction = connection.BeginTransaction(deferred: false);
        foreach (var value in legacy)
            InsertRuntimeAsync(
                    connection,
                    transaction,
                    value,
                    CancellationToken.None)
                .GetAwaiter().GetResult();
        transaction.Commit();
        var migrated = legacyJsonPath + ".migrated";
        if (File.Exists(migrated))
            throw new IOException(
                "A prior migrated connection metadata snapshot already exists.");
        File.Move(legacyJsonPath, migrated);
    }

    private static async Task InsertRuntimeAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DurableConnectionMetadata value,
        CancellationToken cancellationToken)
    {
        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO runtime_connections(
                connection_id,state,connection_generation,
                runtime_connection_id,view_supported,control_supported,
                code,updated_at)
            VALUES(
                $id,$state,$generation,$runtime,$view,$control,$code,$updated)
            """;
        BindRuntimeIdentity(insert, value);
        insert.Parameters.AddWithValue(
            "$runtime",
            value.RuntimeConnectionId is null
                ? DBNull.Value
                : value.RuntimeConnectionId);
        insert.Parameters.AddWithValue("$view", value.ViewSupported);
        insert.Parameters.AddWithValue("$control", value.ControlSupported);
        await insert.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static void BindRuntimeIdentity(
        SqliteCommand command,
        DurableConnectionMetadata value)
    {
        command.Parameters.AddWithValue("$id", value.ConnectionId);
        command.Parameters.AddWithValue("$state", (int)value.State);
        command.Parameters.AddWithValue(
            "$generation",
            value.ConnectionGeneration is null
                ? DBNull.Value
                : value.ConnectionGeneration.Value);
        command.Parameters.AddWithValue("$code", value.Code);
        command.Parameters.AddWithValue(
            "$updated",
            value.UpdatedAtUtc.ToUniversalTime().ToString("O"));
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=30000;
            """;
        command.ExecuteNonQuery();
        return connection;
    }

    private void RestrictDatabaseFiles()
    {
        if (!OperatingSystem.IsWindows())
            return;
        foreach (var path in new[]
                 {
                     databasePath,
                     databasePath + "-wal",
                     databasePath + "-shm"
                 })
        {
            if (!File.Exists(path))
                continue;
            if (File.GetAttributes(path).HasFlag(
                    FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "The connection metadata database file is unsafe.");
            var current = WindowsIdentity.GetCurrent().User ??
                throw new InvalidOperationException(
                    "The current Windows identity has no SID.");
            var security = new FileSecurity();
            security.SetOwner(current);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new(
                current,
                FileSystemRights.FullControl,
                AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }
    }

    private static void ValidateCollection(
        IReadOnlyCollection<DurableConnectionMetadata> connections)
    {
        if (connections.Count > ConnectionHostProtocol.MaximumConnections ||
            connections.Select(value => value.ConnectionId).Distinct(
                StringComparer.Ordinal).Count() != connections.Count ||
            connections.Any(value =>
                value.Version != ConnectionHostProtocol.CurrentVersion ||
                string.IsNullOrWhiteSpace(value.ConnectionId) ||
                value.ConnectionId.Length >
                    ConnectionHostProtocol.MaximumConnectionIdCharacters ||
                value.ConnectionGeneration is <= 0 ||
                string.IsNullOrWhiteSpace(value.Code)))
            throw new InvalidDataException(
                "The connection metadata collection is invalid.");
    }
}
[JsonSerializable(typeof(List<DurableConnectionMetadata>))]
[JsonSerializable(typeof(IReadOnlyCollection<DurableConnectionMetadata>))]
[JsonSerializable(typeof(DurableConnectionMetadata))]
internal sealed partial class ConnectionHostJsonContext : JsonSerializerContext;
