using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.Persistence.Sqlite;
using Steward.Providers.Abstractions;

namespace Steward.Application;

internal sealed record PendingPoolProviderOperation(
    PoolId PoolId,
    PoolActionKind ActionKind,
    ProviderEffect Effect,
    ProviderOperationHandle? Handle,
    DateTimeOffset CreatedAt);

internal sealed class SqliteProviderOperationStore(
    SqliteControlStore controlStore)
{
    public async Task BeginAsync(
        PoolId poolId,
        PoolActionKind actionKind,
        ProviderEffect effect,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var connection =
            await controlStore.OpenConnectionAsync(cancellationToken);
        await EnsureSchemaAsync(connection, cancellationToken);
        var effectJson = JsonSerializer.Serialize(effect, StewardJson.Options);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO orchestration_provider_operations(
                operation_id, pool_id, action_kind, effect_json, handle_json,
                created_at, updated_at)
            VALUES(
                $operation_id, $pool_id, $action_kind, $effect_json, NULL,
                $created_at, $updated_at)
            ON CONFLICT(operation_id) DO UPDATE SET
                updated_at = excluded.updated_at
            WHERE
                orchestration_provider_operations.pool_id = excluded.pool_id
                AND orchestration_provider_operations.action_kind =
                    excluded.action_kind
                AND orchestration_provider_operations.effect_json =
                    excluded.effect_json;
            """;
        command.Parameters.AddWithValue(
            "$operation_id",
            effect.OperationId.ToString());
        command.Parameters.AddWithValue("$pool_id", poolId.ToString());
        command.Parameters.AddWithValue(
            "$action_kind",
            (int)actionKind);
        command.Parameters.AddWithValue("$effect_json", effectJson);
        command.Parameters.AddWithValue("$created_at", now.ToString("O"));
        command.Parameters.AddWithValue("$updated_at", now.ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException(
                "Provider operation identity conflicts with durable intent.");
    }

    public async Task AttachHandleAsync(
        ProviderOperationId operationId,
        ProviderOperationHandle handle,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var handleJson = JsonSerializer.Serialize(
            handle,
            StewardJson.Options);
        await using var connection =
            await controlStore.OpenConnectionAsync(cancellationToken);
        await EnsureSchemaAsync(connection, cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE orchestration_provider_operations
            SET handle_json = $handle_json,
                updated_at = $updated_at
            WHERE operation_id = $operation_id
              AND (handle_json IS NULL OR handle_json = $handle_json);
            """;
        command.Parameters.AddWithValue(
            "$operation_id",
            operationId.ToString());
        command.Parameters.AddWithValue("$handle_json", handleJson);
        command.Parameters.AddWithValue("$updated_at", now.ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException(
                "Provider operation handle conflicts with durable state.");
    }

    public async Task<IReadOnlyList<PendingPoolProviderOperation>> ListAsync(
        PoolId poolId,
        CancellationToken cancellationToken)
    {
        await using var connection =
            await controlStore.OpenConnectionAsync(cancellationToken);
        await EnsureSchemaAsync(connection, cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                pool_id, action_kind, effect_json, handle_json, created_at
            FROM orchestration_provider_operations
            WHERE pool_id = $pool_id
            ORDER BY created_at, operation_id;
            """;
        command.Parameters.AddWithValue("$pool_id", poolId.ToString());
        var result = new List<PendingPoolProviderOperation>();
        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var effect = JsonSerializer.Deserialize<ProviderEffect>(
                reader.GetString(2),
                StewardJson.Options)
                ?? throw new InvalidDataException(
                    "Persisted provider effect is invalid.");
            var handle = reader.IsDBNull(3)
                ? null
                : JsonSerializer.Deserialize<ProviderOperationHandle>(
                    reader.GetString(3),
                    StewardJson.Options)
                  ?? throw new InvalidDataException(
                      "Persisted provider handle is invalid.");
            result.Add(new(
                PoolId.Parse(reader.GetString(0)),
                (PoolActionKind)reader.GetInt32(1),
                effect,
                handle,
                DateTimeOffset.Parse(
                    reader.GetString(4),
                    System.Globalization.CultureInfo.InvariantCulture)));
        }
        return result;
    }

    public async Task CompleteAsync(
        ProviderOperationId operationId,
        CancellationToken cancellationToken)
    {
        await using var connection =
            await controlStore.OpenConnectionAsync(cancellationToken);
        await EnsureSchemaAsync(connection, cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            DELETE FROM orchestration_provider_operations
            WHERE operation_id = $operation_id;
            """;
        command.Parameters.AddWithValue(
            "$operation_id",
            operationId.ToString());
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException(
                "Provider operation completion was not durable.");
    }

    private static async Task EnsureSchemaAsync(
        Microsoft.Data.Sqlite.SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS orchestration_provider_operations(
                operation_id TEXT PRIMARY KEY,
                pool_id TEXT NOT NULL,
                action_kind INTEGER NOT NULL,
                effect_json TEXT NOT NULL,
                handle_json TEXT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS
                ix_orchestration_provider_operations_pool
            ON orchestration_provider_operations(pool_id, created_at);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
