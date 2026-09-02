using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Steward.Contracts;
using Steward.Domain;
using Steward.Persistence.Sqlite;
using Steward.Scheduling;

namespace Steward.Orchestration;

public sealed record RegisterNodeRequest(
    string HostId,
    string NodeIncarnationId,
    string PoolId,
    ExtensionMetadataDto Transport,
    string PeerIdentity,
    string PeerPublicKeyReference,
    ResourceRequirements Capacity,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> SetupFingerprints,
    DateTimeOffset ObservedAt,
    bool Enabled = true)
{
    public NodeEndpointRegistration ToRegistration()
    {
        if (!Domain.HostId.TryParse(HostId, out var hostId) ||
            !Domain.NodeIncarnationId.TryParse(NodeIncarnationId, out var incarnationId) ||
            !Domain.PoolId.TryParse(PoolId, out var poolId))
            throw new ArgumentException("Node registration identifiers are invalid.");
        return new(
            hostId, incarnationId, poolId, Transport,
            PeerIdentity, PeerPublicKeyReference, Capacity,
            Capabilities, SetupFingerprints, ObservedAt, Enabled);
    }
}

public sealed record NodeEndpointRegistration(
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    PoolId PoolId,
    ExtensionMetadataDto Transport,
    string PeerIdentity,
    string PeerPublicKeyReference,
    ResourceRequirements Capacity,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> SetupFingerprints,
    DateTimeOffset ObservedAt,
    bool Enabled = true)
{
    public NodeEndpointRegistration Validate()
    {
        if (string.IsNullOrWhiteSpace(Transport.Kind) || Transport.Kind.Length > 128 ||
            string.IsNullOrWhiteSpace(Transport.Version) || Transport.Version.Length > 64 ||
            !Transport.HasData ||
            Transport.DataByteCount > 16 * 1024)
            throw new ArgumentException("Node transport binding is invalid.");
        if (string.IsNullOrWhiteSpace(PeerIdentity) || PeerIdentity.Length > 256)
            throw new ArgumentException("Node peer identity is invalid.");
        if (string.IsNullOrWhiteSpace(PeerPublicKeyReference) ||
            PeerPublicKeyReference.Length > 2048)
            throw new ArgumentException("Node public-key reference is invalid.");
        if (Capabilities.Count > 256 || Capabilities.Any(string.IsNullOrWhiteSpace) ||
            Capabilities.Distinct(StringComparer.Ordinal).Count() != Capabilities.Count)
            throw new ArgumentException("Node capabilities are invalid.");
        if (SetupFingerprints.Count > 256 || SetupFingerprints.Any(string.IsNullOrWhiteSpace) ||
            SetupFingerprints.Distinct(StringComparer.Ordinal).Count() != SetupFingerprints.Count)
            throw new ArgumentException("Node setup fingerprints are invalid.");
        return this;
    }

    public HostCapacitySnapshot ToSnapshot() =>
        new(HostId, NodeIncarnationId, PoolId, Capacity, Capabilities,
            SetupFingerprints, ObservedAt, Enabled);
}

public sealed class ControlNodeRegistrationStore(SqliteControlStore controlStore)
{
    public async Task RotatePeerAsync(
        NodeEndpointRegistration registration,
        CancellationToken cancellationToken = default)
    {
        registration.Validate();
        await using var connection =
            await controlStore.OpenConnectionAsync(cancellationToken);
        await using var transaction =
            connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT registration_json
            FROM orchestration_node_endpoints
            WHERE host_id=$host AND node_incarnation_id=$incarnation
            """;
        command.Parameters.AddWithValue(
            "$host",
            registration.HostId.ToString());
        command.Parameters.AddWithValue(
            "$incarnation",
            registration.NodeIncarnationId.ToString());
        var storedJson = Convert.ToString(
            await command.ExecuteScalarAsync(cancellationToken))
            ?? throw new KeyNotFoundException(
                "The Node registration does not exist.");
        var stored = JsonSerializer.Deserialize<NodeEndpointRegistration>(
            storedJson,
            StewardJson.Options)
            ?? throw new InvalidDataException(
                "The durable Node registration is invalid.");
        if (stored.HostId != registration.HostId ||
            stored.NodeIncarnationId != registration.NodeIncarnationId ||
            stored.PoolId != registration.PoolId ||
            !SameTransport(stored.Transport, registration.Transport) ||
            stored.Capacity != registration.Capacity ||
            !stored.Capabilities.SequenceEqual(
                registration.Capabilities,
                StringComparer.Ordinal) ||
            !stored.SetupFingerprints.SequenceEqual(
                registration.SetupFingerprints,
                StringComparer.Ordinal) ||
            stored.Enabled != registration.Enabled)
            throw new InvalidOperationException(
                "Node peer rotation cannot change registration identity or capabilities. " +
                $"pool={stored.PoolId == registration.PoolId};" +
                $"transport={stored.Transport == registration.Transport};" +
                $"capacity={stored.Capacity == registration.Capacity};" +
                $"capabilities={stored.Capabilities.SequenceEqual(registration.Capabilities, StringComparer.Ordinal)};" +
                $"setup={stored.SetupFingerprints.SequenceEqual(registration.SetupFingerprints, StringComparer.Ordinal)};" +
                $"enabled={stored.Enabled == registration.Enabled}");
        var json = JsonSerializer.Serialize(
            registration,
            StewardJson.Options);
        command.CommandText = """
            UPDATE orchestration_node_endpoints
            SET peer_identity=$identity,
                peer_public_key_reference=$key,
                registration_json=$json,
                observed_at=$observed
            WHERE host_id=$host AND node_incarnation_id=$incarnation
            """;
        command.Parameters.AddWithValue(
            "$identity",
            registration.PeerIdentity);
        command.Parameters.AddWithValue(
            "$key",
            registration.PeerPublicKeyReference);
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue(
            "$observed",
            registration.ObservedAt.ToUniversalTime().ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException(
                "Node peer rotation lost its durable identity.");
        await transaction.CommitAsync(cancellationToken);
    }

    private static bool SameTransport(
        ExtensionMetadataDto left,
        ExtensionMetadataDto right)
    {
        if (!string.Equals(
                left.Kind,
                right.Kind,
                StringComparison.Ordinal) ||
            !string.Equals(
                left.Version,
                right.Version,
                StringComparison.Ordinal))
            return false;
        var leftJson = JsonSerializer.Serialize(
            left,
            StewardJson.Options);
        var rightJson = JsonSerializer.Serialize(
            right,
            StewardJson.Options);
        using var leftDocument = JsonDocument.Parse(leftJson);
        using var rightDocument = JsonDocument.Parse(rightJson);
        return JsonNode.DeepEquals(
            JsonNode.Parse(
                leftDocument.RootElement.GetProperty("data").GetRawText()),
            JsonNode.Parse(
                rightDocument.RootElement.GetProperty("data").GetRawText()));
    }

    public async Task RegisterAsync(
        NodeEndpointRegistration registration,
        CancellationToken cancellationToken = default)
    {
        registration.Validate();
        var json = JsonSerializer.Serialize(registration, StewardJson.Options);
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT host_id,node_incarnation_id,transport_kind,transport_version,
                   peer_identity,peer_public_key_reference
            FROM orchestration_node_endpoints
            WHERE host_id=$host OR node_incarnation_id=$incarnation
            """;
        command.Parameters.AddWithValue("$host", registration.HostId.ToString());
        command.Parameters.AddWithValue("$incarnation", registration.NodeIncarnationId.ToString());
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken) &&
                (reader.GetString(0) != registration.HostId.ToString() ||
                 reader.GetString(1) != registration.NodeIncarnationId.ToString() ||
                 reader.GetString(2) != registration.Transport.Kind ||
                 reader.GetString(3) != registration.Transport.Version ||
                 reader.GetString(4) != registration.PeerIdentity ||
                 reader.GetString(5) != registration.PeerPublicKeyReference))
                throw new InvalidOperationException(
                    "Host or Node direct endpoint conflicts with durable identity.");
            if (reader.HasRows)
            {
                await reader.DisposeAsync();
                command.CommandText = """
                    UPDATE orchestration_node_endpoints SET
                      pool_id=$pool,registration_json=$json,observed_at=$observed,enabled=$enabled
                    WHERE host_id=$host
                    """;
                command.Parameters.AddWithValue("$pool", registration.PoolId.ToString());
                command.Parameters.AddWithValue("$json", json);
                command.Parameters.AddWithValue("$observed", registration.ObservedAt.ToString("O"));
                command.Parameters.AddWithValue("$enabled", registration.Enabled);
                await command.ExecuteNonQueryAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return;
            }
        }
        command.CommandText = """
            INSERT INTO orchestration_node_endpoints(
                host_id,node_incarnation_id,pool_id,transport_kind,transport_version,
                peer_identity,peer_public_key_reference,registration_json,observed_at,enabled)
            VALUES($host,$incarnation,$pool,$mode,$uri,$identity,$key,$json,$observed,$enabled)
            """;
        command.Parameters.Clear();
        command.Parameters.AddWithValue("$host", registration.HostId.ToString());
        command.Parameters.AddWithValue("$incarnation", registration.NodeIncarnationId.ToString());
        command.Parameters.AddWithValue("$pool", registration.PoolId.ToString());
        command.Parameters.AddWithValue("$mode", registration.Transport.Kind);
        command.Parameters.AddWithValue("$uri", registration.Transport.Version);
        command.Parameters.AddWithValue("$identity", registration.PeerIdentity);
        command.Parameters.AddWithValue("$key", registration.PeerPublicKeyReference);
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue("$observed", registration.ObservedAt.ToString("O"));
        command.Parameters.AddWithValue("$enabled", registration.Enabled);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task TouchObservedAtAsync(
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE orchestration_node_endpoints
            SET observed_at=CASE
              WHEN julianday(observed_at) < julianday($observed)
                THEN $observed
              ELSE observed_at
            END
            WHERE host_id=$host AND node_incarnation_id=$incarnation AND enabled=1
            """;
        command.Parameters.AddWithValue("$host", hostId.ToString());
        command.Parameters.AddWithValue("$incarnation", nodeIncarnationId.ToString());
        command.Parameters.AddWithValue(
            "$observed",
            observedAt.ToUniversalTime().ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            throw new InvalidOperationException(
                "Enabled Node registration does not match the authenticated session identity.");
    }

    public async Task<IReadOnlyList<NodeEndpointRegistration>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection = await controlStore.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT registration_json,observed_at,enabled,host_id,node_incarnation_id,pool_id
            FROM orchestration_node_endpoints ORDER BY host_id
            """;
        var result = new List<NodeEndpointRegistration>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            NodeEndpointRegistration value;
            try
            {
                value = JsonSerializer.Deserialize<NodeEndpointRegistration>(
                    reader.GetString(0), StewardJson.Options)
                    ?? throw new InvalidDataException("Persisted Node registration is invalid.");
            }
            catch (JsonException)
            {
                value = JsonSerializer.Deserialize<NodeEndpointRegistration>(reader.GetString(0))
                    ?? throw new InvalidDataException("Persisted Node registration is invalid.");
            }
            result.Add((value with
            {
                ObservedAt = DateTimeOffset.Parse(reader.GetString(1)),
                Enabled = reader.GetBoolean(2),
                HostId = HostId.Parse(reader.GetString(3)),
                NodeIncarnationId = NodeIncarnationId.Parse(reader.GetString(4)),
                PoolId = PoolId.Parse(reader.GetString(5))
            }).Validate());
        }
        return result;
    }
}
