using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Steward.Contracts;
using Steward.Domain;
using Steward.Orchestration;
using Steward.Persistence.Sqlite;
using Steward.Transport;

namespace Steward.Stack.Local;

[SupportedOSPlatform("windows")]
public sealed class RdpDvcControlSessionWorker(
    ValidatedLocalStackOptions options,
    SqliteControlStore controlStore,
    ControlNodeRegistrationStore registrations,
    ControlOrchestrator orchestrator,
    ControlTerminalRouter terminals,
    ControlTerminalRevocationStore terminalRevocations,
    DirectSessionControlIdentityHandler identity,
    IEnumerable<IAuxiliaryTransportStreamHandler> auxiliaryHandlers,
    ControlNodeLivenessRegistry liveness,
    ILogger<RdpDvcControlSessionWorker> logger) : BackgroundService
{
    private const int MaximumConcurrentCarriers = 8;

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        if (!options.RdpDvcControlCarrierEnabled)
            return;
        var listeners = Enumerable.Range(0, MaximumConcurrentCarriers)
            .Select(_ => RunListenerAsync(stoppingToken))
            .ToArray();
        await Task.WhenAll(listeners).ConfigureAwait(false);
    }

    private async Task RunListenerAsync(
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using var pipe = new NamedPipeServerStream(
                options.RdpDvcControlCarrierPipeName,
                PipeDirection.InOut,
                MaximumConcurrentCarriers,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                64 * 1024,
                64 * 1024);
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken)
                    .ConfigureAwait(false);
                await RunCarrierAsync(pipe, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
                when (exception is
                    IOException or
                    InvalidDataException or
                    UnauthorizedAccessException or
                    CryptographicException or
                    TransportProtocolException or
                    TimeoutException or
                    ObjectDisposedException or
                    System.Threading.Channels.ChannelClosedException)
            {
                logger.LogWarning(
                    "RDP DVC Control carrier failed closed with {Type} " +
                    "and HRESULT 0x{HResult:X8}.",
                    exception.GetType().Name,
                    exception.HResult);
            }
        }
    }

    private async Task RunCarrierAsync(
        NamedPipeServerStream pipe,
        CancellationToken cancellationToken)
    {
        var attachment = await RdpDvcControlCarrierAttachmentCodec
            .ReadAsync(pipe, cancellationToken)
            .ConfigureAwait(false);
        await using var controlResponses =
            await ConnectControlResponsePipeAsync(
                    attachment.AttemptId,
                    cancellationToken)
                .ConfigureAwait(false);
        var stage = CarrierAcceptanceStage.Attachment;
        var authenticated = false;
        try
        {
            var endpoints = await registrations.ListAsync(cancellationToken)
                .ConfigureAwait(false);
            var endpoint = endpoints.SingleOrDefault(value =>
                    value.Enabled &&
                    value.HostId == attachment.HostId &&
                    value.NodeIncarnationId ==
                        attachment.NodeIncarnationId)
                ?? throw new UnauthorizedAccessException(
                    "The carrier does not name an enabled registered Node.");
            var expectedSessionId = ResolveSessionId(endpoint);
            if (attachment.SessionId != expectedSessionId)
                throw new UnauthorizedAccessException(
                    "The carrier session does not match registration.");
            var hello = await CreateHelloAsync(
                    endpoint,
                    attachment,
                    cancellationToken)
                .ConfigureAwait(false);
            await ReconnectCarrierControlMessageCodec.WriteAsync(
                    controlResponses,
                    ReconnectCarrierControlMessage.RelayReady(
                        attachment.AttemptId),
                    cancellationToken)
                .ConfigureAwait(false);
            stage = CarrierAcceptanceStage.SignedSession;
            var terminator = new ControlReconnectSessionTerminator(
                options.TransportIdentity,
                options.TransportPrivateKeyPemPath ??
                throw new InvalidOperationException(
                    "The Control signing key is unavailable."),
                TimeSpan.FromSeconds(30));
            await using var connection = await terminator.AcceptAsync(
                    pipe,
                    attachment,
                    endpoint,
                    hello,
                    cancellationToken)
                .ConfigureAwait(false);

            if (attachment is ReconnectCarrierAttachment reconnect)
            {
                stage = CarrierAcceptanceStage.GenerationCommit;
                await ObserveGenerationAsync(
                        controlStore,
                        reconnect,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            await ReconnectCarrierControlMessageCodec.WriteAsync(
                    controlResponses,
                    ReconnectCarrierControlMessage
                        .SecureSessionAuthenticated(
                            attachment.AttemptId),
                    cancellationToken)
                .ConfigureAwait(false);
            authenticated = true;

            var handlers = auxiliaryHandlers
                .Append<IAuxiliaryTransportStreamHandler>(
                    new DirectSessionControlIdentityStreamHandler(
                        endpoint.HostId,
                        identity))
                .ToArray();
            var pump = new ControlSessionPump(
                orchestrator,
                endpoint.HostId,
                endpoint.NodeIncarnationId,
                terminals,
                terminalRevocations,
                handlers);
            await RunAuthenticatedSessionAsync(
                    endpoint,
                    pump.RunSessionAsync(connection, cancellationToken),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
            when (!authenticated && IsExpectedAcceptanceFailure(exception))
        {
            await TryWriteFailureAsync(
                    controlResponses,
                    attachment.AttemptId,
                    FailureFor(stage, exception),
                    cancellationToken)
                .ConfigureAwait(false);
            throw;
        }
    }
    private async Task<SessionHello> CreateHelloAsync(
        NodeEndpointRegistration endpoint,
        IRdpDvcControlCarrierAttachment attachment,
        CancellationToken cancellationToken)
    {
        var cursor = await orchestrator.GetNodeCursorAsync(
                endpoint.NodeIncarnationId,
                cancellationToken)
            .ConfigureAwait(false);
        var reconnect = attachment as ReconnectCarrierAttachment;
        var supported = new HashSet<string>
        {
            "rdp-dvc-secure",
            "orchestration-v1",
            "terminal-v1",
            "direct-identity-v1",
            "portable-transfer-v1"
        };
        var required = new HashSet<string>
        {
            "orchestration-v1"
        };
        if (reconnect is not null)
        {
            supported.Add("rdp-dvc-reconnect-v2");
            required.Add("rdp-dvc-reconnect-v2");
        }
        return new(
            attachment.SessionId,
            endpoint.NodeIncarnationId,
            1,
            0,
            supported,
            required,
            new Dictionary<StreamKind, long>
            {
                [StreamKind.Events] = cursor,
                [StreamKind.Terminal] =
                    terminals.GetReceivedCursor(
                        endpoint.NodeIncarnationId)
            },
            new(
                options.MaximumTransportPayloadBytes,
                options.MaximumBufferedFrames),
            reconnect?.Binding);
    }
    private async Task RunAuthenticatedSessionAsync(
        NodeEndpointRegistration endpoint,
        Task session,
        CancellationToken cancellationToken)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var leaseId = liveness.MarkOnline(
            endpoint.HostId,
            endpoint.NodeIncarnationId,
            observedAt);
        try
        {
            while (!session.IsCompleted)
            {
                observedAt = DateTimeOffset.UtcNow;
                liveness.Refresh(
                    endpoint.HostId,
                    endpoint.NodeIncarnationId,
                    leaseId,
                    observedAt);
                await registrations.TouchObservedAtAsync(
                        endpoint.HostId,
                        endpoint.NodeIncarnationId,
                        observedAt,
                        cancellationToken)
                    .ConfigureAwait(false);
                await orchestrator.ObserveHostAsync(
                        endpoint.ToSnapshot() with
                        {
                            ObservedAt = observedAt,
                            Available = true
                        },
                        observedAt,
                        cancellationToken)
                    .ConfigureAwait(false);
                var delay = Task.Delay(
                    TimeSpan.FromMinutes(1),
                    cancellationToken);
                if (await Task.WhenAny(session, delay)
                        .ConfigureAwait(false) == session)
                    break;
                await delay.ConfigureAwait(false);
            }
            await session.ConfigureAwait(false);
        }
        finally
        {
            if (liveness.MarkOffline(
                    endpoint.HostId,
                    endpoint.NodeIncarnationId,
                    leaseId))
                await orchestrator.ObserveHostOfflineAsync(
                        endpoint.HostId,
                        endpoint.NodeIncarnationId,
                        CancellationToken.None)
                    .ConfigureAwait(false);
        }
    }

    internal static async Task ObserveGenerationAsync(
        SqliteControlStore store,
        ReconnectCarrierAttachment attachment,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        _ = attachment.Validate();
        await using var connection = await store.OpenConnectionAsync(
                cancellationToken)
            .ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(
            deferred: false);
        await using var schema = connection.CreateCommand();
        schema.Transaction = transaction;
        schema.CommandText = """
            CREATE TABLE IF NOT EXISTS control_reconnect_high_water(
                host_id TEXT NOT NULL,
                node_incarnation_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                attempt_id TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(host_id,node_incarnation_id));
            """;
        await schema.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText = """
            SELECT session_id,generation
            FROM control_reconnect_high_water
            WHERE host_id=$host AND node_incarnation_id=$incarnation
            """;
        read.Parameters.AddWithValue(
            "$host",
            attachment.Binding.HostId.ToString());
        read.Parameters.AddWithValue(
            "$incarnation",
            attachment.Binding.NodeIncarnationId.ToString());
        await using var reader = await read.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var sessionId = reader.GetString(0);
            var generation = reader.GetInt64(1);
            await reader.DisposeAsync().ConfigureAwait(false);
            if (!string.Equals(
                    sessionId,
                    attachment.SessionId.ToString("D"),
                    StringComparison.Ordinal) ||
                attachment.Binding.ReconnectGeneration <= generation)
                throw new UnauthorizedAccessException(
                    "The Control reconnect generation was replayed or rebound.");
            await using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE control_reconnect_high_water
                SET generation=$generation,
                    attempt_id=$attempt,
                    updated_at=$updated
                WHERE host_id=$host
                  AND node_incarnation_id=$incarnation
                  AND generation=$previous
                """;
            BindHighWater(update, attachment);
            update.Parameters.AddWithValue("$previous", generation);
            if (await update.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false) != 1)
                throw new InvalidOperationException(
                    "The Control reconnect high-water compare-and-swap failed.");
        }
        else
        {
            await reader.DisposeAsync().ConfigureAwait(false);
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO control_reconnect_high_water(
                    host_id,node_incarnation_id,session_id,
                    generation,attempt_id,updated_at)
                VALUES(
                    $host,$incarnation,$session,
                    $generation,$attempt,$updated)
                """;
            BindHighWater(insert, attachment);
            await insert.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static void BindHighWater(
        Microsoft.Data.Sqlite.SqliteCommand command,
        ReconnectCarrierAttachment attachment)
    {
        command.Parameters.AddWithValue(
            "$host",
            attachment.Binding.HostId.ToString());
        command.Parameters.AddWithValue(
            "$incarnation",
            attachment.Binding.NodeIncarnationId.ToString());
        command.Parameters.AddWithValue(
            "$session",
            attachment.SessionId.ToString("D"));
        command.Parameters.AddWithValue(
            "$generation",
            attachment.Binding.ReconnectGeneration);
        command.Parameters.AddWithValue(
            "$attempt",
            attachment.Binding.AttemptId.ToString("D"));
        command.Parameters.AddWithValue(
            "$updated",
            DateTimeOffset.UtcNow.ToString("O"));
    }

    private async Task<NamedPipeClientStream>
        ConnectControlResponsePipeAsync(
            Guid attemptId,
            CancellationToken cancellationToken)
    {
        var pipeName = ReconnectCarrierAttachmentCodec
            .AcknowledgementPipeName(
                options.RdpDvcControlCarrierPipeName,
                attemptId);
        var responses = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.Out,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            await responses.ConnectAsync(timeout.Token)
                .ConfigureAwait(false);
            return responses;
        }
        catch
        {
            await responses.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task TryWriteFailureAsync(
        Stream responses,
        Guid attemptId,
        ReconnectCarrierFailure failure,
        CancellationToken cancellationToken)
    {
        try
        {
            await ReconnectCarrierControlMessageCodec.WriteAsync(
                    responses,
                    ReconnectCarrierControlMessage.Failed(
                        attemptId,
                        failure),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
            when (exception is
                IOException or
                OperationCanceledException or
                ObjectDisposedException)
        {
        }
    }

    private static bool IsExpectedAcceptanceFailure(
        Exception exception) =>
        exception is
            IOException or
            InvalidDataException or
            UnauthorizedAccessException or
            CryptographicException or
            TransportProtocolException or
            TimeoutException;

    internal static ReconnectCarrierFailure GenerationFailure(
        Exception exception) =>
        FailureFor(CarrierAcceptanceStage.GenerationCommit, exception);

    private static ReconnectCarrierFailure FailureFor(
        CarrierAcceptanceStage stage,
        Exception exception) =>
        stage switch
        {
            CarrierAcceptanceStage.Attachment =>
                ReconnectCarrierFailure.AttachmentRejected,
            CarrierAcceptanceStage.GenerationCommit =>
                ReconnectCarrierFailure.GenerationRejected,
            CarrierAcceptanceStage.SignedSession
                when exception is TransportProtocolException =>
                ReconnectCarrierFailure.SessionBindingRejected,
            CarrierAcceptanceStage.SignedSession
                when exception is CryptographicException =>
                ReconnectCarrierFailure.SessionAuthenticationFailed,
            _ => ReconnectCarrierFailure.ControlTransportFailed
        };

    private enum CarrierAcceptanceStage
    {
        Attachment,
        SignedSession,
        GenerationCommit
    }
    private static Guid ResolveSessionId(
        NodeEndpointRegistration endpoint)
    {
        if (string.Equals(
                endpoint.Transport.Kind,
                "rdp-dvc-control-carrier",
                StringComparison.Ordinal))
        {
            var binding = endpoint.Transport
                .DeserializeData<RdpDvcSessionBinding>(
                    StewardJson.Options)
                ?.Validate() ?? throw new InvalidDataException(
                    "The registered RDP DVC transport binding is invalid.");
            return binding.SessionId;
        }
        if (string.Equals(
                endpoint.Transport.Kind,
                LocalStackOptions.TransportKind,
                StringComparison.Ordinal))
        {
            var binding = endpoint.Transport
                .DeserializeData<LocalDirectTransportBinding>()
                ?.Validate() ??
                throw new InvalidDataException(
                    "The registered direct transport binding is invalid.");
            if (binding.SessionId is { } configured)
                return configured;
        }
        var bytes = System.Text.Encoding.UTF8.GetBytes(
            $"steward-direct:{endpoint.HostId}:" +
            endpoint.NodeIncarnationId);
        return new Guid(SHA256.HashData(bytes).AsSpan(0, 16));
    }

    private sealed record RdpDvcSessionBinding(
        int Version,
        Guid SessionId)
    {
        public RdpDvcSessionBinding Validate()
        {
            if (Version != 2 || SessionId == Guid.Empty)
                throw new InvalidDataException(
                    "The RDP DVC transport session binding is invalid.");
            return this;
        }
    }
}
