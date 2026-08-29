using Steward.ConnectionHost.Windows;
using Steward.DevBox.Windows;
using Steward.RdCore.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.RdpDvc.LiveAcceptance;

internal interface IConnectionHostCommandClient
{
    Task<ConnectionHostResponse> SendAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken);
}

internal sealed class PipeConnectionHostCommandClient(
    ConnectionHostPipeClient client) : IConnectionHostCommandClient
{
    public Task<ConnectionHostResponse> SendAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken) =>
        client.SendAsync(command, cancellationToken);
}

internal sealed class LiveAcceptanceRunner(
    LiveAcceptanceOptions options,
    Uri providerResource,
    LivePreflightEvidence preflight,
    IConnectionHostCommandClient client,
    IDvcGenerationAttestationSource attestations,
    Func<ISurfaceGuard> surfaceGuardFactory,
    IReadOnlyList<string> authorizationTokens,
    IReadOnlyList<string> evidenceReferences)
{
    private static readonly RdCoreDvcEvidenceEvent[] RequiredEvidence =
        Enum.GetValues<RdCoreDvcEvidenceEvent>();

    internal async Task<RdCoreLiveAcceptanceEvidence> RunAsync(
        CancellationToken cancellationToken)
    {
        if (!options.HasRequiredConsent)
            throw new InvalidOperationException(
                "Exact live-connect and cloud-read consent are required.");
        ValidatePreflight(preflight, options.InvokeBootstrapDeploy);
        if (authorizationTokens.Count != 2 ||
            authorizationTokens.Any(string.IsNullOrWhiteSpace) ||
            string.Equals(
                authorizationTokens[0],
                authorizationTokens[1],
                StringComparison.Ordinal))
            throw new InvalidDataException(
                "Two distinct single-use authorization tokens are required.");
        if (evidenceReferences.Count != 2 ||
            evidenceReferences.Distinct(StringComparer.Ordinal).Count() != 2)
            throw new InvalidDataException(
                "Two distinct remote-bootstrap evidence references are required.");

        var started = DateTimeOffset.UtcNow;
        var runId = Guid.NewGuid().ToString("N");
        var connectionId =
            $"rdcore-live-{Guid.NewGuid():N}";
        Console.Error.WriteLine("LIVE STAGE: resolve-prepare-1");
        await ResolveAndPrepareAsync(
                connectionId,
                cancellationToken)
            .ConfigureAwait(false);

        await using var guard = surfaceGuardFactory();
        var generations = new List<LiveGenerationEvidence>(2);
        try
        {
            Console.Error.WriteLine("LIVE STAGE: guarded-connect-1");
            var first = await ConnectGuardedAsync(
                    connectionId,
                    authorizationTokens[0],
                    evidenceReferences[0],
                    guard,
                    cancellationToken)
                .ConfigureAwait(false);
            generations.Add(ToEvidence(1, first));
            await DisconnectAsync(
                    connectionId,
                    first.ConnectionGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
            await attestations.CloseAsync(
                    first.ConnectionGeneration,
                    cancellationToken)
                .ConfigureAwait(false);

            Console.Error.WriteLine("LIVE STAGE: resolve-prepare-2");
            await ResolveAndPrepareAsync(
                    connectionId,
                    cancellationToken)
                .ConfigureAwait(false);
            guard.ThrowIfViolated();
            Console.Error.WriteLine("LIVE STAGE: guarded-connect-2");
            var second = await ConnectGuardedAsync(
                    connectionId,
                    authorizationTokens[1],
                    evidenceReferences[1],
                    guard,
                    cancellationToken)
                .ConfigureAwait(false);
            if (second.ConnectionGeneration <=
                    first.ConnectionGeneration ||
                second.Nonce == first.Nonce)
                throw new InvalidDataException(
                    "Reconnect did not advance both generation and DVC nonce.");
            generations.Add(ToEvidence(2, second));
            await DisconnectAsync(
                    connectionId,
                    second.ConnectionGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
            await attestations.CloseAsync(
                    second.ConnectionGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
            guard.ThrowIfViolated();
            var final = guard.Observe();
            guard.ThrowIfViolated();
            return new(
                1,
                runId,
                started,
                DateTimeOffset.UtcNow,
                true,
                true,
                options.InvokeBootstrapDeploy,
                false,
                false,
                false,
                StewardRdpDvc.PluginClsid.ToString("B"),
                StewardRdpDvc.AddInName,
                StewardRdpDvc.ChannelName,
                preflight,
                guard.Initial,
                final,
                generations,
                true,
                true,
                true);
        }
        catch
        {
            guard.ThrowIfViolated();
            throw;
        }
    }

    private async Task ResolveAndPrepareAsync(
        string connectionId,
        CancellationToken cancellationToken)
    {
        Console.Error.WriteLine("LIVE RESOLVE STAGE: resolve-command");
        var resolved = await SendAcceptedAsync(
                new(
                    ConnectionHostProtocol.CurrentVersion,
                    RequestId(),
                    ConnectionHostOperation.Resolve,
                    connectionId,
                    providerResource.AbsoluteUri),
                cancellationToken)
            .ConfigureAwait(false);
        RequireStatus(
            resolved,
            RdpDvcSessionState.Resolving,
            "CONNECTION_HOST_RESOLVED",
            dvcConnected: false);
        Console.Error.WriteLine("LIVE RESOLVE STAGE: prepare-command");
        var prepared = await SendAcceptedAsync(
                new(
                    ConnectionHostProtocol.CurrentVersion,
                    RequestId(),
                    ConnectionHostOperation.Prepare,
                    connectionId),
                cancellationToken)
            .ConfigureAwait(false);
        RequireStatus(
            prepared,
            RdpDvcSessionState.Resolving,
            "CONNECTION_HOST_PREPARED",
            dvcConnected: false);
        Console.Error.WriteLine("LIVE RESOLVE STAGE: complete");
    }

    private async Task<DvcGenerationAttestation> ConnectGuardedAsync(
        string connectionId,
        string authorizationToken,
        string evidenceReference,
        ISurfaceGuard guard,
        CancellationToken cancellationToken)
    {
        guard.ThrowIfViolated();
        using var connectCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        var connect = SendAcceptedAsync(
            new(
                ConnectionHostProtocol.CurrentVersion,
                RequestId(),
                ConnectionHostOperation.Connect,
                connectionId,
                AuthorizationToken: authorizationToken,
                DvcEvidenceReference: evidenceReference),
            connectCancellation.Token);
        var completed = await Task.WhenAny(
                connect,
                guard.Violation.WaitAsync(cancellationToken))
            .ConfigureAwait(false);
        if (completed != connect)
        {
            connectCancellation.Cancel();
            guard.ThrowIfViolated();
            throw new HeadlessSurfaceViolationException(
                "The surface guard stopped Connect.",
                new InvalidOperationException(
                    "The surface guard ended without a recorded violation."));
        }
        var response = await connect.ConfigureAwait(false);
        guard.ThrowIfViolated();
        var status = RequireStatus(
            response,
            RdpDvcSessionState.ConnectedTransport,
            "RDP_DVC_CONNECTED_TRANSPORT",
            dvcConnected: true);
        if (status.ConnectionGeneration is not { } generation)
            throw new InvalidDataException(
                "Connected transport did not return a generation.");
        var attestation = attestations.Get(generation);
        ValidateAttestation(attestation, generation);
        return attestation;
    }

    private async Task DisconnectAsync(
        string connectionId,
        long generation,
        CancellationToken cancellationToken)
    {
        var response = await SendAcceptedAsync(
                new(
                    ConnectionHostProtocol.CurrentVersion,
                    RequestId(),
                    ConnectionHostOperation.Disconnect,
                    connectionId,
                    ConnectionGeneration: generation),
                cancellationToken)
            .ConfigureAwait(false);
        RequireStatus(
            response,
            RdpDvcSessionState.Disconnected,
            "RDP_DVC_DISCONNECTED",
            dvcConnected: false);
    }

    private async Task<ConnectionHostResponse> SendAcceptedAsync(
        ConnectionHostCommand command,
        CancellationToken cancellationToken)
    {
        if (command.Operation is
            ConnectionHostOperation.View or
            ConnectionHostOperation.TakeControl)
            throw new InvalidOperationException(
                "Live acceptance never authorizes a visible surface.");
        var response = await client.SendAsync(command, cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            $"LIVE COMMAND RESULT: operation={command.Operation}; " +
            $"accepted={response.Accepted}; code={response.Code}; " +
            $"state={response.Status?.State.ToString() ?? "none"}");
        if (!response.Accepted ||
            response.Version !=
                ConnectionHostProtocol.CurrentVersion ||
            !string.Equals(
                response.RequestId,
                command.RequestId,
                StringComparison.Ordinal))
            throw new InvalidDataException(
                $"ConnectionHost rejected {command.Operation} with code {response.Code}.");
        return response;
    }

    private static ConnectionHostStatus RequireStatus(
        ConnectionHostResponse response,
        RdpDvcSessionState state,
        string code,
        bool dvcConnected)
    {
        var status = response.Status ??
            throw new InvalidDataException(
                "ConnectionHost omitted typed status.");
        if (status.Version != ConnectionHostProtocol.CurrentVersion ||
            status.State != state ||
            status.DvcConnected != dvcConnected ||
            !string.Equals(status.Code, code, StringComparison.Ordinal))
            throw new InvalidDataException(
                "ConnectionHost returned an unexpected bounded state.");
        return status;
    }

    private static void ValidateAttestation(
        DvcGenerationAttestation attestation,
        long generation)
    {
        if (attestation.ConnectionGeneration != generation ||
            attestation.RdpSessionId <= 0 ||
            attestation.Nonce == Guid.Empty ||
            attestation.PingSequence != 1 ||
            (attestation.PingRoundTripTime is { } roundTrip &&
             roundTrip < TimeSpan.Zero) ||
            !attestation.OrderedEvidence.SequenceEqual(RequiredEvidence))
            throw new InvalidDataException(
                "RDCore/DVC evidence was incomplete, out of order, or not bound to the generation.");
    }

    private static void ValidatePreflight(
        LivePreflightEvidence evidence,
        bool expectedDeployInvocation)
    {
        if (!evidence.PackageCompatible ||
            string.IsNullOrWhiteSpace(evidence.PackageFullName) ||
            string.IsNullOrWhiteSpace(evidence.PackageVersion) ||
            !evidence.DevBoxDefaultIdentityReady ||
            !string.Equals(
                evidence.IdentityContext,
                DevBoxConnectionIdentityConstants.ContextName,
                StringComparison.Ordinal) ||
            !evidence.ExactDvcRegistration ||
            !string.Equals(
                evidence.DvcRegistrationCode,
                RdpDvcPluginRegistration
                    .RegisteredActivationPendingCode,
                StringComparison.Ordinal) ||
            evidence.BootstrapDeployInvoked !=
                expectedDeployInvocation ||
            evidence.BootstrapDeploymentReceiptSha256.Length != 64 ||
            evidence.BootstrapDeploymentReceiptSha256.Any(
                static character => !Uri.IsHexDigit(character)))
            throw new InvalidDataException(
                "Package, identity, exact DVC registration, and signed pre-connect bootstrap receipt must all pass.");
    }

    private static LiveGenerationEvidence ToEvidence(
        int ordinal,
        DvcGenerationAttestation attestation) =>
        new(
            ordinal,
            attestation.ConnectionGeneration,
            attestation.RdpSessionId,
            RemoteBootstrapEvidenceLoader.Hash(
                attestation.Nonce.ToByteArray()),
            attestation.PingSequence,
            attestation.PingRoundTripTime?.TotalMilliseconds,
            attestation.OrderedEvidence,
            "RDP_DVC_CONNECTED_TRANSPORT");

    private static string RequestId() => Guid.NewGuid().ToString("N");
}
