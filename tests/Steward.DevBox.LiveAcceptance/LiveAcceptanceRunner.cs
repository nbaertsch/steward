using System.Net;
using Azure;
using Azure.Core;
using Azure.Developer.DevCenter;
using Azure.Developer.DevCenter.Models;
using Azure.Identity;
using Steward.DevBox.Windows;
using Steward.Rdp.Windows;

namespace Steward.DevBox.LiveAcceptance;

internal sealed class LiveAcceptanceRunner
{
    private readonly LiveHarnessConfiguration _configuration;
    private readonly DurableEvidenceStore _store;
    private readonly List<GateEvidence> _gates = [];
    private readonly string _runId = Guid.NewGuid().ToString("N");
    private readonly DateTimeOffset _startedAtUtc = DateTimeOffset.UtcNow;

    public LiveAcceptanceRunner(LiveHarnessConfiguration configuration)
    {
        _configuration = configuration;
        _store = new(configuration.EvidenceDirectory);
    }

    private static string QueryKeys(Uri uri) =>
        string.Join(
            ',',
            uri.Query.TrimStart('?')
                .Split(
                    '&',
                    StringSplitOptions.RemoveEmptyEntries)
                .Select(item =>
                {
                    var separator = item.IndexOf('=');
                    var key = separator < 0
                        ? item
                        : item[..separator];
                    return Uri.UnescapeDataString(key);
                })
                .Where(key => key.All(character =>
                    char.IsAsciiLetterOrDigit(character) ||
                    character is '-' or '_'))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal));

    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        if (!_configuration.AllowBillableCreate)
            throw new InvalidOperationException(
                "Billable Dev Box creation was not explicitly authorized.");

        var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
        var credential = new DevBoxSilentTokenCredential(identity);
        var endpoint = _configuration.Endpoint;
        var client = new DevBoxesClient(endpoint, credential);
        var state = await LoadOrPlanAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (state.Phase == LiveRunPhase.DeleteStarted)
                throw new InvalidOperationException(
                    "A prior explicitly requested delete ended during its exact SDK LRO. Inspect state.json and the developer API before recovery.");
            if (state.Phase == LiveRunPhase.Deleted)
                throw new InvalidOperationException(
                    "This evidence state is complete. Select a new evidence directory for another billable run.");

            if (state.Phase == LiveRunPhase.Planned)
                state = _configuration.RecoverAcceptedCreate
                    ? await RecoverAcceptedCreateAsync(
                        client,
                        state,
                        cancellationToken).ConfigureAwait(false)
                    : await CreateExactlyOneAsync(
                        client,
                        state,
                        cancellationToken).ConfigureAwait(false);
            else if (state.Phase == LiveRunPhase.CreateStarted)
                state = await RecoverAcceptedCreateAsync(
                    client,
                    state,
                    cancellationToken).ConfigureAwait(false);
            else
            {
                var resumedAt = DateTimeOffset.UtcNow;
                _gates.Add(new(
                    "Test 1 - exact Dev Box create LRO",
                    GateOutcome.Passed,
                    resumedAt,
                    resumedAt,
                    "CREATE_PREVIOUSLY_RECONCILED_IN_DURABLE_STATE"));
            }

            if (_configuration.CreateOnly)
            {
                Console.WriteLine(
                    "CREATE-ONLY: Dev Box creation reconciled; no RDP activation was attempted.");
                return 0;
            }

            var rdpGate = await RunRdpGateAsync(
                client,
                identity,
                cancellationToken).ConfigureAwait(false);
            _gates.Add(rdpGate);
            if (rdpGate.Outcome == GateOutcome.Failed)
                return await FinishAsync(
                        GateOutcome.Failed,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (rdpGate.Outcome == GateOutcome.Pending)
                return await FinishAsync(
                        GateOutcome.Pending,
                        cancellationToken)
                    .ConfigureAwait(false);

            state = state with
            {
                Phase = LiveRunPhase.GatewayGatePassed,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);

            var pendingAt = DateTimeOffset.UtcNow;
            _gates.Add(new(
                "Test 5 - authenticated Steward DVC PING/PONG",
                GateOutcome.Pending,
                pendingAt,
                pendingAt,
                "DVC_LIVE_GATE_REQUIRES_OPERATOR_RECONNECT_EXTENSION"));
            state = state with
            {
                Phase = LiveRunPhase.DvcPending,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);

            if (_configuration.DeleteEvidenceBox)
                await DeleteEvidenceBoxAsync(client, state, cancellationToken)
                    .ConfigureAwait(false);

            return await FinishAsync(GateOutcome.Pending, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var now = DateTimeOffset.UtcNow;
            _gates.Add(new(
                "Harness",
                GateOutcome.Failed,
                now,
                now,
                FailureCode(exception)));
            await FinishAsync(GateOutcome.Failed, CancellationToken.None)
                .ConfigureAwait(false);
            throw;
        }
    }

    private async Task<DurableRunState> LoadOrPlanAsync(
        CancellationToken cancellationToken)
    {
        var existing = await _store.LoadStateAsync(cancellationToken)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            if (!string.Equals(
                    existing.ConfigurationFingerprint,
                    _configuration.Fingerprint(),
                    StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "The evidence directory belongs to different typed configuration.");
            if (!existing.HarnessOwnsBox &&
                existing.Phase != LiveRunPhase.Planned)
                throw new InvalidOperationException(
                    "The durable state does not prove that this harness owns the box.");
            return existing;
        }

        var now = DateTimeOffset.UtcNow;
        var state = new DurableRunState(
            1,
            _configuration.Fingerprint(),
            _configuration.Endpoint.GetLeftPart(UriPartial.Authority),
            _configuration.Project,
            _configuration.Pool,
            _configuration.User,
            _configuration.BoxName,
            false,
            LiveRunPhase.Planned,
            null,
            null,
            null,
            null,
            now,
            now);
        await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);
        return state;
    }

    private async Task<DurableRunState> CreateExactlyOneAsync(
        DevBoxesClient client,
        DurableRunState state,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        try
        {
            await client.GetDevBoxAsync(
                _configuration.Project,
                _configuration.User,
                _configuration.BoxName,
                cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException(
                "The configured box already exists and is not owned by this evidence state.");
        }
        catch (RequestFailedException exception) when (exception.Status == 404)
        {
        }

        Console.WriteLine(
            $"BILLABLE ACTION: creating one Dev Box '{_configuration.BoxName}' in the configured existing pool.");
        state = state with
        {
            Phase = LiveRunPhase.CreateStarted,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        await _store.SaveStateAsync(state, cancellationToken)
            .ConfigureAwait(false);
        var box = new Azure.Developer.DevCenter.Models.DevBox(
            _configuration.BoxName,
            _configuration.Project)
        {
            PoolName = _configuration.Pool
        };
        Operation<Azure.Developer.DevCenter.Models.DevBox> operation;
        try
        {
            operation = await client.CreateDevBoxAsync(
                WaitUntil.Started,
                _configuration.Project,
                _configuration.User,
                box,
                cancellationToken).ConfigureAwait(false);
        }
        catch (RequestFailedException exception)
            when (exception.Status is >= 400 and < 500)
        {
            state = state with
            {
                Phase = LiveRunPhase.Planned,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await _store.SaveStateAsync(state, CancellationToken.None)
                .ConfigureAwait(false);
            throw;
        }
        var statusUriHash = OperationStatusUriHash(operation.GetRawResponse());
        state = state with
        {
            HarnessOwnsBox = true,
            Phase = LiveRunPhase.CreateStarted,
            CreateOperationId = TryOperationId(operation),
            CreateStatusUriSha256 = statusUriHash,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);

        state = await WaitForBoxReadyAsync(
            client,
            state,
            cancellationToken).ConfigureAwait(false);
        _gates.Add(new(
            "Test 1 - exact Dev Box create LRO",
            GateOutcome.Passed,
            started,
            DateTimeOffset.UtcNow,
            "CREATE_LRO_SUCCEEDED"));
        return state;
    }

    private async Task<DurableRunState> RecoverAcceptedCreateAsync(
        DevBoxesClient client,
        DurableRunState state,
        CancellationToken cancellationToken)
    {
        var box = await client.GetDevBoxAsync(
            _configuration.Project,
            _configuration.User,
            _configuration.BoxName,
            cancellationToken).ConfigureAwait(false);
        var value = box.Value;
        if (!string.Equals(
                value.Name,
                _configuration.BoxName,
                StringComparison.Ordinal) ||
            !string.Equals(
                value.ProjectName,
                _configuration.Project,
                StringComparison.Ordinal) ||
            !string.Equals(
                value.PoolName,
                _configuration.Pool,
                StringComparison.Ordinal) ||
            value.CreatedTime is null ||
            value.CreatedTime < state.CreatedAtUtc)
            throw new InvalidDataException(
                "The existing Dev Box cannot be proven to belong to " +
                "this create intent.");
        state = state with
        {
            HarnessOwnsBox = true,
            Phase = LiveRunPhase.CreateStarted,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        await _store.SaveStateAsync(state, cancellationToken)
            .ConfigureAwait(false);
        state = await WaitForBoxReadyAsync(
            client,
            state,
            cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        _gates.Add(new(
            "Test 1 - recovered Dev Box create",
            GateOutcome.Passed,
            now,
            now,
            "CREATE_RECOVERED_BY_EXACT_RESOURCE_IDENTITY"));
        return state;
    }

    private async Task<DurableRunState> WaitForBoxReadyAsync(
        DevBoxesClient client,
        DurableRunState state,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(_configuration.CreateTimeout);
        try
        {
            while (true)
            {
                var response = await client.GetDevBoxAsync(
                    _configuration.Project,
                    _configuration.User,
                    _configuration.BoxName,
                    timeout.Token).ConfigureAwait(false);
                var box = response.Value;
                if (!string.Equals(
                        box.Name,
                        _configuration.BoxName,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        box.ProjectName,
                        _configuration.Project,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        box.PoolName,
                        _configuration.Pool,
                        StringComparison.Ordinal))
                    throw new InvalidDataException(
                        "Provider returned another Dev Box identity.");
                var provisioning = box.ProvisioningState?.ToString();
                if (provisioning is
                    "Succeeded" or "ProvisionedWithWarning")
                    break;
                if (provisioning is "Failed" or "Canceled")
                    throw new InvalidOperationException(
                        "The Dev Box create reached a terminal failure.");
                await Task.Delay(
                    TimeSpan.FromSeconds(5),
                    timeout.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The Dev Box create exceeded its configured timeout.");
        }
        state = state with
        {
            Phase = LiveRunPhase.BoxReady,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        await _store.SaveStateAsync(state, cancellationToken)
            .ConfigureAwait(false);
        return state;
    }

    private static string? TryOperationId(
        Operation<Azure.Developer.DevCenter.Models.DevBox> operation)
    {
        try
        {
            return operation.Id;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    private async Task<GateEvidence> RunRdpGateAsync(
        DevBoxesClient client,
        DevBoxIdentityService identity,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var remote = await client.GetRemoteConnectionAsync(
            _configuration.Project,
            _configuration.User,
            _configuration.BoxName,
            cancellationToken).ConfigureAwait(false);
        var uri = remote.Value.RdpConnectionUri ??
            throw new InvalidDataException(
                "GetRemoteConnection returned no rdpConnectionUrl.");
        if (uri.Scheme == "ms-avd")
        {
            return new(
                "Test 3 - headless Windows App ms-avd transport",
                GateOutcome.Failed,
                started,
                DateTimeOffset.UtcNow,
                "HEADLESS_MS_AVD_UNSUPPORTED_VISIBLE_ACTIVATION_REQUIRED");
        }
        if (!uri.IsAbsoluteUri ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.Port != 443 ||
            uri.UserInfo.Length != 0 ||
            uri.Fragment.Length != 0)
            throw new InvalidDataException(
                $"RDP connection URI metadata rejected: scheme " +
                $"'{uri.Scheme}', port '{uri.Port}', userInfo " +
                $"'{uri.UserInfo.Length != 0}', fragment " +
                $"'{uri.Fragment.Length != 0}', pathLength " +
                $"'{uri.AbsolutePath.Length}', queryKeys " +
                $"'{QueryKeys(uri)}'.");
        var remoteFinished = DateTimeOffset.UtcNow;
        _gates.Add(new(
            "Test 2 - typed Dev Box remote connection",
            GateOutcome.Passed,
            started,
            remoteFinished,
            "GET_REMOTE_CONNECTION_SUCCEEDED"));
        var (_, _, token) = await identity.OpenAsync(cancellationToken)
            .ConfigureAwait(false);
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(30)
        };
        using var invoker = new HttpMessageInvoker(handler);
        var fetcher = new RdpContentFetcher(invoker);
        using var downloadTimeout =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        downloadTimeout.CancelAfter(TimeSpan.FromSeconds(60));
        byte[] content;
        try
        {
            content = await fetcher.FetchAsync(
                uri,
                _configuration.Endpoint,
                token,
                downloadTimeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The bounded RDP profile download timed out.");
        }
        var profile = RdpFileParser.Parse(content);
        Array.Clear(content);
        var parsedAt = DateTimeOffset.UtcNow;
        _gates.Add(new(
            "Test 3 - signed RDP boundary",
            GateOutcome.Passed,
            remoteFinished,
            parsedAt,
            "SIGNED_RDP_PROFILE_ACCEPTED"));

        Console.WriteLine(
            "Test 4: starting the minimized mstscax RD Gateway login gate; no credential or token is logged.");
        var session = new MstscActiveXSession();
        var result = await session.ConnectAsync(
            profile,
            new(
                _configuration.RdpConnectionTimeout,
                _configuration.RdpLoginTimeout,
                TimeSpan.FromSeconds(10)),
            diagnostic => Console.WriteLine(
                diagnostic.Code.HasValue
                    ? $"RDP EVENT {diagnostic.Name} code={diagnostic.Code} extended={diagnostic.ExtendedCode}"
                    : $"RDP EVENT {diagnostic.Name}"),
            cancellationToken).ConfigureAwait(false);
        return new(
            "Test 4 - mstscax RD Gateway login handshake",
            result.Succeeded ? GateOutcome.Passed : GateOutcome.Failed,
            started,
            DateTimeOffset.UtcNow,
            result.Succeeded
                ? "RDP_GATEWAY_LOGIN_SUCCEEDED"
                : $"RDP_{result.FailureKind.ToString().ToUpperInvariant()}",
            result.Events,
            result.DisconnectReason,
            result.ExtendedDisconnectReason,
            result.FatalErrorCode,
            result.LogonErrorCode,
            result.GatewayUseObserved,
            result.GatewayRemoteEndpoint);
    }

    private async Task DeleteEvidenceBoxAsync(
        DevBoxesClient client,
        DurableRunState state,
        CancellationToken cancellationToken)
    {
        Console.WriteLine(
            "EXPLICIT CLEANUP: deleting the harness-owned evidence box after the gateway gate passed.");
        var operation = await client.DeleteDevBoxAsync(
            WaitUntil.Started,
            _configuration.Project,
            _configuration.User,
            _configuration.BoxName,
            new RequestContext { CancellationToken = cancellationToken })
            .ConfigureAwait(false);
        state = state with
        {
            Phase = LiveRunPhase.DeleteStarted,
            DeleteOperationId = operation.Id,
            DeleteStatusUriSha256 = OperationStatusUriHash(operation.GetRawResponse()),
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(_configuration.CreateTimeout);
        try
        {
            while (!operation.HasCompleted)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), timeout.Token)
                    .ConfigureAwait(false);
                await operation.UpdateStatusAsync(timeout.Token).ConfigureAwait(false);
                if (!string.Equals(operation.Id, state.DeleteOperationId, StringComparison.Ordinal))
                    throw new InvalidDataException(
                        "The SDK changed the operation ID during exact delete LRO reconciliation.");
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The exact Dev Box delete LRO exceeded its configured timeout.");
        }
        state = state with
        {
            HarnessOwnsBox = false,
            Phase = LiveRunPhase.Deleted,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);
    }

    private async Task<int> FinishAsync(
        GateOutcome outcome,
        CancellationToken cancellationToken)
    {
        var evidence = new AcceptanceEvidence(
            1,
            _runId,
            _startedAtUtc,
            DateTimeOffset.UtcNow,
            _configuration.Endpoint.GetLeftPart(UriPartial.Authority),
            _configuration.Project,
            _configuration.Pool,
            _configuration.User,
            _configuration.BoxName,
            _configuration.AllowBillableCreate,
            _configuration.DeleteEvidenceBox,
            typeof(DevBoxesClient).Assembly.GetName().Version?.ToString() ?? "unknown",
            "Windows mstscax.dll; typed COM declarations generated from the installed Microsoft type library",
            _gates.ToArray(),
            outcome);
        await _store.SaveEvidenceAsync(evidence, cancellationToken)
            .ConfigureAwait(false);
        return outcome switch
        {
            GateOutcome.Passed => 0,
            GateOutcome.Pending => 2,
            _ => 1
        };
    }

    private static string? OperationStatusUriHash(Response response)
    {
        if (response.Headers.TryGetValue("Operation-Location", out var location))
            return Hash(location);
        var value = response.Headers.TryGetValue("Azure-AsyncOperation", out var alternate)
            ? alternate
            : null;
        return value is null ? null : Hash(value);
    }

    private static string Hash(string value) =>
        Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(value)));

    private static string FailureCode(Exception exception) => exception switch
    {
        RequestFailedException failed =>
            $"DEV_CENTER_HTTP_{failed.Status}_{SafeCode(failed.ErrorCode)}",
        AuthenticationFailedException => "DEVBOX_DEFAULT_AUTHENTICATION_FAILED",
        TimeoutException => "HARNESS_TIMEOUT",
        InvalidDataException invalid =>
            $"INVALID_PROVIDER_OR_RDP_DATA_{SafeCode(invalid.Message)}",
        InvalidOperationException => "HARNESS_PRECONDITION_FAILED",
        _ => "UNCLASSIFIED_HARNESS_FAILURE"
    };

    private static string SafeCode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "UNKNOWN";
        var result = new string(value
            .Where(character => char.IsAsciiLetterOrDigit(character))
            .Take(160)
            .ToArray());
        return result.Length == 0
            ? "UNKNOWN"
            : result.ToUpperInvariant();
    }
}
