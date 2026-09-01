using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Steward.Contracts;

public static class EndpointStateFiles
{
    public const string ReconnectLedgerV2 = "reconnect-ledger.v2.db";
    public const string V2Health = "endpoint-health.v2.json";
    public const string RetainedV1Health = "readiness.json";
}

public enum EndpointV2HealthState
{
    WaitingForActiveRdpSession = 0,
    WaitingForReconnect = 1,
    CarrierHandshaking = 2,
    SecureHandshaking = 3,
    Authenticated = 4,
    Reconnecting = 5,
    Failed = 6
}

public sealed record EndpointV2Health(
    int Version,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    string NodeIdentity,
    string ControlIdentity,
    EndpointV2HealthState State,
    long ReconnectGeneration,
    Guid? AttemptId,
    int? WtsSessionId,
    DateTimeOffset UpdatedAtUtc,
    int ProcessId,
    DateTimeOffset ProcessStartedAtUtc);

public sealed record AuthenticatedEndpointV2Health(
    int Version,
    EndpointV2Health Observation,
    string AuthenticationTag);

public static class EndpointV2HealthAuthenticator
{
    public const int Version = 1;
    private static readonly JsonSerializerOptions Json = CreateJson();

    public static AuthenticatedEndpointV2Health Authenticate(
        EndpointV2Health observation,
        ReadOnlySpan<byte> authenticationKey)
    {
        EndpointV2HealthContract.Validate(observation);
        ValidateKey(authenticationKey);
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            observation,
            Json);
        try
        {
            var tag = HMACSHA256.HashData(authenticationKey, canonical);
            try
            {
                return new AuthenticatedEndpointV2Health(
                    Version,
                    observation,
                    Convert.ToBase64String(tag));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(tag);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static EndpointV2Health Verify(
        AuthenticatedEndpointV2Health authenticated,
        ReadOnlySpan<byte> authenticationKey)
    {
        ArgumentNullException.ThrowIfNull(authenticated);
        ValidateKey(authenticationKey);
        if (authenticated.Version != Version ||
            authenticated.Observation is null ||
            string.IsNullOrWhiteSpace(authenticated.AuthenticationTag) ||
            authenticated.AuthenticationTag.Length > 64)
            throw new InvalidDataException(
                "The authenticated endpoint health envelope is invalid.");
        EndpointV2HealthContract.Validate(authenticated.Observation);
        byte[] tag;
        try
        {
            tag = Convert.FromBase64String(authenticated.AuthenticationTag);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "The endpoint health authenticator is malformed.",
                exception);
        }
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            authenticated.Observation,
            Json);
        try
        {
            var expected = HMACSHA256.HashData(
                authenticationKey,
                canonical);
            try
            {
                if (tag.Length != expected.Length ||
                    !CryptographicOperations.FixedTimeEquals(tag, expected))
                    throw new InvalidDataException(
                        "The endpoint health authenticator is invalid.");
                return authenticated.Observation;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expected);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private static void ValidateKey(ReadOnlySpan<byte> authenticationKey)
    {
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "Endpoint health authentication requires a 256-bit key.",
                nameof(authenticationKey));
    }

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.CamelCase,
            allowIntegerValues: false));
        return options;
    }
}

public static class EndpointV2HealthContract
{
    public const int Version = 2;

    public static void Validate(EndpointV2Health value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Version != Version ||
            value.SessionId == Guid.Empty ||
            value.HostId == Guid.Empty ||
            value.NodeIncarnationId == Guid.Empty ||
            !ValidIdentity(value.NodeIdentity) ||
            !ValidIdentity(value.ControlIdentity) ||
            !Enum.IsDefined(value.State) ||
            value.ReconnectGeneration < 0 ||
            value.ReconnectGeneration == 0 && value.AttemptId is not null ||
            value.ReconnectGeneration > 0 && value.AttemptId is null ||
            value.AttemptId == Guid.Empty ||
            value.WtsSessionId is <= 0 ||
            value.ProcessId <= 0 ||
            value.UpdatedAtUtc.Offset != TimeSpan.Zero ||
            value.UpdatedAtUtc <= DateTimeOffset.UnixEpoch ||
            value.ProcessStartedAtUtc.Offset != TimeSpan.Zero ||
            value.ProcessStartedAtUtc <= DateTimeOffset.UnixEpoch ||
            value.ProcessStartedAtUtc > value.UpdatedAtUtc)
            throw new InvalidDataException(
                "The endpoint v2 health contract is invalid.");
        if (value.State == EndpointV2HealthState.Authenticated &&
            (value.ReconnectGeneration <= 0 ||
             value.AttemptId is null ||
             value.WtsSessionId is null))
            throw new InvalidDataException(
                "Authenticated endpoint v2 health lacks attempt evidence.");
    }

    private static bool ValidIdentity(string value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 200 &&
        value.All(character =>
            char.IsAsciiLetterOrDigit(character) ||
            character is '.' or '_' or ':' or '@' or '/' or '-');
}

