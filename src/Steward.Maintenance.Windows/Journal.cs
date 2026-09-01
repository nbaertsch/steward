using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Steward.Maintenance.Windows;

internal sealed record MaintenanceJournalEntry(
    int Version,
    Guid RequestId,
    Guid OperationId,
    string OperationSha256,
    MaintenanceOperation Operation,
    MaintenanceOperationStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string? Continuation,
    string? ErrorCode);

internal sealed class FileMaintenanceJournal
{
    private const int MaximumJournalBytes = 4 * 1024 * 1024;
    private readonly string path;
    private readonly byte[] authenticationKey;
    private readonly object gate = new();
    private static readonly JsonSerializerOptions Json = CreateJson();

    public FileMaintenanceJournal(
        string path,
        ReadOnlySpan<byte> authenticationKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "Maintenance journal key must be 256 bits.",
                nameof(authenticationKey));
        this.path = Path.GetFullPath(path);
        this.authenticationKey = authenticationKey.ToArray();
    }

    public MaintenanceJournalEntry Begin(MaintenanceRequestBody body)
    {
        MaintenanceContract.Validate(body);
        var operationBytes = MaintenanceContract.CanonicalizeOperation(
            body.Operation);
        var operationHash = Convert.ToHexString(
            SHA256.HashData(operationBytes));
        CryptographicOperations.ZeroMemory(operationBytes);
        lock (gate)
        {
            var snapshot = LoadUnsafe();
            var key = new MaintenanceDeliveryKey(
                body.RequestId,
                body.OperationId,
                new MaintenanceOperationDigest(operationHash));
            var byRequest = snapshot.Entries.SingleOrDefault(
                entry => entry.RequestId == body.RequestId);
            if (byRequest is not null &&
                (byRequest.OperationId != key.OperationId ||
                 !string.Equals(
                     byRequest.OperationSha256,
                     key.OperationDigest.Sha256,
                     StringComparison.Ordinal)))
                throw new MaintenanceProtocolException(
                    "request_id_conflict",
                    "Request ID is bound to another maintenance operation.");
            var existing = snapshot.Entries.SingleOrDefault(
                entry => entry.OperationId == body.OperationId);
            if (existing is not null)
            {
                if (!string.Equals(
                        existing.OperationSha256,
                        operationHash,
                        StringComparison.Ordinal) ||
                    existing.RequestId != Guid.Empty &&
                    existing.RequestId != body.RequestId)
                    throw new MaintenanceProtocolException(
                        "operation_id_conflict",
                        "Operation ID is bound to different content.");
                if (existing.RequestId == Guid.Empty)
                {
                    var entries = snapshot.Entries.ToArray();
                    var index = Array.IndexOf(entries, existing);
                    existing = existing with
                    {
                        Version = 2,
                        RequestId = body.RequestId
                    };
                    entries[index] = existing;
                    SaveUnsafe(new JournalSnapshot(2, entries));
                }
                return existing;
            }
            if (snapshot.Entries.Count >= 4096)
                throw new MaintenanceProtocolException(
                    "journal_capacity",
                    "Maintenance journal capacity is exhausted.");
            var now = DateTimeOffset.UtcNow;
            var entry = new MaintenanceJournalEntry(
                2,
                body.RequestId,
                body.OperationId,
                operationHash,
                body.Operation,
                MaintenanceOperationStatus.Accepted,
                now,
                now,
                null,
                null);
            SaveUnsafe(new JournalSnapshot(
                2,
                snapshot.Entries.Append(entry).ToArray()));
            return entry;
        }
    }

    public MaintenanceJournalEntry Transition(
        Guid operationId,
        MaintenanceOperationStatus status,
        string? continuation = null,
        string? errorCode = null)
    {
        if (operationId == Guid.Empty || !Enum.IsDefined(status))
            throw new ArgumentException(
                "Maintenance journal transition is invalid.");
        ValidateBoundedOptional(continuation, 256, nameof(continuation));
        ValidateBoundedOptional(errorCode, 64, nameof(errorCode));
        lock (gate)
        {
            var snapshot = LoadUnsafe();
            var index = snapshot.Entries.ToList().FindIndex(
                entry => entry.OperationId == operationId);
            if (index < 0)
                throw new KeyNotFoundException(
                    "Maintenance operation is not journaled.");
            var current = snapshot.Entries[index];
            if (!IsTransitionAllowed(current.Status, status))
                throw new InvalidOperationException(
                    "Maintenance journal state transition is invalid.");
            var updated = current with
            {
                Status = status,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                Continuation = continuation,
                ErrorCode = errorCode
            };
            var entries = snapshot.Entries.ToArray();
            entries[index] = updated;
            SaveUnsafe(snapshot with { Entries = entries });
            return updated;
        }
    }

    public MaintenanceJournalEntry? Get(Guid operationId)
    {
        lock (gate)
            return LoadUnsafe().Entries.SingleOrDefault(
                entry => entry.OperationId == operationId);
    }

    public IReadOnlyList<MaintenanceJournalEntry> Pending()
    {
        lock (gate)
            return LoadUnsafe().Entries
                .Where(entry => entry.Status is
                    MaintenanceOperationStatus.Accepted or
                    MaintenanceOperationStatus.Running or
                    MaintenanceOperationStatus.AwaitingReboot)
                .OrderBy(entry => entry.CreatedAtUtc)
                .ToArray();
    }

    private JournalSnapshot LoadUnsafe()
    {
        if (!File.Exists(path))
            return new JournalSnapshot(2, []);
        ValidateRegularFile(path);
        var file = File.ReadAllBytes(path);
        if (file.Length is <= 0 or > MaximumJournalBytes)
            throw new InvalidDataException(
                "Maintenance journal size is invalid.");
        try
        {
            var envelope = JsonSerializer.Deserialize<JournalEnvelope>(
                               file,
                               Json)
                           ?? throw new InvalidDataException(
                               "Maintenance journal is empty.");
            if (envelope.Version != 1 ||
                string.IsNullOrWhiteSpace(envelope.Payload) ||
                string.IsNullOrWhiteSpace(envelope.AuthenticationTag))
                throw new InvalidDataException(
                    "Maintenance journal envelope is invalid.");
            var payload = Convert.FromBase64String(envelope.Payload);
            var tag = Convert.FromBase64String(envelope.AuthenticationTag);
            try
            {
                var expected = HMACSHA256.HashData(
                    authenticationKey,
                    payload);
                try
                {
                    if (tag.Length != expected.Length ||
                        !CryptographicOperations.FixedTimeEquals(tag, expected))
                        throw new InvalidDataException(
                            "Maintenance journal authentication failed.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                }
                var snapshot = JsonSerializer.Deserialize<JournalSnapshot>(
                                   payload,
                                   Json)
                               ?? throw new InvalidDataException(
                                   "Maintenance journal payload is empty.");
                ValidateSnapshot(snapshot);
                return snapshot;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(tag);
            }
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Maintenance journal is malformed.",
                exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Maintenance journal encoding is malformed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(file);
        }
    }

    private void SaveUnsafe(JournalSnapshot snapshot)
    {
        ValidateSnapshot(snapshot);
        var directory = Path.GetDirectoryName(path) ??
            throw new InvalidDataException(
                "Maintenance journal has no parent directory.");
        Directory.CreateDirectory(directory);
        MaintenanceStateSecurity.ValidatePath(directory);
        var payload = JsonSerializer.SerializeToUtf8Bytes(snapshot, Json);
        var tag = HMACSHA256.HashData(authenticationKey, payload);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(
            new JournalEnvelope(
                1,
                Convert.ToBase64String(payload),
                Convert.ToBase64String(tag)),
            Json);
        var pending = path + ".new";
        try
        {
            if (envelope.Length > MaximumJournalBytes)
                throw new InvalidDataException(
                    "Maintenance journal exceeds its size bound.");
            using (var stream = new FileStream(
                       pending,
                       FileMode.Create,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(envelope);
                stream.Flush(flushToDisk: true);
            }
            File.Move(pending, path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(envelope);
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }

    private static void ValidateSnapshot(JournalSnapshot snapshot)
    {
        if (snapshot.Version is not (1 or 2) ||
            snapshot.Entries.Count > 4096 ||
            snapshot.Entries.Select(entry => entry.OperationId)
                .Distinct().Count() != snapshot.Entries.Count ||
            snapshot.Entries.Where(entry => entry.RequestId != Guid.Empty)
                .Select(entry => entry.RequestId).Distinct().Count() !=
            snapshot.Entries.Count(entry => entry.RequestId != Guid.Empty))
            throw new InvalidDataException(
                "Maintenance journal snapshot is invalid.");
        foreach (var entry in snapshot.Entries)
        {
            if (entry.Version is not (1 or 2) ||
                entry.Version == 1 && entry.RequestId != Guid.Empty ||
                entry.Version == 2 && entry.RequestId == Guid.Empty ||
                entry.OperationId == Guid.Empty ||
                entry.OperationSha256.Length != 64 ||
                entry.OperationSha256.Any(
                    character => !char.IsAsciiHexDigit(character)) ||
                !Enum.IsDefined(entry.Status))
                throw new InvalidDataException(
                    "Maintenance journal entry is invalid.");
            MaintenanceContract.ValidateOperation(entry.Operation);
            var operation = MaintenanceContract.CanonicalizeOperation(
                entry.Operation);
            try
            {
                var expected = Convert.ToHexString(SHA256.HashData(operation));
                if (!string.Equals(
                        expected,
                        entry.OperationSha256,
                        StringComparison.Ordinal))
                    throw new InvalidDataException(
                        "Maintenance journal operation hash is invalid.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(operation);
            }
            ValidateBoundedOptional(
                entry.Continuation,
                256,
                nameof(entry.Continuation));
            ValidateBoundedOptional(
                entry.ErrorCode,
                64,
                nameof(entry.ErrorCode));
        }
    }

    private static bool IsTransitionAllowed(
        MaintenanceOperationStatus current,
        MaintenanceOperationStatus next) =>
        current == next || (current, next) switch
        {
            (MaintenanceOperationStatus.Accepted,
                MaintenanceOperationStatus.Running or
                MaintenanceOperationStatus.Failed) => true,
            (MaintenanceOperationStatus.Running,
                MaintenanceOperationStatus.AwaitingReboot or
                MaintenanceOperationStatus.Succeeded or
                MaintenanceOperationStatus.Failed) => true,
            (MaintenanceOperationStatus.AwaitingReboot,
                MaintenanceOperationStatus.Running or
                MaintenanceOperationStatus.Succeeded or
                MaintenanceOperationStatus.Failed) => true,
            _ => false
        };

    private static void ValidateRegularFile(string file)
    {
        MaintenanceStateSecurity.ValidatePath(
            Path.GetDirectoryName(file) ?? string.Empty);
        if (File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "Maintenance journal cannot be a reparse point.");
    }

    private static void ValidateBoundedOptional(
        string? value,
        int maximum,
        string name)
    {
        if (value is not null &&
            (value.Length == 0 || value.Length > maximum ||
             value.Any(char.IsControl)))
            throw new ArgumentException(
                "Maintenance journal metadata is invalid.",
                name);
    }

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            MaxDepth = 16,
            PropertyNameCaseInsensitive = false
        };
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.CamelCase,
            allowIntegerValues: false));
        return options;
    }

    private sealed record JournalSnapshot(
        int Version,
        IReadOnlyList<MaintenanceJournalEntry> Entries);

    private sealed record JournalEnvelope(
        int Version,
        string Payload,
        string AuthenticationTag);
}

