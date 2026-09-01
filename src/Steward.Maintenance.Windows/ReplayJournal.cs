using System.Security.Cryptography;
using System.Text.Json;

namespace Steward.Maintenance.Windows;

internal sealed class FileMaintenanceReplayStore : IMaintenanceReplayStore
{
    private const int MaximumBytes = 1024 * 1024;
    private readonly string path;
    private readonly byte[] authenticationKey;
    private readonly int capacity;
    private readonly object gate = new();

    public FileMaintenanceReplayStore(
        string path,
        ReadOnlySpan<byte> authenticationKey,
        int capacity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "Maintenance replay key must be 256 bits.",
                nameof(authenticationKey));
        if (capacity is < 1 or > 65_536)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        this.path = Path.GetFullPath(path);
        this.authenticationKey = authenticationKey.ToArray();
        this.capacity = capacity;
    }

    public bool TryAccept(
        Guid requestId,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset nowUtc)
    {
        if (requestId == Guid.Empty || expiresAtUtc <= nowUtc)
            return false;
        lock (gate)
        {
            var entries = Load()
                .Where(entry => entry.ExpiresAtUtc >= nowUtc)
                .ToList();
            if (entries.Any(entry => entry.RequestId == requestId))
                return false;
            if (entries.Count >= capacity)
                throw new MaintenanceProtocolException(
                    "replay_capacity",
                    "Maintenance replay capacity is exhausted.");
            entries.Add(new ReplayEntry(requestId, expiresAtUtc));
            Save(entries);
            return true;
        }
    }

    private IReadOnlyList<ReplayEntry> Load()
    {
        if (!File.Exists(path))
            return [];
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint) ||
            new FileInfo(path).Length is <= 0 or > MaximumBytes)
            throw new InvalidDataException(
                "Maintenance replay journal is invalid.");
        try
        {
            var envelope = JsonSerializer.Deserialize<ReplayEnvelope>(
                               File.ReadAllBytes(path))
                           ?? throw new InvalidDataException(
                               "Maintenance replay journal is empty.");
            var payload = Convert.FromBase64String(envelope.Payload);
            var tag = Convert.FromBase64String(envelope.AuthenticationTag);
            try
            {
                var expected = HMACSHA256.HashData(
                    authenticationKey,
                    payload);
                try
                {
                    if (envelope.Version != 1 ||
                        tag.Length != expected.Length ||
                        !CryptographicOperations.FixedTimeEquals(tag, expected))
                        throw new InvalidDataException(
                            "Maintenance replay journal authentication failed.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                }
                var snapshot = JsonSerializer.Deserialize<ReplaySnapshot>(
                                   payload)
                               ?? throw new InvalidDataException(
                                   "Maintenance replay snapshot is empty.");
                if (snapshot.Version != 1 ||
                    snapshot.Entries.Count > capacity ||
                    snapshot.Entries.Any(entry =>
                        entry.RequestId == Guid.Empty) ||
                    snapshot.Entries.Select(entry => entry.RequestId)
                        .Distinct().Count() != snapshot.Entries.Count)
                    throw new InvalidDataException(
                        "Maintenance replay snapshot is invalid.");
                return snapshot.Entries;
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
                "Maintenance replay journal is malformed.",
                exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Maintenance replay journal encoding is malformed.",
                exception);
        }
    }

    private void Save(IReadOnlyList<ReplayEntry> entries)
    {
        var directory = Path.GetDirectoryName(path) ??
            throw new InvalidDataException(
                "Maintenance replay journal has no directory.");
        Directory.CreateDirectory(directory);
        MaintenanceStateSecurity.ValidatePath(directory);
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new ReplaySnapshot(1, entries));
        var tag = HMACSHA256.HashData(authenticationKey, payload);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(
            new ReplayEnvelope(
                1,
                Convert.ToBase64String(payload),
                Convert.ToBase64String(tag)));
        var pending = path + ".new";
        try
        {
            if (envelope.Length > MaximumBytes)
                throw new InvalidDataException(
                    "Maintenance replay journal exceeds its bound.");
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

    private sealed record ReplayEntry(
        Guid RequestId,
        DateTimeOffset ExpiresAtUtc);

    private sealed record ReplaySnapshot(
        int Version,
        IReadOnlyList<ReplayEntry> Entries);

    private sealed record ReplayEnvelope(
        int Version,
        string Payload,
        string AuthenticationTag);
}

