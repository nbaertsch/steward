using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Steward.HandleKeeper;

internal sealed class HandleKeeperFencedException() :
    InvalidOperationException("HandleKeeper is fenced for maintenance.");

internal sealed class HandleKeeperFenceException(
    string code,
    string safeMessage) : InvalidOperationException(safeMessage)
{
    internal string Code { get; } = code;
}

internal enum HandleKeeperFencePhase
{
    Unfenced,
    MaintenanceOwned,
    ProvisionerOwned
}

internal enum HandleKeeperFenceAcquireStatus
{
    Acquired,
    LeaseHeld
}

internal sealed record HandleKeeperFenceCapability
{
    private const int CapabilityLength = 32;

    public HandleKeeperFenceCapability(string encoded)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encoded);
        byte[] value;
        try
        {
            value = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "HandleKeeper fence capability is invalid.",
                nameof(encoded),
                exception);
        }
        try
        {
            if (value.Length != CapabilityLength)
                throw new ArgumentException(
                    "HandleKeeper fence capability must be 256 bits.",
                    nameof(encoded));
            Encoded = encoded;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    public string Encoded { get; }

    internal static HandleKeeperFenceCapability Create() => new(
        Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(CapabilityLength)));

    internal string Sha256()
    {
        var value = Convert.FromBase64String(Encoded);
        try
        {
            return Convert.ToHexString(SHA256.HashData(value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    public override string ToString() => "[handle-keeper-fence-capability]";
}

internal sealed record HandleKeeperFenceAcquireRequest(
    Guid TransactionId,
    Guid ScopeId,
    HandleKeeperFenceCapability Capability,
    ulong ExpectedGeneration);

internal sealed record HandleKeeperFenceReleaseRequest(
    Guid TransactionId,
    Guid ScopeId,
    HandleKeeperFenceCapability Capability,
    ulong ExpectedGeneration);

internal sealed record HandleKeeperFenceTransferRequest(
    Guid TransactionId,
    HandleKeeperFenceCapability MaintenanceCapability,
    ulong ExpectedGeneration,
    HandleKeeperFenceCapability ProvisionerCapability,
    string ProvisionerImageSha256);

internal sealed record HandleKeeperTransferredReleaseRequest(
    Guid TransactionId,
    HandleKeeperFenceCapability ProvisionerCapability,
    ulong ExpectedGeneration,
    string ProvisionerImageSha256);

internal sealed record HandleKeeperFenceRollbackSnapshot(
    HandleKeeperFencePhase Phase,
    Guid TransactionId,
    string OwnerCapabilitySha256,
    IReadOnlyList<Guid> ScopeIds);

internal sealed record HandleKeeperFenceSnapshot(
    int Version,
    ulong Generation,
    HandleKeeperFencePhase Phase,
    Guid? TransactionId,
    string? OwnerCapabilitySha256,
    IReadOnlyList<Guid> ScopeIds,
    string? ProvisionerImageSha256,
    HandleKeeperFenceRollbackSnapshot? RollbackSnapshot)
{
    internal int Depth => ScopeIds.Count;

    internal static HandleKeeperFenceSnapshot Unfenced(ulong generation = 0) =>
        new(
            1,
            generation,
            HandleKeeperFencePhase.Unfenced,
            null,
            null,
            [],
            null,
            null);
}

internal sealed record HandleKeeperFenceAcquireResult(
    HandleKeeperFenceAcquireStatus Status,
    HandleKeeperFenceSnapshot Snapshot);

internal interface IHandleKeeperFenceStore
{
    HandleKeeperFenceSnapshot Load();
    void Save(HandleKeeperFenceSnapshot snapshot);
}

internal sealed class InMemoryHandleKeeperFenceStore :
    IHandleKeeperFenceStore
{
    private HandleKeeperFenceSnapshot snapshot =
        HandleKeeperFenceSnapshot.Unfenced();

    public HandleKeeperFenceSnapshot Load() => snapshot;

    public void Save(HandleKeeperFenceSnapshot value)
    {
        Validate(value);
        snapshot = value;
    }

    internal static void Validate(HandleKeeperFenceSnapshot value)
    {
        if (value.Version != 1 || !Enum.IsDefined(value.Phase) ||
            value.ScopeIds.Count > 64 ||
            value.ScopeIds.Any(scope => scope == Guid.Empty) ||
            value.ScopeIds.Distinct().Count() != value.ScopeIds.Count)
            throw new InvalidDataException(
                "HandleKeeper fence snapshot is invalid.");
        if (value.Phase == HandleKeeperFencePhase.Unfenced)
        {
            if (value.TransactionId is not null ||
                value.OwnerCapabilitySha256 is not null ||
                value.ScopeIds.Count != 0 ||
                value.ProvisionerImageSha256 is not null ||
                value.RollbackSnapshot is not null)
                throw new InvalidDataException(
                    "Unfenced HandleKeeper state contains ownership.");
            return;
        }
        if (value.TransactionId is not { } transactionId ||
            transactionId == Guid.Empty ||
            !ValidHash(value.OwnerCapabilitySha256) ||
            value.ScopeIds.Count == 0)
            throw new InvalidDataException(
                "Fenced HandleKeeper state lacks ownership.");
        if (value.Phase == HandleKeeperFencePhase.MaintenanceOwned &&
            (value.ProvisionerImageSha256 is not null ||
             value.RollbackSnapshot is not null))
            throw new InvalidDataException(
                "Maintenance-owned fence has transfer state.");
        if (value.Phase == HandleKeeperFencePhase.ProvisionerOwned &&
            (!ValidHash(value.ProvisionerImageSha256) ||
             value.RollbackSnapshot is not { } rollback ||
             rollback.Phase != HandleKeeperFencePhase.MaintenanceOwned ||
             rollback.TransactionId != transactionId ||
             !ValidHash(rollback.OwnerCapabilitySha256) ||
             !rollback.ScopeIds.SequenceEqual(value.ScopeIds)))
            throw new InvalidDataException(
                "Provisioner-owned fence lacks an exact rollback snapshot.");
    }

    internal static bool ValidHash(string? value) =>
        value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
}

internal enum HandleKeeperDurableCommitResult
{
    FileAndParentDirectoryCommitted,
    FileCommittedParentDirectoryFlushUnsupported
}
internal sealed class FileHandleKeeperFenceStore : IHandleKeeperFenceStore
{
    private const int MaximumJournalBytes = 256 * 1024;
    private static readonly JsonSerializerOptions Json = CreateJson();
    private readonly string path;
    private readonly byte[] authenticationKey;

    internal HandleKeeperDurableCommitResult? LastCommitResult
    {
        get;
        private set;
    }

    internal FileHandleKeeperFenceStore(
        string path,
        ReadOnlySpan<byte> authenticationKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "HandleKeeper fence journal key must be 256 bits.",
                nameof(authenticationKey));
        this.path = Path.GetFullPath(path);
        this.authenticationKey = authenticationKey.ToArray();
    }

    public HandleKeeperFenceSnapshot Load()
    {
        if (!File.Exists(path))
            return HandleKeeperFenceSnapshot.Unfenced();
        var encoded = File.ReadAllBytes(path);
        try
        {
            if (encoded.Length is <= 0 or > MaximumJournalBytes)
                throw new InvalidDataException(
                    "HandleKeeper fence journal size is invalid.");
            var envelope = JsonSerializer.Deserialize<FenceEnvelope>(
                               encoded,
                               Json) ?? throw new InvalidDataException(
                               "HandleKeeper fence journal is empty.");
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
                            "HandleKeeper fence journal authentication failed.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                }
                var snapshot = JsonSerializer.Deserialize<
                                   HandleKeeperFenceSnapshot>(payload, Json) ??
                               throw new InvalidDataException(
                                   "HandleKeeper fence snapshot is empty.");
                InMemoryHandleKeeperFenceStore.Validate(snapshot);
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
                "HandleKeeper fence journal is malformed.",
                exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "HandleKeeper fence journal encoding is malformed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    public void Save(HandleKeeperFenceSnapshot snapshot)
    {
        InMemoryHandleKeeperFenceStore.Validate(snapshot);
        var payload = JsonSerializer.SerializeToUtf8Bytes(snapshot, Json);
        var tag = HMACSHA256.HashData(authenticationKey, payload);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(
            new FenceEnvelope(
                1,
                Convert.ToBase64String(payload),
                Convert.ToBase64String(tag)),
            Json);
        var pending = path + ".new";
        try
        {
            if (envelope.Length > MaximumJournalBytes)
                throw new InvalidDataException(
                    "HandleKeeper fence journal exceeds its bound.");
            Directory.CreateDirectory(
                Path.GetDirectoryName(path) ?? throw new InvalidDataException(
                    "HandleKeeper fence journal has no parent."));
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
            LastCommitResult = FlushParentDirectory(
                Path.GetDirectoryName(path) ??
                throw new InvalidDataException(
                    "HandleKeeper fence journal has no parent."));
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

    private static HandleKeeperDurableCommitResult FlushParentDirectory(
        string directory)
    {
        if (!OperatingSystem.IsWindows())
            return HandleKeeperDurableCommitResult.
                FileCommittedParentDirectoryFlushUnsupported;
        using var handle = DurableNative.CreateFile(
            directory,
            0x80000000,
            0x00000001 | 0x00000002 | 0x00000004,
            IntPtr.Zero,
            3,
            0x02000000 | 0x80000000,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            if (error is 1 or 5 or 6 or 50)
                return HandleKeeperDurableCommitResult.
                    FileCommittedParentDirectoryFlushUnsupported;
            throw new System.ComponentModel.Win32Exception(
                error,
                "HandleKeeper parent directory open failed.");
        }
        if (DurableNative.FlushFileBuffers(handle))
            return HandleKeeperDurableCommitResult.
                FileAndParentDirectoryCommitted;
        var flushError =
            System.Runtime.InteropServices.Marshal.GetLastWin32Error();
        if (flushError is 1 or 5 or 6 or 50)
            return HandleKeeperDurableCommitResult.
                FileCommittedParentDirectoryFlushUnsupported;
        throw new System.ComponentModel.Win32Exception(
            flushError,
            "HandleKeeper parent directory flush failed.");
    }

    private static class DurableNative
    {
#pragma warning disable SYSLIB1054
        [System.Runtime.InteropServices.DllImport(
            "kernel32.dll",
            EntryPoint = "CreateFileW",
            SetLastError = true,
            CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        internal static extern Microsoft.Win32.SafeHandles.SafeFileHandle
            CreateFile(
                string fileName,
                uint desiredAccess,
                uint shareMode,
                IntPtr securityAttributes,
                uint creationDisposition,
                uint flagsAndAttributes,
                IntPtr templateFile);

        [System.Runtime.InteropServices.DllImport(
            "kernel32.dll",
            SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(
            System.Runtime.InteropServices.UnmanagedType.Bool)]
        internal static extern bool FlushFileBuffers(
            Microsoft.Win32.SafeHandles.SafeFileHandle file);
#pragma warning restore SYSLIB1054
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

    private sealed record FenceEnvelope(
        int Version,
        string Payload,
        string AuthenticationTag);
}

internal sealed class HandleKeeperDrainFenceState
{
    private readonly object gate = new();
    private readonly IHandleKeeperFenceStore store;
    private HandleKeeperFenceSnapshot snapshot;
    private readonly HandleKeeperFenceCapability legacyCapability =
        HandleKeeperFenceCapability.Create();
    private readonly Guid legacyTransaction = Guid.NewGuid();
    private readonly Guid legacyScope = Guid.NewGuid();

    internal HandleKeeperDrainFenceState() :
        this(new InMemoryHandleKeeperFenceStore())
    {
    }

    internal HandleKeeperDrainFenceState(IHandleKeeperFenceStore store)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        snapshot = store.Load();
    }

    internal bool IsFenced
    {
        get
        {
            lock (gate)
                return snapshot.Phase != HandleKeeperFencePhase.Unfenced;
        }
    }

    internal HandleKeeperFenceSnapshot Snapshot
    {
        get
        {
            lock (gate)
                return snapshot;
        }
    }

    internal HandleKeeperFenceAcquireResult Acquire(
        HandleKeeperFenceAcquireRequest request,
        Func<int> activeLeaseCount)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(activeLeaseCount);
        ValidateIdentity(request.TransactionId, request.ScopeId);
        lock (gate)
        {
            if (snapshot.Phase == HandleKeeperFencePhase.Unfenced)
            {
                RequireGeneration(request.ExpectedGeneration);
                snapshot = new HandleKeeperFenceSnapshot(
                    1,
                    checked(snapshot.Generation + 1),
                    HandleKeeperFencePhase.MaintenanceOwned,
                    request.TransactionId,
                    request.Capability.Sha256(),
                    [request.ScopeId],
                    null,
                    null);
                Save();
            }
            else
            {
                RequireMaintenanceOwner(
                    request.TransactionId,
                    request.Capability);
                if (!snapshot.ScopeIds.Contains(request.ScopeId))
                {
                    RequireGeneration(request.ExpectedGeneration);
                    if (snapshot.ScopeIds.Count == 64)
                        throw Error(
                            "fence_depth",
                            "HandleKeeper fence nesting is exhausted.");
                    snapshot = snapshot with
                    {
                        Generation = checked(snapshot.Generation + 1),
                        ScopeIds = [.. snapshot.ScopeIds, request.ScopeId]
                    };
                    Save();
                }
            }
            var status = activeLeaseCount() == 0
                ? HandleKeeperFenceAcquireStatus.Acquired
                : HandleKeeperFenceAcquireStatus.LeaseHeld;
            return new HandleKeeperFenceAcquireResult(status, snapshot);
        }
    }

    internal HandleKeeperFenceSnapshot Release(
        HandleKeeperFenceReleaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateIdentity(request.TransactionId, request.ScopeId);
        lock (gate)
        {
            RequireMaintenanceOwner(
                request.TransactionId,
                request.Capability);
            RequireGeneration(request.ExpectedGeneration);
            if (!snapshot.ScopeIds.Contains(request.ScopeId))
                throw Error(
                    "fence_scope",
                    "HandleKeeper fence scope is not owned.");
            var remaining = snapshot.ScopeIds
                .Where(scope => scope != request.ScopeId)
                .ToArray();
            snapshot = remaining.Length == 0
                ? HandleKeeperFenceSnapshot.Unfenced(
                    checked(snapshot.Generation + 1))
                : snapshot with
                {
                    Generation = checked(snapshot.Generation + 1),
                    ScopeIds = remaining
                };
            Save();
            return snapshot;
        }
    }

    internal HandleKeeperFenceSnapshot Transfer(
        HandleKeeperFenceTransferRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateTransaction(request.TransactionId);
        if (!InMemoryHandleKeeperFenceStore.ValidHash(
                request.ProvisionerImageSha256))
            throw new ArgumentException(
                "Provisioner image identity is invalid.",
                nameof(request));
        lock (gate)
        {
            if (snapshot.Phase == HandleKeeperFencePhase.ProvisionerOwned)
            {
                var rollback = snapshot.RollbackSnapshot ??
                    throw new InvalidDataException(
                        "Transferred fence rollback snapshot is missing.");
                if (rollback.TransactionId == request.TransactionId &&
                    HashEquals(
                        rollback.OwnerCapabilitySha256,
                        request.MaintenanceCapability.Sha256()) &&
                    HashEquals(
                        snapshot.OwnerCapabilitySha256,
                        request.ProvisionerCapability.Sha256()) &&
                    HashEquals(
                        snapshot.ProvisionerImageSha256,
                        request.ProvisionerImageSha256))
                    return snapshot;
            }
            RequireMaintenanceOwner(
                request.TransactionId,
                request.MaintenanceCapability);
            RequireGeneration(request.ExpectedGeneration);
            var rollbackSnapshot = new HandleKeeperFenceRollbackSnapshot(
                snapshot.Phase,
                request.TransactionId,
                snapshot.OwnerCapabilitySha256!,
                snapshot.ScopeIds.ToArray());
            snapshot = snapshot with
            {
                Generation = checked(snapshot.Generation + 1),
                Phase = HandleKeeperFencePhase.ProvisionerOwned,
                OwnerCapabilitySha256 =
                    request.ProvisionerCapability.Sha256(),
                ProvisionerImageSha256 =
                    request.ProvisionerImageSha256.ToUpperInvariant(),
                RollbackSnapshot = rollbackSnapshot
            };
            Save();
            return snapshot;
        }
    }

    internal HandleKeeperFenceSnapshot RollbackTransfer(
        Guid transactionId,
        HandleKeeperFenceCapability maintenanceCapability,
        ulong expectedGeneration)
    {
        ValidateTransaction(transactionId);
        ArgumentNullException.ThrowIfNull(maintenanceCapability);
        lock (gate)
        {
            RequireGeneration(expectedGeneration);
            var rollback = snapshot.RollbackSnapshot ??
                throw Error(
                    "fence_phase",
                    "HandleKeeper fence has no ownership transfer.");
            if (snapshot.Phase != HandleKeeperFencePhase.ProvisionerOwned ||
                rollback.TransactionId != transactionId ||
                !HashEquals(
                    rollback.OwnerCapabilitySha256,
                    maintenanceCapability.Sha256()))
                throw Error(
                    "fence_owner",
                    "HandleKeeper transfer rollback owner mismatched.");
            snapshot = new HandleKeeperFenceSnapshot(
                1,
                checked(snapshot.Generation + 1),
                rollback.Phase,
                rollback.TransactionId,
                rollback.OwnerCapabilitySha256,
                rollback.ScopeIds.ToArray(),
                null,
                null);
            Save();
            return snapshot;
        }
    }

    internal HandleKeeperFenceSnapshot ReleaseTransferred(
        HandleKeeperTransferredReleaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateTransaction(request.TransactionId);
        lock (gate)
        {
            RequireGeneration(request.ExpectedGeneration);
            if (snapshot.Phase != HandleKeeperFencePhase.ProvisionerOwned ||
                snapshot.TransactionId != request.TransactionId ||
                !HashEquals(
                    snapshot.OwnerCapabilitySha256,
                    request.ProvisionerCapability.Sha256()) ||
                !HashEquals(
                    snapshot.ProvisionerImageSha256,
                    request.ProvisionerImageSha256))
                throw Error(
                    "fence_owner",
                    "Provisioner fence release identity mismatched.");
            snapshot = HandleKeeperFenceSnapshot.Unfenced(
                checked(snapshot.Generation + 1));
            Save();
            return snapshot;
        }
    }

    internal T ExecuteRetain<T>(Func<T> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (gate)
        {
            if (snapshot.Phase != HandleKeeperFencePhase.Unfenced)
                throw new HandleKeeperFencedException();
            return action();
        }
    }

    internal void ExecuteRetain(Action action) =>
        _ = ExecuteRetain(() =>
        {
            action();
            return true;
        });

    internal T ExecuteLeaseMutation<T>(Func<T> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (gate)
            return action();
    }

    private void RequireMaintenanceOwner(
        Guid transactionId,
        HandleKeeperFenceCapability capability)
    {
        if (snapshot.Phase != HandleKeeperFencePhase.MaintenanceOwned ||
            snapshot.TransactionId != transactionId ||
            !HashEquals(
                snapshot.OwnerCapabilitySha256,
                capability.Sha256()))
            throw Error(
                "fence_owner",
                "HandleKeeper maintenance fence owner mismatched.");
    }

    private void RequireGeneration(ulong expectedGeneration)
    {
        if (snapshot.Generation != expectedGeneration)
            throw Error(
                "fence_stale_generation",
                "HandleKeeper fence generation is stale.");
    }

    private void Save()
    {
        InMemoryHandleKeeperFenceStore.Validate(snapshot);
        store.Save(snapshot);
    }

    private static void ValidateIdentity(Guid transactionId, Guid scopeId)
    {
        ValidateTransaction(transactionId);
        if (scopeId == Guid.Empty)
            throw new ArgumentException(
                "HandleKeeper fence scope identity is required.");
    }

    private static void ValidateTransaction(Guid transactionId)
    {
        if (transactionId == Guid.Empty)
            throw new ArgumentException(
                "HandleKeeper fence transaction identity is required.");
    }

    private static bool HashEquals(string? first, string second)
    {
        if (!InMemoryHandleKeeperFenceStore.ValidHash(first) ||
            !InMemoryHandleKeeperFenceStore.ValidHash(second))
            return false;
        var left = Convert.FromHexString(first!);
        var right = Convert.FromHexString(second);
        try
        {
            return CryptographicOperations.FixedTimeEquals(left, right);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(left);
            CryptographicOperations.ZeroMemory(right);
        }
    }

    private static HandleKeeperFenceException Error(
        string code,
        string message) => new(code, message);
}
