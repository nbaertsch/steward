using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace Steward.Maintenance.Windows;

internal enum EndpointInstallerHandoffAction
{
    InstallEndpoint
}

internal enum EndpointInstallerHandoffPhase
{
    IntentCommitted,
    Triggered,
    Committed,
    RolledBack
}

internal enum EndpointInstallerReceiptOutcome
{
    Committed,
    RolledBack
}

internal sealed record EndpointOwnerCapability
{
    private const int CapabilityBytes = 32;

    public EndpointOwnerCapability(string encoded)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encoded);
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "Endpoint owner capability is invalid.",
                nameof(encoded),
                exception);
        }
        try
        {
            if (decoded.Length != CapabilityBytes)
                throw new ArgumentException(
                    "Endpoint owner capability must be 256 bits.",
                    nameof(encoded));
            Encoded = encoded;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    public string Encoded { get; }

    internal static EndpointOwnerCapability Create() => new(
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(
            CapabilityBytes)));
    internal static EndpointOwnerCapability Derive(
        ReadOnlySpan<byte> key,
        Guid transactionId)
    {
        if (key.Length != 32 || transactionId == Guid.Empty)
            throw new ArgumentException(
                "Endpoint owner capability derivation input is invalid.");
        var context = "Steward.Endpoint.InstallerOwner.v1"u8;
        var input = new byte[context.Length + 16];
        context.CopyTo(input);
        transactionId.TryWriteBytes(input.AsSpan(context.Length));
        var capability = HMACSHA256.HashData(key, input);
        try
        {
            return new EndpointOwnerCapability(
                Convert.ToBase64String(capability));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(capability);
        }
    }

    internal string Sha256()
    {
        var bytes = Convert.FromBase64String(Encoded);
        try
        {
            return Convert.ToHexString(SHA256.HashData(bytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal bool FixedTimeEquals(EndpointOwnerCapability other)
    {
        ArgumentNullException.ThrowIfNull(other);
        var left = Convert.FromBase64String(Encoded);
        var right = Convert.FromBase64String(other.Encoded);
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

    public override string ToString() => "[endpoint-owner-capability]";
}

internal sealed record EndpointInstallerHandoffIntent(
    int Version,
    Guid TransactionId,
    ulong UpdateSequence,
    EndpointOwnerCapability OwnerCapability,
    string ProductVersion,
    string MsiSha256,
    long MsiLength,
    Guid ProductCode,
    Guid UpgradeCode,
    string ReleaseDirectoryName,
    string ProvisionerSha256,
    EndpointInstallerHandoffAction Action);

internal sealed record EndpointInstallerHandoffReceipt(
    int Version,
    Guid TransactionId,
    ulong UpdateSequence,
    string OwnerCapabilitySha256,
    string ProductVersion,
    string MsiSha256,
    Guid ProductCode,
    Guid UpgradeCode,
    EndpointInstallerHandoffAction Action,
    EndpointInstallerReceiptOutcome Outcome,
    int InstallerExitCode)
{
    internal static EndpointInstallerHandoffReceipt Create(
        EndpointInstallerHandoffIntent intent,
        EndpointInstallerReceiptOutcome outcome,
        int installerExitCode)
    {
        ArgumentNullException.ThrowIfNull(intent);
        return new EndpointInstallerHandoffReceipt(
            1,
            intent.TransactionId,
            intent.UpdateSequence,
            intent.OwnerCapability.Sha256(),
            intent.ProductVersion,
            intent.MsiSha256,
            intent.ProductCode,
            intent.UpgradeCode,
            intent.Action,
            outcome,
            installerExitCode);
    }
}

internal sealed record EndpointInstallerHandoffSnapshot(
    int Version,
    ulong Generation,
    EndpointInstallerHandoffPhase Phase,
    EndpointInstallerHandoffIntent Intent,
    EndpointInstallerHandoffReceipt? Receipt);

internal sealed class EndpointInstallerHandoffException(
    string code,
    string safeMessage) : InvalidOperationException(safeMessage)
{
    internal string Code { get; } = code;
}

internal enum DurableFileCommitResult
{
    FileAndParentDirectoryCommitted,
    FileCommittedParentDirectoryFlushUnsupported
}

internal static class WindowsDurableFile
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagWriteThrough = 0x80000000;

    internal static DurableFileCommitResult WriteAtomic(
        string path,
        ReadOnlySpan<byte> content)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var full = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(full) ??
            throw new InvalidDataException(
                "Durable file has no parent directory.");
        Directory.CreateDirectory(directory);
        var pending = full + ".new";
        EndpointUpdateFileValidator.EnsureRegularFileIfPresent(pending);
        try
        {
            using (var stream = new FileStream(
                       pending,
                       FileMode.Create,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }
            File.Move(pending, full, overwrite: true);
            return FlushParentDirectory(directory);
        }
        finally
        {
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }

    internal static DurableFileCommitResult FlushParentDirectory(
        string directory)
    {
        if (!OperatingSystem.IsWindows())
            return DurableFileCommitResult.
                FileCommittedParentDirectoryFlushUnsupported;
        using var handle = NativeMethods.CreateFile(
            directory,
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagWriteThrough,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            if (UnsupportedDirectoryFlush(error))
                return DurableFileCommitResult.
                    FileCommittedParentDirectoryFlushUnsupported;
            throw new System.ComponentModel.Win32Exception(
                error,
                "Opening the parent directory for durable commit failed.");
        }
        if (NativeMethods.FlushFileBuffers(handle))
            return DurableFileCommitResult.
                FileAndParentDirectoryCommitted;
        var flushError = Marshal.GetLastWin32Error();
        if (UnsupportedDirectoryFlush(flushError))
            return DurableFileCommitResult.
                FileCommittedParentDirectoryFlushUnsupported;
        throw new System.ComponentModel.Win32Exception(
            flushError,
            "Flushing the parent directory for durable commit failed.");
    }

    private static bool UnsupportedDirectoryFlush(int error) =>
        error is 1 or 5 or 6 or 50;

    private static class NativeMethods
    {
#pragma warning disable SYSLIB1054
        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateFileW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        internal static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FlushFileBuffers(SafeFileHandle file);
#pragma warning restore SYSLIB1054
    }
}

internal sealed class FileEndpointInstallerHandoffStore
{
    private const int MaximumJournalBytes = 256 * 1024;
    private static readonly JsonSerializerOptions Json = CreateJson();
    private readonly string path;
    private readonly byte[] authenticationKey;

    internal FileEndpointInstallerHandoffStore(
        string path,
        ReadOnlySpan<byte> authenticationKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "Installer handoff journal key must be 256 bits.",
                nameof(authenticationKey));
        this.path = Path.GetFullPath(path);
        this.authenticationKey = authenticationKey.ToArray();
        Current = File.Exists(this.path) ? Restore() : null;
    }

    internal EndpointInstallerHandoffSnapshot? Current { get; private set; }

    internal DurableFileCommitResult? LastCommitResult { get; private set; }

    internal EndpointInstallerHandoffSnapshot Prepare(
        EndpointInstallerHandoffIntent intent)
    {
        ValidateIntent(intent);
        if (Current is { } current)
        {
            if (current.Intent == intent)
                return current;
            if (current.Phase is not (
                    EndpointInstallerHandoffPhase.Committed or
                    EndpointInstallerHandoffPhase.RolledBack))
                throw Error(
                    "installer_transaction_active",
                    "Another installer handoff is already active.");
        }
        Current = new EndpointInstallerHandoffSnapshot(
            1,
            checked((Current?.Generation ?? 0) + 1),
            EndpointInstallerHandoffPhase.IntentCommitted,
            intent,
            null);
        Save();
        return Current;
    }

    internal EndpointInstallerHandoffSnapshot MarkTriggered(
        Guid transactionId,
        EndpointOwnerCapability ownerCapability,
        ulong expectedGeneration)
    {
        var current = RequireOwner(transactionId, ownerCapability);
        if (current.Phase is
            EndpointInstallerHandoffPhase.Triggered or
            EndpointInstallerHandoffPhase.Committed or
            EndpointInstallerHandoffPhase.RolledBack)
            return current;
        RequireGeneration(current, expectedGeneration);
        if (current.Phase != EndpointInstallerHandoffPhase.IntentCommitted)
            throw Error(
                "installer_handoff_phase",
                "Installer handoff cannot be triggered in its current phase.");
        Current = current with
        {
            Generation = checked(current.Generation + 1),
            Phase = EndpointInstallerHandoffPhase.Triggered
        };
        Save();
        return Current;
    }

    internal EndpointInstallerHandoffSnapshot RecordReceipt(
        EndpointInstallerHandoffReceipt receipt,
        ulong expectedGeneration)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var current = Current ?? throw Error(
            "installer_handoff_missing",
            "Installer handoff intent is unavailable.");
        ValidateReceipt(current.Intent, receipt);
        if (current.Receipt == receipt && current.Phase is
            EndpointInstallerHandoffPhase.Committed or
            EndpointInstallerHandoffPhase.RolledBack)
            return current;
        RequireGeneration(current, expectedGeneration);
        if (current.Phase != EndpointInstallerHandoffPhase.Triggered)
            throw Error(
                "installer_handoff_phase",
                "Installer receipt arrived before the handoff was triggered.");
        Current = current with
        {
            Generation = checked(current.Generation + 1),
            Phase = receipt.Outcome == EndpointInstallerReceiptOutcome.Committed
                ? EndpointInstallerHandoffPhase.Committed
                : EndpointInstallerHandoffPhase.RolledBack,
            Receipt = receipt
        };
        Save();
        return Current;
    }

    private EndpointInstallerHandoffSnapshot RequireOwner(
        Guid transactionId,
        EndpointOwnerCapability capability)
    {
        ArgumentNullException.ThrowIfNull(capability);
        var current = Current ?? throw Error(
            "installer_handoff_missing",
            "Installer handoff intent is unavailable.");
        if (current.Intent.TransactionId != transactionId ||
            !current.Intent.OwnerCapability.FixedTimeEquals(capability))
            throw Error(
                "installer_handoff_owner",
                "Installer handoff ownership does not match.");
        return current;
    }

    private static void RequireGeneration(
        EndpointInstallerHandoffSnapshot current,
        ulong expectedGeneration)
    {
        if (current.Generation != expectedGeneration)
            throw Error(
                "installer_handoff_stale_generation",
                "Installer handoff generation is stale.");
    }

    private void Save()
    {
        var current = Current ?? throw new InvalidOperationException(
            "Installer handoff snapshot is unavailable.");
        ValidateSnapshot(current);
        var payload = JsonSerializer.SerializeToUtf8Bytes(current, Json);
        var tag = HMACSHA256.HashData(authenticationKey, payload);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(
            new InstallerHandoffEnvelope(
                1,
                Convert.ToBase64String(payload),
                Convert.ToBase64String(tag)),
            Json);
        try
        {
            if (envelope.Length > MaximumJournalBytes)
                throw new InvalidDataException(
                    "Installer handoff journal exceeds its bound.");
            LastCommitResult = WindowsDurableFile.WriteAtomic(path, envelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    private EndpointInstallerHandoffSnapshot Restore()
    {
        EndpointUpdateFileValidator.EnsureRegularFile(path);
        var encoded = File.ReadAllBytes(path);
        try
        {
            if (encoded.Length is <= 0 or > MaximumJournalBytes)
                throw new InvalidDataException(
                    "Installer handoff journal size is invalid.");
            var envelope = JsonSerializer.Deserialize<InstallerHandoffEnvelope>(
                               encoded,
                               Json) ?? throw new InvalidDataException(
                               "Installer handoff journal is empty.");
            var payload = Convert.FromBase64String(envelope.Payload);
            var tag = Convert.FromBase64String(envelope.AuthenticationTag);
            try
            {
                var expected = HMACSHA256.HashData(authenticationKey, payload);
                try
                {
                    if (envelope.Version != 1 ||
                        !CryptographicOperations.FixedTimeEquals(tag, expected))
                        throw new InvalidDataException(
                            "Installer handoff journal authentication failed.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                }
                var snapshot = JsonSerializer.Deserialize<
                                   EndpointInstallerHandoffSnapshot>(
                                   payload,
                                   Json) ?? throw new InvalidDataException(
                                   "Installer handoff snapshot is empty.");
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
                "Installer handoff journal is malformed.",
                exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Installer handoff journal encoding is malformed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static void ValidateSnapshot(
        EndpointInstallerHandoffSnapshot snapshot)
    {
        if (snapshot.Version != 1 || snapshot.Generation == 0 ||
            !Enum.IsDefined(snapshot.Phase))
            throw new InvalidDataException(
                "Installer handoff snapshot is invalid.");
        ValidateIntent(snapshot.Intent);
        if (snapshot.Phase is
                EndpointInstallerHandoffPhase.Committed or
                EndpointInstallerHandoffPhase.RolledBack)
        {
            if (snapshot.Receipt is null)
                throw new InvalidDataException(
                    "Terminal installer handoff has no receipt.");
            ValidateReceipt(snapshot.Intent, snapshot.Receipt);
        }
        else if (snapshot.Receipt is not null)
        {
            throw new InvalidDataException(
                "Nonterminal installer handoff has a receipt.");
        }
    }

    private static void ValidateIntent(EndpointInstallerHandoffIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        var expectedPrefix = "release-" + intent.ProductVersion + "-";
        if (intent.Version != 1 || intent.TransactionId == Guid.Empty ||
            intent.UpdateSequence == 0 ||
            !Version.TryParse(intent.ProductVersion, out var version) ||
            version.Build < 0 || version.Revision >= 0 ||
            !ValidHash(intent.MsiSha256) || intent.MsiLength <= 0 ||
            intent.ProductCode == Guid.Empty || intent.UpgradeCode == Guid.Empty ||
            intent.ReleaseDirectoryName.Length != expectedPrefix.Length + 16 ||
            !intent.ReleaseDirectoryName.StartsWith(
                expectedPrefix,
                StringComparison.Ordinal) ||
            intent.ReleaseDirectoryName[expectedPrefix.Length..].Any(
                character => !char.IsAsciiHexDigit(character)) ||
            !ValidHash(intent.ProvisionerSha256) ||
            intent.Action != EndpointInstallerHandoffAction.InstallEndpoint)
            throw new ArgumentException(
                "Installer handoff intent is invalid.",
                nameof(intent));
    }

    private static void ValidateReceipt(
        EndpointInstallerHandoffIntent intent,
        EndpointInstallerHandoffReceipt receipt)
    {
        if (receipt.Version != 1 ||
            receipt.TransactionId != intent.TransactionId ||
            receipt.UpdateSequence != intent.UpdateSequence ||
            !FixedHashEquals(
                receipt.OwnerCapabilitySha256,
                intent.OwnerCapability.Sha256()) ||
            receipt.ProductVersion != intent.ProductVersion ||
            !FixedHashEquals(receipt.MsiSha256, intent.MsiSha256) ||
            receipt.ProductCode != intent.ProductCode ||
            receipt.UpgradeCode != intent.UpgradeCode ||
            receipt.Action != intent.Action ||
            !Enum.IsDefined(receipt.Outcome) ||
            receipt.Outcome == EndpointInstallerReceiptOutcome.Committed &&
            receipt.InstallerExitCode is not (0 or 1641 or 3010))
            throw Error(
                "installer_receipt_mismatch",
                "Installer receipt does not match its durable handoff intent.");
    }

    private static bool ValidHash(string value) =>
        value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static bool FixedHashEquals(string first, string second)
    {
        if (!ValidHash(first) || !ValidHash(second))
            return false;
        var left = Convert.FromHexString(first);
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

    private static EndpointInstallerHandoffException Error(
        string code,
        string message) => new(code, message);

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

    private sealed record InstallerHandoffEnvelope(
        int Version,
        string Payload,
        string AuthenticationTag);
}
internal sealed class FileEndpointUpdateTransactionStore :
    IEndpointUpdateTransactionStore
{
    private const int MaximumJournalBytes = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = CreateJson();
    private readonly string path;
    private readonly byte[] authenticationKey;
    private readonly InMemoryEndpointUpdateTransactionStore state;

    internal FileEndpointUpdateTransactionStore(
        string path,
        ReadOnlySpan<byte> authenticationKey,
        string initialActiveVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (authenticationKey.Length != 32)
            throw new ArgumentException(
                "Endpoint update journal key must be 256 bits.",
                nameof(authenticationKey));
        this.path = Path.GetFullPath(path);
        this.authenticationKey = authenticationKey.ToArray();
        MaintenanceStateSecurity.ValidatePath(
            Path.GetDirectoryName(this.path) ?? string.Empty);
        state = File.Exists(this.path)
            ? Restore()
            : new InMemoryEndpointUpdateTransactionStore(initialActiveVersion);
    }

    public EndpointUpdateTransaction? Current => state.Current;
    public EndpointUpdateVersionHistory History => state.History;

    public void Prepare(Guid transactionId)
    {
        var prior = state.Current;
        state.Prepare(transactionId);
        if (prior != state.Current)
            Save();
    }

    public EndpointUpdateTransaction Begin(
        ActivateEndpointUpdateOperation operation,
        EndpointPreservationSnapshot preservedState) =>
        Begin(Guid.NewGuid(), operation, preservedState);

    public EndpointUpdateTransaction Begin(
        Guid transactionId,
        ActivateEndpointUpdateOperation operation,
        EndpointPreservationSnapshot preservedState)
    {
        var result = state.Begin(
            transactionId,
            operation,
            preservedState);
        Save();
        return result;
    }

    public EndpointUpdateTransaction Transition(
        EndpointUpdateTransactionState next,
        VerifiedEndpointRelease? verifiedRelease = null,
        StagedEndpointRelease? stagedRelease = null,
        string? errorCode = null)
    {
        var result = state.Transition(
            next,
            verifiedRelease,
            stagedRelease,
            errorCode);
        Save();
        return result;
    }

    public EndpointUpdateTransaction RecordHealthObservation()
    {
        var result = state.RecordHealthObservation();
        Save();
        return result;
    }

    public EndpointUpdateTransaction CommitKnownGood()
    {
        var transaction = state.CommitKnownGood();
        Save();
        return transaction;
    }

    public EndpointUpdateTransaction CommitRollback(string errorCode)
    {
        var transaction = state.CommitRollback(errorCode);
        Save();
        return transaction;
    }

    private InMemoryEndpointUpdateTransactionStore Restore()
    {
        EndpointUpdateFileValidator.EnsureRegularFile(path);
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is <= 0 or > MaximumJournalBytes)
            throw new InvalidDataException(
                "Endpoint update journal size is invalid.");
        try
        {
            var envelope = JsonSerializer.Deserialize<UpdateJournalEnvelope>(
                               bytes,
                               Json)
                           ?? throw new InvalidDataException(
                               "Endpoint update journal is empty.");
            if (envelope.Version != 1 ||
                string.IsNullOrWhiteSpace(envelope.Payload) ||
                string.IsNullOrWhiteSpace(envelope.AuthenticationTag))
                throw new InvalidDataException(
                    "Endpoint update journal envelope is invalid.");
            var payload = Convert.FromBase64String(envelope.Payload);
            var tag = Convert.FromBase64String(envelope.AuthenticationTag);
            try
            {
                var expected = HMACSHA256.HashData(authenticationKey, payload);
                try
                {
                    if (tag.Length != expected.Length ||
                        !CryptographicOperations.FixedTimeEquals(tag, expected))
                        throw new InvalidDataException(
                            "Endpoint update journal authentication failed.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                }
                var snapshot = JsonSerializer.Deserialize<UpdateStoreSnapshot>(
                                   payload,
                                   Json)
                               ?? throw new InvalidDataException(
                                   "Endpoint update snapshot is empty.");
                Validate(snapshot);
                return InMemoryEndpointUpdateTransactionStore.Restore(
                    snapshot.History,
                    snapshot.Current);
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
                "Endpoint update journal is malformed.",
                exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Endpoint update journal encoding is malformed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private void Save()
    {
        var snapshot = new UpdateStoreSnapshot(1, state.History, state.Current);
        Validate(snapshot);
        var directory = Path.GetDirectoryName(path) ??
            throw new InvalidDataException(
                "Endpoint update journal has no parent directory.");
        Directory.CreateDirectory(directory);
        MaintenanceStateSecurity.ValidatePath(directory);
        var payload = JsonSerializer.SerializeToUtf8Bytes(snapshot, Json);
        var tag = HMACSHA256.HashData(authenticationKey, payload);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(
            new UpdateJournalEnvelope(
                1,
                Convert.ToBase64String(payload),
                Convert.ToBase64String(tag)),
            Json);
        var pending = path + ".new";
        try
        {
            if (envelope.Length > MaximumJournalBytes)
                throw new InvalidDataException(
                    "Endpoint update journal exceeds its bound.");
            EndpointUpdateFileValidator.EnsureRegularFileIfPresent(pending);
            _ = WindowsDurableFile.WriteAtomic(path, envelope);
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

    private static void Validate(UpdateStoreSnapshot snapshot)
    {
        var history = snapshot.History;
        if (snapshot.Version != 1 ||
            history.Version != 1 ||
            !Version.TryParse(history.ActiveVersion, out var active) ||
            active.Build < 0 || active.Revision >= 0 ||
            !Version.TryParse(history.HighestSignedVersion, out var highest) ||
            highest.Build < 0 || highest.Revision >= 0 ||
            active > highest ||
            history.KnownGoodVersions.Count > 256 ||
            history.KnownGoodVersions.Select(value => value.UpdateSequence)
                .Distinct().Count() != history.KnownGoodVersions.Count ||
            history.KnownGoodVersions.Any(value =>
                !Version.TryParse(value.ProductVersion, out _) ||
                !ValidHash(value.ReleaseSha256) ||
                value.UpdateSequence == 0 ||
                value.UpdateSequence > history.LastUpdateSequence) ||
            history.HighestSignedReleaseSha256 is { } releaseHash &&
            !ValidHash(releaseHash))
            throw new InvalidDataException(
                "Endpoint update version history is invalid.");
        if (snapshot.Current is not { } current)
            return;
        if (current.Version != 1 ||
            current.TransactionId == Guid.Empty ||
            current.UpdateSequence == 0 ||
            current.UpdateSequence != history.LastUpdateSequence ||
            !Enum.IsDefined(current.State) ||
            current.HealthObservations < 0 ||
            current.HealthObservations > 120 ||
            !Version.TryParse(current.PriorVersion, out _) ||
            current.PreservedState.HostId == Guid.Empty ||
            current.PreservedState.NodeIncarnationId == Guid.Empty ||
            current.ErrorCode is { Length: > 64 })
            throw new InvalidDataException(
                "Endpoint update transaction is invalid.");
        try
        {
            MaintenanceContract.ValidateOperation(current.Operation);
        }
        catch (MaintenanceProtocolException exception)
        {
            throw new InvalidDataException(
                "Endpoint update operation is invalid.",
                exception);
        }
        if (current.VerifiedRelease is { } verified &&
            verified.Release != current.Operation.Release ||
            current.StagedRelease is { } staged &&
            staged.Release != current.Operation.Release)
            throw new InvalidDataException(
                "Endpoint update release identity changed in the journal.");
    }

    private static bool ValidHash(string value) =>
        value.Length == 64 && value.All(char.IsAsciiHexDigit);

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            MaxDepth = 32,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.CamelCase,
            allowIntegerValues: false));
        return options;
    }

    private sealed record UpdateStoreSnapshot(
        int Version,
        EndpointUpdateVersionHistory History,
        EndpointUpdateTransaction? Current);

    private sealed record UpdateJournalEnvelope(
        int Version,
        string Payload,
        string AuthenticationTag);
}

internal sealed record EndpointStagedFileIdentity(
    long Length,
    string Sha256,
    uint LinkCount,
    uint VolumeSerialNumber,
    ulong FileIndex,
    long LastWriteTimeUtcTicks);

internal static class EndpointUpdateFileValidator
{
    internal static EndpointStagedFileIdentity Capture(
        string stageRoot,
        string file,
        bool requireTrustedAcl)
    {
        ValidateTree(stageRoot, requireTrustedAcl);
        var root = Path.GetFullPath(stageRoot).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        var full = Path.GetFullPath(file);
        if (!full.StartsWith(
                root + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(full))
            throw new EndpointUpdateException(
                "staging_escape",
                "Endpoint staging file escaped its version root.");
        EnsureRegularFile(full);
        using var handle = File.OpenHandle(
            full,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        if (!NativeMethods.GetFileInformationByHandle(handle, out var info))
            NativeMethods.ThrowLastError(nameof(
                NativeMethods.GetFileInformationByHandle));
        if (info.NumberOfLinks != 1)
            throw new EndpointUpdateException(
                "staging_hardlink",
                "Endpoint staging files cannot have hard links.");
        var bytes = File.ReadAllBytes(full);
        try
        {
            return new EndpointStagedFileIdentity(
                bytes.LongLength,
                Convert.ToHexString(SHA256.HashData(bytes)),
                info.NumberOfLinks,
                info.VolumeSerialNumber,
                ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow,
                File.GetLastWriteTimeUtc(full).Ticks);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal static void Revalidate(
        string stageRoot,
        string file,
        EndpointStagedFileIdentity expected,
        bool requireTrustedAcl)
    {
        EndpointStagedFileIdentity actual;
        try
        {
            actual = Capture(stageRoot, file, requireTrustedAcl);
        }
        catch (EndpointUpdateException)
        {
            throw;
        }
        if (actual != expected)
            throw new EndpointUpdateException(
                "staging_mutated",
                "Endpoint staging content changed after verification.");
    }

    internal static void ValidateTree(
        string stageRoot,
        bool requireTrustedAcl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stageRoot);
        var root = Path.GetFullPath(stageRoot);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException(root);
        MaintenanceStateSecurity.ValidatePath(root);
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            var directoryAttributes = File.GetAttributes(directory);
            if (directoryAttributes.HasFlag(FileAttributes.ReparsePoint))
                throw new EndpointUpdateException(
                    "staging_reparse",
                    "Endpoint staging cannot contain reparse points.");
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new EndpointUpdateException(
                        "staging_reparse",
                        "Endpoint staging cannot contain reparse points.");
                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    pending.Push(entry);
                    continue;
                }
                EnsureSingleLink(entry);
            }
        }
        if (requireTrustedAcl)
            MaintenanceStateSecurity.ValidateIsolation(root);
    }

    internal static void EnsureRegularFile(string file)
    {
        if (!File.Exists(file) ||
            File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "Endpoint update journal is not a regular file.");
        EnsureSingleLink(file);
    }

    internal static void EnsureRegularFileIfPresent(string file)
    {
        if (File.Exists(file))
            EnsureRegularFile(file);
    }

    private static void EnsureSingleLink(string file)
    {
        using var handle = File.OpenHandle(
            file,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        if (!NativeMethods.GetFileInformationByHandle(handle, out var info))
            NativeMethods.ThrowLastError(nameof(
                NativeMethods.GetFileInformationByHandle));
        if (info.NumberOfLinks != 1)
            throw new EndpointUpdateException(
                "staging_hardlink",
                "Endpoint staging files cannot have hard links.");
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct ByHandleFileInformation
        {
            internal uint FileAttributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            internal uint VolumeSerialNumber;
            internal uint FileSizeHigh;
            internal uint FileSizeLow;
            internal uint NumberOfLinks;
            internal uint FileIndexHigh;
            internal uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        internal static void ThrowLastError(string operation) =>
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(),
                operation);
    }
}
