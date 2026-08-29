using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Steward.Contracts;
using Steward.Domain;
using Steward.Tasks.Abstractions;
using Steward.Transport;

namespace Steward.Orchestration;

public interface IControlIdentityGrantCatalog
{
    ValueTask<TaskIdentityGrantReference?> ResolveAsync(
        IdentityGrantId grantId,
        WorkloadId workloadId,
        TaskId taskId,
        int generation,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        CancellationToken cancellationToken);
}

public sealed class TaskIdentityLease : IAsyncDisposable
{
    private readonly Func<ValueTask>? release;

    public TaskIdentityLease(
        IReadOnlyList<ProtectedIdentityHandle> handles,
        Func<ValueTask>? release = null)
    {
        Handles = handles ?? throw new ArgumentNullException(nameof(handles));
        this.release = release;
    }

    public IReadOnlyList<ProtectedIdentityHandle> Handles { get; }

    public ValueTask DisposeAsync() => release?.Invoke() ?? ValueTask.CompletedTask;
}

public interface ITaskIdentityResolver
{
    ValueTask<TaskIdentityLease> ResolveAsync(
        AttemptIdentity identity,
        IReadOnlyList<TaskIdentityGrantReference> grants,
        CancellationToken cancellationToken);
}

public sealed class NoIdentityTaskResolver : ITaskIdentityResolver
{
    public ValueTask<TaskIdentityLease> ResolveAsync(
        AttemptIdentity identity,
        IReadOnlyList<TaskIdentityGrantReference> grants,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (grants.Count != 0)
            throw new IdentityResolutionException(
                "identity.renewal-unavailable",
                "Identity delivery is not configured for this Node.");
        return ValueTask.FromResult(new TaskIdentityLease([]));
    }
}

public sealed class IdentityResolutionException : InvalidOperationException
{
    public IdentityResolutionException(
        string code,
        string safeDetail,
        IdentityOfflineBehavior offlineBehavior = IdentityOfflineBehavior.Fail)
        : base(safeDetail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(safeDetail);
        Code = code;
        SafeDetail = safeDetail;
        OfflineBehavior = offlineBehavior;
    }

    public string Code { get; }
    public string SafeDetail { get; }
    public IdentityOfflineBehavior OfflineBehavior { get; }
}

public delegate void ProtectedMaterialConsumer(ReadOnlySpan<char> material);

public interface IProtectedIdentityVault
{
    ProtectedIdentityHandle Store(string provider, string material, DateTimeOffset expiresAt);
    bool TryReveal(ProtectedIdentityHandle handle, ProtectedMaterialConsumer consumer);
    void Remove(ProtectedIdentityHandle handle);
}

public sealed class InMemoryProtectedIdentityVault : IProtectedIdentityVault
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, char[]> values = [];

    public ProtectedIdentityHandle Store(string provider, string material, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(material);
        var handle = new ProtectedIdentityHandle(Guid.NewGuid(), provider, expiresAt);
        if (!values.TryAdd(handle.HandleId, material.ToCharArray()))
            throw new InvalidOperationException("Protected identity handle collision.");
        return handle;
    }

    public bool TryReveal(ProtectedIdentityHandle handle, ProtectedMaterialConsumer consumer)
    {
        ArgumentNullException.ThrowIfNull(consumer);
        if (handle.ExpiresAt <= DateTimeOffset.UtcNow ||
            !values.TryGetValue(handle.HandleId, out var material))
            return false;
        consumer(material);
        return true;
    }

    public void Remove(ProtectedIdentityHandle handle)
    {
        if (values.TryRemove(handle.HandleId, out var material))
            Array.Clear(material);
    }
}

[SupportedOSPlatform("windows")]
public sealed class DpapiProtectedIdentityVault : IProtectedIdentityVault
{
    private static readonly byte[] FileMagic = "STIDVLT1"u8.ToArray();
    private static readonly byte[] EntropyPrefix = "Steward.LocalIdentity.v1"u8.ToArray();
    private const int FileVersion = 1;
    private const int FixedHeaderLength = 44;
    private const int MaximumProviderBytes = 1024;
    private const int MaximumCleartextBytes = 1024 * 1024;
    private const int MaximumProtectedBytes = MaximumCleartextBytes + 4096;
    private readonly string directory;

    public DpapiProtectedIdentityVault(string directory)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The Local Stack identity vault requires Windows DPAPI.");
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (!Path.IsPathFullyQualified(directory))
            throw new ArgumentException("The identity vault path must be absolute.", nameof(directory));
        this.directory = Path.GetFullPath(directory);
        LocalIdentityStorageSecurity.PrepareDirectory(this.directory);
        CleanupExpired(DateTimeOffset.UtcNow);
    }

    public ProtectedIdentityHandle Store(string provider, string material, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(material);
        if (expiresAt <= DateTimeOffset.UtcNow)
            throw new ArgumentOutOfRangeException(nameof(expiresAt));

        var handle = new ProtectedIdentityHandle(Guid.NewGuid(), provider, expiresAt);
        var cleartext = Encoding.UTF8.GetBytes(material);
        if (cleartext.Length > MaximumCleartextBytes)
        {
            CryptographicOperations.ZeroMemory(cleartext);
            throw new ArgumentException("Identity material exceeds the protected vault bound.", nameof(material));
        }
        byte[]? protectedValue = null;
        byte[]? fileValue = null;
        var destination = PathFor(handle.HandleId);
        var pending = destination + "." + Guid.NewGuid().ToString("N") + ".pending";
        try
        {
            protectedValue = ProtectedData.Protect(
                cleartext, Entropy(handle), DataProtectionScope.CurrentUser);
            fileValue = EncodeFile(handle, protectedValue);
            LocalIdentityStorageSecurity.EnsureSafeDirectory(directory);
            using (var stream = new FileStream(
                       pending,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(fileValue);
                stream.Flush(flushToDisk: true);
            }
            LocalIdentityStorageSecurity.RestrictFile(pending);
            File.Move(pending, destination);
            LocalIdentityStorageSecurity.RestrictFile(destination);
            return handle;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
            if (protectedValue is not null)
                CryptographicOperations.ZeroMemory(protectedValue);
            if (fileValue is not null)
                CryptographicOperations.ZeroMemory(fileValue);
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }

    public bool TryReveal(ProtectedIdentityHandle handle, ProtectedMaterialConsumer consumer)
    {
        ArgumentNullException.ThrowIfNull(consumer);
        if (handle.ExpiresAt <= DateTimeOffset.UtcNow)
            return false;
        var path = PathFor(handle.HandleId);
        LocalIdentityStorageSecurity.EnsureSafeDirectory(directory);
        if (!LocalIdentityStorageSecurity.IsSafeRegularFile(path))
            return false;
        LocalIdentityStorageSecurity.RestrictFile(path);

        byte[]? protectedValue = null;
        byte[]? cleartext = null;
        char[]? characters = null;
        try
        {
            var stored = ReadFile(path);
            if (stored.Handle != handle)
                return false;
            protectedValue = stored.ProtectedValue;
            cleartext = ProtectedData.Unprotect(
                protectedValue, Entropy(handle), DataProtectionScope.CurrentUser);
            characters = Encoding.UTF8.GetChars(cleartext);
            consumer(characters);
            return true;
        }
        catch (Exception exception) when (
            exception is CryptographicException or InvalidDataException or IOException or
            UnauthorizedAccessException)
        {
            return false;
        }
        finally
        {
            if (protectedValue is not null)
                CryptographicOperations.ZeroMemory(protectedValue);
            if (cleartext is not null)
                CryptographicOperations.ZeroMemory(cleartext);
            if (characters is not null)
                Array.Clear(characters);
        }
    }

    public void Remove(ProtectedIdentityHandle handle)
    {
        var path = PathFor(handle.HandleId);
        if (LocalIdentityStorageSecurity.IsSafeRegularFile(path))
            File.Delete(path);
    }

    public int CleanupExpired(DateTimeOffset now)
    {
        LocalIdentityStorageSecurity.EnsureSafeDirectory(directory);
        var removed = 0;
        foreach (var path in Directory.EnumerateFiles(directory, "*.identity"))
        {
            if (!LocalIdentityStorageSecurity.IsSafeRegularFile(path))
                throw new IOException("The identity vault contains an unsafe reparse point.");
            LocalIdentityStorageSecurity.RestrictFile(path);
            try
            {
                var stored = ReadFile(path);
                CryptographicOperations.ZeroMemory(stored.ProtectedValue);
                if (stored.Handle.ExpiresAt > now)
                    continue;
            }
            catch (InvalidDataException)
            {
                continue;
            }
            File.Delete(path);
            removed++;
        }
        return removed;
    }

    private string PathFor(Guid handleId) => Path.Combine(directory, $"{handleId:N}.identity");

    private static byte[] EncodeFile(ProtectedIdentityHandle handle, ReadOnlySpan<byte> protectedValue)
    {
        var provider = Encoding.UTF8.GetBytes(handle.Provider);
        if (provider.Length is 0 or > MaximumProviderBytes ||
            protectedValue.Length is 0 or > MaximumProtectedBytes)
            throw new InvalidDataException("Protected identity vault metadata exceeds its bound.");
        var result = new byte[FixedHeaderLength + provider.Length + protectedValue.Length];
        FileMagic.CopyTo(result, 0);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(8), FileVersion);
        handle.HandleId.TryWriteBytes(result.AsSpan(12, 16));
        BinaryPrimitives.WriteInt64BigEndian(result.AsSpan(28), handle.ExpiresAt.UtcTicks);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(36), provider.Length);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(40), protectedValue.Length);
        provider.CopyTo(result, FixedHeaderLength);
        protectedValue.CopyTo(result.AsSpan(FixedHeaderLength + provider.Length));
        CryptographicOperations.ZeroMemory(provider);
        return result;
    }

    private static VaultFile ReadFile(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        if (stream.Length is < FixedHeaderLength or >
            FixedHeaderLength + MaximumProviderBytes + MaximumProtectedBytes)
            throw new InvalidDataException("Protected identity vault file length is invalid.");
        var value = new byte[checked((int)stream.Length)];
        stream.ReadExactly(value);
        try
        {
            if (!value.AsSpan(0, 8).SequenceEqual(FileMagic) ||
                BinaryPrimitives.ReadInt32BigEndian(value.AsSpan(8)) != FileVersion)
                throw new InvalidDataException("Protected identity vault file version is invalid.");
            var handleId = new Guid(value.AsSpan(12, 16));
            var expiryTicks = BinaryPrimitives.ReadInt64BigEndian(value.AsSpan(28));
            var providerLength = BinaryPrimitives.ReadInt32BigEndian(value.AsSpan(36));
            var protectedLength = BinaryPrimitives.ReadInt32BigEndian(value.AsSpan(40));
            if (handleId == Guid.Empty ||
                expiryTicks <= DateTimeOffset.UnixEpoch.UtcTicks ||
                providerLength is <= 0 or > MaximumProviderBytes ||
                protectedLength is <= 0 or > MaximumProtectedBytes ||
                value.Length != FixedHeaderLength + providerLength + protectedLength)
                throw new InvalidDataException("Protected identity vault metadata is invalid.");
            var provider = Encoding.UTF8.GetString(
                value.AsSpan(FixedHeaderLength, providerLength));
            if (string.IsNullOrWhiteSpace(provider))
                throw new InvalidDataException("Protected identity provider is invalid.");
            DateTimeOffset expiresAt;
            try
            {
                expiresAt = new DateTimeOffset(expiryTicks, TimeSpan.Zero);
            }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new InvalidDataException(
                    "Protected identity expiry is outside its bound.", exception);
            }
            var protectedValue = value.AsSpan(
                FixedHeaderLength + providerLength, protectedLength).ToArray();
            return new(
                new(handleId, provider, expiresAt),
                protectedValue);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static byte[] Entropy(ProtectedIdentityHandle handle)
    {
        var value = Encoding.UTF8.GetBytes(
            $"{handle.HandleId:N}|{handle.Provider}|{handle.ExpiresAt.UtcTicks}");
        var entropy = new byte[EntropyPrefix.Length + value.Length];
        EntropyPrefix.CopyTo(entropy, 0);
        value.CopyTo(entropy, EntropyPrefix.Length);
        CryptographicOperations.ZeroMemory(value);
        return entropy;
    }

    private sealed record VaultFile(
        ProtectedIdentityHandle Handle,
        byte[] ProtectedValue);
}

public sealed record LocalControlIdentityGrantRegistration(
    IdentityGrantId IdentityGrantId,
    WorkloadId WorkloadId,
    TaskId TaskId,
    int Generation,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string Provider,
    string Audience,
    IReadOnlyList<string> Scopes,
    DateTimeOffset ExpiresAt,
    int MaximumUses,
    IdentityRenewalMode RenewalMode,
    IdentityOfflineBehavior OfflineBehavior)
{
    internal LocalControlIdentityGrantRegistration Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(Audience);
        if (Generation <= 0)
            throw new ArgumentOutOfRangeException(nameof(Generation));
        if (MaximumUses <= 0)
            throw new ArgumentOutOfRangeException(nameof(MaximumUses));
        if (ExpiresAt <= DateTimeOffset.UnixEpoch)
            throw new ArgumentOutOfRangeException(nameof(ExpiresAt));
        if (!Enum.IsDefined(RenewalMode))
            throw new ArgumentOutOfRangeException(nameof(RenewalMode));
        if (!Enum.IsDefined(OfflineBehavior) ||
            OfflineBehavior == IdentityOfflineBehavior.ContinueWithoutCapability)
            throw new ArgumentOutOfRangeException(nameof(OfflineBehavior));
        if (Scopes.Count is 0 or > 64 ||
            Scopes.Any(string.IsNullOrWhiteSpace) ||
            Scopes.Distinct(StringComparer.Ordinal).Count() != Scopes.Count)
            throw new ArgumentException("Identity grant scopes must be unique and nonempty.", nameof(Scopes));
        return this with { Scopes = [.. Scopes.Order(StringComparer.Ordinal)] };
    }
}

public delegate void ControlIdentityMaterialConsumer(
    string provider,
    ReadOnlySpan<char> material);

[SupportedOSPlatform("windows")]
public sealed class LocalControlIdentityGrantCatalog : IControlIdentityGrantCatalog
{
    private readonly IProtectedIdentityVault vault;
    private readonly LocalIdentityGrantStore store;
    private readonly TimeProvider timeProvider;

    public LocalControlIdentityGrantCatalog(
        IProtectedIdentityVault vault,
        LocalIdentityGrantStore store,
        TimeProvider? timeProvider = null)
    {
        this.vault = vault ?? throw new ArgumentNullException(nameof(vault));
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.timeProvider = timeProvider ?? TimeProvider.System;
        var now = this.timeProvider.GetUtcNow();
        foreach (var handle in store.ReadInactiveHandles(now))
            vault.Remove(handle);
        if (vault is DpapiProtectedIdentityVault dpapi)
            dpapi.CleanupExpired(now);
    }

    public void Register(LocalControlIdentityGrantRegistration registration, string material)
    {
        registration = registration?.Validate() ?? throw new ArgumentNullException(nameof(registration));
        ArgumentException.ThrowIfNullOrWhiteSpace(material);
        var handle = vault.Store(registration.Provider, material, registration.ExpiresAt);
        try
        {
            store.Register(registration, handle, timeProvider.GetUtcNow());
        }
        catch
        {
            vault.Remove(handle);
            throw;
        }
    }

    public bool Revoke(IdentityGrantId grantId)
    {
        var handle = store.Revoke(grantId, timeProvider.GetUtcNow());
        if (handle is null)
            return false;
        vault.Remove(handle);
        return true;
    }

    public ValueTask<TaskIdentityGrantReference?> ResolveAsync(
        IdentityGrantId grantId,
        WorkloadId workloadId,
        TaskId taskId,
        int generation,
        HostId hostId,
        NodeIncarnationId nodeIncarnationId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var reference = store.ResolveOrReserve(
            grantId,
            workloadId,
            taskId,
            generation,
            hostId,
            nodeIncarnationId,
            timeProvider.GetUtcNow());
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(reference);
    }

    internal void Consume(
        DirectIdentityDeliveryRequest request,
        ControlIdentityMaterialConsumer consumer)
    {
        var state = store.Consume(request, timeProvider.GetUtcNow());

        if (!vault.TryReveal(
                state.Handle,
                material => consumer(state.Registration.Provider, material)))
            throw new IdentityResolutionException(
                "identity.unavailable",
                "Task identity material is unavailable.");
    }
}

public sealed record DirectIdentitySessionBinding(
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId NodeIncarnationId,
    string ChannelBinding)
{
    public DirectIdentitySessionBinding Validate()
    {
        if (SessionId == Guid.Empty)
            throw new ArgumentException("A direct identity session ID is required.", nameof(SessionId));
        ArgumentException.ThrowIfNullOrWhiteSpace(ChannelBinding);
        return this;
    }
}

public interface IDirectIdentityDeliveryClient
{
    bool IsControlConnected { get; }
    DirectIdentitySessionBinding Binding { get; }
    ValueTask<EncryptedIdentityDelivery> DeliverAsync(
        DirectIdentityDeliveryRequest request,
        CancellationToken cancellationToken);
}

[SupportedOSPlatform("windows")]
public sealed class DirectSessionControlIdentityHandler
{
    private readonly LocalControlIdentityGrantCatalog catalog;

    public DirectSessionControlIdentityHandler(LocalControlIdentityGrantCatalog catalog) =>
        this.catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));

    public ValueTask<EncryptedIdentityDelivery> HandleAsync(
        DirectIdentitySessionBinding session,
        DirectIdentityDeliveryRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        session = session?.Validate() ?? throw new ArgumentNullException(nameof(session));
        ArgumentNullException.ThrowIfNull(request);
        if (session.HostId != request.Identity.HostId ||
            session.NodeIncarnationId != request.Identity.NodeIncarnationId)
            throw new IdentityResolutionException(
                "identity.session-binding-invalid",
                "Identity delivery is bound to another direct Control session.");

        var aad = DirectIdentityCryptography.CreateAad(session, request);
        try
        {
            using var sender = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            using var recipient = ECDiffieHellman.Create();
            try
            {
                recipient.ImportSubjectPublicKeyInfo(request.RecipientPublicKey, out var read);
                if (read != request.RecipientPublicKey.Length || recipient.KeySize != 256)
                    throw new CryptographicException("Invalid recipient key.");
            }
            catch (CryptographicException)
            {
                throw new IdentityResolutionException(
                    "identity.encryption-invalid",
                    "Identity delivery recipient key is invalid.");
            }

            EncryptedIdentityDelivery? delivery = null;
            catalog.Consume(request, (provider, material) =>
            {
                var plaintext = DirectIdentityCryptography.EncodeMaterial(material, provider);
                byte[]? key = null;
                try
                {
                    key = DirectIdentityCryptography.DeriveKey(sender, recipient.PublicKey, aad);
                    var nonce = RandomNumberGenerator.GetBytes(12);
                    var ciphertext = new byte[plaintext.Length];
                    var tag = new byte[16];
                    using var aes = new AesGcm(key, tag.Length);
                    aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                    delivery = new(
                        request.RequestId,
                        request.Grant.UseId,
                        request.Grant.ExpiresAt,
                        sender.ExportSubjectPublicKeyInfo(),
                        nonce,
                        ciphertext,
                        tag);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                    if (key is not null)
                        CryptographicOperations.ZeroMemory(key);
                }
            });
            return ValueTask.FromResult(
                delivery ?? throw new IdentityResolutionException(
                    "identity.unavailable",
                    "Task identity delivery could not be created."));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }
}

[SupportedOSPlatform("windows")]
public sealed class DirectSessionControlIdentityStreamHandler(
        HostId hostId,
        DirectSessionControlIdentityHandler handler,
        TimeProvider? timeProvider = null) : IAuxiliaryTransportStreamHandler
    {
        private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

        public StreamKind Stream => StreamKind.Identity;

        public async ValueTask HandleAsync(
            ITransportConnection connection,
            TransportFrame frame,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(connection);
            RequireEphemeralSecureSession(connection);
            if (frame.Stream != StreamKind.Identity)
                throw new OrchestrationMessageException(
                    "The direct identity handler accepts only the Identity stream.");
            var decoded = OrchestrationMessageCodec.Decode(frame.Payload);
            if (decoded.Value is not DirectIdentityDeliveryRequest request)
                throw new OrchestrationMessageException(
                    "Control accepts only identity delivery requests on the Identity stream.");
            var binding = new DirectIdentitySessionBinding(
                connection.Session.SessionId,
                hostId,
                connection.Session.NodeIncarnationId,
                connection.Session.Security.ChannelBinding);
            var response = await handler.HandleAsync(
                binding, request, cancellationToken).ConfigureAwait(false);
            var payload = OrchestrationMessageCodec.Encode(
                response, timeProvider.GetUtcNow());
            await connection.SendAsync(new(
                connection.Session.SessionId,
                connection.Session.NodeIncarnationId,
                StreamKind.Identity,
                frame.Sequence,
                frame.Sequence,
                payload), cancellationToken).ConfigureAwait(false);
        }

        internal static void RequireEphemeralSecureSession(ITransportConnection connection)
        {
            if (!connection.Session.Security.IsSecure)
                throw new IdentityResolutionException(
                    "identity.session-insecure",
                    "Identity delivery requires a mutually authenticated encrypted session.");
            if (connection.Session.LocalResumeCursors.GetValueOrDefault(StreamKind.Identity, 0) != 0 ||
                connection.Session.RemoteResumeCursors.GetValueOrDefault(StreamKind.Identity, 0) != 0)
                throw new IdentityResolutionException(
                    "identity.session-replay-invalid",
                    "Identity delivery cannot use persisted resume cursors or replay.");
        }
    }

[SupportedOSPlatform("windows")]
public sealed class DirectSessionNodeIdentityClient(HostId hostId) :
        IDirectIdentityDeliveryClient,
        IAuxiliaryTransportStreamHandler
    {
        private readonly ConcurrentDictionary<
            Guid, TaskCompletionSource<EncryptedIdentityDelivery>> pending = [];
        private readonly SemaphoreSlim sendGate = new(1, 1);
        private ITransportConnection? connection;
        private long sendSequence;

        public StreamKind Stream => StreamKind.Identity;
        public bool IsControlConnected => Volatile.Read(ref connection) is not null;

        public DirectIdentitySessionBinding Binding
        {
            get
            {
                var current = Volatile.Read(ref connection)
                    ?? throw new IdentityControlDisconnectedException();
                return new(
                    current.Session.SessionId,
                    hostId,
                    current.Session.NodeIncarnationId,
                    current.Session.Security.ChannelBinding);
            }
        }

        public IDisposable Attach(ITransportConnection value)
        {
            ArgumentNullException.ThrowIfNull(value);
            DirectSessionControlIdentityStreamHandler.RequireEphemeralSecureSession(value);
            if (Interlocked.CompareExchange(ref connection, value, null) is not null)
                throw new InvalidOperationException(
                    "A direct identity session is already attached.");
            sendSequence = 0;
            return new Attachment(this, value);
        }

        public async ValueTask<EncryptedIdentityDelivery> DeliverAsync(
            DirectIdentityDeliveryRequest request,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            var completion = new TaskCompletionSource<EncryptedIdentityDelivery>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            if (!pending.TryAdd(request.RequestId, completion))
                throw new InvalidOperationException("Identity delivery request collision.");
            var sent = false;
            try
            {
                await sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var current = Volatile.Read(ref connection)
                        ?? throw new IdentityControlDisconnectedException();
                    DirectSessionControlIdentityStreamHandler.RequireEphemeralSecureSession(current);
                    var sequence = checked(++sendSequence);
                    var payload = OrchestrationMessageCodec.Encode(
                        request, DateTimeOffset.UtcNow);
                    await current.SendAsync(new(
                        current.Session.SessionId,
                        current.Session.NodeIncarnationId,
                        StreamKind.Identity,
                        sequence,
                        sequence,
                        payload), cancellationToken).ConfigureAwait(false);
                    sent = true;
                }
                finally
                {
                    sendGate.Release();
                }
                return await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (!sent)
                    pending.TryRemove(request.RequestId, out _);
            }
        }

        public ValueTask HandleAsync(
            ITransportConnection connection,
            TransportFrame frame,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!ReferenceEquals(Volatile.Read(ref this.connection), connection))
                throw new IdentityControlDisconnectedException();
            DirectSessionControlIdentityStreamHandler.RequireEphemeralSecureSession(connection);
            if (frame.Stream != StreamKind.Identity)
                throw new OrchestrationMessageException(
                    "The direct identity client accepts only the Identity stream.");
            var decoded = OrchestrationMessageCodec.Decode(frame.Payload);
            if (decoded.Value is not EncryptedIdentityDelivery response)
                throw new OrchestrationMessageException(
                    "Node accepts only encrypted identity deliveries on the Identity stream.");
            if (!pending.TryRemove(response.RequestId, out var completion))
                throw new OrchestrationMessageException(
                    "Encrypted identity delivery has no pending request.");
            completion.TrySetResult(response);
            return ValueTask.CompletedTask;
        }

        private void Detach(ITransportConnection value)
        {
            if (!ReferenceEquals(
                    Interlocked.CompareExchange(ref connection, null, value),
                    value))
                return;
            foreach (var item in pending.ToArray())
                if (pending.TryRemove(item.Key, out var completion))
                    completion.TrySetException(new IdentityControlDisconnectedException());
        }

        private sealed class Attachment(
            DirectSessionNodeIdentityClient owner,
            ITransportConnection connection) : IDisposable
        {
            public void Dispose() => owner.Detach(connection);
        }
    }

public sealed class IdentityControlDisconnectedException()
    : IOException("The direct Control identity session is disconnected.");

public sealed class DirectSessionTaskIdentityResolver : ITaskIdentityResolver
{
    private readonly IProtectedIdentityVault vault;
    private readonly IDirectIdentityDeliveryClient client;
    private readonly TimeProvider timeProvider;

    public DirectSessionTaskIdentityResolver(
        IProtectedIdentityVault vault,
        IDirectIdentityDeliveryClient client,
        TimeProvider? timeProvider = null)
    {
        this.vault = vault ?? throw new ArgumentNullException(nameof(vault));
        this.client = client ?? throw new ArgumentNullException(nameof(client));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask<TaskIdentityLease> ResolveAsync(
        AttemptIdentity identity,
        IReadOnlyList<TaskIdentityGrantReference> grants,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(grants);
        if (grants.Count == 0)
            return new TaskIdentityLease([]);

        var handles = new List<ProtectedIdentityHandle>(grants.Count);
        try
        {
            foreach (var grant in grants)
                handles.Add(await ResolveOneAsync(identity, grant, cancellationToken).ConfigureAwait(false));
            var released = 0;
            return new TaskIdentityLease(handles, () =>
            {
                if (Interlocked.Exchange(ref released, 1) == 0)
                    foreach (var handle in handles)
                        vault.Remove(handle);
                return ValueTask.CompletedTask;
            });
        }
        catch
        {
            foreach (var handle in handles)
                vault.Remove(handle);
            throw;
        }
    }

    private async ValueTask<ProtectedIdentityHandle> ResolveOneAsync(
        AttemptIdentity identity,
        TaskIdentityGrantReference grant,
        CancellationToken cancellationToken)
    {
        ValidateGrant(identity, grant);
        if (!client.IsControlConnected)
            throw Offline(grant.OfflineBehavior);
        var session = client.Binding.Validate();
        if (session.HostId != identity.HostId ||
            session.NodeIncarnationId != identity.NodeIncarnationId)
            throw new IdentityResolutionException(
                "identity.session-binding-invalid",
                "Identity delivery is bound to another direct Control session.");

        using var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var request = new DirectIdentityDeliveryRequest(
            Guid.NewGuid(), identity, grant, recipient.ExportSubjectPublicKeyInfo());
        EncryptedIdentityDelivery response;
        try
        {
            response = await client.DeliverAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (IdentityControlDisconnectedException)
        {
            throw Offline(grant.OfflineBehavior);
        }
        if (!client.IsControlConnected)
            throw Offline(grant.OfflineBehavior);
        if (response.RequestId != request.RequestId ||
            response.UseId != grant.UseId ||
            response.ExpiresAt != grant.ExpiresAt)
            throw new IdentityResolutionException(
                "identity.delivery-binding-invalid",
                "Encrypted identity delivery does not match its request.");

        var aad = DirectIdentityCryptography.CreateAad(session, request);
        byte[]? key = null;
        byte[]? plaintext = null;
        char[]? material = null;
        try
        {
            using var sender = ECDiffieHellman.Create();
            try
            {
                sender.ImportSubjectPublicKeyInfo(response.SenderPublicKey, out var read);
                if (read != response.SenderPublicKey.Length || sender.KeySize != 256)
                    throw new CryptographicException("Invalid sender key.");
                key = DirectIdentityCryptography.DeriveKey(recipient, sender.PublicKey, aad);
                plaintext = new byte[response.Ciphertext.Length];
                using var aes = new AesGcm(key, response.AuthenticationTag.Length);
                aes.Decrypt(
                    response.Nonce,
                    response.Ciphertext,
                    response.AuthenticationTag,
                    plaintext,
                    aad);
            }
            catch (CryptographicException)
            {
                throw new IdentityResolutionException(
                    "identity.delivery-authentication-failed",
                    "Encrypted identity delivery authentication failed.");
            }

            var decoded = DirectIdentityCryptography.DecodeMaterial(plaintext);
            material = decoded.Material;
            return vault.Store(decoded.Provider, new string(material), grant.ExpiresAt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
            if (key is not null)
                CryptographicOperations.ZeroMemory(key);
            if (plaintext is not null)
                CryptographicOperations.ZeroMemory(plaintext);
            if (material is not null)
                Array.Clear(material);
        }
    }

    private void ValidateGrant(AttemptIdentity identity, TaskIdentityGrantReference grant)
    {
        if (grant.UseId == Guid.Empty ||
            grant.WorkloadId != identity.WorkloadId ||
            grant.TaskId != identity.TaskId ||
            grant.Generation != identity.Generation ||
            grant.HostId != identity.HostId ||
            grant.NodeIncarnationId != identity.NodeIncarnationId ||
            grant.ExpiresAt <= timeProvider.GetUtcNow() ||
            string.IsNullOrWhiteSpace(grant.Audience) ||
            grant.Scopes.Count == 0)
            throw new IdentityResolutionException(
                "identity.binding-invalid",
                "Task identity grant is expired or bound to another execution.");
    }

    private static IdentityResolutionException Offline(IdentityOfflineBehavior behavior) =>
        behavior == IdentityOfflineBehavior.CheckpointAndPause
            ? new(
                "identity.control-disconnected.pause",
                "Control is disconnected; the Task must checkpoint and pause for identity renewal.",
                behavior)
            : new(
                "identity.control-disconnected.fail",
                "Control is disconnected; required Task identity cannot be renewed.",
                IdentityOfflineBehavior.Fail);
}

internal static class DirectIdentityCryptography
{
    private static readonly byte[] KeyInfo = "steward-direct-identity-v1"u8.ToArray();

    internal static byte[] CreateAad(
        DirectIdentitySessionBinding session,
        DirectIdentityDeliveryRequest request)
    {
        var value = new
        {
            session.SessionId,
            SessionHostId = session.HostId,
            SessionNodeIncarnationId = session.NodeIncarnationId,
            session.ChannelBinding,
            request.RequestId,
            request.Identity.WorkloadId,
            request.Identity.PlanRevisionId,
            request.Identity.TaskId,
            request.Identity.AttemptId,
            request.Identity.Generation,
            request.Identity.HostId,
            request.Identity.NodeIncarnationId,
            request.Identity.DelegationId,
            request.Identity.CommandId,
            request.Grant.IdentityGrantId,
            request.Grant.UseId,
            request.Grant.Audience,
            Scopes = request.Grant.Scopes.Order(StringComparer.Ordinal).ToArray(),
            request.Grant.ExpiresAt
        };
        return SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, StewardJson.Options));
    }

    internal static byte[] DeriveKey(
        ECDiffieHellman local,
        ECDiffieHellmanPublicKey remote,
        ReadOnlySpan<byte> aad)
    {
        var secret = local.DeriveRawSecretAgreement(remote);
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, aad.ToArray(), KeyInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    internal static byte[] EncodeMaterial(ReadOnlySpan<char> material, string provider)
    {
        var providerLength = Encoding.UTF8.GetByteCount(provider);
        var materialLength = Encoding.UTF8.GetByteCount(material);
        var result = new byte[4 + providerLength + materialLength];
        BinaryPrimitives.WriteInt32BigEndian(result, providerLength);
        Encoding.UTF8.GetBytes(provider, result.AsSpan(4, providerLength));
        Encoding.UTF8.GetBytes(material, result.AsSpan(4 + providerLength));
        return result;
    }

    internal static (string Provider, char[] Material) DecodeMaterial(ReadOnlySpan<byte> value)
    {
        if (value.Length < 5)
            throw InvalidMaterial();
        var providerLength = BinaryPrimitives.ReadInt32BigEndian(value);
        if (providerLength <= 0 || providerLength > 4096 || 4 + providerLength >= value.Length)
            throw InvalidMaterial();
        var provider = Encoding.UTF8.GetString(value.Slice(4, providerLength));
        if (string.IsNullOrWhiteSpace(provider))
            throw InvalidMaterial();
        return (provider, Encoding.UTF8.GetChars(value[(4 + providerLength)..].ToArray()));
    }

    private static IdentityResolutionException InvalidMaterial() =>
        new("identity.delivery-invalid", "Encrypted identity delivery content is invalid.");
}
