using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Domain;

namespace Steward.Providers.DevBox;

public interface IDevBoxRdpDvcBootstrapCheckpointProtector
{
    byte[] Protect(
        ReadOnlySpan<byte> plaintext,
        ProviderOperationId operationId,
        string idempotencyKey);

    byte[] Unprotect(
        ReadOnlySpan<byte> protectedData,
        ProviderOperationId operationId,
        string idempotencyKey);
}

public sealed class AesGcmDevBoxRdpDvcBootstrapCheckpointProtector :
    IDevBoxRdpDvcBootstrapCheckpointProtector,
    IDisposable
{
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private readonly byte[] _key;
    private bool _disposed;

    public AesGcmDevBoxRdpDvcBootstrapCheckpointProtector(
        ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException(
                "RDP DVC bootstrap checkpoint key must be 256 bits.",
                nameof(key));
        _key = key.ToArray();
    }

    public byte[] Protect(
        ReadOnlySpan<byte> plaintext,
        ProviderOperationId operationId,
        string idempotencyKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];
        using (var aes = new AesGcm(_key, TagBytes))
            aes.Encrypt(
                nonce,
                plaintext,
                ciphertext,
                tag,
                AssociatedData(operationId, idempotencyKey));
        var result = new byte[1 + NonceBytes + TagBytes + ciphertext.Length];
        result[0] = 1;
        nonce.CopyTo(result.AsSpan(1, NonceBytes));
        tag.CopyTo(result.AsSpan(1 + NonceBytes, TagBytes));
        ciphertext.CopyTo(result.AsSpan(1 + NonceBytes + TagBytes));
        CryptographicOperations.ZeroMemory(ciphertext);
        return result;
    }

    public byte[] Unprotect(
        ReadOnlySpan<byte> protectedData,
        ProviderOperationId operationId,
        string idempotencyKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (protectedData.Length < 1 + NonceBytes + TagBytes ||
            protectedData[0] != 1)
            throw new InvalidDataException(
                "RDP DVC bootstrap checkpoint has an invalid envelope.");
        var plaintext = new byte[
            protectedData.Length - 1 - NonceBytes - TagBytes];
        try
        {
            using var aes = new AesGcm(_key, TagBytes);
            aes.Decrypt(
                protectedData.Slice(1, NonceBytes),
                protectedData[(1 + NonceBytes + TagBytes)..],
                protectedData.Slice(1 + NonceBytes, TagBytes),
                plaintext,
                AssociatedData(operationId, idempotencyKey));
            return plaintext;
        }
        catch (CryptographicException exception)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new InvalidDataException(
                "RDP DVC bootstrap checkpoint authentication failed.",
                exception);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        CryptographicOperations.ZeroMemory(_key);
        _disposed = true;
    }

    private static byte[] AssociatedData(
        ProviderOperationId operationId,
        string idempotencyKey) =>
        Encoding.UTF8.GetBytes(
            $"{DevBoxRdpDvcBootstrapPlan.ProviderName}\n" +
            $"{operationId}\n{idempotencyKey}");
}

public sealed class EncryptedFileDevBoxRdpDvcBootstrapStore(
    string directory,
    IDevBoxRdpDvcBootstrapCheckpointProtector protector) :
    ISecureDurableDevBoxRdpDvcBootstrapStore
{
    private const int MaximumCheckpointBytes = 32 * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = CreateJson();
    private readonly string _directory = Path.GetFullPath(directory);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates =
        new(StringComparer.Ordinal);

    public async Task<DevBoxRdpDvcBootstrapCheckpoint?> LoadAsync(
        ProviderOperationId operationId,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        var path = PathFor(operationId, idempotencyKey);
        var gate = _gates.GetOrAdd(path, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(path))
                return null;
            var protectedData = await File.ReadAllBytesAsync(
                    path,
                    cancellationToken)
                .ConfigureAwait(false);
            if (protectedData.Length is 0 or > MaximumCheckpointBytes)
                throw new InvalidDataException(
                    "RDP DVC bootstrap checkpoint exceeds its bound.");
            var plaintext = protector.Unprotect(
                protectedData,
                operationId,
                idempotencyKey);
            try
            {
                return JsonSerializer.Deserialize<
                           DevBoxRdpDvcBootstrapCheckpoint>(
                           plaintext,
                           Json)
                       ?? throw new InvalidDataException(
                           "RDP DVC bootstrap checkpoint is empty.");
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException(
                    "RDP DVC bootstrap checkpoint is invalid.",
                    exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    public Task RecordBeforeEffectAsync(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint,
        CancellationToken cancellationToken) =>
        SaveAsync(checkpoint, cancellationToken);

    public Task RecordCompletedAsync(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint,
        CancellationToken cancellationToken) =>
        SaveAsync(checkpoint, cancellationToken);

    private async Task SaveAsync(
        DevBoxRdpDvcBootstrapCheckpoint checkpoint,
        CancellationToken cancellationToken)
    {
        var path = PathFor(
            checkpoint.Handle.OperationId,
            checkpoint.Handle.IdempotencyKey);
        var gate = _gates.GetOrAdd(path, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(_directory);
            var plaintext = JsonSerializer.SerializeToUtf8Bytes(
                checkpoint,
                Json);
            if (plaintext.Length > MaximumCheckpointBytes)
                throw new InvalidDataException(
                    "RDP DVC bootstrap checkpoint exceeds its bound.");
            byte[]? protectedData = null;
            var pending = path + "." + Guid.NewGuid().ToString("N") + ".new";
            try
            {
                protectedData = protector.Protect(
                    plaintext,
                    checkpoint.Handle.OperationId,
                    checkpoint.Handle.IdempotencyKey);
                await using (var stream = new FileStream(
                                 pending,
                                 FileMode.CreateNew,
                                 FileAccess.Write,
                                 FileShare.None,
                                 4096,
                                 FileOptions.Asynchronous |
                                 FileOptions.WriteThrough))
                {
                    await stream.WriteAsync(
                            protectedData,
                            cancellationToken)
                        .ConfigureAwait(false);
                    await stream.FlushAsync(cancellationToken)
                        .ConfigureAwait(false);
                }
                File.Move(pending, path, overwrite: true);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                if (protectedData is not null)
                    CryptographicOperations.ZeroMemory(protectedData);
                if (File.Exists(pending))
                    File.Delete(pending);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private string PathFor(
        ProviderOperationId operationId,
        string idempotencyKey)
    {
        if (operationId.Value == Guid.Empty ||
            string.IsNullOrWhiteSpace(idempotencyKey))
            throw new ArgumentException(
                "RDP DVC bootstrap checkpoint identity is invalid.");
        var keyHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(idempotencyKey)))
            .ToLowerInvariant();
        return Path.Combine(
            _directory,
            $"{operationId.Value:N}-{keyHash}.checkpoint");
    }

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new ProviderOperationIdConverter());
        return options;
    }

    private sealed class ProviderOperationIdConverter :
        JsonConverter<ProviderOperationId>
    {
        public override ProviderOperationId Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options) =>
            ProviderOperationId.Parse(
                reader.GetString()
                ?? throw new JsonException(
                    "Provider operation ID is missing."));

        public override void Write(
            Utf8JsonWriter writer,
            ProviderOperationId value,
            JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString());
    }
}
