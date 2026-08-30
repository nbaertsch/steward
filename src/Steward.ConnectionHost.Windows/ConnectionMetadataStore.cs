using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows;

public sealed record DurableConnectionMetadata(
    int Version,
    string ConnectionId,
    RdpDvcSessionState State,
    long? ConnectionGeneration,
    string? RuntimeConnectionId,
    bool ViewSupported,
    bool ControlSupported,
    string Code,
    DateTimeOffset UpdatedAtUtc);

public interface IConnectionMetadataStore
{
    Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
        CancellationToken cancellationToken);

    Task SaveAsync(
        IReadOnlyCollection<DurableConnectionMetadata> connections,
        CancellationToken cancellationToken);
}

public sealed class AtomicJsonConnectionMetadataStore :
    IConnectionMetadataStore
{
    private const int MaximumStoreBytes = 1024 * 1024;
    private readonly string path;
    private readonly string directory;

    public AtomicJsonConnectionMetadataStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new ArgumentException(
                "The connection metadata path must be absolute.",
                nameof(path));
        this.path = Path.GetFullPath(path);
        directory = Path.GetDirectoryName(this.path) ??
            throw new ArgumentException(
                "The connection metadata path has no directory.",
                nameof(path));
        PrepareDirectory(directory);
    }

    public async Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return [];
        EnsureSafeDirectory(directory);
        if (!IsSafeRegularFile(path))
            throw new InvalidDataException(
                "The connection metadata file is unsafe.");
        var info = new FileInfo(path);
        if (info.Length is <= 0 or > MaximumStoreBytes)
            throw new InvalidDataException(
                "The connection metadata store has an invalid size.");
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var values = await JsonSerializer.DeserializeAsync(
                stream,
                ConnectionHostJsonContext.Default
                    .ListDurableConnectionMetadata,
                cancellationToken)
            .ConfigureAwait(false) ?? [];
        if (values.Count > ConnectionHostProtocol.MaximumConnections)
            throw new InvalidDataException(
                "The connection metadata store exceeds its bound.");
        return values;
    }

    public async Task SaveAsync(
        IReadOnlyCollection<DurableConnectionMetadata> connections,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connections);
        if (connections.Count > ConnectionHostProtocol.MaximumConnections)
            throw new InvalidDataException(
                "The connection metadata store exceeds its bound.");
        PrepareDirectory(directory);
        if (File.Exists(path) && !IsSafeRegularFile(path))
            throw new IOException(
                "The connection metadata target is unsafe.");
        var replacement = Path.Combine(
            directory,
            $".{Path.GetFileName(path)}." +
            $"{RandomNumberGenerator.GetHexString(16)}.new");
        try
        {
            await using (var stream = new FileStream(
                             replacement,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             16 * 1024,
                             FileOptions.Asynchronous |
                             FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(
                        stream,
                        connections,
                        ConnectionHostJsonContext.Default
                            .IReadOnlyCollectionDurableConnectionMetadata,
                        cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            RestrictFile(replacement);
            if (File.Exists(path) && !IsSafeRegularFile(path))
                throw new IOException(
                    "The connection metadata target became unsafe.");
            File.Move(replacement, path, overwrite: true);
            RestrictFile(path);
        }
        finally
        {
            if (File.Exists(replacement))
                File.Delete(replacement);
        }
    }

    private static void PrepareDirectory(string directory)
    {
        EnsureNoReparseSegments(directory, requireLeaf: false);
        Directory.CreateDirectory(directory);
        EnsureSafeDirectory(directory);
        var identity = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new DirectorySecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    private static void EnsureSafeDirectory(string directory)
    {
        if (!Directory.Exists(directory))
            throw new IOException(
                "The connection metadata directory is unavailable.");
        EnsureNoReparseSegments(directory, requireLeaf: true);
    }

    private static bool IsSafeRegularFile(string file)
    {
        var attributes = File.GetAttributes(file);
        return !attributes.HasFlag(FileAttributes.Directory) &&
            !attributes.HasFlag(FileAttributes.ReparsePoint);
    }

    private static void RestrictFile(string file)
    {
        if (!IsSafeRegularFile(file))
            throw new IOException(
                "Connection metadata requires a regular file.");
        var identity = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var security = new FileSecurity();
        security.SetOwner(identity);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            identity,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(file).SetAccessControl(security);
    }

    private static void EnsureNoReparseSegments(
        string path,
        bool requireLeaf)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ??
            throw new IOException(
                "The connection metadata path has no root.");
        var current = root;
        foreach (var segment in full[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (Directory.Exists(current) &&
                File.GetAttributes(current)
                    .HasFlag(FileAttributes.ReparsePoint))
                throw new IOException(
                    "Connection metadata cannot traverse reparse points.");
        }
        if (requireLeaf && !Directory.Exists(full))
            throw new IOException(
                "The connection metadata directory is unavailable.");
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = false,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(List<DurableConnectionMetadata>))]
[JsonSerializable(typeof(IReadOnlyCollection<DurableConnectionMetadata>))]
internal sealed partial class ConnectionHostJsonContext : JsonSerializerContext;
