using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Transport;

namespace Steward.Endpoint.Provisioner;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var options = ProvisionerOptions.Parse(args);
            var provisioner = new EndpointProvisioner(
                new PhysicalProvisionerFileSystem(),
                new PowerShellTaskRegistrar(),
                new IcaclsEndpointSecurity());
            var receipt = options.VerifyOnly
                ? provisioner.Verify(options)
                : provisioner.Provision(options);
            Console.WriteLine(
                $"Steward endpoint {(options.VerifyOnly ? "verified" : "provisioned")}; receipt={receipt}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Steward endpoint provisioning failed: " +
                $"{exception.GetType().Name}: {exception.Message}");
            return 1;
        }
    }
}

internal sealed record ProvisionerOptions(
    string InstallRoot,
    string ConfigPath,
    string StateRoot,
    string ArtifactAttestationPath,
    bool VerifyOnly = false)
{
    internal static ProvisionerOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var verifyOnly = false;
        for (var index = 0; index < args.Length;)
        {
            if (args[index] == "--verify-only")
            {
                if (verifyOnly)
                    throw new ArgumentException(
                        "Option '--verify-only' was specified more than once.");
                verifyOnly = true;
                index++;
                continue;
            }
            if (index + 1 >= args.Length ||
                args[index] is not (
                    "--install-root" or "--config" or "--state-root" or
                    "--artifact-attestation") ||
                !values.TryAdd(args[index], args[index + 1]))
                throw new ArgumentException(
                    "Usage: --install-root PATH --config PATH --state-root PATH");
            index += 2;
        }
        return new(
            FullDirectory(Required(values, "--install-root")),
            FullFile(Required(values, "--config")),
            Path.GetFullPath(Required(values, "--state-root")),
            FullFile(Required(values, "--artifact-attestation")),
            verifyOnly);
    }

    private static string Required(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var value) &&
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"Required option '{name}' is missing.");

    private static string FullDirectory(string path)
    {
        var full = Path.GetFullPath(path);
        if (!Directory.Exists(full) ||
            File.GetAttributes(full).HasFlag(FileAttributes.ReparsePoint))
            throw new ArgumentException("Install root is not a regular directory.");
        return full;
    }

    private static string FullFile(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full) ||
            File.GetAttributes(full).HasFlag(FileAttributes.ReparsePoint))
            throw new ArgumentException("Provisioning config is not a regular file.");
        return full;
    }
}

internal sealed record EndpointProvisioningConfig(
    int Version,
    string ProductVersion,
    string BootstrapEncryptionPublicKey,
    string ControlSigningPublicKey,
    string ControlIdentity,
    string? ProvisionedUserAccount = null,
    string? ProvisionedUserSid = null);

internal sealed record EndpointArtifactAttestation(
    int Version,
    string ProductVersion,
    string MsiSha256,
    string SourceRepository,
    string SourceCommit,
    string SourceRef,
    string SignerWorkflow,
    string SourceRunId,
    string ProductCode,
    string ConfigSha256,
    string BootstrapEncryptionPublicKeySha256,
    string ControlSigningPublicKeySha256,
    string ControlIdentity);

internal sealed record EndpointMachineIdentity(
    int Version,
    string ProductVersion,
    Guid BootstrapOperationId,
    Guid SessionId,
    Guid HostId,
    Guid IncarnationId,
    string NodeIdentity,
    string ControlIdentity,
    DateTimeOffset CreatedAtUtc);

internal sealed record EndpointProvisioningReceiptBody(
    int Version,
    string ProductVersion,
    string MsiSha256,
    string SourceRepository,
    string SourceCommit,
    string SourceRef,
    string SignerWorkflow,
    string SourceRunId,
    string ProductCode,
    string ConfigSha256,
    string BootstrapEncryptionPublicKeySha256,
    string ControlSigningPublicKeySha256,
    string ControlIdentity,
    Guid BootstrapOperationId,
    Guid SessionId,
    Guid HostId,
    Guid IncarnationId,
    string NodeIdentity,
    string Ciphertext,
    string NodeSigningPublicKey,
    IReadOnlyList<Guid> ConnectionNonces,
    DateTimeOffset ProvisionedAtUtc);

internal sealed record EndpointNonceState(
    int Version,
    Guid SessionId,
    Guid HostId,
    Guid NodeIncarnationId,
    IReadOnlyList<Guid> Nonces,
    int NextIndex);

internal sealed record EndpointProvisioningReceipt(
    EndpointProvisioningReceiptBody Body,
    string Signature);

internal sealed record EndpointPayloadManifest(
    int Version,
    string ProductVersion,
    IReadOnlyList<EndpointPayloadFile> Files);

internal sealed record EndpointPayloadFile(
    string RelativePath,
    long Length,
    string Sha256);

internal interface IProvisionerFileSystem
{
    bool FileExists(string path);
    byte[] ReadAllBytes(string path);
    string ReadAllText(string path);
    bool DirectoryExists(string path);
    IReadOnlyList<string> GetFiles(string path);
    void CreateDirectory(string path);
    void CopyDirectory(string source, string destination);
    void MoveDirectory(string source, string destination);
    void DeleteDirectory(string path);
    void WriteNew(string path, ReadOnlySpan<byte> content);
    void WriteAtomic(string path, ReadOnlySpan<byte> content);
}

internal sealed class PhysicalProvisionerFileSystem : IProvisionerFileSystem
{
    public bool FileExists(string path) => File.Exists(path);
    public byte[] ReadAllBytes(string path) => File.ReadAllBytes(path);
    public string ReadAllText(string path) => File.ReadAllText(path);
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public IReadOnlyList<string> GetFiles(string path) =>
        Directory.GetFiles(path, "*", SearchOption.AllDirectories);
    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
    public void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        var start = new ProcessStartInfo
        {
            FileName = "robocopy.exe",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in new[]
                 {
                     source,
                     destination,
                     "/E",
                     "/COPY:DAT",
                     "/DCOPY:DAT",
                     "/R:0",
                     "/W:0",
                     "/XJ",
                     "/SL",
                     "/NFL",
                     "/NDL",
                     "/NJH",
                     "/NJS",
                     "/NP"
                 })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ??
            throw new InvalidOperationException(
                "Could not start the endpoint state copy.");
        process.WaitForExit();
        if (process.ExitCode >= 8)
            throw new IOException(
                $"Endpoint state copy failed with exit code {process.ExitCode}.");
    }
    public void MoveDirectory(string source, string destination) =>
        Directory.Move(source, destination);
    public void DeleteDirectory(string path)
    {
        if (Directory.Exists(path))
            Directory.Delete(path, recursive: true);
    }

    public void WriteNew(string path, ReadOnlySpan<byte> content)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough);
        stream.Write(content);
        stream.Flush(flushToDisk: true);
    }

    public void WriteAtomic(string path, ReadOnlySpan<byte> content)
    {
        var pending = path + ".new";
        File.WriteAllBytes(pending, content.ToArray());
        File.Move(pending, path, overwrite: true);
    }
}

internal interface IEndpointTaskRegistrar
{
    ProvisionedUser ResolveUser();
    EndpointTaskSnapshot Capture(EndpointMachineIdentity identity);
    void Quiesce(EndpointMachineIdentity identity);
    void Restore(
        EndpointTaskSnapshot snapshot,
        EndpointMachineIdentity identity);
    void Register(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string userAccount,
        string userSid,
        string controlIdentity);
    bool IsHealthy(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string controlIdentity,
        string userAccount,
        string userSid);
}

internal interface IEndpointSecurity
{
    void PrepareStateRoot(
        string stateRoot,
        string? sid,
        bool repairExistingChildren);
    void GrantUserReadExecute(string installRoot, string sid);
}

internal sealed class IcaclsEndpointSecurity : IEndpointSecurity
{
    public void PrepareStateRoot(
        string stateRoot,
        string? sid,
        bool repairExistingChildren)
    {
        var root = Path.GetFullPath(stateRoot);
        var rootAttributes = File.GetAttributes(root);
        if (!rootAttributes.HasFlag(FileAttributes.Directory) ||
            rootAttributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "Endpoint state root must be a plain directory.");

        var grants = new List<string>
        {
            "icacls.exe",
            root,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F"
        };
        if (sid is not null)
            grants.Add($"*{sid}:(OI)(CI)F");
        EndpointProvisioner.Run(
            grants[0],
            grants.Skip(1).ToArray());

        if (!repairExistingChildren)
            return;

        var hasChildren = Directory.EnumerateFileSystemEntries(root).Any();
        if (hasChildren)
            EndpointProvisioner.Run(
                "icacls.exe",
                Path.Combine(root, "*"),
                "/reset",
                "/T",
                "/C",
                "/L");
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     root,
                     "*",
                     SearchOption.AllDirectories))
            if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "Endpoint state cannot contain reparse points.");
    }

    public void GrantUserReadExecute(string installRoot, string sid) =>
        EndpointProvisioner.Run(
            "icacls.exe",
            installRoot,
            "/grant",
            $"*{sid}:(OI)(CI)RX",
            "/T",
            "/C");
}

internal sealed record ProvisionedUser(
    string Account,
    string Sid);

internal sealed record EndpointTaskSnapshot(
    string? KeeperXml,
    bool KeeperWasRunning,
    string? ServerXml,
    bool ServerWasRunning);

internal sealed class EndpointProvisioner(
    IProvisionerFileSystem files,
    IEndpointTaskRegistrar tasks,
    IEndpointSecurity security)
{
    private const int OperationalNonceCount = 32;
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    internal string Provision(ProvisionerOptions options)
    {
        var config = JsonSerializer.Deserialize<EndpointProvisioningConfig>(
                         files.ReadAllText(options.ConfigPath),
                         Json)
                     ?? throw new InvalidDataException(
                         "Provisioning config is empty.");
        var artifact = JsonSerializer.Deserialize<EndpointArtifactAttestation>(
                           files.ReadAllText(options.ArtifactAttestationPath),
                           Json)
                       ?? throw new InvalidDataException(
                           "Artifact attestation is empty.");
        ValidateArtifact(artifact);
        ValidateConfig(config, artifact, options);
        ValidatePayload(options.InstallRoot, artifact.ProductVersion);
        var user = ResolveUser(config);
        var backupRoot = options.StateRoot + ".previous";
        if (!files.DirectoryExists(options.StateRoot) &&
            files.DirectoryExists(backupRoot))
            files.MoveDirectory(backupRoot, options.StateRoot);
        if (files.DirectoryExists(options.StateRoot))
            security.PrepareStateRoot(
                options.StateRoot,
                user.Sid,
                repairExistingChildren: true);
        if (files.DirectoryExists(options.StateRoot) &&
            files.DirectoryExists(backupRoot))
        {
            var currentIsCommitted = false;
            try
            {
                var currentIdentity = LoadIdentity(
                    Path.Combine(options.StateRoot, "identity.json"));
                var currentReceipt = LoadValidatedReceipt(
                    Path.Combine(
                        options.StateRoot,
                        "bootstrap-receipt.json"),
                    options.StateRoot,
                    currentIdentity);
                currentIsCommitted =
                    currentReceipt.ProductVersion ==
                        currentIdentity.ProductVersion &&
                    currentReceipt.ControlIdentity ==
                        currentIdentity.ControlIdentity;
            }

            catch (JsonException)
            {
            }
            catch (InvalidDataException)
            {
            }
            catch (FormatException)
            {
            }
            catch (CryptographicException)
            {
            }
            catch (IOException)
            {
            }
            if (currentIsCommitted)
                files.DeleteDirectory(backupRoot);
            else
            {
                files.DeleteDirectory(options.StateRoot);
                files.MoveDirectory(backupRoot, options.StateRoot);
                security.PrepareStateRoot(
                    options.StateRoot,
                    user.Sid,
                    repairExistingChildren: true);
            }
        }
        var existing = files.DirectoryExists(options.StateRoot);
        if (existing &&
            TryLoadHealthyExisting(
                options,
                config,
                artifact,
                out var receipt))
            return receipt;
        var previousIdentity = existing
            ? LoadIdentity(Path.Combine(options.StateRoot, "identity.json"))
            : null;
        var workingRoot =
            options.StateRoot + $".new-{Guid.NewGuid():N}";
        var backupCreated = false;
        var newStateInstalled = false;
        EndpointTaskSnapshot? taskSnapshot = null;
        EndpointMachineIdentity? taskSnapshotIdentity = null;
        var restoreTasks = false;
        try
        {
            if (existing)
            {
                taskSnapshot = tasks.Capture(previousIdentity!);
                taskSnapshotIdentity = previousIdentity;
                restoreTasks = true;
                tasks.Quiesce(previousIdentity!);
                files.CreateDirectory(workingRoot);
                security.PrepareStateRoot(
                    workingRoot,
                    null,
                    repairExistingChildren: false);
                files.CopyDirectory(options.StateRoot, workingRoot);
            }
            else
            {
                files.CreateDirectory(workingRoot);
                security.PrepareStateRoot(
                    workingRoot,
                    null,
                    repairExistingChildren: false);
            }
            var identityPath = Path.Combine(workingRoot, "identity.json");
            var identity = LoadOrCreateIdentity(
                identityPath,
            artifact.ProductVersion,
            config.ControlIdentity);
            var keys = Path.Combine(workingRoot, "keys");
            files.CreateDirectory(keys);
            var authenticationPath = Path.Combine(keys, "rdp-dvc.key");
            var nodePrivatePath = Path.Combine(keys, "node-signing.pk8");
            var controlPublicPath =
                Path.Combine(keys, "control-signing.spki");
            var authentication = LoadOrCreateSecret(authenticationPath, 32);
            using var node = LoadOrCreateNodeKey(nodePrivatePath);
            var nodePublic = node.ExportSubjectPublicKeyInfo();
            try
            {
                var controlPublic = ResolveConfigFile(
                    options.ConfigPath,
                    config.ControlSigningPublicKey);
                var controlBytes = files.ReadAllBytes(controlPublic);
                ValidateControlPublicKey(controlBytes);
                files.WriteAtomic(controlPublicPath, controlBytes);
                CryptographicOperations.ZeroMemory(controlBytes);
                var nonceState = WriteNonceState(
                    Path.Combine(workingRoot, "nonce-sequence.json"),
                    identity);
                WriteNodeConfig(
                    Path.Combine(workingRoot, "node-host.json"),
                    options.StateRoot,
                    identity);
                WriteReceipt(
                    Path.Combine(
                        workingRoot,
                        "bootstrap-receipt.json"),
                    options,
                    config,
                    artifact,
                    identity,
                    authentication,
                    node,
                    nodePublic,
                    nonceState.Nonces);
                security.PrepareStateRoot(
                    workingRoot,
                    user.Sid,
                    repairExistingChildren: true);
                security.GrantUserReadExecute(options.InstallRoot, user.Sid);
                taskSnapshot ??= tasks.Capture(identity);
                taskSnapshotIdentity ??= identity;
                if (existing)
                {
                    files.MoveDirectory(options.StateRoot, backupRoot);
                    backupCreated = true;
                }
                files.MoveDirectory(workingRoot, options.StateRoot);
                newStateInstalled = true;
                try
                {
                    restoreTasks = true;
                    tasks.Register(
                        options.InstallRoot,
                        options.StateRoot,
                        identity,
                        user.Account,
                        user.Sid,
                        config.ControlIdentity);
                    restoreTasks = false;
                }
                catch
                {
                    files.DeleteDirectory(options.StateRoot);
                    newStateInstalled = false;
                    if (existing)
                    {
                        files.MoveDirectory(backupRoot, options.StateRoot);
                        backupCreated = false;
                    }
                    tasks.Restore(taskSnapshot, identity);
                    restoreTasks = false;
                    throw;
                }
                try
                {
                    files.DeleteDirectory(backupRoot);
                    backupCreated = false;
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
                return Path.Combine(
                    options.StateRoot,
                    "bootstrap-receipt.json");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(authentication);
                CryptographicOperations.ZeroMemory(nodePublic);
            }
        }
        catch
        {
            try
            {
                files.DeleteDirectory(workingRoot);
                if (newStateInstalled)
                {
                    files.DeleteDirectory(options.StateRoot);
                    newStateInstalled = false;
                }
                if (backupCreated &&
                    !files.DirectoryExists(options.StateRoot))
                {
                    files.MoveDirectory(backupRoot, options.StateRoot);
                    backupCreated = false;
                }
                if (!existing)
                    files.DeleteDirectory(options.StateRoot);
                if (!backupCreated)
                    files.DeleteDirectory(backupRoot);
            }
            finally
            {
                if (restoreTasks && taskSnapshot is not null)
                    tasks.Restore(
                        taskSnapshot,
                        taskSnapshotIdentity ??
                        throw new InvalidOperationException(
                            "Endpoint task snapshot identity is unavailable."));
            }
            throw;
        }
    }

    internal string Verify(ProvisionerOptions options)
    {
        var config = JsonSerializer.Deserialize<EndpointProvisioningConfig>(
                         files.ReadAllText(options.ConfigPath),
                         Json)
                     ?? throw new InvalidDataException(
                         "Provisioning config is empty.");
        var artifact = JsonSerializer.Deserialize<EndpointArtifactAttestation>(
                           files.ReadAllText(options.ArtifactAttestationPath),
                           Json)
                       ?? throw new InvalidDataException(
                           "Artifact attestation is empty.");
        ValidateArtifact(artifact);
        ValidateConfig(config, artifact, options);
        ValidatePayload(options.InstallRoot, artifact.ProductVersion);
        if (!files.DirectoryExists(options.StateRoot) ||
            !TryLoadHealthyExisting(
                options,
                config,
                artifact,
                out var receipt))
            throw new InvalidDataException(
                "Endpoint provisioning commit is not healthy.");
        return receipt;
    }

    private EndpointMachineIdentity LoadOrCreateIdentity(
        string path,
        string productVersion,
        string controlIdentity)
    {
        if (files.FileExists(path))
        {
            var existing = JsonSerializer.Deserialize<EndpointMachineIdentity>(
                               files.ReadAllText(path),
                               Json)
                           ?? throw new InvalidDataException(
                               "Existing endpoint identity is invalid.");
            if (existing.Version != 1 ||
                existing.BootstrapOperationId == Guid.Empty ||
                existing.SessionId == Guid.Empty ||
                existing.HostId == Guid.Empty ||
                existing.IncarnationId == Guid.Empty ||
                string.IsNullOrWhiteSpace(existing.NodeIdentity))
                throw new InvalidDataException(
                    "Existing endpoint identity is invalid.");
            if (!Version.TryParse(existing.ProductVersion, out var oldVersion) ||
                !Version.TryParse(productVersion, out var newVersion) ||
                newVersion < oldVersion)
                throw new InvalidOperationException(
                    "Endpoint provisioning cannot downgrade machine state.");
            var updated = existing with
            {
                ProductVersion = productVersion,
                ControlIdentity = controlIdentity
            };
            files.WriteAtomic(
                path,
                JsonSerializer.SerializeToUtf8Bytes(updated, Json));
            return updated;
        }

        var host = Guid.NewGuid();
        var identity = new EndpointMachineIdentity(
            1,
            productVersion,
            Guid.NewGuid(),
            Guid.NewGuid(),
            host,
            Guid.NewGuid(),
            $"node/{host:N}",
            controlIdentity,
            DateTimeOffset.UtcNow);
        files.WriteNew(
            path,
            JsonSerializer.SerializeToUtf8Bytes(identity, Json));
        return identity;
    }

    private ProvisionedUser ResolveUser(EndpointProvisioningConfig config)
    {
        if (config.ProvisionedUserAccount is not { Length: > 0 } account ||
            config.ProvisionedUserSid is not { Length: > 0 } sid)
            return tasks.ResolveUser();
        account = new System.Security.Principal.SecurityIdentifier(sid)
            .Translate(typeof(System.Security.Principal.NTAccount))
            .Value;
        return new(account, sid);
    }

    private EndpointMachineIdentity LoadIdentity(string path)
    {
        if (!files.FileExists(path))
            throw new InvalidDataException(
                "Existing endpoint identity is unavailable.");
        var identity = JsonSerializer.Deserialize<EndpointMachineIdentity>(
                           files.ReadAllText(path),
                           Json)
                       ?? throw new InvalidDataException(
                           "Existing endpoint identity is invalid.");
        if (identity.Version != 1 ||
            identity.BootstrapOperationId == Guid.Empty ||
            identity.SessionId == Guid.Empty ||
            identity.HostId == Guid.Empty ||
            identity.IncarnationId == Guid.Empty ||
            string.IsNullOrWhiteSpace(identity.NodeIdentity) ||
            string.IsNullOrWhiteSpace(identity.ControlIdentity))
            throw new InvalidDataException(
                "Existing endpoint identity is invalid.");
        return identity;
    }

    private byte[] LoadOrCreateSecret(string path, int length)
    {
        if (files.FileExists(path))
        {
            var existing = files.ReadAllBytes(path);
            if (existing.Length != length)
                throw new InvalidDataException(
                    "Existing endpoint secret has an invalid length.");
            return existing;
        }
        var value = RandomNumberGenerator.GetBytes(length);
        files.WriteNew(path, value);
        return value;
    }

    private ECDsa LoadOrCreateNodeKey(string path)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (files.FileExists(path))
        {
            var bytes = files.ReadAllBytes(path);
            try
            {
                key.ImportPkcs8PrivateKey(bytes, out var read);
                if (read != bytes.Length)
                    throw new CryptographicException(
                        "Existing node key contains trailing data.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
            return key;
        }
        var privateKey = key.ExportPkcs8PrivateKey();
        try
        {
            files.WriteNew(path, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
        return key;
    }

    private void WriteReceipt(
        string path,
        ProvisionerOptions options,
        EndpointProvisioningConfig config,
        EndpointArtifactAttestation artifact,
        EndpointMachineIdentity identity,
        byte[] authentication,
        ECDsa node,
        byte[] nodePublic,
        IReadOnlyList<Guid> connectionNonces)
    {
        using var rsa = RSA.Create();
        var envelopePath = ResolveConfigFile(
            options.ConfigPath,
            config.BootstrapEncryptionPublicKey);
        var publicKey = files.ReadAllBytes(envelopePath);
        try
        {
            rsa.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length)
                throw new CryptographicException(
                    "Bootstrap encryption key contains trailing data.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
        var ciphertext = RdpDvcBootstrapEnvelope.Encrypt(
            rsa,
            new(
                identity.BootstrapOperationId,
                identity.SessionId,
                identity.HostId,
                identity.IncarnationId,
                authentication,
                nodePublic));
        try
        {
            var body = new EndpointProvisioningReceiptBody(
                2,
                artifact.ProductVersion,
                artifact.MsiSha256,
                artifact.SourceRepository,
                artifact.SourceCommit,
                artifact.SourceRef,
                artifact.SignerWorkflow,
                artifact.SourceRunId,
                artifact.ProductCode,
                artifact.ConfigSha256,
                artifact.BootstrapEncryptionPublicKeySha256,
                artifact.ControlSigningPublicKeySha256,
                artifact.ControlIdentity,
                identity.BootstrapOperationId,
                identity.SessionId,
                identity.HostId,
                identity.IncarnationId,
                identity.NodeIdentity,
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(nodePublic),
                connectionNonces,
                DateTimeOffset.UtcNow);
            var canonical = JsonSerializer.SerializeToUtf8Bytes(body);
            var signature = node.SignData(
                canonical,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            var receipt = new EndpointProvisioningReceipt(
                body,
                Convert.ToBase64String(signature));
            files.WriteAtomic(
                path,
                JsonSerializer.SerializeToUtf8Bytes(receipt, Json));
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(canonical);
            CryptographicOperations.ZeroMemory(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private EndpointNonceState WriteNonceState(
        string path,
        EndpointMachineIdentity identity)
    {
        var state = new EndpointNonceState(
            1,
            identity.SessionId,
            identity.HostId,
            identity.IncarnationId,
            Enumerable.Range(0, OperationalNonceCount)
                .Select(_ => Guid.NewGuid())
                .ToArray(),
            0);
        files.WriteAtomic(
            path,
            JsonSerializer.SerializeToUtf8Bytes(state, Json));
        return state;
    }

    private void WriteNodeConfig(
        string path,
        string stateRoot,
        EndpointMachineIdentity identity)
    {
        files.WriteAtomic(
            path,
            JsonSerializer.SerializeToUtf8Bytes(
                new
                {
                    journalPath = Path.Combine(stateRoot, "node.db"),
                    executionJournalPath =
                        Path.Combine(stateRoot, "execution.db"),
                    evaluationDatabasePath =
                        Path.Combine(stateRoot, "evaluation.db"),
                    workspaceRoot = Path.Combine(stateRoot, "workspaces"),
                    spoolRoot = Path.Combine(stateRoot, "spool"),
                    spoolHighLimitBytes = 4L * 1024 * 1024 * 1024,
                    spoolHardLimitBytes = 8L * 1024 * 1024 * 1024,
                    spoolOsReserveBytes = 2L * 1024 * 1024 * 1024,
                    keeperPipeName =
                        $"Steward.Node.{identity.IncarnationId:N}",
                    nodeIncarnationId = identity.IncarnationId,
                    hostId = identity.HostId,
                    terminalJournalPath =
                        Path.Combine(stateRoot, "terminal.db"),
                    maximumTerminalSessions = 32,
                    agentsEnabled = false,
                    agentExecutable = "",
                    agentRuntimeProfile = "process-jsonl/1.0"
                },
                Json));
    }

    private void ValidateConfig(
        EndpointProvisioningConfig config,
        EndpointArtifactAttestation artifact,
        ProvisionerOptions options)
    {
        if (config.Version != 1 ||
            string.IsNullOrWhiteSpace(config.ProductVersion) ||
            config.ProductVersion != artifact.ProductVersion ||
            string.IsNullOrWhiteSpace(config.BootstrapEncryptionPublicKey) ||
            string.IsNullOrWhiteSpace(config.ControlSigningPublicKey) ||
            string.IsNullOrWhiteSpace(config.ControlIdentity) ||
            (string.IsNullOrWhiteSpace(config.ProvisionedUserAccount) !=
             string.IsNullOrWhiteSpace(config.ProvisionedUserSid)) ||
            (config.ProvisionedUserAccount is { Length: > 0 } account &&
             (account.Length > 256 || account.Any(char.IsControl))) ||
            (config.ProvisionedUserSid is { Length: > 0 } sid &&
             (!sid.StartsWith("S-1-", StringComparison.Ordinal) ||
              sid.Length > 184)) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.RdpDvc.Server.Windows.dll")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.HandleKeeper.dll")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.RdpDvc.Server.Windows.deps.json")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "Steward.RdpDvc.Server.Windows.runtimeconfig.json")) ||
            !File.Exists(Path.Combine(options.InstallRoot, "e_sqlite3.dll")) ||
            !File.Exists(Path.Combine(
                options.InstallRoot,
                "endpoint-payload.hashes.json")))
            throw new InvalidDataException(
                "Endpoint provisioning inputs are invalid.");
        var bootstrap = ResolveConfigFile(
            options.ConfigPath,
            config.BootstrapEncryptionPublicKey);
        var control = ResolveConfigFile(
            options.ConfigPath,
            config.ControlSigningPublicKey);
        if (!string.Equals(
                config.ControlIdentity,
                artifact.ControlIdentity,
                StringComparison.Ordinal) ||
            !HashMatches(options.ConfigPath, artifact.ConfigSha256) ||
            !HashMatches(
                bootstrap,
                artifact.BootstrapEncryptionPublicKeySha256) ||
            !HashMatches(
                control,
                artifact.ControlSigningPublicKeySha256))
            throw new InvalidDataException(
                "Provisioning trust inputs do not match artifact attestation.");
    }

    private static void ValidateArtifact(
        EndpointArtifactAttestation artifact)
    {
        if (artifact.Version != 1 ||
            !Version.TryParse(artifact.ProductVersion, out _) ||
            artifact.MsiSha256.Length != 64 ||
            artifact.MsiSha256.Any(character =>
                !char.IsAsciiHexDigit(character)) ||
            string.IsNullOrWhiteSpace(artifact.SourceRepository) ||
            artifact.SourceCommit.Length != 40 ||
            artifact.SourceCommit.Any(character =>
                !char.IsAsciiHexDigit(character)) ||
            !artifact.SourceRef.StartsWith("refs/", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(artifact.SignerWorkflow) ||
            string.IsNullOrWhiteSpace(artifact.SourceRunId) ||
            !Guid.TryParse(artifact.ProductCode, out var productCode) ||
            productCode == Guid.Empty ||
            !ValidSha256(artifact.ConfigSha256) ||
            !ValidSha256(artifact.BootstrapEncryptionPublicKeySha256) ||
            !ValidSha256(artifact.ControlSigningPublicKeySha256) ||
            string.IsNullOrWhiteSpace(artifact.ControlIdentity))
            throw new InvalidDataException(
                "Artifact attestation is invalid.");
    }

    private bool HashMatches(string path, string expected) =>
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(expected),
            SHA256.HashData(files.ReadAllBytes(path)));

    private static bool ValidSha256(string value) =>
        value.Length == 64 &&
        value.All(char.IsAsciiHexDigit);

    private void ValidatePayload(
        string installRoot,
        string productVersion)
    {
        var manifestPath = Path.Combine(
            installRoot,
            "endpoint-payload.hashes.json");
        var manifest = JsonSerializer.Deserialize<EndpointPayloadManifest>(
                           File.ReadAllText(manifestPath),
                           Json)
                       ?? throw new InvalidDataException(
                           "Endpoint payload manifest is empty.");
        if (manifest.Version != 1 ||
            manifest.ProductVersion != productVersion ||
            manifest.Files.Count is 0 or > 512)
            throw new InvalidDataException(
                "Endpoint payload manifest is invalid.");
        var root = Path.GetFullPath(installRoot) +
            Path.DirectorySeparatorChar;
        var expected = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var file in manifest.Files)
        {
            if (string.IsNullOrWhiteSpace(file.RelativePath) ||
                Path.IsPathFullyQualified(file.RelativePath) ||
                file.RelativePath.Contains("..", StringComparison.Ordinal) ||
                file.Sha256.Length != 64 ||
                file.Sha256.Any(character =>
                    !char.IsAsciiHexDigit(character)))
                throw new InvalidDataException(
                    "Endpoint payload manifest entry is invalid.");
            var normalized = file.RelativePath.Replace(
                '/',
                Path.DirectorySeparatorChar);
            if (!expected.Add(normalized))
                throw new InvalidDataException(
                    "Endpoint payload manifest contains duplicate entries.");
            var path = Path.GetFullPath(
                Path.Combine(installRoot, normalized));
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(path) ||
                new FileInfo(path).Length != file.Length ||
                !CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(file.Sha256),
                    SHA256.HashData(File.ReadAllBytes(path))))
                throw new InvalidDataException(
                    "Endpoint payload validation failed.");
        }
        var actual = files.GetFiles(installRoot)
            .Select(path => Path.GetRelativePath(installRoot, path))
            .Where(path => !string.Equals(
                path,
                "endpoint-payload.hashes.json",
                StringComparison.OrdinalIgnoreCase))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!actual.SetEquals(expected))
            throw new InvalidDataException(
                "Endpoint payload does not exactly match its manifest.");
    }

    private static void ValidateControlPublicKey(byte[] value)
    {
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(value, out var read);
        if (read != value.Length)
            throw new CryptographicException(
                "Control signing key contains trailing data.");
    }

    private static string ResolveConfigFile(
        string configPath,
        string relative)
    {
        if (Path.IsPathFullyQualified(relative) ||
            relative.Contains("..", StringComparison.Ordinal))
            throw new InvalidDataException(
                "Provisioning config path is invalid.");
        var root = Path.GetDirectoryName(configPath)
            ?? throw new InvalidDataException(
                "Provisioning config has no directory.");
        var path = Path.GetFullPath(Path.Combine(root, relative));
        if (!path.StartsWith(
                Path.GetFullPath(root) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path))
            throw new InvalidDataException(
                "Provisioning config file is unavailable.");
        return path;
    }

    private bool TryLoadHealthyExisting(
        ProvisionerOptions options,
        EndpointProvisioningConfig config,
        EndpointArtifactAttestation artifact,
        out string receiptPath)
    {
        receiptPath = Path.Combine(
            options.StateRoot,
            "bootstrap-receipt.json");
        var identityPath = Path.Combine(options.StateRoot, "identity.json");
        if (!files.FileExists(identityPath) ||
            !files.FileExists(receiptPath))
            return false;
        var identity = LoadIdentity(identityPath);
        if (!string.Equals(
                identity.ProductVersion,
                artifact.ProductVersion,
                StringComparison.Ordinal) ||
            !RequiredStateFiles(options.StateRoot).All(files.FileExists))
            return false;
        var user = ResolveUser(config);
        if (!tasks.IsHealthy(
            options.InstallRoot,
            options.StateRoot,
            identity,
            config.ControlIdentity,
            user.Account,
            user.Sid))
            return false;
        try
        {
            ValidateReceipt(
                receiptPath,
                options.StateRoot,
                identity,
                artifact);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private void ValidateReceipt(
        string path,
        string stateRoot,
        EndpointMachineIdentity identity,
        EndpointArtifactAttestation artifact)
    {
        var body = LoadValidatedReceipt(path, stateRoot, identity);
        if (body.ProductVersion != artifact.ProductVersion ||
            !string.Equals(
                body.MsiSha256,
                artifact.MsiSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.SourceRepository,
                artifact.SourceRepository,
                StringComparison.Ordinal) ||
            !string.Equals(
                body.SourceCommit,
                artifact.SourceCommit,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.SourceRef,
                artifact.SourceRef,
                StringComparison.Ordinal) ||
            !string.Equals(
                body.SignerWorkflow,
                artifact.SignerWorkflow,
                StringComparison.Ordinal) ||
            !string.Equals(
                body.SourceRunId,
                artifact.SourceRunId,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.ProductCode,
                artifact.ProductCode,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.ConfigSha256,
                artifact.ConfigSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.BootstrapEncryptionPublicKeySha256,
                artifact.BootstrapEncryptionPublicKeySha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                body.ControlSigningPublicKeySha256,
                artifact.ControlSigningPublicKeySha256,
                StringComparison.OrdinalIgnoreCase) ||
            body.ControlIdentity != artifact.ControlIdentity)
            throw new InvalidDataException(
                "Existing endpoint receipt does not match current artifact.");
    }

    private EndpointProvisioningReceiptBody LoadValidatedReceipt(
        string path,
        string stateRoot,
        EndpointMachineIdentity identity)
    {
        var receipt = JsonSerializer.Deserialize<EndpointProvisioningReceipt>(
                          files.ReadAllText(path),
                          Json)
                      ?? throw new InvalidDataException(
                          "Existing endpoint receipt is invalid.");
        if (receipt.Body is null ||
            string.IsNullOrWhiteSpace(receipt.Signature))
            throw new InvalidDataException(
                "Existing endpoint receipt is incomplete.");
        var body = receipt.Body;
        if (body.Version != 2 ||
            string.IsNullOrWhiteSpace(body.ProductVersion) ||
            body.ControlIdentity != identity.ControlIdentity ||
            body.BootstrapOperationId != identity.BootstrapOperationId ||
            body.SessionId != identity.SessionId ||
            body.HostId != identity.HostId ||
            body.IncarnationId != identity.IncarnationId ||
            body.NodeIdentity != identity.NodeIdentity ||
            body.ConnectionNonces is not
                { Count: OperationalNonceCount } ||
            body.ConnectionNonces.Any(value => value == Guid.Empty) ||
            body.ConnectionNonces.Distinct().Count() !=
                OperationalNonceCount)
            throw new InvalidDataException(
                "Existing endpoint receipt does not match current state.");
        var noncePath = Path.Combine(stateRoot, "nonce-sequence.json");
        var nonceState = JsonSerializer.Deserialize<EndpointNonceState>(
                             files.ReadAllText(noncePath),
                             Json)
                         ?? throw new InvalidDataException(
                             "Existing endpoint nonce state is invalid.");
        if (nonceState.Version != 1 ||
            nonceState.SessionId != identity.SessionId ||
            nonceState.HostId != identity.HostId ||
            nonceState.NodeIncarnationId != identity.IncarnationId ||
            nonceState.NextIndex < 0 ||
            nonceState.NextIndex > OperationalNonceCount ||
            nonceState.Nonces.Count != OperationalNonceCount ||
            !nonceState.Nonces.SequenceEqual(body.ConnectionNonces))
            throw new InvalidDataException(
                "Existing endpoint nonce state does not match the receipt.");
        var privateBytes = files.ReadAllBytes(
            Path.Combine(stateRoot, "keys", "node-signing.pk8"));
        try
        {
            using var node = ECDsa.Create();
            node.ImportPkcs8PrivateKey(privateBytes, out var read);
            if (read != privateBytes.Length ||
                !CryptographicOperations.FixedTimeEquals(
                    node.ExportSubjectPublicKeyInfo(),
                    Convert.FromBase64String(body.NodeSigningPublicKey)) ||
                !node.VerifyData(
                    JsonSerializer.SerializeToUtf8Bytes(body),
                    Convert.FromBase64String(receipt.Signature),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence))
                throw new InvalidDataException(
                    "Existing endpoint receipt signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateBytes);
        }
        return body;
    }

    private static IEnumerable<string> RequiredStateFiles(string root)
    {
        yield return Path.Combine(root, "keys", "rdp-dvc.key");
        yield return Path.Combine(root, "keys", "node-signing.pk8");
        yield return Path.Combine(root, "keys", "control-signing.spki");
        yield return Path.Combine(root, "nonce-sequence.json");
        yield return Path.Combine(root, "node-host.json");
    }

    internal static void Run(string executable, params string[] arguments)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException(
                $"Unable to start {executable}.");
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"{executable} failed with exit code {process.ExitCode}.");
    }
}

internal sealed class PowerShellTaskRegistrar : IEndpointTaskRegistrar
{
    public ProvisionedUser ResolveUser()
    {
        var script =
            "$p=@(Get-CimInstance Win32_UserProfile|?{!$_.Special-and$_.Loaded-and($_.SID-like'S-1-12-1-*'-or$_.SID-like'S-1-5-21-*')});" +
            "if($p.Count-ne1){exit 2};$sid=$p[0].SID;" +
            "$a=(New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value;" +
            "[pscustomobject]@{account=$a;sid=$sid}|ConvertTo-Json -Compress";
        var output = RunPowerShell(script);
        return JsonSerializer.Deserialize<ProvisionedUser>(
                   output,
                   new JsonSerializerOptions(JsonSerializerDefaults.Web))
               ?? throw new InvalidDataException(
                   "Interactive user resolution failed.");
    }

    public EndpointTaskSnapshot Capture(EndpointMachineIdentity identity)
    {
        var script = $$"""
            $a=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'HandleKeeper-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            $b=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'RdpDvcEndpoint-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            [pscustomobject]@{
              keeperXml=if($null-ne$a){Export-ScheduledTask -TaskPath '\Steward\' -TaskName $a.TaskName}else{$null}
              keeperWasRunning=$null-ne$a-and$a.State-eq'Running'
              serverXml=if($null-ne$b){Export-ScheduledTask -TaskPath '\Steward\' -TaskName $b.TaskName}else{$null}
              serverWasRunning=$null-ne$b-and$b.State-eq'Running'
            }|ConvertTo-Json -Compress
            """;
        return JsonSerializer.Deserialize<EndpointTaskSnapshot>(
                   RunPowerShell(script),
                   new JsonSerializerOptions(JsonSerializerDefaults.Web))
               ?? throw new InvalidDataException(
                   "Endpoint task snapshot failed.");
    }

    public void Quiesce(EndpointMachineIdentity identity)
    {
        var script = $$"""
            $ErrorActionPreference='Stop'
            $names=@('HandleKeeper-{{identity.HostId:N}}','RdpDvcEndpoint-{{identity.HostId:N}}')
            foreach($name in $names){
              Stop-ScheduledTask -TaskName $name -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            }
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            do {
              $running=@($names|Where-Object{
                (Get-ScheduledTask -TaskName $_ -TaskPath '\Steward\' -ErrorAction SilentlyContinue).State-eq'Running'
              }).Count
              if($running-gt0){Start-Sleep -Milliseconds 250}
            } until($running-eq0-or[DateTime]::UtcNow-ge$deadline)
            if($running-ne0){throw 'Endpoint tasks did not quiesce.'}
            """;
        RunPowerShell(script);
    }

    public void Restore(
        EndpointTaskSnapshot snapshot,
        EndpointMachineIdentity identity)
    {
        var keeperXml = snapshot.KeeperXml is null
            ? "$null"
            : "'" + Convert.ToBase64String(
                Encoding.UTF8.GetBytes(snapshot.KeeperXml)) + "'";
        var serverXml = snapshot.ServerXml is null
            ? "$null"
            : "'" + Convert.ToBase64String(
                Encoding.UTF8.GetBytes(snapshot.ServerXml)) + "'";
        var script = $$"""
            $ErrorActionPreference='Stop'
            $keeperName='HandleKeeper-{{identity.HostId:N}}'
            $serverName='RdpDvcEndpoint-{{identity.HostId:N}}'
            Stop-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            Stop-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
            $keeperData={{keeperXml}}
            $serverData={{serverXml}}
            if($null-ne$keeperData){
              $xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($keeperData))
              Register-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Xml $xml -Force|Out-Null
              if(${{snapshot.KeeperWasRunning.ToString().ToLowerInvariant()}}){Start-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\'}
            }
            if($null-ne$serverData){
              $xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($serverData))
              Register-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Xml $xml -Force|Out-Null
              if(${{snapshot.ServerWasRunning.ToString().ToLowerInvariant()}}){Start-ScheduledTask -TaskName $serverName -TaskPath '\Steward\'}
            }
            """;
        RunPowerShell(script);
    }

    public void Register(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string userAccount,
        string userSid,
        string controlIdentity)
    {
        var actions = BuildActions(
            installRoot,
            stateRoot,
            identity,
            userAccount,
            controlIdentity);
        var keeper = Path.Combine(installRoot, "Steward.HandleKeeper.exe");
        var server = Path.Combine(
            installRoot,
            "Steward.RdpDvc.Server.Windows.exe");
        if (!File.Exists(keeper) || !File.Exists(server))
            throw new FileNotFoundException(
                "Self-contained endpoint executables are unavailable.");
        var scriptPath = Path.Combine(
            installRoot,
            $".register-endpoint-{Guid.NewGuid():N}.ps1");
        var script = $$"""
            $ErrorActionPreference='Stop'
            $keeperName='HandleKeeper-{{identity.HostId:N}}'
            $serverName='RdpDvcEndpoint-{{identity.HostId:N}}'
            $keeperPrior=Get-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            $serverPrior=Get-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            $keeperXml=if($null-ne$keeperPrior){Export-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\'}else{$null}
            $serverXml=if($null-ne$serverPrior){Export-ScheduledTask -TaskName $serverName -TaskPath '\Steward\'}else{$null}
            Stop-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            Stop-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -ErrorAction SilentlyContinue
            $trigger=New-ScheduledTaskTrigger -AtLogOn -User '{{Escape(userAccount)}}'
            $principal=New-ScheduledTaskPrincipal -UserId '{{Escape(userAccount)}}' -LogonType Interactive -RunLevel Limited
            $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            $keeper=New-ScheduledTaskAction -Execute '{{Escape(actions.KeeperExecutable)}}' -Argument '{{Escape(actions.KeeperArguments)}}' -WorkingDirectory '{{Escape(installRoot)}}'
            $server=New-ScheduledTaskAction -Execute '{{Escape(actions.ServerExecutable)}}' -Argument '{{Escape(actions.ServerArguments)}}' -WorkingDirectory '{{Escape(installRoot)}}'
            function Add-RemoteConnectTrigger([string]$taskName) {
              [xml]$xml=Export-ScheduledTask -TaskName $taskName -TaskPath '\Steward\'
              $namespace=$xml.Task.NamespaceURI
              $reconnect=$xml.CreateElement('SessionStateChangeTrigger',$namespace)
              foreach($entry in @(
                @('Enabled','true'),
                @('StateChange','RemoteConnect'),
                @('UserId','{{Escape(userAccount)}}'))) {
                $element=$xml.CreateElement($entry[0],$namespace)
                $element.InnerText=$entry[1]
                [void]$reconnect.AppendChild($element)
              }
              [void]$xml.Task.Triggers.AppendChild($reconnect)
              Register-ScheduledTask -TaskName $taskName -TaskPath '\Steward\' -Xml $xml.OuterXml -Force|Out-Null
            }
            try {
              Register-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Action $keeper -Trigger $trigger -Principal $principal -Settings $settings -Force|Out-Null
              Add-RemoteConnectTrigger $keeperName
              Register-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Action $server -Trigger $trigger -Principal $principal -Settings $settings -Force|Out-Null
              Add-RemoteConnectTrigger $serverName
            } catch {
              Unregister-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
              Unregister-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Confirm:$false -ErrorAction SilentlyContinue
              if($null-ne$keeperXml){Register-ScheduledTask -TaskName $keeperName -TaskPath '\Steward\' -Xml $keeperXml -Force|Out-Null}
              if($null-ne$serverXml){Register-ScheduledTask -TaskName $serverName -TaskPath '\Steward\' -Xml $serverXml -Force|Out-Null}
              throw
            }
            """;
        File.WriteAllText(
            scriptPath,
            script,
            new UTF8Encoding(false));
        try
        {
            RunPowerShellFile(scriptPath);
            if (HasActiveRemoteSession(userSid))
            {
                RunPowerShell(
                    $$"""
                    $ErrorActionPreference='Stop'
                    Start-ScheduledTask -TaskName 'HandleKeeper-{{identity.HostId:N}}' -TaskPath '\Steward\'
                    Start-Sleep -Milliseconds 500
                    Start-ScheduledTask -TaskName 'RdpDvcEndpoint-{{identity.HostId:N}}' -TaskPath '\Steward\'
                    """);
            }
        }
        finally
        {
            File.Delete(scriptPath);
        }
    }

    public bool IsHealthy(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string controlIdentity,
        string userAccount,
        string userSid)
    {
        var expected = BuildActions(
            installRoot,
            stateRoot,
            identity,
            userAccount,
            controlIdentity);
        var script = $$"""
            $a=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'HandleKeeper-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            $b=Get-ScheduledTask -TaskPath '\Steward\' -TaskName 'RdpDvcEndpoint-{{identity.HostId:N}}' -ErrorAction SilentlyContinue
            $aUserSid=if($null-ne$a-and![string]::IsNullOrWhiteSpace($a.Principal.UserId)){
              try{([Security.Principal.NTAccount]$a.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value}catch{$null}
            }else{$null}
            $bUserSid=if($null-ne$b-and![string]::IsNullOrWhiteSpace($b.Principal.UserId)){
              try{([Security.Principal.NTAccount]$b.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value}catch{$null}
            }else{$null}
            $canonical=@($a,$b).Where({
              if($null-eq$_-or$_.Triggers.Count-ne2-or
                $null-eq$_.Settings-or
                $null-eq$_.Settings.IdleSettings-or
                $null-eq$_.Settings.NetworkSettings){return $false}
              $settings=$_.Settings
              $settings.AllowDemandStart-and
              $settings.AllowHardTerminate-and
              $settings.Compatibility-eq'Win7'-and
              [string]::IsNullOrEmpty($settings.DeleteExpiredTaskAfter)-and
              $settings.Priority-eq7-and
              $settings.RestartCount-eq0-and
              [string]::IsNullOrEmpty($settings.RestartInterval)-and
              !$settings.RunOnlyIfIdle-and
              !$settings.RunOnlyIfNetworkAvailable-and
              !$settings.WakeToRun-and
              !$settings.DisallowStartOnRemoteAppSession-and
              $settings.UseUnifiedSchedulingEngine-and
              !$settings.Volatile-and
              $settings.IdleSettings.IdleDuration-eq'PT10M'-and
              !$settings.IdleSettings.RestartOnIdle-and
              $settings.IdleSettings.StopOnIdleEnd-and
              $settings.IdleSettings.WaitTimeout-eq'PT1H'-and
              [string]::IsNullOrEmpty($settings.NetworkSettings.Id)-and
              [string]::IsNullOrEmpty($settings.NetworkSettings.Name)-and
              $null-eq$settings.MaintenanceSettings
            }).Count-eq2
            $aTriggers=if($null-ne$a){@($a.Triggers)}else{@()}
            $bTriggers=if($null-ne$b){@($b.Triggers)}else{@()}
            $aLogon=@($aTriggers.Where({
              $_.CimClass.CimClassName-eq'MSFT_TaskLogonTrigger'
            }))
            $bLogon=@($bTriggers.Where({
              $_.CimClass.CimClassName-eq'MSFT_TaskLogonTrigger'
            }))
            $aReconnect=@($aTriggers.Where({
              $_.CimClass.CimClassName-eq'MSFT_TaskSessionStateChangeTrigger'
            }))
            $bReconnect=@($bTriggers.Where({
              $_.CimClass.CimClassName-eq'MSFT_TaskSessionStateChangeTrigger'
            }))
            $triggerDefaults=@(
              $aLogon+$bLogon+$aReconnect+$bReconnect
            ).Where({
              [string]::IsNullOrEmpty($_.Delay)-and
              [string]::IsNullOrEmpty($_.EndBoundary)-and
              [string]::IsNullOrEmpty($_.ExecutionTimeLimit)-and
              [string]::IsNullOrEmpty($_.Id)-and
              [string]::IsNullOrEmpty($_.StartBoundary)-and
              ($null-eq$_.Repetition-or(
                [string]::IsNullOrEmpty($_.Repetition.Duration)-and
                [string]::IsNullOrEmpty($_.Repetition.Interval)-and
                !$_.Repetition.StopAtDurationEnd))
            }).Count-eq4
            $ok=$null-ne$a-and$null-ne$b-and
              $canonical-and$triggerDefaults-and
              $a.Actions.Count-eq1-and$b.Actions.Count-eq1-and
              $a.Actions[0].Execute-eq'{{Escape(expected.KeeperExecutable)}}'-and
              $a.Actions[0].Arguments-eq'{{Escape(expected.KeeperArguments)}}'-and
              $a.Actions[0].WorkingDirectory-eq'{{Escape(installRoot)}}'-and
              $b.Actions[0].Execute-eq'{{Escape(expected.ServerExecutable)}}'-and
              $b.Actions[0].Arguments-eq'{{Escape(expected.ServerArguments)}}'-and
              $b.Actions[0].WorkingDirectory-eq'{{Escape(installRoot)}}'-and
              $aUserSid-eq'{{Escape(userSid)}}'-and
              $bUserSid-eq'{{Escape(userSid)}}'-and
              $a.Principal.LogonType-eq'Interactive'-and
              $b.Principal.LogonType-eq'Interactive'-and
              $a.Principal.RunLevel-eq'Limited'-and
              $b.Principal.RunLevel-eq'Limited'-and
              $a.Principal.ProcessTokenSidType-eq'Default'-and
              $b.Principal.ProcessTokenSidType-eq'Default'-and
              [string]::IsNullOrEmpty(($a.Principal.RequiredPrivilege-join''))-and
              [string]::IsNullOrEmpty(($b.Principal.RequiredPrivilege-join''))-and
              [string]::IsNullOrEmpty($a.Principal.DisplayName)-and
              [string]::IsNullOrEmpty($b.Principal.DisplayName)-and
              $a.Principal.Id-eq'Author'-and
              $b.Principal.Id-eq'Author'-and
              $aLogon.Count-eq1-and$bLogon.Count-eq1-and
              $aReconnect.Count-eq1-and$bReconnect.Count-eq1-and
              $aLogon[0].UserId-eq'{{Escape(userAccount)}}'-and
              $bLogon[0].UserId-eq'{{Escape(userAccount)}}'-and
              $aLogon[0].Enabled-and$bLogon[0].Enabled-and
              $aReconnect[0].UserId-eq'{{Escape(userAccount)}}'-and
              $bReconnect[0].UserId-eq'{{Escape(userAccount)}}'-and
              $aReconnect[0].StateChange-eq3-and
              $bReconnect[0].StateChange-eq3-and
              $aReconnect[0].Enabled-and$bReconnect[0].Enabled-and
              $a.Settings.Enabled-and$b.Settings.Enabled-and
              $a.Settings.Hidden-and$b.Settings.Hidden-and
              $a.Settings.StartWhenAvailable-and
              $b.Settings.StartWhenAvailable-and
              !$a.Settings.DisallowStartIfOnBatteries-and
              !$b.Settings.DisallowStartIfOnBatteries-and
              !$a.Settings.StopIfGoingOnBatteries-and
              !$b.Settings.StopIfGoingOnBatteries-and
              $a.Settings.ExecutionTimeLimit-eq'PT0S'-and
              $b.Settings.ExecutionTimeLimit-eq'PT0S'-and
              $a.Settings.MultipleInstances-eq'IgnoreNew'-and
              $b.Settings.MultipleInstances-eq'IgnoreNew'
            $ok=$ok-and$a.State-in@('Ready','Running')-and
              $b.State-in@('Ready','Running')
            if($ok){'true'}else{'false'}
            """;
        return bool.TryParse(RunPowerShell(script), out var healthy) &&
            healthy;
    }

    private static EndpointActions BuildActions(
        string installRoot,
        string stateRoot,
        EndpointMachineIdentity identity,
        string userAccount,
        string controlIdentity)
    {
        var keys = Path.Combine(stateRoot, "keys");
        return new(
            Path.Combine(installRoot, "Steward.HandleKeeper.exe"),
            $"--console --pipe \"Steward.Node.{identity.IncarnationId:N}\" " +
            $"--node-account \"{userAccount}\"",
            Path.Combine(
                installRoot,
                "Steward.RdpDvc.Server.Windows.exe"),
            $"--session-id {identity.SessionId:D} " +
            $"--host-id {identity.HostId:D} --incarnation-id {identity.IncarnationId:D} " +
            $"--auth-key-file \"{Path.Combine(keys, "rdp-dvc.key")}\" " +
            $"--nonce-sequence-file \"{Path.Combine(stateRoot, "nonce-sequence.json")}\" " +
            $"--readiness-receipt-file \"{Path.Combine(stateRoot, "readiness.json")}\" " +
            $"--node-host-config \"{Path.Combine(stateRoot, "node-host.json")}\" " +
            $"--portable-state-root \"{Path.Combine(stateRoot, "portable")}\" " +
            $"--credential-vault-root \"{Path.Combine(stateRoot, "credentials")}\" " +
            $"--node-signing-key-file \"{Path.Combine(keys, "node-signing.pk8")}\" " +
            $"--node-identity \"{identity.NodeIdentity}\" " +
            $"--control-signing-key-file \"{Path.Combine(keys, "control-signing.spki")}\" " +
            $"--control-identity \"{controlIdentity}\"");
    }

    private static bool HasActiveRemoteSession(string userSid)
    {
        if (!Native.WTSEnumerateSessions(
                IntPtr.Zero,
                0,
                1,
                out var sessions,
                out var count))
            throw new InvalidOperationException(
                "Active RDP session enumeration failed.");
        try
        {
            var size = Marshal.SizeOf<Native.WtsSessionInfo>();
            for (var index = 0; index < count; index++)
            {
                var session = Marshal.PtrToStructure<Native.WtsSessionInfo>(
                    IntPtr.Add(sessions, index * size));
                if (session.SessionId == 0 ||
                    session.State != Native.WtsConnectState.Active ||
                    QueryProtocol(session.SessionId) != 2 ||
                    !Native.WTSQueryUserToken(
                        (uint)session.SessionId,
                        out var token))
                    continue;
                try
                {
                    using var identity = new WindowsIdentity(token);
                    if (string.Equals(
                            identity.User?.Value,
                            userSid,
                            StringComparison.Ordinal))
                        return true;
                }
                finally
                {
                    Native.CloseHandle(token);
                }
            }
            return false;
        }
        finally
        {
            Native.WTSFreeMemory(sessions);
        }
    }

    private static ushort QueryProtocol(int sessionId)
    {
        if (!Native.WTSQuerySessionInformation(
                IntPtr.Zero,
                (uint)sessionId,
                Native.WtsInfoClass.ClientProtocolType,
                out var buffer,
                out var bytes))
            throw new InvalidOperationException(
                "Active RDP session protocol query failed.");
        try
        {
            if (bytes < sizeof(ushort))
                throw new InvalidDataException(
                    "Active RDP session protocol is invalid.");
            return unchecked((ushort)Marshal.ReadInt16(buffer));
        }
        finally
        {
            Native.WTSFreeMemory(buffer);
        }
    }

    private static class Native
    {
        internal enum WtsConnectState
        {
            Active = 0
        }

        internal enum WtsInfoClass
        {
            ClientProtocolType = 16
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WtsSessionInfo
        {
            internal int SessionId;
            internal nint StationName;
            internal WtsConnectState State;
        }

        [DllImport(
            "Wtsapi32.dll",
            EntryPoint = "WTSEnumerateSessionsW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSEnumerateSessions(
            nint server,
            int reserved,
            int version,
            out nint sessionInfo,
            out int count);

        [DllImport(
            "Wtsapi32.dll",
            EntryPoint = "WTSQuerySessionInformationW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSQuerySessionInformation(
            nint server,
            uint sessionId,
            WtsInfoClass infoClass,
            out nint buffer,
            out uint bytesReturned);

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSQueryUserToken(
            uint sessionId,
            out nint token);

        [DllImport("Wtsapi32.dll")]
        internal static extern void WTSFreeMemory(nint memory);

        [DllImport("Kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(nint handle);
    }

    private static string Escape(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static string RunPowerShell(string script)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"steward-provision-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(path, script, new UTF8Encoding(false));
        try
        {
            return RunPowerShellFile(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    internal sealed record EndpointActions(
        string KeeperExecutable,
        string KeeperArguments,
        string ServerExecutable,
        string ServerArguments);

    private static string RunPowerShellFile(string path)
    {
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.SystemDirectory,
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in new[]
                 {
                     "-NoProfile",
                     "-NonInteractive",
                     "-ExecutionPolicy",
                     "Bypass",
                     "-File",
                     path
                 })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException(
                "Unable to start Windows PowerShell.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                "Endpoint task registration failed: " +
                error.Trim()[..Math.Min(error.Trim().Length, 2_000)]);
        return output.Trim();
    }
}
