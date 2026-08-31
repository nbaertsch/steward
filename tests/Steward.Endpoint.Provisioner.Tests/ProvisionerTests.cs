using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Steward.Endpoint.Provisioner;

namespace Steward.Endpoint.Provisioner.Tests;

public sealed class ProvisionerTests : IDisposable
{
    private readonly string root =
        Path.Combine(Path.GetTempPath(), "steward-provisioner-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void EndpointSecurityUsesParentInheritanceAndRepairsLegacyFiles()
    {
        var state = Path.Combine(root, "state");
        Directory.CreateDirectory(state);
        var currentSid = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException();
        var security = new IcaclsEndpointSecurity();

        security.PrepareStateRoot(
            state,
            currentSid.Value,
            repairExistingChildren: false);
        Directory.CreateDirectory(Path.Combine(state, "keys"));
        var file = Path.Combine(state, "keys", "secret.bin");
        File.WriteAllBytes(file, [1, 2, 3]);

        var broken = new FileSecurity();
        broken.SetAccessRuleProtection(true, false);
        new FileInfo(file).SetAccessControl(broken);
        security.PrepareStateRoot(
            state,
            currentSid.Value,
            repairExistingChildren: true);

        foreach (var path in new[] { state, Path.Combine(state, "keys"), file })
        {
            var acl = Directory.Exists(path)
                ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl()
                : new FileInfo(path).GetAccessControl();
            var rules = acl.GetAccessRules(
                    true,
                    true,
                    typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToArray();
            Assert.Equal(path == state, acl.AreAccessRulesProtected);
            Assert.Equal(3, rules.Length);
            Assert.Equal(
                new[] { "S-1-5-18", "S-1-5-32-544", currentSid.Value }
                    .Order(StringComparer.Ordinal),
                rules.Select(rule => rule.IdentityReference.Value)
                    .Order(StringComparer.Ordinal));
            Assert.All(rules, rule =>
                Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights));
            Assert.All(
                rules,
                rule => Assert.Equal(path != state, rule.IsInherited));
        }
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(file));
    }

    [Fact]
    public void RepairPreservesMachineIdentityAndSecrets()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var registrar = new RecordingRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());

        _ = provisioner.Provision(Options(install, config, state, "1.0.0"));
        var firstIdentity = File.ReadAllText(Path.Combine(state, "identity.json"));
        var firstAuth = File.ReadAllBytes(Path.Combine(state, "keys", "rdp-dvc.key"));
        var firstNode = File.ReadAllBytes(Path.Combine(state, "keys", "node-signing.pk8"));
        _ = provisioner.Provision(Options(install, config, state, "1.0.0"));

        Assert.Equal(firstIdentity, File.ReadAllText(Path.Combine(state, "identity.json")));
        Assert.Equal(firstAuth, File.ReadAllBytes(Path.Combine(state, "keys", "rdp-dvc.key")));
        Assert.Equal(firstNode, File.ReadAllBytes(Path.Combine(state, "keys", "node-signing.pk8")));
        Assert.Equal(1, registrar.Registrations);
    }

    [Fact]
    public void ReceiptIsEncryptedSignedAndExcludesPrivateSecrets()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());

        var receiptPath = provisioner.Provision(
            Options(install, config, state, "1.0.0"));
        var receiptText = File.ReadAllText(receiptPath);
        var authentication = File.ReadAllBytes(
            Path.Combine(state, "keys", "rdp-dvc.key"));
        var privateKey = File.ReadAllBytes(
            Path.Combine(state, "keys", "node-signing.pk8"));

        Assert.DoesNotContain(Convert.ToBase64String(authentication), receiptText);
        Assert.DoesNotContain(Convert.ToBase64String(privateKey), receiptText);
        var receipt = JsonSerializer.Deserialize<EndpointProvisioningReceipt>(
                          receiptText,
                          new JsonSerializerOptions(JsonSerializerDefaults.Web))
                      ?? throw new InvalidDataException();
        Assert.NotEmpty(Convert.FromBase64String(receipt.Body.Ciphertext));
        using var publicKey = ECDsa.Create();
        var publicBytes = Convert.FromBase64String(
            receipt.Body.NodeSigningPublicKey);
        publicKey.ImportSubjectPublicKeyInfo(publicBytes, out var read);
        Assert.Equal(publicBytes.Length, read);
        Assert.True(publicKey.VerifyData(
            JsonSerializer.SerializeToUtf8Bytes(receipt.Body),
            Convert.FromBase64String(receipt.Signature),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void ForgedReceiptCannotUseHealthyFastPath()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var registrar = new RecordingRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());
        var options = Options(install, config, state, "1.0.0");
        var receiptPath = provisioner.Provision(options);
        var receipt = JsonSerializer.Deserialize<EndpointProvisioningReceipt>(
                          File.ReadAllText(receiptPath))
                      ?? throw new InvalidDataException();
        File.WriteAllText(
            receiptPath,
            JsonSerializer.Serialize(
                receipt with
                {
                    Signature = Convert.ToBase64String(
                        RandomNumberGenerator.GetBytes(64))
                }));

        _ = provisioner.Provision(options);

        Assert.Equal(2, registrar.Registrations);
    }

    [Fact]
    public void TruncatedReceiptCannotUseHealthyFastPath()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var registrar = new RecordingRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());
        var options = Options(install, config, state, "1.0.0");
        var receiptPath = provisioner.Provision(options);
        File.WriteAllText(receiptPath, """{"body":""");

        _ = provisioner.Provision(options);

        Assert.Equal(2, registrar.Registrations);
    }

    [Fact]
    public void InvalidExistingIdentityFailsClosed()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        Directory.CreateDirectory(state);
        File.WriteAllText(Path.Combine(state, "identity.json"), "{}");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());

        Assert.Throws<InvalidDataException>(
            () => provisioner.Provision(
                Options(install, config, state, "1.0.0")));
    }

    [Fact]
    public void FailedFirstInstallRollsBackMachineState()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new ThrowingRegistrar(),
            new NoOpSecurity());

        Assert.Throws<InvalidOperationException>(
            () => provisioner.Provision(
                Options(install, config, state, "1.0.0")));
        Assert.False(Directory.Exists(state));
        Assert.Empty(
            Directory.GetDirectories(
                root,
                "state.new-*",
                SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public void ReceiptFailureDoesNotTouchTasksAndRollsBackFirstInstall()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var registrar = new RecordingRegistrar();
        var provisioner = new EndpointProvisioner(
            new ThrowReceiptFileSystem(),
            registrar,
            new NoOpSecurity());

        Assert.Throws<IOException>(
            () => provisioner.Provision(
                Options(install, config, state, "1.0.0")));

        Assert.Equal(0, registrar.Registrations);
        Assert.Equal(0, registrar.Restores);
        Assert.False(Directory.Exists(state));
    }

    [Fact]
    public void UpgradeUpdatesVersionButPreservesIdentity()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig("1.0.0");
        var state = Path.Combine(root, "state");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        _ = provisioner.Provision(Options(install, config, state, "1.0.0"));
        var first = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(state, "identity.json")));
        config = CreateConfig("1.1.0");
        RewriteManifestVersion(install, "1.1.0");

        _ = provisioner.Provision(Options(install, config, state, "1.1.0"));
        var second = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(state, "identity.json")));

        Assert.Equal(
            first.RootElement.GetProperty("hostId").GetGuid(),
            second.RootElement.GetProperty("hostId").GetGuid());
        Assert.Equal(
            first.RootElement.GetProperty("incarnationId").GetGuid(),
            second.RootElement.GetProperty("incarnationId").GetGuid());
        Assert.Equal(
            "1.1.0",
            second.RootElement.GetProperty("productVersion").GetString());
    }

    [Fact]
    public void MissingNativeSqliteFailsClosed()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        File.Delete(Path.Combine(install, "e_sqlite3.dll"));
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());

        Assert.Throws<InvalidDataException>(
            () => provisioner.Provision(
                Options(
                    install,
                    CreateConfig(),
                    Path.Combine(root, "state"),
                    "1.0.0")));
    }

    [Fact]
    public void DowngradeFailsClosedAndPreservesIdentity()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        RewriteManifestVersion(install, "2.0.0");
        var state = Path.Combine(root, "state");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        _ = provisioner.Provision(
            Options(install, CreateConfig("2.0.0"), state, "2.0.0"));
        var first = File.ReadAllText(Path.Combine(state, "identity.json"));
        RewriteManifestVersion(install, "1.0.0");

        Assert.Throws<InvalidOperationException>(
            () => provisioner.Provision(
                Options(install, CreateConfig("1.0.0"), state, "1.0.0")));
        Assert.Equal(
            first,
            File.ReadAllText(Path.Combine(state, "identity.json")));
    }

    [Fact]
    public void FailedUpgradeRestoresPriorStateAndTasks()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var state = Path.Combine(root, "state");
        var registrar = new FailUpgradeRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());
        _ = provisioner.Provision(
            Options(install, CreateConfig("1.0.0"), state, "1.0.0"));
        var before = Directory.GetFiles(
                state,
                "*",
                SearchOption.AllDirectories)
            .ToDictionary(
                path => Path.GetRelativePath(state, path),
                File.ReadAllBytes,
                StringComparer.Ordinal);
        RewriteManifestVersion(install, "1.1.0");

        Assert.Throws<InvalidOperationException>(
            () => provisioner.Provision(
                Options(install, CreateConfig("1.1.0"), state, "1.1.0")));

        var after = Directory.GetFiles(
                state,
                "*",
                SearchOption.AllDirectories)
            .ToDictionary(
                path => Path.GetRelativePath(state, path),
                File.ReadAllBytes,
                StringComparer.Ordinal);
        Assert.Equal(before.Keys.Order(), after.Keys.Order());
        Assert.All(before, item => Assert.Equal(item.Value, after[item.Key]));
        Assert.Equal(2, registrar.Registrations);
        Assert.Equal(1, registrar.Restores);
        Assert.Empty(
            Directory.GetDirectories(
                root,
                "state.*-*",
                SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public void FailedStateSwapRestoresPriorDirectory()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var state = Path.Combine(root, "state");
        var registrar = new RecordingRegistrar();
        var initial = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());
        _ = initial.Provision(
            Options(install, CreateConfig("1.0.0"), state, "1.0.0"));
        var before = File.ReadAllText(Path.Combine(state, "identity.json"));
        RewriteManifestVersion(install, "1.1.0");
        var upgrading = new EndpointProvisioner(
            new FailSecondMoveFileSystem(),
            registrar,
            new NoOpSecurity());

        Assert.Throws<IOException>(
            () => upgrading.Provision(
                Options(install, CreateConfig("1.1.0"), state, "1.1.0")));

        Assert.Equal(
            before,
            File.ReadAllText(Path.Combine(state, "identity.json")));
        Assert.Empty(
            Directory.GetDirectories(
                root,
                "state.*-*",
                SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public void StartupRecoversInterruptedStateRename()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var registrar = new RecordingRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());
        var options = Options(install, config, state, "1.0.0");
        _ = provisioner.Provision(options);
        var identity = File.ReadAllText(Path.Combine(state, "identity.json"));
        Directory.Move(state, state + ".previous");

        _ = provisioner.Provision(options);

        Assert.Equal(
            identity,
            File.ReadAllText(Path.Combine(state, "identity.json")));
        Assert.False(Directory.Exists(state + ".previous"));
    }

    [Fact]
    public void StartupRepairsStateRestoredFromPreviousBackup()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var options = Options(install, config, state, "1.0.0");
        var initial = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        _ = initial.Provision(options);
        new PhysicalProvisionerFileSystem().CopyDirectory(
            state,
            state + ".previous");
        File.WriteAllText(
            Path.Combine(state, "bootstrap-receipt.json"),
            "{}");
        var security = new RecordingSecurity();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            security);

        _ = provisioner.Provision(options);

        Assert.True(security.PreparedRoots.Count >= 2);
        Assert.Equal(state, security.PreparedRoots[0]);
        Assert.Equal(state, security.PreparedRoots[1]);
        Assert.False(Directory.Exists(state + ".previous"));
    }

    [Fact]
    public void VerifyOnlyDoesNotReregisterHealthyEndpoint()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var registrar = new RecordingRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());
        var options = Options(install, config, state, "1.0.0");
        var receipt = provisioner.Provision(options);

        var verified = provisioner.Verify(options with { VerifyOnly = true });

        Assert.Equal(receipt, verified);
        Assert.Equal(1, registrar.Registrations);
    }

    [Fact]
    public void StaleBackupDoesNotRollBackCurrentStateOnNextUpgrade()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var state = Path.Combine(root, "state");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        _ = provisioner.Provision(
            Options(install, CreateConfig("1.0.0"), state, "1.0.0"));
        new PhysicalProvisionerFileSystem().CopyDirectory(
            state,
            state + ".previous");
        RewriteManifestVersion(install, "1.1.0");

        _ = provisioner.Provision(
            Options(install, CreateConfig("1.1.0"), state, "1.1.0"));

        using var identity = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(state, "identity.json")));
        Assert.Equal(
            "1.1.0",
            identity.RootElement.GetProperty("productVersion").GetString());
        Assert.False(Directory.Exists(state + ".previous"));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private string CreateInstall()
    {
        var install = Path.Combine(root, "install");
        Directory.CreateDirectory(install);
        File.WriteAllText(
            Path.Combine(install, "Steward.RdpDvc.Server.Windows.dll"),
            "fixture");
        File.WriteAllText(
            Path.Combine(install, "Steward.HandleKeeper.dll"),
            "fixture");
        File.WriteAllText(
            Path.Combine(
                install,
                "Steward.RdpDvc.Server.Windows.deps.json"),
            "{}");
        File.WriteAllText(
            Path.Combine(
                install,
                "Steward.RdpDvc.Server.Windows.runtimeconfig.json"),
            "{}");
        File.WriteAllText(Path.Combine(install, "e_sqlite3.dll"), "fixture");
        var payload = Directory.GetFiles(install)
            .OrderBy(Path.GetFileName, StringComparer.Ordinal)
            .Select(path => new EndpointPayloadFile(
                Path.GetFileName(path),
                new FileInfo(path).Length,
                Convert.ToHexString(
                    SHA256.HashData(File.ReadAllBytes(path)))))
            .ToArray();
        File.WriteAllText(
            Path.Combine(install, "endpoint-payload.hashes.json"),
            JsonSerializer.Serialize(
                new EndpointPayloadManifest(1, "1.0.0", payload)));
        return install;
    }

    private string CreateConfig(string version = "1.0.0")
    {
        using var rsa = RSA.Create(3072);
        using var control = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var directory = Path.Combine(root, "config");
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(
            Path.Combine(directory, "bootstrap-envelope.spki"),
            rsa.ExportSubjectPublicKeyInfo());
        File.WriteAllBytes(
            Path.Combine(directory, "control-signing.spki"),
            control.ExportSubjectPublicKeyInfo());
        var config = Path.Combine(directory, "config.json");
        File.WriteAllText(
            config,
            JsonSerializer.Serialize(
                new EndpointProvisioningConfig(
                    1,
                    version,
                    "bootstrap-envelope.spki",
                    "control-signing.spki",
                    "control")));
        return config;
    }

    private ProvisionerOptions Options(
        string install,
        string config,
        string state,
        string version)
    {
        var path = Path.Combine(
            root,
            $"artifact-{version.Replace('.', '-')}.json");
        var configDirectory = Path.GetDirectoryName(config)
            ?? throw new InvalidOperationException();
        File.WriteAllText(
            path,
            JsonSerializer.Serialize(
                new EndpointArtifactAttestation(
                    1,
                    version,
                    new string('A', 64),
                    "microsoft/switchyard",
                    new string('B', 40),
                    "refs/heads/main",
                    "microsoft/switchyard/.github/workflows/release-endpoint.yml",
                    "123456789",
                    "{11111111-1111-1111-1111-111111111111}",
                    FileHash(config),
                    FileHash(Path.Combine(
                        configDirectory,
                        "bootstrap-envelope.spki")),
                    FileHash(Path.Combine(
                        configDirectory,
                        "control-signing.spki")),
                    "control")));
        return new(install, config, state, path);
    }

    private static string FileHash(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static void RewriteManifestVersion(
        string install,
        string version)
    {
        var path = Path.Combine(
            install,
            "endpoint-payload.hashes.json");
        var manifest = JsonSerializer.Deserialize<EndpointPayloadManifest>(
                           File.ReadAllText(path))
                       ?? throw new InvalidDataException();
        File.WriteAllText(
            path,
            JsonSerializer.Serialize(
                manifest with { ProductVersion = version }));
    }

    private sealed class RecordingRegistrar : IEndpointTaskRegistrar
    {
        public int Registrations { get; private set; }
        public int Restores { get; private set; }
        public ProvisionedUser ResolveUser() =>
            new("TEST\\user", "S-1-5-21-1-2-3-1001");
        public EndpointTaskSnapshot Capture(EndpointMachineIdentity identity) =>
            new(null, false, null, false);
        public void Quiesce(EndpointMachineIdentity identity)
        {
        }
        public void Restore(
            EndpointTaskSnapshot snapshot,
            EndpointMachineIdentity identity)
        {
            Restores++;
        }
        public void Register(
            string installRoot,
            string stateRoot,
            EndpointMachineIdentity identity,
            string userAccount,
            string userSid,
            string controlIdentity) =>
            Registrations++;

        public bool IsHealthy(
            string installRoot,
            string stateRoot,
            EndpointMachineIdentity identity,
            string controlIdentity,
            string userAccount,
            string userSid) =>
            Registrations > 0;
    }

    private sealed class ThrowReceiptFileSystem : IProvisionerFileSystem
    {
        private readonly PhysicalProvisionerFileSystem inner = new();

        public bool FileExists(string path) => inner.FileExists(path);
        public byte[] ReadAllBytes(string path) => inner.ReadAllBytes(path);
        public string ReadAllText(string path) => inner.ReadAllText(path);
        public bool DirectoryExists(string path) => inner.DirectoryExists(path);
        public IReadOnlyList<string> GetFiles(string path) =>
            inner.GetFiles(path);
        public void CreateDirectory(string path) =>
            inner.CreateDirectory(path);
        public void CopyDirectory(string source, string destination) =>
            inner.CopyDirectory(source, destination);
        public void MoveDirectory(string source, string destination) =>
            inner.MoveDirectory(source, destination);
        public void DeleteDirectory(string path) =>
            inner.DeleteDirectory(path);
        public void WriteNew(string path, ReadOnlySpan<byte> content) =>
            inner.WriteNew(path, content);
        public void WriteAtomic(string path, ReadOnlySpan<byte> content)
        {
            if (path.EndsWith(
                    "bootstrap-receipt.json",
                    StringComparison.OrdinalIgnoreCase))
                throw new IOException("receipt write failed");
            inner.WriteAtomic(path, content);
        }
    }

    private sealed class FailSecondMoveFileSystem : IProvisionerFileSystem
    {
        private readonly PhysicalProvisionerFileSystem inner = new();
        private int moves;

        public bool FileExists(string path) => inner.FileExists(path);
        public byte[] ReadAllBytes(string path) => inner.ReadAllBytes(path);
        public string ReadAllText(string path) => inner.ReadAllText(path);
        public bool DirectoryExists(string path) => inner.DirectoryExists(path);
        public IReadOnlyList<string> GetFiles(string path) =>
            inner.GetFiles(path);
        public void CreateDirectory(string path) =>
            inner.CreateDirectory(path);
        public void CopyDirectory(string source, string destination) =>
            inner.CopyDirectory(source, destination);
        public void MoveDirectory(string source, string destination)
        {
            moves++;
            if (moves == 2)
                throw new IOException("state install move failed");
            inner.MoveDirectory(source, destination);
        }
        public void DeleteDirectory(string path) =>
            inner.DeleteDirectory(path);
        public void WriteNew(string path, ReadOnlySpan<byte> content) =>
            inner.WriteNew(path, content);
        public void WriteAtomic(string path, ReadOnlySpan<byte> content) =>
            inner.WriteAtomic(path, content);
    }

    private sealed class NoOpSecurity : IEndpointSecurity
    {
        public void PrepareStateRoot(
            string stateRoot,
            string? sid,
            bool repairExistingChildren)
        {
        }

        public void GrantUserReadExecute(string installRoot, string sid)
        {
        }
    }

    private sealed class RecordingSecurity : IEndpointSecurity
    {
        public List<string> PreparedRoots { get; } = [];

        public void PrepareStateRoot(
            string stateRoot,
            string? sid,
            bool repairExistingChildren) =>
            PreparedRoots.Add(stateRoot);

        public void GrantUserReadExecute(string installRoot, string sid)
        {
        }
    }

    private sealed class ThrowingRegistrar : IEndpointTaskRegistrar
    {
        public ProvisionedUser ResolveUser() =>
            new("TEST\\user", "S-1-5-21-1-2-3-1001");
        public EndpointTaskSnapshot Capture(EndpointMachineIdentity identity) =>
            new(null, false, null, false);
        public void Quiesce(EndpointMachineIdentity identity)
        {
        }
        public void Restore(
            EndpointTaskSnapshot snapshot,
            EndpointMachineIdentity identity)
        {
        }

        public void Register(
            string installRoot,
            string stateRoot,
            EndpointMachineIdentity identity,
            string userAccount,
            string userSid,
            string controlIdentity) =>
            throw new InvalidOperationException("registration failed");

        public bool IsHealthy(
            string installRoot,
            string stateRoot,
            EndpointMachineIdentity identity,
            string controlIdentity,
            string userAccount,
            string userSid) =>
            false;
    }

    private sealed class FailUpgradeRegistrar : IEndpointTaskRegistrar
    {
        public int Registrations { get; private set; }
        public int Restores { get; private set; }

        public ProvisionedUser ResolveUser() =>
            new("TEST\\user", "S-1-5-21-1-2-3-1001");
        public EndpointTaskSnapshot Capture(EndpointMachineIdentity identity) =>
            new(null, false, null, false);
        public void Quiesce(EndpointMachineIdentity identity)
        {
        }
        public void Restore(
            EndpointTaskSnapshot snapshot,
            EndpointMachineIdentity identity)
        {
            Restores++;
        }

        public void Register(
            string installRoot,
            string stateRoot,
            EndpointMachineIdentity identity,
            string userAccount,
            string userSid,
            string controlIdentity)
        {
            Registrations++;
            if (Registrations == 2)
                throw new InvalidOperationException("upgrade registration failed");
        }

        public bool IsHealthy(
            string installRoot,
            string stateRoot,
            EndpointMachineIdentity identity,
            string controlIdentity,
            string userAccount,
            string userSid) =>
            Registrations > 0;
    }
}
