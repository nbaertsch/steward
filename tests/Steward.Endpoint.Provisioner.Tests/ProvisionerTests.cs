using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Steward.Contracts;
using Steward.Endpoint.Provisioner;

namespace Steward.Endpoint.Provisioner.Tests;

public sealed class ProvisionerTests : IDisposable
{
    private readonly string root =
        Path.Combine(Path.GetTempPath(), "steward-provisioner-tests", Guid.NewGuid().ToString("N"));
    private byte[]? bootstrapPublicKey;
    private byte[]? controlPublicKey;

    [Fact]
    public void Configured_Entra_user_does_not_require_prelogin_account_translation()
    {
        const string account = "REDMOND\\steward-user";
        const string sid =
            "S-1-12-1-3482208621-1225039397-1130211761-942570504";

        var user = EndpointProvisioner.ResolveConfiguredUser(account, sid);

        Assert.Equal(account, user.Account);
        Assert.Equal(sid, user.Sid);
    }

    [Fact]
    public void Rollback_option_parse_does_not_require_staged_config_files()
    {
        Directory.CreateDirectory(root);
        var install = Path.Combine(root, "install");
        Directory.CreateDirectory(install);
        var transactionId = Guid.NewGuid();

        var options = ProvisionerOptions.Parse(
            [
                "--r",
                transactionId.ToString("B"),
                "--i",
                install,
                "--g",
                Path.Combine(root, "missing-config.json"),
                "--a",
                Path.Combine(root, "missing-attestation.json")
            ]);

        Assert.Equal(MsiTransactionAction.Rollback, options.TransactionAction);
        Assert.Equal(transactionId, options.MsiTransactionId);
        Assert.Equal(Path.GetFullPath(install), options.InstallRoot);
    }

    [Fact]
    public void Prepare_option_parse_requires_staged_config_file()
    {
        Directory.CreateDirectory(root);
        var install = Path.Combine(root, "install");
        Directory.CreateDirectory(install);
        var attestation = Path.Combine(root, "attestation.json");
        File.WriteAllText(attestation, "{}");

        Assert.Throws<ArgumentException>(() => ProvisionerOptions.Parse(
            [
                "--p",
                Guid.NewGuid().ToString("B"),
                "--i",
                install,
                "--g",
                Path.Combine(root, "missing-config.json"),
                "--a",
                attestation
            ]));
    }

    [Fact]
    public void Prepare_option_parse_requires_staged_attestation_file()
    {
        Directory.CreateDirectory(root);
        var install = Path.Combine(root, "install");
        Directory.CreateDirectory(install);
        var config = Path.Combine(root, "config.json");
        File.WriteAllText(config, "{}");

        Assert.Throws<ArgumentException>(() => ProvisionerOptions.Parse(
            [
                "--p",
                Guid.NewGuid().ToString("B"),
                "--i",
                install,
                "--g",
                config,
                "--a",
                Path.Combine(root, "missing-attestation.json")
            ]));
    }

    [Fact]
    public void Physical_atomic_write_flushes_file_and_reports_parent_directory_durability()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "durable.json");
        var files = new PhysicalProvisionerFileSystem();

        var result = files.WriteAtomicDurable(path, "committed"u8);

        Assert.Equal("committed", File.ReadAllText(path));
        Assert.True(result is
            ProvisionerDurableCommitResult.FileAndParentDirectoryCommitted or
            ProvisionerDurableCommitResult.
                FileCommittedParentDirectoryFlushUnsupported);
    }
    [Fact]
    public void Endpoint_acl_plan_applies_split_authority_without_inheritable_user_full_control()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var state = Path.Combine(root, "state");
        Directory.CreateDirectory(state);
        var keys = Path.Combine(state, "keys");
        Directory.CreateDirectory(keys);
        var secret = Path.Combine(keys, "node-signing.pk8");
        File.WriteAllBytes(secret, [1, 2, 3]);
        var journal = Path.Combine(state, "node.db");
        File.WriteAllBytes(journal, [4, 5, 6]);
        var currentSid = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException();
        var security = new IcaclsEndpointSecurity();

        security.PrepareStateRoot(
            state,
            currentSid.Value,
            repairExistingChildren: true);

        var rootAcl = new DirectoryInfo(state).GetAccessControl();
        var rootRules = Rules(rootAcl, currentSid);
        Assert.DoesNotContain(rootRules, rule =>
            rule.FileSystemRights.HasFlag(FileSystemRights.FullControl) &&
            rule.InheritanceFlags != InheritanceFlags.None);

        var keyRule = Assert.Single(Rules(
            new FileInfo(secret).GetAccessControl(), currentSid));
        Assert.True(keyRule.FileSystemRights.HasFlag(
            FileSystemRights.ReadAndExecute));
        Assert.False(keyRule.FileSystemRights.HasFlag(FileSystemRights.Write));

        var journalRule = Assert.Single(Rules(
            new FileInfo(journal).GetAccessControl(), currentSid));
        Assert.True(journalRule.FileSystemRights.HasFlag(FileSystemRights.Modify));
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(secret));
        Assert.Equal(new byte[] { 4, 5, 6 }, File.ReadAllBytes(journal));

        static FileSystemAccessRule[] Rules(
            FileSystemSecurity security,
            SecurityIdentifier sid) => security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference == sid)
            .ToArray();
    }

    [Fact]
    public void Endpoint_acl_excludes_AppContainer_and_task_SIDs_without_blanket_denies()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var state = Path.Combine(root, "state");
        var keys = Path.Combine(state, "keys");
        Directory.CreateDirectory(keys);
        var authorityFiles = new[]
        {
            Path.Combine(state, "identity.json"),
            Path.Combine(keys, "node-signing.pk8"),
            Path.Combine(keys, "control-signing.spki"),
            Path.Combine(state, EndpointStateFiles.ReconnectLedgerV2),
            Path.Combine(state, "node.db")
        };
        foreach (var file in authorityFiles)
            File.WriteAllText(file, "preserved");
        var user = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException();
        new IcaclsEndpointSecurity().PrepareStateRoot(
            state,
            user.Value,
            repairExistingChildren: true);
        var appContainer = new SecurityIdentifier(
            "S-1-15-2-1-2-3-4-5-6-7-8");
        var taskSid = new SecurityIdentifier(
            "S-1-5-80-111111111-222222222-333333333-444444444-555555555");

        foreach (var path in authorityFiles)
        {
            var acl = new FileInfo(path).GetAccessControl();
            var rules = acl.GetAccessRules(
                    true,
                    true,
                    typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToArray();
            Assert.DoesNotContain(rules, rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                (rule.IdentityReference == appContainer ||
                 rule.IdentityReference == taskSid));
            Assert.DoesNotContain(rules, rule =>
                rule.AccessControlType == AccessControlType.Deny);
            Assert.False(EndpointAclEffectivePolicy.AllowsRestrictedToken(
                acl,
                user,
                appContainer,
                FileSystemRights.ReadData));
            Assert.False(EndpointAclEffectivePolicy.AllowsRestrictedToken(
                acl,
                user,
                taskSid,
                FileSystemRights.ReadData));
            Assert.False(EndpointAclEffectivePolicy.AllowsRestrictedToken(
                acl,
                user,
                taskSid,
                FileSystemRights.WriteData));
        }
    }
    [Fact]
    public void Acl_migration_and_rollback_preserve_every_identity_and_state_value()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var state = Path.Combine(root, "state");
        var backup = Path.Combine(root, "state.previous");
        var keys = Path.Combine(state, "keys");
        Directory.CreateDirectory(keys);
        var values = new[]
        {
            new PreservedAclValue("identity.json", "identity"u8.ToArray()),
            new PreservedAclValue(
                Path.Combine("keys", "rdp-dvc.key"),
                new byte[] { 1, 2, 3, 4 }),
            new PreservedAclValue(
                Path.Combine("keys", "node-signing.pk8"),
                new byte[] { 5, 6, 7, 8 }),
            new PreservedAclValue(
                Path.Combine("keys", "control-signing.spki"),
                new byte[] { 9, 10, 11, 12 }),
            new PreservedAclValue(
                EndpointStateFiles.ReconnectLedgerV2,
                "reconnect"u8.ToArray()),
            new PreservedAclValue("node.db", "node-journal"u8.ToArray()),
            new PreservedAclValue(
                "execution.db",
                "execution-journal"u8.ToArray()),
            new PreservedAclValue(
                "updater-state.json",
                "updater-state"u8.ToArray())
        };
        foreach (var value in values)
        {
            var path = Path.Combine(state, value.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, value.Content);
        }
        foreach (var value in values)
        {
            var destination = Path.Combine(backup, value.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(Path.Combine(state, value.RelativePath), destination);
        }
        var sid = WindowsIdentity.GetCurrent().User?.Value ??
            throw new InvalidOperationException();
        var security = new IcaclsEndpointSecurity();
        security.PrepareStateRoot(state, sid, repairExistingChildren: true);
        security.PrepareStateRoot(backup, sid, repairExistingChildren: true);

        var failedActivation = state + ".failed";
        Directory.Move(state, failedActivation);
        Directory.Move(backup, state);

        Assert.All(values, value => Assert.Equal(
            value.Content,
            File.ReadAllBytes(Path.Combine(state, value.RelativePath))));
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
            new NoOpSecurity(),
            new AlwaysReadyHealthVerifier());

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
    public void CleanV2InstallAndRepairNeverCreateLegacyNonceInventory()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig("2.0.0");
        var state = Path.Combine(root, "state");
        RewriteManifestVersion(install, "2.0.0");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        var options = Options(install, config, state, "2.0.0");

        var receiptPath = provisioner.Provision(options);
        _ = provisioner.Provision(options);

        Assert.False(File.Exists(Path.Combine(state, "nonce-sequence.json")));
        var receipt = File.ReadAllText(receiptPath);
        Assert.DoesNotContain("connectionNonces", receipt, StringComparison.Ordinal);
        Assert.DoesNotContain("v1Migration", receipt, StringComparison.Ordinal);
        Assert.Contains("reconnectLedger", receipt, StringComparison.Ordinal);
    }

    [Fact]
    public void ExistingV1NonceInventoryIsPreservedReadOnlyAndReceiptedForMigration()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig("1.0.23");
        var state = Path.Combine(root, "state");
        RewriteManifestVersion(install, "1.0.23");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        _ = provisioner.Provision(Options(install, config, state, "1.0.23"));
        var identity = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(state, "identity.json"))).RootElement;
        var legacy = new EndpointNonceState(
            1,
            identity.GetProperty("sessionId").GetGuid(),
            identity.GetProperty("hostId").GetGuid(),
            identity.GetProperty("incarnationId").GetGuid(),
            Enumerable.Range(0, 32).Select(_ => Guid.NewGuid()).ToArray(),
            7);
        var noncePath = Path.Combine(state, "nonce-sequence.json");
        File.WriteAllText(
            noncePath,
            JsonSerializer.Serialize(
                legacy,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var original = File.ReadAllBytes(noncePath);
        RewriteAsRetainedV1Receipt(state, legacy);
        config = CreateConfig("1.1.0");
        RewriteManifestVersion(install, "1.1.0");

        var receiptPath = provisioner.Provision(
            Options(install, config, state, "1.1.0"));

        Assert.Equal(original, File.ReadAllBytes(noncePath));
        using var receipt = JsonDocument.Parse(File.ReadAllText(receiptPath));
        var migration = receipt.RootElement.GetProperty("body")
            .GetProperty("v1Migration");
        Assert.Equal(32, migration.GetProperty("nonceCount").GetInt32());
        Assert.Equal(7, migration.GetProperty("nextIndex").GetInt32());
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(original)),
            migration.GetProperty("inventorySha256").GetString());
        Assert.Equal(
            "1.0.23",
            migration.GetProperty("retainedEndpointVersion").GetString());
        Assert.Equal(
            "retained-v1-migration.json",
            migration.GetProperty("authorizationFile").GetString());
        Assert.True(File.Exists(Path.Combine(
            state,
            migration.GetProperty("authorizationFile").GetString()!)));
    }

    [Fact]
    public void UnmarkedNonceInventoryCannotAuthorizeV1Migration()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig("1.0.23");
        var state = Path.Combine(root, "state");
        RewriteManifestVersion(install, "1.0.23");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        _ = provisioner.Provision(Options(install, config, state, "1.0.23"));
        var identity = JsonSerializer.Deserialize<EndpointMachineIdentity>(
            File.ReadAllText(Path.Combine(state, "identity.json")),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        var noncePath = Path.Combine(state, "nonce-sequence.json");
        File.WriteAllText(
            noncePath,
            JsonSerializer.Serialize(
                new EndpointNonceState(
                    1,
                    identity.SessionId,
                    identity.HostId,
                    identity.IncarnationId,
                    [Guid.NewGuid(), Guid.NewGuid()],
                    0),
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        config = CreateConfig("1.1.0");
        RewriteManifestVersion(install, "1.1.0");

        Assert.Throws<InvalidDataException>(() => provisioner.Provision(
            Options(install, config, state, "1.1.0")));
    }

    [Fact]
    public void Administrative_1023_state_is_removed_only_after_structural_commit()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var legacyState = Path.Combine(
            root,
            "legacy-install",
            "Endpoint");
        var state = Path.Combine(root, "Endpoint");
        var registrar = new RecordingRegistrar();
        var retained = CreateRetainedV1State(
            install,
            legacyState,
            registrar);
        var retainedNonce = File.ReadAllBytes(Path.Combine(
            legacyState,
            "nonce-sequence.json"));
        RewriteManifestVersion(install, "1.1.0");
        var options = Options(
            install,
            CreateConfig("1.1.0"),
            state,
            "1.1.0") with
        {
            LegacyStateRoot = legacyState,
            MsiTransactionId = Guid.NewGuid()
        };
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity(),
            new NeverReadyHealthVerifier());

        _ = provisioner.Provision(options);

        Assert.True(Directory.Exists(legacyState));
        Assert.True(Directory.Exists(state));
        Assert.True(File.Exists(options.TransactionJournalPath));

        provisioner.CommitMsiTransaction(options);

        Assert.False(Directory.Exists(legacyState));
        Assert.False(File.Exists(options.TransactionJournalPath));
        var current = JsonSerializer.Deserialize<EndpointMachineIdentity>(
            File.ReadAllText(Path.Combine(state, "identity.json")),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        Assert.Equal(retained.HostId, current.HostId);
        Assert.Equal(retained.IncarnationId, current.IncarnationId);
        Assert.Equal(retained.SessionId, current.SessionId);
        Assert.Equal(
            retainedNonce,
            File.ReadAllBytes(Path.Combine(state, "nonce-sequence.json")));
        Assert.True(File.Exists(Path.Combine(
            state,
            "retained-v1-migration.json")));
    }

    [Fact]
    public void Committed_1023_recovery_finishes_legacy_cleanup_after_crash()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var legacyState = Path.Combine(
            root,
            "legacy-install",
            "Endpoint");
        var state = Path.Combine(root, "Endpoint");
        var registrar = new RecordingRegistrar();
        _ = CreateRetainedV1State(
            install,
            legacyState,
            registrar);
        RewriteManifestVersion(install, "1.1.0");
        var options = Options(
            install,
            CreateConfig("1.1.0"),
            state,
            "1.1.0") with
        {
            LegacyStateRoot = legacyState,
            MsiTransactionId = Guid.NewGuid()
        };
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity(),
            new NeverReadyHealthVerifier());
        _ = provisioner.Provision(options);
        var json = new JsonSerializerOptions(
            JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };
        var transaction =
            JsonSerializer.Deserialize<EndpointProvisionerTransaction>(
                File.ReadAllText(options.TransactionJournalPath),
                json)!;
        File.WriteAllText(
            options.TransactionJournalPath,
            JsonSerializer.Serialize(
                transaction with
                {
                    State = EndpointProvisionerTransactionState.Committed
                },
                json));

        _ = new EndpointProvisioner(
                new PhysicalProvisionerFileSystem(),
                registrar,
                new NoOpSecurity(),
                new NeverReadyHealthVerifier())
            .Provision(options);

        Assert.False(Directory.Exists(legacyState));
        Assert.False(Directory.Exists(transaction.BackupRoot));
        Assert.False(File.Exists(options.TransactionJournalPath));
        Assert.True(Directory.Exists(state));
    }

    [Fact]
    public void Administrative_1023_state_remains_authoritative_after_rollback()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var legacyState = Path.Combine(
            root,
            "legacy-install",
            "Endpoint");
        var state = Path.Combine(root, "Endpoint");
        var registrar = new RecordingRegistrar();
        var retained = CreateRetainedV1State(
            install,
            legacyState,
            registrar);
        var retainedIdentity = File.ReadAllBytes(Path.Combine(
            legacyState,
            "identity.json"));
        RewriteManifestVersion(install, "1.1.0");
        var options = Options(
            install,
            CreateConfig("1.1.0"),
            state,
            "1.1.0") with
        {
            LegacyStateRoot = legacyState,
            MsiTransactionId = Guid.NewGuid()
        };
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());

        _ = provisioner.Provision(options);
        provisioner.RollbackMsiTransaction(
            options,
            "injected_failure");

        Assert.False(Directory.Exists(state));
        Assert.True(Directory.Exists(legacyState));
        Assert.Equal(
            retainedIdentity,
            File.ReadAllBytes(Path.Combine(
                legacyState,
                "identity.json")));
        var current = JsonSerializer.Deserialize<EndpointMachineIdentity>(
            File.ReadAllText(Path.Combine(
                legacyState,
                "identity.json")),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        Assert.Equal(retained.HostId, current.HostId);
        Assert.False(File.Exists(options.TransactionJournalPath));
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
            new NoOpSecurity(),
            new AlwaysReadyHealthVerifier());
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
            new NoOpSecurity(),
            new AlwaysReadyHealthVerifier());
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
        Assert.False(Directory.Exists(Path.Combine(root, "Maintenance")));
        Assert.Empty(
            Directory.GetDirectories(
                root,
                "state.new-*",
                SearchOption.TopDirectoryOnly));
    }
    [Fact]
    public void FailedUpgradeRestoresPriorMaintenancePolicy()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var state = Path.Combine(root, "state");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new FailUpgradeRegistrar(),
            new NoOpSecurity());
        _ = provisioner.Provision(
            Options(install, CreateConfig("1.0.0"), state, "1.0.0"));
        var maintenance = Path.Combine(root, "Maintenance");
        var firstPolicy = File.ReadAllBytes(
            Path.Combine(maintenance, "service-config.json"));
        var firstBootstrap = File.ReadAllBytes(
            Path.Combine(maintenance, "bootstrap-envelope.spki"));
        RewriteManifestVersion(install, "1.1.0");

        Assert.Throws<InvalidOperationException>(() =>
            provisioner.Provision(
                Options(install, CreateConfig("1.1.0"), state, "1.1.0")));

        Assert.Equal(
            firstPolicy,
            File.ReadAllBytes(Path.Combine(maintenance, "service-config.json")));
        Assert.Equal(
            firstBootstrap,
            File.ReadAllBytes(Path.Combine(maintenance, "bootstrap-envelope.spki")));
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
        var firstReceipt = File.ReadAllBytes(Path.Combine(
            state, "bootstrap-receipt.json"));
        File.WriteAllText(Path.Combine(state, "readiness.json"), "stale");
        File.WriteAllText(
            Path.Combine(state, "readiness.json.failure"),
            "stale");
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
        Assert.False(File.Exists(Path.Combine(state, "readiness.json")));
        Assert.False(
            File.Exists(Path.Combine(state, "readiness.json.failure")));
        Assert.False(File.Exists(Path.Combine(state, "nonce-sequence.json")));
        var receiptHistory = Directory.GetFiles(
            Path.Combine(state, "receipts"),
            "bootstrap-1.0.0-*.json",
            SearchOption.TopDirectoryOnly);
        var archivedReceipt = Assert.Single(receiptHistory);
        Assert.Equal(firstReceipt, File.ReadAllBytes(archivedReceipt));
    }

    [Fact]
    public void UpgradeRejectsChangedControlTrust()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var state = Path.Combine(root, "state");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        _ = provisioner.Provision(
            Options(
                install,
                CreateConfig("1.0.0"),
                state,
                "1.0.0"));
        RewriteManifestVersion(install, "1.1.0");
        var upgradeConfig = CreateConfig("1.1.0");
        using var replacement = ECDsa.Create(
            ECCurve.NamedCurves.nistP256);
        File.WriteAllBytes(
            Path.Combine(root, "config", "control-signing.spki"),
            replacement.ExportSubjectPublicKeyInfo());

        Assert.Throws<InvalidOperationException>(() =>
            provisioner.Provision(
                Options(
                    install,
                    upgradeConfig,
                    state,
                    "1.1.0")));
    }

    [Fact]
    public void Provision_removes_legacy_register_script_transients_before_payload_validation()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var legacy = Path.Combine(
            install,
            ".register-endpoint-0123456789abcdef0123456789ABCDEF.ps1");
        File.WriteAllText(legacy, "legacy transient");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());

        _ = provisioner.Provision(Options(
            install,
            CreateConfig(),
            Path.Combine(root, "state"),
            "1.0.0"));

        Assert.False(File.Exists(legacy));
    }

    [Theory]
    [InlineData("unexpected.ps1")]
    [InlineData(".register-endpoint-malicious.ps1")]
    [InlineData(".register-endpoint-.ps1")]
    [InlineData(".register-endpoint-0123456789abcdef.ps1")]
    public void Unexpected_install_root_file_still_fails_payload_validation(
        string fileName)
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        File.WriteAllText(Path.Combine(install, fileName), "unexpected");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());

        Assert.Throws<InvalidDataException>(() => provisioner.Provision(Options(
            install,
            CreateConfig(),
            Path.Combine(root, "state"),
            "1.0.0")));
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
            new NoOpSecurity(),
            new AlwaysReadyHealthVerifier());
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
            new NoOpSecurity(),
            new AlwaysReadyHealthVerifier());
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
    public void Msi_transaction_commits_structural_install_without_live_runtime()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var state = Path.Combine(root, "state");
        var initial = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            new RecordingRegistrar(),
            new NoOpSecurity());
        _ = initial.Provision(
            Options(install, CreateConfig("1.0.0"), state, "1.0.0"));
        var priorIdentity = File.ReadAllBytes(Path.Combine(state, "identity.json"));
        RewriteManifestVersion(install, "1.1.0");
        var transactionId = Guid.NewGuid();
        var options = Options(
            install, CreateConfig("1.1.0"), state, "1.1.0") with
        {
            MsiTransactionId = transactionId
        };
        var registrar = new RecordingRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());

        _ = provisioner.Provision(options);

        Assert.True(Directory.Exists(state + ".previous"));
        Assert.True(File.Exists(options.TransactionJournalPath));
        Assert.NotEqual(priorIdentity, File.ReadAllBytes(Path.Combine(state, "identity.json")));

        new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity(),
            new NeverReadyHealthVerifier()).CommitMsiTransaction(options);

        Assert.False(Directory.Exists(state + ".previous"));
        Assert.False(File.Exists(options.TransactionJournalPath));
        Assert.Throws<InvalidDataException>(() =>
            new EndpointProvisioner(
                new PhysicalProvisionerFileSystem(),
                registrar,
                new NoOpSecurity(),
                new NeverReadyHealthVerifier()).Verify(options));
        Assert.NotEmpty(new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity(),
            new NeverReadyHealthVerifier()).VerifyInstalled(options));
        using var identity = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(state, "identity.json")));
        Assert.Equal("1.1.0", identity.RootElement
            .GetProperty("productVersion").GetString());
    }

    [Fact]
    public void Dirty_1032_entra_upgrade_rolls_back_after_staging_files_are_removed()
    {
        Directory.CreateDirectory(root);
        const string account = "AzureAD\\noahbaertsch@microsoft.com";
        const string sid =
            "S-1-12-1-3482208621-1225039397-1130211761-942570504";
        var install = CreateInstall();
        var state = Path.Combine(root, "state");
        var registrar = new TransactionalRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());
        RewriteManifestVersion(install, "1.0.32");
        _ = provisioner.Provision(Options(
            install,
            CreateConfig("1.0.32", account, sid),
            state,
            "1.0.32"));
        var priorIdentity = File.ReadAllText(Path.Combine(state, "identity.json"));
        RewriteManifestVersion(install, "1.0.37");
        var upgradeConfig = CreateConfig("1.0.37", account, sid);
        var options = Options(install, upgradeConfig, state, "1.0.37") with
        {
            MsiTransactionId = Guid.NewGuid()
        };

        _ = provisioner.Provision(options);
        File.Delete(options.ConfigPath);
        File.Delete(options.ArtifactAttestationPath);
        var rollback = ProvisionerOptions.Parse(
            [
                "--r",
                options.MsiTransactionId.Value.ToString("B"),
                "--i",
                install,
                "--s",
                state,
                "--m",
                options.EffectiveMaintenanceStateRoot,
                "--g",
                options.ConfigPath,
                "--a",
                options.ArtifactAttestationPath
            ]);

        provisioner.RollbackMsiTransaction(rollback, "msi_rollback");

        Assert.False(File.Exists(options.TransactionJournalPath));
        Assert.Equal(priorIdentity, File.ReadAllText(Path.Combine(state, "identity.json")));
        using var identity = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(state, "identity.json")));
        Assert.Equal("1.0.32", identity.RootElement
            .GetProperty("productVersion").GetString());
    }

    [Theory]
    [InlineData("InstallServices")]
    [InlineData("StartServices")]
    public void Msi_post_provision_failure_rolls_back_state_and_exact_tasks(
        string failingPhase)
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var state = Path.Combine(root, "state");
        var registrar = new TransactionalRegistrar();
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(), registrar, new NoOpSecurity());
        _ = provisioner.Provision(
            Options(install, CreateConfig("1.0.0"), state, "1.0.0"));
        var priorState = Directory.GetFiles(state, "*", SearchOption.AllDirectories)
            .ToDictionary(
                file => Path.GetRelativePath(state, file),
                File.ReadAllBytes,
                StringComparer.OrdinalIgnoreCase);
        RewriteManifestVersion(install, "1.1.0");
        var options = Options(
            install, CreateConfig("1.1.0"), state, "1.1.0") with
        {
            MsiTransactionId = Guid.NewGuid()
        };
        _ = provisioner.Provision(options);

        new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(), registrar, new NoOpSecurity())
            .RollbackMsiTransaction(options, failingPhase);

        var restored = Directory.GetFiles(state, "*", SearchOption.AllDirectories)
            .ToDictionary(
                file => Path.GetRelativePath(state, file),
                File.ReadAllBytes,
                StringComparer.OrdinalIgnoreCase);
        Assert.Equal(priorState.Keys.Order(StringComparer.OrdinalIgnoreCase),
            restored.Keys.Order(StringComparer.OrdinalIgnoreCase));
        foreach (var pair in priorState)
            Assert.Equal(pair.Value, restored[pair.Key]);
        Assert.Equal(registrar.CapturedSnapshot, registrar.RestoredSnapshot);
        Assert.False(Directory.Exists(state + ".previous"));
        Assert.False(File.Exists(options.TransactionJournalPath));
    }

    [Fact]
    public void Same_version_structural_no_op_does_not_require_live_runtime()
    {
        Directory.CreateDirectory(root);
        var install = CreateInstall();
        var config = CreateConfig();
        var state = Path.Combine(root, "state");
        var registrar = new RecordingRegistrar();
        var health = new SequenceReadyHealthVerifier(false, true);
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity(),
            health);
        var options = Options(install, config, state, "1.0.0");

        _ = provisioner.Provision(options);
        _ = provisioner.Provision(options);
        _ = provisioner.Provision(options);

        Assert.Equal(1, registrar.Registrations);
        Assert.Equal(0, health.Observations);
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
            new NoOpSecurity(),
            new AlwaysReadyHealthVerifier());
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
        if (!Directory.Exists(root))
            return;
        if (OperatingSystem.IsWindows())
        {
            var sid = WindowsIdentity.GetCurrent().User?.Value;
            if (sid is not null)
            {
                try
                {
                    EndpointProvisioner.Run(
                        "icacls.exe",
                        root,
                        "/grant",
                        $"*{sid}:(OI)(CI)F",
                        "/T",
                        "/C",
                        "/Q");
                }
                catch (InvalidOperationException)
                {
                }
            }
        }
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
            Path.Combine(install, "Steward.Maintenance.Windows.exe"),
            "fixture");
        File.WriteAllText(
            Path.Combine(install, "Steward.Maintenance.Windows.dll"),
            "fixture");
        File.WriteAllText(
            Path.Combine(
                install,
                "Steward.Maintenance.Windows.deps.json"),
            "{}");
        File.WriteAllText(
            Path.Combine(
                install,
                "Steward.Maintenance.Windows.runtimeconfig.json"),
            "{}");
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

    private string CreateConfig(
        string version = "1.0.0",
        string? provisionedUserAccount = null,
        string? provisionedUserSid = null)
    {
        if (bootstrapPublicKey is null)
        {
            using var rsa = RSA.Create(3072);
            bootstrapPublicKey = rsa.ExportSubjectPublicKeyInfo();
        }
        if (controlPublicKey is null)
        {
            using var control = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            controlPublicKey = control.ExportSubjectPublicKeyInfo();
        }
        var directory = Path.Combine(root, "config");
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(
            Path.Combine(directory, "bootstrap-envelope.spki"),
            bootstrapPublicKey);
        File.WriteAllBytes(
            Path.Combine(directory, "control-signing.spki"),
            controlPublicKey);
        var config = Path.Combine(directory, "config.json");
        File.WriteAllText(
            config,
            JsonSerializer.Serialize(
                new EndpointProvisioningConfig(
                    1,
                    version,
                    "bootstrap-envelope.spki",
                    "control-signing.spki",
                    "control",
                    provisionedUserAccount,
                    provisionedUserSid)));
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

    private EndpointMachineIdentity CreateRetainedV1State(
        string install,
        string state,
        IEndpointTaskRegistrar registrar)
    {
        var config = CreateConfig("1.0.23");
        RewriteManifestVersion(install, "1.0.23");
        var provisioner = new EndpointProvisioner(
            new PhysicalProvisionerFileSystem(),
            registrar,
            new NoOpSecurity());
        _ = provisioner.Provision(
            Options(install, config, state, "1.0.23"));
        var identity = JsonSerializer.Deserialize<EndpointMachineIdentity>(
            File.ReadAllText(Path.Combine(state, "identity.json")),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        var legacy = new EndpointNonceState(
            1,
            identity.SessionId,
            identity.HostId,
            identity.IncarnationId,
            Enumerable.Range(0, 32)
                .Select(_ => Guid.NewGuid())
                .ToArray(),
            7);
        File.WriteAllText(
            Path.Combine(state, "nonce-sequence.json"),
            JsonSerializer.Serialize(
                legacy,
                new JsonSerializerOptions(
                    JsonSerializerDefaults.Web)));
        RewriteAsRetainedV1Receipt(state, legacy);
        return identity;
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

    private sealed record PreservedAclValue(
        string RelativePath,
        byte[] Content);
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

    private sealed class TransactionalRegistrar : IEndpointTaskRegistrar
    {
        internal EndpointTaskSnapshot CapturedSnapshot { get; } =
            new("<Task keeper=\"exact\" />", true,
                "<Task endpoint=\"exact\" />", false);
        internal EndpointTaskSnapshot? RestoredSnapshot { get; private set; }

        public ProvisionedUser ResolveUser() =>
            new("TEST\\user", "S-1-5-21-1-2-3-1001");
        public EndpointTaskSnapshot Capture(EndpointMachineIdentity identity) =>
            CapturedSnapshot;
        public void Quiesce(EndpointMachineIdentity identity) { }
        public void Restore(
            EndpointTaskSnapshot snapshot,
            EndpointMachineIdentity identity) =>
            RestoredSnapshot = snapshot;
        public void Register(
            string installRoot,
            string stateRoot,
            EndpointMachineIdentity identity,
            string userAccount,
            string userSid,
            string controlIdentity)
        { }
        public bool IsHealthy(
            string installRoot,
            string stateRoot,
            EndpointMachineIdentity identity,
            string controlIdentity,
            string userAccount,
            string userSid) => true;
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

    private sealed class NeverReadyHealthVerifier :
        IEndpointReadyHealthVerifier
    {
        public bool IsKnownGood(
            ProvisionerOptions options,
            EndpointMachineIdentity identity) => false;
    }

    private sealed class AlwaysReadyHealthVerifier :
        IEndpointReadyHealthVerifier
    {
        public bool IsKnownGood(
            ProvisionerOptions options,
            EndpointMachineIdentity identity) => true;
    }

    private sealed class SequenceReadyHealthVerifier(params bool[] values) :
        IEndpointReadyHealthVerifier
    {
        private int index;
        internal int Observations { get; private set; }

        public bool IsKnownGood(
            ProvisionerOptions options,
            EndpointMachineIdentity identity)
        {
            Observations++;
            var current = Math.Min(index, values.Length - 1);
            index++;
            return values[current];
        }
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
    private static void RewriteAsRetainedV1Receipt(
        string state,
        EndpointNonceState legacy)
    {
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };
        var path = Path.Combine(state, "bootstrap-receipt.json");
        var receipt = JsonSerializer.Deserialize<EndpointProvisioningReceipt>(
            File.ReadAllText(path),
            json)!;
        var body = receipt.Body with
        {
            LegacyConnectionNonces = legacy.Nonces,
            ReconnectLedger = null,
            V1Migration = null
        };
        var privateKey = File.ReadAllBytes(Path.Combine(
            state,
            "keys",
            "node-signing.pk8"));
        try
        {
            using var signer = ECDsa.Create();
            signer.ImportPkcs8PrivateKey(privateKey, out var read);
            Assert.Equal(privateKey.Length, read);
            var canonical = JsonSerializer.SerializeToUtf8Bytes(body);
            var signature = signer.SignData(
                canonical,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            File.WriteAllText(
                path,
                JsonSerializer.Serialize(
                    new EndpointProvisioningReceipt(
                        body,
                        Convert.ToBase64String(signature)),
                    json));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }
}
