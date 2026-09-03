using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Azure;
using Azure.Developer.DevCenter;
using Steward.DevBox.Windows;
using Steward.Domain;
using Steward.Providers.Abstractions;
using Steward.Providers.DevBox;
using Steward.Transport;

const string Consent =
    "I_UNDERSTAND_THIS_MUTATES_THE_RETAINED_DEV_BOX_CUSTOMIZATION";

if (args is
    [
        "--list-task-definitions",
        var endpointText,
        var projectName
    ])
{
    var endpoint = new Uri(endpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var catalog = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var definitions = await catalog.ListTaskDefinitionsAsync(
        projectName,
        CancellationToken.None);
    Console.WriteLine(JsonSerializer.Serialize(
        definitions,
        new JsonSerializerOptions(
            JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        }));
    return 0;
}

if (args is
    [
        "--check-remote-connection",
        var remoteEndpointText,
        var remoteProjectName,
        var remoteBoxName
    ])
{
    var endpoint = new Uri(remoteEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var remote = await sdk.GetRemoteConnectionAsync(
        remoteProjectName,
        "me",
        remoteBoxName,
        CancellationToken.None);
    Console.WriteLine(
        remote.Value.RdpConnectionUri is null
            ? "REMOTE_CONNECTION_MISSING"
            : "REMOTE_CONNECTION_READY");
    return 0;
}

if (args is
    [
        "--list-groups",
        var groupsEndpointText,
        var groupsProjectName,
        var groupsBoxName
    ])
{
    var endpoint = new Uri(groupsEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    Console.WriteLine(JsonSerializer.Serialize(
        await customizations.ListAsync(
            groupsProjectName,
            "me",
            groupsBoxName,
            CancellationToken.None),
        new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        }));
    return 0;
}

if (args is
    [
        "--list-customization-groups",
        var listEndpointText,
        var listProjectName,
        var listBoxName
    ])
{
    var endpoint = new Uri(listEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var groups = await customizations.ListAsync(
        listProjectName,
        "me",
        listBoxName,
        CancellationToken.None);
    foreach (var group in groups
                 .OrderByDescending(value => value.StartTime)
                 .Take(200))
        Console.WriteLine(JsonSerializer.Serialize(group));
    return 0;
}

if (args is
    [
        "--get-group",
        var getEndpointText,
        var getProjectName,
        var getBoxName,
        var getGroupName
    ])
{
    var endpoint = new Uri(getEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var group = await customizations.GetAsync(
        getProjectName,
        "me",
        getBoxName,
        getGroupName,
        CancellationToken.None);
    Console.WriteLine(
        $"GROUP {group.Name}: {group.Status}");
    foreach (var task in group.Tasks)
    {
        var log = await GetTaskLogAsync(
            customizations,
            task.LogUri,
            expectedMarker: null,
            TimeSpan.FromSeconds(30),
            CancellationToken.None);
        Console.WriteLine(
            $"TASK {task.DisplayName ?? task.Name}: {task.Status}");
        Console.WriteLine(SafeBootstrapLogDiagnostic(log));
    }
    return 0;
}

if (args is
    [
        "--restart-devbox",
        var restartEndpointText,
        var restartProjectName,
        var restartBoxName
    ])
{
    var endpoint = new Uri(restartEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    Console.WriteLine($"STOPPING {restartBoxName}");
    await sdk.StopDevBoxAsync(
        WaitUntil.Completed,
        restartProjectName,
        "me",
        restartBoxName,
        false,
        new RequestContext { CancellationToken = CancellationToken.None });
    Console.WriteLine($"STARTING {restartBoxName}");
    await sdk.StartDevBoxAsync(
        WaitUntil.Completed,
        restartProjectName,
        "me",
        restartBoxName,
        new RequestContext { CancellationToken = CancellationToken.None });
    Console.WriteLine($"RESTARTED {restartBoxName}");
    return 0;
}

if (args is
    [
        "--delete-group",
        var deleteEndpointText,
        var deleteProjectName,
        var deleteBoxName,
        var deleteGroupName
    ])
{
    var endpoint = new Uri(deleteEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    await customizations.DeleteAsync(
        deleteProjectName,
        "me",
        deleteBoxName,
        deleteGroupName,
        CancellationToken.None);
    Console.WriteLine($"DELETED {deleteBoxName}: {deleteGroupName}");
    return 0;
}

if (args is
    [
        "--save-group-log",
        var saveEndpointText,
        var saveProjectName,
        var saveBoxName,
        var saveGroupName,
        var saveOutputPath
    ])
{
    var endpoint = new Uri(saveEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var group = await customizations.GetAsync(
        saveProjectName,
        "me",
        saveBoxName,
        saveGroupName,
        CancellationToken.None);
    var logs = new List<string>(group.Tasks.Count);
    foreach (var task in group.Tasks)
    {
        var taskLog = await GetTaskLogAsync(
            customizations,
            task.LogUri,
            expectedMarker: null,
            TimeSpan.FromSeconds(30),
            CancellationToken.None);
        logs.Add(
            $"TASK {task.DisplayName ?? task.Name}: {task.Status}" +
            Environment.NewLine +
            taskLog);
    }
    var log = string.Join(
        Environment.NewLine + Environment.NewLine,
        logs);
    WritePrivateFile(
        Path.GetFullPath(saveOutputPath),
        Encoding.UTF8.GetBytes(log));
    Console.WriteLine(
        $"Saved {log.Length} characters from {group.Name}.");
    return 0;
}

if (args is
    [
        "--materialize-msi-receipt",
        var receiptLogPath,
        var envelopePrivateKeyPath,
        var materialOutputDirectory,
        var materialBoxName,
        var expectedProductVersion,
        var expectedSourceRepository,
        var expectedSourceCommit
    ])
{
    if (!Version.TryParse(
            expectedProductVersion,
            out var expectedVersion) ||
        expectedVersion.ToString(3) != expectedProductVersion ||
        !Regex.IsMatch(
            expectedSourceRepository,
            "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
            RegexOptions.CultureInvariant) ||
        !Regex.IsMatch(
            expectedSourceCommit,
            "^[0-9A-Fa-f]{40}$",
            RegexOptions.CultureInvariant))
        throw new ArgumentException(
            "Expected endpoint release provenance is invalid.");
    var receiptText = File.ReadAllText(Path.GetFullPath(receiptLogPath));
    JsonDocument document;
    try
    {
        document = JsonDocument.Parse(receiptText);
    }
    catch (JsonException)
    {
        var line = receiptText.Split(
                ['\r', '\n'],
                StringSplitOptions.RemoveEmptyEntries)
            .SingleOrDefault(value =>
                value.Contains(
                    "\"runtime\":true,\"receipt\":",
                    StringComparison.Ordinal))
            ?? throw new InvalidDataException(
                "The health log contains no unique endpoint receipt.");
        document = JsonDocument.Parse(line[line.IndexOf('{')..]);
    }
    using (document)
    {
    var receipt = document.RootElement.TryGetProperty(
            "receipt",
            out var wrappedReceipt)
        ? wrappedReceipt
        : document.RootElement;
    var body = receipt.GetProperty("body");
    var nodePublic = Convert.FromBase64String(
        body.GetProperty("nodeSigningPublicKey").GetString()
        ?? throw new InvalidDataException(
            "The endpoint receipt has no node public key."));
    var signature = Convert.FromBase64String(
        receipt.GetProperty("signature").GetString()
        ?? throw new InvalidDataException(
            "The endpoint receipt has no signature."));
    var typedBody = body.Deserialize<EndpointReceiptBody>(
            new JsonSerializerOptions(JsonSerializerDefaults.Web))
        ?? throw new InvalidDataException(
            "The endpoint receipt body is invalid.");
    var canonical = JsonSerializer.SerializeToUtf8Bytes(
        typedBody);
    try
    {
        using var nodeVerifier = ECDsa.Create();
        nodeVerifier.ImportSubjectPublicKeyInfo(
            nodePublic,
            out var nodeRead);
        if (nodeRead != nodePublic.Length ||
            !nodeVerifier.VerifyData(
                canonical,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence))
            throw new CryptographicException(
                "The endpoint receipt signature is invalid.");
        if (body.GetProperty("version").GetInt32() != 2 ||
            body.GetProperty("productVersion").GetString() !=
                expectedProductVersion ||
            body.GetProperty("sourceRepository").GetString() !=
                expectedSourceRepository ||
            body.GetProperty("sourceCommit").GetString() !=
                expectedSourceCommit)
            throw new InvalidDataException(
                "The endpoint receipt provenance is invalid.");
        using var envelopeKey = RSA.Create();
        var privateBytes = File.ReadAllBytes(
            ValidatePrivateKeyPath(
                envelopePrivateKeyPath,
                "bootstrap envelope"));
        try
        {
            envelopeKey.ImportPkcs8PrivateKey(
                privateBytes,
                out var privateRead);
            if (privateRead != privateBytes.Length)
                throw new CryptographicException(
                    "The bootstrap envelope key contains trailing data.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateBytes);
        }
        var ciphertext = Convert.FromBase64String(
            body.GetProperty("ciphertext").GetString()
            ?? throw new InvalidDataException(
                "The endpoint receipt has no ciphertext."));
        var payload = RdpDvcBootstrapEnvelope.Decrypt(
            envelopeKey,
            ciphertext);
        try
        {
            var operationId = body.GetProperty(
                "bootstrapOperationId").GetGuid();
            var sessionId = body.GetProperty("sessionId").GetGuid();
            var hostId = body.GetProperty("hostId").GetGuid();
            var incarnationId = body.GetProperty(
                "incarnationId").GetGuid();
            if (payload.OperationId != operationId ||
                payload.SessionId != sessionId ||
                payload.HostId != hostId ||
                payload.NodeIncarnationId != incarnationId ||
                !CryptographicOperations.FixedTimeEquals(
                    payload.NodeSigningPublicKey,
                    nodePublic))
                throw new InvalidDataException(
                    "The endpoint envelope identity is invalid.");
            var output = Path.GetFullPath(materialOutputDirectory);
            Directory.CreateDirectory(output);
            WritePrivateFile(
                Path.Combine(output, "dvc-auth.key"),
                payload.AuthenticationKey);
            WritePrivateFile(
                Path.Combine(output, "node-public.pem"),
                Encoding.ASCII.GetBytes(
                    PemEncoding.WriteString(
                        "PUBLIC KEY",
                        nodePublic)));
            var metadata = JsonSerializer.SerializeToUtf8Bytes(
                new
                {
                    version = 1,
                    devBox = materialBoxName,
                    operationId,
                    sessionId,
                    hostId,
                    nodeIncarnationId = incarnationId,
                    nodeIdentity = body.GetProperty(
                        "nodeIdentity").GetString()
                },
                new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    WriteIndented = true
                });
            WritePrivateFile(
                Path.Combine(output, "endpoint.json"),
                metadata);
            CryptographicOperations.ZeroMemory(metadata);
            Console.WriteLine(
                $"Materialized verified endpoint {materialBoxName} " +
                $"for host {hostId:D}.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(
                payload.AuthenticationKey);
            CryptographicOperations.ZeroMemory(
                payload.NodeSigningPublicKey);
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(nodePublic);
        CryptographicOperations.ZeroMemory(signature);
        CryptographicOperations.ZeroMemory(canonical);
    }
    }
    return 0;
}

if (args is
    [
        "--install-endpoint",
        var installEndpointText,
        var installProjectName,
        var installBoxName,
        var installReleaseUrlFile,
        var installBootstrapPublicKeyFile,
        var installControlPublicKeyFile,
        var installControlIdentity,
        var installNodeAccount,
        var installNodeSid
    ])
{
    var endpoint = new Uri(installEndpointText, UriKind.Absolute);
    var releaseUrl = File.ReadAllText(
        Path.GetFullPath(installReleaseUrlFile)).Trim();
    if (!Uri.TryCreate(
            releaseUrl,
            UriKind.Absolute,
            out var releaseUri) ||
        releaseUri.Scheme != Uri.UriSchemeHttps ||
        !string.Equals(
            releaseUri.Host,
            "release-assets.githubusercontent.com",
            StringComparison.OrdinalIgnoreCase))
        throw new InvalidDataException(
            "Endpoint release URL must be an ephemeral GitHub release asset URL.");
    var bootstrapPublic = Convert.ToBase64String(
        File.ReadAllBytes(Path.GetFullPath(
            installBootstrapPublicKeyFile)));
    var controlPublic = Convert.ToBase64String(
        File.ReadAllBytes(Path.GetFullPath(
            installControlPublicKeyFile)));
    if (Convert.FromBase64String(bootstrapPublic).Length
            is not (294 or 422 or 550) ||
        Convert.FromBase64String(controlPublic).Length is < 80 or > 512 ||
        !Regex.IsMatch(
            installControlIdentity,
            "^[A-Za-z0-9._@:-]{3,256}$",
            RegexOptions.CultureInvariant) ||
        !Regex.IsMatch(
            installNodeAccount,
            "^[A-Za-z0-9._@\\\\/-]{3,256}$",
            RegexOptions.CultureInvariant) ||
        !Regex.IsMatch(
            installNodeSid,
            "^S-1-12-1-(\\d+-){2}\\d+-\\d+$",
            RegexOptions.CultureInvariant))
        throw new InvalidDataException(
            "Endpoint catalog task identity or trust parameters are invalid.");
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var expectedParameters = new HashSet<string>(
        [
            "releaseAssetUrl",
            "bootstrapEncryptionPublicKeyBase64",
            "controlSigningPublicKeyBase64",
            "controlIdentity",
            "nodeUserAccount",
            "nodeUserSid"
        ],
        StringComparer.Ordinal);
    var definitions = await customizations.ListTaskDefinitionsAsync(
        installProjectName,
        CancellationToken.None);
    var definition = definitions.SingleOrDefault(definition =>
        string.Equals(
            definition.Name,
            "install-steward-endpoint",
            StringComparison.Ordinal) &&
        definition.Parameters.SetEquals(expectedParameters))
        ?? throw new InvalidOperationException(
            "The released install-steward-endpoint catalog task with the exact expected parameter contract is unavailable.");
    var taskName = definition.Name.Contains(
        '/',
        StringComparison.Ordinal)
        ? definition.Name
        : $"{definition.CatalogName}/{definition.Name}";
    var groupName =
        "steward-endpoint-" + Guid.NewGuid().ToString("N");
    var tasks = new[]
    {
        new DevBoxCustomizationTaskRequest(
            taskName,
            "Install signed Steward endpoint",
            new Dictionary<string, string>
            {
                ["releaseAssetUrl"] = releaseUrl,
                ["bootstrapEncryptionPublicKeyBase64"] = bootstrapPublic,
                ["controlSigningPublicKeyBase64"] = controlPublic,
                ["controlIdentity"] = installControlIdentity,
                ["nodeUserAccount"] = installNodeAccount,
                ["nodeUserSid"] = installNodeSid
            },
            DevBoxCustomizationExecutionAccount.System,
            1_800)
    };
    var group = await customizations.ApplyAsync(
        installProjectName,
        "me",
        installBoxName,
        groupName,
        tasks,
        CancellationToken.None);
    var deadline = DateTimeOffset.UtcNow.AddMinutes(12);
    while (!Terminal(group.Status))
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException(
                "Endpoint installation did not reach terminal status.");
        await Task.Delay(TimeSpan.FromSeconds(10));
        group = await customizations.GetAsync(
            installProjectName,
            "me",
            installBoxName,
            groupName,
            CancellationToken.None);
    }
    if (!Succeeded(group.Status))
    {
        foreach (var task in group.Tasks.Where(task =>
                     !Succeeded(task.Status)))
        {
            var taskLog = await GetTaskLogAsync(
                customizations,
                task.LogUri,
                expectedMarker: null,
                TimeSpan.FromSeconds(30),
                CancellationToken.None);
            Console.Error.WriteLine(
                $"{task.DisplayName ?? task.Name}: {task.Status}; " +
                SafeBootstrapLogDiagnostic(taskLog));
        }
        throw new InvalidOperationException(
            $"Endpoint installation ended in {group.Status}.");
    }
    Console.WriteLine($"INSTALLED {installBoxName}: {group.Name}");
    return 0;
}

if (args is
    [
        "--install-endpoint-intrinsic",
        var intrinsicEndpointText,
        var intrinsicProjectName,
        var intrinsicBoxName,
        var intrinsicReleaseUrl,
        var intrinsicBootstrapPublic,
        var intrinsicControlPublic,
        var intrinsicControlIdentity,
        var intrinsicNodeAccount,
        var intrinsicNodeSid
    ])
{
    var endpoint = new Uri(intrinsicEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var installerPath = Path.GetFullPath(
        Path.Combine(
            AppContext.BaseDirectory,
            "..",
            "..",
            "..",
            "..",
            "catalog",
            "devbox",
            "steward-endpoint",
            "Install-Steward.ps1"));
    if (!File.Exists(installerPath))
        installerPath = Path.GetFullPath(
            Path.Combine(
                Environment.CurrentDirectory,
                "catalog",
                "devbox",
                "steward-endpoint",
                "Install-Steward.ps1"));
    var installer = File.ReadAllText(installerPath, Encoding.UTF8)
        .Replace(
            "__STEWARD_APPROVED_SOURCE_REPOSITORY__",
            "nbaertsch/steward",
            StringComparison.Ordinal)
        .Replace(
            "__STEWARD_APPROVED_SIGNER_WORKFLOW__",
            "nbaertsch/steward/.github/workflows/release-endpoint.yml",
            StringComparison.Ordinal)
        ;
    static string Utf8Base64(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    static string GzipUtf8Base64(string value)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(
                   output,
                   CompressionLevel.SmallestSize,
                   leaveOpen: true))
            gzip.Write(Encoding.UTF8.GetBytes(value));
        return Convert.ToBase64String(output.ToArray());
    }

    var installerBase64 = GzipUtf8Base64(installer);
    var releaseBase64 = Utf8Base64(intrinsicReleaseUrl);
    var bootstrapBase64 = Utf8Base64(intrinsicBootstrapPublic);
    var controlBase64 = Utf8Base64(intrinsicControlPublic);
    var controlIdentityBase64 = Utf8Base64(intrinsicControlIdentity);
    var nodeAccountBase64 = Utf8Base64(intrinsicNodeAccount);
    var nodeSidBase64 = Utf8Base64(intrinsicNodeSid);
    var command =
        "$ErrorActionPreference='Stop';" +
        "$u=[Text.Encoding]::UTF8;" +
        $"$compressed=[Convert]::FromBase64String('{installerBase64}');" +
        "$input=[IO.MemoryStream]::new($compressed,$false);" +
        "$gzip=[IO.Compression.GZipStream]::new($input,[IO.Compression.CompressionMode]::Decompress);" +
        "$reader=[IO.StreamReader]::new($gzip,$u,$true);" +
        "try{$script=$reader.ReadToEnd()}finally{$reader.Dispose();$gzip.Dispose();$input.Dispose()};" +
        $"$release=$u.GetString([Convert]::FromBase64String('{releaseBase64}'));" +
        $"$bootstrap=$u.GetString([Convert]::FromBase64String('{bootstrapBase64}'));" +
        $"$control=$u.GetString([Convert]::FromBase64String('{controlBase64}'));" +
        $"$controlId=$u.GetString([Convert]::FromBase64String('{controlIdentityBase64}'));" +
        $"$nodeAccount=$u.GetString([Convert]::FromBase64String('{nodeAccountBase64}'));" +
        $"$nodeSid=$u.GetString([Convert]::FromBase64String('{nodeSidBase64}'));" +
        "$scratch=Join-Path $env:ProgramData 'Steward\\install';" +
        "New-Item -ItemType Directory -Path $scratch -Force|Out-Null;" +
        "$path=Join-Path $scratch ('Install-Steward-'+[guid]::NewGuid().ToString('N')+'.ps1');" +
        "Set-Content -LiteralPath $path -Value $script -Encoding utf8;" +
        "try{& $path -ReleaseAssetUrl ([uri]$release) -BootstrapEncryptionPublicKeyBase64 $bootstrap -ControlSigningPublicKeyBase64 $control -ControlIdentity $controlId -NodeUserAccount $nodeAccount -NodeUserSid $nodeSid}" +
        "finally{Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue}";
    var groupName =
        "steward-endpoint-intrinsic-" + Guid.NewGuid().ToString("N");
    var group = await customizations.ApplyAsync(
        intrinsicProjectName,
        "me",
        intrinsicBoxName,
        groupName,
        [
            new(
                "~/powershell",
                "Install signed Steward endpoint via bootstrap recovery",
                new Dictionary<string, string>
                {
                    ["command"] = command
                },
                DevBoxCustomizationExecutionAccount.System,
                1_800)
        ],
        CancellationToken.None);
    var deadline = DateTimeOffset.UtcNow.AddMinutes(20);
    while (!Terminal(group.Status))
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException(
                "Endpoint intrinsic installation did not reach terminal status.");
        await Task.Delay(TimeSpan.FromSeconds(10));
        group = await customizations.GetAsync(
            intrinsicProjectName,
            "me",
            intrinsicBoxName,
            groupName,
            CancellationToken.None);
    }
    if (!Succeeded(group.Status))
    {
        foreach (var task in group.Tasks.Where(task =>
                     !Succeeded(task.Status)))
        {
            var taskLog = await GetTaskLogAsync(
                customizations,
                task.LogUri,
                expectedMarker: null,
                TimeSpan.FromSeconds(30),
                CancellationToken.None);
            Console.Error.WriteLine(
                $"{task.DisplayName ?? task.Name}: {task.Status}; " +
                SafeBootstrapLogDiagnostic(taskLog));
        }
        throw new InvalidOperationException(
            $"Endpoint intrinsic installation ended in {group.Status}.");
    }
    Console.WriteLine($"INSTALLED_INTRINSIC {intrinsicBoxName}: {group.Name}");
    return 0;
}
if (args is
    [
        "--install-winget-package",
        var wingetEndpointText,
        var wingetProjectName,
        var wingetBoxName,
        var wingetPackage,
        var wingetVersion
    ])
{
    var endpoint = new Uri(wingetEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var groupName = "steward-winget-" + Guid.NewGuid().ToString("N")[..8];
    var parameters = new Dictionary<string, string>
    {
        ["package"] = wingetPackage
    };
    if (wingetVersion != "-")
        parameters["version"] = wingetVersion;
    var group = await customizations.ApplyAsync(
        wingetProjectName,
        "me",
        wingetBoxName,
        groupName,
        [
            new(
                "~/winget",
                "Install approved package with Dev Box intrinsic Winget",
                parameters,
                DevBoxCustomizationExecutionAccount.System,
                3_600)
        ],
        CancellationToken.None);
    var deadline = DateTimeOffset.UtcNow.AddMinutes(30);
    while (!Terminal(group.Status))
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException("Winget package installation did not complete.");
        await Task.Delay(TimeSpan.FromSeconds(15));
        group = await customizations.GetAsync(
            wingetProjectName,
            "me",
            wingetBoxName,
            groupName,
            CancellationToken.None);
    }
    if (group.Tasks.Count != 0)
    {
        foreach (var task in group.Tasks)
        {
            var log = await GetTaskLogAsync(
                customizations,
                task.LogUri,
                expectedMarker: null,
                TimeSpan.FromSeconds(30),
                CancellationToken.None);
            Console.WriteLine(log);
        }
    }
    Console.WriteLine($"WINGET_INSTALL {wingetBoxName}: {group.Status}");
    return Succeeded(group.Status) ? 0 : 1;
}

if (args.Length == 5 &&
    (args[0] == "--run-diagnostic-powershell" ||
     args[0] == "--run-user-diagnostic-powershell"))
{
    var runEndpointText = args[1];
    var runProjectName = args[2];
    var runBoxName = args[3];
    var runCommandBase64 = args[4];
    var endpoint = new Uri(runEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var groupName = "steward-diag-run-" + Guid.NewGuid().ToString("N")[..8];
    var command = Encoding.UTF8.GetString(Convert.FromBase64String(runCommandBase64));
    if (command.Length > 16_000)
        throw new ArgumentException("Diagnostic command exceeds its bound.");
    var runAs = args[0] == "--run-user-diagnostic-powershell"
        ? DevBoxCustomizationExecutionAccount.User
        : DevBoxCustomizationExecutionAccount.System;
    var group = await customizations.ApplyAsync(
        runProjectName,
        "me",
        runBoxName,
        groupName,
        [
            new(
                "~/powershell",
                "Run bounded Steward diagnostic command",
                new Dictionary<string, string> { ["command"] = command },
                runAs,
                300)
        ],
        CancellationToken.None);
    Console.WriteLine($"DIAGNOSTIC_GROUP {runBoxName}: {group.Name}");
    var deadline = DateTimeOffset.UtcNow.AddMinutes(10);
    while (!Terminal(group.Status))
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException("Diagnostic command did not complete.");
        await Task.Delay(TimeSpan.FromSeconds(5));
        group = await customizations.GetAsync(
            runProjectName,
            "me",
            runBoxName,
            groupName,
            CancellationToken.None);
    }
    if (group.Tasks.Count == 0)
    {
        Console.Error.WriteLine(
            $"Diagnostic group {group.Name} ended in {group.Status} without task rows.");
        return Succeeded(group.Status) ? 0 : 1;
    }
    foreach (var task in group.Tasks)
    {
        var log = await GetTaskLogAsync(
            customizations,
            task.LogUri,
            expectedMarker: null,
            TimeSpan.FromSeconds(30),
            CancellationToken.None);
        Console.WriteLine(log);
    }
    return Succeeded(group.Status) ? 0 : 1;
}

if (args is
    [
        "--resolve-node-user",
        var userEndpointText,
        var userProjectName,
        var userBoxName
    ])
{
    var endpoint = new Uri(userEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var groupName = "steward-user-" + Guid.NewGuid().ToString("N")[..8];
    var command =
        "$ErrorActionPreference='Stop';" +
        "$p=@(Get-CimInstance Win32_UserProfile|?{!$_.Special-and$_.Loaded-and($_.SID-like'S-1-12-1-*'-or$_.SID-like'S-1-5-21-*')});" +
        "Write-Output ('PROFILE_COUNT='+$p.Count);" +
        "foreach($x in $p){$a='';try{$a=(New-Object Security.Principal.SecurityIdentifier($x.SID)).Translate([Security.Principal.NTAccount]).Value}catch{$a=('ERR:'+ $PSItem.Exception.Message)};[pscustomobject]@{account=$a;sid=$x.SID;localPath=$x.LocalPath;loaded=$x.Loaded}|ConvertTo-Json -Compress}";
    var group = await customizations.ApplyAsync(
        userProjectName,
        "me",
        userBoxName,
        groupName,
        [
            new(
                "~/powershell",
                "Resolve Steward endpoint user",
                new Dictionary<string, string> { ["command"] = command },
                DevBoxCustomizationExecutionAccount.System,
                300)
        ],
        CancellationToken.None);
    var deadline = DateTimeOffset.UtcNow.AddMinutes(10);
    while (!Terminal(group.Status))
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException("User resolution did not complete.");
        await Task.Delay(TimeSpan.FromSeconds(5));
        group = await customizations.GetAsync(
            userProjectName,
            "me",
            userBoxName,
            groupName,
            CancellationToken.None);
    }
    var log = await GetTaskLogAsync(
        customizations,
        group.Tasks.Single().LogUri,
        expectedMarker: null,
        TimeSpan.FromSeconds(30),
        CancellationToken.None);
    Console.WriteLine(log);
    return Succeeded(group.Status) ? 0 : 1;
}

if (args is
    [
        "--endpoint-msi-summary",
        var summaryEndpointText,
        var summaryProjectName,
        var summaryBoxName
    ])
{
    var endpoint = new Uri(summaryEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var groupName =
        "steward-msi-summary-" + Guid.NewGuid().ToString("N")[..8];
    var command =
        "$ErrorActionPreference='Stop';" +
        "$p='C:\\ProgramData\\Steward\\install\\steward-endpoint-msi.log';" +
        "Write-Output ('WHOAMI='+[Security.Principal.WindowsIdentity]::GetCurrent().Name);" +
        "Write-Output ('LOG_EXISTS='+(Test-Path -LiteralPath $p));" +
        "if(Test-Path -LiteralPath $p){" +
        "$patterns='Action start|Action ended|Return value 3|CustomAction|Error 1722|failed|Exception|error code|Product: Steward Endpoint';" +
        "Select-String -LiteralPath $p -Pattern $patterns|Select-Object -Last 160|ForEach-Object{$_.Line}" +
        "};" +
        "$i=New-Object -ComObject WindowsInstaller.Installer;" +
        "$u='{37C34E0A-E245-48A4-B07C-78E2955A7E65}';" +
        "foreach($r in @($i.RelatedProducts($u))){try{Write-Output ('RELATED='+$r+' STATE='+$i.ProductState($r)+' VERSION='+$i.ProductInfo($r,'VersionString'))}catch{Write-Output ('RELATED='+$r+' ERR='+$_.Exception.Message)}};" +
        "$failures=@(Get-ChildItem -LiteralPath 'C:\\ProgramData\\Steward' -Recurse -Force -ErrorAction SilentlyContinue -Filter '*failure*'|Select-Object -First 20);" +
        "foreach($f in $failures){Write-Output ('FAILURE_FILE='+$f.FullName);Get-Content -LiteralPath $f.FullName -TotalCount 80 -ErrorAction SilentlyContinue}";
    var group = await customizations.ApplyAsync(
        summaryProjectName,
        "me",
        summaryBoxName,
        groupName,
        [
            new(
                "~/powershell",
                "Summarize Steward endpoint MSI state",
                new Dictionary<string, string>
                {
                    ["command"] = command
                },
                DevBoxCustomizationExecutionAccount.System,
                300)
        ],
        CancellationToken.None);
    var deadline = DateTimeOffset.UtcNow.AddMinutes(10);
    while (!Terminal(group.Status))
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException("MSI summary did not complete.");
        await Task.Delay(TimeSpan.FromSeconds(5));
        group = await customizations.GetAsync(
            summaryProjectName,
            "me",
            summaryBoxName,
            groupName,
            CancellationToken.None);
    }
    var log = await GetTaskLogAsync(
        customizations,
        group.Tasks.Single().LogUri,
        expectedMarker: null,
        TimeSpan.FromSeconds(30),
        CancellationToken.None);
    Console.WriteLine(log);
    return Succeeded(group.Status) ? 0 : 1;
}

if (args is
    [
        "--collect-endpoint-diagnostics",
        var diagEndpointText,
        var diagProjectName,
        var diagBoxName,
        var diagOutputPath
    ])
{
    var endpoint = new Uri(diagEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var groupName =
        "steward-diag-" +
        diagBoxName[^Math.Min(12, diagBoxName.Length)..] +
        "-" + Guid.NewGuid().ToString("N")[..8];
    var command =
        "$ErrorActionPreference='Stop';" +
        "$root='C:\\ProgramData\\Steward';" +
        "$out=Join-Path $env:ProgramData ('Steward\\install\\diag-'+[guid]::NewGuid().ToString('N')+'.txt');" +
        "New-Item -ItemType Directory -Path (Split-Path -Parent $out) -Force|Out-Null;" +
        "'STEWARD_DIAG_BEGIN'|Set-Content -LiteralPath $out;" +
        "'WHOAMI='+([Security.Principal.WindowsIdentity]::GetCurrent().Name)|Add-Content $out;" +
        "$paths=@('C:\\ProgramData\\Steward\\install\\steward-endpoint-msi.log','C:\\ProgramData\\Steward\\Endpoint\\bootstrap-receipt.json');" +
        "foreach($p in $paths){'PATH='+$p+' EXISTS='+(Test-Path -LiteralPath $p)|Add-Content $out;if(Test-Path -LiteralPath $p){'--- '+$p+' ---'|Add-Content $out;$lines=@(Get-Content -LiteralPath $p -ErrorAction SilentlyContinue);$hits=@();for($i=0;$i -lt $lines.Count;$i++){if($lines[$i] -match 'Return value 3|failed|Exception|Fatal|error'){ $hits+=$i }};foreach($h in ($hits|Select-Object -First 6)){$start=[Math]::Max(0,$h-80);$end=[Math]::Min($lines.Count-1,$h+30);$lines[$start..$end]|Add-Content $out;'---'|Add-Content $out};Get-Content -LiteralPath $p -Tail 80 -ErrorAction SilentlyContinue|Add-Content $out}};" +
        "'--- FAILURE FILES ---'|Add-Content $out;Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue|Where-Object{$_.Name -match 'fail|diag|receipt|config|attestation|log'}|Select-Object -First 40 FullName,Length,LastWriteTime|Format-List|Out-String -Width 4096|Add-Content $out;" +
        "$bytes=[IO.File]::ReadAllBytes($out);Write-Output ('STEWARD_ENDPOINT_DIAG_RAW:'+[Convert]::ToBase64String($bytes));[Array]::Clear($bytes,0,$bytes.Length);Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue";
    var group = await customizations.ApplyAsync(
        diagProjectName,
        "me",
        diagBoxName,
        groupName,
        [
            new(
                "~/powershell",
                "Collect Steward endpoint diagnostics",
                new Dictionary<string, string>
                {
                    ["command"] = command
                },
                DevBoxCustomizationExecutionAccount.System,
                300)
        ],
        CancellationToken.None);
    var deadline = DateTimeOffset.UtcNow.AddMinutes(10);
    while (!Terminal(group.Status))
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException(
                "Endpoint diagnostics did not complete.");
        await Task.Delay(TimeSpan.FromSeconds(5));
        group = await customizations.GetAsync(
            diagProjectName,
            "me",
            diagBoxName,
            groupName,
            CancellationToken.None);
    }
    if (!Succeeded(group.Status))
        throw new InvalidOperationException(
            "Endpoint diagnostics collection failed.");
    var log = await GetTaskLogAsync(
        customizations,
        group.Tasks.Single().LogUri,
        expectedMarker: null,
        TimeSpan.FromSeconds(30),
        CancellationToken.None);
    const string marker = "STEWARD_ENDPOINT_DIAG_RAW:";
    var markerIndex = log.LastIndexOf(marker, StringComparison.Ordinal);
    if (markerIndex < 0)
        throw new InvalidDataException(
            "Endpoint diagnostics marker is missing.");
    var encoded = log[(markerIndex + marker.Length)..];
    var lineEnd = encoded.IndexOfAny(['\r', '\n']);
    if (lineEnd >= 0)
        encoded = encoded[..lineEnd];
    var bytes = Convert.FromBase64String(encoded.Trim());
    WritePrivateFile(
        Path.GetFullPath(diagOutputPath),
        bytes);
    CryptographicOperations.ZeroMemory(bytes);
    Console.WriteLine($"WROTE_ENDPOINT_DIAGNOSTICS {diagOutputPath}");
    return 0;
}

if (args is
    [
        "--retrieve-msi-receipt",
        var retrieveEndpointText,
        var retrieveProjectName,
        var retrieveBoxName,
        var retrieveOutputPath
    ])
{
    var endpoint = new Uri(retrieveEndpointText, UriKind.Absolute);
    var identity = new DevBoxIdentityService(new DevBoxIdentityStore());
    var sdk = new DevBoxesClient(
        endpoint,
        new DevBoxSilentTokenCredential(identity));
    var customizations = new DevBoxCustomizationClient(
        endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdk.Pipeline));
    var groupName =
        "steward-receipt-" +
        retrieveBoxName[^Math.Min(12, retrieveBoxName.Length)..] +
        "-" + Guid.NewGuid().ToString("N")[..8];
    var command =
        "$ErrorActionPreference='Stop';" +
        "$path='C:\\ProgramData\\Steward\\Endpoint\\bootstrap-receipt.json';" +
        "if(!(Test-Path -LiteralPath $path)){" +
        "$matches=@(Get-ChildItem -LiteralPath 'C:\\ProgramData\\Steward' " +
        "-Recurse -Force -Filter 'bootstrap-receipt.json' -File " +
        "-ErrorAction SilentlyContinue);" +
        "if($matches.Count-ne1){" +
        "Write-Output ('STEWARD_RECEIPT_CANDIDATES:'+" +
        "$matches.Count+':'+($matches.FullName-join'|'));" +
        "$inventory=@(Get-ChildItem -LiteralPath 'C:\\ProgramData\\Steward' " +
        "-Recurse -Force -ErrorAction SilentlyContinue|" +
        "Select-Object -First 100 -ExpandProperty FullName);" +
        "Write-Output ('STEWARD_ENDPOINT_INVENTORY:'+($inventory-join'|'));" +
        "$msiLog='C:\\ProgramData\\Steward\\install\\steward-endpoint-msi.log';" +
        "if(Test-Path -LiteralPath $msiLog){" +
        "$stateLines=@(Select-String -LiteralPath $msiLog " +
        "-Pattern 'receipt|state-root|Return value 3|" +
        "provisioning failed|InvalidDataException|UnauthorizedAccess|" +
        "Exception:'|Select-Object -Last 80 -ExpandProperty Line);" +
        "Write-Output ('STEWARD_MSI_STATE_LINES:'+($stateLines-join'|'))};" +
        "throw 'Endpoint receipt missing or ambiguous'};" +
        "$path=$matches[0].FullName};" +
        "$bytes=[IO.File]::ReadAllBytes($path);" +
        "$encoded=[Convert]::ToBase64String($bytes);" +
        "[Array]::Clear($bytes,0,$bytes.Length);" +
        "$chunks=@(for($i=0;$i-lt$encoded.Length;$i+=32){" +
        "'STEWARD_ENDPOINT_RECEIPT_CHUNK:{0:D4}:{1}'-f" +
        "($i/32),$encoded.Substring($i,[Math]::Min(32,$encoded.Length-$i))});" +
        "throw ($chunks-join[Environment]::NewLine)";
    var group = await customizations.ApplyAsync(
        retrieveProjectName,
        "me",
        retrieveBoxName,
        groupName,
        [
            new(
                "~/powershell",
                "Return raw signed Steward endpoint receipt",
                new Dictionary<string, string>
                {
                    ["command"] = command
                },
                DevBoxCustomizationExecutionAccount.System,
                300)
        ],
        CancellationToken.None);
    var deadline = DateTimeOffset.UtcNow.AddMinutes(10);
    while (!Terminal(group.Status))
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException(
                "Endpoint receipt retrieval did not complete.");
        await Task.Delay(TimeSpan.FromSeconds(5));
        try
        {
            group = await customizations.GetAsync(
                retrieveProjectName,
                "me",
                retrieveBoxName,
                groupName,
                CancellationToken.None);
        }
        catch (RequestFailedException exception)
            when (exception.Status is 404 or 409)
        {
        }
    }
    const string marker = "STEWARD_ENDPOINT_RECEIPT_CHUNK:";
    var log = await GetTaskLogAsync(
        customizations,
        group.Tasks.Single().LogUri,
        marker,
        TimeSpan.FromSeconds(30),
        CancellationToken.None);
    if (!log.Contains(marker, StringComparison.Ordinal))
    {
        if (!Succeeded(group.Status))
            Console.Error.WriteLine(
                SafeBootstrapLogDiagnostic(log));
        throw new InvalidDataException(
            "Raw endpoint receipt marker is missing.");
    }
    var encoded = ReadIndexedBase64Payload(log);
    var receiptBytes = Convert.FromBase64String(encoded);
    try
    {
        WritePrivateFile(
            Path.GetFullPath(retrieveOutputPath),
            receiptBytes);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(receiptBytes);
    }
    Console.WriteLine(
        $"Retrieved raw receipt for {retrieveBoxName}.");
    return 0;
}

if (args is ["--help"])
{
    Console.WriteLine(
        """
        Steward.DevBox.BootstrapDeploy
          --endpoint HTTPS_DEV_CENTER --project NAME --user me|GUID --devbox NAME
          --bundle ZIP --operation-id GUID --idempotency-key VALUE --status-query-id GUID
          --session-id GUID --host-id GUID --incarnation-id GUID
          --nonce-0 GUID --nonce-1 GUID --auth-key-file PATH
          --checkpoint-key-file PATH --handle-key-file PATH
          --state-directory PATH --receipt PATH
          --consent I_UNDERSTAND_THIS_MUTATES_THE_RETAINED_DEV_BOX_CUSTOMIZATION

        Endpoint catalog install:
          --install-endpoint HTTPS_DEV_CENTER PROJECT DEVBOX RELEASE_URL_FILE
          BOOTSTRAP_PUBLIC_KEY_FILE CONTROL_PUBLIC_KEY_FILE CONTROL_IDENTITY
          NODE_USER_ACCOUNT NODE_USER_SID

        Optional dual attestation:
          --node-signing-private-key PATH --node-identity VALUE
          --control-signing-private-key PATH --control-identity VALUE
          --attested-receipt PATH
        """);
    return 0;
}

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

byte[]? authenticationKey = null;
byte[]? checkpointKey = null;
byte[]? handleKey = null;
byte[]? nodeTransportPrivateKey = null;
byte[]? controlTransportPublicKey = null;
var stage = "options";
try
{
    var options = Options.Parse(args);
    if (options.Consent != Consent)
        throw new InvalidOperationException(
            $"Live customization is disabled. Pass --consent {Consent}.");
    if (options.InspectStaging ||
        options.ProbeEndpoint ||
        options.RestartOnlyId is not null ||
        (!options.InspectRecovery && !options.InspectOperation))
        throw new NotSupportedException(
            "Chunked Dev Box customization delivery, probes, and lifecycle mutation are quarantined. Use the signed catalog MSI bootstrap.");

    stage = "keys";
    checkpointKey = ReadKey(
        options.CheckpointKeyFile,
        32,
        32,
        "checkpoint");
    handleKey = ReadKey(
        options.HandleKeyFile,
        32,
        32,
        "handle");
    using var bootstrapEncryption = LoadOrCreateBootstrapEncryptionKey(
        options.StateDirectory,
        options.OperationId.Value,
        checkpointKey);
    authenticationKey = SHA256.HashData(
        bootstrapEncryption.ExportSubjectPublicKeyInfo());
    RequireDistinct(authenticationKey, checkpointKey, handleKey);
    if (options.NodeSigningPrivateKeyFile is not null)
    {
        using var nodeTransportKey = ReadSigningKey(
            options.NodeSigningPrivateKeyFile);
        using var controlTransportKey = ReadSigningKey(
            options.ControlSigningPrivateKeyFile!);
        nodeTransportPrivateKey =
            nodeTransportKey.ExportPkcs8PrivateKey();
        controlTransportPublicKey =
            controlTransportKey.ExportSubjectPublicKeyInfo();
    }

    stage = "bundle";
    var bundle = RdpDvcBootstrapBundle.Load(options.BundlePath);
    var request = new DevBoxRdpDvcBootstrapRequest(
        options.OperationId,
        options.IdempotencyKey,
        options.Project,
        options.User,
        options.DevBox,
        options.SessionId,
        options.HostId,
        options.IncarnationId,
        options.ConnectionNonces,
        authenticationKey,
        options.NodeIdentity,
        nodeTransportPrivateKey is null
            ? ReadOnlyMemory<byte>.Empty
            : nodeTransportPrivateKey,
        options.ControlIdentity,
        controlTransportPublicKey is null
            ? ReadOnlyMemory<byte>.Empty
            : controlTransportPublicKey,
        bootstrapEncryption.ExportSubjectPublicKeyInfo()).Validate();
    var planned = DevBoxRdpDvcBootstrapPlan.Create(request, bundle);
    for (var index = 0; index < planned.Groups.Count; index++)
        Console.Error.WriteLine(
            $"BOOTSTRAP PLAN GROUP {index}: tasks={planned.Groups[index].Tasks.Count}; " +
            $"commandChars={planned.Groups[index].Tasks.Sum(task => task.Parameters.Values.Sum(value => value.Length))}; " +
            $"payloadBytes={DevBoxCustomizationClient.MeasureApplyRequestBytes(planned.Groups[index].Tasks)}");

    stage = "identity";
    var defaultStore = new DevBoxIdentityStore();
    var connectionIdentity = new DevBoxConnectionIdentityService(
        defaultStore,
        new DevBoxConnectionIdentityStore());
    var connectionStatus = await connectionIdentity.StatusAsync(
            cancellation.Token)
        .ConfigureAwait(false);
    if (connectionStatus.Outcome != DevBoxConnectionIdentityOutcome.Ready ||
        !connectionStatus.Enrolled)
        throw new InvalidOperationException(
            "Production DevBoxConnectionIdentity is not ready.");

    var devCenterIdentity = new DevBoxIdentityService(defaultStore);
    var credential = new DevBoxSilentTokenCredential(devCenterIdentity);
    var sdkClient = new DevBoxesClient(options.Endpoint, credential);
    var customization = new DevBoxCustomizationClient(
        options.Endpoint,
        new AzurePipelineDevBoxCustomizationTransport(sdkClient.Pipeline));
    if (options.RestartOnlyId is not null)
    {
        stage = "restart-only";
        await RestartDevBoxAsync(
                sdkClient,
                options,
                "manual-" + options.RestartOnlyId,
                cancellation.Token)
            .ConfigureAwait(false);
        return 0;
    }
    if (options.InspectRecovery)
    {
        stage = "recovery-inspection";
        var recoveryPrefix =
            $"steward-rdp-{request.OperationId.Value:N}-recovery";
        var recoveryGroups = (await customization.ListAsync(
                request.Project,
                request.User,
                request.DevBox,
                cancellation.Token)
            .ConfigureAwait(false))
            .Where(group => group.Name.StartsWith(
                recoveryPrefix,
                StringComparison.Ordinal))
            .OrderBy(group => group.Name, StringComparer.Ordinal)
            .ToArray();
        foreach (var summary in recoveryGroups.TakeLast(10))
        {
            Console.WriteLine(
                $"RECOVERY {summary.Name}: {summary.Status}; " +
                $"started={summary.StartTime?.ToString("O") ?? "none"}; " +
                $"ended={summary.EndTime?.ToString("O") ?? "none"}");
            if (!Terminal(summary.Status))
                continue;
            var group = await customization.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    summary.Name,
                    cancellation.Token)
                .ConfigureAwait(false);
            foreach (var task in group.Tasks)
            {
                var log = await ReadHydratedTaskLogAsync(
                        customization,
                        task.LogUri,
                        cancellation.Token)
                    .ConfigureAwait(false);
                Console.WriteLine(
                    $"  TASK {task.Status}: " +
                    $"{SafeBootstrapLogDiagnostic(log)}");
            }
        }
        return 0;
    }
    if (options.InspectStaging)
    {
        stage = "staging-inspection";
        var probePrefix =
            $"steward-rdp-{request.OperationId.Value:N}-staging-probe";
        var probeGroups = (await customization.ListAsync(
                options.Project,
                options.User,
                options.DevBox,
                cancellation.Token)
            .ConfigureAwait(false))
            .Where(group => group.Name.StartsWith(
                probePrefix,
                StringComparison.Ordinal))
            .ToArray();
        var probeName =
            $"{probePrefix}-{probeGroups.Length:D4}";
        var probe = await customization.ApplyAsync(
                request.Project,
                request.User,
                request.DevBox,
                probeName,
                [
                    DevBoxRdpDvcBootstrapPlan.CreateStagingProbeTask(
                        request,
                        bundle)
                ],
                cancellation.Token)
            .ConfigureAwait(false);
        var probeDeadline =
            DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
        while (!Terminal(probe.Status))
        {
            if (DateTimeOffset.UtcNow >= probeDeadline)
                throw new TimeoutException(
                    "The RDP DVC staging probe did not complete.");
            await Task.Delay(options.PollInterval, cancellation.Token)
                .ConfigureAwait(false);
            probe = await customization.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    probeName,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        if (!Succeeded(probe.Status) ||
            probe.Tasks.Count != 1 ||
            !Succeeded(probe.Tasks[0].Status))
            throw new InvalidOperationException(
                "The RDP DVC staging probe failed.");
        var probeLog = await ReadHydratedTaskLogAsync(
                customization,
                probe.Tasks[0].LogUri,
                cancellation.Token)
            .ConfigureAwait(false);
        const string probeMarker = "STEWARD_RDP_DVC_STAGING_PROBE:";
        var markerIndex = probeLog.LastIndexOf(
            probeMarker,
            StringComparison.Ordinal);
        if (markerIndex < 0)
            throw new InvalidDataException(
                "The RDP DVC staging probe marker is missing.");
        var probeLine = probeLog[markerIndex..];
        var probeEnd = probeLine.IndexOfAny(['\r', '\n']);
        Console.WriteLine(probeEnd < 0
            ? probeLine
            : probeLine[..probeEnd]);
        return 0;
    }
    if (options.ProbeEndpoint)
    {
        stage = "endpoint-probe";
        var probePrefix =
            $"steward-rdp-{request.OperationId.Value:N}-probe";
        var probeGroups = (await customization.ListAsync(
                options.Project,
                options.User,
                options.DevBox,
                cancellation.Token)
            .ConfigureAwait(false))
            .Where(group => group.Name.StartsWith(
                probePrefix,
                StringComparison.Ordinal))
            .ToArray();
        var probeName =
            $"{probePrefix}-{probeGroups.Length:D4}";
        var probe = await customization.ApplyAsync(
                request.Project,
                request.User,
                request.DevBox,
                probeName,
                [DevBoxRdpDvcBootstrapPlan.CreateEndpointProbeTask(request)],
                cancellation.Token)
            .ConfigureAwait(false);
        var probeDeadline =
            DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
        while (!Terminal(probe.Status))
        {
            if (DateTimeOffset.UtcNow >= probeDeadline)
                throw new TimeoutException(
                    "The RDP DVC endpoint probe did not complete.");
            await Task.Delay(options.PollInterval, cancellation.Token)
                .ConfigureAwait(false);
            probe = await customization.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    probeName,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        if (probe.Tasks.Count != 1)
            throw new InvalidDataException(
                "The RDP DVC endpoint probe result is invalid.");
        var probeLog = await ReadHydratedTaskLogAsync(
                customization,
                probe.Tasks[0].LogUri,
                cancellation.Token)
            .ConfigureAwait(false);
        var probeMarker = "STEWARD_RDP_DVC_PROBE:";
        var markerIndex = probeLog.LastIndexOf(
            probeMarker,
            StringComparison.Ordinal);
        if (markerIndex < 0)
        {
            Console.Error.WriteLine(
                $"BOOTSTRAP PROBE DIAGNOSTIC: " +
                $"{SafeBootstrapLogDiagnostic(probeLog)}");
            Console.Error.WriteLine(
                "BOOTSTRAP PROBE RAW: " +
                probeLog.Replace('\r', ' ').Replace('\n', '|'));
            throw new InvalidDataException(
                "The RDP DVC endpoint probe marker is missing.");
        }
        var probeLine = probeLog[markerIndex..];
        var probeEnd = probeLine.IndexOfAny(['\r', '\n']);
        if (probeEnd >= 0)
            probeLine = probeLine[..probeEnd];
        Console.WriteLine(probeLine);
        return 0;
    }
    if (options.InspectOperation)
    {
        stage = "operation-inspection";
        using var inspectProtector =
            new AesGcmDevBoxRdpDvcBootstrapCheckpointProtector(
                checkpointKey);
        var inspectStore = new EncryptedFileDevBoxRdpDvcBootstrapStore(
            Path.Combine(options.StateDirectory, "operations"),
            inspectProtector);
        var inspect = await inspectStore.LoadAsync(
                options.OperationId,
                options.IdempotencyKey,
                cancellation.Token)
            .ConfigureAwait(false);
        if (inspect is null)
        {
            Console.WriteLine("OPERATION CHECKPOINT: absent");
            return 0;
        }
        Console.WriteLine(
            $"OPERATION CHECKPOINT: group={inspect.GroupIndex}/" +
            $"{inspect.Operation.Groups.Count}; completed={inspect.Completed}");
        if (!inspect.Completed &&
            inspect.GroupIndex < inspect.Operation.Groups.Count)
        {
            var active = await customization.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    inspect.Operation.Groups[inspect.GroupIndex].Name,
                    cancellation.Token)
                .ConfigureAwait(false);
            Console.WriteLine(
                $"OPERATION ACTIVE GROUP: {active.Status}; " +
                $"started={active.StartTime?.ToString("O") ?? "none"}; " +
                $"ended={active.EndTime?.ToString("O") ?? "none"}");
            foreach (var task in active.Tasks)
            {
                Console.WriteLine($"  OPERATION TASK: {task.Status}");
                if (Terminal(task.Status) &&
                    !Succeeded(task.Status))
                {
                    var log = await ReadHydratedTaskLogAsync(
                            customization,
                            task.LogUri,
                            cancellation.Token)
                        .ConfigureAwait(false);
                    Console.WriteLine(
                        $"    ERROR-CODE: {ClassifyBootstrapLog(log)}");
                    Console.WriteLine(
                        $"    SAFE-DIAGNOSTIC: " +
                        $"{SafeBootstrapLogDiagnostic(log)}");
                }
            }
        }
        return 0;
    }
    var nonterminalGroups = (await customization.ListAsync(
            options.Project,
            options.User,
            options.DevBox,
            cancellation.Token)
        .ConfigureAwait(false))
        .Where(group =>
            !Succeeded(group.Status) &&
            !group.Status.Equals(
                "Failed",
                StringComparison.OrdinalIgnoreCase) &&
            !group.Status.Equals(
                "ValidationFailed",
                StringComparison.OrdinalIgnoreCase))
        .OrderBy(group => group.StartTime ?? DateTimeOffset.MaxValue)
        .ToArray();
    Console.Error.WriteLine(
        $"BOOTSTRAP QUEUE: nonterminal={nonterminalGroups.Length}");
    foreach (var group in nonterminalGroups.Take(20))
        Console.Error.WriteLine(
            $"  QUEUED GROUP: {group.Name}; status={group.Status}; " +
            $"started={group.StartTime?.ToString("O") ?? "none"}");
    var restartQueued = options.RestartStalledCustomization &&
        nonterminalGroups is
        [
            {
                Status: "NotStarted",
                StartTime: null
            }
        ] &&
        DevBoxRdpDvcBootstrapRecovery.CanRestartWithoutLosingStaging(
            nonterminalGroups[0].Name,
            planned.Groups[0].Name);
    var restartRunning = options.RestartStalledStatus &&
        nonterminalGroups is
        [
            {
                Status: "Running",
                StartTime: { } started
            }
        ] &&
        DevBoxRdpDvcBootstrapRecovery.CanRestartWithoutLosingStaging(
            nonterminalGroups[0].Name,
            planned.Groups[0].Name) &&
        started <= DateTimeOffset.UtcNow.Subtract(
            TimeSpan.FromMinutes(5));
    if (restartQueued || restartRunning)
    {
        stage = "dispatch-recovery";
        await RecoverStalledDispatchAsync(
                sdkClient,
                planned,
                nonterminalGroups,
                options,
                restartRunning,
                cancellation.Token)
            .ConfigureAwait(false);
    }
    using var checkpointProtector =
        new AesGcmDevBoxRdpDvcBootstrapCheckpointProtector(
            checkpointKey);
    var durableStore = new EncryptedFileDevBoxRdpDvcBootstrapStore(
        Path.Combine(options.StateDirectory, "operations"),
        checkpointProtector);
    var deployer = new DevBoxRdpDvcBootstrapDeployer(
        customization,
        durableStore,
        new HmacDevBoxOperationHandleProtector(handleKey));
    var prior = await durableStore.LoadAsync(
            options.OperationId,
            options.IdempotencyKey,
            cancellation.Token)
        .ConfigureAwait(false);
    DevBoxCustomizationGroupResult? priorActive = null;
    if (prior is not null)
    {
        Console.Error.WriteLine(
            $"BOOTSTRAP CHECKPOINT: group={prior.GroupIndex}/{prior.Operation.Groups.Count}; completed={prior.Completed}");
        if (!prior.Completed &&
            prior.GroupIndex < prior.Operation.Groups.Count)
        {
            try
            {
                var active = await customization.GetAsync(
                        request.Project,
                        request.User,
                        request.DevBox,
                        prior.Operation.Groups[prior.GroupIndex].Name,
                        cancellation.Token)
                    .ConfigureAwait(false);
                priorActive = active;
                Console.Error.WriteLine(
                    $"BOOTSTRAP ACTIVE GROUP: {active.Status}; tasks={active.Tasks.Count}");
                foreach (var task in active.Tasks)
                {
                    Console.Error.WriteLine(
                        $"  ACTIVE TASK: {task.Status}");
                    if (!Succeeded(task.Status) &&
                        !task.Status.Equals(
                            "Running",
                            StringComparison.OrdinalIgnoreCase) &&
                        !task.Status.Equals(
                            "NotStarted",
                            StringComparison.OrdinalIgnoreCase))
                    {
                        var log = await ReadHydratedTaskLogAsync(
                                customization,
                                task.LogUri,
                                cancellation.Token)
                            .ConfigureAwait(false);
                        Console.Error.WriteLine(
                            $"    ERROR-CODE: {ClassifyBootstrapLog(log)}");
                        Console.Error.WriteLine(
                            $"    SAFE-DIAGNOSTIC: {SafeBootstrapLogDiagnostic(log)}");
                    }
                }
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(
                    $"BOOTSTRAP ACTIVE GROUP: unavailable ({exception.GetType().Name})");
            }
        }
    }
    if (prior is
        {
            Completed: false
        } &&
        prior.GroupIndex == planned.Groups.Count - 1 &&
        priorActive is { Tasks: [var failedInstallerTask] } &&
        DevBoxRdpDvcBootstrapRecovery.CanRecoverFinalInstaller(
            priorActive.Status,
            priorActive.Tasks.Select(task => task.Status).ToArray()))
    {
        stage = "failed-installer-recovery";
        await MaterializeBootstrapEnvelopeAsync(
                customization,
                failedInstallerTask.LogUri,
                bootstrapEncryption,
                request,
                options.AuthenticationKeyFile,
                options.PollInterval,
                TimeSpan.FromSeconds(30),
                cancellation.Token)
            .ConfigureAwait(false);
        var recoveryPrefix =
            $"steward-rdp-{request.OperationId.Value:N}-recovery";
        var recoveryGroups = (await customization.ListAsync(
                request.Project,
                request.User,
                request.DevBox,
                cancellation.Token)
            .ConfigureAwait(false))
            .Where(group => group.Name.StartsWith(
                recoveryPrefix,
                StringComparison.Ordinal))
            .ToArray();
        var inFlightRecovery = options.RestartStalledStatus
            ? null
            : recoveryGroups.SingleOrDefault(group =>
                !Succeeded(group.Status) &&
                !group.Status.Equals(
                    "Failed",
                    StringComparison.OrdinalIgnoreCase) &&
                !group.Status.Equals(
                    "ValidationFailed",
                    StringComparison.OrdinalIgnoreCase));
        var recoveryGroupName = inFlightRecovery?.Name ??
            $"{recoveryPrefix}-{recoveryGroups.Length:D4}";
        DevBoxCustomizationGroupResult recovery;
        try
        {
            recovery = await customization.ApplyAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    recoveryGroupName,
                    [
                        DevBoxRdpDvcBootstrapPlan
                            .CreateEndpointRecoveryTask(request, bundle)
                    ],
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        catch (RequestFailedException exception)
            when (exception.Status == 409)
        {
            recovery = await customization.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    recoveryGroupName,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        var recoveryDeadline =
            DateTimeOffset.UtcNow + options.Timeout;
        while (!Terminal(recovery.Status))
        {
            if (DateTimeOffset.UtcNow >= recoveryDeadline)
                throw new TimeoutException(
                    "The recovered RDP DVC endpoint did not become ready.");
            await Task.Delay(options.PollInterval, cancellation.Token)
                .ConfigureAwait(false);
            recovery = await customization.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    recoveryGroupName,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        if (!Succeeded(recovery.Status) ||
            recovery.Tasks.Count != 1 ||
            !Succeeded(recovery.Tasks[0].Status))
        {
            Console.Error.WriteLine(
                $"BOOTSTRAP RECOVERY GROUP: {recovery.Status}; tasks={recovery.Tasks.Count}");
            foreach (var task in recovery.Tasks)
            {
                Console.Error.WriteLine(
                    $"  RECOVERY TASK: {task.Status}");
                if (!Succeeded(task.Status) &&
                    !task.Status.Equals(
                        "Running",
                        StringComparison.OrdinalIgnoreCase) &&
                    !task.Status.Equals(
                        "NotStarted",
                        StringComparison.OrdinalIgnoreCase))
                {
                    var log = await customization.GetTaskLogAsync(
                            task.LogUri,
                            cancellation.Token)
                        .ConfigureAwait(false);
                    Console.Error.WriteLine(
                        $"    ERROR-CODE: {ClassifyBootstrapLog(log)}");
                    Console.Error.WriteLine(
                        $"    SAFE-DIAGNOSTIC: {SafeBootstrapLogDiagnostic(log)}");
                }
            }
            throw new InvalidOperationException(
                "The recovered RDP DVC endpoint failed to start.");
        }
        var recoveryLog = await ReadHydratedTaskLogAsync(
                customization,
                recovery.Tasks[0].LogUri,
                cancellation.Token)
            .ConfigureAwait(false);
        foreach (var marker in new[]
                 {
                     "STEWARD_RDP_DVC_REMOTE_READINESS:",
                     "STEWARD_RDP_DVC_REMOTE_FAILURE:",
                     "STEWARD_RDP_DVC_REMOTE_LAUNCHER:",
                     "STEWARD_RDP_DVC_REMOTE_SERVER_ERROR:",
                     "STEWARD_RDP_DVC_STARTUP:"
                 })
        {
            var markerIndex = recoveryLog.LastIndexOf(
                marker,
                StringComparison.Ordinal);
            if (markerIndex < 0)
                continue;
            var line = recoveryLog[markerIndex..];
            var lineEnd = line.IndexOfAny(['\r', '\n']);
            if (lineEnd >= 0)
                line = line[..lineEnd];
            Console.Error.WriteLine(
                $"BOOTSTRAP RECOVERY MARKER: " +
                $"{(line.Length <= 2048 ? line : line[..2048])}");
        }
        Console.Error.WriteLine(
            $"BOOTSTRAP RECOVERY DIAGNOSTIC: " +
            $"{SafeBootstrapLogDiagnostic(recoveryLog)}");
        if (options.RestartAfterBootstrap)
        {
            stage = "post-recovery-restart";
            await RestartDevBoxAsync(
                    sdkClient,
                    options,
                    recoveryGroupName,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        var pendingResult = new ProviderOperationResult(
            ProviderOperationStatus.Running,
            prior.Handle,
            null);
        var pendingReceipt =
            DevBoxRdpDvcBootstrapReceipts.CreateDeploymentPending(
                request,
                bundle,
                pendingResult);
        await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
                options.ReceiptPath,
                pendingReceipt,
                cancellation.Token)
            .ConfigureAwait(false);
        if (options.NodeSigningPrivateKeyFile is not null)
        {
            using var controlKey = ReadSigningKey(
                options.ControlSigningPrivateKeyFile!);
            var attested =
                DevBoxRdpDvcBootstrapReceipts.AttestPending(
                    pendingReceipt,
                    options.ControlIdentity!,
                    controlKey);
            await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
                    options.AttestedReceiptPath!,
                    attested,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        Console.WriteLine(
            "Recovered protected bootstrap secrets from the failed installer; awaiting headless RDCore user session.");
        return 0;
    }

    stage = "deploy";
    var result = await deployer.DeployAsync(
            request,
            bundle,
            cancellation.Token)
        .ConfigureAwait(false);
    var deferredCheckpoint = await durableStore.LoadAsync(
            options.OperationId,
            options.IdempotencyKey,
            cancellation.Token)
        .ConfigureAwait(false);
    if (deferredCheckpoint is not null &&
        deferredCheckpoint.GroupIndex ==
            planned.Groups.Count - 1 &&
        planned.Groups[^1].Tasks.All(task =>
            task.RunAs ==
                DevBoxCustomizationExecutionAccount.System) &&
        result.Status == ProviderOperationStatus.Running)
    {
        var deferredDeadline =
            DateTimeOffset.UtcNow + options.Timeout;
        DevBoxCustomizationGroupResult deferred;
        while (true)
        {
            await Task.Delay(options.PollInterval, cancellation.Token)
                .ConfigureAwait(false);
            deferred = await customization.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    planned.Groups[^1].Name,
                    cancellation.Token)
                .ConfigureAwait(false);
            var installerRunning =
                deferred.Tasks.Count == planned.Groups[^1].Tasks.Count &&
                deferred.Tasks
                    .Take(deferred.Tasks.Count - 1)
                    .All(task => Succeeded(task.Status)) &&
                deferred.Tasks[^1].Status.Equals(
                    "Running",
                    StringComparison.OrdinalIgnoreCase);
            if (installerRunning || Terminal(deferred.Status))
                break;
            if (DateTimeOffset.UtcNow >= deferredDeadline)
                throw new TimeoutException(
                    "Deferred bootstrap did not reach the endpoint installer.");
        }
        if (deferred.Status is not ("NotStarted" or "Running"))
            throw new InvalidOperationException(
                "Deferred user bootstrap did not remain accepted.");
        await MaterializeBootstrapEnvelopeAsync(
                customization,
                deferred.Tasks[^1].LogUri,
                bootstrapEncryption,
                request,
                options.AuthenticationKeyFile,
                options.PollInterval,
                options.Timeout,
                cancellation.Token)
            .ConfigureAwait(false);
        var deferredReceipt =
            DevBoxRdpDvcBootstrapReceipts.CreateDeploymentPending(
                request,
                bundle,
                result);
        await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
                options.ReceiptPath,
                deferredReceipt,
                cancellation.Token)
            .ConfigureAwait(false);
        if (options.NodeSigningPrivateKeyFile is not null)
        {
            using var controlKey = ReadSigningKey(
                options.ControlSigningPrivateKeyFile!);
            var attested =
                DevBoxRdpDvcBootstrapReceipts.AttestPending(
                deferredReceipt,
                options.ControlIdentity!,
                controlKey);
            await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
                    options.AttestedReceiptPath!,
                    attested,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        Console.WriteLine(
            "Deferred SYSTEM bootstrap receipt written; awaiting headless RDCore user session.");
        return 0;
    }
    var deadline = DateTimeOffset.UtcNow + options.Timeout;
    var notStartedSince = new Dictionary<string, DateTimeOffset>(
        StringComparer.Ordinal);
    while (result.Status is
           ProviderOperationStatus.Accepted or
           ProviderOperationStatus.Running)
    {
        if (DateTimeOffset.UtcNow >= deadline)
            throw new TimeoutException(
                "Dev Box bootstrap customization did not reach terminal status.");
        await Task.Delay(options.PollInterval, cancellation.Token)
            .ConfigureAwait(false);
        stage = "reconcile";
        result = await deployer.ReconcileAsync(
                result.Handle
                ?? throw new InvalidDataException(
                    "Running bootstrap operation has no durable handle."),
                cancellation.Token)
            .ConfigureAwait(false);
        if ((options.RestartStalledCustomization ||
             options.RestartStalledStatus) &&
            result.Status is
                ProviderOperationStatus.Accepted or
                ProviderOperationStatus.Running)
        {
            var queued = (await customization.ListAsync(
                    options.Project,
                    options.User,
                    options.DevBox,
                    cancellation.Token)
                .ConfigureAwait(false))
                .Where(group =>
                    !Succeeded(group.Status) &&
                    !group.Status.Equals(
                        "Failed",
                        StringComparison.OrdinalIgnoreCase) &&
                    !group.Status.Equals(
                        "ValidationFailed",
                        StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (queued is
                [
                    {
                        Status: "NotStarted",
                        StartTime: null
                    } stalled
                ] &&
                DevBoxRdpDvcBootstrapRecovery
                    .CanRestartWithoutLosingStaging(
                        stalled.Name,
                        planned.Groups[0].Name))
            {
                var now = DateTimeOffset.UtcNow;
                if (!notStartedSince.TryGetValue(
                        stalled.Name,
                        out var observed))
                {
                    notStartedSince[stalled.Name] = now;
                }
                else if (now - observed >= TimeSpan.FromMinutes(2))
                {
                    stage = "dispatch-recovery";
                    await RecoverStalledDispatchAsync(
                            sdkClient,
                            planned,
                            queued,
                            options,
                            recoverRunning: false,
                            cancellation.Token)
                        .ConfigureAwait(false);
                    notStartedSince.Remove(stalled.Name);
                    stage = "reconcile";
                }
            }
            else if (options.RestartStalledStatus &&
                     queued is
                     [
                         {
                             Status: "Running",
                             StartTime: { } runningSince
                         }
                     ] &&
                     DevBoxRdpDvcBootstrapRecovery
                         .CanRestartWithoutLosingStaging(
                             queued[0].Name,
                             planned.Groups[0].Name) &&
                     queued[0].Name != planned.Groups[^1].Name &&
                     runningSince <= DateTimeOffset.UtcNow.Subtract(
                         TimeSpan.FromMinutes(5)))
            {
                stage = "dispatch-recovery";
                await RecoverStalledDispatchAsync(
                        sdkClient,
                        planned,
                        queued,
                        options,
                        recoverRunning: true,
                        cancellation.Token)
                    .ConfigureAwait(false);
                notStartedSince.Clear();
                stage = "reconcile";
            }
            else
            {
                notStartedSince.Clear();
            }
        }
    }
    if (result.Status != ProviderOperationStatus.Succeeded)
    {
        await PrintSafeTaskStatusesAsync(
                customization,
                request,
                bundle,
                cancellation.Token)
            .ConfigureAwait(false);
        throw new InvalidOperationException(
            $"Dev Box bootstrap ended in {result.Status}.");
    }
    if (options.RestartAfterBootstrap)
    {
        stage = "post-bootstrap-restart";
        await RestartDevBoxAsync(
                sdkClient,
                options,
                $"bootstrap-{options.OperationId.Value:N}",
                cancellation.Token)
            .ConfigureAwait(false);
    }

    stage = "readiness";
    var readiness = await ReadInstallerReadinessAsync(
            customization,
            request,
            planned.Groups[^1].Name,
            cancellation.Token)
        .ConfigureAwait(false);
    if (readiness.Receipt.State == "completed" &&
        readiness.Receipt.NextGeneration == 2 &&
        readiness.Receipt.AuthenticatedGenerations.Count == 2)
    {
        Console.WriteLine(
            "Bootstrap terminal readiness verified from the successful installer log; signed pre-connect receipt preserved.");
        return 0;
    }
    stage = "receipt";
    var receipt = DevBoxRdpDvcBootstrapReceipts.Create(
        request,
        bundle,
        result,
        readiness);
    await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
            options.ReceiptPath,
            receipt,
            cancellation.Token)
        .ConfigureAwait(false);

    if (options.NodeSigningPrivateKeyFile is not null)
    {
        using var nodeKey = ReadSigningKey(
            options.NodeSigningPrivateKeyFile);
        using var controlKey = ReadSigningKey(
            options.ControlSigningPrivateKeyFile!);
        stage = "attestation";
        var attested = DevBoxRdpDvcBootstrapReceipts.Attest(
            receipt,
            options.NodeIdentity!,
            nodeKey,
            options.ControlIdentity!,
            controlKey);
        await DevBoxRdpDvcBootstrapReceipts.SaveAsync(
                options.AttestedReceiptPath!,
                attested,
                cancellation.Token)
            .ConfigureAwait(false);
    }

    Console.WriteLine(
        $"Bootstrap receipt written to {Path.GetFileName(options.ReceiptPath)}; remote state={readiness.Receipt.State}, pre-connect-ready={receipt.PreConnectReady}.");
    return 0;
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine(
        "CANCELLED: durable bootstrap state is preserved.");
    return 130;
}
catch (Exception exception)
{
    var safeDetail = exception switch
    {
        RequestFailedException request =>
            $"HTTP {request.Status}; code={request.ErrorCode ?? "none"}",
        ArgumentException or InvalidDataException or InvalidOperationException =>
            exception.Message,
        _ => "details suppressed"
    };
    Console.Error.WriteLine(
        $"FAILED ({stage}/{exception.GetType().Name}): {safeDetail}; durable state is preserved.");
    return 1;
}
finally
{
    Zero(authenticationKey);
    Zero(checkpointKey);
    Zero(handleKey);
    Zero(nodeTransportPrivateKey);
    Zero(controlTransportPublicKey);
}

static async Task<DevBoxRdpDvcReadinessObservation>
    ReadInstallerReadinessAsync(
        DevBoxCustomizationClient client,
        DevBoxRdpDvcBootstrapRequest request,
        string groupName,
        CancellationToken cancellationToken)
{
    var group = await client.GetAsync(
            request.Project,
            request.User,
            request.DevBox,
            groupName,
            cancellationToken)
        .ConfigureAwait(false);
    if (!Succeeded(group.Status) ||
        group.Tasks.Count == 0 ||
        !Succeeded(group.Tasks[^1].Status))
        throw new InvalidOperationException(
            "The completed bootstrap installer result is unavailable.");
    var log = await client.GetTaskLogAsync(
            group.Tasks[^1].LogUri,
            cancellationToken)
        .ConfigureAwait(false);
    return DevBoxRdpDvcReadiness.ParseLog(log, request);
}

static async Task MaterializeBootstrapEnvelopeAsync(
    DevBoxCustomizationClient client,
    Uri logUri,
    RSA encryptionKey,
    DevBoxRdpDvcBootstrapRequest request,
    string authenticationKeyPath,
    TimeSpan pollInterval,
    TimeSpan timeout,
    CancellationToken cancellationToken)
{
    const string marker = "STEWARD_RDP_DVC_BOOTSTRAP_ENVELOPE:";
    var deadline = DateTimeOffset.UtcNow + timeout;
    string? encoded = null;
    while (DateTimeOffset.UtcNow < deadline)
    {
        try
        {
            var log = await client.GetTaskLogAsync(
                    logUri,
                    cancellationToken)
                .ConfigureAwait(false);
            var markerIndex = log.LastIndexOf(
                marker,
                StringComparison.Ordinal);
            if (markerIndex >= 0)
            {
                encoded = log[(markerIndex + marker.Length)..];
                var lineEnd = encoded.IndexOfAny(['\r', '\n']);
                if (lineEnd >= 0)
                    encoded = encoded[..lineEnd];
                encoded = encoded.Trim();
                break;
            }
        }
        catch (RequestFailedException exception)
            when (exception.Status is 404 or 409)
        {
        }
        await Task.Delay(pollInterval, cancellationToken)
            .ConfigureAwait(false);
    }
    if (string.IsNullOrWhiteSpace(encoded))
        throw new TimeoutException(
            "The encrypted bootstrap envelope was not published.");
    var ciphertext = Convert.FromBase64String(encoded);
    var payload = RdpDvcBootstrapEnvelope.Decrypt(
        encryptionKey,
        ciphertext);
    try
    {
        if (payload.OperationId != request.OperationId.Value ||
            payload.SessionId != request.SessionId ||
            payload.HostId != request.HostId.Value ||
            payload.NodeIncarnationId != request.IncarnationId.Value)
            throw new InvalidDataException(
                "The bootstrap envelope identity is invalid.");
        WritePrivateFile(
            authenticationKeyPath,
            payload.AuthenticationKey);
        var nodePublicPath = authenticationKeyPath +
            ".node-transport-public.pem";
        WritePrivateFile(
            nodePublicPath,
            Encoding.ASCII.GetBytes(
                PemEncoding.WriteString(
                    "PUBLIC KEY",
                    payload.NodeSigningPublicKey)));
        Console.WriteLine(
            $"Bootstrap secrets materialized to protected local files; node transport public key={Path.GetFileName(nodePublicPath)}.");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(ciphertext);
        CryptographicOperations.ZeroMemory(
            payload.AuthenticationKey);
        CryptographicOperations.ZeroMemory(
            payload.NodeSigningPublicKey);
    }
}

static async Task<string> ReadHydratedTaskLogAsync(
    DevBoxCustomizationClient client,
    Uri logUri,
    CancellationToken cancellationToken)
{
    var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
    while (true)
    {
        var log = await client.GetTaskLogAsync(
                logUri,
                cancellationToken)
            .ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(log) ||
            DateTimeOffset.UtcNow >= deadline)
            return log;
        await Task.Delay(
                TimeSpan.FromSeconds(2),
                cancellationToken)
            .ConfigureAwait(false);
    }
}

static void WritePrivateFile(string path, ReadOnlySpan<byte> content)
{
    var fullPath = Path.GetFullPath(path);
    var directory = Path.GetDirectoryName(fullPath)
        ?? throw new InvalidOperationException(
            "A private file path requires a directory.");
    var current = WindowsIdentity.GetCurrent().User
        ?? throw new InvalidOperationException(
            "The current Windows identity has no SID.");
    Directory.CreateDirectory(directory);
    if (File.GetAttributes(directory)
        .HasFlag(FileAttributes.ReparsePoint))
        throw new IOException(
            "The private file directory is unsafe.");
    var directorySecurity = new DirectorySecurity();
    directorySecurity.SetOwner(current);
    directorySecurity.SetAccessRuleProtection(true, false);
    directorySecurity.AddAccessRule(new(
        current,
        FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit |
        InheritanceFlags.ObjectInherit,
        PropagationFlags.None,
        AccessControlType.Allow));
    new DirectoryInfo(directory).SetAccessControl(directorySecurity);
    var pending = Path.Combine(
        directory,
        $".{Path.GetFileName(fullPath)}." +
        $"{RandomNumberGenerator.GetHexString(16)}.new");
    var security = new FileSecurity();
    security.SetOwner(current);
    security.SetAccessRuleProtection(true, false);
    security.AddAccessRule(new(
        current,
        FileSystemRights.FullControl,
        AccessControlType.Allow));
    try
    {
        using (var stream = new FileStream(
                   pending,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   4096,
                   FileOptions.WriteThrough))
        {
            new FileInfo(pending).SetAccessControl(security);
            stream.Write(content);
            stream.Flush(flushToDisk: true);
        }
        File.Move(pending, fullPath, overwrite: true);
    }
    finally
    {
        if (File.Exists(pending))
            File.Delete(pending);
    }
}

static async Task PrintSafeTaskStatusesAsync(
    DevBoxCustomizationClient client,
    DevBoxRdpDvcBootstrapRequest request,
    RdpDvcBootstrapBundle bundle,
    CancellationToken cancellationToken)
{
    var operation = DevBoxRdpDvcBootstrapPlan.Create(request, bundle);
    for (var index = 0; index < operation.Groups.Count; index++)
    {
        try
        {
            var group = await client.GetAsync(
                    request.Project,
                    request.User,
                    request.DevBox,
                    operation.Groups[index].Name,
                    cancellationToken)
                .ConfigureAwait(false);
            Console.Error.WriteLine(
                $"BOOTSTRAP GROUP {index}: {group.Status}");
            foreach (var task in group.Tasks)
            {
                Console.Error.WriteLine(
                    $"  TASK {task.DisplayName}: {task.Status}");
                if (!Succeeded(task.Status) &&
                    !task.Status.Equals(
                        "Running",
                        StringComparison.OrdinalIgnoreCase) &&
                    !task.Status.Equals(
                        "NotStarted",
                        StringComparison.OrdinalIgnoreCase))
                {
                    var log = await client.GetTaskLogAsync(
                            task.LogUri,
                            cancellationToken)
                        .ConfigureAwait(false);
                    Console.Error.WriteLine(
                        $"    ERROR-CODE: {ClassifyBootstrapLog(log)}");
                    Console.Error.WriteLine(
                        $"    SAFE-DIAGNOSTIC: {SafeBootstrapLogDiagnostic(log)}");
                }
            }
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"BOOTSTRAP GROUP {index}: status unavailable ({exception.GetType().Name})");
        }
    }
}

static async Task RecoverStalledDispatchAsync(
    DevBoxesClient client,
    DevBoxRdpDvcBootstrapOperation operation,
    IReadOnlyList<DevBoxCustomizationGroupSummary> nonterminalGroups,
    Options options,
    bool recoverRunning,
    CancellationToken cancellationToken)
{
    var expected = operation.Groups
        .Select(static group => group.Name)
        .ToHashSet(StringComparer.Ordinal);
    expected.Add(
        $"steward-rdp-{operation.Intent.OperationId.Value:N}-recovery");
    if (nonterminalGroups.Count != 1 ||
        !(expected.Contains(nonterminalGroups[0].Name) ||
          nonterminalGroups[0].Name.StartsWith(
              $"steward-rdp-{operation.Intent.OperationId.Value:N}-recovery-",
              StringComparison.Ordinal)) ||
        (recoverRunning
            ? nonterminalGroups[0].Status != "Running" ||
              nonterminalGroups[0].StartTime is null
            : nonterminalGroups[0].Status != "NotStarted" ||
              nonterminalGroups[0].StartTime is not null))
        throw new InvalidOperationException(
            "Dispatch recovery requires exactly the current unstarted bootstrap group.");
    var directory = Path.Combine(
        options.StateDirectory,
        "dispatch-recovery");
    Directory.CreateDirectory(directory);
    var path = Path.Combine(
        directory,
        $"{options.OperationId.Value:N}-{nonterminalGroups[0].Name}" +
        $"{(recoverRunning ? ".status" : string.Empty)}.phase");
    var phase = File.Exists(path)
        ? await File.ReadAllTextAsync(path, cancellationToken)
            .ConfigureAwait(false)
        : null;
    if (phase is null)
    {
        await WriteRecoveryPhaseAsync(path, "stop-intent", cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            "BOOTSTRAP DISPATCH RECOVERY: stopping the idle evidence Dev Box.");
        await client.StopDevBoxAsync(
                WaitUntil.Completed,
                options.Project,
                options.User,
                options.DevBox,
                false,
                new RequestContext
                {
                    CancellationToken = cancellationToken
                })
            .ConfigureAwait(false);
        await WriteRecoveryPhaseAsync(path, "stopped", cancellationToken)
            .ConfigureAwait(false);
        phase = "stopped";
    }
    else if (phase == "stop-intent")
    {
        throw new InvalidOperationException(
            "Dev Box dispatch recovery stopped at an ambiguous power boundary.");
    }
    if (phase == "stopped")
    {
        Console.Error.WriteLine(
            "BOOTSTRAP DISPATCH RECOVERY: starting the evidence Dev Box.");
        await client.StartDevBoxAsync(
                WaitUntil.Completed,
                options.Project,
                options.User,
                options.DevBox,
                new RequestContext
                {
                    CancellationToken = cancellationToken
                })
            .ConfigureAwait(false);
        await WriteRecoveryPhaseAsync(path, "completed", cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            "BOOTSTRAP DISPATCH RECOVERY: restart completed.");
        return;
    }
    if (phase != "completed")
        throw new InvalidDataException(
            "Dev Box dispatch recovery state is invalid.");
}

static async Task RestartDevBoxAsync(
    DevBoxesClient client,
    Options options,
    string recoveryId,
    CancellationToken cancellationToken)
{
    var directory = Path.Combine(
        options.StateDirectory,
        "post-bootstrap-restart");
    Directory.CreateDirectory(directory);
    var path = Path.Combine(
        directory,
        $"{recoveryId}.phase");
    var phase = File.Exists(path)
        ? await File.ReadAllTextAsync(path, cancellationToken)
            .ConfigureAwait(false)
        : null;
    if (phase is null)
    {
        await WriteRecoveryPhaseAsync(path, "stop-intent", cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            "BOOTSTRAP COMMIT RECOVERY: stopping the idle evidence Dev Box.");
        await client.StopDevBoxAsync(
                WaitUntil.Completed,
                options.Project,
                options.User,
                options.DevBox,
                false,
                new RequestContext
                {
                    CancellationToken = cancellationToken
                })
            .ConfigureAwait(false);
        await WriteRecoveryPhaseAsync(path, "stopped", cancellationToken)
            .ConfigureAwait(false);
        phase = "stopped";
    }
    else if (phase == "stop-intent")
    {
        throw new InvalidOperationException(
            "Post-bootstrap restart stopped at an ambiguous power boundary.");
    }
    if (phase == "stopped")
    {
        Console.Error.WriteLine(
            "BOOTSTRAP COMMIT RECOVERY: starting the evidence Dev Box.");
        await client.StartDevBoxAsync(
                WaitUntil.Completed,
                options.Project,
                options.User,
                options.DevBox,
                new RequestContext
                {
                    CancellationToken = cancellationToken
                })
            .ConfigureAwait(false);
        await WriteRecoveryPhaseAsync(path, "completed", cancellationToken)
            .ConfigureAwait(false);
        Console.Error.WriteLine(
            "BOOTSTRAP COMMIT RECOVERY: restart completed.");
        return;
    }
    if (phase != "completed")
        throw new InvalidDataException(
            "Post-bootstrap restart state is invalid.");
}

static async Task WriteRecoveryPhaseAsync(
    string path,
    string phase,
    CancellationToken cancellationToken)
{
    var pending = path + ".new";
    await File.WriteAllTextAsync(
            pending,
            phase,
            new UTF8Encoding(false),
            cancellationToken)
        .ConfigureAwait(false);
    File.Move(pending, path, overwrite: true);
}

static string ClassifyBootstrapLog(string log)
{
    var diagnosticLog = string.Join(
        '\n',
        log.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Where(line => !line.Contains(
                "Running command",
                StringComparison.OrdinalIgnoreCase)));
    var known = new Dictionary<string, string>(
        StringComparer.OrdinalIgnoreCase)
    {
        ["staging is missing"] = "STAGING_MISSING",
        ["chunk sequence is incomplete"] = "CHUNK_SEQUENCE_INCOMPLETE",
        ["bundle is incomplete"] = "BUNDLE_INCOMPLETE",
        ["base64 length mismatch"] = "BASE64_LENGTH_MISMATCH",
        ["archive hash mismatch"] = "ARCHIVE_HASH_MISMATCH",
        ["manifest version mismatch"] = "MANIFEST_VERSION_MISMATCH",
        ["manifest path"] = "MANIFEST_PATH_INVALID",
        ["payload verification failed"] = "PAYLOAD_HASH_MISMATCH",
        ["payload contains unmanifested"] = "UNMANIFESTED_PAYLOAD",
        ["root ACL failed"] = "ROOT_ACL_FAILED",
        ["key ACL failed"] = "KEY_ACL_FAILED",
        ["install ACL failed"] = "INSTALL_ACL_FAILED",
        [".NET runtime is not installed"] = "DOTNET_RUNTIME_MISSING"
    };
    foreach (var item in known)
        if (diagnosticLog.Contains(
                item.Key,
                StringComparison.OrdinalIgnoreCase))
            return item.Value;
    return "UNCLASSIFIED_REMOTE_TASK_FAILURE";
}

static string SafeBootstrapLogDiagnostic(string log)
{
    var lines = log.Split(
        ['\r', '\n'],
        StringSplitOptions.RemoveEmptyEntries);
    var candidates = lines
        .Where(line =>
            line.Contains(
                "STEWARD_PERSISTENCE",
                StringComparison.Ordinal) ||
            line.Contains(
                "STEWARD_RDP_DVC_ACL:",
                StringComparison.Ordinal) ||
            line.Contains(
                "STEWARD_RDP_DVC_RUNTIMES:",
                StringComparison.Ordinal) ||
            line.Contains(
                "STEWARD_RDP_DVC_SYSTEM_HOST_EXIT:",
                StringComparison.Ordinal) ||
            line.Contains(
                "Steward endpoint provisioner failure:",
                StringComparison.Ordinal))
        .TakeLast(4)
        .Concat(lines.Where(line =>
            !line.Contains(
                "Running command",
                StringComparison.OrdinalIgnoreCase) &&
            (line.Contains("error", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("exception", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("unavailable", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("mismatch", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("limit", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("ParserError", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("CategoryInfo", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("FullyQualifiedErrorId", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("At line:", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("not recognized", StringComparison.OrdinalIgnoreCase) ||
             line.Contains("cannot", StringComparison.OrdinalIgnoreCase)))
            .TakeLast(8));
    var diagnostic = string.Join(" | ", candidates);
    if (diagnostic.Length == 0)
        diagnostic = string.Join(
            " | ",
            log.Split(
                    ['\r', '\n'],
                    StringSplitOptions.RemoveEmptyEntries)
                .Where(line => !line.Contains(
                    "Running command",
                    StringComparison.OrdinalIgnoreCase))
                .TakeLast(3));
    if (diagnostic.Length == 0)
        diagnostic = "No diagnostic line was returned.";
    diagnostic = Regex.Replace(
        diagnostic,
        "[A-Za-z0-9+/=_-]{48,}",
        "<redacted-token>",
        RegexOptions.CultureInvariant);
    diagnostic = Regex.Replace(
        diagnostic,
        @"https?://\S+",
        "<redacted-uri>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    var bytes = Encoding.UTF8.GetBytes(log);
    var hash = Convert.ToHexString(SHA256.HashData(bytes))
        .ToLowerInvariant();
    if (diagnostic.Length > 1024)
        diagnostic = diagnostic[^1024..];
    return $"{diagnostic} (bytes={bytes.Length}; sha256={hash})";
}

static async Task<string> GetTaskLogAsync(
    DevBoxCustomizationClient customizations,
    Uri logUri,
    string? expectedMarker,
    TimeSpan timeout,
    CancellationToken cancellationToken)
{
    var deadline = DateTimeOffset.UtcNow + timeout;
    var log = string.Empty;
    do
    {
        try
        {
            log = await customizations.GetTaskLogAsync(
                    logUri,
                    cancellationToken)
                .ConfigureAwait(false);
            if (expectedMarker is null
                    ? !string.IsNullOrWhiteSpace(log)
                    : log.Contains(expectedMarker, StringComparison.Ordinal))
                return log;
        }
        catch (RequestFailedException exception)
            when (exception.Status is 404 or 409)
        {
        }
        await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken)
            .ConfigureAwait(false);
    } while (DateTimeOffset.UtcNow < deadline);
    return log;
}

static string ReadIndexedBase64Payload(string log)
{
    var matches = Regex.Matches(
        log,
        @"STEWARD_ENDPOINT_RECEIPT_CHUNK:(\d{4}):([A-Za-z0-9+/]{1,32}={0,2})",
        RegexOptions.CultureInvariant);
    var chunks = new SortedDictionary<int, string>();
    foreach (Match match in matches)
    {
        var index = int.Parse(
            match.Groups[1].Value,
            System.Globalization.CultureInfo.InvariantCulture);
        var value = match.Groups[2].Value;
        if (chunks.TryGetValue(index, out var existing) &&
            !string.Equals(existing, value, StringComparison.Ordinal))
            throw new InvalidDataException(
                "Raw endpoint receipt contains conflicting chunks.");
        chunks[index] = value;
    }
    if (chunks.Count == 0 ||
        chunks.Count > 2048 ||
        chunks.Keys.Where((value, index) => value != index).Any())
        throw new InvalidDataException(
            "Raw endpoint receipt payload is invalid.");
    var encoded = string.Concat(chunks.Values);
    if (encoded.Length > 64 * 1024)
        throw new InvalidDataException(
            "Raw endpoint receipt payload exceeds its bound.");
    return encoded;
}

static bool Terminal(string status) =>
    Succeeded(status) ||
    status.Equals("Failed", StringComparison.OrdinalIgnoreCase) ||
    status.Equals("TimedOut", StringComparison.OrdinalIgnoreCase) ||
    status.Equals(
        "ValidationFailed",
        StringComparison.OrdinalIgnoreCase) ||
    status.Equals("Canceled", StringComparison.OrdinalIgnoreCase) ||
    status.Equals("Cancelled", StringComparison.OrdinalIgnoreCase);

static bool Succeeded(string status) =>
    status.Equals("Succeeded", StringComparison.OrdinalIgnoreCase) ||
    status.Equals("Completed", StringComparison.OrdinalIgnoreCase);

static byte[] ReadKey(
    string path,
    int minimum,
    int maximum,
    string description)
{
    var fullPath = ValidatePrivateKeyPath(path, description);
    byte[] key;
    using (var stream = new FileStream(
               fullPath,
               FileMode.Open,
               FileAccess.Read,
               FileShare.Read,
               4096,
               FileOptions.SequentialScan))
    {
        key = new byte[stream.Length];
        stream.ReadExactly(key);
    }
    if (key.Length < minimum || key.Length > maximum)
    {
        CryptographicOperations.ZeroMemory(key);
        throw new InvalidDataException(
            $"{description} key length is invalid.");
    }
    return key;
}

static void RequireDistinct(params byte[][] keys)
{
    for (var left = 0; left < keys.Length; left++)
    for (var right = left + 1; right < keys.Length; right++)
        if (keys[left].Length == keys[right].Length &&
            CryptographicOperations.FixedTimeEquals(
                keys[left],
                keys[right]))
            throw new InvalidDataException(
                "Bootstrap authentication and persistence keys must be distinct.");
}

static ECDsa ReadSigningKey(string path)
{
    var fullPath = ValidatePrivateKeyPath(path, "signing");
    var key = ECDsa.Create();
    try
    {
        key.ImportFromPem(File.ReadAllText(fullPath));
        _ = key.ExportParameters(includePrivateParameters: true);
        return key;
    }
    catch
    {
        key.Dispose();
        throw;
    }
}

static string ValidatePrivateKeyPath(
        string path,
        string description)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException(
                $"{description} key path is invalid.");
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException(
                $"{description} key directory is invalid.");
        var root = Path.GetPathRoot(directory)
            ?? throw new InvalidOperationException(
                $"{description} key root is invalid.");
        var currentPath = root;
        foreach (var segment in directory[root.Length..].Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            currentPath = Path.Combine(currentPath, segment);
            if (Directory.Exists(currentPath) &&
                File.GetAttributes(currentPath)
                    .HasFlag(FileAttributes.ReparsePoint))
                throw new IOException(
                    $"{description} key path contains a reparse point.");
        }
        if (!File.Exists(fullPath) ||
            File.GetAttributes(fullPath)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException(
                $"{description} key file is unavailable.");
        var current = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "The current Windows identity has no SID.");
        var system = new SecurityIdentifier(
            WellKnownSidType.LocalSystemSid,
            null);
        var security = new FileInfo(fullPath).GetAccessControl();
        if (!current.Equals(
                security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException(
                $"{description} key owner is invalid.");
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType == AccessControlType.Allow &&
                !current.Equals(rule.IdentityReference) &&
                !system.Equals(rule.IdentityReference))
                throw new UnauthorizedAccessException(
                    $"{description} key grants unintended access.");
        return fullPath;
}

static RSA LoadOrCreateBootstrapEncryptionKey(
        string stateDirectory,
        Guid operationId,
        ReadOnlySpan<byte> checkpointKey)
    {
        var directory = Path.Combine(
            Path.GetFullPath(stateDirectory),
            "bootstrap-envelopes");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{operationId:N}.key");
        var aad = operationId.ToByteArray();
        if (File.Exists(path))
        {
            var stored = File.ReadAllBytes(path);
            if (stored.Length < 12 + 16 + 1)
                throw new InvalidDataException(
                    "The bootstrap envelope key state is malformed.");
            var cleartext = new byte[stored.Length - 28];
            try
            {
                using var aes = new AesGcm(checkpointKey, 16);
                aes.Decrypt(
                    stored.AsSpan(0, 12),
                    stored.AsSpan(28),
                    stored.AsSpan(12, 16),
                    cleartext,
                    aad);
                var rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(cleartext, out var read);
                if (read != cleartext.Length)
                {
                    rsa.Dispose();
                    throw new InvalidDataException(
                        "The bootstrap envelope key contains trailing data.");
                }
                return rsa;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stored);
                CryptographicOperations.ZeroMemory(cleartext);
            }
        }
        var created = RSA.Create(3072);
        var privateKey = created.ExportPkcs8PrivateKey();
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[privateKey.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(checkpointKey, 16);
            aes.Encrypt(nonce, privateKey, ciphertext, tag, aad);
            var stored = new byte[nonce.Length + tag.Length + ciphertext.Length];
            nonce.CopyTo(stored, 0);
            tag.CopyTo(stored, nonce.Length);
            ciphertext.CopyTo(stored, nonce.Length + tag.Length);
            var pending = path + ".new";
            File.WriteAllBytes(pending, stored);
            File.Move(pending, path, overwrite: false);
            CryptographicOperations.ZeroMemory(stored);
            return created;
        }
        catch
        {
            created.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
}

static void Zero(byte[]? value)
{
    if (value is not null)
        CryptographicOperations.ZeroMemory(value);
}

internal sealed record EndpointReceiptReconnectLedger(
    int Version,
    string LedgerFile,
    string HealthFile);

internal sealed record EndpointReceiptV1Migration(
    int Version,
    string RetainedEndpointVersion,
    int NonceCount,
    int NextIndex,
    string InventorySha256,
    string AuthorizationFile,
    string AuthorizationSha256);

internal sealed record EndpointReceiptBody(
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
    [property: JsonPropertyName("connectionNonces")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<Guid>? LegacyConnectionNonces,
    DateTimeOffset ProvisionedAtUtc,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    EndpointReceiptReconnectLedger? ReconnectLedger,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    EndpointReceiptV1Migration? V1Migration = null);

internal sealed record Options(
    Uri Endpoint,
    string Project,
    string User,
    string DevBox,
    string BundlePath,
    ProviderOperationId OperationId,
    string IdempotencyKey,
    Guid StatusQueryId,
    Guid SessionId,
    HostId HostId,
    NodeIncarnationId IncarnationId,
    IReadOnlyList<Guid> ConnectionNonces,
    string AuthenticationKeyFile,
    string CheckpointKeyFile,
    string HandleKeyFile,
    string StateDirectory,
    string ReceiptPath,
    TimeSpan PollInterval,
    TimeSpan Timeout,
    string Consent,
    string? NodeSigningPrivateKeyFile,
    string? NodeIdentity,
    string? ControlSigningPrivateKeyFile,
    string? ControlIdentity,
    string? AttestedReceiptPath,
    bool RestartStalledCustomization,
    bool RestartAfterBootstrap,
    bool RestartStalledStatus,
    bool ProbeEndpoint,
    bool InspectRecovery,
    bool InspectStaging,
    bool InspectOperation,
    string? RestartOnlyId)
{
    private const string RestartConsent =
        "I_CONFIRM_THIS_DEV_BOX_HAS_NO_ACTIVE_WORK_AND_MAY_BE_RESTARTED";

    internal static Options Parse(string[] arguments)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Length; index += 2)
        {
            if (index + 1 >= arguments.Length ||
                !Known.Contains(arguments[index]) ||
                !values.TryAdd(arguments[index], arguments[index + 1]))
                throw new ArgumentException(
                    "Bootstrap deployment arguments are invalid.");
        }
        var endpointText = Required(values, "--endpoint");
        if (!Uri.TryCreate(
                endpointText,
                UriKind.Absolute,
                out var endpoint))
            throw new ArgumentException("Dev Center endpoint is invalid.");
        var pollSeconds = Integer(
            values,
            "--poll-seconds",
            defaultValue: 5,
            minimum: 1,
            maximum: 60);
        var timeoutSeconds = Integer(
            values,
            "--timeout-seconds",
            defaultValue: 900,
            minimum: 30,
            maximum: 7200);
        var nodeKey = Optional(values, "--node-signing-private-key");
        var nodeIdentity = Optional(values, "--node-identity");
        var controlKey = Optional(
            values,
            "--control-signing-private-key");
        var controlIdentity = Optional(values, "--control-identity");
        var attestedPath = Optional(values, "--attested-receipt");
        var restart = Optional(
            values,
            "--restart-stalled-customization");
        if (restart is not null && restart != RestartConsent)
            throw new ArgumentException(
                "The stalled-customization restart consent is invalid.");
        var restartAfterBootstrap = Optional(
            values,
            "--restart-after-bootstrap");
        if (restartAfterBootstrap is not null &&
            restartAfterBootstrap != RestartConsent)
            throw new ArgumentException(
                "The post-bootstrap restart consent is invalid.");
        var restartStalledStatus = Optional(
            values,
            "--restart-stalled-status");
        if (restartStalledStatus is not null &&
            restartStalledStatus != RestartConsent)
            throw new ArgumentException(
                "The stalled-status restart consent is invalid.");
        var probeEndpoint = Optional(
            values,
            "--probe-endpoint");
        if (probeEndpoint is not null &&
            !bool.TryParse(probeEndpoint, out _))
            throw new ArgumentException(
                "The endpoint probe option must be true or false.");
        var inspectRecovery = Optional(
            values,
            "--inspect-recovery");
        if (inspectRecovery is not null &&
            !bool.TryParse(inspectRecovery, out _))
            throw new ArgumentException(
                "The recovery inspection option must be true or false.");
        var inspectStaging = Optional(
            values,
            "--inspect-staging");
        if (inspectStaging is not null &&
            !bool.TryParse(inspectStaging, out _))
            throw new ArgumentException(
                "The staging inspection option must be true or false.");
        var inspectOperation = Optional(
            values,
            "--inspect-operation");
        if (inspectOperation is not null &&
            !bool.TryParse(inspectOperation, out _))
            throw new ArgumentException(
                "The operation inspection option must be true or false.");
        var restartOnlyId = Optional(
            values,
            "--restart-only-id");
        if (restartOnlyId is not null &&
            (restartAfterBootstrap is null ||
             restartOnlyId.Length is < 3 or > 128 ||
             restartOnlyId.Any(character =>
                 !char.IsAsciiLetterOrDigit(character) &&
                 character is not '-' and not '_' and not '.')))
            throw new ArgumentException(
                "Restart-only requires restart consent and a bounded identifier.");
        var attestationCount = new[]
        {
            nodeKey,
            nodeIdentity,
            controlKey,
            controlIdentity,
            attestedPath
        }.Count(value => value is not null);
        if (attestationCount is not 0 and not 5)
            throw new ArgumentException(
                "Node and Control attestation options must be supplied together.");
        return new(
            endpoint,
            Required(values, "--project"),
            Required(values, "--user"),
            Required(values, "--devbox"),
            Path.GetFullPath(Required(values, "--bundle")),
            new ProviderOperationId(GuidValue(values, "--operation-id")),
            Required(values, "--idempotency-key"),
            GuidValue(values, "--status-query-id"),
            GuidValue(values, "--session-id"),
            new HostId(GuidValue(values, "--host-id")),
            new NodeIncarnationId(
                GuidValue(values, "--incarnation-id")),
            [
                GuidValue(values, "--nonce-0"),
                GuidValue(values, "--nonce-1")
            ],
            Path.GetFullPath(Required(values, "--auth-key-file")),
            Path.GetFullPath(
                Required(values, "--checkpoint-key-file")),
            Path.GetFullPath(Required(values, "--handle-key-file")),
            Path.GetFullPath(Required(values, "--state-directory")),
            Path.GetFullPath(Required(values, "--receipt")),
            TimeSpan.FromSeconds(pollSeconds),
            TimeSpan.FromSeconds(timeoutSeconds),
            Required(values, "--consent"),
            nodeKey is null ? null : Path.GetFullPath(nodeKey),
            nodeIdentity,
            controlKey is null ? null : Path.GetFullPath(controlKey),
            controlIdentity,
            attestedPath is null ? null : Path.GetFullPath(attestedPath),
            restart is not null,
            restartAfterBootstrap is not null,
            restartStalledStatus is not null,
            bool.TryParse(probeEndpoint, out var probe) && probe,
            bool.TryParse(inspectRecovery, out var inspect) && inspect,
            bool.TryParse(inspectStaging, out var inspectStage) &&
            inspectStage,
            bool.TryParse(inspectOperation, out var inspectOp) &&
            inspectOp,
            restartOnlyId);
    }

    private static readonly HashSet<string> Known =
    [
        "--endpoint",
        "--project",
        "--user",
        "--devbox",
        "--bundle",
        "--operation-id",
        "--idempotency-key",
        "--status-query-id",
        "--session-id",
        "--host-id",
        "--incarnation-id",
        "--nonce-0",
        "--nonce-1",
        "--auth-key-file",
        "--checkpoint-key-file",
        "--handle-key-file",
        "--state-directory",
        "--receipt",
        "--poll-seconds",
        "--timeout-seconds",
        "--consent",
        "--node-signing-private-key",
        "--node-identity",
        "--control-signing-private-key",
        "--control-identity",
        "--attested-receipt",
        "--restart-stalled-customization",
        "--restart-after-bootstrap",
        "--restart-stalled-status",
        "--probe-endpoint",
        "--inspect-recovery",
        "--inspect-staging",
        "--inspect-operation",
        "--restart-only-id"
    ];

    private static string Required(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.TryGetValue(name, out var value) &&
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException(
                $"Required argument '{name}' is missing.");

    private static string? Optional(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        values.GetValueOrDefault(name);

    private static Guid GuidValue(
        IReadOnlyDictionary<string, string> values,
        string name) =>
        Guid.TryParse(Required(values, name), out var value) &&
        value != Guid.Empty
            ? value
            : throw new ArgumentException(
                $"Argument '{name}' must be a nonempty GUID.");

    private static int Integer(
        IReadOnlyDictionary<string, string> values,
        string name,
        int defaultValue,
        int minimum,
        int maximum)
    {
        var text = values.GetValueOrDefault(name);
        if (text is null)
            return defaultValue;
        if (!int.TryParse(text, out var value) ||
            value < minimum ||
            value > maximum)
            throw new ArgumentException(
                $"Argument '{name}' is outside its bound.");
        return value;
    }

}

internal sealed record StatusQueryIntent(
    int Version,
    Guid QueryId,
    Guid OperationId,
    string Project,
    string User,
    string DevBox,
    string BundleVersion,
    string ArchiveSha256)
{
    internal static async Task RecordAsync(
        string stateDirectory,
        Guid queryId,
        Options options,
        RdpDvcBootstrapBundle bundle,
        CancellationToken cancellationToken)
    {
        var directory = Path.Combine(
            Path.GetFullPath(stateDirectory),
            "status-queries");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{queryId:N}.json");
        var intent = new StatusQueryIntent(
            1,
            queryId,
            options.OperationId.Value,
            options.Project,
            options.User,
            options.DevBox,
            bundle.Manifest.Version,
            bundle.ArchiveSha256);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            intent,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (File.Exists(path))
        {
            var existing = await File.ReadAllBytesAsync(
                    path,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!existing.AsSpan().SequenceEqual(bytes))
                throw new InvalidOperationException(
                    "Status query ID was reused with different intent.");
            return;
        }
        var pending = path + ".new";
        await using (var stream = new FileStream(
                         pending,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await stream.WriteAsync(bytes, cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        File.Move(pending, path);
    }
}
