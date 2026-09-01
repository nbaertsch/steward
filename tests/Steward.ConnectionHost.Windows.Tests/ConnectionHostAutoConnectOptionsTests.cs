using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class ConnectionHostAutoConnectOptionsTests : IDisposable
{
    private readonly string root = Path.Combine(
        AppContext.BaseDirectory,
        "auto-connect",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void Descriptor_contract_contains_only_non_secret_desired_identity()
    {
        var properties = typeof(ConnectionHostAutoConnectOptions)
            .GetProperties()
            .Select(value => value.Name)
            .ToArray();

        Assert.DoesNotContain("AuthorizationToken", properties);
        Assert.DoesNotContain("EvidenceReference", properties);
        Assert.DoesNotContain("ConnectionNonce", properties);
        Assert.Contains("DevBoxEndpoint", properties);
        Assert.Contains("ConnectionId", properties);
    }
    [Fact]
    public async Task Load_accepts_a_valid_bounded_descriptor()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "auto-connect.json");
        var expected = Valid();
        await ConnectionHostAutoConnectOptions.WriteProtectedAsync(
            path,
            expected);

        var actual = await ConnectionHostAutoConnectOptions.LoadAsync(
            path,
            CancellationToken.None);

        Assert.Equal(expected, actual);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Load_rejects_an_invalid_transport_identity()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "auto-connect.json");
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ConnectionHostAutoConnectOptions.WriteProtectedAsync(
                path,
                Valid() with { HostId = Guid.Empty }));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Load_rejects_a_relative_descriptor_path()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ConnectionHostAutoConnectOptions.LoadAsync(
                "auto-connect.json",
                CancellationToken.None));
    }

    [Fact]
    public async Task Load_rejects_a_descriptor_with_inherited_permissions()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "auto-connect.json");
        await File.WriteAllBytesAsync(
            path,
            JsonSerializer.SerializeToUtf8Bytes(
                Valid(),
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            ConnectionHostAutoConnectOptions.LoadAsync(
                path,
                CancellationToken.None));
    }

    [Fact]
    public async Task Load_rejects_private_but_unprotected_plaintext()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "auto-connect.json");
        await ConnectionHostAutoConnectOptions.WriteProtectedAsync(
            path,
            Valid());
        await File.WriteAllBytesAsync(
            path,
            JsonSerializer.SerializeToUtf8Bytes(
                Valid(),
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ConnectionHostAutoConnectOptions.LoadAsync(
                path,
                CancellationToken.None));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private static ConnectionHostAutoConnectOptions Valid() =>
        new(
            2,
            new("https://project-1.devcenter.azure.com/"),
            "project-1",
            "me",
            "devbox-1",
            "connection-b1",
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid());

    private static void Protect(string path)
    {
        var current = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException();
        var security = new FileSecurity();
        security.SetOwner(current);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(new(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }
}
