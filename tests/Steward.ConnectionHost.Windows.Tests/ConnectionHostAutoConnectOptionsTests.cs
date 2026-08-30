using System.Text.Json;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class ConnectionHostAutoConnectOptionsTests : IDisposable
{
    private readonly string root = Path.Combine(
        AppContext.BaseDirectory,
        "auto-connect",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Load_accepts_a_valid_bounded_descriptor()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "auto-connect.json");
        var expected = Valid();
        await File.WriteAllBytesAsync(
            path,
            JsonSerializer.SerializeToUtf8Bytes(
                expected,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));

        var actual = await ConnectionHostAutoConnectOptions.LoadAsync(
            path,
            CancellationToken.None);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task Load_rejects_an_invalid_transport_identity()
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "auto-connect.json");
        await File.WriteAllBytesAsync(
            path,
            JsonSerializer.SerializeToUtf8Bytes(
                Valid() with { HostId = Guid.Empty },
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ConnectionHostAutoConnectOptions.LoadAsync(
                path,
                CancellationToken.None));
    }

    [Fact]
    public async Task Load_rejects_a_relative_descriptor_path()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ConnectionHostAutoConnectOptions.LoadAsync(
                "auto-connect.json",
                CancellationToken.None));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }

    private static ConnectionHostAutoConnectOptions Valid() =>
        new(
            1,
            new("https://project-1.devcenter.azure.com/"),
            "project-1",
            "me",
            "devbox-1",
            "connection-b1",
            "authorization-token",
            "evidence-reference",
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid());
}
