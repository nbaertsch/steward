using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Steward.ConnectionHost.Windows;
using Steward.Transport.Rdp.Windows;

namespace Steward.ConnectionHost.Windows.Tests;

public sealed class HostBoundaryTests
{
    [Fact]
    public async Task Metadata_uses_current_user_acl_and_no_fixed_temp_file()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "connections.json");
            var store = new AtomicJsonConnectionMetadataStore(path);

            await store.SaveAsync(
                [],
                CancellationToken.None);

            Assert.Empty(
                Directory.GetFiles(directory, "*.new"));
            Assert.False(
                File.GetAttributes(path)
                    .HasFlag(FileAttributes.ReparsePoint));
            var current = WindowsIdentity.GetCurrent().User;
            var owner = new FileInfo(path)
                .GetAccessControl()
                .GetOwner(typeof(SecurityIdentifier));
            Assert.Equal(current, owner);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Pipe_reports_bounded_protocol_error_for_malformed_frame()
    {
        var pipeName = "Steward.ConnectionHost.Malformed." +
            Guid.NewGuid().ToString("N");
        var options = new ConnectionHostOptions
        {
            PipeName = pipeName,
            CommandTimeout = TimeSpan.FromSeconds(5)
        };
        await using var host = BoundaryHost.Create(options);
        await host.InitializeAsync();
        using var stop = new CancellationTokenSource();
        var server = new ConnectionHostPipeServer(options, host)
            .RunAsync(stop.Token);
        await using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            TokenImpersonationLevel.Identification);
        await client.ConnectAsync(CancellationToken.None);
        var invalidLength = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(
            invalidLength,
            ConnectionHostProtocol.MaximumMessageBytes + 1);
        await client.WriteAsync(
            invalidLength,
            CancellationToken.None);
        await client.FlushAsync(CancellationToken.None);

        var response = await ConnectionHostProtocol.ReadResponseAsync(
            client,
            CancellationToken.None);
        stop.Cancel();
        await server;

        Assert.False(response.Accepted);
        Assert.Equal("invalid", response.RequestId);
        Assert.Equal("CONNECTION_HOST_PROTOCOL_INVALID", response.Code);
    }

    [Fact]
    public void Evidence_key_file_is_dpapi_protected_and_current_user_only()
    {
        var directory = TestDirectory();
        try
        {
            var path = Path.Combine(directory, "evidence.key");
            var key = RandomNumberGenerator.GetBytes(32);

            CurrentUserProtectedDataFile.Write(
                path,
                AuthenticatedRdpDvcEvidencePublisher.KeyFilePurpose,
                key);

            var protectedValue = File.ReadAllBytes(path);
            var cleartext = CurrentUserProtectedDataFile.Read(
                path,
                AuthenticatedRdpDvcEvidencePublisher.KeyFilePurpose);
            var owner = new FileInfo(path)
                .GetAccessControl()
                .GetOwner(typeof(SecurityIdentifier));
            Assert.False(protectedValue.AsSpan().IndexOf(key) >= 0);
            Assert.Equal(key, cleartext);
            Assert.Equal(WindowsIdentity.GetCurrent().User, owner);
            CryptographicOperations.ZeroMemory(cleartext);
            CryptographicOperations.ZeroMemory(key);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Ticket_store_binds_runtime_identity_without_secrets()
    {
        var directory = TestDirectory();
        try
        {
            var store = new DpapiRdpDvcEvidenceTicketStore(directory);
            var reference = "bound-ticket-reference";
            var route = new RdpDvcEvidenceRoute(
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                0,
                Guid.NewGuid());
            store.Write(reference, route);
            var identity = new RdpDvcEvidenceTicketIdentity(
                reference,
                "connection",
                "runtime",
                19,
                route);

            await store.BindAsync(identity, CancellationToken.None);
            Assert.Equal(identity, store.ReadBound(reference));
            var bound = identity with
            {
                Route = route.BindWtsSession(42)
            };
            store.BindWtsSession(bound);
            var restored = store.ReadBound(reference);

            Assert.Equal(bound, restored);
            Assert.False(File.Exists(
                Path.Combine(directory, reference + ".ticket")));
            var protectedText = Convert.ToHexString(
                await File.ReadAllBytesAsync(
                    Path.Combine(directory, reference + ".bound")));
            Assert.DoesNotContain(
                Convert.ToHexString(
                    System.Text.Encoding.UTF8.GetBytes("connection")),
                protectedText,
                StringComparison.Ordinal);
            Assert.Throws<InvalidOperationException>(
                () => store.BindWtsSession(
                    bound with
                    {
                        Route = route.BindWtsSession(43)
                    }));
            await store.ReleaseAsync(reference);
            Assert.False(File.Exists(
                Path.Combine(directory, reference + ".bound")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string TestDirectory()
    {
        var directory = Path.Combine(
            AppContext.BaseDirectory,
            "connection-host-boundary-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static class BoundaryHost
    {
        public static ConnectionHostOrchestrator Create(
            ConnectionHostOptions options) =>
            new(
                options,
                new UnusedIdentity(),
                new DisabledDevBoxConnectionResolver(),
                new UnusedCompatibility(),
                new UnusedRegistration(),
                new DisabledRdCoreConnectionRuntime(),
                new SingleUseControlConnectAuthorizationValidator(),
                new MemoryMetadataStore());
    }

    private sealed class UnusedIdentity :
        Steward.DevBox.Windows.IDevBoxConnectionIdentityGate
    {
        public Task<Steward.DevBox.Windows.DevBoxConnectionIdentityStatus>
            StatusAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedCompatibility :
        IRdCoreCompatibilityInspector
    {
        public RdCoreCompatibilitySnapshot Inspect() =>
            throw new NotSupportedException();
    }

    private sealed class UnusedRegistration :
        IDvcRegistrationSnapshotProvider
    {
        public Steward.Transport.Rdp.Windows.DvcPluginRegistrationStatus
            GetStatus() =>
            throw new NotSupportedException();
    }

    private sealed class MemoryMetadataStore : IConnectionMetadataStore
    {
        public Task<IReadOnlyList<DurableConnectionMetadata>> LoadAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DurableConnectionMetadata>>([]);

        public Task SaveAsync(
            IReadOnlyCollection<DurableConnectionMetadata> connections,
            CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
