namespace Steward.RdCore.Windows.Tests;

public sealed class BinarySecurityTests
{
    [Fact]
    public void Path_validator_rejects_reparse_points()
    {
        var fileSystem = new StubFileSystem
        {
            ReparseFileName = RdCorePathValidator.NativeSdkFileName
        };
        var validator = new RdCorePathValidator(fileSystem);

        var result = validator.Validate(@"C:\Packages\Windows365");

        Assert.Equal(RdCoreCapabilityCode.ReparsePointRejected, result.Code);
        Assert.Null(result.Paths);
    }

    [Fact]
    public void Path_validator_rejects_oversize_files()
    {
        var fileSystem = new StubFileSystem
        {
            FileLength = RdCorePathValidator.DefaultMaximumBinarySize + 1
        };
        var validator = new RdCorePathValidator(fileSystem);

        var result = validator.Validate(@"C:\Packages\Windows365");

        Assert.Equal(RdCoreCapabilityCode.FileTooLarge, result.Code);
    }

    [Fact]
    public void Authenticode_verifier_rejects_unsigned_fixture()
    {
        var verifier = new MicrosoftAuthenticodeVerifier();

        var result = verifier.Verify(typeof(BinarySecurityTests).Assembly.Location);

        Assert.Equal(AuthenticodeStatus.Untrusted, result);
    }

    [Fact]
    public void Portable_executable_validator_accepts_managed_fixture()
    {
        var validator = new PortableExecutableValidator(
            new PhysicalRdCoreFileSystem());

        var result = validator.Validate(
            typeof(BinarySecurityTests).Assembly.Location,
            requireManagedMetadata: true);

        Assert.Equal(RdCoreCapabilityCode.Compatible, result.Code);
        Assert.True(result.HasMetadata);
    }

    private sealed class StubFileSystem : IRdCoreFileSystem
    {
        public string? ReparseFileName { get; init; }

        public long FileLength { get; init; } = 1024;

        public string GetFullPath(string path) => Path.GetFullPath(path);

        public bool DirectoryExists(string path) => true;

        public bool FileExists(string path) => true;

        public FileAttributes GetAttributes(string path) =>
            string.Equals(
                Path.GetFileName(path),
                ReparseFileName,
                StringComparison.Ordinal)
                ? FileAttributes.ReparsePoint
                : FileAttributes.Normal;

        public long GetFileLength(string path) => FileLength;

        public Stream OpenRead(string path) => new MemoryStream([0]);
    }
}
