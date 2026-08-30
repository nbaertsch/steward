using System.Text.Json;

namespace Steward.DevBox.LiveAcceptance;

internal sealed class DurableEvidenceStore
{
    private readonly string _directory;
    private readonly string _statePath;

    public DurableEvidenceStore(string directory)
    {
        _directory = directory;
        _statePath = Path.Combine(directory, "state.json");
    }

    public async Task<DurableRunState?> LoadStateAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_statePath))
            return null;
        await using var stream = File.OpenRead(_statePath);
        return await JsonSerializer.DeserializeAsync(
            stream,
            HarnessJsonContext.Default.DurableRunState,
            cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("Durable live-run state is empty.");
    }

    public Task SaveStateAsync(
        DurableRunState state,
        CancellationToken cancellationToken) =>
        WriteAtomicAsync(
            _statePath,
            state,
            HarnessJsonContext.Default.DurableRunState,
            cancellationToken);

    public Task SaveEvidenceAsync(
        AcceptanceEvidence evidence,
        CancellationToken cancellationToken) =>
        WriteAtomicAsync(
            Path.Combine(_directory, $"evidence-{evidence.RunId}.json"),
            evidence,
            HarnessJsonContext.Default.AcceptanceEvidence,
            cancellationToken);

    private async Task WriteAtomicAsync<T>(
        string path,
        T value,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_directory);
        var pending = path + ".new";
        await using (var stream = new FileStream(
                         pending,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.WriteThrough | FileOptions.Asynchronous))
        {
            await JsonSerializer.SerializeAsync(
                stream,
                value,
                typeInfo,
                cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        File.Move(pending, path, true);
    }
}
