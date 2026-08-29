using System.Security.Cryptography;
using Steward.Domain;
using Steward.PortableState;
using Steward.Tasks.Abstractions;

namespace Steward.Orchestration;

public sealed record PublishedTaskOutput(TaskRuntimeOutput Output, bool HasPortableReceipt);

public interface ITaskPortablePublisher
{
    ValueTask<PublishedTaskOutput> PublishAsync(
        AttemptIdentity identity,
        string workspace,
        TaskRuntimeOutput output,
        bool required,
        CancellationToken cancellationToken);
}

public sealed class SpoolingTaskPortablePublisher(
    DiskSpool spool,
    PortableObjectUploader? uploader = null) : ITaskPortablePublisher
{
    public async ValueTask<PublishedTaskOutput> PublishAsync(
        AttemptIdentity identity,
        string workspace,
        TaskRuntimeOutput output,
        bool required,
        CancellationToken cancellationToken)
    {
        if (output is not (TaskRuntimeArtifact or TaskRuntimeCheckpoint))
            return new(output, false);
        var (id, reference, mediaType, size, declaredHash, kind) = output switch
        {
            TaskRuntimeArtifact artifact => (
                artifact.PortableObjectId, artifact.Reference, artifact.MediaType,
                artifact.SizeBytes, artifact.ContentHash, "artifact"),
            TaskRuntimeCheckpoint checkpoint => (
                checkpoint.PortableObjectId, checkpoint.Reference, "application/octet-stream",
                checkpoint.SizeBytes, checkpoint.ContentHash, "checkpoint"),
            _ => throw new InvalidOperationException()
        };
        if (Uri.TryCreate(reference, UriKind.Absolute, out var portable) &&
            portable.Scheme.Equals("portable", StringComparison.OrdinalIgnoreCase))
            return new(output, true);
        var path = Path.IsPathFullyQualified(reference)
            ? Path.GetFullPath(reference)
            : Path.GetFullPath(Path.Combine(workspace, reference));
        var relative = Path.GetRelativePath(workspace, path);
        if (Path.IsPathRooted(relative) || relative == ".." ||
            relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
            !File.Exists(path))
            throw new InvalidDataException("Portable output path is absent or outside the Task workspace.");
        await using var content = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, true);
        var actualSize = content.Length;
        var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(content, cancellationToken));
        content.Position = 0;
        if (size != actualSize || !string.Equals(declaredHash, hash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Portable output metadata does not match its content.");
        var descriptor = new PortableObjectDescriptor(
            PortableObjectDescriptor.ContentAddressedName(kind, hash),
            id.ToString(), "1.0", mediaType, hash, actualSize,
            new Dictionary<string, string>
            {
                ["workloadId"] = identity.WorkloadId.ToString(),
                ["taskId"] = identity.TaskId.ToString(),
                ["attemptId"] = identity.AttemptId.ToString(),
                ["generation"] = identity.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture)
            });
        var existing = spool.GetItems().SingleOrDefault(x => x.PortableObjectId == id);
        SpoolManifest manifest;
        if (existing is not null)
        {
            if (existing.Object.Sha256 != descriptor.Sha256 ||
                existing.Object.Length != descriptor.Length ||
                existing.Object.LogicalObjectId != descriptor.LogicalObjectId)
                throw new InvalidDataException("Portable output identity conflicts with its durable spool.");
            manifest = existing;
        }
        else
        {
            var admitted = await spool.AdmitAsync(
                id, descriptor, content, required, cancellationToken).ConfigureAwait(false);
            if (!admitted.Admitted)
                throw new InvalidOperationException("portable.spool-admission-denied");
            manifest = admitted.Manifest!;
        }
        if (uploader is null)
        {
            if (required)
                throw new InvalidOperationException("portable.remote-store-unavailable");
            return new(Rewrite(output, $"spool://{manifest.SpoolId:D}", hash, actualSize), false);
        }
        PortableObjectReceipt? receipt;
        do
        {
            receipt = await spool.UploadNextAsync(uploader, cancellationToken).ConfigureAwait(false);
        } while (receipt is not null &&
                 spool.GetItems().Any(x => x.PortableObjectId == id && x.State != SpoolItemState.Committed));
        var committed = spool.GetItems().Single(x => x.PortableObjectId == id);
        if (committed.Receipt is null)
            throw new InvalidOperationException("portable.receipt-incomplete");
        return new(Rewrite(
            output,
            $"portable://{committed.Receipt.ObjectName}",
            hash,
            actualSize), true);
    }

    private static TaskRuntimeOutput Rewrite(
        TaskRuntimeOutput output, string reference, string hash, long size) => output switch
        {
            TaskRuntimeArtifact artifact => artifact with
            {
                Reference = reference,
                ContentHash = hash,
                SizeBytes = size
            },
            TaskRuntimeCheckpoint checkpoint => checkpoint with
            {
                Reference = reference,
                ContentHash = hash,
                SizeBytes = size
            },
            _ => output
        };
}
