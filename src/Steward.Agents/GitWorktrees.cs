namespace Steward.Agents;

using System.Text;
using Steward.Tasks.Abstractions;

public sealed record GitRepositoryIdentity(string CanonicalRemote, string RepositoryId);
public sealed record GitWorktreeSpec(
    GitRepositoryIdentity Repository,
    string LocalRepositoryRoot,
    string WorkspaceRoot,
    string BaseReference,
    string BaseCommit,
    string WorktreePath);
public sealed record GitArtifact(string MediaType, byte[] Content, string Sha256);

public sealed record GitProcessRequest(
    string Executable,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    int MaximumOutputBytes);
public sealed record GitProcessResult(
    int ExitCode,
    byte[] StandardOutput,
    string StandardError,
    bool OutputTruncated = false);

public interface IGitProcess
{
    Task<GitProcessResult> RunAsync(GitProcessRequest request, CancellationToken cancellationToken);
}

public interface IAgentWorktree : IAsyncDisposable
{
    GitWorktreeSpec Spec { get; }
    Task<GitArtifact> ExportDirtyPatchAsync(CancellationToken cancellationToken);
    Task<GitArtifact> ExportBundleAsync(CancellationToken cancellationToken);
}

public interface IAgentWorktreeManager
{
    Task<IAgentWorktree> CreateAsync(GitWorktreeSpec spec, CancellationToken cancellationToken);
}

public interface IWorktreePathValidator
{
    void ValidateContainedPath(string workspaceRoot, string worktreePath);
}

public sealed class ReparseAwareWorktreePathValidator : IWorktreePathValidator
{
    public void ValidateContainedPath(string workspaceRoot, string worktreePath)
    {
        var workspace = Path.GetFullPath(workspaceRoot).TrimEnd(Path.DirectorySeparatorChar);
        var worktree = Path.GetFullPath(worktreePath);
        var relative = Path.GetRelativePath(workspace, worktree);
        try
        {
            if (!string.Equals(WorkspacePaths.Resolve(workspace, relative), worktree, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Worktree path is not canonical.", nameof(worktreePath));
        }
        catch (InvalidOperationException exception)
        {
            throw new ArgumentException("Worktree path traverses a reparse point.", nameof(worktreePath), exception);
        }
    }
}

public sealed class GitCliWorktreeManager : IAgentWorktreeManager
{
    private readonly IGitProcess _process;
    private readonly IWorktreePathValidator _paths;
    public GitCliWorktreeManager(IGitProcess process, IWorktreePathValidator? paths = null)
    {
        _process = process;
        _paths = paths ?? new ReparseAwareWorktreePathValidator();
    }

    public async Task<IAgentWorktree> CreateAsync(GitWorktreeSpec spec, CancellationToken cancellationToken)
    {
        Validate(spec);
        await VerifyRepositoryAsync(spec, cancellationToken).ConfigureAwait(false);
        var result = await _process.RunAsync(new("git",
            ["worktree", "add", "--detach", "--", spec.WorktreePath, spec.BaseCommit],
            spec.LocalRepositoryRoot, AgentLimits.MaximumActivityBytes), cancellationToken).ConfigureAwait(false);
        EnsureSuccess(result, AgentLimits.MaximumActivityBytes, "worktree creation");
        return new GitCliWorktree(spec, _process);
    }

    private void Validate(GitWorktreeSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        AgentLimits.Text(spec.Repository.RepositoryId, 256, nameof(spec.Repository.RepositoryId));
        AgentLimits.Text(spec.Repository.CanonicalRemote, 2048, nameof(spec.Repository.CanonicalRemote));
        if (!Uri.TryCreate(spec.Repository.CanonicalRemote, UriKind.Absolute, out var remote) ||
            remote.Scheme is not ("https" or "ssh"))
            throw new ArgumentException("Canonical remote must be an absolute HTTPS or SSH URI.", nameof(spec));
        if (!string.IsNullOrEmpty(remote.UserInfo) || !string.IsNullOrEmpty(remote.Query) ||
            !string.IsNullOrEmpty(remote.Fragment))
            throw new ArgumentException("Canonical remote cannot embed credentials, query, or fragment.", nameof(spec));
        if (!Path.IsPathFullyQualified(spec.LocalRepositoryRoot) ||
            !Path.IsPathFullyQualified(spec.WorkspaceRoot) ||
            !Path.IsPathFullyQualified(spec.WorktreePath))
            throw new ArgumentException("Repository, workspace, and worktree paths must be absolute.", nameof(spec));
        AgentLimits.Text(spec.LocalRepositoryRoot, 4096, nameof(spec.LocalRepositoryRoot));
        AgentLimits.Text(spec.WorkspaceRoot, 4096, nameof(spec.WorkspaceRoot));
        AgentLimits.Text(spec.WorktreePath, 4096, nameof(spec.WorktreePath));
        var repository = Path.GetFullPath(spec.LocalRepositoryRoot).TrimEnd(Path.DirectorySeparatorChar);
        var workspace = Path.GetFullPath(spec.WorkspaceRoot).TrimEnd(Path.DirectorySeparatorChar);
        var worktree = Path.GetFullPath(spec.WorktreePath);
        if (!Directory.Exists(repository))
            throw new DirectoryNotFoundException(repository);
        _paths.ValidateContainedPath(workspace, worktree);
        AgentLimits.Text(spec.BaseReference, 512, nameof(spec.BaseReference));
        if (spec.BaseReference.StartsWith('-') || spec.BaseReference.Contains("..", StringComparison.Ordinal) ||
            spec.BaseReference.Any(char.IsControl))
            throw new ArgumentException("Base reference is invalid.", nameof(spec));
        if (spec.BaseCommit.Length is not (40 or 64) || !spec.BaseCommit.All(Uri.IsHexDigit))
            throw new ArgumentException("Base commit must be a full hexadecimal object ID.", nameof(spec));
    }

    private async Task VerifyRepositoryAsync(GitWorktreeSpec spec, CancellationToken cancellationToken)
    {
        var remoteResult = await _process.RunAsync(new(
            "git", ["remote", "get-url", "--all", "origin"], spec.LocalRepositoryRoot, 16 * 1024),
            cancellationToken).ConfigureAwait(false);
        EnsureSuccess(remoteResult, 16 * 1024, "remote identity verification");
        var remotes = Encoding.UTF8.GetString(remoteResult.StandardOutput)
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (remotes.Length == 0 || !remotes.Any(x =>
            string.Equals(x.TrimEnd('/'), spec.Repository.CanonicalRemote.TrimEnd('/'), StringComparison.Ordinal)))
            throw new InvalidDataException("Local repository canonical remote does not match the declared identity.");
        foreach (var value in remotes)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query))
                throw new InvalidDataException("Local repository remote contains credentials or an invalid URI.");
        }

        var commitResult = await _process.RunAsync(new(
            "git", ["rev-parse", "--verify", $"{spec.BaseReference}^{{commit}}"],
            spec.LocalRepositoryRoot, 1024), cancellationToken).ConfigureAwait(false);
        EnsureSuccess(commitResult, 1024, "base commit verification");
        var resolved = Encoding.ASCII.GetString(commitResult.StandardOutput).Trim();
        if (!string.Equals(resolved, spec.BaseCommit, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Declared base commit does not match the resolved base reference.");
    }

    private static void EnsureSuccess(GitProcessResult result, int maximumBytes, string operation)
    {
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Git {operation} failed with exit code {result.ExitCode}.");
        if (result.OutputTruncated || result.StandardOutput.LongLength > maximumBytes ||
            System.Text.Encoding.UTF8.GetByteCount(result.StandardError) > AgentLimits.MaximumActivityBytes)
            throw new InvalidDataException($"Git {operation} exceeded its bounded output contract.");
    }

    private sealed class GitCliWorktree(GitWorktreeSpec spec, IGitProcess process) : IAgentWorktree
    {
        public GitWorktreeSpec Spec { get; } = spec;
        public async Task<GitArtifact> ExportDirtyPatchAsync(CancellationToken cancellationToken)
        {
            var result = await process.RunAsync(
                new("git", ["diff", "--binary", "--no-ext-diff"], Spec.WorktreePath, AgentLimits.MaximumResponseBytes),
                cancellationToken).ConfigureAwait(false);
            EnsureSuccess(result, AgentLimits.MaximumResponseBytes, "dirty patch export");
            return Artifact("text/x-diff", result.StandardOutput);
        }

        public async Task<GitArtifact> ExportBundleAsync(CancellationToken cancellationToken)
        {
            var result = await process.RunAsync(
                new("git", ["bundle", "create", "-", "--all"], Spec.WorktreePath, AgentLimits.MaximumContextBytes),
                cancellationToken).ConfigureAwait(false);
            EnsureSuccess(result, AgentLimits.MaximumContextBytes, "bundle export");
            return Artifact("application/x-git-bundle", result.StandardOutput);
        }

        public async ValueTask DisposeAsync()
        {
            var result = await process.RunAsync(new("git", ["worktree", "remove", "--force", "--", Spec.WorktreePath],
                Spec.LocalRepositoryRoot, AgentLimits.MaximumActivityBytes), CancellationToken.None).ConfigureAwait(false);
            EnsureSuccess(result, AgentLimits.MaximumActivityBytes, "worktree cleanup");
        }

        private static GitArtifact Artifact(string mediaType, byte[] content) =>
            new(mediaType, content, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(content)));
    }
}
