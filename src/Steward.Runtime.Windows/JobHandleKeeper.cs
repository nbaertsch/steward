using Microsoft.Win32.SafeHandles;
using Steward.Domain;

namespace Steward.Runtime.Windows;

public sealed record JobLeaseIdentity(
    string JobName,
    TaskAttemptId AttemptId,
    int Generation,
    NodeIncarnationId NodeIncarnationId)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(JobName) || Generation <= 0 ||
            AttemptId.Value == Guid.Empty || NodeIncarnationId.Value == Guid.Empty)
            throw new ArgumentException("A Job lease requires complete immutable identity.");
        var expected = $@"Local\Steward.{AttemptId.Value:N}.{Generation}";
        if (!StringComparer.Ordinal.Equals(JobName, expected))
            throw new ArgumentException("Job name does not match attempt identity.");
    }
}

/// <summary>
/// Boundary for a Job-handle retention service. A production implementation
/// must duplicate the handle into an independently supervised service before
/// Retain returns, duplicate it back for Open, authenticate callers, and bind
/// leases to the immutable attempt/generation/process identity held by the
/// execution journal.
/// </summary>
public interface IJobHandleKeeper : IDisposable
{
    bool SurvivesClientRestart { get; }
    void Retain(JobLeaseIdentity identity, SafeFileHandle handle);
    SafeFileHandle Open(JobLeaseIdentity identity);
    void Release(JobLeaseIdentity identity);
}

/// <summary>
/// Test and single-process implementation. It cannot preserve a named Job Object
/// when this process exits. Production implementations must cross an IPC/service
/// boundary and authenticate Retain/Open/Release requests.
/// </summary>
public sealed class InProcessJobHandleKeeper : IJobHandleKeeper
{
    private readonly Dictionary<string, (JobLeaseIdentity Identity, SafeFileHandle Handle)> handles = new(StringComparer.Ordinal);
    private readonly object gate = new();
    public bool SurvivesClientRestart => false;

    public void Retain(JobLeaseIdentity identity, SafeFileHandle handle)
    {
        identity.Validate();
        ArgumentNullException.ThrowIfNull(handle);
        lock (gate)
        {
            if (handles.ContainsKey(identity.JobName)) throw new InvalidOperationException($"Job '{identity.JobName}' is already retained.");
            handles.Add(identity.JobName, (identity, handle));
        }
    }

    public SafeFileHandle Open(JobLeaseIdentity identity)
    {
        identity.Validate();
        lock (gate)
        {
            if (!handles.TryGetValue(identity.JobName, out var lease) || lease.Handle.IsInvalid)
                throw new KeyNotFoundException($"Job '{identity.JobName}' is not retained.");
            if (lease.Identity != identity) throw new UnauthorizedAccessException("Job lease identity mismatch.");
            if (!NativeMethods.DuplicateHandle(NativeMethods.GetCurrentProcess(), lease.Handle, NativeMethods.GetCurrentProcess(),
                    out var duplicate, 0, false, NativeMethods.DuplicateSameAccess))
                NativeMethods.ThrowLastError(nameof(NativeMethods.DuplicateHandle));
            return duplicate;
        }
    }

    public void Release(JobLeaseIdentity identity)
    {
        identity.Validate();
        lock (gate)
        {
            if (!handles.TryGetValue(identity.JobName, out var lease)) return;
            if (lease.Identity != identity) throw new UnauthorizedAccessException("Job lease identity mismatch.");
            handles.Remove(identity.JobName);
            lease.Handle.Dispose();
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            foreach (var lease in handles.Values) lease.Handle.Dispose();
            handles.Clear();
        }
    }
}
