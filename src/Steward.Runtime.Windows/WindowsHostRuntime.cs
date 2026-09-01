using Steward.Tasks.Abstractions;

namespace Steward.Runtime.Windows;

internal sealed class WindowsHostRuntime(IProcessExecutor processes) : IHostRuntime
{
    public HostRuntimeDescriptor Descriptor { get; } = new(
        "windows",
        new Version(1, 0),
        HostRuntimeCapabilities.Process |
        HostRuntimeCapabilities.ResourceControl |
        HostRuntimeCapabilities.BoundedFileOutput |
        HostRuntimeCapabilities.ProcessTreeCancellation |
        HostRuntimeCapabilities.ProcessRecovery);

    public IProcessExecutor Processes { get; } = processes;
}
