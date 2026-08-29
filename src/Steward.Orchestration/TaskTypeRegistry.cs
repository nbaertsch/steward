using Steward.Tasks.Abstractions;

namespace Steward.Orchestration;

public interface ITaskTypeRegistry
{
    ITaskType Resolve(string name, string version);
}

public sealed class TaskTypeRegistry : ITaskTypeRegistry
{
    private readonly IReadOnlyDictionary<(string Name, string Version), ITaskType> types;

    public TaskTypeRegistry(IEnumerable<ITaskType> taskTypes)
    {
        ArgumentNullException.ThrowIfNull(taskTypes);
        var entries = taskTypes.Select(x => (
            Key: (x.Type.Name, x.Type.Version.ToString()),
            Value: x)).ToArray();
        if (entries.Length == 0)
            throw new ArgumentException("At least one TaskType must be registered.", nameof(taskTypes));
        if (entries.Any(x => string.IsNullOrWhiteSpace(x.Key.Name)) ||
            entries.Select(x => x.Key).Distinct().Count() != entries.Length)
            throw new ArgumentException("TaskType name/version registrations must be unique.", nameof(taskTypes));
        types = entries.ToDictionary(x => x.Key, x => x.Value);
    }

    public ITaskType Resolve(string name, string version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        return types.TryGetValue((name, version), out var taskType)
            ? taskType
            : throw new KeyNotFoundException($"TaskType '{name}/{version}' is not registered.");
    }
}
