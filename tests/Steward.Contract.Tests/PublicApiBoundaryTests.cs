using System.Reflection;
using System.Text.Json;

namespace Steward.Contract.Tests;

public sealed class PublicApiBoundaryTests
{
    private static readonly string[] ForbiddenPropertyNames =
    [
        "Command",
        "Arguments",
        "Executable",
        "ExecutablePath",
        "Environment",
        "Script",
        "Shell"
    ];

    [Fact]
    public void Production_public_APIs_are_strongly_typed()
    {
        var violations = ProductionAssemblies()
            .SelectMany(FindUnsafePublicApi)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            violations.Length == 0,
            "Unsafe production public APIs:" + Environment.NewLine +
            string.Join(Environment.NewLine, violations));
    }

    [Fact]
    public void Privileged_contracts_have_no_generic_execution_surface()
    {
        var guardedAssemblies = new HashSet<string>(StringComparer.Ordinal)
        {
            "Steward.Maintenance.Windows",
            "Steward.Runtime.Windows",
            "Steward.Tasks.Abstractions",
            "Steward.Tasks.Agent",
            "Steward.Tasks.Compose",
            "Steward.Tasks.Process",
            "Steward.Workloads.Evals"
        };
        var violations = ProductionAssemblies()
            .Where(assembly => guardedAssemblies.Contains(
                assembly.GetName().Name!))
            .SelectMany(assembly => assembly.GetExportedTypes())
            .SelectMany(type => type.GetProperties(
                BindingFlags.Public |
                BindingFlags.Instance |
                BindingFlags.Static |
                BindingFlags.DeclaredOnly))
            .Where(property => ForbiddenPropertyNames.Contains(
                property.Name,
                StringComparer.OrdinalIgnoreCase) &&
                IsGenericExecutionType(property.PropertyType))
            .Select(property => $"{property.DeclaringType!.FullName}.{property.Name}")
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            violations.Length == 0,
            "Generic privileged or task-adapter execution APIs:" + Environment.NewLine +
            string.Join(Environment.NewLine, violations));
    }

    private static IEnumerable<string> FindUnsafePublicApi(Assembly assembly)
    {
        foreach (var type in assembly.GetExportedTypes())
        {
            const BindingFlags flags = BindingFlags.Public |
                                       BindingFlags.NonPublic |
                                       BindingFlags.Instance |
                                       BindingFlags.Static |
                                       BindingFlags.DeclaredOnly;
            foreach (var property in type.GetProperties(flags))
            {
                if (IsExternallyVisible(property.GetMethod) ||
                    IsExternallyVisible(property.SetMethod))
                {
                    if (IsUnsafe(property.PropertyType))
                        yield return $"{assembly.GetName().Name}: property {type.FullName}.{property.Name}: {property.PropertyType}";
                }
            }
            foreach (var field in type.GetFields(flags))
            {
                if (IsExternallyVisible(field) && IsUnsafe(field.FieldType))
                    yield return $"{assembly.GetName().Name}: field {type.FullName}.{field.Name}: {field.FieldType}";
            }
            foreach (var constructor in type.GetConstructors(flags))
            {
                if (!IsExternallyVisible(constructor))
                    continue;
                foreach (var parameter in constructor.GetParameters().Where(
                             parameter => IsUnsafe(parameter.ParameterType)))
                    yield return $"{assembly.GetName().Name}: constructor {type.FullName}({parameter.Name}): {parameter.ParameterType}";
            }
            foreach (var method in type.GetMethods(flags))
            {
                if (!IsExternallyVisible(method) || method.IsSpecialName ||
                    IsClrObjectOverride(method))
                    continue;
                if (IsUnsafe(method.ReturnType))
                    yield return $"{assembly.GetName().Name}: return {type.FullName}.{method.Name}: {method.ReturnType}";
                foreach (var parameter in method.GetParameters().Where(
                             parameter => IsUnsafe(parameter.ParameterType)))
                    yield return $"{assembly.GetName().Name}: parameter {type.FullName}.{method.Name}({parameter.Name}): {parameter.ParameterType}";
            }
        }
    }

    private static bool IsGenericExecutionType(Type type) =>
        type == typeof(string) ||
        type.IsArray && type.GetElementType() == typeof(string) ||
        type.IsGenericType && type.GetGenericArguments().Any(
            argument => argument == typeof(string));
    private static bool IsUnsafe(Type type)
    {
        if (type == typeof(object) ||
            type == typeof(System.Collections.IDictionary) ||
            type == typeof(System.Collections.Hashtable) ||
            type == typeof(JsonElement) ||
            type == typeof(JsonDocument) ||
            type == typeof(System.Text.Json.Nodes.JsonNode) ||
            type == typeof(System.Text.Json.Nodes.JsonObject) ||
            type == typeof(System.Text.Json.Nodes.JsonArray) ||
            type.Namespace is "System.Reflection" or
                "System.Runtime.InteropServices.ComTypes")
            return true;
        if (type.HasElementType)
            return IsUnsafe(type.GetElementType()!);
        return type.IsGenericType && type.GetGenericArguments().Any(IsUnsafe);
    }

    private static bool IsClrObjectOverride(MethodInfo method) =>
        method.Name == nameof(Equals) &&
        method.GetBaseDefinition().DeclaringType == typeof(object);

    private static bool IsExternallyVisible(MethodBase? method) =>
        method is not null &&
        (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly);

    private static bool IsExternallyVisible(FieldInfo field) =>
        field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly;

    private static IReadOnlyList<Assembly> ProductionAssemblies()
    {
        var root = RepositoryRoot();
        return Directory.EnumerateFiles(
                Path.Combine(root, "src"),
                "*.csproj",
                SearchOption.AllDirectories)
            .Select(Path.GetFileNameWithoutExtension)
            .Where(name => name is not null)
            .Select(name => Assembly.Load(new AssemblyName(name!)))
            .OrderBy(assembly => assembly.GetName().Name, StringComparer.Ordinal)
            .ToArray();
    }

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null &&
               !File.Exists(Path.Combine(current.FullName, "Steward.slnx")))
            current = current.Parent;
        return current?.FullName ??
               throw new DirectoryNotFoundException("Repository root not found.");
    }
}
