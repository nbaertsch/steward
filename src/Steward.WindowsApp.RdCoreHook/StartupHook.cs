using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

public static class StartupHook
{
    private static nint shimModule;
    private static PluginLoadContext? pluginLoadContext;
    private const string AssemblyName =
        "Microsoft.CloudManagedDesktop.Clients.NxtClient.RDCore";
    private const string ConfigurationType =
        "Microsoft.CloudManagedDesktop.Clients.NxtClient.RDCore.Configuration.RdpConfiguration";

    public static void Initialize()
    {
        if (!string.Equals(
                Path.GetFileName(Environment.ProcessPath),
                "Windows365.exe",
                StringComparison.OrdinalIgnoreCase))
            return;
        var assembly = Assembly.Load(AssemblyName);
        var type = assembly.GetType(
            ConfigurationType,
            throwOnError: true,
            ignoreCase: false)!;
        var target = type.GetMethod(
            "ConfigurePlugins",
            BindingFlags.Instance | BindingFlags.Public) ??
            throw new MissingMethodException(
                ConfigurationType,
                "ConfigurePlugins");
        var postfix = typeof(StartupHook).GetMethod(
            nameof(EnableStewardPlugin),
            BindingFlags.Static | BindingFlags.NonPublic) ??
            throw new MissingMethodException(
                nameof(StartupHook),
                nameof(EnableStewardPlugin));
        var harmonyPath = Environment.GetEnvironmentVariable(
            "STEWARD_RDCORE_HARMONY_PATH");
        if (string.IsNullOrWhiteSpace(harmonyPath) ||
            !Path.IsPathFullyQualified(harmonyPath) ||
            !File.Exists(harmonyPath) ||
            File.GetAttributes(harmonyPath)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException(
                "The Steward RDCore instrumentation dependency is invalid.");
        var harmonyAssembly = Assembly.LoadFrom(
            Path.GetFullPath(harmonyPath));
        var harmonyType = harmonyAssembly.GetType(
            "HarmonyLib.Harmony",
            throwOnError: true)!;
        var harmonyMethodType = harmonyAssembly.GetType(
            "HarmonyLib.HarmonyMethod",
            throwOnError: true)!;
        var harmony = Activator.CreateInstance(
            harmonyType,
            "dev.steward.windowsapp.rdcore") ??
            throw new InvalidOperationException(
                "Harmony initialization failed.");
        var harmonyPostfix = Activator.CreateInstance(
            harmonyMethodType,
            postfix) ??
            throw new InvalidOperationException(
                "Harmony postfix initialization failed.");
        var patch = harmonyType.GetMethods(
                BindingFlags.Instance | BindingFlags.Public)
            .Single(method =>
                method.Name == "Patch" &&
                method.GetParameters().Length == 5);
        patch.Invoke(
            harmony,
            [target, null, harmonyPostfix, null, null]);

        var commonAssembly = Assembly.Load(
            "Microsoft.CloudManagedDesktop.Clients.NxtClient.Common");
        var resolverType = commonAssembly.GetType(
            "Microsoft.CloudManagedDesktop.Clients.NxtClient.Common.FeatureEnablement.FeatureEnablementResolver",
            throwOnError: true)!;
        var capabilityType = commonAssembly.GetType(
            "Microsoft.CloudManagedDesktop.Clients.NxtClient.Common.FeatureEnablement.RuntimeCapability",
            throwOnError: true)!;
        var capabilityTarget = resolverType.GetMethod(
            "IsCapabilityPresent",
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            [capabilityType],
            modifiers: null) ??
            throw new MissingMethodException(
                resolverType.FullName,
                "IsCapabilityPresent");
        var capabilityPrefix = typeof(StartupHook).GetMethod(
            nameof(EnableLoadThirdPartyPluginsCapability),
            BindingFlags.Static | BindingFlags.NonPublic) ??
            throw new MissingMethodException(
                nameof(StartupHook),
                nameof(EnableLoadThirdPartyPluginsCapability));
        var harmonyPrefix = Activator.CreateInstance(
            harmonyMethodType,
            capabilityPrefix) ??
            throw new InvalidOperationException(
                "Harmony prefix initialization failed.");
        patch.Invoke(
            harmony,
            [capabilityTarget, harmonyPrefix, null, null, null]);
        Record("initialized");
    }

    private static void EnableStewardPlugin(object connection)
    {
        var settings = connection.GetType()
            .GetProperty(
                "ConnectionSettings",
                BindingFlags.Instance | BindingFlags.Public)
            ?.GetValue(connection) ??
            throw new MissingMemberException(
                connection.GetType().FullName,
                "ConnectionSettings");
        var property = settings.GetType().GetProperty(
            "AllowThirdPartyPlugins",
            BindingFlags.Instance | BindingFlags.Public) ??
            throw new MissingMemberException(
                settings.GetType().FullName,
                "AllowThirdPartyPlugins");
        property.SetValue(settings, true);
        if (property.GetValue(settings) is not true)
            throw new InvalidOperationException(
                "RDCore rejected Steward third-party plugin activation.");
        var firstPartyProperty = settings.GetType().GetProperty(
            "FirstPartyDVCPlugins",
            BindingFlags.Instance | BindingFlags.Public) ??
            throw new MissingMemberException(
                settings.GetType().FullName,
                "FirstPartyDVCPlugins");
        var firstParty = firstPartyProperty.GetValue(settings) as string ??
            string.Empty;
        var shimPath = Environment.GetEnvironmentVariable(
            "STEWARD_RDCORE_SHIM_PATH");
        if (string.IsNullOrWhiteSpace(shimPath) ||
            !Path.IsPathFullyQualified(shimPath) ||
            !File.Exists(shimPath) ||
            File.GetAttributes(shimPath)
                .HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException(
                "The Steward RDCore DVC shim is invalid.");
        shimPath = Path.GetFullPath(shimPath);
        if (shimModule == 0)
        {
            shimModule = NativeLibrary.Load(shimPath);
            Record("shim-loaded");
        }
        try
        {
            InstallManagedPlugin(shimPath);
        }
        catch (Exception exception)
        {
            var root = exception is TargetInvocationException
            {
                InnerException: { } inner
            }
                ? inner
                : exception;
            Record(
                "managed-plugin-failed-" +
                root.GetType().Name +
                (root is FileNotFoundException
                {
                    FileName: { Length: > 0 } fileName
                }
                    ? "-" + new AssemblyName(fileName).Name
                    : root is FileLoadException
                    {
                        FileName: { Length: > 0 } loadedFile
                    }
                    ? "-" + new AssemblyName(loadedFile).Name
                    : string.Empty));
            throw;
        }
        if (!firstParty.Split(
                ',',
                StringSplitOptions.RemoveEmptyEntries |
                StringSplitOptions.TrimEntries)
            .Contains(
                shimPath,
                StringComparer.OrdinalIgnoreCase))
            firstPartyProperty.SetValue(
                settings,
                string.IsNullOrEmpty(firstParty)
                    ? shimPath
                    : firstParty + "," + shimPath);
        Record("plugins-enabled");
    }

    private static void InstallManagedPlugin(string shimPath)
    {
        var hostPath = Environment.GetEnvironmentVariable(
            "STEWARD_RDCORE_MANAGED_PLUGIN_PATH");
        if (string.IsNullOrWhiteSpace(hostPath) ||
            !Path.IsPathFullyQualified(hostPath) ||
            !File.Exists(hostPath))
            throw new InvalidOperationException(
                "The Steward managed DVC host is unavailable.");
        hostPath = Path.GetFullPath(hostPath);
        pluginLoadContext ??= new PluginLoadContext(hostPath);
        var assembly = pluginLoadContext.LoadFromAssemblyPath(hostPath);
        var factory = assembly.GetType(
                "Steward.RdpDvc.Client.Windows.EmbeddedDvcPluginHost",
                throwOnError: true)!
            .GetMethod(
                "Start",
                BindingFlags.Static | BindingFlags.Public) ??
            throw new MissingMethodException(
                "EmbeddedDvcPluginHost",
                "Start");
        var plugin = factory.Invoke(null, null) ??
            throw new InvalidOperationException(
                "The Steward managed DVC host returned no plug-in.");
        var pointer = Marshal.GetIUnknownForObject(plugin);
        try
        {
            var export = NativeLibrary.GetExport(
                shimModule,
                "StewardSetPluginInstance");
            var setter =
                Marshal.GetDelegateForFunctionPointer<PluginSetter>(export);
            setter(pointer);
        }
        finally
        {
            Marshal.Release(pointer);
        }
        Record("managed-plugin-installed");
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void PluginSetter(nint instance);

    private sealed class PluginLoadContext(string hostPath) :
        AssemblyLoadContext(
            "Steward.RdpDvc.Embedded",
            isCollectible: false)
    {
        private readonly AssemblyDependencyResolver resolver =
            new(hostPath);

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            var path = resolver.ResolveAssemblyToPath(assemblyName);
            return path is null
                ? null
                : LoadFromAssemblyPath(path);
        }

        protected override nint LoadUnmanagedDll(string name)
        {
            var path = resolver.ResolveUnmanagedDllToPath(name);
            return path is null
                ? 0
                : LoadUnmanagedDllFromPath(path);
        }
    }

    private static bool EnableLoadThirdPartyPluginsCapability(
        object capability,
        ref bool __result)
    {
        if (!string.Equals(
                capability.ToString(),
                "Load3PPlugins",
                StringComparison.Ordinal))
            return true;
        __result = true;
        Record("load3p-capability-enabled");
        return false;
    }

    private static void Record(string stage)
    {
        var path = Environment.GetEnvironmentVariable(
            "STEWARD_RDCORE_HOOK_EVIDENCE_PATH");
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException(
                "The Steward RDCore hook evidence path is invalid.");
        File.AppendAllText(
            Path.GetFullPath(path),
            stage + Environment.NewLine);
    }
}
