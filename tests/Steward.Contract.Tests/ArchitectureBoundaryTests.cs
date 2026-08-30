using System.Xml.Linq;

namespace Steward.Contract.Tests;

public sealed class ArchitectureBoundaryTests
{
    [Fact]
    public void Active_solution_has_no_cloud_infrastructure_projects_or_packages()
    {
        var root = RepositoryRoot();
        var solution = File.ReadAllText(Path.Combine(root, "Steward.slnx"));
        Assert.DoesNotContain("Steward.Relay", solution, StringComparison.Ordinal);
        Assert.DoesNotContain("Steward.IdentityBroker", solution, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "azure-relay-sdk-compatibility", solution, StringComparison.Ordinal);

        var projects = Directory.EnumerateFiles(
            Path.Combine(root, "src"), "*.csproj", SearchOption.AllDirectories);
        foreach (var project in projects)
        {
            var relative = Path.GetRelativePath(root, project);
            var packages = XDocument.Load(project)
                .Descendants("PackageReference")
                .Select(x => (string?)x.Attribute("Include"))
                .Where(x => x is not null)
                .Cast<string>()
                .ToArray();
            Assert.DoesNotContain(packages, package =>
                package.Contains("Relay", StringComparison.OrdinalIgnoreCase) ||
                package.Contains("Storage.Blobs", StringComparison.OrdinalIgnoreCase) ||
                package.Contains("ResourceManager", StringComparison.OrdinalIgnoreCase) ||
                package.Contains("Azure.Provisioning", StringComparison.OrdinalIgnoreCase));
            foreach (var package in packages.Where(x =>
                         x.StartsWith("Azure.", StringComparison.Ordinal)))
            {
                var allowed =
                    relative == Path.Combine(
                        "src", "Steward.Providers.DevBox",
                        "Steward.Providers.DevBox.csproj") &&
                    package == "Azure.Developer.DevCenter" ||
                    relative == Path.Combine(
                        "src", "Steward.DevBox.Windows",
                        "Steward.DevBox.Windows.csproj") &&
                    package is "Azure.Identity" or "Azure.Identity.Broker" ||
                    relative == Path.Combine(
                        "src", "Steward.Rdp.Windows",
                        "Steward.Rdp.Windows.csproj") &&
                    package == "Azure.Core";
                Assert.True(
                    allowed,
                    $"Azure package '{package}' is outside the approved Dev Box boundary in {relative}.");
            }
        }
    }

    [Fact]
    public void Core_projects_do_not_depend_on_local_stack_or_devbox_plugin()
    {
        var root = RepositoryRoot();
        var coreProjects = new[]
        {
            "Steward.Domain",
            "Steward.Contracts",
            "Steward.Application",
            "Steward.Orchestration",
            "Steward.Scheduling",
            "Steward.Transport",
            "Steward.PortableState",
            "Steward.Tasks.Abstractions"
        };
        foreach (var name in coreProjects)
        {
            var project = Path.Combine(root, "src", name, $"{name}.csproj");
            var references = XDocument.Load(project)
                .Descendants("ProjectReference")
                .Select(x => (string?)x.Attribute("Include") ?? string.Empty)
                .ToArray();
            Assert.DoesNotContain(references, reference =>
                reference.Contains("Steward.Stack.Local", StringComparison.Ordinal) ||
                reference.Contains("Steward.Providers.DevBox", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Windows_desktop_is_an_adapter_and_core_has_no_windows_ui_dependency()
    {
        var root = RepositoryRoot();
        var desktopProject = Path.Combine(
            root,
            "src",
            "Steward.Desktop.Windows",
            "Steward.Desktop.Windows.csproj");
        var desktopReferences = XDocument.Load(desktopProject)
            .Descendants("ProjectReference")
            .Select(x => Path.GetFileNameWithoutExtension(
                (string?)x.Attribute("Include") ?? string.Empty))
            .ToArray();
        Assert.Contains("Steward.Control.Client", desktopReferences);
        Assert.Contains("Steward.DevBox.Windows", desktopReferences);
        Assert.Contains("Steward.Transport.Rdp.Windows", desktopReferences);
        Assert.DoesNotContain("Steward.Rdp.Windows", desktopReferences);
        Assert.DoesNotContain("Steward.Persistence.Sqlite", desktopReferences);
        Assert.DoesNotContain(
            Directory.EnumerateFiles(
                Path.GetDirectoryName(desktopProject)!,
                "*.cs",
                SearchOption.AllDirectories)
                .Select(File.ReadAllText),
            source => source.Contains(
                "Microsoft.Data.Sqlite",
                StringComparison.Ordinal));

        var clientProject = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Steward.Control.Client",
            "Steward.Control.Client.csproj"));
        Assert.Contains("<TargetFramework>net10.0</TargetFramework>", clientProject);
        Assert.DoesNotContain("UseWindowsForms", clientProject, StringComparison.Ordinal);

        foreach (var core in new[]
                 {
                     "Steward.Domain",
                     "Steward.Contracts",
                     "Steward.Application"
                 })
        {
            var directory = Path.Combine(root, "src", core);
            foreach (var source in Directory.EnumerateFiles(
                         directory,
                         "*.cs",
                         SearchOption.AllDirectories))
            {
                var text = File.ReadAllText(source);
                Assert.DoesNotContain(
                    "Steward.Desktop.Windows",
                    text,
                    StringComparison.Ordinal);
                Assert.DoesNotContain(
                    "Steward.Rdp.Windows",
                    text,
                    StringComparison.Ordinal);
                Assert.DoesNotContain(
                    "System.Windows.Forms",
                    text,
                    StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Rdp_dvc_transport_is_out_of_process_and_behind_stream_ports()
    {
        var root = RepositoryRoot();
        var clientProject = File.ReadAllText(Path.Combine(
                    root,
                    "src",
                    "Steward.RdpDvc.Client.Windows",
                    "Steward.RdpDvc.Client.Windows.csproj"));
        var serverProject = File.ReadAllText(Path.Combine(
                    root,
                    "src",
                    "Steward.RdpDvc.Server.Windows",
                    "Steward.RdpDvc.Server.Windows.csproj"));
        var adapterProject = XDocument.Load(Path.Combine(
                    root,
                    "src",
                    "Steward.Transport.Rdp.Windows",
                    "Steward.Transport.Rdp.Windows.csproj"));
        Assert.Contains("<OutputType>Exe</OutputType>", clientProject);
        Assert.Contains("<TargetFramework>net10.0-windows</TargetFramework>", clientProject);
        Assert.Contains("<OutputType>Exe</OutputType>", serverProject);
        Assert.Contains("<TargetFramework>net10.0-windows</TargetFramework>", serverProject);
        Assert.Contains(
            adapterProject.Descendants("ProjectReference"),
            reference =>
                ((string?)reference.Attribute("Include") ?? string.Empty)
                .Contains(
                    "Steward.Transport.csproj",
                    StringComparison.Ordinal));

        var dvcSources = new[]
        {
            Path.Combine(root, "src", "Steward.RdpDvc.Client.Windows"),
            Path.Combine(root, "src", "Steward.RdpDvc.Server.Windows"),
            Path.Combine(root, "src", "Steward.Transport.Rdp.Windows")
        }.SelectMany(directory =>
            Directory.EnumerateFiles(
                directory,
                "*.cs",
                SearchOption.AllDirectories))
            .Select(File.ReadAllText)
            .ToArray();
        Assert.DoesNotContain(
            dvcSources,
            source =>
                source.Contains("InprocServer32", StringComparison.Ordinal) ||
                source.Contains("SetWindowsHookEx", StringComparison.Ordinal) ||
                source.Contains("CreateRemoteThread", StringComparison.Ordinal));

        var coreProjectReferences = XDocument.Load(Path.Combine(
                root,
                "src",
                "Steward.Transport",
                "Steward.Transport.csproj"))
            .Descendants("ProjectReference")
            .Select(reference =>
                (string?)reference.Attribute("Include") ?? string.Empty);
        Assert.DoesNotContain(
            coreProjectReferences,
            reference => reference.Contains(
                "Rdp.Windows",
                StringComparison.Ordinal));
    }

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null &&
               !File.Exists(Path.Combine(current.FullName, "Steward.slnx")))
            current = current.Parent;
        return current?.FullName
            ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
