using System.Runtime.InteropServices;
using Microsoft.NET.HostModel.AppHost;
using Microsoft.NET.HostModel.Bundle;

// Trusted fixture generator only. Generated hosts are inspected, never executed.
if (args.Length != 2) throw new ArgumentException("Expected apphost template and absent output directory");
var template = Path.GetFullPath(args[0]);
var output = Path.GetFullPath(args[1]);
if (Directory.Exists(output)) throw new IOException("Output directory must be absent");
Directory.CreateDirectory(output);
var assembly = typeof(Program).Assembly.Location;
var resource = Path.Combine(output, "resource.txt");
File.WriteAllText(resource, string.Concat(Enumerable.Repeat("owned compressed fixture content\n", 4096)));
foreach (var (version, compress) in new[] { (new Version(3, 1), false), (new Version(5, 0), false), (new Version(8, 0), false), (new Version(8, 0), true) })
{
    var label = $"net{version.Major}-{(compress ? "compressed" : "plain")}";
    var directory = Path.Combine(output, label);
    Directory.CreateDirectory(directory);
    var host = Path.Combine(directory, "template.exe");
    HostWriter.CreateAppHost(template, host, "BundleFixture.dll");
    var bundler = new Bundler("Probe.exe", directory,
        BundleOptions.BundleOtherFiles | (compress ? BundleOptions.EnableCompression : BundleOptions.None),
        OSPlatform.Windows, Architecture.X64, version, appAssemblyName: "BundleFixture");
    Console.WriteLine(bundler.GenerateBundle(new[] {
        new FileSpec(host, "Probe.exe"),
        new FileSpec(assembly, "BundleFixture.dll"),
        new FileSpec(Path.ChangeExtension(assembly, ".deps.json"), "BundleFixture.deps.json"),
        new FileSpec(Path.ChangeExtension(assembly, ".runtimeconfig.json"), "BundleFixture.runtimeconfig.json"),
        new FileSpec(resource, "data/resource.txt"),
    }));
}
