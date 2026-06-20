using ConShield.RuntimeCollector;

namespace ConShield.Tests;

public class RuntimeCollectorTests
{
    [Fact]
    public void RuntimeCollector_UsesDedicatedEndpointEnvironmentVariable()
    {
        var previous = Environment.GetEnvironmentVariable("CONSHIELD_ENDPOINT");
        try
        {
            Environment.SetEnvironmentVariable("CONSHIELD_ENDPOINT", "http://192.168.54.1:5080/api/v1/security-events");
            var result = CommandLineParser.Parse(["collect", "--stdin", "--mapping", MappingPath()]);

            Assert.True(result.IsValid);
            Assert.Equal("http://192.168.54.1:5080/api/v1/security-events", result.Options!.Endpoint);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CONSHIELD_ENDPOINT", previous);
        }
    }

    [Fact]
    public void RuntimeCollector_InvalidArgs_AreRejected()
    {
        Assert.False(CommandLineParser.Parse(["collect", "--stdin", "--file", "x", "--mapping", "config/runtime/falco-mapping-v1.json", "--no-submit"]).IsValid);
        Assert.False(CommandLineParser.Parse(["collect", "--stdin", "--mapping", "config/runtime/falco-mapping-v1.json", "--unknown"]).IsValid);
        Assert.False(CommandLineParser.Parse(["collect", "--stdin", "--mapping=config/runtime/falco-mapping-v1.json"]).IsValid);
    }

    [Fact]
    public async Task RuntimeCollector_StdinNoSubmit_ProcessesValidAndMalformedLines()
    {
        var input = """
        {"time":"2026-06-18T10:00:00Z","rule":"Terminal shell in container","priority":"Critical","output":"demo","hostname":"runtime-node","source":"syscall","tags":["container"],"output_fields":{"container.id":"demo","proc.name":"sh","evt.type":"execve"}}
        {"time":
        """;
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var code = await RuntimeCollectorApp.RunAsync(
            ["collect", "--stdin", "--mapping", MappingPath(), "--no-submit"],
            new StringReader(input),
            stdout,
            stderr,
            CancellationToken.None);

        Assert.Equal(RuntimeCollectorExitCode.PartialFailure, code);
        Assert.Contains("parsed=1", stdout.ToString());
        Assert.DoesNotContain("demo", stdout.ToString());
    }

    [Fact]
    public async Task RuntimeCollector_FileNoSubmit_SucceedsForDemoSample()
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var code = await RuntimeCollectorApp.RunAsync(
            ["collect", "--file", SamplePath(), "--mapping", MappingPath(), "--no-submit"],
            TextReader.Null,
            stdout,
            stderr,
            CancellationToken.None);

        Assert.Equal(RuntimeCollectorExitCode.Success, code);
        Assert.Contains("parsed=4", stdout.ToString());
        Assert.Contains("unmapped=1", stdout.ToString());
    }

    private static string MappingPath() => Path.Combine(FindRepoRoot(), "config", "runtime", "falco-mapping-v1.json");
    private static string SamplePath() => Path.Combine(FindRepoRoot(), "samples", "falco", "runtime-demo.jsonl");

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
    }
}
