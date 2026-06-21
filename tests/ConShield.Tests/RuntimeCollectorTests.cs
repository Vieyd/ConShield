using ConShield.RuntimeCollector;
using System.Text;

namespace ConShield.Tests;

public class RuntimeCollectorTests
{
    [Fact]
    public async Task BoundedReader_AcceptsExactLimit_AndDrainsOversizedLine()
    {
        const int limit = 32;
        var valid = new string('a', limit);
        var input = $"{valid}\n{new string('b', 100_000)}\nnext\n";
        var options = new RuntimeCollectorOptions { Stdin = true, MaxLineBytes = limit };
        var lines = new List<byte[]>();

        await foreach (var line in BoundedRuntimeLineReader.ReadAsync(options, new StringReader(input), CancellationToken.None))
            lines.Add(line);

        Assert.Equal(3, lines.Count);
        Assert.Equal(valid, Encoding.UTF8.GetString(lines[0]));
        Assert.Equal(limit + 1, lines[1].Length);
        Assert.Equal("next", Encoding.UTF8.GetString(lines[2]));
    }

    [Fact]
    public async Task FollowReader_EmitsExistingAndAppendedLinesOnce()
    {
        var path = Path.GetTempFileName();
        await File.WriteAllTextAsync(path, "one\n");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        var options = new RuntimeCollectorOptions { FilePath = path, Follow = true, MaxLineBytes = 1024 };
        await using var reader = BoundedRuntimeLineReader.ReadAsync(options, TextReader.Null, cancellation.Token)
            .GetAsyncEnumerator(cancellation.Token);

        try
        {
            Assert.True(await reader.MoveNextAsync());
            Assert.Equal("one", Encoding.UTF8.GetString(reader.Current));
            await File.AppendAllTextAsync(path, "two\n");
            Assert.True(await reader.MoveNextAsync());
            Assert.Equal("two", Encoding.UTF8.GetString(reader.Current));

            var pending = reader.MoveNextAsync().AsTask();
            await Task.Delay(1200);
            Assert.False(pending.IsCompleted, "Follow mode reread an existing line without an append.");
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task FollowReader_ResetsAfterTruncate()
    {
        var path = Path.GetTempFileName();
        await File.WriteAllTextAsync(path, "first-line\n");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        var options = new RuntimeCollectorOptions { FilePath = path, Follow = true, MaxLineBytes = 1024 };
        await using var reader = BoundedRuntimeLineReader.ReadAsync(options, TextReader.Null, cancellation.Token)
            .GetAsyncEnumerator(cancellation.Token);

        try
        {
            Assert.True(await reader.MoveNextAsync());
            Assert.Equal("first-line", Encoding.UTF8.GetString(reader.Current));
            await Task.Delay(50);
            await File.WriteAllTextAsync(path, "new\n");
            Assert.True(await reader.MoveNextAsync());
            Assert.Equal("new", Encoding.UTF8.GetString(reader.Current));
        }
        finally
        {
            File.Delete(path);
        }
    }

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
            Assert.Equal("CONSHIELD_RUNTIME_COLLECTOR_API_KEY", result.Options.ApiKeyEnv);
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
