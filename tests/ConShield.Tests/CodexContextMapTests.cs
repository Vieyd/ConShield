namespace ConShield.Tests;

public sealed class CodexContextMapTests
{
    [Fact]
    public void ConShieldCodemap_ExistsAndMentionsMajorAreas()
    {
        var text = ReadRepositoryFile("docs", "CONSHIELD_CODEMAP.md");

        Assert.Contains("src/ConShield.Web", text, StringComparison.Ordinal);
        Assert.Contains("src/ConShield.Data", text, StringComparison.Ordinal);
        Assert.Contains("ConShield.EventConsumer", text, StringComparison.Ordinal);
        Assert.Contains("RabbitMQ", text, StringComparison.Ordinal);
        Assert.Contains("Mongo", text, StringComparison.Ordinal);
        Assert.Contains("deploy/falco-linux", text, StringComparison.Ordinal);
        Assert.Contains("tests/ConShield.Tests", text, StringComparison.Ordinal);
    }

    [Fact]
    public void CodexWorkflows_ExistsAndDefinesTaskWorkflows()
    {
        var text = ReadRepositoryFile("docs", "CODEX_WORKFLOWS.md");

        Assert.Contains("UI task workflow", text, StringComparison.Ordinal);
        Assert.Contains("SIEM workflow", text, StringComparison.Ordinal);
        Assert.Contains("Outbox/RabbitMQ workflow", text, StringComparison.Ordinal);
        Assert.Contains("Fedora/runtime workflow", text, StringComparison.Ordinal);
        Assert.Contains("Validation matrix", text, StringComparison.Ordinal);
    }

    [Fact]
    public void ContextMaps_DoNotContainSecrets()
    {
        var combined = string.Join(
            "\n",
            ReadRepositoryFile("docs", "CONSHIELD_CODEMAP.md"),
            ReadRepositoryFile("docs", "CODEX_WORKFLOWS.md"));

        var forbiddenFragments = new[]
        {
            "Host=127.0.0.1;Port=5432",
            "Host=localhost;Port=5432",
            "Password=",
            "ApiKey=",
            "X-ConShield-Api-Key:",
            "Bearer ",
            "CONSHIELD_EXTERNAL_EVENT_API_KEY=",
            "CONSHIELD_RUNTIME_COLLECTOR_API_KEY=",
            "SensorCredentialSecret=",
            "VerifierHash=",
            "CredentialVerifierHash=",
            "BEGIN PRIVATE KEY"
        };

        foreach (var fragment in forbiddenFragments)
        {
            Assert.DoesNotContain(fragment, combined, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ReadmeMentionsCodexContextMaps()
    {
        var readme = ReadRepositoryFile("README.md");

        Assert.Contains("docs/CONSHIELD_CODEMAP.md", readme, StringComparison.Ordinal);
        Assert.Contains("docs/CODEX_WORKFLOWS.md", readme, StringComparison.Ordinal);
    }

    private static string ReadRepositoryFile(params string[] relativePathParts)
    {
        var root = LocateRepositoryRoot();
        var path = Path.Combine(new[] { root }.Concat(relativePathParts).ToArray());

        Assert.True(File.Exists(path), $"Expected repository file to exist: {path}");
        return File.ReadAllText(path);
    }

    private static string LocateRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("Could not locate repository root.");
    }
}
