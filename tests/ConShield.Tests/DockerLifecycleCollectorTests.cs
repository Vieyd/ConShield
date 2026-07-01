using System.Diagnostics;
using ConShield.Cli;

namespace ConShield.Tests;

public sealed class DockerLifecycleCollectorTests
{
    [Fact]
    public void FixturesAreCommittedAndDoNotContainSensitiveDockerFields()
    {
        foreach (var relativePath in new[]
        {
            Path.Combine("tests", "TestData", "DockerEvents", "container-lifecycle-events.json"),
            Path.Combine("tests", "TestData", "DockerEvents", "container-lifecycle-suspicious-events.json")
        })
        {
            var content = ReadRepoFile(relativePath);

            Assert.Contains("\"Type\"", content, StringComparison.Ordinal);
            Assert.Contains("\"Action\"", content, StringComparison.Ordinal);
            Assert.DoesNotContain("\"Mounts\"", content, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("\"Env\"", content, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("CONSHIELD_", content, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Password", content, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("api_key", content, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("/home/", content, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("/var/run/", content, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void LifecycleFixtureNoSubmitSucceedsWithoutLiveDockerOrWeb()
    {
        var result = RunCli(
            "lifecycle",
            "replay",
            "--from-docker-events-json",
            @".\tests\TestData\DockerEvents\container-lifecycle-events.json",
            "--no-submit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Command: lifecycle replay", result.Output, StringComparison.Ordinal);
        Assert.Contains("SourceSystem: conshield.docker-lifecycle-collector", result.Output, StringComparison.Ordinal);
        Assert.Contains("container.lifecycle.created", result.Output, StringComparison.Ordinal);
        Assert.Contains("container.lifecycle.started", result.Output, StringComparison.Ordinal);
        Assert.Contains("container.lifecycle.abnormal_exit", result.Output, StringComparison.Ordinal);
        Assert.Contains("Ingestion: SKIP", result.Output, StringComparison.Ordinal);
        Assert.Contains("Expected rules: LIFE-001,LIFE-002 unaffected", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeCliOutput(result.Output);
    }

    [Fact]
    public void LifecycleFixtureMapsExpectedEventTypes()
    {
        var events = DockerLifecycleCollector.Normalize(
            DockerLifecycleCollector.ParseFixture(Path.Combine(RepoRoot(), "tests", "TestData", "DockerEvents", "container-lifecycle-events.json")));

        Assert.Equal(4, events.Count);
        Assert.Equal(DockerLifecycleCollector.SourceSystem, "conshield.docker-lifecycle-collector");
        Assert.Contains(events, x => x.EventType == DockerLifecycleEventTypes.Created);
        Assert.Contains(events, x => x.EventType == DockerLifecycleEventTypes.Started);
        Assert.Contains(events, x => x.EventType == DockerLifecycleEventTypes.AbnormalExit);
        Assert.Contains(events, x => x.EventType == DockerLifecycleEventTypes.Destroyed);
        Assert.All(events, x =>
        {
            Assert.NotEqual(Guid.Empty, x.ExternalEventId);
            Assert.DoesNotContain("/home/", x.Description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("/var/run/", x.Description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Password=", x.Description, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void SuspiciousLifecycleFixtureMapsWarningEventTypes()
    {
        var events = DockerLifecycleCollector.Normalize(
            DockerLifecycleCollector.ParseFixture(Path.Combine(RepoRoot(), "tests", "TestData", "DockerEvents", "container-lifecycle-suspicious-events.json")));

        Assert.Equal(3, events.Count);
        Assert.Contains(events, x => x.EventType == DockerLifecycleEventTypes.AbnormalExit);
        Assert.Contains(events, x => x.EventType == DockerLifecycleEventTypes.ExecStarted);
        Assert.All(events, x => Assert.Equal("Warning", x.Severity));
    }

    [Fact]
    public void LifecycleExternalEventIdsAreStableForSameFixture()
    {
        var fixturePath = Path.Combine(RepoRoot(), "tests", "TestData", "DockerEvents", "container-lifecycle-events.json");
        var first = DockerLifecycleCollector.Normalize(DockerLifecycleCollector.ParseFixture(fixturePath));
        var second = DockerLifecycleCollector.Normalize(DockerLifecycleCollector.ParseFixture(fixturePath));

        Assert.Equal(
            first.Select(x => x.ExternalEventId).ToArray(),
            second.Select(x => x.ExternalEventId).ToArray());
    }

    [Fact]
    public void InvalidLifecycleFixtureFailsClosedWithSafeMessage()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), "conshield-invalid-docker-events.json");
        File.WriteAllText(tempPath, "{ invalid docker event json }");

        try
        {
            var ex = Assert.Throws<DockerLifecycleException>(() => DockerLifecycleCollector.ParseFixture(tempPath));

            Assert.Equal("Docker events fixture is not valid JSON.", ex.Message);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    [Fact]
    public void EvidenceReadinessDemoAndDocsMentionDockerLifecycleCollector()
    {
        var combined = string.Join(
            "\n",
            ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1"),
            ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("docs", "CONSHIELD_CLI.md"),
            ReadRepoFile("docs", "DOCKER_LIFECYCLE_COLLECTOR.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("README.md"));

        foreach (var expected in new[]
        {
            "Docker Lifecycle Collector Evidence",
            "conshield.docker-lifecycle-collector",
            "container.lifecycle.",
            "dotnet run --project .\\src\\ConShield.Cli -- lifecycle replay",
            ".\\tests\\TestData\\DockerEvents\\container-lifecycle-events.json",
            "Docker lifecycle collector fixture"
        })
        {
            Assert.Contains(expected, combined, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN CERTIFICATE-----", combined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SiemLifecycleRulesRemainConfigured()
    {
        var siemRules = ReadRepoFile("config", "siem-rules.default.json");

        Assert.Contains("\"LIFE-001\"", siemRules, StringComparison.Ordinal);
        Assert.Contains("\"LIFE-002\"", siemRules, StringComparison.Ordinal);
    }

    private static CommandResult RunCli(params string[] arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = RepoRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        psi.ArgumentList.Add("run");
        psi.ArgumentList.Add("--no-build");
        psi.ArgumentList.Add("--configuration");
        psi.ArgumentList.Add("Release");
        psi.ArgumentList.Add("--project");
        psi.ArgumentList.Add(@".\src\ConShield.Cli");
        psi.ArgumentList.Add("--");

        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);

        var result = TestProcessRunner.Run(psi, TimeSpan.FromSeconds(60));
        return new CommandResult(result.ExitCode, result.Output);
    }

    private static string ReadRepoFile(params string[] parts) =>
        File.ReadAllText(Path.Combine(new[] { RepoRoot() }.Concat(parts).ToArray()));

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }

    private static void AssertSafeCliOutput(string output)
    {
        foreach (var marker in new[]
        {
            "AdditionalDataJson",
            "PayloadJson",
            "\"Mounts\"",
            "\"Env\"",
            "CONSHIELD_",
            "api_key",
            "connection string",
            "Password=",
            "Docker logs",
            "/home/",
            "/var/run/",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----",
            "signing key"
        })
        {
            Assert.DoesNotContain(marker, output, StringComparison.OrdinalIgnoreCase);
        }
    }

    private sealed record CommandResult(int ExitCode, string Output);
}
