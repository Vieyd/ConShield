using System.Diagnostics;
using ConShield.Cli;

namespace ConShield.Tests;

public sealed class LiveDockerLifecycleWatchTests
{
    [Fact]
    public void WatchValidationRejectsOutOfRangeDurationAndMaxEvents()
    {
        Assert.Throws<CliUsageException>(() => DockerLifecycleWatch.Validate(0, 100));
        Assert.Throws<CliUsageException>(() => DockerLifecycleWatch.Validate(301, 100));
        Assert.Throws<CliUsageException>(() => DockerLifecycleWatch.Validate(30, 0));
        Assert.Throws<CliUsageException>(() => DockerLifecycleWatch.Validate(30, 1001));

        DockerLifecycleWatch.Validate(1, 1);
        DockerLifecycleWatch.Validate(300, 1000);
    }

    [Fact]
    public async Task WatchUnavailablePathIsSafeAndDoesNotRequireDocker()
    {
        var result = await DockerLifecycleWatch.WatchAsync(
            durationSeconds: 1,
            maxEvents: 1,
            dockerCliPath: "conshield-missing-docker-cli-for-tests");

        Assert.False(result.DockerAvailable);
        Assert.Equal(0, result.EventsObserved);
        Assert.Empty(result.Events);
        Assert.Contains("start Docker Desktop", result.Hint, StringComparison.Ordinal);
        Assert.DoesNotContain("CONSHIELD_", result.Hint, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api", result.Hint, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", result.Hint, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LiveDockerJsonLineReusesExistingLifecycleMappingAndSanitization()
    {
        var line = """
            {"Type":"container","Action":"die","Actor":{"ID":"abcdef1234567890","Attributes":{"name":"demo-api","image":"demo/api:latest","exitCode":"137","mount.path":"/var/run/docker.sock","secret":"CONSHIELD_should_not_escape"}},"time":1710000000}
            """;

        var parsed = DockerLifecycleCollector.ParseJsonLine(line);
        var normalized = Assert.Single(DockerLifecycleCollector.Normalize([parsed]));

        Assert.Equal(DockerLifecycleCollector.SourceSystem, normalized.ToIngestRequest().GetType().GetProperty("sourceSystem")?.GetValue(normalized.ToIngestRequest()));
        Assert.Equal(DockerLifecycleEventTypes.AbnormalExit, normalized.EventType);
        Assert.Equal("Warning", normalized.Severity);
        Assert.Equal("abcdef123456", normalized.AdditionalData.ContainerIdShort);
        Assert.Equal("demo-api", normalized.AdditionalData.ContainerName);
        Assert.Equal("demo/api:latest", normalized.AdditionalData.ImageReference);
        Assert.Equal(137, normalized.AdditionalData.ExitCode);
        Assert.NotEqual(Guid.Empty, normalized.ExternalEventId);

        var combined = normalized.Description + " " + normalized.AdditionalData;
        Assert.DoesNotContain("/var/run", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CONSHIELD_", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", combined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CliLifecycleWatchHelpAndValidationAreCiSafe()
    {
        var help = RunCli("lifecycle", "help");

        Assert.Equal(0, help.ExitCode);
        Assert.Contains("lifecycle watch --duration-seconds 30", help.Output, StringComparison.Ordinal);
        Assert.Contains("not required for CI", help.Output, StringComparison.Ordinal);
        AssertSafeOutput(help.Output);

        var invalidDuration = RunCli("lifecycle", "watch", "--duration-seconds", "0", "--no-submit");
        Assert.Equal(2, invalidDuration.ExitCode);
        Assert.Contains("--duration-seconds must be between", invalidDuration.Output, StringComparison.Ordinal);
        AssertSafeOutput(invalidDuration.Output);

        var conflictingSubmitFlags = RunCli("lifecycle", "watch", "--duration-seconds", "1", "--submit", "--no-submit");
        Assert.Equal(2, conflictingSubmitFlags.ExitCode);
        Assert.Contains("Use either --submit or --no-submit", conflictingSubmitFlags.Output, StringComparison.Ordinal);
        AssertSafeOutput(conflictingSubmitFlags.Output);
    }

    [Fact]
    public void DocsDashboardAndDemoMarkLiveWatchOptionalAndReadOnly()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "DOCKER_LIFECYCLE_COLLECTOR.md"),
            ReadRepoFile("docs", "CONSHIELD_CLI.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"));

        foreach (var expected in new[]
        {
            "lifecycle watch",
            "--duration-seconds 30",
            "--no-submit",
            "--submit",
            "Optional manual",
            "not required",
            "Docker Desktop",
            "Web UI does not execute Docker commands",
            "read-only copy/paste"
        })
        {
            Assert.Contains(expected, combined, StringComparison.OrdinalIgnoreCase);
        }

        var webSource = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"));

        Assert.DoesNotContain("Process.Start", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PowerShell.Create", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("UseShellExecute", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("method=\"post\"", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fetch(", webSource, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FullValidationRemainsOfflineAndDoesNotRunLifecycleWatch()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldFullValidation.ps1");

        Assert.Contains("lifecycle watch", script, StringComparison.Ordinal);
        Assert.Contains("lifecycle replay", script, StringComparison.Ordinal);
        Assert.DoesNotContain("'watch'", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"watch\"", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("docker events", script, StringComparison.OrdinalIgnoreCase);
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

    private static void AssertSafeOutput(string output)
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
