namespace ConShield.Tests;

public sealed class FalcoRuntimeSensorPathTests
{
    [Fact]
    public void ReplayScript_UsesSafeFixturesAndDoesNotPrintSecretValues()
    {
        var script = ReadRepoFile("scripts", "Replay-ConShieldFalcoRuntimeEvent.ps1");

        Assert.Contains("tests\\TestData\\Falco\\terminal-shell-container.json", script, StringComparison.Ordinal);
        Assert.Contains("conshield.falco-linux-sensor", script, StringComparison.Ordinal);
        Assert.Contains("Expected rule:", script, StringComparison.Ordinal);
        Assert.Contains("CONSHIELD_EXTERNAL_EVENT_API_KEY", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-Content Env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AdditionalDataJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConvertTo-Json", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RuntimeSensorDocs_LinkReplayEvidenceAndFedoraHelper()
    {
        var docs = ReadRepoFile("docs", "FALCO_RUNTIME_SENSOR.md");
        var readme = ReadRepoFile("README.md");

        Assert.Contains("Replay-ConShieldFalcoRuntimeEvent.ps1", docs, StringComparison.Ordinal);
        Assert.Contains("collect-falco-json.sh", docs, StringComparison.Ordinal);
        Assert.Contains("Runtime Sensor Evidence", docs, StringComparison.Ordinal);
        Assert.Contains("does not install or require Fedora", readme, StringComparison.Ordinal);
    }

    [Fact]
    public void FedoraCollectorHelper_DoesNotAcceptSecretsAsArguments()
    {
        var script = ReadRepoFile("deploy", "falco-linux", "collect-falco-json.sh");

        Assert.Contains("--file <path>", script, StringComparison.Ordinal);
        Assert.Contains("--stdin", script, StringComparison.Ordinal);
        Assert.Contains("--no-submit", script, StringComparison.Ordinal);
        Assert.Contains("/etc/conshield/runtime-collector.env", script, StringComparison.Ordinal);
        Assert.DoesNotContain("--api-key", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("echo \"$CONSHIELD_RUNTIME_COLLECTOR_API_KEY", script, StringComparison.Ordinal);
    }

    private static string ReadRepoFile(params string[] relativePath)
    {
        var fullPath = Path.Combine(GetRepositoryRoot(), Path.Combine(relativePath));
        return File.ReadAllText(fullPath);
    }

    private static string GetRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
