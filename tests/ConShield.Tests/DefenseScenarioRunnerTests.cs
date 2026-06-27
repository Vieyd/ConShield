namespace ConShield.Tests;

public class DefenseScenarioRunnerTests
{
    [Fact]
    public void DefenseScenarioRunner_ExistsAndIsSecretSafe()
    {
        var script = ReadRepoFile("scripts", "Run-ConShieldDefenseScenario.ps1");

        Assert.Contains("Run-ConShieldDefenseScenario.ps1", Path.Combine(GetRepositoryRoot(), "scripts", "Run-ConShieldDefenseScenario.ps1"), StringComparison.Ordinal);
        Assert.Contains("No secrets, raw JSON, connection strings, API keys, tokens, cookies, verifier values, or env values are printed.", script, StringComparison.Ordinal);
        Assert.Contains("Remove-Item Env:CONSHIELD_DEMO_CONNECTION_STRING", script, StringComparison.Ordinal);
        Assert.DoesNotContain("appsettings.Development.json", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("VerifierSha256", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CONSHIELD_RUNTIME_COLLECTOR_API_KEY", script, StringComparison.Ordinal);
        Assert.DoesNotContain("plaintext-secret", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api-key-that-must-not-render", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DefenseScenarioRunner_HasExpectedScenarioSteps()
    {
        var script = ReadRepoFile("scripts", "Run-ConShieldDefenseScenario.ps1");

        Assert.Contains("image scan", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("policy gate", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("synthetic runtime", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("demo lifecycle", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SIEM correlation", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("/Reports/SecuritySummary", script, StringComparison.Ordinal);
        Assert.Contains("tools/ConShield.DemoScenario", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DefenseScenarioRunner_UsesSafeOutputAndMarkdownEvidence()
    {
        var script = ReadRepoFile("scripts", "Run-ConShieldDefenseScenario.ps1");

        Assert.Contains("[string]$OutputMarkdownPath", script, StringComparison.Ordinal);
        Assert.Contains("Write-MarkdownEvidence", script, StringComparison.Ordinal);
        Assert.Contains("AdditionalDataJson", script, StringComparison.Ordinal);
        Assert.Contains("intentionally excluded", script, StringComparison.Ordinal);
        Assert.DoesNotContain("ConvertTo-Json", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Get-Content Env:", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DefenseScenarioRunner_HasStableExitBehavior()
    {
        var script = ReadRepoFile("scripts", "Run-ConShieldDefenseScenario.ps1");

        Assert.Contains("$evidence.Result = 'PASS'", script, StringComparison.Ordinal);
        Assert.Contains("$evidence.Result = 'WARN'", script, StringComparison.Ordinal);
        Assert.Contains("$evidence.Result = 'FAIL'", script, StringComparison.Ordinal);
        Assert.Contains("return 0", script, StringComparison.Ordinal);
        Assert.Contains("return 1", script, StringComparison.Ordinal);
        Assert.Contains("return 2", script, StringComparison.Ordinal);
        Assert.Contains("exit $exitCode", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DefenseScenarioRunner_DocsMentionSafeLocalWorkflow()
    {
        var combinedDocs = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "DEMO_EVIDENCE_PACK.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"));

        Assert.Contains("scripts/Run-ConShieldDefenseScenario.ps1", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("Start-ConShield.ps1 -StartApps -OpenRabbit", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("PASS/WARN/FAIL", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("no real Fedora", combinedDocs, StringComparison.OrdinalIgnoreCase);
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
