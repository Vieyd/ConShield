namespace ConShield.Tests;

public class DemoScenarioValidationScriptTests
{
    [Fact]
    public void ValidateDemoScenarioScript_DefaultsToDryRun()
    {
        var script = ReadRepoFile("scripts", "Validate-DemoScenario.ps1");

        Assert.Contains("[string]$Scenario = 'full-demo'", script, StringComparison.Ordinal);
        Assert.Contains("$effectiveDryRun = -not $Apply", script, StringComparison.Ordinal);
        Assert.Contains("'--dry-run'", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateDemoScenarioScript_RequiresExplicitApplyForWrites()
    {
        var script = ReadRepoFile("scripts", "Validate-DemoScenario.ps1");

        Assert.Contains("if ($Apply -and $DryRun)", script, StringComparison.Ordinal);
        Assert.Contains("CONSHIELD_DEMO_CONNECTION_STRING must be set for -Apply", script, StringComparison.Ordinal);
        Assert.Contains("dotnet", script, StringComparison.Ordinal);
        Assert.Contains("tools/ConShield.DemoScenario", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateDemoScenarioScript_DoesNotPrintConnectionString()
    {
        var script = ReadRepoFile("scripts", "Validate-DemoScenario.ps1");

        Assert.Contains("Get-Item Env:CONSHIELD_DEMO_CONNECTION_STRING", script, StringComparison.Ordinal);
        Assert.Contains("intentionally not printed", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Host=127.0.0.1", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConnectionStrings", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("VerifierSha256", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("appsettings.Development.json", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateDemoScenarioScript_ResetRequiresYesForApply()
    {
        var script = ReadRepoFile("scripts", "Validate-DemoScenario.ps1");

        Assert.Contains("Reset apply requires -Yes", script, StringComparison.Ordinal);
        Assert.Contains("'--reset-demo-data'", script, StringComparison.Ordinal);
        Assert.Contains("'--yes'", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateDemoScenarioScript_ListsExpectedRoutes()
    {
        var script = ReadRepoFile("scripts", "Validate-DemoScenario.ps1");

        Assert.Contains("/Operations/Health", script, StringComparison.Ordinal);
        Assert.Contains("/SecurityEvents", script, StringComparison.Ordinal);
        Assert.Contains("/Sensors", script, StringComparison.Ordinal);
        Assert.Contains("/Reports/SecuritySummary", script, StringComparison.Ordinal);
        Assert.Contains("/Siem", script, StringComparison.Ordinal);
        Assert.Contains("/Incidents", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoDocs_MentionValidationScript()
    {
        var combinedDocs = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "DEMO_EVIDENCE_PACK.md"),
            ReadRepoFile("docs", "CONSHIELD_FINAL_HANDOFF_SNAPSHOT.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"));

        Assert.Contains("scripts/Validate-DemoScenario.ps1", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("-Apply", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("-ResetDemoData", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("-SkipWebChecks", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("production", combinedDocs, StringComparison.OrdinalIgnoreCase);
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
