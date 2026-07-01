namespace ConShield.Tests;

public sealed class GuidedDemoSeedTests
{
    [Fact]
    public void SeedScriptExistsAndUsesExistingSafeWorkflows()
    {
        var script = ReadRepoFile("scripts", "Seed-ConShieldDemoData.ps1");

        foreach (var required in new[]
        {
            "param(",
            "$BaseUrl = 'http://127.0.0.1:5080'",
            "[switch]$ResetFirst",
            "[switch]$SkipEvidenceExport",
            "$OutputEvidencePath = '.\\artifacts\\local\\defense-evidence-guided-demo.md'",
            "Run-ConShieldDefenseScenario.ps1",
            "Replay-ConShieldFalcoRuntimeEvent.ps1",
            "Export-ConShieldDefenseEvidence.ps1",
            "Reset-ConShieldLocalDemoData.ps1",
            "tests\\TestData\\Falco\\terminal-shell-container.json",
            "tests\\TestData\\Trivy\\sample-image-scan.json",
            "tests\\TestData\\DockerEvents\\container-lifecycle-events.json"
        })
        {
            Assert.Contains(required, script, StringComparison.Ordinal);
        }

        Assert.Contains("Invoke-WebRequest", script, StringComparison.Ordinal);
        Assert.Contains("/Operations/Health", script, StringComparison.Ordinal);
        Assert.Contains("Start-ConShield.ps1 -StartApps -OpenRabbit", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Start-Process", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("docker run", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("trivy image", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Read-Host", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SeedScriptCoversRequiredDemoSignalsAndStepLevelOutput()
    {
        var script = ReadRepoFile("scripts", "Seed-ConShieldDemoData.ps1");

        foreach (var marker in new[]
        {
            "IMG-001",
            "POL-001",
            "LIFE-001",
            "LIFE-002",
            "RTE-001",
            "SENSOR-001",
            "SENSOR-002",
            "SIGN-001",
            "SIGN-002",
            "SIGN-003",
            "ConShield demo data seed",
            "Prerequisites",
            "Runtime/Falco replay",
            "Sensor trust unknown",
            "Sensor trust revoked",
            "Signed sensor missing",
            "Signed sensor invalid",
            "Signed sensor stale",
            "Defense scenario correlation",
            "Image scan",
            "CI/CD gate finding",
            "Protected run decision",
            "Docker lifecycle replay",
            "Evidence-ready data",
            "Dashboard-ready data",
            "Failed step:",
            "Hint:",
            "Result:"
        })
        {
            Assert.Contains(marker, script, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void SeedScriptResetIsExplicitAndSafeByDefault()
    {
        var script = ReadRepoFile("scripts", "Seed-ConShieldDemoData.ps1");

        Assert.Contains("if ($ResetFirst)", script, StringComparison.Ordinal);
        Assert.Contains("-Arguments @('-ConfirmReset')", script, StringComparison.Ordinal);
        Assert.Contains("Optional reset' -Status 'SKIP'", script, StringComparison.Ordinal);
        Assert.Contains("not requested; pass -ResetFirst", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Remove-Item -Recurse", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("docker volume", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CliDemoSeedMapsToSeedScript()
    {
        var cli = ReadRepoFile("src", "ConShield.Cli", "Program.cs");
        var docs = ReadRepoFile("docs", "CONSHIELD_CLI.md");

        foreach (var expected in new[]
        {
            "\"seed\" => await RunScriptCommandAsync",
            "\"demo seed\"",
            "\"Seed-ConShieldDemoData.ps1\"",
            "--base-url",
            "--reset-first",
            "--skip-evidence-export",
            "--output-evidence",
            "--continue-on-expected-findings",
            "--timeout-seconds",
            "dotnet run --project .\\src\\ConShield.Cli -- demo seed"
        })
        {
            Assert.Contains(expected, cli + Environment.NewLine + docs, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void GuidedDemoDocsAndUiReferencesExistButDoNotExecuteSeedInBrowser()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("docs", "GUIDED_DEMO_SCENARIO.md"),
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("docs", "DIPLOMA_DEFENSE_NARRATIVE.md"),
            ReadRepoFile("docs", "RELEASE_AND_DEMO_PACKAGING.md"),
            ReadRepoFile("docs", "ARCHITECTURE.md"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml"),
            ReadRepoFile("scripts", "New-ConShieldDemoReleasePack.ps1"));

        foreach (var expected in new[]
        {
            "GUIDED_DEMO_SCENARIO.md",
            "Seed-ConShieldDemoData.ps1",
            "demo seed",
            "http://127.0.0.1:5080/Dashboard",
            "http://127.0.0.1:5080/Demo",
            "The Web UI only displays this command as a copy/paste reference",
            "This dashboard is read-only",
            "the browser does not execute"
        })
        {
            Assert.Contains(expected, combined, StringComparison.Ordinal);
        }

        var webSource = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml"));

        Assert.DoesNotContain("Process.Start", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PowerShell.Create", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("UseShellExecute", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("method=\"post\"", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fetch(", webSource, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GuidedDemoDocsCoverTroubleshootingAndSafetyBoundaries()
    {
        var docs = ReadRepoFile("docs", "GUIDED_DEMO_SCENARIO.md");

        foreach (var expected in new[]
        {
            "## Prerequisites",
            "## Optional clean reset",
            "## One-command guided seed",
            "## Guided walkthrough after seed",
            "## Evidence export",
            "## Troubleshooting",
            "## Safety guarantees",
            "does not require real Fedora/Falco",
            "does not reset data by default",
            "must not be committed"
        })
        {
            Assert.Contains(expected, docs, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ReadmeKeepsEnglishFirstRussianSecondAfterGuidedSeedUpdate()
    {
        var readme = ReadRepoFile("README.md");
        var englishIndex = readme.IndexOf("## English", StringComparison.Ordinal);
        var russianAnchorIndex = readme.IndexOf("<a id=\"русский\"></a>", StringComparison.Ordinal);
        var russianIndex = readme.IndexOf("## Русский", StringComparison.Ordinal);

        Assert.True(englishIndex >= 0, "README English section is missing.");
        Assert.True(russianAnchorIndex > englishIndex, "Russian anchor must follow English.");
        Assert.True(russianIndex > russianAnchorIndex, "Russian section must follow Russian anchor.");
        Assert.DoesNotMatch("[А-Яа-яЁё]", readme[englishIndex..russianAnchorIndex]);
        Assert.Matches("[А-Яа-яЁё]", readme[russianIndex..]);
        Assert.Contains("### Guided demo data seed", readme[englishIndex..russianAnchorIndex], StringComparison.Ordinal);
        Assert.Contains("### Seed guided demo data", readme[russianIndex..], StringComparison.Ordinal);
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
}
