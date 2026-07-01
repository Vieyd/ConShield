using System.Text.RegularExpressions;
using System.Diagnostics;

namespace ConShield.Tests;

public sealed class FullIntegrationContractTests
{
    private static readonly string PrivateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";
    private static readonly string CertificateMarker = "-----BEGIN " + "CERTIFICATE-----";

    [Fact]
    public void FullValidationScriptAndChecklistExistWithSafeDefaultContract()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldFullValidation.ps1");
        var checklist = ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md");

        foreach (var expected in new[]
        {
            "ConShield full validation",
            "Repository",
            "Configuration",
            "CLI",
            "Scripts",
            "Fixtures",
            "Demo contract",
            "Evidence contract",
            "Security guardrails",
            "Result: PASS",
            "[switch]$IncludeWeb",
            "dotnet",
            "pwsh",
            "Test-ConShieldSiemRules.ps1",
            "Test-ConShieldContainerPolicy.ps1",
            "Test-ConShieldSensorRegistry.ps1"
        })
        {
            Assert.Contains(expected, script, StringComparison.Ordinal);
        }

        foreach (var section in new[]
        {
            "## 1. Local prerequisites",
            "## 2. Services / infrastructure",
            "## 3. Configuration validation",
            "## 4. CLI validation",
            "## 5. Image scanning",
            "## 6. Protected container run",
            "## 7. CI/CD container gate",
            "## 8. Docker lifecycle collector",
            "## 9. Falco/runtime replay",
            "## 10. Sensor trust registry",
            "## 11. Sensor trust enforcement",
            "## 12. Signed sensor events",
            "## 13. SIEM rules and incidents",
            "## 14. Operator workflow",
            "## 15. Runtime Sensor Health",
            "## 16. Evidence export",
            "## 17. Demo walkthrough",
            "## 18. README/docs consistency",
            "## 19. Security guardrails",
            "## 20. Known intentionally optional checks",
            "## Known follow-up work"
        })
        {
            Assert.Contains(section, checklist, StringComparison.Ordinal);
        }

        Assert.Contains("does not require live Web/API", checklist, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("real certificates, private keys, or signing keys", checklist, StringComparison.OrdinalIgnoreCase);
        AssertSafeText(script + checklist);
    }

    [Fact]
    public void FullValidationScriptHasValidPowerShellSyntax()
    {
        var path = Path.Combine(RepoRoot(), "scripts", "Test-ConShieldFullValidation.ps1");
        var literalPath = path.Replace("'", "''", StringComparison.Ordinal);
        var result = RunPwsh(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$errors=$null; $null=[System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath '" + literalPath + "' -Raw), [ref]$errors); if($errors){$errors; exit 1}");

        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void CliDemoAndEvidenceContractsCoverCurrentWorkflowSurface()
    {
        var cli = ReadRepoFile("src", "ConShield.Cli", "Program.cs");
        var demo = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"));
        var evidence = ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1");

        foreach (var command in new[]
        {
            "validate",
            "demo readiness",
            "demo seed",
            "demo reset",
            "scan image",
            "run protected",
            "sensor replay",
            "sensor collect",
            "lifecycle replay",
            "lifecycle watch",
            "gate image",
            "evidence export"
        })
        {
            Assert.Contains(command, cli, StringComparison.Ordinal);
        }

        foreach (var demoMarker in new[]
        {
            "Test-ConShieldDemoReadiness.ps1",
            "Seed-ConShieldDemoData.ps1",
            "demo seed",
            "Reset-ConShieldLocalDemoData.ps1",
            "scan image",
            "run protected",
            "gate image",
            "lifecycle replay",
            "lifecycle watch",
            "sensor replay",
            "sensor collect",
            "Export-ConShieldDefenseEvidence.ps1",
            "/Reports/SecuritySummary",
            "/SecurityEvents",
            "/Siem",
            "/Incidents",
            "/RuntimeSensors"
        })
        {
            Assert.Contains(demoMarker, demo, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var evidenceSection in new[]
        {
            "ConShield Defense Evidence Pack",
            "Image Scan Evidence",
            "Protected Run Evidence",
            "Container Policy Evidence",
            "SIEM Rules Evidence",
            "Sensor Trust Evidence",
            "Sensor Trust Enforcement Evidence",
            "Signed Sensor Event Evidence",
            "Docker Lifecycle Collector Evidence",
            "Runtime Sensor Health",
            "Operator Workflow"
        })
        {
            Assert.Contains(evidenceSection, evidence, StringComparison.Ordinal);
        }

        AssertSafeText(cli + demo + evidence);
    }

    [Fact]
    public void ConfigsFixturesAndGeneratedArtifactGuardrailsArePresent()
    {
        foreach (var relativePath in new[]
        {
            "config/siem-rules.default.json",
            "config/container-policy.default.json",
            "config/sensor-registry.default.json",
            "tests/TestData/Trivy/sample-image-scan.json",
            "tests/TestData/Trivy/warn-image-scan.json",
            "tests/TestData/Trivy/clean-image-scan.json",
            "tests/TestData/DockerEvents/container-lifecycle-events.json"
        })
        {
            Assert.True(File.Exists(Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar))), $"Missing file: {relativePath}");
        }

        var gitignore = ReadRepoFile(".gitignore");
        foreach (var marker in new[]
        {
            "artifacts/local/",
            "*.env",
            "src/**/appsettings.Development.json",
            "*.log",
            "*.jsonl",
            "TestResults/",
            "*.tar.gz",
            "*trivy-report*.json"
        })
        {
            Assert.Contains(marker, gitignore, StringComparison.OrdinalIgnoreCase);
        }

        var fullValidation = ReadRepoFile("scripts", "Test-ConShieldFullValidation.ps1");
        Assert.Contains("git' -Arguments @('ls-files', 'artifacts/local')", fullValidation, StringComparison.Ordinal);
    }

    [Fact]
    public void ReadmeAndDocsReferenceFullValidationAndKeepLinksResolvable()
    {
        var readme = ReadRepoFile("README.md");
        var cliDoc = ReadRepoFile("docs", "CONSHIELD_CLI.md");
        var runbook = ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md");

        foreach (var text in new[] { readme, cliDoc, runbook })
        {
            Assert.Contains("Test-ConShieldFullValidation.ps1", text, StringComparison.Ordinal);
            Assert.Contains("CONSHIELD_FULL_VALIDATION_CHECKLIST.md", text, StringComparison.Ordinal);
        }

        var englishIndex = readme.IndexOf("## English", StringComparison.Ordinal);
        var russianAnchorIndex = readme.IndexOf("<a id=\"русский\"></a>", StringComparison.Ordinal);
        var russianIndex = readme.IndexOf("## Русский", StringComparison.Ordinal);
        Assert.True(englishIndex >= 0, "README English section is missing.");
        Assert.True(russianAnchorIndex > englishIndex, "Russian anchor must follow English section.");
        Assert.True(russianIndex > russianAnchorIndex, "Russian section must follow its anchor.");
        Assert.DoesNotMatch("[А-Яа-яЁё]", readme[englishIndex..russianAnchorIndex]);
        Assert.Matches("[А-Яа-яЁё]", readme[russianIndex..]);

        foreach (Match match in Regex.Matches(readme, @"\[[^\]]+\]\((?<target>[^)#]+)(#[^)]+)?\)"))
        {
            var target = match.Groups["target"].Value;
            if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                target.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var fullPath = Path.Combine(RepoRoot(), target.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(fullPath), $"README link target does not exist: {target}");
        }
    }

    private static CommandResult RunPwsh(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            WorkingDirectory = RepoRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        var result = TestProcessRunner.Run(startInfo, TimeSpan.FromSeconds(60));
        return new CommandResult(result.ExitCode, result.Output);
    }

    private static void AssertSafeText(string text)
    {
        foreach (var forbidden in new[]
        {
            PrivateKeyMarker,
            CertificateMarker,
            "Docker logs |",
            "Get-Content Env:",
            "Write-Host $env:",
            "Write-Output $env:"
        })
        {
            Assert.DoesNotContain(forbidden, text, StringComparison.OrdinalIgnoreCase);
        }
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

    private sealed record CommandResult(int ExitCode, string Output);
}
