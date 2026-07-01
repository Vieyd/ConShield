using System.Diagnostics;

namespace ConShield.Tests;

public sealed class ProductPackagingTests
{
    private static readonly string PrivateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";
    private static readonly string CertificateMarker = "-----BEGIN " + "CERTIFICATE-----";

    [Fact]
    public void PackagingScriptExistsWithValidPowerShellSyntax()
    {
        var path = Path.Combine(RepoRoot(), "scripts", "New-ConShieldDemoReleasePack.ps1");

        Assert.True(File.Exists(path), "Packaging script is missing.");
        var result = RunPwshWithEnvironment(
            new Dictionary<string, string?> { ["CONSHIELD_PARSE_TARGET"] = path },
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$path=$env:CONSHIELD_PARSE_TARGET; if([string]::IsNullOrWhiteSpace($path)){exit 2}; $errors=$null; $null=[System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath $path -Raw), [ref]$errors); if($errors){$errors; exit 1}");

        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void PackagingScriptPublishesCliRunsValidationAndUsesArtifactsLocal()
    {
        var script = ReadRepoFile("scripts", "New-ConShieldDemoReleasePack.ps1");

        foreach (var expected in new[]
        {
            "ConShield demo release pack",
            "[string]$OutputRoot = '.\\artifacts\\local'",
            "[string]$PackName = 'conshield-demo-release-pack'",
            "dotnet restore .\\ConShield.sln",
            "dotnet build .\\ConShield.sln --configuration Release --no-restore",
            "dotnet test .\\ConShield.sln --configuration Release --no-build",
            "Test-ConShieldFullValidation.ps1",
            "dotnet publish .\\src\\ConShield.Cli\\ConShield.Cli.csproj",
            "conshieldctl",
            "bin\\conshield-cli",
            "Compress-Archive",
            "Result: PASS"
        })
        {
            Assert.Contains(expected, script, StringComparison.Ordinal);
        }

        Assert.Contains("OutputRoot must be the repository artifacts/local path.", script, StringComparison.Ordinal);
        Assert.Contains("Test-PackSafety", script, StringComparison.Ordinal);
        AssertSafeText(script);
    }

    [Fact]
    public void PackagingScriptUsesSafeAllowListAndExcludesLocalArtifacts()
    {
        var script = ReadRepoFile("scripts", "New-ConShieldDemoReleasePack.ps1");

        foreach (var expected in new[]
        {
            "docs\\PRODUCT_POSITIONING.md",
            "docs\\COMPETITIVE_ANALYSIS.md",
            "docs\\DIPLOMA_DEFENSE_NARRATIVE.md",
            "docs\\ROADMAP_TO_PRODUCTION.md",
            "docs\\THREAT_MODEL.md",
            "docs\\ATTACKER_SCENARIOS.md",
            "docs\\SECURITY_REQUIREMENTS.md",
            "docs\\REQUIREMENTS_TRACEABILITY_MATRIX.md",
            "docs\\RESIDUAL_RISKS.md",
            "docs\\ARCHITECTURE.md",
            "docs\\ARCHITECTURE_DIAGRAMS.md",
            "docs\\DATA_FLOW_MODEL.md",
            "docs\\DEPLOYMENT_VIEW.md",
            "docs\\SEQUENCE_FLOWS.md",
            "docs\\RELEASE_AND_DEMO_PACKAGING.md",
            "docs\\CONSHIELD_FULL_VALIDATION_CHECKLIST.md",
            "docs\\CONSHIELD_CLI.md",
            "docs\\CICD_CONTAINER_GATE.md",
            "docs\\DOCKER_LIFECYCLE_COLLECTOR.md",
            "docs\\SIGNED_SENSOR_EVENTS.md",
            "docs\\SENSOR_TRUST_REGISTRY.md",
            "docs\\SIEM_RULES.md",
            "docs\\CONTAINER_POLICY.md",
            "docs\\OPERATIONS_AND_SIEM_RUNBOOK.md",
            "config\\siem-rules.default.json",
            "config\\container-policy.default.json",
            "config\\sensor-registry.default.json",
            "Start-ConShield.ps1",
            "scripts\\Test-ConShieldFullValidation.ps1",
            "scripts\\Test-ConShieldDemoReadiness.ps1",
            "scripts\\Export-ConShieldDefenseEvidence.ps1"
        })
        {
            Assert.Contains(expected, script, StringComparison.Ordinal);
        }

        foreach (var forbidden in new[]
        {
            "appsettings\\.Development\\.json",
            "appsettings\\.Local\\.json",
            ".env",
            "artifacts[\\\\/]local",
            "logs[\\\\/]",
            "screenshots[\\\\/]",
            "TestResults[\\\\/]",
            "bin[\\\\/]",
            "obj[\\\\/]"
        })
        {
            Assert.Contains(forbidden, script, StringComparison.OrdinalIgnoreCase);
        }

        Assert.DoesNotContain("docs\\DEMO_EVIDENCE_PACK.md", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReleasePackagingDocsDemoReadmeAndRunbookContainCommand()
    {
        var combined = string.Join(
            "\n",
            ReadRepoFile("docs", "RELEASE_AND_DEMO_PACKAGING.md"),
            ReadRepoFile("docs", "CONSHIELD_CLI.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("README.md"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"));

        foreach (var expected in new[]
        {
            "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\New-ConShieldDemoReleasePack.ps1",
            "artifacts/local/conshield-demo-release-pack",
            "artifacts/local/conshield-demo-release-pack.zip",
            "RELEASE_AND_DEMO_PACKAGING.md"
        })
        {
            Assert.Contains(expected, combined, StringComparison.Ordinal);
        }

        AssertSafeText(combined);
    }

    [Fact]
    public void GitignoreProtectsGeneratedReleaseOutputs()
    {
        var gitignore = ReadRepoFile(".gitignore");

        foreach (var expected in new[]
        {
            "artifacts/local/",
            "artifacts/local/conshield-demo-release-pack/",
            "artifacts/local/conshield-demo-release-pack*.zip",
            "artifacts/local/conshieldctl/",
            "artifacts/local/publish/"
        })
        {
            Assert.Contains(expected, gitignore, StringComparison.OrdinalIgnoreCase);
        }

        var trackedArtifacts = RunGit("ls-files", "artifacts/local");
        Assert.True(string.IsNullOrWhiteSpace(trackedArtifacts.Output), "Generated artifacts/local files must not be tracked.");
    }

    [Fact]
    public void ReleasePackagingDocExplainsIncludedAndExcludedContent()
    {
        var doc = ReadRepoFile("docs", "RELEASE_AND_DEMO_PACKAGING.md");

        foreach (var expected in new[]
        {
            "published `ConShield.Cli`",
            "selected docs",
            "committed default configs",
            "selected safe helper scripts",
            "Intentionally excluded",
            "Generated evidence remains local",
            "does not require live Web/API",
            "real certificates, private keys, signing keys, or real secrets"
        })
        {
            Assert.Contains(expected, doc, StringComparison.OrdinalIgnoreCase);
        }

        Assert.DoesNotContain("Password=", doc, StringComparison.OrdinalIgnoreCase);
        AssertSafeText(doc);
    }

    private static CommandResult RunPwshWithEnvironment(IReadOnlyDictionary<string, string?> environment, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            WorkingDirectory = RepoRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        foreach (var item in environment)
            startInfo.Environment[item.Key] = item.Value;

        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        var result = TestProcessRunner.Run(startInfo, TimeSpan.FromSeconds(60));
        return new CommandResult(result.ExitCode, result.Output);
    }

    private static CommandResult RunGit(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "git",
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
            "Write-Output $env:",
            "Password=<",
            "Host=127.0.0.1;Port=",
            "CONSHIELD_API_KEY =",
            "CONSHIELD_RUNTIME_COLLECTOR_API_KEY="
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
