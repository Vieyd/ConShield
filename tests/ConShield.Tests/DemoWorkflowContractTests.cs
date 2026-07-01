using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ConShield.Tests;

public sealed class DemoWorkflowContractTests
{
    [Fact]
    public void ImageScanFixtureWorkflow_IsDeterministicSafeAndNoSubmit()
    {
        var first = RunPwsh(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\scripts\\Invoke-ConShieldImageScan.ps1",
            "-FromTrivyJson",
            ".\\tests\\TestData\\Trivy\\sample-image-scan.json",
            "-NoSubmit");
        var second = RunPwsh(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\scripts\\Invoke-ConShieldImageScan.ps1",
            "-FromTrivyJson",
            ".\\tests\\TestData\\Trivy\\sample-image-scan.json",
            "-NoSubmit");

        Assert.Equal(0, first.ExitCode);
        Assert.Equal(0, second.ExitCode);
        Assert.Contains("SourceSystem: conshield.image-scanner", first.Output, StringComparison.Ordinal);
        Assert.Contains("Expected rule: IMG-001", first.Output, StringComparison.Ordinal);
        Assert.Contains("Ingestion: SKIP", first.Output, StringComparison.Ordinal);
        Assert.Equal(ExtractExternalEventId(first.Output), ExtractExternalEventId(second.Output));
        AssertSafeOutput(first.Output);

        var script = ReadRepoFile("scripts", "Invoke-ConShieldImageScan.ps1");
        Assert.Contains("container.image.scan.completed", script, StringComparison.Ordinal);
        Assert.Contains("if ($NoSubmit) { 'SKIP' }", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ProtectedRunFixtureWorkflow_CoversBlockWarnAllowNoRunAndNoSubmit()
    {
        var block = RunProtectedRun("sample-image-scan.json", "demo/insecure-api:latest", "conshield-demo-insecure", "-NoSubmit", "-Execute");
        var warn = RunProtectedRun("warn-image-scan.json", "demo/warn-api:latest", "conshield-demo-warn", "-NoSubmit");
        var clean = RunProtectedRun("clean-image-scan.json", "demo/clean-api:latest", "conshield-demo-clean", "-NoRun", "-NoSubmit");
        var repeat = RunProtectedRun("sample-image-scan.json", "demo/insecure-api:latest", "conshield-demo-insecure", "-NoSubmit", "-Execute");

        Assert.Equal(0, block.ExitCode);
        Assert.Equal(0, warn.ExitCode);
        Assert.Equal(0, clean.ExitCode);
        Assert.Equal(0, repeat.ExitCode);

        Assert.Contains("Policy: Block", block.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (blocked by policy)", block.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("Docker run", block.Output, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("Policy: Warn", warn.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (requires -AcceptWarning and -Execute)", warn.Output, StringComparison.Ordinal);

        Assert.Contains("Policy: Allow", clean.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (NoRun requested)", clean.Output, StringComparison.Ordinal);

        foreach (var output in new[] { block.Output, warn.Output, clean.Output })
        {
            Assert.Contains("IMG event: SKIP", output, StringComparison.Ordinal);
            Assert.Contains("POL event: SKIP", output, StringComparison.Ordinal);
            Assert.Contains("LIFE event: SKIP", output, StringComparison.Ordinal);
            Assert.Contains("Expected rules: IMG-001,POL-001,LIFE-001", output, StringComparison.Ordinal);
            AssertSafeOutput(output);
        }

        Assert.Equal(ExtractExternalEventId(block.Output), ExtractExternalEventId(repeat.Output));

        var script = ReadRepoFile("scripts", "Invoke-ConShieldProtectedRun.ps1");
        Assert.Contains("conshield.image-scanner", script, StringComparison.Ordinal);
        Assert.Contains("conshield.container-guard", script, StringComparison.Ordinal);
        Assert.Contains("conshield.container-runtime", script, StringComparison.Ordinal);
        Assert.Contains("container.image.scan.completed", script, StringComparison.Ordinal);
        Assert.Contains("container.image.policy.evaluated", script, StringComparison.Ordinal);
        Assert.Contains("container.image.launch.result", script, StringComparison.Ordinal);
        Assert.Contains("if ($NoRun)", script, StringComparison.Ordinal);
        Assert.Contains("if ($Decision -eq 'Block')", script, StringComparison.Ordinal);
        Assert.Contains("if ($Decision -eq 'Warn' -and (-not $AcceptWarning -or -not $Execute))", script, StringComparison.Ordinal);
    }

    [Fact]
    public void EvidenceExportContract_IncludesRequiredSectionsAndAvoidsRawDataSources()
    {
        var script = ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1");

        foreach (var section in new[]
        {
            "## Image Scan Evidence",
            "## Protected Run Evidence",
            "## Runtime Sensor Health",
            "## Operator Workflow"
        })
        {
            Assert.Contains(section, script, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("AdditionalDataJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SourceEventIdsJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Get-Content Env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Docker logs |", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DockerLogs", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Sensitive configuration values, raw event bodies, and local logs are intentionally excluded.", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoPageContract_ContainsSafeCommandsLinksAndNoSecretMarkers()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "ViewModels", "DemoWalkthroughViewModel.cs"));

        foreach (var required in new[]
        {
            "Test-ConShieldDemoReadiness.ps1",
            "Reset-ConShieldLocalDemoData.ps1",
            "Invoke-ConShieldImageScan.ps1",
            "Invoke-ConShieldProtectedRun.ps1",
            "Replay-ConShieldFalcoRuntimeEvent.ps1",
            "Export-ConShieldDefenseEvidence.ps1",
            "/Reports/SecuritySummary",
            "/SecurityEvents",
            "/Siem",
            "/Incidents",
            "/RuntimeSensors"
        })
        {
            Assert.Contains(required, combined, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("AdditionalDataJson", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadJson", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api key", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection string", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("GetEnvironmentVariable", combined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReadinessResetAndPowerShellScripts_HaveGuardrailsAndValidSyntax()
    {
        var readiness = ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1");
        var reset = ReadRepoFile("scripts", "Reset-ConShieldLocalDemoData.ps1");

        foreach (var expected in new[]
        {
            "Failed step: {0}",
            "Failure detail: {0}",
            "Hint: {0}",
            "Image scan fixture",
            "Protected run fixture",
            "Generated evidence: {0}",
            "artifacts\\local\\demo-readiness-evidence.md"
        })
        {
            Assert.Contains(expected, readiness, StringComparison.Ordinal);
        }

        Assert.Contains("[switch]$ConfirmReset", reset, StringComparison.Ordinal);
        Assert.Contains("pass -ConfirmReset for actual reset", reset, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("$OutputArtifactRoot = '.\\artifacts\\local'", reset, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("refusing to clean outside artifacts/local", reset, StringComparison.OrdinalIgnoreCase);

        var syntax = RunPwsh(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$paths=@(); $paths+=Get-ChildItem .\\scripts\\*.ps1; $paths+=Get-Item .\\Start-ConShield.ps1; foreach($p in $paths){$e=$null; $null=[System.Management.Automation.PSParser]::Tokenize((Get-Content $p.FullName -Raw), [ref]$e); if($e){$e; exit 1}}");
        Assert.Equal(0, syntax.ExitCode);
    }

    [Fact]
    public void ReadmeContract_KeepsBilingualStructureCommandsAndValidDocLinks()
    {
        var readme = ReadRepoFile("README.md");
        var englishIndex = readme.IndexOf("## English", StringComparison.Ordinal);
        var russianAnchorIndex = readme.IndexOf("<a id=\"русский\"></a>", StringComparison.Ordinal);
        var russianIndex = readme.IndexOf("## Русский", StringComparison.Ordinal);

        Assert.True(englishIndex >= 0, "README English section is missing.");
        Assert.True(russianAnchorIndex > englishIndex, "Russian anchor must follow the English section.");
        Assert.True(russianIndex > russianAnchorIndex, "Russian section must follow its anchor.");

        var english = readme[englishIndex..russianAnchorIndex];
        var russian = readme[russianIndex..];
        Assert.DoesNotMatch("[А-Яа-яЁё]", english);
        Assert.Matches("[А-Яа-яЁё]", russian);

        foreach (var command in new[]
        {
            "Invoke-ConShieldImageScan.ps1",
            "Invoke-ConShieldProtectedRun.ps1",
            "Test-ConShieldDemoReadiness.ps1",
            "Reset-ConShieldLocalDemoData.ps1"
        })
        {
            Assert.Contains(command, english, StringComparison.Ordinal);
            Assert.Contains(command, russian, StringComparison.Ordinal);
        }

        foreach (Match match in Regex.Matches(readme, @"\[[^\]]+\]\((?<target>[^)#]+)(#[^)]+)?\)"))
        {
            var target = match.Groups["target"].Value;
            if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                target.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            Assert.True(
                File.Exists(Path.Combine(GetRepositoryRoot(), target.Replace('/', Path.DirectorySeparatorChar))),
                $"README link target does not exist: {target}");
        }
    }

    private static CommandResult RunProtectedRun(string fixtureName, string image, string containerName, params string[] extraArguments)
    {
        var arguments = new List<string>
        {
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\scripts\\Invoke-ConShieldProtectedRun.ps1",
            "-Image",
            image,
            "-ContainerName",
            containerName,
            "-FromTrivyJson",
            $".\\tests\\TestData\\Trivy\\{fixtureName}"
        };
        arguments.AddRange(extraArguments);
        return RunPwsh(arguments.ToArray());
    }

    private static void AssertSafeOutput(string output)
    {
        foreach (var forbidden in new[]
        {
            "\"Vulnerabilities\"",
            "\"Results\"",
            "AdditionalDataJson",
            "PayloadJson",
            "CONSHIELD_",
            "api_key",
            "api key",
            "connection string",
            "password",
            "token",
            "Docker logs"
        })
        {
            Assert.DoesNotContain(forbidden, output, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string ExtractExternalEventId(string output)
    {
        var match = Regex.Match(output, @"ExternalEventId:\s+([0-9a-fA-F-]{36})");
        Assert.True(match.Success, "ExternalEventId was not found in output.");
        return match.Groups[1].Value;
    }

    private static CommandResult RunPwsh(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            WorkingDirectory = GetRepositoryRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        var result = TestProcessRunner.Run(startInfo, TimeSpan.FromSeconds(60));
        return new CommandResult(result.ExitCode, result.Output);
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

    private sealed record CommandResult(int ExitCode, string Output);
}
