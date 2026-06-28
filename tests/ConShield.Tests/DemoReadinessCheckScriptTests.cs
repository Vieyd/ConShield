namespace ConShield.Tests;

public sealed class DemoReadinessCheckScriptTests
{
    [Fact]
    public void DemoReadinessScript_ExistsWithSafeDefaultsAndParameters()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1");

        Assert.Contains("[string]$OutputMarkdownPath = '.\\artifacts\\local\\demo-readiness-evidence.md'", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$SkipStartApps", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$SkipScenario", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$SkipImageScan", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$SkipFalcoReplay", script, StringComparison.Ordinal);
        Assert.Contains("ConShield demo readiness check", script, StringComparison.Ordinal);
        Assert.Contains("Result: {0}", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoReadinessScript_ReusesExistingSafeWorkflowScripts()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1");

        Assert.Contains("Start-ConShield.ps1", script, StringComparison.Ordinal);
        Assert.Contains("Run-ConShieldDefenseScenario.ps1", script, StringComparison.Ordinal);
        Assert.Contains("Invoke-ConShieldImageScan.ps1", script, StringComparison.Ordinal);
        Assert.Contains("sample-image-scan.json", script, StringComparison.Ordinal);
        Assert.Contains("-NoSubmit", script, StringComparison.Ordinal);
        Assert.Contains("Replay-ConShieldFalcoRuntimeEvent.ps1", script, StringComparison.Ordinal);
        Assert.Contains("Export-ConShieldDefenseEvidence.ps1", script, StringComparison.Ordinal);
        Assert.Contains("/RuntimeSensors", script, StringComparison.Ordinal);
        Assert.Contains("/Account/DemoUserDiagnostics", script, StringComparison.Ordinal);
        Assert.Contains("conshield-postgres", script, StringComparison.Ordinal);
        Assert.Contains("conshield-rabbitmq", script, StringComparison.Ordinal);
        Assert.Contains("conshield-mongo", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoReadinessScript_ReportsStepLevelStatusesAndFailureContext()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1");

        foreach (var label in new[]
        {
            "Git",
            "Docker",
            "PostgreSQL",
            "RabbitMQ",
            "MongoDB",
            "Demo users",
            "Web",
            "EventConsumer",
            "Defense scenario",
            "Image scan fixture",
            "Falco replay",
            "Runtime Sensor Health",
            "Evidence export"
        })
        {
            Assert.Contains(label, script, StringComparison.Ordinal);
        }

        Assert.Contains("Failed step: {0}", script, StringComparison.Ordinal);
        Assert.Contains("Failure detail: {0}", script, StringComparison.Ordinal);
        Assert.Contains("Hint: {0}", script, StringComparison.Ordinal);
        Assert.Contains("Rerun: pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldDemoReadiness.ps1", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoReadinessScript_UsesSafeChildInvocationWithoutEarlyReturn()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1");

        Assert.Contains("$escapedArguments = foreach ($argument in $Arguments)", script, StringComparison.Ordinal);
        Assert.Contains("ExitCode = [int]$process.ExitCode", script, StringComparison.Ordinal);
        Assert.Contains("Output = @($output)", script, StringComparison.Ordinal);
        Assert.DoesNotContain("return $value", script, StringComparison.Ordinal);
        Assert.DoesNotContain("return ('\"{0}\"", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoReadinessScript_AcceptsProtectedRuntimeSensorRedirects()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1");

        Assert.Contains("$normalizedBaseUrl + '/RuntimeSensors'", script, StringComparison.Ordinal);
        Assert.Contains("ExpectedStatusCodes @(200, 302, 401, 403)", script, StringComparison.Ordinal);
        Assert.Contains("Runtime Sensor Health", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoReadinessScript_DoesNotPrintSecretSourcesOrRawPayloads()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1");

        Assert.Contains("Invoke-CapturedCommand", script, StringComparison.Ordinal);
        Assert.Contains("Test-GeneratedEvidenceSafety", script, StringComparison.Ordinal);
        Assert.Contains("AdditionalDataJson", script, StringComparison.Ordinal);
        Assert.Contains("PayloadJson", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-Content Env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConvertTo-Json", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("appsettings.Development.json", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DemoReadinessScript_KeepsGeneratedEvidenceUnderArtifactsLocal()
    {
        var script = ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1");

        Assert.Contains("[string]$OutputMarkdownPath = '.\\artifacts\\local\\demo-readiness-evidence.md'", script, StringComparison.Ordinal);
        Assert.Contains("Generated evidence: {0}", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoReadinessDocs_MentionCommandInReadmeAndRunbook()
    {
        var combinedDocs = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"));

        Assert.Contains("scripts\\Test-ConShieldDemoReadiness.ps1", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("Demo readiness check", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("artifacts/local/demo-readiness-evidence.md", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("Runtime Sensor Health", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("does not require a real Fedora/Falco", combinedDocs, StringComparison.OrdinalIgnoreCase);
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
