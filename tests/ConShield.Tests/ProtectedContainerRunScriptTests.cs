using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ConShield.Tests;

public sealed class ProtectedContainerRunScriptTests
{
    [Fact]
    public void ProtectedRunScript_ExistsWithSafeParametersAndConventions()
    {
        var script = ReadRepoFile("scripts", "Invoke-ConShieldProtectedRun.ps1");

        Assert.Contains("Invoke-ConShieldProtectedRun.ps1", script, StringComparison.Ordinal);
        Assert.Contains("[string]$Image", script, StringComparison.Ordinal);
        Assert.Contains("[string]$ContainerName", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$NoSubmit", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$NoRun", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$Execute", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$AcceptWarning", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$RemoveExistingDemoContainer", script, StringComparison.Ordinal);
        Assert.Contains("conshield.image-scanner", script, StringComparison.Ordinal);
        Assert.Contains("conshield.container-guard", script, StringComparison.Ordinal);
        Assert.Contains("conshield.container-runtime", script, StringComparison.Ordinal);
        Assert.Contains("container.image.launch.result", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ProtectedRunScript_MissingRequiredParametersFailsSafely()
    {
        var result = RunPwsh("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\Invoke-ConShieldProtectedRun.ps1");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Usage:", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("CONSHIELD_", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("AdditionalDataJson", result.Output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProtectedRunScript_NoRunNoSubmitBlockFixtureNeverInvokesDocker()
    {
        var result = RunProtectedFixture("sample-image-scan.json", "demo/insecure-api:latest", "conshield-demo-insecure", "-NoRun", "-NoSubmit", "-Execute");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Policy: Block", result.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (blocked by policy)", result.Output, StringComparison.Ordinal);
        Assert.Contains("IMG event: SKIP", result.Output, StringComparison.Ordinal);
        Assert.Contains("POL event: SKIP", result.Output, StringComparison.Ordinal);
        Assert.Contains("LIFE event: SKIP", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("Docker run", result.Output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProtectedRunScript_CleanFixtureAllowsButNoRunNeverInvokesDocker()
    {
        var result = RunProtectedFixture("clean-image-scan.json", "demo/clean-api:latest", "conshield-demo-clean", "-NoRun", "-NoSubmit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Policy: Allow", result.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (NoRun requested)", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void ProtectedRunScript_WarnFixtureRequiresAcceptanceAndExecute()
    {
        var result = RunProtectedFixture("warn-image-scan.json", "demo/warn-api:latest", "conshield-demo-warn", "-NoSubmit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Policy: Warn", result.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (requires -AcceptWarning and -Execute)", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void ProtectedRunScript_FixtureModeProducesDeterministicExternalEventId()
    {
        var first = RunProtectedFixture("sample-image-scan.json", "demo/insecure-api:latest", "conshield-demo-insecure", "-NoRun", "-NoSubmit");
        var second = RunProtectedFixture("sample-image-scan.json", "demo/insecure-api:latest", "conshield-demo-insecure", "-NoRun", "-NoSubmit");

        Assert.Equal(0, first.ExitCode);
        Assert.Equal(0, second.ExitCode);
        Assert.Equal(ExtractExternalEventId(first.Output), ExtractExternalEventId(second.Output));
    }

    [Fact]
    public void ProtectedRunScript_DoesNotPrintSecretsRawJsonPayloadsOrLogs()
    {
        var script = ReadRepoFile("scripts", "Invoke-ConShieldProtectedRun.ps1");
        var result = RunProtectedFixture("sample-image-scan.json", "demo/insecure-api:latest", "conshield-demo-insecure", "-NoRun", "-NoSubmit");

        Assert.DoesNotContain("Get-Content Env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $json", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $payload", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $apiKey", script, StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain("\"Vulnerabilities\"", result.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AdditionalDataJson", result.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadJson", result.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Docker logs", result.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection string=", result.Output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProtectedRunDocsDemoReadinessAndEvidenceHooks_ArePresent()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("docs", "CONTAINER_POLICY_GATE.md"),
            ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1"),
            ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"));

        Assert.Contains("Invoke-ConShieldProtectedRun.ps1", combined, StringComparison.Ordinal);
        Assert.Contains("Protected Run Evidence", combined, StringComparison.Ordinal);
        Assert.Contains("Protected run fixture", combined, StringComparison.Ordinal);
        Assert.Contains("container.image.launch.result", combined, StringComparison.Ordinal);
        Assert.Contains("sample-image-scan.json", combined, StringComparison.Ordinal);
    }

    [Fact]
    public void WarnFixture_IsSmallAndSanitized()
    {
        var path = Path.Combine(GetRepositoryRoot(), "tests", "TestData", "Trivy", "warn-image-scan.json");
        var text = File.ReadAllText(path);

        Assert.True(new FileInfo(path).Length < 16_384);
        Assert.DoesNotContain("BEGIN ", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRIVATE KEY", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api_key", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token", text, StringComparison.OrdinalIgnoreCase);
    }

    private static CommandResult RunProtectedFixture(string fixtureName, string image, string containerName, params string[] extraArguments)
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

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("pwsh was not started.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit(60_000);

        return new CommandResult(process.ExitCode, output + error);
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
