using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ConShield.Tests;

public sealed class ImageScanCliScriptTests
{
    [Fact]
    public void ImageScanCliScript_ExistsWithSafeUserFacingOptions()
    {
        var script = ReadRepoFile("scripts", "Invoke-ConShieldImageScan.ps1");

        Assert.Contains("scripts\\Invoke-ConShieldImageScan.ps1", script, StringComparison.Ordinal);
        Assert.Contains("[string]$Image", script, StringComparison.Ordinal);
        Assert.Contains("[string]$FromTrivyJson", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$NoSubmit", script, StringComparison.Ordinal);
        Assert.Contains("[string]$OutputMarkdownPath", script, StringComparison.Ordinal);
        Assert.Contains("conshield.image-scanner", script, StringComparison.Ordinal);
        Assert.Contains("container.image.scan.completed", script, StringComparison.Ordinal);
        Assert.Contains("IMG-001", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ImageScanCliScript_UsesDeterministicFixtureModeAndNoSubmitSkip()
    {
        var script = ReadRepoFile("scripts", "Invoke-ConShieldImageScan.ps1");

        Assert.Contains("New-DeterministicGuid", script, StringComparison.Ordinal);
        Assert.Contains("ReportSha256", script, StringComparison.Ordinal);
        Assert.Contains("SKIP (fixture)", script, StringComparison.Ordinal);
        Assert.Contains("if ($NoSubmit) { 'SKIP' }", script, StringComparison.Ordinal);
        Assert.Contains("Invoke-RestMethod", script, StringComparison.Ordinal);
        Assert.Contains("Submit-ImageScanEvent", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ImageScanCliScript_DoesNotPrintRawJsonOrSecretSources()
    {
        var script = ReadRepoFile("scripts", "Invoke-ConShieldImageScan.ps1");

        Assert.DoesNotContain("Get-Content Env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $json", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $payload", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $ReportJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $apiKey", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $apiKey", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ImageScanCliScript_MissingInputFailsSafelyWithUsage()
    {
        var result = RunPwsh("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\Invoke-ConShieldImageScan.ps1");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Usage:", result.Output, StringComparison.Ordinal);
        Assert.Contains("Offline validation:", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("CONSHIELD_", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void ImageScanCliScript_FixtureNoSubmitPrintsSafeDeterministicSummary()
    {
        var first = RunImageScanFixtureNoSubmit();
        var second = RunImageScanFixtureNoSubmit();

        Assert.Equal(0, first.ExitCode);
        Assert.Equal(0, second.ExitCode);
        Assert.Contains("ConShield image scan", first.Output, StringComparison.Ordinal);
        Assert.Contains("SourceSystem: conshield.image-scanner", first.Output, StringComparison.Ordinal);
        Assert.Contains("Expected rule: IMG-001", first.Output, StringComparison.Ordinal);
        Assert.Contains("Critical vulnerabilities: 1", first.Output, StringComparison.Ordinal);
        Assert.Contains("High vulnerabilities: 1", first.Output, StringComparison.Ordinal);
        Assert.Contains("Medium vulnerabilities: 1", first.Output, StringComparison.Ordinal);
        Assert.Contains("Low vulnerabilities: 1", first.Output, StringComparison.Ordinal);
        Assert.Contains("Misconfigurations: 1", first.Output, StringComparison.Ordinal);
        Assert.Contains("Ingestion: SKIP", first.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", first.Output, StringComparison.Ordinal);

        Assert.Equal(ExtractExternalEventId(first.Output), ExtractExternalEventId(second.Output));

        foreach (var forbidden in new[]
        {
            "\"Vulnerabilities\"",
            "Misconfigurations\":",
            "AdditionalDataJson",
            "PayloadJson",
            "CONSHIELD_",
            "api key",
            "connection string"
        })
        {
            Assert.DoesNotContain(forbidden, first.Output, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ImageScanCliFixtures_AreSmallAndSanitized()
    {
        foreach (var relativePath in new[]
        {
            Path.Combine("tests", "TestData", "Trivy", "sample-image-scan.json"),
            Path.Combine("tests", "TestData", "Trivy", "clean-image-scan.json")
        })
        {
            var fullPath = Path.Combine(GetRepositoryRoot(), relativePath);
            var text = File.ReadAllText(fullPath);

            Assert.True(new FileInfo(fullPath).Length < 16_384);
            Assert.DoesNotContain("BEGIN ", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("PRIVATE KEY", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("api_key", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("token", text, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ImageScanCliDocsAndEvidenceHooks_ArePresent()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("docs", "CONTAINER_IMAGE_SCANNING.md"),
            ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"));

        Assert.Contains("Invoke-ConShieldImageScan.ps1", combined, StringComparison.Ordinal);
        Assert.Contains("tests\\TestData\\Trivy\\sample-image-scan.json", combined, StringComparison.Ordinal);
        Assert.Contains("## Image Scan Evidence", combined, StringComparison.Ordinal);
        Assert.Contains("image scan fixture", combined, StringComparison.OrdinalIgnoreCase);
    }

    private static CommandResult RunImageScanFixtureNoSubmit() =>
        RunPwsh(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\scripts\\Invoke-ConShieldImageScan.ps1",
            "-FromTrivyJson",
            ".\\tests\\TestData\\Trivy\\sample-image-scan.json",
            "-NoSubmit");

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
