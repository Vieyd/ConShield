using System.Diagnostics;
using ConShield.Cli;

namespace ConShield.Tests;

public sealed class LiveTrivyImageScanTests
{
    [Fact]
    public void CliHelpIncludesOptionalLiveTrivyScanAndGate()
    {
        var help = RunCli("--help");
        var scanHelp = RunCli("scan", "help");
        var gateHelp = RunCli("gate", "help");

        Assert.Equal(0, help.ExitCode);
        Assert.Equal(0, scanHelp.ExitCode);
        Assert.Equal(0, gateHelp.ExitCode);

        var combined = help.Output + scanHelp.Output + gateHelp.Output;
        Assert.Contains("--live-trivy", combined, StringComparison.Ordinal);
        Assert.Contains("scan image --image alpine:3.19 --live-trivy --no-submit", combined, StringComparison.Ordinal);
        Assert.Contains("gate image --image alpine:3.19 --live-trivy --fail-on block --no-submit", combined, StringComparison.Ordinal);
        Assert.Contains("not required for CI", combined, StringComparison.Ordinal);
        AssertSafeOutput(combined);
    }

    [Fact]
    public void ScanImageLiveTrivyValidatesModeAndTimeoutWithoutTrivy()
    {
        var missingImage = RunCli("scan", "image", "--live-trivy", "--no-submit");
        Assert.Equal(2, missingImage.ExitCode);
        Assert.Contains("--live-trivy requires --image", missingImage.Output, StringComparison.Ordinal);

        var mixedModes = RunCli(
            "scan",
            "image",
            "--from-trivy-json",
            @".\tests\TestData\Trivy\sample-image-scan.json",
            "--image",
            "alpine:3.19",
            "--live-trivy",
            "--no-submit");
        Assert.Equal(2, mixedModes.ExitCode);
        Assert.Contains("Use either --from-trivy-json or --live-trivy", mixedModes.Output, StringComparison.Ordinal);

        var invalidTimeout = RunCli("scan", "image", "--image", "alpine:3.19", "--live-trivy", "--timeout-seconds", "1", "--no-submit");
        Assert.Equal(2, invalidTimeout.ExitCode);
        Assert.Contains("--timeout-seconds must be between", invalidTimeout.Output, StringComparison.Ordinal);

        AssertSafeOutput(missingImage.Output + mixedModes.Output + invalidTimeout.Output);
    }

    [Fact]
    public void ScanImageLiveTrivyUnavailablePathIsSafe()
    {
        var result = RunCli(
            "scan",
            "image",
            "--image",
            "alpine:3.19",
            "--live-trivy",
            "--trivy-path",
            MissingTrivyPath(),
            "--timeout-seconds",
            "15",
            "--no-submit");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Command: scan image", result.Output, StringComparison.Ordinal);
        Assert.Contains("Trivy executable was not found", result.Output, StringComparison.Ordinal);
        Assert.Contains("FromTrivyJson", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void GateImageLiveTrivyValidatesModeAndPreservesExitCodeContract()
    {
        var mixedModes = RunCli(
            "gate",
            "image",
            "--image",
            "alpine:3.19",
            "--from-trivy-json",
            @".\tests\TestData\Trivy\sample-image-scan.json",
            "--live-trivy",
            "--fail-on",
            "block",
            "--no-submit");
        Assert.Equal(2, mixedModes.ExitCode);
        Assert.Contains("Use either --from-trivy-json or --live-trivy", mixedModes.Output, StringComparison.Ordinal);

        var invalidTimeout = RunCli("gate", "image", "--image", "alpine:3.19", "--live-trivy", "--timeout-seconds", "1", "--no-submit");
        Assert.Equal(2, invalidTimeout.ExitCode);
        Assert.Contains("--timeout-seconds must be between", invalidTimeout.Output, StringComparison.Ordinal);

        var unavailable = RunCli(
            "gate",
            "image",
            "--image",
            "alpine:3.19",
            "--live-trivy",
            "--trivy-path",
            MissingTrivyPath(),
            "--fail-on",
            "block",
            "--no-submit");
        Assert.Equal(3, unavailable.ExitCode);
        Assert.Contains("Trivy: unavailable", unavailable.Output, StringComparison.Ordinal);
        Assert.Contains("install Trivy or use --from-trivy-json fixture mode", unavailable.Output, StringComparison.Ordinal);
        Assert.Contains("Exit code: 3", unavailable.Output, StringComparison.Ordinal);
        Assert.Contains("Result: FAIL", unavailable.Output, StringComparison.Ordinal);

        AssertSafeOutput(mixedModes.Output + invalidTimeout.Output + unavailable.Output);
    }

    [Fact]
    public void LiveTrivyImplementationUsesArgumentListAndFixtureValidationStaysOffline()
    {
        var trivyRunner = ReadRepoFile("src", "ConShield.ImageScanner", "TrivyRunner.cs");
        var processRunner = ReadRepoFile("src", "ConShield.ImageScanner", "ProcessRunner.cs");
        var fullValidation = ReadRepoFile("scripts", "Test-ConShieldFullValidation.ps1");

        Assert.Contains("ProcessStartInfo", processRunner, StringComparison.Ordinal);
        Assert.Contains("startInfo.ArgumentList.Add", processRunner, StringComparison.Ordinal);
        Assert.Contains("\"vuln,secret,misconfig\"", trivyRunner, StringComparison.Ordinal);
        Assert.Contains("TrivyReportParser.Parse", ReadRepoFile("src", "ConShield.Cli", "CicdContainerGate.cs"), StringComparison.Ordinal);
        Assert.DoesNotContain("--live-trivy", fullValidation, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("trivy image", fullValidation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DocsDashboardAndDemoMarkLiveTrivyOptionalAndReadOnly()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "CONTAINER_IMAGE_SCANNING.md"),
            ReadRepoFile("docs", "CICD_CONTAINER_GATE.md"),
            ReadRepoFile("docs", "CONSHIELD_CLI.md"),
            ReadRepoFile("docs", "GUIDED_DEMO_SCENARIO.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"));

        foreach (var expected in new[]
        {
            "--live-trivy",
            "Optional live Trivy",
            "not required for full validation",
            "Requires local Trivy",
            "scan image",
            "gate image",
            "alpine:3.19",
            "fail-on block",
            "Web UI does not execute Trivy"
        })
        {
            Assert.Contains(expected, combined, StringComparison.OrdinalIgnoreCase);
        }

        var webSource = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"));

        Assert.DoesNotContain("Process.Start", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PowerShell.Create", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("UseShellExecute", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("method=\"post\"", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fetch(", webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", combined + webSource, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN CERTIFICATE-----", combined + webSource, StringComparison.OrdinalIgnoreCase);
    }

    private static CommandResult RunCli(params string[] arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = RepoRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        psi.ArgumentList.Add("run");
        psi.ArgumentList.Add("--no-build");
        psi.ArgumentList.Add("--configuration");
        psi.ArgumentList.Add("Release");
        psi.ArgumentList.Add("--project");
        psi.ArgumentList.Add(@".\src\ConShield.Cli");
        psi.ArgumentList.Add("--");

        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start CLI.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit(120_000);

        return new CommandResult(process.ExitCode, output + error);
    }

    private static string MissingTrivyPath() => Path.Combine(Path.GetTempPath(), $"conshield-missing-trivy-{Guid.NewGuid():N}.exe");

    private static string ReadRepoFile(params string[] parts) =>
        File.ReadAllText(Path.Combine(new[] { RepoRoot() }.Concat(parts).ToArray()));

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }

    private static void AssertSafeOutput(string output)
    {
        foreach (var marker in new[]
        {
            "AdditionalDataJson",
            "PayloadJson",
            "\"Vulnerabilities\"",
            "\"Results\"",
            "\"Secrets\"",
            "CONSHIELD_",
            "api_key",
            "connection string",
            "Password=",
            "Docker logs",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----",
            "signing key"
        })
        {
            Assert.DoesNotContain(marker, output, StringComparison.OrdinalIgnoreCase);
        }
    }

    private sealed record CommandResult(int ExitCode, string Output);
}
