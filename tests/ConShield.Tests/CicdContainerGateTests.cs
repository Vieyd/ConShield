using ConShield.Cli;

namespace ConShield.Tests;

public sealed class CicdContainerGateTests
{
    private static readonly string PrivateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";
    private static readonly string CertificateMarker = "-----BEGIN " + "CERTIFICATE-----";

    [Fact]
    public void CleanFixtureWithFailOnBlockExitsZero()
    {
        var result = RunGate(
            "--image", "demo/clean-api:latest",
            "--from-trivy-json", FixturePath("clean-image-scan.json"),
            "--fail-on", "block",
            "--no-submit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Policy: Allow", result.Output, StringComparison.Ordinal);
        Assert.Contains("Gate: PASS", result.Output, StringComparison.Ordinal);
        Assert.Contains("Exit code: 0", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void WarnFixtureWithFailOnBlockExitsZero()
    {
        var result = RunGate(
            "--image", "demo/warn-api:latest",
            "--from-trivy-json", FixturePath("warn-image-scan.json"),
            "--fail-on", "block",
            "--no-submit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Policy: Warn", result.Output, StringComparison.Ordinal);
        Assert.Contains("Matched policy rules: POLICY-HIGH-VULN-WARN", result.Output, StringComparison.Ordinal);
        Assert.Contains("Gate: PASS_WITH_FINDINGS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void WarnFixtureWithFailOnWarnExitsPolicyFailure()
    {
        var result = RunGate(
            "--image", "demo/warn-api:latest",
            "--from-trivy-json", FixturePath("warn-image-scan.json"),
            "--fail-on", "warn",
            "--no-submit");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Policy: Warn", result.Output, StringComparison.Ordinal);
        Assert.Contains("Gate: FAIL", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void BlockFixtureWithFailOnBlockExitsPolicyFailure()
    {
        var result = RunGate(
            "--image", "demo/insecure-api:latest",
            "--from-trivy-json", FixturePath("sample-image-scan.json"),
            "--fail-on", "block",
            "--no-submit");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Policy: Block", result.Output, StringComparison.Ordinal);
        Assert.Contains("Matched policy rules: POLICY-CRITICAL-VULN-BLOCK", result.Output, StringComparison.Ordinal);
        Assert.Contains("Gate: FAIL", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void BlockFixtureWithFailOnNeverExitsZeroAndShowsFindings()
    {
        var result = RunGate(
            "--image", "demo/insecure-api:latest",
            "--from-trivy-json", FixturePath("sample-image-scan.json"),
            "--fail-on", "never",
            "--no-submit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Policy: Block", result.Output, StringComparison.Ordinal);
        Assert.Contains("Critical vulnerabilities: 1", result.Output, StringComparison.Ordinal);
        Assert.Contains("High vulnerabilities: 1", result.Output, StringComparison.Ordinal);
        Assert.Contains("Gate: PASS_WITH_FINDINGS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void MissingFixturePathReturnsUsageError()
    {
        var result = RunGate(
            "--image", "demo/missing-api:latest",
            "--from-trivy-json", FixturePath("missing-image-scan.json"),
            "--no-submit");

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Usage error:", result.Error, StringComparison.Ordinal);
        Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output + result.Error);
    }

    [Fact]
    public void InvalidFailOnReturnsUsageError()
    {
        var result = RunGate(
            "--image", "demo/warn-api:latest",
            "--from-trivy-json", FixturePath("warn-image-scan.json"),
            "--fail-on", "critical",
            "--no-submit");

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("--fail-on must be block, warn, or never", result.Error, StringComparison.Ordinal);
        AssertSafeOutput(result.Output + result.Error);
    }

    [Fact]
    public void MarkdownReportIsCreatedAndSanitized()
    {
        var reportPath = Path.Combine(Path.GetTempPath(), $"conshield-cicd-gate-{Guid.NewGuid():N}.md");
        try
        {
            var result = RunGate(
                "--image", "demo/insecure-api:latest",
                "--from-trivy-json", FixturePath("sample-image-scan.json"),
                "--fail-on", "never",
                "--report", reportPath,
                "--no-submit");

            Assert.Equal(0, result.ExitCode);
            Assert.True(File.Exists(reportPath));
            var report = File.ReadAllText(reportPath);
            Assert.Contains("# ConShield CI/CD Gate Report", report, StringComparison.Ordinal);
            Assert.Contains("- Decision: Block", report, StringComparison.Ordinal);
            Assert.Contains("- Gate: PASS_WITH_FINDINGS", report, StringComparison.Ordinal);
            Assert.Contains("- Matched policy rules: POLICY-CRITICAL-VULN-BLOCK", report, StringComparison.Ordinal);
            AssertSafeReport(report);
            AssertSafeOutput(result.Output + result.Error);
        }
        finally
        {
            File.Delete(reportPath);
        }
    }

    [Fact]
    public void SubmitModeFailsClosedAsInfrastructureErrorInV1()
    {
        var result = RunGate(
            "--image", "demo/clean-api:latest",
            "--from-trivy-json", FixturePath("clean-image-scan.json"),
            "--submit");

        Assert.Equal(3, result.ExitCode);
        Assert.Contains("Submit: unsupported", result.Error, StringComparison.Ordinal);
        Assert.Contains("Exit code: 3", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output + result.Error);
    }

    [Fact]
    public void ReadinessDemoDocsAndReadmeContainGateHooks()
    {
        var combined = string.Join(
            "\n",
            ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("docs", "CICD_CONTAINER_GATE.md"),
            ReadRepoFile("docs", "CONSHIELD_CLI.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("README.md"));

        foreach (var expected in new[]
        {
            "dotnet run --project .\\src\\ConShield.Cli -- gate image",
            "CI/CD container gate",
            "--fail-on never",
            "CICD_CONTAINER_GATE.md",
            "0` means passed",
            "1` means failed by policy"
        })
        {
            Assert.Contains(expected, combined, StringComparison.Ordinal);
        }

        Assert.DoesNotContain(PrivateKeyMarker, combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(CertificateMarker, combined, StringComparison.OrdinalIgnoreCase);
    }

    private static GateCommandResult RunGate(params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exitCode = CicdContainerGate.RunImageGate(RepoRoot(), args, output, error);
        return new GateCommandResult(exitCode, output.ToString(), error.ToString());
    }

    private static string ReadRepoFile(params string[] parts) =>
        File.ReadAllText(Path.Combine(new[] { RepoRoot() }.Concat(parts).ToArray()));

    private static string FixturePath(string fileName) =>
        Path.Combine(RepoRoot(), "tests", "TestData", "Trivy", fileName);

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
            "\"Vulnerabilities\"",
            "\"Results\"",
            "AdditionalDataJson",
            "PayloadJson",
            "CONSHIELD_",
            "api_key",
            "api key",
            "connection string",
            "Password=",
            "Docker logs",
            PrivateKeyMarker,
            CertificateMarker,
            "signing key"
        })
        {
            Assert.DoesNotContain(marker, output, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static void AssertSafeReport(string report)
    {
        foreach (var marker in new[]
        {
            "\"Vulnerabilities\"",
            "\"Results\"",
            "AdditionalDataJson",
            "PayloadJson",
            "CONSHIELD_",
            "api_key",
            "Password=",
            PrivateKeyMarker,
            CertificateMarker
        })
        {
            Assert.DoesNotContain(marker, report, StringComparison.OrdinalIgnoreCase);
        }
    }

    private sealed record GateCommandResult(int ExitCode, string Output, string Error);
}
