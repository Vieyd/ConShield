using System.Diagnostics;

namespace ConShield.Tests;

public sealed class UnifiedCliTests
{
    [Fact]
    public void SolutionIncludesUnifiedCliProject()
    {
        var solution = ReadRepoFile("ConShield.sln");

        Assert.Contains("ConShield.Cli", solution, StringComparison.Ordinal);
        Assert.Contains(@"src\ConShield.Cli\ConShield.Cli.csproj", solution, StringComparison.Ordinal);
    }

    [Fact]
    public void HelpListsRequiredCommandGroups()
    {
        var result = RunCli("--help");

        Assert.Equal(0, result.ExitCode);
        foreach (var expected in new[]
        {
            "ConShield CLI",
            "validate",
            "demo readiness",
            "demo reset",
            "scan image",
            "gate image",
            "run protected",
            "sensor replay",
            "lifecycle replay",
            "evidence export"
        })
        {
            Assert.Contains(expected, result.Output, StringComparison.Ordinal);
        }

        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void ValidateRunsDeterministicConfigChecks()
    {
        var result = RunCli("validate");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Step: SIEM rules", result.Output, StringComparison.Ordinal);
        Assert.Contains("Step: Container policy", result.Output, StringComparison.Ordinal);
        Assert.Contains("Step: Sensor registry", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void ImageScanFixtureNoSubmitSucceedsWithoutNetworkOrWeb()
    {
        var result = RunCli(
            "scan",
            "image",
            "--from-trivy-json",
            @".\tests\TestData\Trivy\sample-image-scan.json",
            "--no-submit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Command: scan image", result.Output, StringComparison.Ordinal);
        Assert.Contains("Ingestion: SKIP", result.Output, StringComparison.Ordinal);
        Assert.Contains("Expected rule: IMG-001", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void ProtectedRunFixtureNoRunNoSubmitSucceedsWithoutDockerOrWeb()
    {
        var result = RunCli(
            "run",
            "protected",
            "--image",
            "demo/insecure-api:latest",
            "--container-name",
            "conshield-demo-insecure",
            "--from-trivy-json",
            @".\tests\TestData\Trivy\sample-image-scan.json",
            "--no-run",
            "--no-submit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Command: run protected", result.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void SignedSensorReplayNoSubmitSucceedsWithoutFedoraFalcoOrWeb()
    {
        var result = RunCli("sensor", "replay", "--demo-signature", "--no-submit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Command: sensor replay", result.Output, StringComparison.Ordinal);
        Assert.Contains("Signature: Valid", result.Output, StringComparison.Ordinal);
        Assert.Contains("Expected rules: RTE-001", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void DemoResetRequiresExplicitConfirm()
    {
        var result = RunCli("demo", "reset");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Reset requires explicit --confirm", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("ConfirmReset", result.Output, StringComparison.OrdinalIgnoreCase);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void InvalidCommandReturnsNonZeroAndSafeUsage()
    {
        var result = RunCli("bogus");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Usage error", result.Output, StringComparison.Ordinal);
        Assert.Contains("Commands:", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void CliUsesProcessArgumentListAndDoesNotUseShellCommandStrings()
    {
        var program = ReadRepoFile("src", "ConShield.Cli", "Program.cs");

        Assert.Contains("startInfo.ArgumentList.Add", program, StringComparison.Ordinal);
        Assert.Contains("UseShellExecute = false", program, StringComparison.Ordinal);
        Assert.DoesNotContain("cmd.exe", program, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("powershell.exe -Command", program, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("pwsh -Command", program, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("UseShellExecute = true", program, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DemoReadinessAndDocsMentionUnifiedCliAlternatives()
    {
        var combined = string.Join(
            "\n",
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1"),
            ReadRepoFile("docs", "CONSHIELD_CLI.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("README.md"));

        foreach (var expected in new[]
        {
            "dotnet run --project .\\src\\ConShield.Cli -- --help",
            "dotnet run --project .\\src\\ConShield.Cli -- validate",
            "dotnet run --project .\\src\\ConShield.Cli -- scan image",
            "dotnet run --project .\\src\\ConShield.Cli -- gate image",
            "dotnet run --project .\\src\\ConShield.Cli -- run protected",
            "dotnet run --project .\\src\\ConShield.Cli -- lifecycle replay",
            "dotnet run --project .\\src\\ConShield.Cli -- sensor replay",
            "dotnet run --project .\\src\\ConShield.Cli -- evidence export",
            "demo reset --confirm"
        })
        {
            Assert.Contains(expected, combined, StringComparison.Ordinal);
        }

        Assert.Contains("ConShield.Cli              Unified local CLI wrapper", ReadRepoFile("README.md"), StringComparison.Ordinal);
        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN CERTIFICATE-----", combined, StringComparison.OrdinalIgnoreCase);
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
