using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ConShield.Tests;

public sealed class ContainerPolicyAsCodeTests
{
    [Fact]
    public void DefaultContainerPolicyConfig_ExistsValidatesAndKeepsExpectedRules()
    {
        var path = Path.Combine(GetRepositoryRoot(), "config", "container-policy.default.json");
        var text = File.ReadAllText(path);

        Assert.Contains("\"version\": 1", text, StringComparison.Ordinal);
        Assert.Contains("\"defaultDecision\": \"Allow\"", text, StringComparison.Ordinal);
        Assert.Contains("POLICY-CRITICAL-VULN-BLOCK", text, StringComparison.Ordinal);
        Assert.Contains("POLICY-HIGH-VULN-WARN", text, StringComparison.Ordinal);

        var result = RunPwsh("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\Test-ConShieldContainerPolicy.ps1");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("ConShield container policy validation", result.Output, StringComparison.Ordinal);
        Assert.Contains("Config: config/container-policy.default.json", result.Output, StringComparison.Ordinal);
        Assert.Contains("Default decision: Allow", result.Output, StringComparison.Ordinal);
        Assert.Contains("POLICY-CRITICAL-VULN-BLOCK: OK", result.Output, StringComparison.Ordinal);
        Assert.Contains("POLICY-HIGH-VULN-WARN: OK", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void InvalidContainerPolicyConfig_FailsWithSafeMessage()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"conshield-invalid-container-policy-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(tempPath, """
            {
              "version": 1,
              "policyId": "container-policy-as-code",
              "policyVersion": "1.0.0",
              "defaultDecision": "Allow",
              "rules": [
                {
                  "id": "POLICY-BAD",
                  "enabled": true,
                  "name": "Bad rule",
                  "match": { "criticalVulnerabilitiesAtLeast": -1 },
                  "decision": "Block",
                  "reason": "bad"
                }
              ]
            }
            """);

            var result = RunPwsh("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\Test-ConShieldContainerPolicy.ps1", "-ConfigPath", tempPath);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("Failed rule: POLICY-BAD", result.Output, StringComparison.Ordinal);
            Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
            AssertSafeOutput(result.Output);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    [Fact]
    public void ProtectedRunFixtures_MapToBlockWarnAndAllowWithMatchedPolicyRules()
    {
        var block = RunProtectedFixture("sample-image-scan.json", "demo/insecure-api:latest", "conshield-demo-insecure", "-NoRun", "-NoSubmit", "-Execute");
        var warn = RunProtectedFixture("warn-image-scan.json", "demo/warn-api:latest", "conshield-demo-warn", "-NoSubmit");
        var clean = RunProtectedFixture("clean-image-scan.json", "demo/clean-api:latest", "conshield-demo-clean", "-NoRun", "-NoSubmit");

        Assert.Equal(0, block.ExitCode);
        Assert.Contains("Policy: Block", block.Output, StringComparison.Ordinal);
        Assert.Contains("Matched policy rules: POLICY-CRITICAL-VULN-BLOCK", block.Output, StringComparison.Ordinal);
        Assert.Contains("Policy config: config/container-policy.default.json", block.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (blocked by policy)", block.Output, StringComparison.Ordinal);

        Assert.Equal(0, warn.ExitCode);
        Assert.Contains("Policy: Warn", warn.Output, StringComparison.Ordinal);
        Assert.Contains("Matched policy rules: POLICY-HIGH-VULN-WARN", warn.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (requires -AcceptWarning and -Execute)", warn.Output, StringComparison.Ordinal);

        Assert.Equal(0, clean.ExitCode);
        Assert.Contains("Policy: Allow", clean.Output, StringComparison.Ordinal);
        Assert.Contains("Matched policy rules: -", clean.Output, StringComparison.Ordinal);
        Assert.Contains("Launch: Skipped (NoRun requested)", clean.Output, StringComparison.Ordinal);

        foreach (var output in new[] { block.Output, warn.Output, clean.Output })
        {
            Assert.Contains("IMG event: SKIP", output, StringComparison.Ordinal);
            Assert.Contains("POL event: SKIP", output, StringComparison.Ordinal);
            Assert.Contains("LIFE event: SKIP", output, StringComparison.Ordinal);
            AssertSafeOutput(output);
        }
    }

    [Fact]
    public void ProtectedRun_BlockOverridesWarnAndDisabledRuleDoesNotAffectDecision()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"conshield-container-policy-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(tempPath, """
            {
              "version": 1,
              "policyId": "container-policy-as-code",
              "policyVersion": "1.0.0",
              "defaultDecision": "Allow",
              "rules": [
                {
                  "id": "POLICY-DISABLED-BLOCK",
                  "enabled": false,
                  "name": "Disabled block",
                  "match": { "highVulnerabilitiesAtLeast": 1 },
                  "decision": "Block",
                  "reason": "Disabled rule should not match."
                },
                {
                  "id": "POLICY-HIGH-VULN-WARN",
                  "enabled": true,
                  "name": "Warn on high vulnerabilities",
                  "match": { "highVulnerabilitiesAtLeast": 1 },
                  "decision": "Warn",
                  "reason": "Image contains high vulnerabilities."
                },
                {
                  "id": "POLICY-CRITICAL-VULN-BLOCK",
                  "enabled": true,
                  "name": "Block critical vulnerabilities",
                  "match": { "criticalVulnerabilitiesAtLeast": 1 },
                  "decision": "Block",
                  "reason": "Image contains critical vulnerabilities."
                }
              ]
            }
            """);

            var result = RunProtectedFixture(
                "sample-image-scan.json",
                "demo/insecure-api:latest",
                "conshield-demo-insecure",
                "-NoRun",
                "-NoSubmit",
                "-PolicyPath",
                tempPath);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("Policy: Block", result.Output, StringComparison.Ordinal);
            Assert.Contains("Matched policy rules: POLICY-CRITICAL-VULN-BLOCK", result.Output, StringComparison.Ordinal);
            Assert.DoesNotContain("POLICY-DISABLED-BLOCK", result.Output, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    [Fact]
    public void EvidenceReadinessDemoAndDocsContainContainerPolicyHooks()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1"),
            ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("README.md"));

        Assert.Contains("Container Policy Evidence", combined, StringComparison.Ordinal);
        Assert.Contains("Test-ConShieldContainerPolicy.ps1", combined, StringComparison.Ordinal);
        Assert.Contains("Container policy validation", combined, StringComparison.Ordinal);
        Assert.Contains("config/container-policy.default.json", combined, StringComparison.Ordinal);
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
            "password",
            "token",
            "Docker logs"
        })
        {
            Assert.DoesNotContain(marker, output, StringComparison.OrdinalIgnoreCase);
        }
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
