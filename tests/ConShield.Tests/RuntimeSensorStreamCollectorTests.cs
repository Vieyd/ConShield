using ConShield.Cli;

namespace ConShield.Tests;

public sealed class RuntimeSensorStreamCollectorTests
{
    [Fact]
    public void FixtureExistsAndIsJsonLinesWithOneSafeMalformedLine()
    {
        var fixture = ReadRepoFile("tests", "TestData", "Falco", "falco-runtime-stream.jsonl");
        var lines = fixture.Split(["\r\n", "\n"], StringSplitOptions.None).Where(x => x.Length > 0).ToArray();

        Assert.True(lines.Length >= 5);
        Assert.Contains("ConShield Safe Demo Shell in Container", fixture, StringComparison.Ordinal);
        Assert.Contains("Write below etc", fixture, StringComparison.Ordinal);
        Assert.Contains("Launch Suspicious Network Tool in Container", fixture, StringComparison.Ordinal);
        Assert.Contains("{malformed-safe-demo-line", fixture, StringComparison.Ordinal);
        Assert.DoesNotContain("password", fixture, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api_key", fixture, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN", fixture, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SensorCollectFixtureNoSubmitSucceedsWithoutFedoraFalcoOrWeb()
    {
        var result = await RunCollectorAsync(
            "--from-json-lines",
            @".\tests\TestData\Falco\falco-runtime-stream.jsonl",
            "--demo-signature",
            "--no-submit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Command: sensor collect", result.Output, StringComparison.Ordinal);
        Assert.Contains("ConShield runtime sensor stream collector", result.Output, StringComparison.Ordinal);
        Assert.Contains("Mode: json-lines", result.Output, StringComparison.Ordinal);
        Assert.Contains("Sensor trust: Trusted", result.Output, StringComparison.Ordinal);
        Assert.Contains("Signature mode: Demo", result.Output, StringComparison.Ordinal);
        Assert.Contains("Events read: 5", result.Output, StringComparison.Ordinal);
        Assert.Contains("Events normalized: 4", result.Output, StringComparison.Ordinal);
        Assert.Contains("Events skipped: 1", result.Output, StringComparison.Ordinal);
        Assert.Contains("Skip reasons: malformed_json=1", result.Output, StringComparison.Ordinal);
        Assert.Contains("Signature statuses: Valid", result.Output, StringComparison.Ordinal);
        Assert.Contains("Events submitted: 0", result.Output, StringComparison.Ordinal);
        Assert.Contains("Ingestion: SKIP", result.Output, StringComparison.Ordinal);
        Assert.Contains("Expected rules: RTE-001,SENSOR-001,SENSOR-002,SIGN-001,SIGN-002,SIGN-003", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Theory]
    [InlineData("--simulate-unknown-sensor", "Sensor trust: Unknown", "Enforcement: AcceptUnknownWithAlert")]
    [InlineData("--simulate-revoked-sensor", "Sensor trust: Revoked", "Enforcement: FlagRevokedWithAlert")]
    [InlineData("--simulate-disabled-sensor", "Sensor trust: Disabled", "Enforcement: FlagDisabledWithAlert")]
    [InlineData("--simulate-missing-signature", "Signature mode: Missing", "Signature statuses: Missing")]
    [InlineData("--simulate-invalid-signature", "Signature mode: Invalid", "Signature statuses: Invalid")]
    [InlineData("--simulate-stale-signature", "Signature mode: Stale", "Signature statuses: Stale")]
    [InlineData("--simulate-replay-signature", "Signature mode: ReplayDetected", "Signature statuses: ReplayDetected")]
    public async Task SensorCollectSimulationModesAreDeterministicAndSafe(string flag, string expectedFirst, string expectedSecond)
    {
        var args = new List<string>
        {
            "--from-json-lines",
            @".\tests\TestData\Falco\falco-runtime-stream.jsonl",
            "--no-submit",
            flag
        };

        var result = await RunCollectorAsync(args.ToArray());

        Assert.Equal(0, result.ExitCode);
        Assert.Contains(expectedFirst, result.Output, StringComparison.Ordinal);
        Assert.Contains(expectedSecond, result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public async Task SensorCollectDeterministicEventIdsAreStableAcrossRuns()
    {
        var first = await RunCollectorAsync("--from-json-lines", @".\tests\TestData\Falco\falco-runtime-stream.jsonl", "--demo-signature", "--no-submit");
        var second = await RunCollectorAsync("--from-json-lines", @".\tests\TestData\Falco\falco-runtime-stream.jsonl", "--demo-signature", "--no-submit");

        Assert.Equal(0, first.ExitCode);
        Assert.Equal(0, second.ExitCode);
        Assert.Equal(ExternalIds(first.Output), ExternalIds(second.Output));
    }

    [Fact]
    public async Task SensorCollectSubmitFailsSafelyWhenLocalWebUnavailable()
    {
        var result = await RunCollectorAsync(
            "--from-json-lines",
            @".\tests\TestData\Falco\falco-runtime-stream.jsonl",
            "--demo-signature",
            "--submit",
            "--base-url",
            "http://127.0.0.1:9");

        Assert.Equal(3, result.ExitCode);
        Assert.Contains("Web: FAIL", result.Output, StringComparison.Ordinal);
        Assert.Contains("Events submitted: 0", result.Output, StringComparison.Ordinal);
        Assert.Contains("Hint: start local services", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void DashboardDemoDocsExposeCollectorAsReadOnlyCopyPasteReference()
    {
        var combined = string.Join(
            "\n",
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("docs", "CONSHIELD_CLI.md"),
            ReadRepoFile("docs", "FALCO_RUNTIME_SENSOR.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("README.md"));

        Assert.Contains("sensor collect", combined, StringComparison.Ordinal);
        Assert.Contains("falco-runtime-stream.jsonl", combined, StringComparison.Ordinal);
        Assert.Contains("Runtime Sensor Stream Collector", combined, StringComparison.Ordinal);
        Assert.Contains("Web UI does not execute", combined, StringComparison.OrdinalIgnoreCase);

        var webControllers = ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs")
            + ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs");
        Assert.DoesNotContain("ProcessStartInfo", webControllers, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cmd.exe", webControllers, StringComparison.OrdinalIgnoreCase);
    }

    private static string ExternalIds(string output)
    {
        var line = output.Split(["\r\n", "\n"], StringSplitOptions.None)
            .Single(x => x.StartsWith("ExternalEventIds:", StringComparison.Ordinal));
        return line["ExternalEventIds:".Length..].Trim();
    }

    private static async Task<CommandResult> RunCollectorAsync(params string[] arguments)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exitCode = await RuntimeSensorStreamCollector.RunAsync(
            RepoRoot(),
            arguments,
            new StringReader(string.Empty),
            output,
            error);

        return new CommandResult(exitCode, output.ToString() + error);
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
            "\"output_fields\"",
            "\"output\"",
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
