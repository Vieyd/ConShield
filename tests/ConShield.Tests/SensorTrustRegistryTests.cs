using System.Diagnostics;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class SensorTrustRegistryTests
{
    [Fact]
    public void DefaultSensorRegistry_ExistsValidatesAndMapsDemoFalcoSourceToTrusted()
    {
        var path = Path.Combine(GetRepositoryRoot(), "config", "sensor-registry.default.json");
        var text = File.ReadAllText(path);

        Assert.Contains("\"version\": 1", text, StringComparison.Ordinal);
        Assert.Contains("demo-falco-linux-01", text, StringComparison.Ordinal);
        Assert.Contains(SecuritySourceSystems.FalcoLinuxSensor, text, StringComparison.Ordinal);
        Assert.Contains("\"status\": \"Trusted\"", text, StringComparison.Ordinal);

        var registry = SensorTrustRegistryLoader.LoadFromFile(path, GetRepositoryRoot());
        var sensor = registry.FindBySourceSystem(SecuritySourceSystems.FalcoLinuxSensor);

        Assert.NotNull(sensor);
        Assert.Equal("demo-falco-linux-01", sensor.SensorId);
        Assert.Equal(SensorTrustStatuses.Trusted, sensor.Status);
        Assert.Contains("container.runtime.shell_spawned", sensor.ExpectedEventTypes);

        var result = RunPwsh("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\Test-ConShieldSensorRegistry.ps1");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("ConShield sensor registry validation", result.Output, StringComparison.Ordinal);
        Assert.Contains("Config: config/sensor-registry.default.json", result.Output, StringComparison.Ordinal);
        Assert.Contains("Sensors: 4", result.Output, StringComparison.Ordinal);
        Assert.Contains("Trusted: 2", result.Output, StringComparison.Ordinal);
        Assert.Contains("Revoked: 1", result.Output, StringComparison.Ordinal);
        Assert.Contains("Disabled: 1", result.Output, StringComparison.Ordinal);
        Assert.Contains("demo-falco-linux-01: OK", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void InvalidSensorRegistry_FailsWithSafeDiagnostics()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"conshield-invalid-sensor-registry-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(tempPath, """
            {
              "version": 1,
              "sensors": [
                {
                  "sensorId": "bad-sensor",
                  "displayName": "Bad Sensor",
                  "sourceSystem": "conshield.bad-runtime",
                  "status": "Broken",
                  "expectedEventTypes": [ "container.runtime.shell_spawned" ]
                }
              ]
            }
            """);

            var result = RunPwsh("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\Test-ConShieldSensorRegistry.ps1", "-ConfigPath", tempPath);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("Failed sensor: bad-sensor", result.Output, StringComparison.Ordinal);
            Assert.Contains("status must be Trusted, Unknown, Revoked, or Disabled", result.Output, StringComparison.Ordinal);
            Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
            AssertSafeOutput(result.Output);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    [Fact]
    public void SensorRegistryLoader_RejectsDuplicateIdsAndCertificateBlocks()
    {
        var duplicatePath = Path.Combine(Path.GetTempPath(), $"conshield-duplicate-sensor-registry-{Guid.NewGuid():N}.json");
        var certificatePath = Path.Combine(Path.GetTempPath(), $"conshield-certificate-sensor-registry-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(duplicatePath, """
            {
              "version": 1,
              "sensors": [
                { "sensorId": "dup", "displayName": "One", "sourceSystem": "conshield.one", "status": "Trusted" },
                { "sensorId": "dup", "displayName": "Two", "sourceSystem": "conshield.two", "status": "Trusted" }
              ]
            }
            """);

            File.WriteAllText(certificatePath, """
            {
              "version": 1,
              "sensors": [
                {
                  "sensorId": "cert",
                  "displayName": "Cert",
                  "sourceSystem": "conshield.cert",
                  "status": "Trusted",
                  "fingerprintSha256": "PRIVATE KEY material is not allowed"
                }
              ]
            }
            """);

            Assert.Throws<InvalidDataException>(() => SensorTrustRegistryLoader.LoadFromFile(duplicatePath));
            Assert.Throws<InvalidDataException>(() => SensorTrustRegistryLoader.LoadFromFile(certificatePath));
        }
        finally
        {
            File.Delete(duplicatePath);
            File.Delete(certificatePath);
        }
    }

    [Fact]
    public async Task RuntimeSensorHealth_EnrichesTrustStatusAndUnknownSources()
    {
        await using var db = CreateDbContext();
        var now = new DateTime(2026, 06, 29, 12, 0, 0, DateTimeKind.Utc);
        db.SecurityEvents.Add(RuntimeEvent(SecuritySourceSystems.FalcoLinuxSensor, "container.runtime.shell_spawned", now.AddMinutes(-5), EventSeverity.High));
        db.SecurityEvents.Add(RuntimeEvent("conshield.unknown-falco", "container.runtime.custom", now.AddMinutes(-4), EventSeverity.Warning));
        await db.SaveChangesAsync();

        var registry = SensorTrustRegistryLoader.LoadFromFile(
            Path.Combine(GetRepositoryRoot(), "config", "sensor-registry.default.json"),
            GetRepositoryRoot());
        var result = await new RuntimeSensorHealthService(db, registry)
            .GetAsync(new RuntimeSensorHealthOptions(now, TimeSpan.FromHours(24)));

        var trusted = result.Sources.Single(x => x.SourceSystem == SecuritySourceSystems.FalcoLinuxSensor);
        Assert.Equal("demo-falco-linux-01", trusted.SensorId);
        Assert.Equal(SensorTrustStatuses.Trusted, trusted.TrustStatus);
        Assert.Equal("local-demo", trusted.Environment);

        var unknown = result.Sources.Single(x => x.SourceSystem == "conshield.unknown-falco");
        Assert.Equal("-", unknown.SensorId);
        Assert.Equal(SensorTrustStatuses.Unknown, unknown.TrustStatus);
    }

    [Fact]
    public async Task RuntimeSensorHealth_RepresentsRevokedAndDisabledRegistrySourcesSafely()
    {
        await using var db = CreateDbContext();
        var now = new DateTime(2026, 06, 29, 12, 0, 0, DateTimeKind.Utc);
        var registry = new SensorTrustRegistry(
            1,
            "test",
            new[]
            {
                new SensorTrustRegistryEntry("revoked-runtime", "Revoked Runtime", "conshield.revoked-falco", "test", SensorTrustStatuses.Revoked, Array.Empty<string>(), null, null),
                new SensorTrustRegistryEntry("disabled-runtime", "Disabled Runtime", "conshield.disabled-falco", "test", SensorTrustStatuses.Disabled, Array.Empty<string>(), null, null)
            });

        var result = await new RuntimeSensorHealthService(db, registry)
            .GetAsync(new RuntimeSensorHealthOptions(now, TimeSpan.FromHours(24)));

        Assert.Equal(SensorTrustStatuses.Revoked, result.Sources.Single(x => x.SourceSystem == "conshield.revoked-falco").TrustStatus);
        Assert.Equal(SensorTrustStatuses.Disabled, result.Sources.Single(x => x.SourceSystem == "conshield.disabled-falco").TrustStatus);
        Assert.All(result.Sources, row => Assert.NotEqual("AdditionalDataJson", row.DisplayName));
    }

    [Fact]
    public void ReplayEvidenceReadinessDemoAndDocsContainSensorTrustHooks()
    {
        var replay = RunPwsh("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1", "-NoSubmit");

        Assert.Equal(0, replay.ExitCode);
        Assert.Contains("SensorId: demo-falco-linux-01", replay.Output, StringComparison.Ordinal);
        Assert.Contains("Sensor trust: Trusted", replay.Output, StringComparison.Ordinal);
        Assert.Contains("SourceSystem: conshield.falco-linux-sensor", replay.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", replay.Output, StringComparison.Ordinal);
        AssertSafeOutput(replay.Output);

        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1"),
            ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "RuntimeSensors", "Index.cshtml"),
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "SENSOR_TRUST_REGISTRY.md"));

        Assert.Contains("Sensor Trust Evidence", combined, StringComparison.Ordinal);
        Assert.Contains("Test-ConShieldSensorRegistry.ps1", combined, StringComparison.Ordinal);
        Assert.Contains("Sensor registry validation", combined, StringComparison.Ordinal);
        Assert.Contains("config/sensor-registry.default.json", combined, StringComparison.Ordinal);
        Assert.Contains("TrustStatus", combined, StringComparison.Ordinal);
        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN CERTIFICATE-----", combined, StringComparison.OrdinalIgnoreCase);
    }

    private static SecurityEventEntry RuntimeEvent(
        string sourceSystem,
        string externalEventType,
        DateTime occurredAtUtc,
        EventSeverity severity) =>
        new()
        {
            OccurredAtUtc = occurredAtUtc,
            EventType = SecurityEventType.ExternalEvent,
            Severity = severity,
            SourceSystem = sourceSystem,
            ExternalEventType = externalEventType,
            Description = $"Runtime event {externalEventType}."
        };

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"sensor-trust-registry-{Guid.NewGuid():N}")
            .Options;
        return new ApplicationDbContext(options);
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
            "AdditionalDataJson",
            "PayloadJson",
            "CONSHIELD_",
            "api_key",
            "api key",
            "connection string",
            "password",
            "token",
            "-----BEGIN",
            "PRIVATE KEY",
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
