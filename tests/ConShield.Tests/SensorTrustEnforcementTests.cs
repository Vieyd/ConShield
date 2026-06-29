using System.Diagnostics;
using System.Text.Json;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class SensorTrustEnforcementTests
{
    [Fact]
    public async Task TrustedRuntimeSensor_KeepsRteBehaviorAndDoesNotCreateSensorTrustAlert()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, SecuritySourceSystems.FalcoLinuxSensor, "trusted-container");
        await db.SaveChangesAsync();

        var result = await CreateService(db, DefaultRegistry()).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal("RTE-001", (await db.SiemAlerts.SingleAsync()).RuleCode);
        Assert.Equal(0, await db.SiemAlerts.CountAsync(x => x.RuleCode == "SENSOR-001" || x.RuleCode == "SENSOR-002"));
    }

    [Fact]
    public async Task UnknownRuntimeSensor_CreatesSensor001WithoutIncident()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, "conshield.falco-unknown-sensor", "unknown-container");
        await db.SaveChangesAsync();

        var result = await CreateService(db, DefaultRegistry()).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(0, result.CreatedIncidents);
        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("SENSOR-001", alert.RuleCode);
        Assert.Equal(EventSeverity.High, alert.Severity);
        Assert.Contains("AcceptUnknownWithAlert", alert.Description, StringComparison.Ordinal);
        Assert.Contains("trustStatus=Unknown", alert.Description, StringComparison.Ordinal);
        Assert.DoesNotContain("AdditionalDataJson", alert.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ContainerLaunchResult_DoesNotCreateSensorTrustAlert()
    {
        await using var db = CreateDbContext();
        db.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = "container.image.launch.result",
            Severity = EventSeverity.Info,
            SourceSystem = "conshield.container-runtime",
            Description = "Protected run launch result."
        });
        await db.SaveChangesAsync();

        var result = await CreateService(db, DefaultRegistry()).RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Empty(await db.SiemAlerts.ToListAsync());
    }

    [Theory]
    [InlineData("conshield.falco-revoked-sensor", "Revoked", "FlagRevokedWithAlert")]
    [InlineData("conshield.falco-disabled-sensor", "Disabled", "FlagDisabledWithAlert")]
    public async Task RevokedOrDisabledRuntimeSensor_CreatesSensor002Incident(
        string sourceSystem,
        string expectedTrust,
        string expectedAction)
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, sourceSystem, "untrusted-container");
        await db.SaveChangesAsync();

        var result = await CreateService(db, DefaultRegistry()).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);
        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("SENSOR-002", alert.RuleCode);
        Assert.Equal(EventSeverity.Critical, alert.Severity);
        Assert.Contains($"trustStatus={expectedTrust}", alert.Description, StringComparison.Ordinal);
        Assert.Contains(expectedAction, alert.Description, StringComparison.Ordinal);
        Assert.Equal(alert.IncidentId, (await db.Incidents.SingleAsync()).Id);
    }

    [Fact]
    public async Task RuntimeSensorHealth_IncludesEnforcementAndSensorTrustAlertCounts()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, "conshield.falco-unknown-sensor", "unknown-container");
        await db.SaveChangesAsync();
        var eventId = await db.SecurityEvents.Select(x => x.Id).SingleAsync();
        db.SiemAlerts.Add(new SiemAlertRecord
        {
            CreatedAtUtc = DateTime.UtcNow,
            RuleCode = "SENSOR-001",
            RuleName = "Unknown runtime sensor source",
            TriggerKey = "SENSOR-001:conshield.falco-unknown-sensor",
            Severity = EventSeverity.High,
            Status = AlertStatuses.New,
            Description = "Sensor trust enforcement AcceptUnknownWithAlert.",
            SourceEventIdsJson = JsonSerializer.Serialize(new[] { eventId })
        });
        await db.SaveChangesAsync();

        var health = await new RuntimeSensorHealthService(db, DefaultRegistry()).GetAsync();
        var row = health.Sources.Single(x => x.SourceSystem == "conshield.falco-unknown-sensor");

        Assert.Equal(SensorTrustStatuses.Unknown, row.TrustStatus);
        Assert.Equal(SensorTrustEnforcementActions.AcceptUnknownWithAlert, row.EnforcementAction);
        Assert.Equal(1, row.RelatedSensorTrustAlertCount);
    }

    [Theory]
    [InlineData("", "Sensor trust: Trusted", "Enforcement: AcceptTrusted", "Expected rule: RTE-001")]
    [InlineData("-SimulateUnknownSensor", "Sensor trust: Unknown", "Enforcement: AcceptUnknownWithAlert", "Expected rule: SENSOR-001")]
    [InlineData("-SimulateRevokedSensor", "Sensor trust: Revoked", "Enforcement: FlagRevokedWithAlert", "Expected rule: SENSOR-002")]
    [InlineData("-SimulateDisabledSensor", "Sensor trust: Disabled", "Enforcement: FlagDisabledWithAlert", "Expected rule: SENSOR-002")]
    public void ReplayScript_TrustModesAreDeterministicAndSafe(
        string mode,
        string expectedTrust,
        string expectedAction,
        string expectedRule)
    {
        var args = new List<string>
        {
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1",
            "-NoSubmit"
        };
        if (!string.IsNullOrWhiteSpace(mode))
            args.Add(mode);

        var result = RunPwsh(args.ToArray());

        Assert.Equal(0, result.ExitCode);
        Assert.Contains(expectedTrust, result.Output, StringComparison.Ordinal);
        Assert.Contains(expectedAction, result.Output, StringComparison.Ordinal);
        Assert.Contains(expectedRule, result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void EvidenceReadinessDemoAndDocsContainSensorTrustEnforcementHooks()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1"),
            ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "RuntimeSensors", "Index.cshtml"),
            ReadRepoFile("docs", "SENSOR_TRUST_REGISTRY.md"));

        Assert.Contains("Sensor Trust Enforcement Evidence", combined, StringComparison.Ordinal);
        Assert.Contains("SimulateUnknownSensor", combined, StringComparison.Ordinal);
        Assert.Contains("SimulateRevokedSensor", combined, StringComparison.Ordinal);
        Assert.Contains("SENSOR-001", combined, StringComparison.Ordinal);
        Assert.Contains("SENSOR-002", combined, StringComparison.Ordinal);
        Assert.Contains("EnforcementAction", combined, StringComparison.Ordinal);
        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN CERTIFICATE-----", combined, StringComparison.OrdinalIgnoreCase);
    }

    private static SiemCorrelationService CreateService(ApplicationDbContext dbContext, SensorTrustRegistry registry) =>
        new(dbContext, new SpySecurityEventWriter(), new StaticRuleProvider(DefaultRuleSet()), registry);

    private static SiemRuleSet DefaultRuleSet() =>
        SiemRulesConfigurationLoader.BuiltInDefaults("test-defaults", usedFallback: true);

    private static SensorTrustRegistry DefaultRegistry() =>
        SensorTrustRegistryLoader.LoadFromFile(
            Path.Combine(GetRepositoryRoot(), "config", "sensor-registry.default.json"),
            GetRepositoryRoot());

    private static void AddRuntimeEvent(ApplicationDbContext dbContext, string sourceSystem, string containerId)
    {
        dbContext.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = "container.runtime.shell_spawned",
            Severity = EventSeverity.High,
            SourceSystem = sourceSystem,
            SourceHost = "runtime-node",
            Description = "Falco-compatible runtime event.",
            AdditionalDataJson = JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                provider = "falco-compatible",
                mappingId = "falco-container-runtime-baseline",
                mappingVersion = "1.0.0",
                mappingSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                mappingKey = "shell-in-container",
                correlate = true,
                falcoRule = "Terminal shell in container",
                falcoPriority = "Critical",
                falcoSource = "syscall",
                falcoTags = new[] { "container" },
                eventFingerprintSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                containerId,
                containerName = "runtime-demo",
                imageReference = "alpine:3.20",
                processName = "sh",
                eventType = "execve",
                rawOutputSha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                commandLineSha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            })
        });
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
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

    private sealed class StaticRuleProvider : ISiemRuleProvider
    {
        private readonly SiemRuleSet _ruleSet;

        public StaticRuleProvider(SiemRuleSet ruleSet)
        {
            _ruleSet = ruleSet;
        }

        public SiemRuleSet GetRules() => _ruleSet;
    }

    private sealed class SpySecurityEventWriter : ISecurityEventWriter
    {
        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed record CommandResult(int ExitCode, string Output);
}
