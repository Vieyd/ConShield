using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.DemoScenario;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public class DemoScenarioRunnerTests
{
    [Fact]
    public async Task DemoScenario_DryRun_DoesNotWrite()
    {
        await using var db = CreateDbContext();
        var output = new StringWriter();
        var runner = new DemoScenarioRunner();

        var result = await runner.RunAsync(
            db,
            new DemoScenarioOptions("healthy", DryRun: true, ResetDemoData: false, Yes: false),
            output);

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(db.Sensors);
        Assert.Empty(db.SecurityEvents);
        Assert.Contains("dry_run=true", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task HealthyScenario_SeedsDemoSensorsAndEvents()
    {
        await using var db = CreateDbContext();

        await RunScenarioAsync(db, "healthy");

        Assert.Equal(2, await db.Sensors.CountAsync(x => x.DisplayName.StartsWith("demo-")));
        Assert.Equal(2, await db.SecurityEvents.CountAsync(x => x.SourceSystem != null && x.SourceSystem.StartsWith("conshield.demo")));
        Assert.Single(await db.SecurityEventInboxReceipts.ToListAsync());
        Assert.Single(await db.SecurityEventOutboxMessages.ToListAsync());
        Assert.All(await db.SecurityEvents.ToListAsync(), x => Assert.Contains("\"DemoScenario\":true", x.AdditionalDataJson, StringComparison.Ordinal));
    }

    [Fact]
    public async Task LifecycleAlertsScenario_SeedsLifecycleEvents()
    {
        await using var db = CreateDbContext();

        await RunScenarioAsync(db, "lifecycle-alerts");

        Assert.Equal(4, await db.SecurityEvents.CountAsync(x => x.SourceSystem == SecuritySourceSystems.SensorLifecycle));
        Assert.Contains(await db.SecurityEvents.ToListAsync(), x => x.ExternalEventType == SensorLifecycleEventTypes.SensorRevoked);
        Assert.Equal(3, await db.SecurityEvents.CountAsync(x =>
            x.ExternalEventType == SensorLifecycleEventTypes.SensorCredentialRotated
            || x.ExternalEventType == SensorLifecycleEventTypes.SensorCredentialRevoked));
    }

    [Fact]
    public async Task LifecycleAlertsScenario_CanTriggerLife001AndLife002()
    {
        await using var db = CreateDbContext();

        await RunScenarioAsync(db, "lifecycle-alerts");

        var alerts = await db.SiemAlerts.OrderBy(x => x.RuleCode).ToListAsync();
        Assert.Contains(alerts, x => x.RuleCode == "LIFE-001");
        Assert.Contains(alerts, x => x.RuleCode == "LIFE-002");
        Assert.Equal(2, await db.Incidents.CountAsync());
    }

    [Fact]
    public async Task RuntimeIncidentScenario_CanTriggerRte001()
    {
        await using var db = CreateDbContext();

        await RunScenarioAsync(db, "runtime-incident");

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("RTE-001", alert.RuleCode);
        Assert.Contains("demo-runtime-container-01", alert.TriggerKey, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OutboxBacklogScenario_UsesOnlyDemoRows()
    {
        await using var db = CreateDbContext();

        await RunScenarioAsync(db, "outbox-backlog");

        var messages = await db.SecurityEventOutboxMessages.OrderBy(x => x.Status).ToListAsync();
        Assert.Equal(3, messages.Count);
        Assert.Contains(messages, x => x.Status == SecurityEventOutboxStatus.Pending);
        Assert.Contains(messages, x => x.Status == SecurityEventOutboxStatus.Processing);
        Assert.Contains(messages, x => x.Status == SecurityEventOutboxStatus.DeadLetter);
        Assert.All(messages, x =>
        {
            Assert.StartsWith("conshield.demo", x.MessageType, StringComparison.Ordinal);
            Assert.Contains("\"DemoScenario\":true", x.PayloadJson, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task ResetDemoData_RemovesOnlyDemoRecords()
    {
        await using var db = CreateDbContext();
        var nonDemoEvent = new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow,
            EventType = SecurityEventType.AccessDenied,
            Severity = EventSeverity.Warning,
            SourceSystem = "conshield.real-test",
            Description = "Non-demo record that must remain."
        };
        var nonDemoSensor = new Sensor
        {
            SensorId = Guid.NewGuid(),
            DisplayName = "fedora-runtime-01",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            LastSeenAtUtc = DateTime.UtcNow
        };
        db.SecurityEvents.Add(nonDemoEvent);
        db.Sensors.Add(nonDemoSensor);
        await db.SaveChangesAsync();

        await RunScenarioAsync(db, "full-demo");
        var before = await db.SecurityEvents.CountAsync();
        Assert.True(before > 1);

        var output = new StringWriter();
        var result = await new DemoScenarioRunner().RunAsync(
            db,
            new DemoScenarioOptions("healthy", DryRun: false, ResetDemoData: true, Yes: true),
            output);

        Assert.Equal(0, result.ExitCode);
        Assert.Single(await db.SecurityEvents.ToListAsync());
        Assert.Equal(nonDemoEvent.Id, (await db.SecurityEvents.SingleAsync()).Id);
        Assert.Single(await db.Sensors.ToListAsync());
        Assert.Equal(nonDemoSensor.SensorId, (await db.Sensors.SingleAsync()).SensorId);
        Assert.Empty(db.SecurityEventOutboxMessages);
        Assert.Empty(db.SecurityEventInboxReceipts);
        Assert.Empty(db.SiemAlerts);
        Assert.Empty(db.Incidents);
    }

    [Fact]
    public async Task ResetDemoData_DoesNotRemoveNonDemoRecords()
    {
        await using var db = CreateDbContext();
        var entry = new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow,
            EventType = SecurityEventType.ExternalEvent,
            Severity = EventSeverity.High,
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            ExternalEventType = "container.runtime.shell_spawned",
            Description = "Real-looking runtime event without demo marker.",
            AdditionalDataJson = "{}"
        };
        db.SecurityEvents.Add(entry);
        await db.SaveChangesAsync();

        var result = await new DemoScenarioRunner().RunAsync(
            db,
            new DemoScenarioOptions("healthy", DryRun: false, ResetDemoData: true, Yes: true),
            new StringWriter());

        Assert.Equal(0, result.ExitCode);
        Assert.Single(await db.SecurityEvents.ToListAsync());
    }

    [Fact]
    public async Task DemoScenario_OutputDoesNotContainSecrets()
    {
        await using var db = CreateDbContext();
        var output = new StringWriter();
        Environment.SetEnvironmentVariable("CONSHIELD_DEMO_CONNECTION_STRING", "Host=localhost;Password=secret-that-must-not-render");

        try
        {
            var result = await new DemoScenarioRunner().RunAsync(
                db,
                new DemoScenarioOptions("full-demo", DryRun: true, ResetDemoData: false, Yes: false),
                output);

            Assert.Equal(0, result.ExitCode);
            Assert.DoesNotContain("secret-that-must-not-render", output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("Password=", output.ToString(), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CONSHIELD_DEMO_CONNECTION_STRING", null);
        }
    }

    private static async Task RunScenarioAsync(ApplicationDbContext db, string scenario)
    {
        var result = await new DemoScenarioRunner().RunAsync(
            db,
            new DemoScenarioOptions(scenario, DryRun: false, ResetDemoData: false, Yes: true),
            new StringWriter());

        Assert.Equal(0, result.ExitCode);
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new ApplicationDbContext(options);
    }
}
