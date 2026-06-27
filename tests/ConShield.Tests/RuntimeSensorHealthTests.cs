using System.Text.Json;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.Web.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class RuntimeSensorHealthTests
{
    [Fact]
    public void RuntimeSensorsController_RequiresAuthentication()
    {
        var attribute = typeof(RuntimeSensorsController).GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true);

        Assert.NotEmpty(attribute);
    }

    [Fact]
    public async Task RuntimeSensorHealth_GroupsRuntimeEventsBySourceSystem()
    {
        await using var db = CreateDbContext();
        var now = new DateTime(2026, 06, 27, 12, 0, 0, DateTimeKind.Utc);
        db.SecurityEvents.Add(RuntimeEvent(SecuritySourceSystems.FalcoLinuxSensor, "container.runtime.shell_spawned", now.AddMinutes(-5), EventSeverity.High));
        db.SecurityEvents.Add(RuntimeEvent(SecuritySourceSystems.FalcoLinuxSensor, "container.runtime.etc_write", now.AddMinutes(-3), EventSeverity.Warning));
        db.SecurityEvents.Add(RuntimeEvent("conshield.custom-falco", "container.runtime.custom", now.AddMinutes(-2), EventSeverity.High));
        await db.SaveChangesAsync();

        var result = await new RuntimeSensorHealthService(db).GetAsync(new RuntimeSensorHealthOptions(now, TimeSpan.FromHours(24)));

        var falco = Assert.Single(result.Sources, x => x.SourceSystem == SecuritySourceSystems.FalcoLinuxSensor);
        Assert.Equal(2, falco.EventCount);
        Assert.Equal("container.runtime.etc_write", falco.LatestEventType);
        Assert.Equal(RuntimeSensorHealthStatuses.Active, falco.Status);
        Assert.Contains(result.Sources, x => x.SourceSystem == "conshield.custom-falco");
    }

    [Fact]
    public async Task RuntimeSensorHealth_StaleAndNoDataStatesAreSafe()
    {
        await using var db = CreateDbContext();
        var now = new DateTime(2026, 06, 27, 12, 0, 0, DateTimeKind.Utc);
        db.SecurityEvents.Add(RuntimeEvent(SecuritySourceSystems.FalcoLinuxSensor, "container.runtime.shell_spawned", now.AddDays(-3), EventSeverity.High));
        await db.SaveChangesAsync();

        var result = await new RuntimeSensorHealthService(db).GetAsync(new RuntimeSensorHealthOptions(now, TimeSpan.FromHours(24)));

        Assert.Equal(RuntimeSensorHealthStatuses.Stale, result.Sources.Single(x => x.SourceSystem == SecuritySourceSystems.FalcoLinuxSensor).Status);
        Assert.Equal(RuntimeSensorHealthStatuses.NoData, result.Sources.Single(x => x.SourceSystem == "conshield.container-runtime").Status);
    }

    [Fact]
    public async Task RuntimeSensorHealth_CountsRelatedRteAlertsAndIncidents()
    {
        await using var db = CreateDbContext();
        var now = new DateTime(2026, 06, 27, 12, 0, 0, DateTimeKind.Utc);
        var runtimeEvent = RuntimeEvent(SecuritySourceSystems.FalcoLinuxSensor, "container.runtime.shell_spawned", now.AddMinutes(-5), EventSeverity.High);
        db.SecurityEvents.Add(runtimeEvent);
        await db.SaveChangesAsync();

        var incident = new IncidentRecord
        {
            CreatedAtUtc = now,
            Name = "[RTE-001] Runtime",
            Severity = EventSeverity.High,
            Status = "New",
            SourceEventId = runtimeEvent.Id
        };
        db.Incidents.Add(incident);
        await db.SaveChangesAsync();

        db.SiemAlerts.Add(new SiemAlertRecord
        {
            CreatedAtUtc = now,
            RuleCode = "RTE-001",
            RuleName = "Runtime threat",
            TriggerKey = "RTE-001:runtime",
            Severity = EventSeverity.High,
            Status = "New",
            IncidentId = incident.Id,
            Description = $"Runtime threat shell-in-container detected. Source event #{runtimeEvent.Id}.",
            SourceEventIdsJson = JsonSerializer.Serialize(new[] { runtimeEvent.Id })
        });
        await db.SaveChangesAsync();

        var result = await new RuntimeSensorHealthService(db).GetAsync(new RuntimeSensorHealthOptions(now, TimeSpan.FromHours(24)));
        var row = result.Sources.Single(x => x.SourceSystem == SecuritySourceSystems.FalcoLinuxSensor);

        Assert.Equal(1, row.RelatedRteAlertCount);
        Assert.Equal(1, row.RelatedIncidentCount);
    }

    [Fact]
    public void RuntimeSensorHealthView_IncludesTitleSummaryTableAndLinks()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "RuntimeSensors", "Index.cshtml");
        var securitySummary = ReadRepoFile("src", "ConShield.Web", "Views", "Reports", "SecuritySummary.cshtml");

        Assert.Contains("Runtime Sensor Health", view, StringComparison.Ordinal);
        Assert.Contains("Runtime sources", view, StringComparison.Ordinal);
        Assert.Contains("<table", view, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"SecurityEvents\"", view, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Siem\"", view, StringComparison.Ordinal);
        Assert.Contains("asp-route-RuleCode=\"RTE-001\"", view, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Incidents\"", view, StringComparison.Ordinal);
        Assert.DoesNotContain("@item.AdditionalDataJson", view, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runtime Sensor Health", securitySummary, StringComparison.Ordinal);
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
            .UseInMemoryDatabase($"runtime-sensor-health-{Guid.NewGuid():N}")
            .Options;
        return new ApplicationDbContext(options);
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
}
