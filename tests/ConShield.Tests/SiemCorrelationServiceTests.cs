using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public class SiemCorrelationServiceTests
{
    [Fact]
    public async Task BF001_TwoLoginFailures_DoesNotCreateAlert()
    {
        await using var db = CreateDbContext();
        AddLoginFailures(db, "operator", 2);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Equal(0, result.CreatedIncidents);
        Assert.Empty(db.SiemAlerts);
        Assert.Empty(db.Incidents);
    }

    [Fact]
    public async Task BF001_ThreeLoginFailures_CreatesOneAlertAndOneIncident()
    {
        await using var db = CreateDbContext();
        AddLoginFailures(db, "operator", 3);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("BF-001", alert.RuleCode);
        Assert.Equal(AlertStatuses.New, alert.Status);

        var incident = await db.Incidents.SingleAsync();
        Assert.Equal(alert.IncidentId, incident.Id);
        Assert.Equal(EventSeverity.High, incident.Severity);
    }

    [Fact]
    public async Task BF001_RepeatedRun_DoesNotCreateDuplicateActiveAlert()
    {
        await using var db = CreateDbContext();
        AddLoginFailures(db, "operator", 3);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var firstRun = await service.RunAsync();
        var secondRun = await service.RunAsync();

        Assert.Equal(1, firstRun.CreatedAlerts);
        Assert.Equal(1, firstRun.CreatedIncidents);
        Assert.Equal(0, secondRun.CreatedAlerts);
        Assert.Equal(0, secondRun.CreatedIncidents);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "BF-001"));
        Assert.Equal(1, await db.Incidents.CountAsync());
    }

    [Fact]
    public async Task UE001_FiveUserExceptionChanges_CreatesAlert()
    {
        await using var db = CreateDbContext();
        AddUserExceptionChanges(db, "adminib", 5);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("UE-001", alert.RuleCode);
        Assert.Equal(EventSeverity.Critical, alert.Severity);
    }

    [Fact]
    public async Task CR001_CriticalEventsFromSameSourceIp_CreatesAlert()
    {
        await using var db = CreateDbContext();
        AddCriticalEvents(db, "172.16.5.44", 2);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("CR-001", alert.RuleCode);
        Assert.Equal("CR-001:172.16.5.44", alert.TriggerKey);
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new ApplicationDbContext(options);
    }

    private static SiemCorrelationService CreateService(ApplicationDbContext dbContext)
    {
        return new SiemCorrelationService(dbContext, new SpySecurityEventWriter());
    }

    private static void AddLoginFailures(ApplicationDbContext dbContext, string userName, int count)
    {
        for (var i = 0; i < count; i++)
        {
            dbContext.SecurityEvents.Add(new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10 - i),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = userName,
                SourceIp = "10.10.10.21",
                Description = "Неуспешная попытка входа в систему."
            });
        }
    }

    private static void AddUserExceptionChanges(ApplicationDbContext dbContext, string userName, int count)
    {
        for (var i = 0; i < count; i++)
        {
            dbContext.SecurityEvents.Add(new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-5 - i),
                EventType = SecurityEventType.UserExceptionUpdated,
                Severity = EventSeverity.Info,
                UserName = userName,
                SourceIp = "127.0.0.1",
                Description = $"Изменена запись UserException #{i + 1}."
            });
        }
    }

    private static void AddCriticalEvents(ApplicationDbContext dbContext, string sourceIp, int count)
    {
        for (var i = 0; i < count; i++)
        {
            dbContext.SecurityEvents.Add(new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-15 - i),
                EventType = SecurityEventType.AccessDenied,
                Severity = EventSeverity.Critical,
                UserName = "runtime-agent",
                SourceIp = sourceIp,
                Description = "Критическое событие контроля выполнения контейнера."
            });
        }
    }

    private sealed class SpySecurityEventWriter : ISecurityEventWriter
    {
        public List<SecurityEventWriteRequest> Requests { get; } = new();

        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            return Task.CompletedTask;
        }
    }
}
