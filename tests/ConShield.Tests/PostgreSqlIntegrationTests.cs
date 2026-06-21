using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

[Collection("PostgreSql")]
public class PostgreSqlIntegrationTests
{
    private const string ConnectionVariable = "CONSHIELD_TEST_POSTGRES_CONNECTION";

    [PostgreSqlFact]
    public async Task Migrations_CreateSchemaOnCleanPostgreSqlDatabase()
    {
        await using var db = await CreateMigratedDbContextAsync();

        var pendingMigrations = await db.Database.GetPendingMigrationsAsync();

        Assert.Empty(pendingMigrations);
        Assert.True(await db.Database.CanConnectAsync());
    }

    [PostgreSqlFact]
    public async Task CorrelationRules_WorkOnPostgreSqlProvider()
    {
        await using var db = await CreateMigratedDbContextAsync();
        AddLoginFailures(db, "operator", 3);
        AddUserExceptionChanges(db, "adminib", 5);
        AddCriticalEvents(db, "172.16.5.44", 2);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(3, result.CreatedAlerts);
        Assert.Equal(3, result.CreatedIncidents);
        Assert.Contains(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == "BF-001");
        Assert.Contains(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == "UE-001");
        Assert.Contains(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == "CR-001");
    }

    [PostgreSqlFact]
    public async Task Correlation_DoesNotDuplicateActiveAlertOnPostgreSqlProvider()
    {
        await using var db = await CreateMigratedDbContextAsync();
        AddLoginFailures(db, "operator", 3);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var firstRun = await service.RunAsync();
        var secondRun = await service.RunAsync();

        Assert.Equal(1, firstRun.CreatedAlerts);
        Assert.Equal(0, secondRun.CreatedAlerts);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "BF-001" && x.Status == AlertStatuses.New));
    }

    [PostgreSqlFact]
    public async Task Correlation_ConcurrentRuns_CreateOneAlertAndIncident()
    {
        await using (var setup = await CreateMigratedDbContextAsync())
        {
            AddLoginFailures(setup, "operator", 3);
            await setup.SaveChangesAsync();
        }

        await using var firstDb = CreatePostgreSqlDbContext();
        await using var secondDb = CreatePostgreSqlDbContext();
        var results = await Task.WhenAll(
            CreateService(firstDb).RunAsync(),
            CreateService(secondDb).RunAsync());

        await using var verify = CreatePostgreSqlDbContext();
        Assert.Equal(1, results.Sum(x => x.CreatedAlerts));
        Assert.Equal(1, results.Sum(x => x.CreatedIncidents));
        Assert.Equal(1, await verify.SiemAlerts.CountAsync(x => x.RuleCode == "BF-001"));
        Assert.Equal(1, await verify.Incidents.CountAsync(x => x.Name.Contains("BF-001")));
    }

    [PostgreSqlFact]
    public async Task QueryFilters_AreCaseInsensitiveOnPostgreSqlProvider()
    {
        await using var db = await CreateMigratedDbContextAsync();
        db.SecurityEvents.Add(new SecurityEventEntry
        {
            EventType = SecurityEventType.LoginFailure,
            Severity = EventSeverity.Warning,
            UserName = "AdminIB",
            SourceIp = "10.10.10.21",
            Description = "Mixed Case Login Failure"
        });
        db.Incidents.Add(new IncidentRecord
        {
            Name = "DATABASE Incident",
            Severity = EventSeverity.High,
            Status = IncidentStatuses.New,
            Notes = "Case insensitive incident search",
            SourceEventId = 42
        });
        db.SiemAlerts.Add(new SiemAlertRecord
        {
            RuleCode = "BF-001",
            RuleName = "Repeated Login Failures",
            TriggerKey = "BF-001:AdminIB",
            Severity = EventSeverity.High,
            Status = AlertStatuses.New,
            Description = "Case insensitive alert search"
        });
        await db.SaveChangesAsync();

        var eventMatches = await db.SecurityEvents
            .ApplySecurityEventFilters("adminib", null, null, "failure")
            .ToListAsync();
        var incidentMatches = await db.Incidents
            .ApplyIncidentFilters(null, null, "database")
            .ToListAsync();
        var alertMatches = await db.SiemAlerts
            .ApplySiemAlertFilters(null, null, "bf-001", "LOGIN")
            .ToListAsync();

        Assert.Single(eventMatches);
        Assert.Single(incidentMatches);
        Assert.Single(alertMatches);
    }

    [PostgreSqlFact]
    public async Task DateTimeValues_AreStoredAndReadAsUtc()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var occurredAtUtc = TruncateToMicroseconds(DateTime.SpecifyKind(DateTime.UtcNow.AddMinutes(-1), DateTimeKind.Utc));
        db.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = occurredAtUtc,
            EventType = SecurityEventType.LoginSuccess,
            Severity = EventSeverity.Info,
            UserName = "adminib",
            Description = "UTC timestamp check"
        });
        await db.SaveChangesAsync();

        db.ChangeTracker.Clear();

        var saved = await db.SecurityEvents.SingleAsync();

        Assert.Equal(DateTimeKind.Utc, saved.OccurredAtUtc.Kind);
        Assert.Equal(occurredAtUtc, saved.OccurredAtUtc);
    }

    [PostgreSqlFact]
    public async Task SensorInventory_ConstraintsAndUniqueIndexesAreEnforced()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var sensorId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        db.Sensors.Add(new Sensor
        {
            SensorId = sensorId,
            DisplayName = "First sensor",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            Credentials =
            [
                new SensorCredential { CredentialId = credentialId, VerifierSha256 = new byte[32] }
            ]
        });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        db.Sensors.Add(new Sensor
        {
            SensorId = sensorId,
            DisplayName = "Duplicate sensor",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector
        });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();

        db.Sensors.Add(new Sensor
        {
            SensorId = Guid.NewGuid(),
            DisplayName = "Second sensor",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            Credentials =
            [
                new SensorCredential { CredentialId = credentialId, VerifierSha256 = new byte[32] }
            ]
        });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();

        db.Sensors.Add(new Sensor
        {
            SensorId = Guid.NewGuid(),
            DisplayName = "Invalid verifier sensor",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            Credentials =
            [
                new SensorCredential { CredentialId = Guid.NewGuid(), VerifierSha256 = new byte[31] }
            ]
        });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    private static async Task<ApplicationDbContext> CreateMigratedDbContextAsync()
    {
        var db = CreatePostgreSqlDbContext();
        await db.Database.EnsureDeletedAsync();
        await db.Database.MigrateAsync();
        return db;
    }

    private static ApplicationDbContext CreatePostgreSqlDbContext()
    {
        var connectionString = Environment.GetEnvironmentVariable(ConnectionVariable);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException($"{ConnectionVariable} is required for PostgreSQL integration tests.");
        }

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseNpgsql(connectionString)
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
        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    private static DateTime TruncateToMicroseconds(DateTime value)
    {
        return new DateTime(value.Ticks - value.Ticks % 10, DateTimeKind.Utc);
    }
}

public sealed class PostgreSqlFactAttribute : FactAttribute
{
    public PostgreSqlFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CONSHIELD_TEST_POSTGRES_CONNECTION")))
        {
            Skip = "Set CONSHIELD_TEST_POSTGRES_CONNECTION to run PostgreSQL integration tests.";
        }
    }
}

[CollectionDefinition("PostgreSql", DisableParallelization = true)]
public sealed class PostgreSqlCollection
{
}
