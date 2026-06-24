using System.Reflection;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.Web.Controllers;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class OperationsHealthTests
{
    [Fact]
    public void OperationsHealth_RequiresAdminIB()
    {
        var attribute = typeof(OperationsController).GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(AppRoles.AdminIB, attribute.Roles);
    }

    [Fact]
    public void Operator_CannotOpenOperationsHealth()
    {
        var controllerAuthorize = typeof(OperationsController).GetCustomAttribute<AuthorizeAttribute>();
        var method = typeof(OperationsController).GetMethod(
            nameof(OperationsController.Health),
            [typeof(CancellationToken)]);

        Assert.NotNull(controllerAuthorize);
        Assert.Equal(AppRoles.AdminIB, controllerAuthorize.Roles);
        Assert.DoesNotContain(AppRoles.Operator, controllerAuthorize.Roles, StringComparison.Ordinal);
        Assert.NotNull(method);
        Assert.Null(method.GetCustomAttribute<AllowAnonymousAttribute>());
    }

    [Fact]
    public async Task OperationsHealth_RendersSensorCounts()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        SeedSensors(db, nowUtc);

        var model = await HealthModelAsync(db);

        Assert.Equal(5, model.Sensors.Total);
        Assert.Equal(4, model.Sensors.Active);
        Assert.Equal(1, model.Sensors.Revoked);
        Assert.Equal(1, model.Sensors.NeverSeen);
        Assert.Equal(1, model.Sensors.Online);
        Assert.Equal(1, model.Sensors.Warning);
        Assert.Equal(1, model.Sensors.Offline);
        Assert.Equal(OperationalHealthStatus.Attention, model.Sensors.StatusLabel);
    }

    [Fact]
    public async Task OperationsHealth_RendersSecurityEventCounts()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        SeedSecurityEvents(db, nowUtc);

        var model = await HealthModelAsync(db);

        Assert.Equal(4, model.SecurityEvents.Total);
        Assert.Equal(2, model.SecurityEvents.LastHour);
        Assert.Equal(3, model.SecurityEvents.Last24Hours);
        Assert.Equal(OperationalHealthStatus.Ok, model.SecurityEvents.StatusLabel);
    }

    [Fact]
    public async Task OperationsHealth_RendersLifecycleEventCount()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        SeedSecurityEvents(db, nowUtc);

        var model = await HealthModelAsync(db);

        Assert.Equal(1, model.SecurityEvents.LifecycleLast24Hours);
    }

    [Fact]
    public async Task OperationsHealth_RendersOutboxSummary()
    {
        await using var db = CreateDbContext();
        SeedOutbox(db);

        var model = await HealthModelAsync(db);

        Assert.Equal(4, model.Outbox.Total);
        Assert.Equal(1, model.Outbox.Pending);
        Assert.Equal(1, model.Outbox.Processing);
        Assert.Equal(2, model.Outbox.NotDispatched);
        Assert.Equal(1, model.Outbox.Delivered);
        Assert.Equal(1, model.Outbox.DeadLetter);
        Assert.Equal(OperationalHealthStatus.Attention, model.Outbox.StatusLabel);
    }

    [Fact]
    public async Task OperationsHealth_RendersInboxSummary()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        SeedInbox(db, nowUtc);

        var model = await HealthModelAsync(db);

        Assert.Equal(2, model.Inbox.Total);
        Assert.Equal(2, model.Inbox.Last24Hours);
        Assert.Equal(1, model.Inbox.Redelivered);
        Assert.Equal(1, model.Inbox.DeliveryCountOverOne);
        Assert.Equal(OperationalHealthStatus.Warning, model.Inbox.StatusLabel);
    }

    [Fact]
    public async Task OperationsHealth_DoesNotRenderSecretsOrVerifiers()
    {
        await using var db = CreateDbContext();
        var forbiddenPlaintext = "plaintext-secret-that-must-not-render";
        db.Sensors.Add(new Sensor
        {
            SensorId = Guid.NewGuid(),
            DisplayName = "fedora-runtime-01",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            LastSeenAtUtc = DateTime.UtcNow,
            Credentials =
            [
                new SensorCredential
                {
                    CredentialId = Guid.NewGuid(),
                    VerifierSha256 = [1, 2, 3, 4],
                    CreatedAtUtc = DateTime.UtcNow
                }
            ]
        });
        db.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow,
            EventType = SecurityEventType.ExternalEvent,
            Severity = EventSeverity.Info,
            SourceSystem = SecuritySourceSystems.SensorLifecycle,
            ExternalEventType = SensorLifecycleEventTypes.SensorCredentialRotated,
            Description = "credential rotation",
            AdditionalDataJson = $$"""{"credential":"{{forbiddenPlaintext}}","VerifierSha256":"must-not-render","Password":"must-not-render"}"""
        });
        await db.SaveChangesAsync();

        var model = await HealthModelAsync(db);
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "Operations", "Health.cshtml");
        var serializedModel = string.Join(
            '|',
            model.Sensors.StatusLabel,
            model.SecurityEvents.StatusLabel,
            model.Outbox.StatusLabel,
            model.Inbox.StatusLabel);
        var combined = viewText + serializedModel;

        Assert.DoesNotContain(forbiddenPlaintext, combined, StringComparison.Ordinal);
        Assert.DoesNotContain("VerifierSha256", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CONSHIELD_RUNTIME_COLLECTOR_API_KEY", combined, StringComparison.Ordinal);
    }

    [Fact]
    public void OperationsHealth_HasAdminNavigationLink()
    {
        var layout = ReadRepoFile("src", "ConShield.Web", "Views", "Shared", "_Layout.cshtml");

        Assert.Contains("User.IsInRole(\"AdminIB\")", layout, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Operations\"", layout, StringComparison.Ordinal);
        Assert.Contains("asp-action=\"Health\"", layout, StringComparison.Ordinal);
        Assert.Contains("Здоровье", layout, StringComparison.Ordinal);
    }

    [Fact]
    public void OperationsHealth_HelpTextReferencesOperationsSiemRunbook()
    {
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "Operations", "Health.cshtml");

        Assert.Contains("docs/OPERATIONS_AND_SIEM_RUNBOOK.md", viewText, StringComparison.Ordinal);
        Assert.Contains("Security Events", viewText, StringComparison.Ordinal);
        Assert.Contains("SIEM alerts", viewText, StringComparison.Ordinal);
        Assert.Contains("Sensor Fleet", viewText, StringComparison.Ordinal);
    }

    private static async Task<OperationalHealthViewModel> HealthModelAsync(ApplicationDbContext db)
    {
        var result = await new OperationsController(db).Health(CancellationToken.None);
        var view = Assert.IsType<ViewResult>(result);
        return Assert.IsType<OperationalHealthViewModel>(view.Model);
    }

    private static void SeedSensors(ApplicationDbContext db, DateTime nowUtc)
    {
        db.Sensors.AddRange(
            Sensor("online", nowUtc.AddSeconds(-30), revokedAtUtc: null),
            Sensor("warning", nowUtc.AddMinutes(-3), revokedAtUtc: null),
            Sensor("offline", nowUtc.AddMinutes(-10), revokedAtUtc: null),
            Sensor("never-seen", lastSeenAtUtc: null, revokedAtUtc: null),
            Sensor("revoked", nowUtc.AddSeconds(-20), revokedAtUtc: nowUtc.AddSeconds(-10)));
        db.SaveChanges();
    }

    private static Sensor Sensor(string displayName, DateTime? lastSeenAtUtc, DateTime? revokedAtUtc) => new()
    {
        SensorId = Guid.NewGuid(),
        DisplayName = displayName,
        SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
        LastSeenAtUtc = lastSeenAtUtc,
        RevokedAtUtc = revokedAtUtc,
        CreatedAtUtc = DateTime.UtcNow.AddHours(-1),
        UpdatedAtUtc = DateTime.UtcNow
    };

    private static void SeedSecurityEvents(ApplicationDbContext db, DateTime nowUtc)
    {
        db.SecurityEvents.AddRange(
            SecurityEvent(nowUtc.AddMinutes(-30), SecuritySourceSystems.FalcoRuntimeCollector),
            SecurityEvent(nowUtc.AddHours(-2), SecuritySourceSystems.FalcoRuntimeCollector),
            SecurityEvent(nowUtc.AddHours(-25), SecuritySourceSystems.FalcoRuntimeCollector),
            SecurityEvent(nowUtc.AddMinutes(-10), SecuritySourceSystems.SensorLifecycle, SensorLifecycleEventTypes.SensorCredentialRotated));
        db.SaveChanges();
    }

    private static SecurityEventEntry SecurityEvent(
        DateTime occurredAtUtc,
        string sourceSystem,
        string? externalEventType = null) => new()
    {
        OccurredAtUtc = occurredAtUtc,
        EventType = SecurityEventType.ExternalEvent,
        Severity = EventSeverity.Info,
        SourceSystem = sourceSystem,
        ExternalEventType = externalEventType,
        Description = "test event",
        AdditionalDataJson = "{\"safe\":true}"
    };

    private static void SeedOutbox(ApplicationDbContext db)
    {
        var nowUtc = DateTime.UtcNow;
        db.SecurityEventOutboxMessages.AddRange(
            Outbox(SecurityEventOutboxStatus.Pending, nowUtc.AddMinutes(-20)),
            Outbox(SecurityEventOutboxStatus.Processing, nowUtc.AddMinutes(-10)),
            Outbox(SecurityEventOutboxStatus.Delivered, nowUtc.AddMinutes(-5)),
            Outbox(SecurityEventOutboxStatus.DeadLetter, nowUtc.AddMinutes(-1)));
        db.SaveChanges();
    }

    private static SecurityEventOutboxMessage Outbox(SecurityEventOutboxStatus status, DateTime createdAtUtc) => new()
    {
        MessageId = Guid.NewGuid(),
        SecurityEventId = 1,
        MessageType = "conshield.security-event",
        PayloadJson = "{\"safe\":true}",
        Status = status,
        CreatedAtUtc = createdAtUtc,
        AvailableAtUtc = createdAtUtc,
        DeliveredAtUtc = status == SecurityEventOutboxStatus.Delivered ? createdAtUtc.AddSeconds(5) : null
    };

    private static void SeedInbox(ApplicationDbContext db, DateTime nowUtc)
    {
        db.SecurityEventInboxReceipts.AddRange(
            Inbox(nowUtc.AddHours(-2), nowUtc.AddHours(-1), redelivered: false, deliveryCount: 1),
            Inbox(nowUtc.AddMinutes(-30), processedAtUtc: null, redelivered: true, deliveryCount: 2));
        db.SaveChanges();
    }

    private static SecurityEventInboxReceipt Inbox(
        DateTime receivedAtUtc,
        DateTime? processedAtUtc,
        bool redelivered,
        int deliveryCount) => new()
    {
        MessageId = Guid.NewGuid(),
        SecurityEventId = 1,
        MessageType = "conshield.security-event",
        PayloadSha256 = new string('a', 64),
        RoutingKey = "security.events",
        ReceivedAtUtc = receivedAtUtc,
        ProcessedAtUtc = processedAtUtc,
        Redelivered = redelivered,
        DeliveryCount = deliveryCount
    };

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"operations-health-{Guid.NewGuid():N}")
            .Options;
        return new ApplicationDbContext(options);
    }

    private static string ReadRepoFile(params string[] relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(new[] { directory.FullName }.Concat(relativePath).ToArray());
            if (File.Exists(candidate))
                return File.ReadAllText(candidate);
            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not find repository file: {Path.Combine(relativePath)}");
    }
}
