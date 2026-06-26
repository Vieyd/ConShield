using System.Reflection;
using System.Text;
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

public sealed class SecuritySummaryReportTests
{
    [Fact]
    public void SecuritySummaryReport_RequiresAdminIB()
    {
        var attribute = typeof(ReportsController).GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(AppRoles.AdminIB, attribute.Roles);
    }

    [Fact]
    public void Operator_CannotOpenSecuritySummaryReport()
    {
        var controllerAuthorize = typeof(ReportsController).GetCustomAttribute<AuthorizeAttribute>();
        var method = typeof(ReportsController).GetMethod(
            nameof(ReportsController.SecuritySummary),
            [typeof(string), typeof(CancellationToken)]);

        Assert.NotNull(controllerAuthorize);
        Assert.Equal(AppRoles.AdminIB, controllerAuthorize.Roles);
        Assert.DoesNotContain(AppRoles.Operator, controllerAuthorize.Roles, StringComparison.Ordinal);
        Assert.NotNull(method);
        Assert.Null(method.GetCustomAttribute<AllowAnonymousAttribute>());
    }

    [Fact]
    public void SecuritySummaryMarkdown_RequiresAdminIB()
    {
        var controllerAuthorize = typeof(ReportsController).GetCustomAttribute<AuthorizeAttribute>();
        var method = typeof(ReportsController).GetMethod(
            nameof(ReportsController.SecuritySummaryMarkdown),
            [typeof(string), typeof(CancellationToken)]);

        Assert.NotNull(controllerAuthorize);
        Assert.Equal(AppRoles.AdminIB, controllerAuthorize.Roles);
        Assert.NotNull(method);
        Assert.Null(method.GetCustomAttribute<AllowAnonymousAttribute>());
    }

    [Fact]
    public async Task SecuritySummaryReport_RendersSensorAndEventCounts()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        SeedReportData(db, nowUtc);

        var model = await ReportModelAsync(db, "24h");

        Assert.Equal(4, model.Sensors.Total);
        Assert.Equal(3, model.Sensors.Active);
        Assert.Equal(1, model.Sensors.Revoked);
        Assert.Equal(1, model.Sensors.Online);
        Assert.Equal(1, model.Sensors.Warning);
        Assert.Equal(1, model.Sensors.Offline);
        Assert.Equal(4, model.SecurityEvents.EventsInRange);
        Assert.Equal(1, model.SecurityEvents.SeverityCounts[EventSeverity.Info]);
        Assert.Equal(1, model.SecurityEvents.SeverityCounts[EventSeverity.Warning]);
        Assert.Equal(1, model.SecurityEvents.SeverityCounts[EventSeverity.High]);
        Assert.Equal(1, model.SecurityEvents.SeverityCounts[EventSeverity.Critical]);
        Assert.Equal(1, model.SecurityEvents.LifecycleAuditEvents);
    }

    [Fact]
    public async Task SecuritySummaryReport_RendersSiemLifecycleAlertCounts()
    {
        await using var db = CreateDbContext();
        SeedReportData(db, DateTime.UtcNow);

        var model = await ReportModelAsync(db, "24h");

        Assert.Equal(2, model.Siem.ActiveAlerts);
        Assert.Equal(2, model.Siem.LifecycleAlertsInRange);
        Assert.Equal(1, model.Siem.Life001AlertsInRange);
        Assert.Equal(1, model.Siem.Life002AlertsInRange);
        Assert.Equal(1, model.Siem.IncidentsInRange);
    }

    [Fact]
    public async Task SecuritySummaryReport_RendersOutboxSummary()
    {
        await using var db = CreateDbContext();
        SeedReportData(db, DateTime.UtcNow);

        var model = await ReportModelAsync(db, "24h");

        Assert.Equal(1, model.Pipeline.OutboxPending);
        Assert.Equal(1, model.Pipeline.OutboxProcessing);
        Assert.Equal(1, model.Pipeline.OutboxDeadLetter);
        Assert.Equal(2, model.Pipeline.InboxTotal);
        Assert.Equal(2, model.Pipeline.InboxInRange);
        Assert.Equal(1, model.Pipeline.InboxRedelivered);
        Assert.Equal(1, model.Pipeline.InboxDeliveryCountOverOne);
    }

    [Fact]
    public async Task SecuritySummaryReport_RangeDefaultsTo24h()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        SeedReportData(db, nowUtc);
        db.SecurityEvents.Add(SecurityEvent(nowUtc.AddHours(-30), EventSeverity.Info));
        await db.SaveChangesAsync();

        var model = await ReportModelAsync(db, "unexpected");

        Assert.Equal("24h", model.RangeKey);
        Assert.Equal(4, model.SecurityEvents.EventsInRange);
    }

    [Fact]
    public async Task SecuritySummaryReport_Range7dWorks()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        SeedReportData(db, nowUtc);
        db.SecurityEvents.Add(SecurityEvent(nowUtc.AddDays(-2), EventSeverity.Info));
        await db.SaveChangesAsync();

        var model = await ReportModelAsync(db, "7d");

        Assert.Equal("7d", model.RangeKey);
        Assert.Equal(6, model.SecurityEvents.EventsInRange);
    }

    [Fact]
    public async Task SecuritySummaryReport_DoesNotRenderSecretsOrRawJson()
    {
        await using var db = CreateDbContext();
        const string forbidden = "plaintext-secret-that-must-not-render";
        SeedReportData(db, DateTime.UtcNow, forbidden);

        var model = await ReportModelAsync(db, "24h");
        var combined = ReadRepoFile("src", "ConShield.Web", "Views", "Reports", "SecuritySummary.cshtml")
            + model.Markdown
            + string.Join('|', model.OperatorChecklist);

        Assert.DoesNotContain(forbidden, combined, StringComparison.Ordinal);
        Assert.DoesNotContain("AdditionalDataJson", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CONSHIELD_RUNTIME_COLLECTOR_API_KEY", combined, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SecuritySummaryMarkdown_ReturnsMarkdownAndSafeFilename()
    {
        await using var db = CreateDbContext();
        SeedReportData(db, DateTime.UtcNow);

        var result = await new ReportsController(db).SecuritySummaryMarkdown("24h", CancellationToken.None);
        var file = Assert.IsType<FileContentResult>(result);
        var markdown = Encoding.UTF8.GetString(file.FileContents);

        Assert.StartsWith("text/markdown", file.ContentType, StringComparison.Ordinal);
        Assert.Matches(@"^conshield-security-summary-\d{8}-\d{4}\.md$", file.FileDownloadName);
        Assert.Contains("# ConShield — сводка безопасности", markdown, StringComparison.Ordinal);
        Assert.Contains("Lifecycle-оповещения SIEM: 2", markdown, StringComparison.Ordinal);
        Assert.Contains("Очередь: ожидает: 1", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SecuritySummaryMarkdown_DoesNotRenderSecretsOrRawJson()
    {
        await using var db = CreateDbContext();
        const string forbidden = "secret-export-value";
        SeedReportData(db, DateTime.UtcNow, forbidden);

        var result = await new ReportsController(db).SecuritySummaryMarkdown("24h", CancellationToken.None);
        var file = Assert.IsType<FileContentResult>(result);
        var markdown = Encoding.UTF8.GetString(file.FileContents);

        Assert.DoesNotContain(forbidden, markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("AdditionalDataJson", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CONSHIELD_RUNTIME_COLLECTOR_API_KEY", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("raw event JSON", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("API keys", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection strings", markdown, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Layout_HasAdminReportsLink()
    {
        var layout = ReadRepoFile("src", "ConShield.Web", "Views", "Shared", "_Layout.cshtml");

        Assert.Contains("User.IsInRole(\"AdminIB\")", layout, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Reports\"", layout, StringComparison.Ordinal);
        Assert.Contains("asp-action=\"SecuritySummary\"", layout, StringComparison.Ordinal);
        Assert.Contains("Отчёты", layout, StringComparison.Ordinal);
    }

    [Fact]
    public void SecuritySummaryReport_DocsReferenceRunbook()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Reports", "SecuritySummary.cshtml");
        var runbook = ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md");

        Assert.Contains("docs/OPERATIONS_AND_SIEM_RUNBOOK.md", view, StringComparison.Ordinal);
        Assert.Contains("/Reports/SecuritySummary", runbook, StringComparison.Ordinal);
        Assert.Contains("Markdown", runbook, StringComparison.Ordinal);
    }

    private static async Task<SecuritySummaryReportViewModel> ReportModelAsync(ApplicationDbContext db, string? range)
    {
        var result = await new ReportsController(db).SecuritySummary(range, CancellationToken.None);
        var view = Assert.IsType<ViewResult>(result);
        return Assert.IsType<SecuritySummaryReportViewModel>(view.Model);
    }

    private static void SeedReportData(ApplicationDbContext db, DateTime nowUtc, string forbiddenValue = "safe")
    {
        db.Sensors.AddRange(
            Sensor("online", nowUtc.AddSeconds(-30), revokedAtUtc: null),
            Sensor("warning", nowUtc.AddMinutes(-3), revokedAtUtc: null),
            Sensor("offline", nowUtc.AddMinutes(-10), revokedAtUtc: null),
            Sensor("revoked", nowUtc.AddSeconds(-20), revokedAtUtc: nowUtc.AddSeconds(-10)));

        db.SecurityEvents.AddRange(
            SecurityEvent(nowUtc.AddMinutes(-30), EventSeverity.Info),
            SecurityEvent(nowUtc.AddMinutes(-25), EventSeverity.Warning),
            SecurityEvent(nowUtc.AddMinutes(-20), EventSeverity.High),
            SecurityEvent(nowUtc.AddMinutes(-10), EventSeverity.Critical, SecuritySourceSystems.SensorLifecycle, forbiddenValue),
            SecurityEvent(nowUtc.AddHours(-25), EventSeverity.Info));

        db.SiemAlerts.AddRange(
            SiemAlert("LIFE-001", AlertStatuses.New, nowUtc.AddMinutes(-15)),
            SiemAlert("LIFE-002", AlertStatuses.Acknowledged, nowUtc.AddMinutes(-10)),
            SiemAlert("BF-001", AlertStatuses.Closed, nowUtc.AddMinutes(-5)));

        db.Incidents.Add(new IncidentRecord
        {
            CreatedAtUtc = nowUtc.AddMinutes(-5),
            Name = "Lifecycle review",
            Severity = EventSeverity.Warning,
            Status = "Open",
            Notes = "aggregate test"
        });

        db.SecurityEventOutboxMessages.AddRange(
            Outbox(SecurityEventOutboxStatus.Pending, nowUtc.AddMinutes(-20)),
            Outbox(SecurityEventOutboxStatus.Processing, nowUtc.AddMinutes(-10)),
            Outbox(SecurityEventOutboxStatus.DeadLetter, nowUtc.AddMinutes(-1)));

        db.SecurityEventInboxReceipts.AddRange(
            Inbox(nowUtc.AddMinutes(-30), nowUtc.AddMinutes(-20), redelivered: false, deliveryCount: 1),
            Inbox(nowUtc.AddMinutes(-10), processedAtUtc: null, redelivered: true, deliveryCount: 2));

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

    private static SecurityEventEntry SecurityEvent(
        DateTime occurredAtUtc,
        EventSeverity severity,
        string sourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
        string additionalValue = "safe") => new()
        {
            OccurredAtUtc = occurredAtUtc,
            EventType = SecurityEventType.ExternalEvent,
            Severity = severity,
            SourceSystem = sourceSystem,
            ExternalEventType = sourceSystem == SecuritySourceSystems.SensorLifecycle ? SensorLifecycleEventTypes.SensorCredentialRotated : null,
            Description = "test event",
            AdditionalDataJson = $$"""{"credential":"{{additionalValue}}","Password":"must-not-render"}"""
        };

    private static SiemAlertRecord SiemAlert(string ruleCode, string status, DateTime createdAtUtc) => new()
    {
        CreatedAtUtc = createdAtUtc,
        RuleCode = ruleCode,
        RuleName = $"{ruleCode} test",
        TriggerKey = $"{ruleCode}:test",
        Severity = EventSeverity.Warning,
        Status = status,
        Description = "aggregate alert"
    };

    private static SecurityEventOutboxMessage Outbox(SecurityEventOutboxStatus status, DateTime createdAtUtc) => new()
    {
        MessageId = Guid.NewGuid(),
        SecurityEventId = 1,
        MessageType = "conshield.security-event",
        PayloadJson = "{\"safe\":true}",
        Status = status,
        CreatedAtUtc = createdAtUtc,
        AvailableAtUtc = createdAtUtc
    };

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
            .UseInMemoryDatabase($"security-summary-report-{Guid.NewGuid():N}")
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
