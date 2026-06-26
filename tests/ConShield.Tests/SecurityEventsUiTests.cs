using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.Web.Controllers;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class SecurityEventsUiTests
{
    private const string KnownPlaintextCredential = "plaintext-credential-that-must-not-render";
    private const string KnownApiKey = "api-key-that-must-not-render";

    [Fact]
    public async Task SecurityEventsFilter_FiltersBySourceSystem()
    {
        await using var db = CreateDbContext();
        SeedSecurityEvents(db);
        var controller = new SecurityEventsController(db);

        var model = await IndexModelAsync(controller, new SecurityEventFilterViewModel
        {
            SourceSystem = SecuritySourceSystems.SensorLifecycle.ToUpperInvariant()
        });

        Assert.Equal(3, model.Items.Count);
        Assert.All(model.Items, item => Assert.Equal(SecuritySourceSystems.SensorLifecycle, item.SourceSystem));
        Assert.Equal(3, model.Paging.TotalCount);
    }

    [Fact]
    public async Task SecurityEventsIndex_DefaultPageSizeIsCappedAndReportsTotalCount()
    {
        await using var db = CreateDbContext();
        var now = DateTime.UtcNow;
        for (var index = 0; index < 60; index++)
        {
            db.SecurityEvents.Add(new SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-index),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = "operator",
                Description = $"event {index}"
            });
        }

        await db.SaveChangesAsync();
        var controller = new SecurityEventsController(db);

        var model = await IndexModelAsync(controller, new SecurityEventFilterViewModel());

        Assert.Equal(PagingViewModel.DefaultPageSize, model.Items.Count);
        Assert.Equal(60, model.Paging.TotalCount);
        Assert.Equal(1, model.Paging.Page);
        Assert.Equal(PagingViewModel.DefaultPageSize, model.Paging.PageSize);
        Assert.True(model.Paging.HasNextPage);
    }

    [Fact]
    public async Task SecurityEventsIndex_NormalizesInvalidPagingAndCapsPageSize()
    {
        await using var db = CreateDbContext();
        var now = DateTime.UtcNow;
        for (var index = 0; index < 130; index++)
        {
            db.SecurityEvents.Add(new SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-index),
                EventType = SecurityEventType.AccessDenied,
                Severity = EventSeverity.Critical,
                UserName = "runtime-agent",
                Description = $"runtime event {index}"
            });
        }

        await db.SaveChangesAsync();
        var controller = new SecurityEventsController(db);

        var result = await controller.Index(new SecurityEventFilterViewModel(), CancellationToken.None, page: -10, pageSize: 500);
        var view = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<SecurityEventIndexViewModel>(view.Model);

        Assert.Equal(PagingViewModel.MaxPageSize, model.Items.Count);
        Assert.Equal(1, model.Paging.Page);
        Assert.Equal(PagingViewModel.MaxPageSize, model.Paging.PageSize);
        Assert.Equal(130, model.Paging.TotalCount);
    }

    [Fact]
    public async Task SecurityEventsFilter_FiltersByExternalEventType()
    {
        await using var db = CreateDbContext();
        SeedSecurityEvents(db);
        var controller = new SecurityEventsController(db);

        var model = await IndexModelAsync(controller, new SecurityEventFilterViewModel
        {
            ExternalEventType = SensorLifecycleEventTypes.SensorCredentialRevoked.ToUpperInvariant()
        });

        var item = Assert.Single(model.Items);
        Assert.Equal(SensorLifecycleEventTypes.SensorCredentialRevoked, item.ExternalEventType);
    }

    [Fact]
    public async Task SecurityEventsFilter_CanShowSensorLifecycleEvents()
    {
        await using var db = CreateDbContext();
        SeedSecurityEvents(db);
        var controller = new SecurityEventsController(db);

        var model = await IndexModelAsync(controller, new SecurityEventFilterViewModel
        {
            SourceSystem = SecuritySourceSystems.SensorLifecycle
        });

        Assert.Equal(3, model.Items.Count);
        Assert.Contains(model.Items, item => item.ExternalEventType == SensorLifecycleEventTypes.SensorCredentialRotated);
        Assert.Contains(model.Items, item => item.ExternalEventType == SensorLifecycleEventTypes.SensorCredentialRevoked);
        Assert.Contains(model.Items, item => item.ExternalEventType == SensorLifecycleEventTypes.SensorRevoked);
    }

    [Fact]
    public async Task SecurityEventsFilter_CanShowCredentialRotationsOnly()
    {
        await using var db = CreateDbContext();
        SeedSecurityEvents(db);
        var controller = new SecurityEventsController(db);

        var model = await IndexModelAsync(controller, new SecurityEventFilterViewModel
        {
            SourceSystem = SecuritySourceSystems.SensorLifecycle,
            ExternalEventType = SensorLifecycleEventTypes.SensorCredentialRotated
        });

        var item = Assert.Single(model.Items);
        Assert.Equal(SensorLifecycleEventTypes.SensorCredentialRotated, item.ExternalEventType);
        Assert.Equal("credential rotation", item.Description);
    }

    [Fact]
    public void SecurityEventsIndex_RendersLifecycleQuickLinks()
    {
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml");

        Assert.Contains("Lifecycle сенсоров", viewText, StringComparison.Ordinal);
        Assert.Contains("Ротации", viewText, StringComparison.Ordinal);
        Assert.Contains("Отзыв учетных данных", viewText, StringComparison.Ordinal);
        Assert.Contains("Отзыв сенсоров", viewText, StringComparison.Ordinal);
        Assert.Contains("asp-route-SourceSystem", viewText, StringComparison.Ordinal);
        Assert.Contains("asp-route-ExternalEventType", viewText, StringComparison.Ordinal);
        Assert.Contains(nameof(SecuritySourceSystems.SensorLifecycle), viewText, StringComparison.Ordinal);
        Assert.Contains(nameof(SensorLifecycleEventTypes.SensorCredentialRotated), viewText, StringComparison.Ordinal);
        Assert.Contains(nameof(SensorLifecycleEventTypes.SensorCredentialRevoked), viewText, StringComparison.Ordinal);
        Assert.Contains(nameof(SensorLifecycleEventTypes.SensorRevoked), viewText, StringComparison.Ordinal);
    }

    [Fact]
    public void SecurityEventsIndex_RendersLifecycleAuditHelpText()
    {
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml");

        Assert.Contains(nameof(SecuritySourceSystems.SensorLifecycle), viewText, StringComparison.Ordinal);
        Assert.Contains(nameof(SensorLifecycleEventTypes.SensorCredentialRotated), viewText, StringComparison.Ordinal);
        Assert.Contains(nameof(SensorLifecycleEventTypes.SensorCredentialRevoked), viewText, StringComparison.Ordinal);
        Assert.Contains(nameof(SensorLifecycleEventTypes.SensorRevoked), viewText, StringComparison.Ordinal);
        Assert.Contains("docs/SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md", viewText, StringComparison.Ordinal);
        Assert.Contains("docs/OPERATIONS_AND_SIEM_RUNBOOK.md", viewText, StringComparison.Ordinal);
        Assert.Contains("не вставляйте учетные данные", viewText, StringComparison.Ordinal);
    }

    [Fact]
    public void OperationsAndSiemRunbook_ContainsRequiredOperatorGuidance()
    {
        var runbook = ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md");

        Assert.Contains("/Operations/Health", runbook, StringComparison.Ordinal);
        Assert.Contains("/SecurityEvents", runbook, StringComparison.Ordinal);
        Assert.Contains("/Sensors", runbook, StringComparison.Ordinal);
        Assert.Contains("LIFE-001", runbook, StringComparison.Ordinal);
        Assert.Contains("LIFE-002", runbook, StringComparison.Ordinal);
        Assert.Contains("conshield.sensor-lifecycle", runbook, StringComparison.Ordinal);
        Assert.Contains("VerifierSha256", runbook, StringComparison.Ordinal);
        Assert.Contains("Never paste generated credentials", runbook, StringComparison.Ordinal);
    }

    [Fact]
    public void SecurityEventsIndex_RendersSourceSystemAndExternalEventTypeAsCompactSummary()
    {
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml");

        Assert.Contains("Источник", viewText, StringComparison.Ordinal);
        Assert.Contains("Внешний тип", viewText, StringComparison.Ordinal);
        Assert.Contains("name=\"SourceSystem\"", viewText, StringComparison.Ordinal);
        Assert.Contains("name=\"ExternalEventType\"", viewText, StringComparison.Ordinal);
        Assert.Contains("@item.SourceSystem", viewText, StringComparison.Ordinal);
        Assert.Contains("@item.ExternalEventType", viewText, StringComparison.Ordinal);
        Assert.Contains("Актор / источник", viewText, StringComparison.Ordinal);
        Assert.Contains("ShortTechnicalValue(item.SourceSystem)", viewText, StringComparison.Ordinal);
        Assert.Contains("ShortTechnicalValue(item.ExternalEventType)", viewText, StringComparison.Ordinal);
        Assert.DoesNotContain("<th>Доп. данные</th>", viewText, StringComparison.Ordinal);
        Assert.DoesNotContain("@item.AdditionalDataJson", viewText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SecurityEventsIndex_DoesNotRenderCredentialPlaintextOrVerifier()
    {
        await using var db = CreateDbContext();
        var sensorId = Guid.NewGuid();
        db.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow,
            EventType = SecurityEventType.ExternalEvent,
            Severity = EventSeverity.Info,
            UserName = "adminib",
            SourceSystem = SecuritySourceSystems.SensorLifecycle,
            ExternalEventType = SensorLifecycleEventTypes.SensorCredentialRotated,
            Description = "credential rotation",
            AdditionalDataJson = $$"""
                {"sensorId":"{{sensorId}}","credentialId":"{{Guid.NewGuid()}}","displayName":"fedora-runtime-01","requestedBy":"adminib","action":"rotateCredential","reasonProvided":true}
                """
        });
        await db.SaveChangesAsync();
        var controller = new SecurityEventsController(db);

        var model = await IndexModelAsync(controller, new SecurityEventFilterViewModel
        {
            SourceSystem = SecuritySourceSystems.SensorLifecycle
        });
        var renderedData = Assert.Single(model.Items).AdditionalDataJson ?? string.Empty;
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml");

        Assert.DoesNotContain(KnownPlaintextCredential, renderedData, StringComparison.Ordinal);
        Assert.DoesNotContain(KnownApiKey, renderedData, StringComparison.Ordinal);
        Assert.DoesNotContain("VerifierSha256", renderedData, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(KnownPlaintextCredential, viewText, StringComparison.Ordinal);
        Assert.DoesNotContain(KnownApiKey, viewText, StringComparison.Ordinal);
        Assert.DoesNotContain("VerifierSha256", viewText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SensorLifecycleAuditPlaybook_ContainsRequiredOperatorGuidance()
    {
        var playbook = ReadRepoFile("docs", "SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md");

        Assert.Contains("conshield.sensor-lifecycle", playbook, StringComparison.Ordinal);
        Assert.Contains("sensor.credential.rotated", playbook, StringComparison.Ordinal);
        Assert.Contains("sensor.credential.revoked", playbook, StringComparison.Ordinal);
        Assert.Contains("sensor.revoked", playbook, StringComparison.Ordinal);
        Assert.Contains("VerifierSha256", playbook, StringComparison.Ordinal);
        Assert.Contains("plaintext credential", playbook, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Do not paste credentials", playbook, StringComparison.Ordinal);
        Assert.Contains("API key", playbook, StringComparison.Ordinal);
        Assert.Contains("Fedora protected env file content", playbook, StringComparison.Ordinal);
    }

    private static async Task<SecurityEventIndexViewModel> IndexModelAsync(
        SecurityEventsController controller,
        SecurityEventFilterViewModel filter)
    {
        var result = await controller.Index(filter, CancellationToken.None);
        var view = Assert.IsType<ViewResult>(result);
        return Assert.IsType<SecurityEventIndexViewModel>(view.Model);
    }

    private static void SeedSecurityEvents(ApplicationDbContext db)
    {
        var now = DateTime.UtcNow;
        db.SecurityEvents.AddRange(
            LifecycleEvent(now.AddMinutes(-1), SensorLifecycleEventTypes.SensorCredentialRotated, "credential rotation"),
            LifecycleEvent(now.AddMinutes(-2), SensorLifecycleEventTypes.SensorCredentialRevoked, "credential revoke"),
            LifecycleEvent(now.AddMinutes(-3), SensorLifecycleEventTypes.SensorRevoked, "sensor revoke"),
            new SecurityEventEntry
            {
                OccurredAtUtc = now.AddMinutes(-4),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = "operator",
                SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
                Description = "non lifecycle event",
                AdditionalDataJson = "{\"source\":\"runtime\"}"
            });
        db.SaveChanges();
    }

    private static SecurityEventEntry LifecycleEvent(DateTime occurredAtUtc, string externalEventType, string description) => new()
    {
        OccurredAtUtc = occurredAtUtc,
        EventType = SecurityEventType.ExternalEvent,
        Severity = EventSeverity.Info,
        UserName = "adminib",
        SourceSystem = SecuritySourceSystems.SensorLifecycle,
        ExternalEventType = externalEventType,
        Description = description,
        AdditionalDataJson = "{\"sensorId\":\"00000000-0000-0000-0000-000000000001\",\"requestedBy\":\"adminib\",\"reasonProvided\":true}"
    };

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"security-events-ui-{Guid.NewGuid():N}")
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
