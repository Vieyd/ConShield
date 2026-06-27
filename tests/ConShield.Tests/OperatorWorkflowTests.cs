using System.Security.Claims;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using ConShield.Web.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class OperatorWorkflowTests
{
    [Fact]
    public void IncidentDetails_ShowsWorkflowActionsForOpenIncident()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Details.cshtml");

        Assert.Contains("Операторский workflow", view, StringComparison.Ordinal);
        Assert.Contains("asp-action=\"Close\"", view, StringComparison.Ordinal);
        Assert.Contains("name=\"conclusion\"", view, StringComparison.Ordinal);
        Assert.Contains("required", view, StringComparison.Ordinal);
        Assert.Contains("Взять в работу", view, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IncidentCanBeMovedToInProgress()
    {
        await using var db = CreateDbContext();
        var incident = SeedIncident(db, IncidentStatuses.New);
        var controller = CreateIncidentController(db);

        var result = await controller.ChangeStatus(incident.Id, IncidentStatuses.InProgress, CancellationToken.None);

        Assert.IsType<RedirectToActionResult>(result);
        var updated = await db.Incidents.SingleAsync();
        Assert.Equal(IncidentStatuses.InProgress, updated.Status);
        Assert.Null(updated.ClosedAtUtc);
        Assert.Null(updated.Conclusion);
    }

    [Fact]
    public async Task IncidentCannotBeClosedWithEmptyConclusion()
    {
        await using var db = CreateDbContext();
        var incident = SeedIncident(db, IncidentStatuses.InProgress);
        var controller = CreateIncidentController(db);

        var result = await controller.Close(incident.Id, "   ", CancellationToken.None);

        Assert.IsType<RedirectToActionResult>(result);
        var updated = await db.Incidents.SingleAsync();
        Assert.Equal(IncidentStatuses.InProgress, updated.Status);
        Assert.Null(updated.ClosedAtUtc);
        Assert.Null(updated.Conclusion);
    }

    [Fact]
    public async Task IncidentCanBeClosedWithTrimmedConclusion()
    {
        await using var db = CreateDbContext();
        var incident = SeedIncident(db, IncidentStatuses.InProgress);
        var controller = CreateIncidentController(db);

        var result = await controller.Close(incident.Id, "  investigated and contained  ", CancellationToken.None);

        Assert.IsType<RedirectToActionResult>(result);
        var updated = await db.Incidents.SingleAsync();
        Assert.Equal(IncidentStatuses.Closed, updated.Status);
        Assert.NotNull(updated.ClosedAtUtc);
        Assert.Equal("investigated and contained", updated.Conclusion);
    }

    [Fact]
    public void ClosedIncidentDisplaysConclusionAndHidesInvalidActions()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Details.cshtml");

        Assert.Contains("Model.Status == IncidentStatuses.Closed", view, StringComparison.Ordinal);
        Assert.Contains("Вывод оператора", view, StringComparison.Ordinal);
        Assert.Contains("Model.Conclusion", view, StringComparison.Ordinal);
        Assert.Contains("Инцидент закрыт; недопустимые действия скрыты.", view, StringComparison.Ordinal);
        Assert.Contains("Model.Status != IncidentStatuses.Closed", view, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SiemAlertCanBeAcknowledgedWithTimestampAndUser()
    {
        await using var db = CreateDbContext();
        var alert = SeedAlert(db, AlertStatuses.New);
        var controller = CreateSiemController(db);

        var result = await controller.ChangeStatus(alert.Id, AlertStatuses.Acknowledged, CancellationToken.None);

        Assert.IsType<RedirectToActionResult>(result);
        var updated = await db.SiemAlerts.SingleAsync();
        Assert.Equal(AlertStatuses.Acknowledged, updated.Status);
        Assert.NotNull(updated.AcknowledgedAtUtc);
        Assert.Equal("adminib", updated.AcknowledgedBy);
    }

    [Fact]
    public void OperatorNavigationLinksExist()
    {
        var summary = ReadRepoFile("src", "ConShield.Web", "Views", "Reports", "SecuritySummary.cshtml");
        var siemDetails = ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Details.cshtml");
        var incidentDetails = ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Details.cshtml");

        Assert.Contains("asp-controller=\"Siem\" asp-action=\"Index\"", summary, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Incidents\" asp-action=\"Details\"", siemDetails, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"SecurityEvents\"", incidentDetails, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Siem\" asp-action=\"Details\"", incidentDetails, StringComparison.Ordinal);
        Assert.DoesNotContain("AdditionalDataJson", incidentDetails, StringComparison.Ordinal);
        Assert.DoesNotContain("PayloadJson", incidentDetails, StringComparison.Ordinal);
    }

    [Fact]
    public void EvidenceExportIncludesSafeOperatorWorkflowSection()
    {
        var script = ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1");

        Assert.Contains("## Operator Workflow", script, StringComparison.Ordinal);
        Assert.Contains("OperatorIncidentCounts", script, StringComparison.Ordinal);
        Assert.Contains("OperatorAcknowledgedAlerts", script, StringComparison.Ordinal);
        Assert.Contains("OperatorClosedIncidents", script, StringComparison.Ordinal);
        Assert.Contains("Conclusion", script, StringComparison.Ordinal);
        Assert.DoesNotContain("AdditionalDataJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SourceEventIdsJson", script, StringComparison.OrdinalIgnoreCase);
    }

    private static IncidentRecord SeedIncident(ApplicationDbContext db, string status)
    {
        var incident = new IncidentRecord
        {
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-10),
            Name = "Operator workflow test",
            Severity = EventSeverity.Warning,
            Status = status,
            SourceEventId = 1,
            Notes = "safe note"
        };

        db.Incidents.Add(incident);
        db.SaveChanges();
        return incident;
    }

    private static SiemAlertRecord SeedAlert(ApplicationDbContext db, string status)
    {
        var alert = new SiemAlertRecord
        {
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-10),
            RuleCode = "RTE-001",
            RuleName = "Runtime test",
            TriggerKey = "runtime:test",
            Severity = EventSeverity.Warning,
            Status = status,
            Description = "safe alert"
        };

        db.SiemAlerts.Add(alert);
        db.SaveChanges();
        return alert;
    }

    private static IncidentsController CreateIncidentController(ApplicationDbContext db)
    {
        var controller = new IncidentsController(db, new NoOpSecurityEventWriter());
        AttachAdminContext(controller);
        return controller;
    }

    private static SiemController CreateSiemController(ApplicationDbContext db)
    {
        var controller = new SiemController(db, new NoOpCorrelationService(), new NoOpSecurityEventWriter());
        AttachAdminContext(controller);
        return controller;
    }

    private static void AttachAdminContext(Controller controller)
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, "adminib"),
                new Claim(ClaimTypes.Role, AppRoles.AdminIB)
            ],
            "Test");
        var httpContext = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        controller.TempData = new TempDataDictionary(httpContext, new InMemoryTempDataProvider());
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"operator-workflow-{Guid.NewGuid():N}")
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

    private sealed class NoOpSecurityEventWriter : ISecurityEventWriter
    {
        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class NoOpCorrelationService : ISiemCorrelationService
    {
        public Task<CorrelationRunResult> RunAsync(CancellationToken cancellationToken = default) => Task.FromResult(new CorrelationRunResult());
    }

    private sealed class InMemoryTempDataProvider : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();

        public void SaveTempData(HttpContext context, IDictionary<string, object> values)
        {
        }
    }
}
