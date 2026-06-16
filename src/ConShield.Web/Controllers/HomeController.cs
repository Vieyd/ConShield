using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize]
public class HomeController : Controller
{
    private readonly ApplicationDbContext _dbContext;

    public HomeController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var model = new HomeDashboardViewModel
        {
            UserExceptionsCount = await _dbContext.UserExceptions.CountAsync(cancellationToken),
            ActiveExceptionsCount = await _dbContext.UserExceptions.CountAsync(x => x.IsActive, cancellationToken),
            SecurityEventsCount = await _dbContext.SecurityEvents.CountAsync(cancellationToken),
            CriticalEventsCount = await _dbContext.SecurityEvents.CountAsync(x => x.Severity == EventSeverity.Critical, cancellationToken),
            IncidentsCount = await _dbContext.Incidents.CountAsync(cancellationToken),
            NewIncidentsCount = await _dbContext.Incidents.CountAsync(x => x.Status == IncidentStatuses.New, cancellationToken),
            InProgressIncidentsCount = await _dbContext.Incidents.CountAsync(x => x.Status == IncidentStatuses.InProgress, cancellationToken),
            ClosedIncidentsCount = await _dbContext.Incidents.CountAsync(x => x.Status == IncidentStatuses.Closed, cancellationToken),
            SiemAlertsCount = await _dbContext.SiemAlerts.CountAsync(cancellationToken),
            NewSiemAlertsCount = await _dbContext.SiemAlerts.CountAsync(x => x.Status == AlertStatuses.New, cancellationToken),
            RecentAlerts = await _dbContext.SiemAlerts
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(5)
                .ToListAsync(cancellationToken),
            RecentIncidents = await _dbContext.Incidents
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(5)
                .ToListAsync(cancellationToken),
            RecentCriticalEvents = await _dbContext.SecurityEvents
                .Where(x => x.Severity == EventSeverity.Critical)
                .OrderByDescending(x => x.OccurredAtUtc)
                .Take(5)
                .ToListAsync(cancellationToken)
        };

        return View(model);
    }

    [AllowAnonymous]
    public IActionResult Error()
    {
        return View();
    }
}
