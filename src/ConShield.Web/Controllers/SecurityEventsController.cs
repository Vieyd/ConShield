using ConShield.Data;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize]
public class SecurityEventsController : Controller
{
    private readonly ApplicationDbContext _dbContext;

    public SecurityEventsController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<IActionResult> Index([FromQuery] SecurityEventFilterViewModel filter, CancellationToken cancellationToken)
    {
        var query = _dbContext.SecurityEvents.AsQueryable();

        if (!string.IsNullOrWhiteSpace(filter.UserName))
        {
            var userName = filter.UserName.Trim();
            query = query.Where(x => x.UserName != null && x.UserName.Contains(userName));
        }

        if (filter.Severity.HasValue)
        {
            query = query.Where(x => x.Severity == filter.Severity.Value);
        }

        if (filter.EventType.HasValue)
        {
            query = query.Where(x => x.EventType == filter.EventType.Value);
        }

        if (!string.IsNullOrWhiteSpace(filter.SearchText))
        {
            var searchText = filter.SearchText.Trim();
            query = query.Where(x =>
                x.Description.Contains(searchText) ||
                (x.AdditionalDataJson != null && x.AdditionalDataJson.Contains(searchText)) ||
                (x.SourceIp != null && x.SourceIp.Contains(searchText)));
        }

        var events = await query
            .OrderByDescending(x => x.OccurredAtUtc)
            .Take(300)
            .ToListAsync(cancellationToken);

        return View(new SecurityEventIndexViewModel
        {
            Filter = filter,
            Items = events
        });
    }

    [HttpGet("api/security-events/recent")]
    [Authorize(Roles = "AdminIB")]
    public async Task<IActionResult> RecentJson(CancellationToken cancellationToken)
    {
        var events = await _dbContext.SecurityEvents
            .OrderByDescending(x => x.OccurredAtUtc)
            .Take(100)
            .Select(x => new
            {
                x.Id,
                x.OccurredAtUtc,
                x.EventType,
                x.Severity,
                x.UserName,
                x.SourceIp,
                x.Description,
                x.AdditionalDataJson
            })
            .ToListAsync(cancellationToken);

        return Json(events);
    }
}
