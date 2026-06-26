using ConShield.Application;
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

    public async Task<IActionResult> Index(
        [FromQuery] SecurityEventFilterViewModel filter,
        CancellationToken cancellationToken,
        [FromQuery] int? page = null,
        [FromQuery] int? pageSize = null)
    {
        var query = _dbContext.SecurityEvents
            .ApplySecurityEventFilters(
                filter.UserName,
                filter.Severity,
                filter.EventType,
                filter.SearchText,
                filter.SourceSystem,
                filter.ExternalEventType);

        var (normalizedPage, normalizedPageSize) = PagingViewModel.Normalize(page, pageSize);
        var totalCount = await query.CountAsync(cancellationToken);
        normalizedPage = PagingViewModel.ClampPage(normalizedPage, normalizedPageSize, totalCount);

        var events = await query
            .OrderByDescending(x => x.OccurredAtUtc)
            .ThenByDescending(x => x.Id)
            .Skip((normalizedPage - 1) * normalizedPageSize)
            .Take(normalizedPageSize)
            .ToListAsync(cancellationToken);

        return View(new SecurityEventIndexViewModel
        {
            Filter = filter,
            Items = events,
            Paging = new PagingViewModel
            {
                Page = normalizedPage,
                PageSize = normalizedPageSize,
                TotalCount = totalCount
            }
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
                x.SourceSystem,
                x.ExternalEventType,
                x.Description,
                x.AdditionalDataJson
            })
            .ToListAsync(cancellationToken);

        return Json(events);
    }
}
