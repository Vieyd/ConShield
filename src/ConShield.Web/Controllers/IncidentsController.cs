using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize]
public class IncidentsController : Controller
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ISecurityEventWriter _eventWriter;

    public IncidentsController(ApplicationDbContext dbContext, ISecurityEventWriter eventWriter)
    {
        _dbContext = dbContext;
        _eventWriter = eventWriter;
    }

    public async Task<IActionResult> Index(
        [FromQuery] IncidentFilterViewModel filter,
        CancellationToken cancellationToken,
        [FromQuery] int? page = null,
        [FromQuery] int? pageSize = null)
    {
        var query = _dbContext.Incidents
            .ApplyIncidentFilters(filter.Status, filter.Severity, filter.SearchText);

        var (normalizedPage, normalizedPageSize) = PagingViewModel.Normalize(page, pageSize);
        var totalCount = await query.CountAsync(cancellationToken);
        normalizedPage = PagingViewModel.ClampPage(normalizedPage, normalizedPageSize, totalCount);

        var items = await query
            .OrderByDescending(x => x.CreatedAtUtc)
            .ThenByDescending(x => x.Id)
            .Skip((normalizedPage - 1) * normalizedPageSize)
            .Take(normalizedPageSize)
            .ToListAsync(cancellationToken);

        return View(new IncidentIndexViewModel
        {
            Filter = filter,
            Items = items,
            Paging = new PagingViewModel
            {
                Page = normalizedPage,
                PageSize = normalizedPageSize,
                TotalCount = totalCount
            }
        });
    }

    public async Task<IActionResult> Details(long id, CancellationToken cancellationToken)
    {
        var item = await _dbContext.Incidents.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (item is null)
        {
            return NotFound();
        }

        ViewBag.SourceEvent = item.SourceEventId.HasValue
            ? await _dbContext.SecurityEvents.FirstOrDefaultAsync(x => x.Id == item.SourceEventId.Value, cancellationToken)
            : null;
        ViewBag.RelatedAlert = await _dbContext.SiemAlerts
            .Where(x => x.IncidentId == item.Id)
            .OrderByDescending(x => x.CreatedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        return View(item);
    }

    [Authorize(Roles = AppRoles.AdminIB)]
    public IActionResult Create()
    {
        return View(new IncidentEditViewModel
        {
            Status = IncidentStatuses.New,
            Severity = EventSeverity.Warning
        });
    }

    [Authorize(Roles = AppRoles.AdminIB)]
    public async Task<IActionResult> CreateFromEvent(long eventId, CancellationToken cancellationToken)
    {
        var securityEvent = await _dbContext.SecurityEvents.FirstOrDefaultAsync(x => x.Id == eventId, cancellationToken);
        if (securityEvent is null)
        {
            return NotFound();
        }

        var model = new IncidentEditViewModel
        {
            Name = $"Инцидент по событию #{securityEvent.Id}",
            Severity = securityEvent.Severity,
            Status = IncidentStatuses.New,
            SourceEventId = securityEvent.Id,
            Notes = securityEvent.Description
        };

        return View("Create", model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = AppRoles.AdminIB)]
    public async Task<IActionResult> Create(IncidentEditViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        model.Status = NormalizeStatus(model.Status);

        var entity = new IncidentRecord
        {
            Name = model.Name,
            Severity = model.Severity,
            Status = model.Status,
            SourceEventId = model.SourceEventId,
            Notes = model.Notes,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.Incidents.Add(entity);
        await _dbContext.SaveChangesAsync(cancellationToken);

        await WriteIncidentAuditAsync(
            SecurityEventType.IncidentCreated,
            entity.Severity,
            $"Создан инцидент #{entity.Id}: {entity.Name}.",
            new { entity.Id, entity.Status, entity.SourceEventId },
            cancellationToken);

        return RedirectToAction(nameof(Index));
    }

    [Authorize(Roles = AppRoles.AdminIB)]
    public async Task<IActionResult> Edit(long id, CancellationToken cancellationToken)
    {
        var item = await _dbContext.Incidents.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (item is null)
        {
            return NotFound();
        }

        return View(new IncidentEditViewModel
        {
            Id = item.Id,
            Name = item.Name,
            Severity = item.Severity,
            Status = item.Status,
            SourceEventId = item.SourceEventId,
            Notes = item.Notes
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = AppRoles.AdminIB)]
    public async Task<IActionResult> Edit(IncidentEditViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var entity = await _dbContext.Incidents.FirstOrDefaultAsync(x => x.Id == model.Id, cancellationToken);
        if (entity is null)
        {
            return NotFound();
        }

        entity.Name = model.Name;
        entity.Severity = model.Severity;
        entity.Status = NormalizeStatus(model.Status);
        entity.SourceEventId = model.SourceEventId;
        entity.Notes = model.Notes;

        await _dbContext.SaveChangesAsync(cancellationToken);

        await WriteIncidentAuditAsync(
            SecurityEventType.IncidentUpdated,
            entity.Severity,
            $"Изменен инцидент #{entity.Id}: {entity.Name}.",
            new { entity.Id, entity.Status, entity.SourceEventId },
            cancellationToken);

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = AppRoles.AdminIB)]
    public async Task<IActionResult> ChangeStatus(long id, string status, CancellationToken cancellationToken)
    {
        var entity = await _dbContext.Incidents.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (entity is null)
        {
            return NotFound();
        }

        var normalizedStatus = NormalizeStatus(status);
        if (entity.Status == IncidentStatuses.Closed)
        {
            return RedirectToAction(nameof(Details), new { id = entity.Id });
        }

        entity.Status = normalizedStatus == IncidentStatuses.Closed
            ? IncidentStatuses.InProgress
            : normalizedStatus;
        await _dbContext.SaveChangesAsync(cancellationToken);

        await WriteIncidentAuditAsync(
            SecurityEventType.IncidentUpdated,
            entity.Severity,
            $"Изменен статус инцидента #{entity.Id} на {entity.Status}.",
            new { entity.Id, entity.Status, entity.SourceEventId },
            cancellationToken);

        return RedirectToAction(nameof(Details), new { id = entity.Id });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = AppRoles.AdminIB)]
    public async Task<IActionResult> Close(long id, string? conclusion, CancellationToken cancellationToken)
    {
        var entity = await _dbContext.Incidents.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (entity is null)
        {
            return NotFound();
        }

        if (entity.Status == IncidentStatuses.Closed)
        {
            return RedirectToAction(nameof(Details), new { id = entity.Id });
        }

        var normalizedConclusion = NormalizeConclusion(conclusion);
        if (string.IsNullOrWhiteSpace(normalizedConclusion))
        {
            TempData["IncidentError"] = "Для закрытия инцидента укажите непустой вывод оператора.";
            return RedirectToAction(nameof(Details), new { id = entity.Id });
        }

        entity.Status = IncidentStatuses.Closed;
        entity.ClosedAtUtc = DateTime.UtcNow;
        entity.Conclusion = normalizedConclusion;
        await _dbContext.SaveChangesAsync(cancellationToken);

        await WriteIncidentAuditAsync(
            SecurityEventType.IncidentUpdated,
            entity.Severity,
            $"Закрыт инцидент #{entity.Id}: {entity.Name}.",
            new { entity.Id, entity.Status, entity.SourceEventId, conclusionProvided = true },
            cancellationToken);

        return RedirectToAction(nameof(Details), new { id = entity.Id });
    }

    private static string NormalizeStatus(string? status)
    {
        return status switch
        {
            IncidentStatuses.InProgress => IncidentStatuses.InProgress,
            IncidentStatuses.Closed => IncidentStatuses.Closed,
            _ => IncidentStatuses.New
        };
    }

    private static string NormalizeConclusion(string? conclusion)
    {
        var trimmed = (conclusion ?? string.Empty).Trim();
        return trimmed.Length <= 500 ? trimmed : trimmed[..500];
    }

    private async Task WriteIncidentAuditAsync(SecurityEventType eventType, EventSeverity severity, string description, object additionalData, CancellationToken cancellationToken)
    {
        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = eventType,
            Severity = severity,
            UserName = User.Identity?.Name,
            SourceIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            Description = description,
            AdditionalData = additionalData
        });
    }
}
