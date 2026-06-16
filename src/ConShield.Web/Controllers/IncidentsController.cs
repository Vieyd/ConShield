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

    public async Task<IActionResult> Index([FromQuery] IncidentFilterViewModel filter, CancellationToken cancellationToken)
    {
        var query = _dbContext.Incidents.AsQueryable();

        if (!string.IsNullOrWhiteSpace(filter.Status))
        {
            var status = filter.Status.Trim();
            query = query.Where(x => x.Status == status);
        }

        if (filter.Severity.HasValue)
        {
            query = query.Where(x => x.Severity == filter.Severity.Value);
        }

        if (!string.IsNullOrWhiteSpace(filter.SearchText))
        {
            var searchText = filter.SearchText.Trim();
            query = query.Where(x =>
                x.Name.Contains(searchText) ||
                (x.Notes != null && x.Notes.Contains(searchText)) ||
                (x.SourceEventId.HasValue && x.SourceEventId.Value.ToString().Contains(searchText)));
        }

        var items = await query
            .OrderByDescending(x => x.CreatedAtUtc)
            .ToListAsync(cancellationToken);

        return View(new IncidentIndexViewModel
        {
            Filter = filter,
            Items = items
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

        entity.Status = NormalizeStatus(status);
        await _dbContext.SaveChangesAsync(cancellationToken);

        await WriteIncidentAuditAsync(
            SecurityEventType.IncidentUpdated,
            entity.Severity,
            $"Изменен статус инцидента #{entity.Id} на {entity.Status}.",
            new { entity.Id, entity.Status, entity.SourceEventId },
            cancellationToken);

        return RedirectToAction(nameof(Index));
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
