using System.Text.Json;
using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize]
public class SiemController : Controller
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ISiemCorrelationService _correlationService;
    private readonly ISecurityEventWriter _eventWriter;

    public SiemController(ApplicationDbContext dbContext, ISiemCorrelationService correlationService, ISecurityEventWriter eventWriter)
    {
        _dbContext = dbContext;
        _correlationService = correlationService;
        _eventWriter = eventWriter;
    }

    public async Task<IActionResult> Index(
        [FromQuery] SiemAlertFilterViewModel filter,
        CancellationToken cancellationToken,
        [FromQuery] int? page = null,
        [FromQuery] int? pageSize = null)
    {
        var query = _dbContext.SiemAlerts
            .ApplySiemAlertFilters(filter.Status, filter.Severity, filter.RuleCode, filter.SearchText);

        var (normalizedPage, normalizedPageSize) = PagingViewModel.Normalize(page, pageSize);
        var totalCount = await query.CountAsync(cancellationToken);
        normalizedPage = PagingViewModel.ClampPage(normalizedPage, normalizedPageSize, totalCount);

        var items = await query
            .OrderByDescending(x => x.CreatedAtUtc)
            .ThenByDescending(x => x.Id)
            .Skip((normalizedPage - 1) * normalizedPageSize)
            .Take(normalizedPageSize)
            .ToListAsync(cancellationToken);

        return View(new SiemAlertIndexViewModel
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

    public IActionResult Rules()
    {
        return View(SiemRuleCatalog.Rules.OrderBy(x => x.RuleCode).ToList());
    }

    public async Task<IActionResult> Details(long id, CancellationToken cancellationToken)
    {
        var alert = await _dbContext.SiemAlerts.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (alert is null)
        {
            return NotFound();
        }

        var sourceEventIds = ParseIds(alert.SourceEventIdsJson);
        var sourceEvents = sourceEventIds.Count == 0
            ? new List<ConShield.Data.Entities.SecurityEventEntry>()
            : await _dbContext.SecurityEvents
                .Where(x => sourceEventIds.Contains(x.Id))
                .OrderByDescending(x => x.OccurredAtUtc)
                .ToListAsync(cancellationToken);

        var incident = alert.IncidentId.HasValue
            ? await _dbContext.Incidents.FirstOrDefaultAsync(x => x.Id == alert.IncidentId.Value, cancellationToken)
            : null;

        return View(new SiemAlertDetailsViewModel
        {
            Alert = alert,
            Incident = incident,
            SourceEventIds = sourceEventIds,
            SourceEvents = sourceEvents
        });
    }

    [Authorize(Roles = AppRoles.AdminIB)]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RunCorrelation(CancellationToken cancellationToken)
    {
        var result = await _correlationService.RunAsync(cancellationToken);
        TempData["SiemMessage"] = $"Корреляция выполнена: alerts={result.CreatedAlerts}, incidents={result.CreatedIncidents}, rules={string.Join(", ", result.TriggeredRules.Distinct())}";
        return RedirectToAction(nameof(Index));
    }

    [Authorize(Roles = AppRoles.AdminIB)]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangeStatus(long id, string status, CancellationToken cancellationToken)
    {
        var alert = await _dbContext.SiemAlerts.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (alert is null)
        {
            return NotFound();
        }

        alert.Status = status switch
        {
            AlertStatuses.Acknowledged => AlertStatuses.Acknowledged,
            AlertStatuses.Closed => AlertStatuses.Closed,
            _ => AlertStatuses.New
        };

        await _dbContext.SaveChangesAsync(cancellationToken);

        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = SecurityEventType.CorrelationAlert,
            Severity = alert.Severity,
            UserName = User.Identity?.Name,
            SourceIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            Description = $"Изменен статус SIEM alert #{alert.Id} на {alert.Status}.",
            AdditionalData = new { alert.Id, alert.RuleCode, alert.Status }
        });

        return RedirectToAction(nameof(Index));
    }


    [Authorize(Roles = AppRoles.AdminIB)]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetState(CancellationToken cancellationToken)
    {
        var alerts = await _dbContext.SiemAlerts.ToListAsync(cancellationToken);
        var allIncidents = await _dbContext.Incidents.ToListAsync(cancellationToken);
        var incidents = await _dbContext.Incidents
            .Where(x => EF.Functions.ILike(x.Name, "[%")
                        || EF.Functions.ILike(x.Name, "%демонстрационный%")
                        || (x.Notes != null && EF.Functions.ILike(x.Notes, "%демонстрац%")))
            .ToListAsync(cancellationToken);

        var removedAlerts = alerts.Count;
        var removedIncidents = incidents.Count;

        if (removedAlerts > 0)
        {
            _dbContext.SiemAlerts.RemoveRange(alerts);
        }

        if (removedIncidents > 0)
        {
            _dbContext.Incidents.RemoveRange(incidents);
        }

        await _dbContext.SaveChangesAsync(cancellationToken);

        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = SecurityEventType.IncidentUpdated,
            Severity = EventSeverity.Info,
            UserName = User.Identity?.Name,
            SourceIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            Description = "Администратор выполнил очистку SIEM-оповещений и автоматически сформированных инцидентов.",
            AdditionalData = new { removedAlerts, removedIncidents }
        });

        TempData["SiemMessage"] = $"Удалено SIEM-оповещений: {removedAlerts}, инцидентов: {removedIncidents}. Журнал событий безопасности сохранён.";
        return RedirectToAction(nameof(Index));
    }

    [Authorize(Roles = AppRoles.AdminIB)]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> GenerateScenario(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;

        var events = new[]
        {
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-95),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = "adminib",
                SourceIp = "10.10.10.21",
                Description = "Неуспешная попытка входа в систему."
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-80),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = "adminib",
                SourceIp = "10.10.10.21",
                Description = "Неуспешная попытка входа в систему."
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-65),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = "adminib",
                SourceIp = "10.10.10.21",
                Description = "Неуспешная попытка входа в систему."
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-50),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = "operator",
                SourceIp = "10.10.10.34",
                Description = "Неуспешная попытка входа в систему."
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-40),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = "operator",
                SourceIp = "10.10.10.34",
                Description = "Неуспешная попытка входа в систему."
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-30),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = "operator",
                SourceIp = "10.10.10.34",
                Description = "Неуспешная попытка входа в систему."
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-25),
                EventType = SecurityEventType.UserExceptionUpdated,
                Severity = EventSeverity.Info,
                UserName = "adminib",
                SourceIp = "127.0.0.1",
                Description = "Изменена запись UserException #1.",
                AdditionalDataJson = JsonSerializer.Serialize(new { Id = 1, UserLogin = "svc-build", SourceSystem = "CI/CD" })
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-22),
                EventType = SecurityEventType.UserExceptionUpdated,
                Severity = EventSeverity.Info,
                UserName = "adminib",
                SourceIp = "127.0.0.1",
                Description = "Изменена запись UserException #2.",
                AdditionalDataJson = JsonSerializer.Serialize(new { Id = 2, UserLogin = "runtime-user", SourceSystem = "Runtime" })
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-18),
                EventType = SecurityEventType.UserExceptionDeleted,
                Severity = EventSeverity.Warning,
                UserName = "adminib",
                SourceIp = "127.0.0.1",
                Description = "Удалена запись UserException #3.",
                AdditionalDataJson = JsonSerializer.Serialize(new { Id = 3, UserLogin = "temp-user", SourceSystem = "Runtime" })
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-15),
                EventType = SecurityEventType.UserExceptionUpdated,
                Severity = EventSeverity.Info,
                UserName = "adminib",
                SourceIp = "127.0.0.1",
                Description = "Изменена запись UserException #1.",
                AdditionalDataJson = JsonSerializer.Serialize(new { Id = 1, UserLogin = "svc-build", SourceSystem = "CI/CD" })
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddSeconds(-10),
                EventType = SecurityEventType.UserExceptionUpdated,
                Severity = EventSeverity.Info,
                UserName = "adminib",
                SourceIp = "127.0.0.1",
                Description = "Изменена запись UserException #2.",
                AdditionalDataJson = JsonSerializer.Serialize(new { Id = 2, UserLogin = "runtime-user", SourceSystem = "Runtime" })
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddMinutes(-4),
                EventType = SecurityEventType.AccessDenied,
                Severity = EventSeverity.Critical,
                UserName = "runtime-agent",
                SourceIp = "172.16.5.44",
                Description = "Критическое событие контроля выполнения контейнера."
            },
            new ConShield.Data.Entities.SecurityEventEntry
            {
                OccurredAtUtc = now.AddMinutes(-3),
                EventType = SecurityEventType.AccessDenied,
                Severity = EventSeverity.Critical,
                UserName = "runtime-agent",
                SourceIp = "172.16.5.44",
                Description = "Повторное критическое событие контроля выполнения контейнера."
            }
        };

        _dbContext.SecurityEvents.AddRange(events);
        await _dbContext.SaveChangesAsync(cancellationToken);

        var result = await _correlationService.RunAsync(cancellationToken);

        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = SecurityEventType.CorrelationAlert,
            Severity = EventSeverity.Info,
            UserName = User.Identity?.Name,
            SourceIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            Description = "Администратор сформировал пакет тестовых событий и выполнил корреляцию.",
            AdditionalData = new { events = events.Length, result.CreatedAlerts, result.CreatedIncidents }
        });

        TempData["SiemMessage"] = $"Сформировано событий: {events.Length}. Создано SIEM-оповещений: {result.CreatedAlerts}, инцидентов: {result.CreatedIncidents}.";
        return RedirectToAction(nameof(Index));
    }

    private static IReadOnlyCollection<long> ParseIds(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<long>();
        }

        try
        {
            var items = JsonSerializer.Deserialize<List<long>>(json);
            return items ?? (IReadOnlyCollection<long>)Array.Empty<long>();
        }
        catch
        {
            return Array.Empty<long>();
        }
    }
}
