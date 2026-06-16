using System.Text.Json;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Application;

public class SiemCorrelationService : ISiemCorrelationService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ISecurityEventWriter _eventWriter;

    public SiemCorrelationService(ApplicationDbContext dbContext, ISecurityEventWriter eventWriter)
    {
        _dbContext = dbContext;
        _eventWriter = eventWriter;
    }

    public async Task<CorrelationRunResult> RunAsync(CancellationToken cancellationToken = default)
    {
        var result = new CorrelationRunResult();
        var now = DateTime.UtcNow;

        var recentLoginFailures = await _dbContext.SecurityEvents
            .Where(x => x.EventType == SecurityEventType.LoginFailure && x.OccurredAtUtc >= now.AddMinutes(-2))
            .ToListAsync(cancellationToken);

        var created1 = await ProcessRuleAsync(
            ruleCode: "BF-001",
            ruleName: "Повторные неуспешные попытки входа",
            severity: EventSeverity.High,
            descriptionFactory: group => $"Зафиксировано {group.Count} неуспешных попыток входа для учетной записи {group.Key} за последние 2 минуты.",
            eventIdsFactory: group => group.EventIds,
            groups: recentLoginFailures
                .GroupBy(x => string.IsNullOrWhiteSpace(x.UserName) ? "unknown-user" : x.UserName!)
                .Select(g => new RuleCandidate
                {
                    Key = g.Key,
                    Count = g.Count(),
                    EventIds = g.OrderBy(x => x.Id).Select(x => x.Id).ToList()
                })
                .Where(x => x.Count >= 3)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created1);

        var recentUserExceptionChanges = await _dbContext.SecurityEvents
            .Where(x => (x.EventType == SecurityEventType.UserExceptionUpdated || x.EventType == SecurityEventType.UserExceptionDeleted)
                        && x.OccurredAtUtc >= now.AddSeconds(-30))
            .ToListAsync(cancellationToken);

        var created2 = await ProcessRuleAsync(
            ruleCode: "UE-001",
            ruleName: "Массовые изменения записей UserExceptions",
            severity: EventSeverity.Critical,
            descriptionFactory: group => $"Пользователь {group.Key} выполнил {group.Count} операций изменения или удаления UserExceptions за последние 30 секунд.",
            eventIdsFactory: group => group.EventIds,
            groups: recentUserExceptionChanges
                .GroupBy(x => string.IsNullOrWhiteSpace(x.UserName) ? "unknown-user" : x.UserName!)
                .Select(g => new RuleCandidate
                {
                    Key = g.Key,
                    Count = g.Count(),
                    EventIds = g.OrderBy(x => x.Id).Select(x => x.Id).ToList()
                })
                .Where(x => x.Count >= 5)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created2);

        var recentCriticalEvents = await _dbContext.SecurityEvents
            .Where(x => x.Severity == EventSeverity.Critical && x.OccurredAtUtc >= now.AddMinutes(-5))
            .ToListAsync(cancellationToken);

        var created3 = await ProcessRuleAsync(
            ruleCode: "CR-001",
            ruleName: "Повторные критические события с одного источника",
            severity: EventSeverity.Critical,
            descriptionFactory: group => $"С источника {group.Key} зарегистрировано {group.Count} критических события за последние 5 минут.",
            eventIdsFactory: group => group.EventIds,
            groups: recentCriticalEvents
                .GroupBy(x => string.IsNullOrWhiteSpace(x.SourceIp) ? "unknown-ip" : x.SourceIp!)
                .Select(g => new RuleCandidate
                {
                    Key = g.Key,
                    Count = g.Count(),
                    EventIds = g.OrderBy(x => x.Id).Select(x => x.Id).ToList()
                })
                .Where(x => x.Count >= 2)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created3);
        return result;
    }

    private async Task<CorrelationRunResult> ProcessRuleAsync(
        string ruleCode,
        string ruleName,
        EventSeverity severity,
        Func<RuleCandidate, string> descriptionFactory,
        Func<RuleCandidate, List<long>> eventIdsFactory,
        List<RuleCandidate> groups,
        bool createIncident,
        CancellationToken cancellationToken)
    {
        var result = new CorrelationRunResult();

        foreach (var group in groups)
        {
            var triggerKey = $"{ruleCode}:{group.Key}";
            var exists = await _dbContext.SiemAlerts.AnyAsync(x => x.RuleCode == ruleCode
                && x.TriggerKey == triggerKey
                && x.CreatedAtUtc >= DateTime.UtcNow.AddMinutes(-10)
                && x.Status != AlertStatuses.Closed, cancellationToken);

            if (exists)
                continue;

            var alert = new SiemAlertRecord
            {
                CreatedAtUtc = DateTime.UtcNow,
                RuleCode = ruleCode,
                RuleName = ruleName,
                TriggerKey = triggerKey,
                Severity = severity,
                Status = AlertStatuses.New,
                Description = descriptionFactory(group),
                SourceEventIdsJson = JsonSerializer.Serialize(eventIdsFactory(group))
            };

            _dbContext.SiemAlerts.Add(alert);
            await _dbContext.SaveChangesAsync(cancellationToken);
            result.CreatedAlerts++;
            result.TriggeredRules.Add(ruleCode);

            await _eventWriter.WriteAsync(new SecurityEventWriteRequest
            {
                EventType = SecurityEventType.CorrelationAlert,
                Severity = severity,
                UserName = "siem-engine",
                Description = $"Сработало правило корреляции {ruleCode}: {ruleName}.",
                AdditionalData = new { alert.Id, alert.RuleCode, alert.TriggerKey }
            });

            if (createIncident)
            {
                var incident = new IncidentRecord
                {
                    CreatedAtUtc = DateTime.UtcNow,
                    Name = $"[{ruleCode}] {ruleName}",
                    Severity = severity,
                    Status = IncidentStatuses.New,
                    SourceEventId = group.EventIds.FirstOrDefault(),
                    Notes = alert.Description
                };

                _dbContext.Incidents.Add(incident);
                await _dbContext.SaveChangesAsync(cancellationToken);
                alert.IncidentId = incident.Id;
                await _dbContext.SaveChangesAsync(cancellationToken);
                result.CreatedIncidents++;

                await _eventWriter.WriteAsync(new SecurityEventWriteRequest
                {
                    EventType = SecurityEventType.IncidentCreated,
                    Severity = severity,
                    UserName = "siem-engine",
                    Description = $"По правилу {ruleCode} автоматически создан инцидент #{incident.Id}.",
                    AdditionalData = new
                    {
                        IncidentId = incident.Id,
                        incident.SourceEventId,
                        AlertId = alert.Id
                    }
                });
            }
        }

        return result;
    }

    private static void Merge(CorrelationRunResult target, CorrelationRunResult source)
    {
        target.CreatedAlerts += source.CreatedAlerts;
        target.CreatedIncidents += source.CreatedIncidents;
        target.TriggeredRules.AddRange(source.TriggeredRules);
    }

    private sealed class RuleCandidate
    {
        public string Key { get; set; } = string.Empty;
        public int Count { get; set; }
        public List<long> EventIds { get; set; } = new();
    }
}
