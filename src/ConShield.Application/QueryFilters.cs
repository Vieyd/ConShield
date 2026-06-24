using ConShield.Contracts.Enums;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Application;

public static class QueryFilters
{
    public static IQueryable<SecurityEventEntry> ApplySecurityEventFilters(
        this IQueryable<SecurityEventEntry> query,
        string? userName,
        EventSeverity? severity,
        SecurityEventType? eventType,
        string? searchText,
        string? sourceSystem = null,
        string? externalEventType = null)
    {
        if (!string.IsNullOrWhiteSpace(userName))
        {
            var pattern = ToContainsPattern(userName);
            query = query.Where(x => x.UserName != null && EF.Functions.ILike(x.UserName, pattern));
        }

        if (severity.HasValue)
        {
            query = query.Where(x => x.Severity == severity.Value);
        }

        if (eventType.HasValue)
        {
            query = query.Where(x => x.EventType == eventType.Value);
        }

        if (!string.IsNullOrWhiteSpace(sourceSystem))
        {
            var normalizedSourceSystem = sourceSystem.Trim().ToLower();
            query = query.Where(x => x.SourceSystem != null && x.SourceSystem.ToLower() == normalizedSourceSystem);
        }

        if (!string.IsNullOrWhiteSpace(externalEventType))
        {
            var normalizedExternalEventType = externalEventType.Trim().ToLower();
            query = query.Where(x => x.ExternalEventType != null && x.ExternalEventType.ToLower() == normalizedExternalEventType);
        }

        if (!string.IsNullOrWhiteSpace(searchText))
        {
            var pattern = ToContainsPattern(searchText);
            query = query.Where(x =>
                EF.Functions.ILike(x.Description, pattern) ||
                (x.AdditionalDataJson != null && EF.Functions.ILike(x.AdditionalDataJson, pattern)) ||
                (x.SourceIp != null && EF.Functions.ILike(x.SourceIp, pattern)) ||
                (x.SourceSystem != null && EF.Functions.ILike(x.SourceSystem, pattern)) ||
                (x.ExternalEventType != null && EF.Functions.ILike(x.ExternalEventType, pattern)));
        }

        return query;
    }

    public static IQueryable<IncidentRecord> ApplyIncidentFilters(
        this IQueryable<IncidentRecord> query,
        string? status,
        EventSeverity? severity,
        string? searchText)
    {
        if (!string.IsNullOrWhiteSpace(status))
        {
            var normalizedStatus = status.Trim();
            query = query.Where(x => x.Status == normalizedStatus);
        }

        if (severity.HasValue)
        {
            query = query.Where(x => x.Severity == severity.Value);
        }

        if (!string.IsNullOrWhiteSpace(searchText))
        {
            var pattern = ToContainsPattern(searchText);
            var hasSourceEventId = long.TryParse(searchText.Trim(), out var sourceEventId);

            query = query.Where(x =>
                EF.Functions.ILike(x.Name, pattern) ||
                (x.Notes != null && EF.Functions.ILike(x.Notes, pattern)) ||
                (hasSourceEventId && x.SourceEventId == sourceEventId));
        }

        return query;
    }

    public static IQueryable<SiemAlertRecord> ApplySiemAlertFilters(
        this IQueryable<SiemAlertRecord> query,
        string? status,
        EventSeverity? severity,
        string? ruleCode,
        string? searchText)
    {
        if (!string.IsNullOrWhiteSpace(status))
        {
            var normalizedStatus = status.Trim();
            query = query.Where(x => x.Status == normalizedStatus);
        }

        if (severity.HasValue)
        {
            query = query.Where(x => x.Severity == severity.Value);
        }

        if (!string.IsNullOrWhiteSpace(ruleCode))
        {
            var pattern = ToContainsPattern(ruleCode);
            query = query.Where(x => EF.Functions.ILike(x.RuleCode, pattern));
        }

        if (!string.IsNullOrWhiteSpace(searchText))
        {
            var pattern = ToContainsPattern(searchText);
            query = query.Where(x =>
                EF.Functions.ILike(x.Description, pattern) ||
                EF.Functions.ILike(x.RuleName, pattern) ||
                EF.Functions.ILike(x.TriggerKey, pattern));
        }

        return query;
    }

    private static string ToContainsPattern(string value)
    {
        return $"%{EscapeLikePattern(value.Trim())}%";
    }

    private static string EscapeLikePattern(string value)
    {
        return value
            .Replace(@"\", @"\\")
            .Replace("%", @"\%")
            .Replace("_", @"\_");
    }
}
