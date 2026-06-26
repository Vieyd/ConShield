using System.Text;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.Web.Infrastructure;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize(Roles = AppRoles.AdminIB)]
public sealed class ReportsController : Controller
{
    private const string Range24Hours = "24h";
    private const string Range7Days = "7d";

    private readonly ApplicationDbContext _dbContext;

    public ReportsController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    [HttpGet]
    public async Task<IActionResult> SecuritySummary(string? range, CancellationToken cancellationToken)
    {
        var model = await BuildReportAsync(range, cancellationToken);
        return View(model.WithMarkdown(BuildMarkdown(model)));
    }

    [HttpGet]
    public async Task<IActionResult> SecuritySummaryMarkdown(string? range, CancellationToken cancellationToken)
    {
        var model = await BuildReportAsync(range, cancellationToken);
        var markdown = BuildMarkdown(model);
        var fileName = $"conshield-security-summary-{model.GeneratedAtUtc:yyyyMMdd-HHmm}.md";

        return File(Encoding.UTF8.GetBytes(markdown), "text/markdown; charset=utf-8", fileName);
    }

    private async Task<SecuritySummaryReportViewModel> BuildReportAsync(string? requestedRange, CancellationToken cancellationToken)
    {
        var nowUtc = DateTime.UtcNow;
        var (rangeKey, rangeLabel, rangeStartUtc) = ResolveRange(requestedRange, nowUtc);
        var sensors = await _dbContext.Sensors
            .AsNoTracking()
            .Select(sensor => new SensorSummaryRow(sensor.LastSeenAtUtc, sensor.RevokedAtUtc))
            .ToListAsync(cancellationToken);

        var sensorSection = BuildSensorSection(sensors, nowUtc);
        var eventSection = await BuildEventSectionAsync(rangeStartUtc, nowUtc, cancellationToken);
        var siemSection = await BuildSiemSectionAsync(rangeStartUtc, cancellationToken);
        var pipelineSection = await BuildPipelineSectionAsync(rangeStartUtc, cancellationToken);
        var overallStatus = BuildOverallStatus(sensorSection, eventSection, siemSection, pipelineSection);
        var checklist = BuildOperatorChecklist(sensorSection, eventSection, siemSection, pipelineSection);

        return new SecuritySummaryReportViewModel
        {
            GeneratedAtUtc = nowUtc,
            RangeKey = rangeKey,
            RangeLabel = rangeLabel,
            RangeStartUtc = rangeStartUtc,
            RangeEndUtc = nowUtc,
            OverallStatus = overallStatus,
            Sensors = sensorSection,
            SecurityEvents = eventSection,
            Siem = siemSection,
            Pipeline = pipelineSection,
            OperatorChecklist = checklist
        };
    }

    private static (string RangeKey, string RangeLabel, DateTime RangeStartUtc) ResolveRange(string? range, DateTime nowUtc)
    {
        if (string.Equals(range, Range7Days, StringComparison.OrdinalIgnoreCase))
            return (Range7Days, "7 дней", nowUtc.AddDays(-7));

        return (Range24Hours, "24 часа", nowUtc.AddHours(-24));
    }

    private static SecuritySummarySensorSection BuildSensorSection(IReadOnlyCollection<SensorSummaryRow> sensors, DateTime nowUtc)
    {
        var total = sensors.Count;
        var revoked = sensors.Count(sensor => sensor.RevokedAtUtc is not null);
        var activeSensors = sensors.Where(sensor => sensor.RevokedAtUtc is null).ToArray();
        var active = total - revoked;
        var neverSeen = activeSensors.Count(sensor => sensor.LastSeenAtUtc is null);
        var online = activeSensors.Count(sensor => IsHeartbeatWithin(sensor.LastSeenAtUtc, nowUtc, TimeSpan.FromMinutes(2)));
        var warning = activeSensors.Count(sensor =>
            sensor.LastSeenAtUtc is not null
            && !IsHeartbeatWithin(sensor.LastSeenAtUtc, nowUtc, TimeSpan.FromMinutes(2))
            && IsHeartbeatWithin(sensor.LastSeenAtUtc, nowUtc, TimeSpan.FromMinutes(5)));
        var offline = activeSensors.Count(sensor =>
            sensor.LastSeenAtUtc is not null
            && !IsHeartbeatWithin(sensor.LastSeenAtUtc, nowUtc, TimeSpan.FromMinutes(5)));
        var latestHeartbeatAtUtc = sensors
            .Select(sensor => (DateTime?)sensor.LastSeenAtUtc)
            .Where(value => value is not null)
            .DefaultIfEmpty()
            .Max();

        return new SecuritySummarySensorSection
        {
            Total = total,
            Active = active,
            Revoked = revoked,
            Online = online,
            Warning = warning,
            Offline = offline,
            NeverSeen = neverSeen,
            LatestHeartbeatAtUtc = latestHeartbeatAtUtc
        };
    }

    private async Task<SecuritySummaryEventSection> BuildEventSectionAsync(
        DateTime rangeStartUtc,
        DateTime rangeEndUtc,
        CancellationToken cancellationToken)
    {
        var severityCounts = new Dictionary<EventSeverity, int>();
        foreach (var severity in Enum.GetValues<EventSeverity>())
        {
            severityCounts[severity] = await _dbContext.SecurityEvents.CountAsync(
                x => x.OccurredAtUtc >= rangeStartUtc && x.OccurredAtUtc <= rangeEndUtc && x.Severity == severity,
                cancellationToken);
        }

        return new SecuritySummaryEventSection
        {
            EventsInRange = await _dbContext.SecurityEvents.CountAsync(
                x => x.OccurredAtUtc >= rangeStartUtc && x.OccurredAtUtc <= rangeEndUtc,
                cancellationToken),
            LatestEventAtUtc = await _dbContext.SecurityEvents
                .Where(x => x.OccurredAtUtc >= rangeStartUtc && x.OccurredAtUtc <= rangeEndUtc)
                .Select(x => (DateTime?)x.OccurredAtUtc)
                .DefaultIfEmpty()
                .MaxAsync(cancellationToken),
            SeverityCounts = severityCounts,
            LifecycleAuditEvents = await _dbContext.SecurityEvents.CountAsync(
                x => x.OccurredAtUtc >= rangeStartUtc
                     && x.OccurredAtUtc <= rangeEndUtc
                     && x.SourceSystem == SecuritySourceSystems.SensorLifecycle,
                cancellationToken)
        };
    }

    private async Task<SecuritySummarySiemSection> BuildSiemSectionAsync(DateTime rangeStartUtc, CancellationToken cancellationToken)
    {
        var lifecycleRuleCodes = new[] { "LIFE-001", "LIFE-002" };

        return new SecuritySummarySiemSection
        {
            ActiveAlerts = await _dbContext.SiemAlerts.CountAsync(x => x.Status != AlertStatuses.Closed, cancellationToken),
            LifecycleAlertsInRange = await _dbContext.SiemAlerts.CountAsync(
                x => x.CreatedAtUtc >= rangeStartUtc && lifecycleRuleCodes.Contains(x.RuleCode),
                cancellationToken),
            Life001AlertsInRange = await _dbContext.SiemAlerts.CountAsync(
                x => x.CreatedAtUtc >= rangeStartUtc && x.RuleCode == "LIFE-001",
                cancellationToken),
            Life002AlertsInRange = await _dbContext.SiemAlerts.CountAsync(
                x => x.CreatedAtUtc >= rangeStartUtc && x.RuleCode == "LIFE-002",
                cancellationToken),
            IncidentsInRange = await _dbContext.Incidents.CountAsync(x => x.CreatedAtUtc >= rangeStartUtc, cancellationToken)
        };
    }

    private async Task<SecuritySummaryPipelineSection> BuildPipelineSectionAsync(DateTime rangeStartUtc, CancellationToken cancellationToken)
    {
        return new SecuritySummaryPipelineSection
        {
            OutboxPending = await _dbContext.SecurityEventOutboxMessages.CountAsync(
                x => x.Status == SecurityEventOutboxStatus.Pending,
                cancellationToken),
            OutboxProcessing = await _dbContext.SecurityEventOutboxMessages.CountAsync(
                x => x.Status == SecurityEventOutboxStatus.Processing,
                cancellationToken),
            OutboxDeadLetter = await _dbContext.SecurityEventOutboxMessages.CountAsync(
                x => x.Status == SecurityEventOutboxStatus.DeadLetter,
                cancellationToken),
            InboxTotal = await _dbContext.SecurityEventInboxReceipts.CountAsync(cancellationToken),
            InboxInRange = await _dbContext.SecurityEventInboxReceipts.CountAsync(
                x => x.ReceivedAtUtc >= rangeStartUtc,
                cancellationToken),
            InboxRedelivered = await _dbContext.SecurityEventInboxReceipts.CountAsync(x => x.Redelivered, cancellationToken),
            InboxDeliveryCountOverOne = await _dbContext.SecurityEventInboxReceipts.CountAsync(x => x.DeliveryCount > 1, cancellationToken),
            LatestInboxReceivedAtUtc = await _dbContext.SecurityEventInboxReceipts
                .Select(x => (DateTime?)x.ReceivedAtUtc)
                .DefaultIfEmpty()
                .MaxAsync(cancellationToken),
            LatestInboxProcessedAtUtc = await _dbContext.SecurityEventInboxReceipts
                .Where(x => x.ProcessedAtUtc != null)
                .Select(x => x.ProcessedAtUtc)
                .DefaultIfEmpty()
                .MaxAsync(cancellationToken)
        };
    }

    private static string BuildOverallStatus(
        SecuritySummarySensorSection sensors,
        SecuritySummaryEventSection securityEvents,
        SecuritySummarySiemSection siem,
        SecuritySummaryPipelineSection pipeline)
    {
        var hasNoData = sensors.Total == 0
            && securityEvents.EventsInRange == 0
            && siem.ActiveAlerts == 0
            && siem.IncidentsInRange == 0
            && pipeline.OutboxPending == 0
            && pipeline.OutboxProcessing == 0
            && pipeline.OutboxDeadLetter == 0
            && pipeline.InboxTotal == 0;

        if (hasNoData)
            return SecuritySummaryStatus.NoData;

        if (sensors.Offline > 0
            || sensors.NeverSeen > 0
            || securityEvents.EventsInRange == 0
            || siem.ActiveAlerts > 0
            || siem.LifecycleAlertsInRange > 0
            || siem.IncidentsInRange > 0
            || pipeline.OutboxPending > 0
            || pipeline.OutboxProcessing > 0
            || pipeline.OutboxDeadLetter > 0
            || pipeline.InboxRedelivered > 0
            || pipeline.InboxDeliveryCountOverOne > 0)
        {
            return SecuritySummaryStatus.NeedsAttention;
        }

        return SecuritySummaryStatus.Ok;
    }

    private static IReadOnlyList<string> BuildOperatorChecklist(
        SecuritySummarySensorSection sensors,
        SecuritySummaryEventSection securityEvents,
        SecuritySummarySiemSection siem,
        SecuritySummaryPipelineSection pipeline)
    {
        var checklist = new List<string>();

        if (sensors.Offline > 0 || sensors.NeverSeen > 0)
            checklist.Add("Откройте раздел «Сенсоры» и проверьте сенсоры без связи или без heartbeat.");
        if (securityEvents.EventsInRange == 0)
            checklist.Add("Проверьте прием событий RuntimeCollector и внешний поток событий за выбранный период.");
        if (securityEvents.LifecycleAuditEvents > 0)
            checklist.Add("Проверьте lifecycle-события и убедитесь, что они соответствуют плановым действиям.");
        if (siem.LifecycleAlertsInRange > 0)
            checklist.Add("Откройте оповещения SIEM по правилам LIFE-001 и LIFE-002 и свяжите неожиданные изменения с инцидентами.");
        if (siem.ActiveAlerts > 0 || siem.IncidentsInRange > 0)
            checklist.Add("Проверьте активные оповещения и инциденты перед закрытием ежедневной проверки.");
        if (pipeline.OutboxPending > 0 || pipeline.OutboxProcessing > 0 || pipeline.OutboxDeadLetter > 0)
            checklist.Add("Проверьте очередь отправки и ошибки доставки перед тем, как полагаться на downstream-проекции.");
        if (pipeline.InboxRedelivered > 0 || pipeline.InboxDeliveryCountOverOne > 0)
            checklist.Add("Проверьте повторные доставки inbox на признаки дублей или задержанной обработки.");
        if (checklist.Count == 0)
            checklist.Add("Продолжайте ежедневную проверку разделов «Состояние системы», «События», «Оповещения SIEM» и «Сенсоры».");

        checklist.Add("Зафиксируйте вывод оператора в runbook или связанном инциденте.");
        return checklist;
    }

    private static string BuildMarkdown(SecuritySummaryReportViewModel model)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# ConShield — сводка безопасности");
        builder.AppendLine();
        builder.AppendLine($"- Сформировано: {model.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC ({model.GeneratedAtUtc.ToMoscowDisplay()} MSK)");
        builder.AppendLine($"- Период: {model.RangeLabel} ({model.RangeStartUtc:yyyy-MM-dd HH:mm:ss} UTC — {model.RangeEndUtc:yyyy-MM-dd HH:mm:ss} UTC)");
        builder.AppendLine($"- Общий статус: {DisplayText.SecuritySummaryStatus(model.OverallStatus)}");
        builder.AppendLine();
        builder.AppendLine("## Сенсоры");
        builder.AppendLine();
        builder.AppendLine($"- Всего: {model.Sensors.Total}");
        builder.AppendLine($"- Активных: {model.Sensors.Active}");
        builder.AppendLine($"- Отозваны: {model.Sensors.Revoked}");
        builder.AppendLine($"- В сети / предупреждение / нет связи: {model.Sensors.Online} / {model.Sensors.Warning} / {model.Sensors.Offline}");
        builder.AppendLine($"- Без heartbeat: {model.Sensors.NeverSeen}");
        builder.AppendLine($"- Последний heartbeat: {FormatUtc(model.Sensors.LatestHeartbeatAtUtc)}");
        builder.AppendLine();
        builder.AppendLine("## События безопасности");
        builder.AppendLine();
        builder.AppendLine($"- Событий за период: {model.SecurityEvents.EventsInRange}");
        builder.AppendLine($"- Последнее событие: {FormatUtc(model.SecurityEvents.LatestEventAtUtc)}");
        builder.AppendLine("- Распределение по критичности:");
        foreach (var severity in Enum.GetValues<EventSeverity>())
            builder.AppendLine($"  - {DisplayText.Severity(severity)}: {model.SecurityEvents.SeverityCounts.GetValueOrDefault(severity)}");
        builder.AppendLine($"- Lifecycle-аудит: {model.SecurityEvents.LifecycleAuditEvents}");
        builder.AppendLine();
        builder.AppendLine("## SIEM");
        builder.AppendLine();
        builder.AppendLine($"- Активные оповещения: {model.Siem.ActiveAlerts}");
        builder.AppendLine($"- Lifecycle-оповещения SIEM: {model.Siem.LifecycleAlertsInRange}");
        builder.AppendLine($"- Оповещения LIFE-001: {model.Siem.Life001AlertsInRange}");
        builder.AppendLine($"- Оповещения LIFE-002: {model.Siem.Life002AlertsInRange}");
        builder.AppendLine($"- Инцидентов за период: {model.Siem.IncidentsInRange}");
        builder.AppendLine();
        builder.AppendLine("## Пайплайн доставки");
        builder.AppendLine();
        builder.AppendLine($"- Очередь: ожидает: {model.Pipeline.OutboxPending}");
        builder.AppendLine($"- Очередь: в обработке: {model.Pipeline.OutboxProcessing}");
        builder.AppendLine($"- Ошибки доставки: {model.Pipeline.OutboxDeadLetter}");
        builder.AppendLine($"- Подтверждения: всего: {model.Pipeline.InboxTotal}");
        builder.AppendLine($"- Подтверждения за период: {model.Pipeline.InboxInRange}");
        builder.AppendLine($"- Повторные доставки: {model.Pipeline.InboxRedelivered}");
        builder.AppendLine($"- Delivery count > 1: {model.Pipeline.InboxDeliveryCountOverOne}");
        builder.AppendLine($"- Последнее получение inbox: {FormatUtc(model.Pipeline.LatestInboxReceivedAtUtc)}");
        builder.AppendLine($"- Последняя обработка inbox: {FormatUtc(model.Pipeline.LatestInboxProcessedAtUtc)}");
        builder.AppendLine();
        builder.AppendLine("## Чек-лист оператора");
        builder.AppendLine();
        foreach (var item in model.OperatorChecklist)
            builder.AppendLine($"- {item}");
        builder.AppendLine();
        builder.AppendLine("_Этот отчет только для чтения содержит только агрегированные счетчики и временные метки._");

        return builder.ToString();
    }

    private static bool IsHeartbeatWithin(DateTime? lastSeenAtUtc, DateTime nowUtc, TimeSpan maxAge)
    {
        if (lastSeenAtUtc is null)
            return false;

        var age = nowUtc - lastSeenAtUtc.Value;
        if (age < TimeSpan.Zero)
            age = TimeSpan.Zero;

        return age <= maxAge;
    }

    private static string FormatUtc(DateTime? value) => value is null
        ? "—"
        : $"{value.Value:yyyy-MM-dd HH:mm:ss} UTC";

    private sealed record SensorSummaryRow(DateTime? LastSeenAtUtc, DateTime? RevokedAtUtc);
}

internal static class SecuritySummaryReportModelExtensions
{
    public static SecuritySummaryReportViewModel WithMarkdown(this SecuritySummaryReportViewModel model, string markdown) => new()
    {
        GeneratedAtUtc = model.GeneratedAtUtc,
        RangeKey = model.RangeKey,
        RangeLabel = model.RangeLabel,
        RangeStartUtc = model.RangeStartUtc,
        RangeEndUtc = model.RangeEndUtc,
        OverallStatus = model.OverallStatus,
        Sensors = model.Sensors,
        SecurityEvents = model.SecurityEvents,
        Siem = model.Siem,
        Pipeline = model.Pipeline,
        OperatorChecklist = model.OperatorChecklist,
        Markdown = markdown
    };
}
