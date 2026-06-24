using ConShield.Contracts.Constants;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize(Roles = AppRoles.AdminIB)]
public sealed class OperationsController : Controller
{
    private readonly ApplicationDbContext _dbContext;

    public OperationsController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    [HttpGet]
    public async Task<IActionResult> Health(CancellationToken cancellationToken)
    {
        var nowUtc = DateTime.UtcNow;
        var lastHour = nowUtc.AddHours(-1);
        var last24Hours = nowUtc.AddHours(-24);

        var sensors = await _dbContext.Sensors
            .AsNoTracking()
            .Select(sensor => new SensorHealthRow(sensor.LastSeenAtUtc, sensor.RevokedAtUtc))
            .ToListAsync(cancellationToken);

        var model = new OperationalHealthViewModel
        {
            GeneratedAtUtc = nowUtc,
            Sensors = BuildSensorSummary(sensors, nowUtc),
            SecurityEvents = await BuildSecurityEventSummaryAsync(lastHour, last24Hours, cancellationToken),
            Outbox = await BuildOutboxSummaryAsync(cancellationToken),
            Inbox = await BuildInboxSummaryAsync(last24Hours, cancellationToken)
        };

        return View(model);
    }

    private static SensorHealthSummary BuildSensorSummary(
        IReadOnlyCollection<SensorHealthRow> sensors,
        DateTime nowUtc)
    {
        var total = sensors.Count;
        var revoked = sensors.Count(sensor => sensor.RevokedAtUtc is not null);
        var active = total - revoked;
        var activeSensors = sensors.Where(sensor => sensor.RevokedAtUtc is null).ToArray();
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

        return new SensorHealthSummary
        {
            Total = total,
            Active = active,
            Revoked = revoked,
            NeverSeen = neverSeen,
            Online = online,
            Warning = warning,
            Offline = offline,
            LatestHeartbeatAtUtc = latestHeartbeatAtUtc,
            StatusLabel = SensorStatus(total, active, neverSeen, warning, offline)
        };
    }

    private async Task<SecurityEventHealthSummary> BuildSecurityEventSummaryAsync(
        DateTime lastHour,
        DateTime last24Hours,
        CancellationToken cancellationToken)
    {
        var total = await _dbContext.SecurityEvents.CountAsync(cancellationToken);
        var lastHourCount = await _dbContext.SecurityEvents.CountAsync(x => x.OccurredAtUtc >= lastHour, cancellationToken);
        var last24HoursCount = await _dbContext.SecurityEvents.CountAsync(x => x.OccurredAtUtc >= last24Hours, cancellationToken);
        var lifecycleLast24Hours = await _dbContext.SecurityEvents.CountAsync(
            x => x.OccurredAtUtc >= last24Hours && x.SourceSystem == SecuritySourceSystems.SensorLifecycle,
            cancellationToken);
        var latestEventAtUtc = await _dbContext.SecurityEvents
            .Select(x => (DateTime?)x.OccurredAtUtc)
            .DefaultIfEmpty()
            .MaxAsync(cancellationToken);

        return new SecurityEventHealthSummary
        {
            Total = total,
            LastHour = lastHourCount,
            Last24Hours = last24HoursCount,
            LatestEventAtUtc = latestEventAtUtc,
            LifecycleLast24Hours = lifecycleLast24Hours,
            StatusLabel = total == 0 ? OperationalHealthStatus.NoData :
                lastHourCount > 0 ? OperationalHealthStatus.Ok :
                last24HoursCount > 0 ? OperationalHealthStatus.Warning :
                OperationalHealthStatus.Attention
        };
    }

    private async Task<OutboxHealthSummary> BuildOutboxSummaryAsync(CancellationToken cancellationToken)
    {
        var total = await _dbContext.SecurityEventOutboxMessages.CountAsync(cancellationToken);
        var pending = await _dbContext.SecurityEventOutboxMessages.CountAsync(x => x.Status == SecurityEventOutboxStatus.Pending, cancellationToken);
        var processing = await _dbContext.SecurityEventOutboxMessages.CountAsync(x => x.Status == SecurityEventOutboxStatus.Processing, cancellationToken);
        var delivered = await _dbContext.SecurityEventOutboxMessages.CountAsync(x => x.Status == SecurityEventOutboxStatus.Delivered, cancellationToken);
        var deadLetter = await _dbContext.SecurityEventOutboxMessages.CountAsync(x => x.Status == SecurityEventOutboxStatus.DeadLetter, cancellationToken);
        var oldestPendingAtUtc = await _dbContext.SecurityEventOutboxMessages
            .Where(x => x.Status == SecurityEventOutboxStatus.Pending || x.Status == SecurityEventOutboxStatus.Processing)
            .Select(x => (DateTime?)x.CreatedAtUtc)
            .DefaultIfEmpty()
            .MinAsync(cancellationToken);
        var latestCreatedAtUtc = await _dbContext.SecurityEventOutboxMessages
            .Select(x => (DateTime?)x.CreatedAtUtc)
            .DefaultIfEmpty()
            .MaxAsync(cancellationToken);
        var notDispatched = pending + processing;

        return new OutboxHealthSummary
        {
            Total = total,
            Pending = pending,
            Processing = processing,
            NotDispatched = notDispatched,
            Delivered = delivered,
            DeadLetter = deadLetter,
            OldestPendingAtUtc = oldestPendingAtUtc,
            LatestCreatedAtUtc = latestCreatedAtUtc,
            StatusLabel = total == 0 ? OperationalHealthStatus.NoData :
                deadLetter > 0 ? OperationalHealthStatus.Attention :
                notDispatched > 0 ? OperationalHealthStatus.Warning :
                OperationalHealthStatus.Ok
        };
    }

    private async Task<InboxHealthSummary> BuildInboxSummaryAsync(DateTime last24Hours, CancellationToken cancellationToken)
    {
        var total = await _dbContext.SecurityEventInboxReceipts.CountAsync(cancellationToken);
        var last24HoursCount = await _dbContext.SecurityEventInboxReceipts.CountAsync(x => x.ReceivedAtUtc >= last24Hours, cancellationToken);
        var latestReceivedAtUtc = await _dbContext.SecurityEventInboxReceipts
            .Select(x => (DateTime?)x.ReceivedAtUtc)
            .DefaultIfEmpty()
            .MaxAsync(cancellationToken);
        var latestProcessedAtUtc = await _dbContext.SecurityEventInboxReceipts
            .Where(x => x.ProcessedAtUtc != null)
            .Select(x => x.ProcessedAtUtc)
            .DefaultIfEmpty()
            .MaxAsync(cancellationToken);
        var redelivered = await _dbContext.SecurityEventInboxReceipts.CountAsync(x => x.Redelivered, cancellationToken);
        var deliveryCountOverOne = await _dbContext.SecurityEventInboxReceipts.CountAsync(x => x.DeliveryCount > 1, cancellationToken);

        return new InboxHealthSummary
        {
            Total = total,
            Last24Hours = last24HoursCount,
            LatestReceivedAtUtc = latestReceivedAtUtc,
            LatestProcessedAtUtc = latestProcessedAtUtc,
            Redelivered = redelivered,
            DeliveryCountOverOne = deliveryCountOverOne,
            StatusLabel = total == 0 ? OperationalHealthStatus.NoData :
                redelivered > 0 || deliveryCountOverOne > 0 ? OperationalHealthStatus.Warning :
                OperationalHealthStatus.Ok
        };
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

    private static string SensorStatus(int total, int active, int neverSeen, int warning, int offline)
    {
        if (total == 0)
            return OperationalHealthStatus.NoData;
        if (offline > 0)
            return OperationalHealthStatus.Attention;
        if (warning > 0 || neverSeen > 0 || active == 0)
            return OperationalHealthStatus.Warning;
        return OperationalHealthStatus.Ok;
    }

    private sealed record SensorHealthRow(DateTime? LastSeenAtUtc, DateTime? RevokedAtUtc);
}
