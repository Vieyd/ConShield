using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class SecurityEventOutboxStatusService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IOutboxClock _clock;
    private readonly SecurityEventOutboxOptions _options;

    public SecurityEventOutboxStatusService(
        ApplicationDbContext dbContext,
        IOutboxClock clock,
        IOptions<SecurityEventOutboxOptions> options)
    {
        _dbContext = dbContext;
        _clock = clock;
        _options = options.Value;
    }

    public async Task<SecurityEventOutboxStatusSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        var now = _clock.UtcNow;
        var counts = await _dbContext.SecurityEventOutboxMessages
            .GroupBy(x => x.Status)
            .Select(x => new StatusCount(x.Key, x.Count()))
            .ToListAsync(cancellationToken);

        var oldestPending = await _dbContext.SecurityEventOutboxMessages
            .Where(x => x.Status == SecurityEventOutboxStatus.Pending)
            .OrderBy(x => x.CreatedAtUtc)
            .Select(x => (DateTime?)x.CreatedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        var lastDelivered = await _dbContext.SecurityEventOutboxMessages
            .Where(x => x.Status == SecurityEventOutboxStatus.Delivered)
            .OrderByDescending(x => x.DeliveredAtUtc)
            .Select(x => x.DeliveredAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        var latest = await _dbContext.SecurityEventOutboxMessages
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(50)
            .Select(x => new SecurityEventOutboxMessageSummary(
                x.MessageId,
                x.SecurityEventId,
                x.MessageType,
                x.Status.ToString(),
                x.AttemptCount,
                x.CreatedAtUtc,
                x.AvailableAtUtc,
                x.DeliveredAtUtc,
                x.LastErrorCode,
                x.LastErrorSummary))
            .ToListAsync(cancellationToken);

        TimeSpan? pendingAge = oldestPending is null ? null : now - oldestPending.Value;
        var deadLetters = GetCount(counts, SecurityEventOutboxStatus.DeadLetter);
        var degraded = deadLetters > 0
            || (pendingAge.HasValue && pendingAge.Value > TimeSpan.FromSeconds(_options.DegradedPendingAgeSeconds));

        return new SecurityEventOutboxStatusSnapshot(
            PendingCount: GetCount(counts, SecurityEventOutboxStatus.Pending),
            ProcessingCount: GetCount(counts, SecurityEventOutboxStatus.Processing),
            DeliveredCount: GetCount(counts, SecurityEventOutboxStatus.Delivered),
            DeadLetterCount: deadLetters,
            OldestPendingAge: pendingAge,
            LastDeliveredAtUtc: lastDelivered,
            IsDegraded: degraded,
            LatestMessages: latest);
    }

    private static int GetCount(IEnumerable<StatusCount> counts, SecurityEventOutboxStatus status)
    {
        foreach (var count in counts)
        {
            if (count.Status == status)
                return count.Count;
        }

        return 0;
    }

    private sealed record StatusCount(SecurityEventOutboxStatus Status, int Count);
}

public sealed record SecurityEventOutboxStatusSnapshot(
    int PendingCount,
    int ProcessingCount,
    int DeliveredCount,
    int DeadLetterCount,
    TimeSpan? OldestPendingAge,
    DateTime? LastDeliveredAtUtc,
    bool IsDegraded,
    IReadOnlyList<SecurityEventOutboxMessageSummary> LatestMessages);

public sealed record SecurityEventOutboxMessageSummary(
    Guid MessageId,
    long SecurityEventId,
    string MessageType,
    string Status,
    int AttemptCount,
    DateTime CreatedAtUtc,
    DateTime AvailableAtUtc,
    DateTime? DeliveredAtUtc,
    string? LastErrorCode,
    string? LastErrorSummary);
