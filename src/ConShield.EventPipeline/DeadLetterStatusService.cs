using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace ConShield.EventPipeline;

public sealed class DeadLetterStatusService
{
    private readonly ApplicationDbContext _dbContext;

    public DeadLetterStatusService(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<DeadLetterStatusSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        var messages = _dbContext.DeadLetterQuarantineMessages.AsNoTracking();
        var requests = _dbContext.DeadLetterReplayRequests.AsNoTracking();
        return new DeadLetterStatusSnapshot(
            await messages.CountAsync(cancellationToken),
            await messages.CountAsync(x => x.ReplayEligibility == DeadLetterReplayEligibility.Eligible, cancellationToken),
            await messages.CountAsync(x => x.ReplayEligibility == DeadLetterReplayEligibility.NotEligible, cancellationToken),
            await requests.CountAsync(x => x.Status == DeadLetterReplayRequestStatus.Pending, cancellationToken),
            await requests.CountAsync(x => x.Status == DeadLetterReplayRequestStatus.Failed, cancellationToken),
            await messages.MaxAsync(x => (DateTime?)x.CapturedAtUtc, cancellationToken),
            await requests.MaxAsync(x => x.PublishedAtUtc, cancellationToken));
    }
}

public sealed record DeadLetterStatusSnapshot(
    int QuarantinedCount,
    int EligibleCount,
    int NotEligibleCount,
    int PendingReplayRequests,
    int FailedReplayRequests,
    DateTime? LastCapturedAtUtc,
    DateTime? LastReplayPublishedAtUtc);
