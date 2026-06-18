using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class DeadLetterReplayRequestService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ISecurityEventWriter _eventWriter;
    private readonly IOutboxClock _clock;
    private readonly DeadLetterReplayOptions _options;

    public DeadLetterReplayRequestService(
        ApplicationDbContext dbContext,
        ISecurityEventWriter eventWriter,
        IOutboxClock clock,
        IOptions<DeadLetterReplayOptions> options)
    {
        _dbContext = dbContext;
        _eventWriter = eventWriter;
        _clock = clock;
        _options = options.Value;
    }

    public async Task<DeadLetterReplayRequestResult> RequestAsync(
        Guid quarantineId,
        string requestedBy,
        string reason,
        CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var safeUser = SafeRequired(requestedBy, 128);
        var safeReason = SafeRequired(reason, _options.MaxReasonLength);
        if (!_options.Enabled)
            return DeadLetterReplayRequestResult.Rejected("replay_disabled", "Replay is disabled.");
        if (safeReason.Length == 0)
            return DeadLetterReplayRequestResult.Rejected("reason_required", "A bounded replay reason is required.");

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
        var message = await _dbContext.DeadLetterQuarantineMessages
            .Include(x => x.ReplayRequests)
            .SingleOrDefaultAsync(x => x.QuarantineId == quarantineId, cancellationToken);
        if (message is null)
            return DeadLetterReplayRequestResult.Rejected("not_found", "Quarantine record was not found.");

        var validation = ValidateRequest(message, now);
        if (validation is not null)
        {
            var rejected = new DeadLetterReplayRequest
            {
                ReplayRequestId = Guid.NewGuid(),
                QuarantineMessageId = message.Id,
                RequestedBy = safeUser,
                RequestedAtUtc = now,
                Reason = safeReason,
                Status = DeadLetterReplayRequestStatus.Rejected,
                AttemptCount = 0,
                AvailableAtUtc = now,
                CompletedAtUtc = now,
                LastErrorCode = validation.Value.Code,
                LastErrorSummary = validation.Value.Summary,
                ReplaySequence = NextReplaySequence(message)
            };
            _dbContext.DeadLetterReplayRequests.Add(rejected);
            await _dbContext.SaveChangesAsync(cancellationToken);
            await WriteAuditAsync(SecurityEventType.DeadLetterReplayRejected, EventSeverity.Warning, message, rejected, safeUser, safeReason, validation.Value.Code, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return DeadLetterReplayRequestResult.Rejected(validation.Value.Code, validation.Value.Summary);
        }

        var request = new DeadLetterReplayRequest
        {
            ReplayRequestId = Guid.NewGuid(),
            QuarantineMessageId = message.Id,
            RequestedBy = safeUser,
            RequestedAtUtc = now,
            Reason = safeReason,
            Status = DeadLetterReplayRequestStatus.Pending,
            AttemptCount = 0,
            AvailableAtUtc = now,
            ReplaySequence = NextReplaySequence(message)
        };
        _dbContext.DeadLetterReplayRequests.Add(request);
        await _dbContext.SaveChangesAsync(cancellationToken);
        await WriteAuditAsync(SecurityEventType.DeadLetterReplayRequested, EventSeverity.Warning, message, request, safeUser, safeReason, "requested", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return DeadLetterReplayRequestResult.Queued(request.ReplayRequestId);
    }

    private (string Code, string Summary)? ValidateRequest(DeadLetterQuarantineMessage message, DateTime now)
    {
        if (message.ReplayEligibility == DeadLetterReplayEligibility.NotEligible)
            return ("not_eligible", "This quarantine record is not eligible for replay.");
        if (message.PayloadBytes is null && string.IsNullOrWhiteSpace(message.PayloadJson))
            return ("payload_unavailable", "The original payload is not available for replay.");
        if (message.CapturedAtUtc < now.AddDays(-_options.MaxMessageAgeDays))
            return ("message_too_old", "This quarantine record is older than the configured replay age limit.");
        var replayCount = message.ReplayRequests.Count(x => x.Status is DeadLetterReplayRequestStatus.Pending or DeadLetterReplayRequestStatus.Processing or DeadLetterReplayRequestStatus.Published);
        if (replayCount >= _options.MaxReplayRequestsPerMessage)
            return ("replay_limit_exhausted", "Replay request limit is exhausted for this message.");
        if (message.ReplayRequests.Any(x => x.Status is DeadLetterReplayRequestStatus.Pending or DeadLetterReplayRequestStatus.Processing))
            return ("active_request_exists", "An active replay request already exists for this message.");
        var lastPublishedOrRequested = message.ReplayRequests
            .Where(x => x.Status is not DeadLetterReplayRequestStatus.Rejected)
            .Select(x => x.PublishedAtUtc ?? x.RequestedAtUtc)
            .DefaultIfEmpty(DateTime.MinValue)
            .Max();
        if (lastPublishedOrRequested != DateTime.MinValue && now < lastPublishedOrRequested.AddSeconds(_options.MinimumIntervalSeconds))
            return ("cooldown_active", "Replay cooldown is still active for this message.");
        return null;
    }

    private static int NextReplaySequence(DeadLetterQuarantineMessage message) =>
        message.ReplayRequests.Count(x => x.Status is DeadLetterReplayRequestStatus.Published
            or DeadLetterReplayRequestStatus.Failed
            or DeadLetterReplayRequestStatus.Rejected
            or DeadLetterReplayRequestStatus.Pending
            or DeadLetterReplayRequestStatus.Processing) + 1;

    private Task WriteAuditAsync(
        SecurityEventType eventType,
        EventSeverity severity,
        DeadLetterQuarantineMessage message,
        DeadLetterReplayRequest? request,
        string requestedBy,
        string reason,
        string reasonCode,
        CancellationToken cancellationToken) =>
        _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = eventType,
            Severity = severity,
            Description = $"Dead-letter replay {reasonCode}.",
            UserName = requestedBy,
            SourceSystem = "conshield.dlq-replay",
            ExternalEventType = eventType.ToString(),
            AdditionalData = new
            {
                replayRequestId = request?.ReplayRequestId,
                quarantineId = message.QuarantineId,
                originalMessageId = message.OriginalMessageId,
                payloadSha256 = message.PayloadSha256,
                replaySequence = request?.ReplaySequence,
                requestedBy,
                reasonCode,
                reason
            }
        }, cancellationToken);

    private static string SafeRequired(string? value, int maxLength)
    {
        var safe = new string((value ?? string.Empty).Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }
}

public sealed record DeadLetterReplayRequestResult(bool Accepted, Guid? ReplayRequestId, string? ErrorCode, string? SafeErrorSummary)
{
    public static DeadLetterReplayRequestResult Queued(Guid replayRequestId) => new(true, replayRequestId, null, null);
    public static DeadLetterReplayRequestResult Rejected(string errorCode, string safeErrorSummary) =>
        new(false, null, OutboxSinkResult.Safe(errorCode, 64), OutboxSinkResult.Safe(safeErrorSummary, 512));
}
