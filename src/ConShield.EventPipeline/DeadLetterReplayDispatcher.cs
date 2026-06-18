using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class DeadLetterReplayDispatcher
{
    private readonly ApplicationDbContext _dbContext;
    private readonly DeadLetterReplayPublisher _publisher;
    private readonly ISecurityEventWriter _eventWriter;
    private readonly IOutboxClock _clock;
    private readonly DeadLetterReplayOptions _options;
    private readonly ILogger<DeadLetterReplayDispatcher> _logger;

    public DeadLetterReplayDispatcher(
        ApplicationDbContext dbContext,
        DeadLetterReplayPublisher publisher,
        ISecurityEventWriter eventWriter,
        IOutboxClock clock,
        IOptions<DeadLetterReplayOptions> options,
        ILogger<DeadLetterReplayDispatcher> logger)
    {
        _dbContext = dbContext;
        _publisher = publisher;
        _eventWriter = eventWriter;
        _clock = clock;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<DeadLetterReplayDispatchResult> DispatchOnceAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
            return new DeadLetterReplayDispatchResult(0, 0, 0, 0);

        var requests = await ClaimBatchAsync(cancellationToken);
        var published = 0;
        var failed = 0;
        var retried = 0;
        foreach (var request in requests)
        {
            var result = await DispatchOneAsync(request, cancellationToken);
            published += result == DeadLetterReplayOneResult.Published ? 1 : 0;
            failed += result == DeadLetterReplayOneResult.Failed ? 1 : 0;
            retried += result == DeadLetterReplayOneResult.Retried ? 1 : 0;
        }

        return new DeadLetterReplayDispatchResult(requests.Count, published, retried, failed);
    }

    private async Task<List<DeadLetterReplayRequest>> ClaimBatchAsync(CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var lockToken = Guid.NewGuid();
        var lockedUntil = now.AddSeconds(_options.LockSeconds);
        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
        var connection = _dbContext.Database.GetDbConnection();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction.GetDbTransaction();
        command.CommandText = """
            UPDATE "DeadLetterReplayRequests"
            SET "Status" = 'Processing',
                "LockToken" = @lockToken,
                "LockedUntilUtc" = @lockedUntil
            WHERE "Id" IN (
                SELECT "Id"
                FROM "DeadLetterReplayRequests"
                WHERE (
                    ("Status" = 'Pending' AND "AvailableAtUtc" <= @now)
                    OR ("Status" = 'Processing' AND "LockedUntilUtc" IS NOT NULL AND "LockedUntilUtc" <= @now)
                )
                ORDER BY "AvailableAtUtc", "Id"
                LIMIT @batchSize
                FOR UPDATE SKIP LOCKED
            )
            RETURNING "Id";
            """;
        AddParameter(command, "lockToken", lockToken);
        AddParameter(command, "lockedUntil", lockedUntil);
        AddParameter(command, "now", now);
        AddParameter(command, "batchSize", _options.BatchSize);
        var ids = new List<long>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
                ids.Add(reader.GetInt64(0));
        }
        await transaction.CommitAsync(cancellationToken);
        return await _dbContext.DeadLetterReplayRequests
            .Include(x => x.QuarantineMessage)
            .Where(x => ids.Contains(x.Id))
            .OrderBy(x => x.Id)
            .ToListAsync(cancellationToken);
    }

    private async Task<DeadLetterReplayOneResult> DispatchOneAsync(DeadLetterReplayRequest request, CancellationToken cancellationToken)
    {
        if (request.QuarantineMessage is null)
            return await MarkTerminalFailureAsync(request, "quarantine_missing", "Quarantine record is missing.", cancellationToken);

        var publish = await _publisher.PublishAsync(request.QuarantineMessage, request, cancellationToken);
        if (publish.Type == OutboxSinkResultType.Succeeded)
        {
            var now = _clock.UtcNow;
            var updated = await _dbContext.DeadLetterReplayRequests
                .Where(x => x.Id == request.Id && x.LockToken == request.LockToken && x.Status == DeadLetterReplayRequestStatus.Processing)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(x => x.Status, DeadLetterReplayRequestStatus.Published)
                    .SetProperty(x => x.PublishedAtUtc, now)
                    .SetProperty(x => x.CompletedAtUtc, now)
                    .SetProperty(x => x.LockToken, (Guid?)null)
                    .SetProperty(x => x.LockedUntilUtc, (DateTime?)null)
                    .SetProperty(x => x.LastErrorCode, (string?)null)
                    .SetProperty(x => x.LastErrorSummary, (string?)null), cancellationToken);
            if (updated == 1)
                await WriteAuditAsync(SecurityEventType.DeadLetterReplayPublished, EventSeverity.Info, request, "published", cancellationToken);
            return DeadLetterReplayOneResult.Published;
        }

        var attempt = request.AttemptCount + 1;
        if (publish.Type == OutboxSinkResultType.PermanentFailure || attempt >= _options.MaxPublishAttempts)
            return await MarkTerminalFailureAsync(request, publish.ErrorCode ?? "publish_failed", publish.SafeErrorSummary ?? "Replay publish failed.", cancellationToken);

        var availableAt = _clock.UtcNow.AddSeconds(CalculateBackoffSeconds(attempt));
        await _dbContext.DeadLetterReplayRequests
            .Where(x => x.Id == request.Id && x.LockToken == request.LockToken && x.Status == DeadLetterReplayRequestStatus.Processing)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.Status, DeadLetterReplayRequestStatus.Pending)
                .SetProperty(x => x.AttemptCount, attempt)
                .SetProperty(x => x.AvailableAtUtc, availableAt)
                .SetProperty(x => x.LockToken, (Guid?)null)
                .SetProperty(x => x.LockedUntilUtc, (DateTime?)null)
                .SetProperty(x => x.LastErrorCode, OutboxSinkResult.Safe(publish.ErrorCode, 64))
                .SetProperty(x => x.LastErrorSummary, OutboxSinkResult.Safe(publish.SafeErrorSummary, 512)), cancellationToken);
        return DeadLetterReplayOneResult.Retried;
    }

    private async Task<DeadLetterReplayOneResult> MarkTerminalFailureAsync(
        DeadLetterReplayRequest request,
        string errorCode,
        string errorSummary,
        CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        await _dbContext.DeadLetterReplayRequests
            .Where(x => x.Id == request.Id && x.LockToken == request.LockToken && x.Status == DeadLetterReplayRequestStatus.Processing)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.Status, DeadLetterReplayRequestStatus.Failed)
                .SetProperty(x => x.AttemptCount, request.AttemptCount + 1)
                .SetProperty(x => x.CompletedAtUtc, now)
                .SetProperty(x => x.LockToken, (Guid?)null)
                .SetProperty(x => x.LockedUntilUtc, (DateTime?)null)
                .SetProperty(x => x.LastErrorCode, OutboxSinkResult.Safe(errorCode, 64))
                .SetProperty(x => x.LastErrorSummary, OutboxSinkResult.Safe(errorSummary, 512)), cancellationToken);
        await WriteAuditAsync(SecurityEventType.DeadLetterReplayFailed, EventSeverity.High, request, errorCode, cancellationToken);
        return DeadLetterReplayOneResult.Failed;
    }

    public int CalculateBackoffSeconds(int attemptCount)
    {
        var safeAttempt = Math.Clamp(attemptCount, 1, 30);
        var multiplier = 1L << Math.Min(safeAttempt - 1, 20);
        return (int)Math.Max(1, Math.Min((long)_options.MaxRetrySeconds, (long)_options.BaseRetrySeconds * multiplier));
    }

    private Task WriteAuditAsync(SecurityEventType eventType, EventSeverity severity, DeadLetterReplayRequest request, string reasonCode, CancellationToken cancellationToken)
    {
        var message = request.QuarantineMessage!;
        return _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = eventType,
            Severity = severity,
            Description = $"Dead-letter replay {reasonCode}.",
            UserName = request.RequestedBy,
            SourceSystem = "conshield.dlq-replay",
            ExternalEventType = eventType.ToString(),
            AdditionalData = new
            {
                replayRequestId = request.ReplayRequestId,
                quarantineId = message.QuarantineId,
                originalMessageId = message.OriginalMessageId,
                payloadSha256 = message.PayloadSha256,
                replaySequence = request.ReplaySequence,
                requestedBy = request.RequestedBy,
                reasonCode
            }
        }, cancellationToken);
    }

    private static void AddParameter(System.Data.Common.DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }

    private enum DeadLetterReplayOneResult
    {
        Published,
        Retried,
        Failed
    }
}

public sealed record DeadLetterReplayDispatchResult(int Claimed, int Published, int Retried, int Failed);
