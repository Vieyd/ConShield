using System.Text;
using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using RabbitMQ.Client;

namespace ConShield.EventPipeline;

public sealed class DeadLetterCaptureProcessor
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IOutboxClock _clock;
    private readonly RabbitMqOptions _rabbitOptions;
    private readonly DeadLetterReplayOptions _replayOptions;

    public DeadLetterCaptureProcessor(
        ApplicationDbContext dbContext,
        IOutboxClock clock,
        IOptions<RabbitMqOptions> rabbitOptions,
        IOptions<DeadLetterReplayOptions> replayOptions)
    {
        _dbContext = dbContext;
        _clock = clock;
        _rabbitOptions = rabbitOptions.Value;
        _replayOptions = replayOptions.Value;
    }

    public async Task<DeadLetterCaptureResult> CaptureAsync(
        byte[] body,
        IReadOnlyBasicProperties properties,
        string routingKey,
        CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var sha = SecurityEventEnvelopeValidator.Sha256Hex(body);
        var headerSummary = DeadLetterHeaderParser.Parse(properties);
        var classification = Classify(body, properties, routingKey, sha, headerSummary);
        var synthetic = BuildSyntheticFingerprint(classification.OriginalMessageId, sha, routingKey, body.Length);

        try
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
            var existing = await FindExistingAsync(classification.OriginalMessageId, sha, synthetic, cancellationToken);
            if (existing is not null)
            {
                existing.CaptureCount += 1;
                existing.LastDeadLetteredAtUtc = headerSummary.TimeUtc ?? now;
                await _dbContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return DeadLetterCaptureResult.Captured(existing.QuarantineId, duplicate: true);
            }

            _dbContext.DeadLetterQuarantineMessages.Add(new DeadLetterQuarantineMessage
            {
                QuarantineId = Guid.NewGuid(),
                OriginalMessageId = classification.OriginalMessageId,
                PayloadSha256 = sha,
                SyntheticFingerprint = synthetic,
                MessageType = classification.MessageType,
                SchemaVersion = classification.SchemaVersion,
                SecurityEventId = classification.SecurityEventId,
                OriginalExchange = _rabbitOptions.ExchangeName,
                OriginalRoutingKey = _rabbitOptions.RoutingKey,
                DeadLetterExchange = _rabbitOptions.DeadLetterExchangeName,
                DeadLetterQueue = _rabbitOptions.DeadLetterQueueName,
                ContentType = Safe(properties.ContentType, 128),
                CapturedAtUtc = now,
                FirstDeadLetteredAtUtc = headerSummary.TimeUtc ?? now,
                LastDeadLetteredAtUtc = headerSummary.TimeUtc ?? now,
                DeadLetterReason = headerSummary.Reason,
                ValidationCategory = classification.ValidationCategory,
                ReplayEligibility = classification.ReplayEligibility,
                PayloadJson = classification.PayloadJson,
                PayloadBytes = classification.PayloadBytes,
                PayloadLength = body.Length,
                HeaderSummaryJson = headerSummary.ToJson(),
                CaptureCount = 1,
                EligibilityExplanation = classification.EligibilityExplanation
            });
            await _dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return DeadLetterCaptureResult.Captured(Guid.Empty, duplicate: false);
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            _dbContext.ChangeTracker.Clear();
            var existing = await FindExistingAsync(classification.OriginalMessageId, sha, synthetic, cancellationToken);
            if (existing is null)
                return DeadLetterCaptureResult.TransientFailure("capture_unique_race", "Quarantine duplicate race could not reload committed row.");

            existing.CaptureCount += 1;
            existing.LastDeadLetteredAtUtc = headerSummary.TimeUtc ?? now;
            await _dbContext.SaveChangesAsync(cancellationToken);
            return DeadLetterCaptureResult.Captured(existing.QuarantineId, duplicate: true);
        }
        catch (DbUpdateException)
        {
            return DeadLetterCaptureResult.TransientFailure("quarantine_db_error", "Quarantine capture failed due to a database error.");
        }
    }

    private async Task<DeadLetterQuarantineMessage?> FindExistingAsync(
        Guid? originalMessageId,
        string payloadSha256,
        string syntheticFingerprint,
        CancellationToken cancellationToken)
    {
        if (originalMessageId.HasValue)
        {
            return await _dbContext.DeadLetterQuarantineMessages
                .SingleOrDefaultAsync(x => x.OriginalMessageId == originalMessageId && x.PayloadSha256 == payloadSha256, cancellationToken);
        }

        return await _dbContext.DeadLetterQuarantineMessages
            .SingleOrDefaultAsync(x => x.SyntheticFingerprint == syntheticFingerprint, cancellationToken);
    }

    private DeadLetterClassification Classify(
        byte[] body,
        IReadOnlyBasicProperties properties,
        string routingKey,
        string sha,
        DeadLetterHeaderSummary headerSummary)
    {
        var originalMessageId = Guid.TryParse(properties.MessageId, out var parsedMessageId) ? parsedMessageId : (Guid?)null;
        if (body.Length > _replayOptions.MaxPayloadBytes)
        {
            return new DeadLetterClassification(
                originalMessageId,
                null,
                null,
                null,
                "payload_too_large",
                DeadLetterReplayEligibility.NotEligible,
                "Payload is larger than the configured quarantine limit.",
                null,
                SafePrefix(body));
        }

        var envelope = SecurityEventEnvelopeValidator.TryRead(body, out var failure);
        if (envelope is null)
        {
            return new DeadLetterClassification(
                originalMessageId,
                properties.Type,
                null,
                null,
                failure?.ErrorCode ?? "invalid_payload",
                DeadLetterReplayEligibility.NotEligible,
                failure?.SafeErrorSummary ?? "Payload could not be validated.",
                IsUtf8JsonCandidate(body) ? Encoding.UTF8.GetString(body) : null,
                IsUtf8JsonCandidate(body) ? null : body);
        }

        var propertyFailure = SecurityEventEnvelopeValidator.ValidateRabbitProperties(properties, routingKey, _rabbitOptions, envelope);
        if (propertyFailure is not null)
        {
            return new DeadLetterClassification(
                originalMessageId,
                envelope.MessageType,
                envelope.SchemaVersion,
                envelope.SecurityEvent.Id,
                propertyFailure.ErrorCode ?? "invalid_properties",
                DeadLetterReplayEligibility.NotEligible,
                propertyFailure.SafeErrorSummary ?? "RabbitMQ properties did not match the payload identity.",
                Encoding.UTF8.GetString(body),
                null);
        }

        var eligibility = headerSummary.Reason == "delivery_limit"
            ? DeadLetterReplayEligibility.Eligible
            : DeadLetterReplayEligibility.RequiresReview;
        var explanation = eligibility == DeadLetterReplayEligibility.Eligible
            ? "Envelope and message identity are valid; dead-letter reason indicates exhausted transient delivery."
            : "Envelope is valid but the dead-letter reason requires AdminIB review.";

        return new DeadLetterClassification(
            envelope.MessageId,
            envelope.MessageType,
            envelope.SchemaVersion,
            envelope.SecurityEvent.Id,
            "valid_envelope",
            eligibility,
            explanation,
            Encoding.UTF8.GetString(body),
            null);
    }

    private static byte[] SafePrefix(byte[] body)
    {
        var length = Math.Min(body.Length, 1024);
        var prefix = new byte[length];
        Array.Copy(body, prefix, length);
        return prefix;
    }

    private static bool IsUtf8JsonCandidate(byte[] body)
    {
        try
        {
            var text = Encoding.UTF8.GetString(body);
            var trimmed = text.TrimStart();
            return trimmed.StartsWith('{') || trimmed.StartsWith('[');
        }
        catch
        {
            return false;
        }
    }

    private static string BuildSyntheticFingerprint(Guid? messageId, string sha, string routingKey, int length) =>
        messageId.HasValue ? string.Empty : $"{sha}:{Safe(routingKey, 64)}:{length}";

    private static string? Safe(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var safe = new string(value.Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }

    private static bool IsUniqueViolation(DbUpdateException ex) =>
        ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };

    private sealed record DeadLetterClassification(
        Guid? OriginalMessageId,
        string? MessageType,
        int? SchemaVersion,
        long? SecurityEventId,
        string ValidationCategory,
        DeadLetterReplayEligibility ReplayEligibility,
        string EligibilityExplanation,
        string? PayloadJson,
        byte[]? PayloadBytes);
}

public sealed record DeadLetterCaptureResult(
    DeadLetterCaptureOutcome Outcome,
    Guid? QuarantineId,
    bool Duplicate,
    string? ErrorCode,
    string? SafeErrorSummary)
{
    public static DeadLetterCaptureResult Captured(Guid quarantineId, bool duplicate) =>
        new(DeadLetterCaptureOutcome.Captured, quarantineId, duplicate, null, null);

    public static DeadLetterCaptureResult TransientFailure(string errorCode, string safeErrorSummary) =>
        new(DeadLetterCaptureOutcome.TransientFailure, null, false, OutboxSinkResult.Safe(errorCode, 64), OutboxSinkResult.Safe(safeErrorSummary, 512));
}

public enum DeadLetterCaptureOutcome
{
    Captured,
    TransientFailure
}
