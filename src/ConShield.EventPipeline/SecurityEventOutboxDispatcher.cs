using System.Text.Json;
using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class SecurityEventOutboxDispatcher
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly ApplicationDbContext _dbContext;
    private readonly ISecurityEventOutboxSink _sink;
    private readonly IOutboxClock _clock;
    private readonly SecurityEventOutboxOptions _options;
    private readonly ILogger<SecurityEventOutboxDispatcher> _logger;

    public SecurityEventOutboxDispatcher(
        ApplicationDbContext dbContext,
        ISecurityEventOutboxSink sink,
        IOutboxClock clock,
        IOptions<SecurityEventOutboxOptions> options,
        ILogger<SecurityEventOutboxDispatcher> logger)
    {
        _dbContext = dbContext;
        _sink = sink;
        _clock = clock;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<OutboxDispatchResult> DispatchOnceAsync(CancellationToken cancellationToken = default)
    {
        var messages = await ClaimBatchAsync(cancellationToken);
        var delivered = 0;
        var failed = 0;
        var deadLettered = 0;

        foreach (var message in messages)
        {
            try
            {
                var result = await DeliverOneAsync(message, cancellationToken);
                delivered += result.Delivered ? 1 : 0;
                failed += result.Failed ? 1 : 0;
                deadLettered += result.DeadLettered ? 1 : 0;
            }
            catch (OperationCanceledException)
            {
                await MarkFailureAsync(
                    message,
                    OutboxSinkResult.TransientFailure("cancelled", "Dispatch was cancelled."),
                    cancellationToken: CancellationToken.None);
                failed++;
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Outbox message {MessageId} failed with an unexpected dispatcher error.", message.MessageId);
                await MarkFailureAsync(
                    message,
                    OutboxSinkResult.TransientFailure("dispatcher_error", "Dispatcher failed before delivery completed."),
                    cancellationToken: CancellationToken.None);
                failed++;
            }
        }

        return new OutboxDispatchResult(messages.Count, delivered, failed, deadLettered);
    }

    private async Task<List<SecurityEventOutboxMessage>> ClaimBatchAsync(CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var lockToken = Guid.NewGuid();
        var lockedUntil = now.AddSeconds(_options.LockSeconds);
        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
        var messages = new List<SecurityEventOutboxMessage>();
        var connection = _dbContext.Database.GetDbConnection();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction.GetDbTransaction();
        command.CommandText = """
            UPDATE "SecurityEventOutbox"
            SET "Status" = 'Processing',
                "LockToken" = @lockToken,
                "LockedUntilUtc" = @lockedUntil,
                "LastAttemptAtUtc" = @now
            WHERE "Id" IN (
                SELECT "Id"
                FROM "SecurityEventOutbox"
                WHERE (
                    ("Status" = 'Pending' AND "AvailableAtUtc" <= @now)
                    OR ("Status" = 'Processing' AND "LockedUntilUtc" IS NOT NULL AND "LockedUntilUtc" <= @now)
                )
                ORDER BY "AvailableAtUtc", "Id"
                LIMIT @batchSize
                FOR UPDATE SKIP LOCKED
            )
            RETURNING "Id", "MessageId", "SecurityEventId", "MessageType", "SchemaVersion", "PayloadJson",
                "Status", "CreatedAtUtc", "AvailableAtUtc", "AttemptCount", "LastAttemptAtUtc",
                "LockedUntilUtc", "LockToken", "DeliveredAtUtc", "LastErrorCode", "LastErrorSummary";
            """;
        AddParameter(command, "lockToken", lockToken);
        AddParameter(command, "lockedUntil", lockedUntil);
        AddParameter(command, "now", now);
        AddParameter(command, "batchSize", _options.BatchSize);

        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
                messages.Add(ReadMessage(reader));
        }

        await transaction.CommitAsync(cancellationToken);
        return messages;
    }

    private static void AddParameter(System.Data.Common.DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }

    private static SecurityEventOutboxMessage ReadMessage(System.Data.Common.DbDataReader reader)
    {
        return new SecurityEventOutboxMessage
        {
            Id = reader.GetInt64(0),
            MessageId = reader.GetGuid(1),
            SecurityEventId = reader.GetInt64(2),
            MessageType = reader.GetString(3),
            SchemaVersion = reader.GetInt32(4),
            PayloadJson = reader.GetString(5),
            Status = Enum.Parse<SecurityEventOutboxStatus>(reader.GetString(6)),
            CreatedAtUtc = reader.GetDateTime(7),
            AvailableAtUtc = reader.GetDateTime(8),
            AttemptCount = reader.GetInt32(9),
            LastAttemptAtUtc = reader.IsDBNull(10) ? null : reader.GetDateTime(10),
            LockedUntilUtc = reader.IsDBNull(11) ? null : reader.GetDateTime(11),
            LockToken = reader.IsDBNull(12) ? null : reader.GetGuid(12),
            DeliveredAtUtc = reader.IsDBNull(13) ? null : reader.GetDateTime(13),
            LastErrorCode = reader.IsDBNull(14) ? null : reader.GetString(14),
            LastErrorSummary = reader.IsDBNull(15) ? null : reader.GetString(15)
        };
    }

    private async Task<MessageDispatchResult> DeliverOneAsync(
        SecurityEventOutboxMessage message,
        CancellationToken cancellationToken)
    {
        var envelope = TryReadEnvelope(message, out var parseFailure);
        if (envelope is null)
        {
            await MarkDeadLetterAsync(message, parseFailure!, cancellationToken);
            return MessageDispatchResult.DeadLetterResult();
        }

        OutboxSinkResult sinkResult;
        try
        {
            sinkResult = await _sink.DeliverAsync(envelope, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            sinkResult = OutboxSinkResult.TransientFailure("cancelled", "Sink delivery was cancelled.");
        }

        if (sinkResult.Type == OutboxSinkResultType.Succeeded)
        {
            await MarkDeliveredAsync(message, cancellationToken);
            return MessageDispatchResult.DeliveredResult();
        }

        await MarkFailureAsync(message, sinkResult, cancellationToken);
        return sinkResult.Type == OutboxSinkResultType.PermanentFailure || message.AttemptCount + 1 >= _options.MaxAttempts
            ? MessageDispatchResult.DeadLetterResult()
            : MessageDispatchResult.FailedResult();
    }

    private static SecurityEventEnvelope? TryReadEnvelope(
        SecurityEventOutboxMessage message,
        out OutboxSinkResult? failure)
    {
        failure = null;
        try
        {
            var envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(message.PayloadJson, SerializerOptions);
            if (envelope is null)
            {
                failure = OutboxSinkResult.PermanentFailure("payload_null", "Outbox payload was empty.");
                return null;
            }

            if (envelope.SchemaVersion != SecurityEventEnvelope.CurrentSchemaVersion)
            {
                failure = OutboxSinkResult.PermanentFailure("unsupported_schema", "Outbox payload schema version is not supported.");
                return null;
            }

            if (envelope.MessageType != SecurityEventEnvelope.SecurityEventCreatedMessageType
                || message.MessageType != SecurityEventEnvelope.SecurityEventCreatedMessageType)
            {
                failure = OutboxSinkResult.PermanentFailure("unsupported_message_type", "Outbox message type is not supported.");
                return null;
            }

            if (envelope.MessageId != message.MessageId || envelope.SecurityEvent.Id != message.SecurityEventId)
            {
                failure = OutboxSinkResult.PermanentFailure("payload_mismatch", "Outbox payload identity does not match the row.");
                return null;
            }

            return envelope;
        }
        catch (JsonException)
        {
            failure = OutboxSinkResult.PermanentFailure("malformed_payload", "Outbox payload is not valid JSON.");
            return null;
        }
    }

    private async Task MarkDeliveredAsync(SecurityEventOutboxMessage message, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        await _dbContext.SecurityEventOutboxMessages
            .Where(x => x.Id == message.Id
                && x.LockToken == message.LockToken
                && x.Status == SecurityEventOutboxStatus.Processing)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.Status, SecurityEventOutboxStatus.Delivered)
                .SetProperty(x => x.DeliveredAtUtc, now)
                .SetProperty(x => x.LockToken, (Guid?)null)
                .SetProperty(x => x.LockedUntilUtc, (DateTime?)null)
                .SetProperty(x => x.LastErrorCode, (string?)null)
                .SetProperty(x => x.LastErrorSummary, (string?)null), cancellationToken);
    }

    private async Task MarkFailureAsync(
        SecurityEventOutboxMessage message,
        OutboxSinkResult result,
        CancellationToken cancellationToken)
    {
        if (result.Type == OutboxSinkResultType.PermanentFailure || message.AttemptCount + 1 >= _options.MaxAttempts)
        {
            await MarkDeadLetterAsync(message, result, cancellationToken);
            return;
        }

        var now = _clock.UtcNow;
        var attemptCount = Math.Max(0, message.AttemptCount) + 1;
        var availableAt = now.AddSeconds(CalculateBackoffSeconds(attemptCount));
        var errorCode = OutboxSinkResult.Safe(result.ErrorCode, 64);
        var errorSummary = OutboxSinkResult.Safe(result.SafeErrorSummary, 512);

        await _dbContext.SecurityEventOutboxMessages
            .Where(x => x.Id == message.Id
                && x.LockToken == message.LockToken
                && x.Status == SecurityEventOutboxStatus.Processing)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.Status, SecurityEventOutboxStatus.Pending)
                .SetProperty(x => x.AttemptCount, attemptCount)
                .SetProperty(x => x.AvailableAtUtc, availableAt)
                .SetProperty(x => x.LockToken, (Guid?)null)
                .SetProperty(x => x.LockedUntilUtc, (DateTime?)null)
                .SetProperty(x => x.LastErrorCode, errorCode)
                .SetProperty(x => x.LastErrorSummary, errorSummary), cancellationToken);
    }

    private async Task MarkDeadLetterAsync(
        SecurityEventOutboxMessage message,
        OutboxSinkResult result,
        CancellationToken cancellationToken)
    {
        var attemptCount = result.Type == OutboxSinkResultType.Succeeded
            ? message.AttemptCount
            : Math.Max(0, message.AttemptCount) + 1;
        var errorCode = OutboxSinkResult.Safe(result.ErrorCode, 64);
        var errorSummary = OutboxSinkResult.Safe(result.SafeErrorSummary, 512);

        await _dbContext.SecurityEventOutboxMessages
            .Where(x => x.Id == message.Id
                && x.LockToken == message.LockToken
                && x.Status == SecurityEventOutboxStatus.Processing)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.Status, SecurityEventOutboxStatus.DeadLetter)
                .SetProperty(x => x.AttemptCount, attemptCount)
                .SetProperty(x => x.LockToken, (Guid?)null)
                .SetProperty(x => x.LockedUntilUtc, (DateTime?)null)
                .SetProperty(x => x.LastErrorCode, errorCode)
                .SetProperty(x => x.LastErrorSummary, errorSummary), cancellationToken);
    }

    public int CalculateBackoffSeconds(int attemptCount)
    {
        var safeAttempt = Math.Clamp(attemptCount, 1, 30);
        var multiplier = 1L << Math.Min(safeAttempt - 1, 20);
        var seconds = Math.Min((long)_options.MaxRetrySeconds, (long)_options.BaseRetrySeconds * multiplier);
        return (int)Math.Max(1, seconds);
    }

    private sealed record MessageDispatchResult(bool Delivered, bool Failed, bool DeadLettered)
    {
        public static MessageDispatchResult DeliveredResult() => new(true, false, false);
        public static MessageDispatchResult FailedResult() => new(false, true, false);
        public static MessageDispatchResult DeadLetterResult() => new(false, false, true);
    }
}

public sealed record OutboxDispatchResult(int Claimed, int Delivered, int Failed, int DeadLettered);
