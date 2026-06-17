using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;

namespace ConShield.EventPipeline;

public sealed class SecurityEventInboxProcessor
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IOutboxClock _clock;
    private readonly RabbitMqOptions _options;

    public SecurityEventInboxProcessor(
        ApplicationDbContext dbContext,
        IOutboxClock clock,
        IOptions<RabbitMqOptions> options)
    {
        _dbContext = dbContext;
        _clock = clock;
        _options = options.Value;
    }

    public async Task<InboxProcessResult> ProcessAsync(
        byte[] body,
        IReadOnlyBasicProperties properties,
        string routingKey,
        bool redelivered,
        CancellationToken cancellationToken)
    {
        var envelope = SecurityEventEnvelopeValidator.TryRead(body, out var failure);
        if (envelope is null)
            return InboxProcessResult.PermanentFailure(failure!);

        failure = SecurityEventEnvelopeValidator.ValidateRabbitProperties(properties, routingKey, _options, envelope);
        if (failure is not null)
            return InboxProcessResult.PermanentFailure(failure);

        try
        {
            var now = _clock.UtcNow;
            var existing = await _dbContext.SecurityEventInboxReceipts
                .SingleOrDefaultAsync(x => x.MessageId == envelope.MessageId, cancellationToken);

            if (existing is not null)
            {
                existing.DeliveryCount += 1;
                existing.Redelivered = existing.Redelivered || redelivered;
                await _dbContext.SaveChangesAsync(cancellationToken);
                return InboxProcessResult.Duplicate();
            }

            await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
            _dbContext.SecurityEventInboxReceipts.Add(new SecurityEventInboxReceipt
            {
                MessageId = envelope.MessageId,
                SecurityEventId = envelope.SecurityEvent.Id,
                MessageType = envelope.MessageType,
                SchemaVersion = envelope.SchemaVersion,
                PayloadSha256 = SecurityEventEnvelopeValidator.Sha256Hex(body),
                RoutingKey = routingKey,
                ReceivedAtUtc = now,
                ProcessedAtUtc = now,
                Redelivered = redelivered,
                DeliveryCount = 1
            });
            await _dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return InboxProcessResult.Processed();
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            _dbContext.ChangeTracker.Clear();
            return InboxProcessResult.Duplicate();
        }
    }

    private static bool IsUniqueViolation(DbUpdateException ex)
    {
        return ex.InnerException?.GetType().Name.Contains("PostgresException", StringComparison.OrdinalIgnoreCase) == true
            && ex.InnerException.Message.Contains("23505", StringComparison.Ordinal);
    }
}

public sealed record InboxProcessResult(InboxProcessOutcome Outcome, OutboxSinkResult? Failure = null)
{
    public static InboxProcessResult Processed() => new(InboxProcessOutcome.Processed);
    public static InboxProcessResult Duplicate() => new(InboxProcessOutcome.Duplicate);
    public static InboxProcessResult PermanentFailure(OutboxSinkResult failure) => new(InboxProcessOutcome.PermanentFailure, failure);
}

public enum InboxProcessOutcome
{
    Processed,
    Duplicate,
    PermanentFailure
}
