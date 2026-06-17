using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
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

        var identity = SecurityEventPayloadIdentity.FromEnvelope(envelope, SecurityEventEnvelopeValidator.Sha256Hex(body));
        var existing = await MarkDuplicateIfExistsAsync(identity, redelivered, cancellationToken);
        if (existing is not null)
            return existing;

        return await CompleteAsync(identity, routingKey, redelivered, _clock.UtcNow, cancellationToken);
    }

    public async Task<InboxProcessResult?> MarkDuplicateIfExistsAsync(
        SecurityEventPayloadIdentity identity,
        bool redelivered,
        CancellationToken cancellationToken)
    {
        var existing = await _dbContext.SecurityEventInboxReceipts
            .SingleOrDefaultAsync(x => x.MessageId == identity.MessageId, cancellationToken);

        if (existing is null)
            return null;

        if (!identity.Matches(existing))
            return InboxProcessResult.PermanentFailure(OutboxSinkResult.PermanentFailure(
                "inbox_payload_mismatch",
                "RabbitMQ message id was already completed with different payload identity."));

        existing.DeliveryCount += 1;
        existing.Redelivered = existing.Redelivered || redelivered;
        await _dbContext.SaveChangesAsync(cancellationToken);
        return InboxProcessResult.Duplicate();
    }

    public async Task<InboxProcessResult> CompleteAsync(
        SecurityEventPayloadIdentity identity,
        string routingKey,
        bool redelivered,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
            _dbContext.SecurityEventInboxReceipts.Add(new SecurityEventInboxReceipt
            {
                MessageId = identity.MessageId,
                SecurityEventId = identity.SecurityEventId,
                MessageType = identity.MessageType,
                SchemaVersion = identity.SchemaVersion,
                PayloadSha256 = identity.PayloadSha256,
                RoutingKey = routingKey,
                ReceivedAtUtc = nowUtc,
                ProcessedAtUtc = nowUtc,
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
            var existing = await MarkDuplicateIfExistsAsync(identity, redelivered: true, cancellationToken);
            return existing ?? InboxProcessResult.TransientFailure(OutboxSinkResult.TransientFailure(
                "inbox_unique_race",
                "Inbox unique race could not reload committed receipt."));
        }
    }

    public static bool IsUniqueViolation(DbUpdateException ex) =>
        ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}

public sealed record InboxProcessResult(InboxProcessOutcome Outcome, OutboxSinkResult? Failure = null)
{
    public static InboxProcessResult Processed() => new(InboxProcessOutcome.Processed);
    public static InboxProcessResult Duplicate() => new(InboxProcessOutcome.Duplicate);
    public static InboxProcessResult TransientFailure(OutboxSinkResult failure) => new(InboxProcessOutcome.TransientFailure, failure);
    public static InboxProcessResult PermanentFailure(OutboxSinkResult failure) => new(InboxProcessOutcome.PermanentFailure, failure);
}

public enum InboxProcessOutcome
{
    Processed,
    Duplicate,
    TransientFailure,
    PermanentFailure
}
