using Microsoft.Extensions.Options;
using RabbitMQ.Client;

namespace ConShield.EventPipeline;

public sealed class SecurityEventDeliveryProcessor
{
    private readonly SecurityEventInboxProcessor _inboxProcessor;
    private readonly ISecurityEventRawProjection _rawProjection;
    private readonly IOutboxClock _clock;
    private readonly RabbitMqOptions _options;

    public SecurityEventDeliveryProcessor(
        SecurityEventInboxProcessor inboxProcessor,
        ISecurityEventRawProjection rawProjection,
        IOutboxClock clock,
        IOptions<RabbitMqOptions> options)
    {
        _inboxProcessor = inboxProcessor;
        _rawProjection = rawProjection;
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

        var payloadSha256 = SecurityEventEnvelopeValidator.Sha256Hex(body);
        var identity = SecurityEventPayloadIdentity.FromEnvelope(envelope, payloadSha256);

        var existing = await _inboxProcessor.MarkDuplicateIfExistsAsync(identity, redelivered, cancellationToken);
        if (existing is not null)
            return existing;

        var now = _clock.UtcNow;
        var projected = await _rawProjection.ProjectAsync(envelope, body, payloadSha256, now, cancellationToken);
        if (projected.Outcome == SecurityEventRawProjectionOutcome.TransientFailure)
            return InboxProcessResult.TransientFailure(OutboxSinkResult.TransientFailure(projected.ErrorCode!, projected.SafeErrorSummary!));
        if (projected.Outcome == SecurityEventRawProjectionOutcome.PermanentFailure)
            return InboxProcessResult.PermanentFailure(OutboxSinkResult.PermanentFailure(projected.ErrorCode!, projected.SafeErrorSummary!));

        return await _inboxProcessor.CompleteAsync(identity, routingKey, redelivered, now, cancellationToken);
    }
}
