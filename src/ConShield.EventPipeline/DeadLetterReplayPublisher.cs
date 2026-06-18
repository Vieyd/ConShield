using System.Text;
using ConShield.Data.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Exceptions;

namespace ConShield.EventPipeline;

public sealed class DeadLetterReplayPublisher
{
    private readonly IRabbitMqConnectionProvider _connectionProvider;
    private readonly RabbitMqTopology _topology;
    private readonly RabbitMqOptions _rabbitOptions;
    private readonly ILogger<DeadLetterReplayPublisher> _logger;

    public DeadLetterReplayPublisher(
        IRabbitMqConnectionProvider connectionProvider,
        RabbitMqTopology topology,
        IOptions<RabbitMqOptions> rabbitOptions,
        ILogger<DeadLetterReplayPublisher> logger)
    {
        _connectionProvider = connectionProvider;
        _topology = topology;
        _rabbitOptions = rabbitOptions.Value;
        _logger = logger;
    }

    public async Task<OutboxSinkResult> PublishAsync(
        DeadLetterQuarantineMessage message,
        DeadLetterReplayRequest request,
        CancellationToken cancellationToken)
    {
        if (message.OriginalMessageId is null)
            return OutboxSinkResult.PermanentFailure("invalid_message_id", "Replay requires a valid original MessageId.");

        var body = message.PayloadBytes ?? Encoding.UTF8.GetBytes(message.PayloadJson ?? string.Empty);
        if (body.Length == 0)
            return OutboxSinkResult.PermanentFailure("payload_unavailable", "Replay payload is unavailable.");

        try
        {
            var connection = await _connectionProvider.GetConnectionAsync("conshield-dlq-replay-publisher", cancellationToken);
            await using var channel = await connection.CreateChannelAsync(
                new CreateChannelOptions(
                    publisherConfirmationsEnabled: true,
                    publisherConfirmationTrackingEnabled: true,
                    outstandingPublisherConfirmationsRateLimiter: null,
                    consumerDispatchConcurrency: null),
                cancellationToken);
            await _topology.DeclareAsync(channel, cancellationToken);
            var properties = CreateProperties(message, request);
            await channel.BasicPublishAsync(
                _rabbitOptions.ExchangeName,
                _rabbitOptions.RoutingKey,
                mandatory: true,
                basicProperties: properties,
                body: body,
                cancellationToken: cancellationToken);
            return OutboxSinkResult.Succeeded();
        }
        catch (PublishReturnException)
        {
            return OutboxSinkResult.TransientFailure("mandatory_return", "RabbitMQ returned the replay message as unroutable.");
        }
        catch (PublishException)
        {
            return OutboxSinkResult.TransientFailure("publisher_nack", "RabbitMQ did not confirm the replay message.");
        }
        catch (OperationCanceledException)
        {
            return OutboxSinkResult.TransientFailure("publish_timeout", "RabbitMQ replay publish timed out or was cancelled.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Dead-letter replay publish failed for request {ReplayRequestId}.", request.ReplayRequestId);
            return RabbitMqSecurityEventOutboxSink.ClassifyPublishFailure(ex);
        }
    }

    public static BasicProperties CreateProperties(DeadLetterQuarantineMessage message, DeadLetterReplayRequest request) =>
        new()
        {
            ContentType = string.Equals(message.ContentType, "application/json", StringComparison.OrdinalIgnoreCase) ? "application/json" : "application/json",
            ContentEncoding = "utf-8",
            DeliveryMode = DeliveryModes.Persistent,
            Persistent = true,
            MessageId = message.OriginalMessageId?.ToString("D"),
            Type = SecurityEventEnvelope.SecurityEventCreatedMessageType,
            AppId = "conshield",
            Timestamp = new AmqpTimestamp(DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
            Headers = new Dictionary<string, object?>
            {
                ["x-conshield-replay-request-id"] = request.ReplayRequestId.ToString("D"),
                ["x-conshield-replay-sequence"] = request.ReplaySequence,
                ["x-conshield-original-quarantine-id"] = message.QuarantineId.ToString("D")
            }!
        };
}
