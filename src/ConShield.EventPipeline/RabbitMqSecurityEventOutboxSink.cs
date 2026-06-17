using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Exceptions;

namespace ConShield.EventPipeline;

public sealed class RabbitMqSecurityEventOutboxSink : ISecurityEventOutboxSink
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly IRabbitMqConnectionProvider _connectionProvider;
    private readonly RabbitMqTopology _topology;
    private readonly RabbitMqOptions _options;
    private readonly ILogger<RabbitMqSecurityEventOutboxSink> _logger;

    public RabbitMqSecurityEventOutboxSink(
        IRabbitMqConnectionProvider connectionProvider,
        RabbitMqTopology topology,
        IOptions<RabbitMqOptions> options,
        ILogger<RabbitMqSecurityEventOutboxSink> logger)
    {
        _connectionProvider = connectionProvider;
        _topology = topology;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<OutboxSinkResult> DeliverAsync(SecurityEventEnvelope envelope, CancellationToken cancellationToken)
    {
        var validation = SecurityEventEnvelopeValidator.ValidateEnvelope(envelope);
        if (validation is not null)
            return validation;

        byte[] body;
        try
        {
            body = JsonSerializer.SerializeToUtf8Bytes(envelope, SerializerOptions);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return OutboxSinkResult.PermanentFailure("serialization_failed", "Outbox envelope could not be serialized.");
        }

        if (body.Length > SecurityEventEnvelope.MaxPayloadBytes)
            return OutboxSinkResult.PermanentFailure("body_too_large", "Outbox envelope exceeds the RabbitMQ body limit.");

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(_options.PublishTimeoutSeconds));

            var connection = await _connectionProvider.GetConnectionAsync("conshield-web-outbox-publisher", timeout.Token);
            await using var channel = await connection.CreateChannelAsync(
                new CreateChannelOptions(
                    publisherConfirmationsEnabled: true,
                    publisherConfirmationTrackingEnabled: true,
                    outstandingPublisherConfirmationsRateLimiter: null,
                    consumerDispatchConcurrency: null),
                timeout.Token);

            await _topology.DeclareAsync(channel, timeout.Token);

            var properties = CreateProperties(envelope);
            // With confirmation tracking enabled, RabbitMQ.Client throws on mandatory returns and nacks.
            await channel.BasicPublishAsync(
                _options.ExchangeName,
                _options.RoutingKey,
                mandatory: true,
                basicProperties: properties,
                body: body,
                cancellationToken: timeout.Token);

            return OutboxSinkResult.Succeeded();
        }
        catch (PublishReturnException)
        {
            _logger.LogDebug("RabbitMQ mandatory return for message {MessageId}.", envelope.MessageId);
            return OutboxSinkResult.TransientFailure("mandatory_return", "RabbitMQ returned the message as unroutable.");
        }
        catch (PublishException)
        {
            _logger.LogDebug("RabbitMQ publisher nack for message {MessageId}.", envelope.MessageId);
            return OutboxSinkResult.TransientFailure("publisher_nack", "RabbitMQ did not confirm the published message.");
        }
        catch (OperationCanceledException)
        {
            return OutboxSinkResult.TransientFailure("publish_timeout", "RabbitMQ publish timed out or was cancelled.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning("RabbitMQ publish failed for message {MessageId}.", envelope.MessageId);
            return ClassifyPublishFailure(ex);
        }
    }

    public static BasicProperties CreateProperties(SecurityEventEnvelope envelope)
    {
        return new BasicProperties
        {
            ContentType = "application/json",
            ContentEncoding = "utf-8",
            DeliveryMode = DeliveryModes.Persistent,
            Persistent = true,
            MessageId = envelope.MessageId.ToString("D"),
            Type = SecurityEventEnvelope.SecurityEventCreatedMessageType,
            AppId = "conshield",
            Timestamp = new AmqpTimestamp(new DateTimeOffset(envelope.CreatedAtUtc).ToUnixTimeSeconds()),
            Headers = new Dictionary<string, object?>
            {
                ["schema-version"] = envelope.SchemaVersion,
                ["security-event-id"] = envelope.SecurityEvent.Id,
                ["source-system"] = OutboxSinkResult.Safe(envelope.SecurityEvent.SourceSystem, 128)
            }!
        };
    }

    public static OutboxSinkResult ClassifyPublishFailure(Exception ex)
    {
        return ex switch
        {
            PublishReturnException => OutboxSinkResult.TransientFailure("mandatory_return", "RabbitMQ returned the message as unroutable."),
            PublishException => OutboxSinkResult.TransientFailure("publisher_nack", "RabbitMQ did not confirm the published message."),
            OperationCanceledException => OutboxSinkResult.TransientFailure("publish_timeout", "RabbitMQ publish timed out or was cancelled."),
            BrokerUnreachableException => OutboxSinkResult.TransientFailure("rabbitmq_unavailable", "RabbitMQ publish failed transiently."),
            AuthenticationFailureException => OutboxSinkResult.PermanentFailure("rabbitmq_config_error", "RabbitMQ topology or configuration is invalid."),
            OperationInterruptedException operation when IsPreconditionFailure(operation) =>
                OutboxSinkResult.PermanentFailure("rabbitmq_config_error", "RabbitMQ topology or configuration is invalid."),
            _ => OutboxSinkResult.TransientFailure("rabbitmq_unavailable", "RabbitMQ publish failed transiently.")
        };
    }

    private static bool IsPreconditionFailure(OperationInterruptedException ex)
    {
        return ex.ShutdownReason?.ReplyCode is 403 or 404 or 405 or 406;
    }
}
