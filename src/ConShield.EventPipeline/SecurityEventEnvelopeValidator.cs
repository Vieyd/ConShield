using System.Security.Cryptography;
using System.Text.Json;
using RabbitMQ.Client;

namespace ConShield.EventPipeline;

public static class SecurityEventEnvelopeValidator
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static OutboxSinkResult? ValidateEnvelope(SecurityEventEnvelope envelope)
    {
        if (envelope.SchemaVersion != SecurityEventEnvelope.CurrentSchemaVersion)
            return OutboxSinkResult.PermanentFailure("unsupported_schema", "Unsupported security event envelope schema.");
        if (!string.Equals(envelope.MessageType, SecurityEventEnvelope.SecurityEventCreatedMessageType, StringComparison.Ordinal))
            return OutboxSinkResult.PermanentFailure("unsupported_message_type", "Unsupported security event message type.");
        if (envelope.MessageId == Guid.Empty || envelope.SecurityEvent.Id <= 0)
            return OutboxSinkResult.PermanentFailure("invalid_identity", "Envelope identity is invalid.");
        if (envelope.CreatedAtUtc.Kind != DateTimeKind.Utc || envelope.SecurityEvent.OccurredAtUtc.Kind != DateTimeKind.Utc)
            return OutboxSinkResult.PermanentFailure("invalid_timestamp", "Envelope timestamps must be UTC.");
        return null;
    }

    public static SecurityEventEnvelope? TryRead(ReadOnlySpan<byte> body, out OutboxSinkResult? failure)
    {
        failure = null;
        if (body.Length == 0)
        {
            failure = OutboxSinkResult.PermanentFailure("empty_body", "RabbitMQ message body is empty.");
            return null;
        }

        if (body.Length > SecurityEventEnvelope.MaxPayloadBytes)
        {
            failure = OutboxSinkResult.PermanentFailure("body_too_large", "RabbitMQ message body exceeds the configured limit.");
            return null;
        }

        try
        {
            var envelope = JsonSerializer.Deserialize<SecurityEventEnvelope>(body, SerializerOptions);
            if (envelope is null)
            {
                failure = OutboxSinkResult.PermanentFailure("payload_null", "RabbitMQ message body was empty.");
                return null;
            }

            failure = ValidateEnvelope(envelope);
            return failure is null ? envelope : null;
        }
        catch (JsonException)
        {
            failure = OutboxSinkResult.PermanentFailure("malformed_json", "RabbitMQ message body is malformed JSON.");
            return null;
        }
    }

    public static OutboxSinkResult? ValidateRabbitProperties(
        IReadOnlyBasicProperties properties,
        string routingKey,
        RabbitMqOptions options,
        SecurityEventEnvelope envelope)
    {
        if (!string.Equals(routingKey, options.RoutingKey, StringComparison.Ordinal))
            return OutboxSinkResult.PermanentFailure("wrong_routing_key", "RabbitMQ message used an unexpected routing key.");
        if (!string.Equals(properties.ContentType, "application/json", StringComparison.OrdinalIgnoreCase))
            return OutboxSinkResult.PermanentFailure("wrong_content_type", "RabbitMQ message content type is not application/json.");
        if (!string.Equals(properties.Type, SecurityEventEnvelope.SecurityEventCreatedMessageType, StringComparison.Ordinal))
            return OutboxSinkResult.PermanentFailure("wrong_message_type", "RabbitMQ message type is unsupported.");
        if (!Guid.TryParse(properties.MessageId, out var propertyMessageId))
            return OutboxSinkResult.PermanentFailure("invalid_message_id", "RabbitMQ message id is not a UUID.");
        if (propertyMessageId != envelope.MessageId)
            return OutboxSinkResult.PermanentFailure("message_id_mismatch", "RabbitMQ message id does not match the payload.");
        return null;
    }

    public static string Sha256Hex(byte[] body)
    {
        return Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
    }
}
