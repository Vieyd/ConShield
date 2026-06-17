using System.Text.Json;

namespace ConShield.EventPipeline;

public sealed record SecurityEventEnvelope(
    int SchemaVersion,
    Guid MessageId,
    string MessageType,
    DateTime CreatedAtUtc,
    SecurityEventEnvelopeData SecurityEvent)
{
    public const int CurrentSchemaVersion = 1;
    public const string SecurityEventCreatedMessageType = "security.event.created";
    public const int MaxPayloadBytes = 65536;
}

public sealed record SecurityEventEnvelopeData(
    long Id,
    DateTime OccurredAtUtc,
    string EventType,
    string Severity,
    string? UserName,
    string? SourceIp,
    Guid? ExternalEventId,
    string? SourceSystem,
    string? ExternalEventType,
    string? SourceHost,
    string Description,
    JsonElement? AdditionalData);
