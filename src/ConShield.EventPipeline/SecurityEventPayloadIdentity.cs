using ConShield.Data.Entities;

namespace ConShield.EventPipeline;

public sealed record SecurityEventPayloadIdentity(
    Guid MessageId,
    string MessageType,
    long SecurityEventId,
    int SchemaVersion,
    string PayloadSha256)
{
    public static SecurityEventPayloadIdentity FromEnvelope(SecurityEventEnvelope envelope, string payloadSha256) =>
        new(
            envelope.MessageId,
            envelope.MessageType,
            envelope.SecurityEvent.Id,
            envelope.SchemaVersion,
            payloadSha256);

    public bool Matches(SecurityEventInboxReceipt receipt) =>
        receipt.MessageId == MessageId
        && string.Equals(receipt.MessageType, MessageType, StringComparison.Ordinal)
        && receipt.SecurityEventId == SecurityEventId
        && receipt.SchemaVersion == SchemaVersion
        && string.Equals(receipt.PayloadSha256, PayloadSha256, StringComparison.Ordinal);
}
