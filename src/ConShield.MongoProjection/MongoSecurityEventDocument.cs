using System.Text.Json;
using ConShield.EventPipeline;
using MongoDB.Bson;

namespace ConShield.MongoProjection;

public sealed class MongoSecurityEventDocument
{
    public const int CurrentSchemaVersion = 1;
    private const int MaxStringLength = 2000;

    public MongoSecurityEventDocument(
        string id,
        int schemaVersion,
        string messageId,
        string messageType,
        string payloadSha256,
        DateTime projectedAtUtc,
        DateTime expiresAtUtc,
        BsonDocument securityEvent)
    {
        Id = id;
        SchemaVersion = schemaVersion;
        MessageId = messageId;
        MessageType = messageType;
        PayloadSha256 = payloadSha256;
        ProjectedAtUtc = DateTime.SpecifyKind(projectedAtUtc, DateTimeKind.Utc);
        ExpiresAtUtc = DateTime.SpecifyKind(expiresAtUtc, DateTimeKind.Utc);
        SecurityEvent = securityEvent;
    }

    public string Id { get; }
    public int SchemaVersion { get; }
    public string MessageId { get; }
    public string MessageType { get; }
    public string PayloadSha256 { get; }
    public DateTime ProjectedAtUtc { get; }
    public DateTime ExpiresAtUtc { get; }
    public BsonDocument SecurityEvent { get; }

    public static MongoSecurityEventDocument FromEnvelope(
        SecurityEventEnvelope envelope,
        string payloadSha256,
        DateTime projectedAtUtc,
        int retentionDays)
    {
        var messageId = envelope.MessageId.ToString("D").ToLowerInvariant();
        var eventData = envelope.SecurityEvent;
        BsonValue additionalData = eventData.AdditionalData is null || eventData.AdditionalData.Value.ValueKind == JsonValueKind.Null
            ? BsonNull.Value
            : eventData.AdditionalData.Value.ValueKind == JsonValueKind.Object
                ? BsonDocument.Parse(eventData.AdditionalData.Value.GetRawText())
                : throw new InvalidOperationException("additionalData must be a JSON object or null.");

        var securityEvent = new BsonDocument
        {
            ["id"] = eventData.Id,
            ["occurredAtUtc"] = ToUtc(eventData.OccurredAtUtc),
            ["eventType"] = SafeString(eventData.EventType, 128),
            ["severity"] = SafeString(eventData.Severity, 64),
            ["userName"] = BsonNullable(eventData.UserName, 128),
            ["sourceIp"] = BsonNullable(eventData.SourceIp, 64),
            ["externalEventId"] = eventData.ExternalEventId is null ? BsonNull.Value : eventData.ExternalEventId.Value.ToString("D").ToLowerInvariant(),
            ["sourceSystem"] = BsonNullable(eventData.SourceSystem, 128),
            ["externalEventType"] = BsonNullable(eventData.ExternalEventType, 128),
            ["sourceHost"] = BsonNullable(eventData.SourceHost, 256),
            ["description"] = SafeString(eventData.Description, MaxStringLength),
            ["additionalData"] = additionalData
        };

        return new MongoSecurityEventDocument(
            messageId,
            CurrentSchemaVersion,
            messageId,
            envelope.MessageType,
            payloadSha256,
            ToUtc(projectedAtUtc),
            ToUtc(projectedAtUtc).AddDays(retentionDays),
            securityEvent);
    }

    public BsonDocument ToBsonDocument() => new()
    {
        ["_id"] = Id,
        ["schemaVersion"] = SchemaVersion,
        ["messageId"] = MessageId,
        ["messageType"] = MessageType,
        ["payloadSha256"] = PayloadSha256,
        ["projectedAtUtc"] = ProjectedAtUtc,
        ["expiresAtUtc"] = ExpiresAtUtc,
        ["securityEvent"] = SecurityEvent
    };

    public bool HasSameIdentity(MongoSecurityEventDocument other) =>
        string.Equals(PayloadSha256, other.PayloadSha256, StringComparison.Ordinal)
        && string.Equals(MessageType, other.MessageType, StringComparison.Ordinal)
        && SchemaVersion == other.SchemaVersion
        && SecurityEvent.GetValue("id", BsonNull.Value) == other.SecurityEvent.GetValue("id", BsonNull.Value);

    public static MongoSecurityEventDocument FromBsonDocument(BsonDocument document)
    {
        var securityEvent = document.GetValue("securityEvent", new BsonDocument()).AsBsonDocument;
        return new MongoSecurityEventDocument(
            document.GetValue("_id").AsString,
            document.GetValue("schemaVersion").ToInt32(),
            document.GetValue("messageId").AsString,
            document.GetValue("messageType").AsString,
            document.GetValue("payloadSha256").AsString,
            document.GetValue("projectedAtUtc").ToUniversalTime(),
            document.GetValue("expiresAtUtc").ToUniversalTime(),
            securityEvent);
    }

    private static DateTime ToUtc(DateTime value) =>
        value.Kind == DateTimeKind.Utc ? value : DateTime.SpecifyKind(value, DateTimeKind.Utc);

    private static BsonValue BsonNullable(string? value, int maxLength) =>
        string.IsNullOrWhiteSpace(value) ? BsonNull.Value : SafeString(value, maxLength);

    private static string SafeString(string value, int maxLength)
    {
        var safe = new string(value.Where(ch => !char.IsControl(ch) || ch is ' ' or '\t').ToArray()).Trim();
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }
}
