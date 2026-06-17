namespace ConShield.Data.Entities;

public class SecurityEventInboxReceipt
{
    public long Id { get; set; }
    public Guid MessageId { get; set; }
    public long SecurityEventId { get; set; }
    public string MessageType { get; set; } = string.Empty;
    public int SchemaVersion { get; set; } = 1;
    public string PayloadSha256 { get; set; } = string.Empty;
    public string RoutingKey { get; set; } = string.Empty;
    public DateTime ReceivedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ProcessedAtUtc { get; set; }
    public bool Redelivered { get; set; }
    public int DeliveryCount { get; set; }
}
