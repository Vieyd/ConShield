namespace ConShield.Data.Entities;

public class SecurityEventOutboxMessage
{
    public long Id { get; set; }
    public Guid MessageId { get; set; }
    public long SecurityEventId { get; set; }
    public SecurityEventEntry? SecurityEvent { get; set; }
    public string MessageType { get; set; } = string.Empty;
    public int SchemaVersion { get; set; } = 1;
    public string PayloadJson { get; set; } = string.Empty;
    public SecurityEventOutboxStatus Status { get; set; } = SecurityEventOutboxStatus.Pending;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime AvailableAtUtc { get; set; } = DateTime.UtcNow;
    public int AttemptCount { get; set; }
    public DateTime? LastAttemptAtUtc { get; set; }
    public DateTime? LockedUntilUtc { get; set; }
    public Guid? LockToken { get; set; }
    public DateTime? DeliveredAtUtc { get; set; }
    public string? LastErrorCode { get; set; }
    public string? LastErrorSummary { get; set; }
}

public enum SecurityEventOutboxStatus
{
    Pending,
    Processing,
    Delivered,
    DeadLetter
}
