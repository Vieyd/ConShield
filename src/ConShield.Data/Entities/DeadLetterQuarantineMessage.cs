namespace ConShield.Data.Entities;

public class DeadLetterQuarantineMessage
{
    public long Id { get; set; }
    public Guid QuarantineId { get; set; }
    public Guid? OriginalMessageId { get; set; }
    public string PayloadSha256 { get; set; } = string.Empty;
    public string SyntheticFingerprint { get; set; } = string.Empty;
    public string? MessageType { get; set; }
    public int? SchemaVersion { get; set; }
    public long? SecurityEventId { get; set; }
    public string OriginalExchange { get; set; } = string.Empty;
    public string OriginalRoutingKey { get; set; } = string.Empty;
    public string DeadLetterExchange { get; set; } = string.Empty;
    public string DeadLetterQueue { get; set; } = string.Empty;
    public string? ContentType { get; set; }
    public DateTime CapturedAtUtc { get; set; }
    public DateTime? FirstDeadLetteredAtUtc { get; set; }
    public DateTime? LastDeadLetteredAtUtc { get; set; }
    public string DeadLetterReason { get; set; } = string.Empty;
    public string ValidationCategory { get; set; } = string.Empty;
    public DeadLetterReplayEligibility ReplayEligibility { get; set; }
    public string? PayloadJson { get; set; }
    public byte[]? PayloadBytes { get; set; }
    public int PayloadLength { get; set; }
    public string? HeaderSummaryJson { get; set; }
    public int CaptureCount { get; set; }
    public string EligibilityExplanation { get; set; } = string.Empty;
    public ICollection<DeadLetterReplayRequest> ReplayRequests { get; set; } = new List<DeadLetterReplayRequest>();
}

public enum DeadLetterReplayEligibility
{
    Eligible = 0,
    RequiresReview = 1,
    NotEligible = 2
}
