namespace ConShield.Data.Entities;

public class DeadLetterReplayRequest
{
    public long Id { get; set; }
    public Guid ReplayRequestId { get; set; }
    public long QuarantineMessageId { get; set; }
    public DeadLetterQuarantineMessage? QuarantineMessage { get; set; }
    public string RequestedBy { get; set; } = string.Empty;
    public DateTime RequestedAtUtc { get; set; }
    public string Reason { get; set; } = string.Empty;
    public DeadLetterReplayRequestStatus Status { get; set; }
    public int AttemptCount { get; set; }
    public DateTime AvailableAtUtc { get; set; }
    public DateTime? LockedUntilUtc { get; set; }
    public Guid? LockToken { get; set; }
    public DateTime? PublishedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public string? LastErrorCode { get; set; }
    public string? LastErrorSummary { get; set; }
    public int ReplaySequence { get; set; }
}

public enum DeadLetterReplayRequestStatus
{
    Pending = 0,
    Processing = 1,
    Published = 2,
    Rejected = 3,
    Failed = 4
}
