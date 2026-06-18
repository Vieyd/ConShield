using ConShield.Data.Entities;

namespace ConShield.Web.ViewModels;

public sealed class DeadLetterIndexViewModel
{
    public IReadOnlyList<DeadLetterListItemViewModel> Items { get; init; } = Array.Empty<DeadLetterListItemViewModel>();
    public string? Eligibility { get; init; }
    public string? Reason { get; init; }
    public string? ReplayStatus { get; init; }
    public DateTime? CapturedFromUtc { get; init; }
    public DateTime? CapturedToUtc { get; init; }
    public int Page { get; init; }
    public int TotalPages { get; init; }
}

public sealed class DeadLetterListItemViewModel
{
    public Guid QuarantineId { get; init; }
    public Guid? OriginalMessageId { get; init; }
    public string PayloadSha256 { get; init; } = string.Empty;
    public string? MessageType { get; init; }
    public string DeadLetterReason { get; init; } = string.Empty;
    public DeadLetterReplayEligibility ReplayEligibility { get; init; }
    public DateTime CapturedAtUtc { get; init; }
    public int CaptureCount { get; init; }
    public string? LatestReplayStatus { get; init; }
}

public sealed class DeadLetterDetailsViewModel
{
    public Guid QuarantineId { get; init; }
    public Guid? OriginalMessageId { get; init; }
    public string PayloadSha256 { get; init; } = string.Empty;
    public string? MessageType { get; init; }
    public int? SchemaVersion { get; init; }
    public long? SecurityEventId { get; init; }
    public string OriginalExchange { get; init; } = string.Empty;
    public string OriginalRoutingKey { get; init; } = string.Empty;
    public string DeadLetterExchange { get; init; } = string.Empty;
    public string DeadLetterQueue { get; init; } = string.Empty;
    public string? ContentType { get; init; }
    public DateTime CapturedAtUtc { get; init; }
    public DateTime? FirstDeadLetteredAtUtc { get; init; }
    public DateTime? LastDeadLetteredAtUtc { get; init; }
    public string DeadLetterReason { get; init; } = string.Empty;
    public string ValidationCategory { get; init; } = string.Empty;
    public DeadLetterReplayEligibility ReplayEligibility { get; init; }
    public int PayloadLength { get; init; }
    public string? HeaderSummaryJson { get; init; }
    public int CaptureCount { get; init; }
    public string EligibilityExplanation { get; init; } = string.Empty;
    public IReadOnlyList<DeadLetterReplayHistoryViewModel> ReplayHistory { get; init; } = Array.Empty<DeadLetterReplayHistoryViewModel>();
}

public sealed class DeadLetterReplayHistoryViewModel
{
    public Guid ReplayRequestId { get; init; }
    public string RequestedBy { get; init; } = string.Empty;
    public DateTime RequestedAtUtc { get; init; }
    public string Reason { get; init; } = string.Empty;
    public DeadLetterReplayRequestStatus Status { get; init; }
    public int AttemptCount { get; init; }
    public DateTime? PublishedAtUtc { get; init; }
    public DateTime? CompletedAtUtc { get; init; }
    public string? LastErrorCode { get; init; }
    public string? LastErrorSummary { get; init; }
    public int ReplaySequence { get; init; }
}
