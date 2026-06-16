using ConShield.Contracts.Enums;

namespace ConShield.Data.Entities;

public class SecurityEventEntry
{
    public long Id { get; set; }
    public DateTime OccurredAtUtc { get; set; } = DateTime.UtcNow;
    public SecurityEventType EventType { get; set; }
    public EventSeverity Severity { get; set; }
    public string? UserName { get; set; }
    public string? SourceIp { get; set; }
    public string Description { get; set; } = string.Empty;
    public string? AdditionalDataJson { get; set; }
}
