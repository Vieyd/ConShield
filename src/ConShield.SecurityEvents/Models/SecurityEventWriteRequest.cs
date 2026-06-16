using ConShield.Contracts.Enums;

namespace ConShield.SecurityEvents.Models;

public class SecurityEventWriteRequest
{
    public SecurityEventType EventType { get; set; }
    public EventSeverity Severity { get; set; } = EventSeverity.Info;
    public string Description { get; set; } = string.Empty;
    public string? UserName { get; set; }
    public string? SourceIp { get; set; }
    public DateTime? OccurredAtUtc { get; set; }
    public Guid? ExternalEventId { get; set; }
    public string? SourceSystem { get; set; }
    public string? ExternalEventType { get; set; }
    public string? SourceHost { get; set; }
    public object? AdditionalData { get; set; }
}
