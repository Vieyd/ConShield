using ConShield.Contracts.Enums;

namespace ConShield.Data.Entities;

public class IncidentRecord
{
    public long Id { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public string Name { get; set; } = string.Empty;
    public EventSeverity Severity { get; set; }
    public string Status { get; set; } = "New";
    public long? SourceEventId { get; set; }
    public string? Notes { get; set; }
}
