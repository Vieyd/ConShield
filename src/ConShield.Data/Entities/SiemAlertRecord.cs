using ConShield.Contracts.Enums;

namespace ConShield.Data.Entities;

public class SiemAlertRecord
{
    public long Id { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public string RuleCode { get; set; } = string.Empty;
    public string RuleName { get; set; } = string.Empty;
    public string TriggerKey { get; set; } = string.Empty;
    public EventSeverity Severity { get; set; }
    public string Status { get; set; } = "New";
    public string Description { get; set; } = string.Empty;
    public string? SourceEventIdsJson { get; set; }
    public long? IncidentId { get; set; }
}
