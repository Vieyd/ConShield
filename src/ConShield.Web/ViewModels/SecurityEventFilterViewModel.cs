using ConShield.Contracts.Enums;

namespace ConShield.Web.ViewModels;

public class SecurityEventFilterViewModel
{
    public string? UserName { get; set; }
    public EventSeverity? Severity { get; set; }
    public SecurityEventType? EventType { get; set; }
    public string? SearchText { get; set; }
}
