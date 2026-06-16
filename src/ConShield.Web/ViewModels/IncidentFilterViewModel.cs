using ConShield.Contracts.Enums;

namespace ConShield.Web.ViewModels;

public class IncidentFilterViewModel
{
    public string? Status { get; set; }
    public EventSeverity? Severity { get; set; }
    public string? SearchText { get; set; }
}
