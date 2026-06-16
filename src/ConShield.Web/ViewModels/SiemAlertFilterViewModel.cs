using ConShield.Contracts.Enums;

namespace ConShield.Web.ViewModels;

public class SiemAlertFilterViewModel
{
    public string? Status { get; set; }
    public EventSeverity? Severity { get; set; }
    public string? RuleCode { get; set; }
    public string? SearchText { get; set; }
}
