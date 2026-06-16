using System.ComponentModel.DataAnnotations;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;

namespace ConShield.Web.ViewModels;

public class IncidentEditViewModel
{
    public long Id { get; set; }

    [Required(ErrorMessage = "Укажите название инцидента")]
    [Display(Name = "Название инцидента")]
    public string Name { get; set; } = string.Empty;

    [Display(Name = "Критичность")]
    public EventSeverity Severity { get; set; } = EventSeverity.Warning;

    [Required(ErrorMessage = "Укажите статус")]
    [Display(Name = "Статус")]
    public string Status { get; set; } = IncidentStatuses.New;

    [Display(Name = "Идентификатор исходного события")]
    public long? SourceEventId { get; set; }

    [Display(Name = "Примечание")]
    public string? Notes { get; set; }
}
