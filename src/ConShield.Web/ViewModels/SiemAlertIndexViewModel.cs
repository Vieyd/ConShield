using ConShield.Data.Entities;

namespace ConShield.Web.ViewModels;

public class SiemAlertIndexViewModel
{
    public SiemAlertFilterViewModel Filter { get; set; } = new();
    public IReadOnlyCollection<SiemAlertRecord> Items { get; set; } = Array.Empty<SiemAlertRecord>();
}
