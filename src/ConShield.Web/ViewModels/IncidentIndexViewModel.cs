using ConShield.Data.Entities;

namespace ConShield.Web.ViewModels;

public class IncidentIndexViewModel
{
    public IncidentFilterViewModel Filter { get; set; } = new();
    public IReadOnlyList<IncidentRecord> Items { get; set; } = [];
}
