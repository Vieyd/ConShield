using ConShield.Data.Entities;

namespace ConShield.Web.ViewModels;

public sealed class SiemAlertDetailsViewModel
{
    public SiemAlertRecord Alert { get; set; } = new();
    public IncidentRecord? Incident { get; set; }
    public IReadOnlyCollection<SecurityEventEntry> SourceEvents { get; set; } = Array.Empty<SecurityEventEntry>();
    public IReadOnlyCollection<long> SourceEventIds { get; set; } = Array.Empty<long>();
}
