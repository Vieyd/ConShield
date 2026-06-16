using ConShield.Data.Entities;

namespace ConShield.Web.ViewModels;

public sealed class HomeDashboardViewModel
{
    public int UserExceptionsCount { get; set; }
    public int ActiveExceptionsCount { get; set; }
    public int SecurityEventsCount { get; set; }
    public int CriticalEventsCount { get; set; }
    public int IncidentsCount { get; set; }
    public int NewIncidentsCount { get; set; }
    public int InProgressIncidentsCount { get; set; }
    public int ClosedIncidentsCount { get; set; }
    public int SiemAlertsCount { get; set; }
    public int NewSiemAlertsCount { get; set; }
    public IReadOnlyCollection<SiemAlertRecord> RecentAlerts { get; set; } = Array.Empty<SiemAlertRecord>();
    public IReadOnlyCollection<IncidentRecord> RecentIncidents { get; set; } = Array.Empty<IncidentRecord>();
    public IReadOnlyCollection<SecurityEventEntry> RecentCriticalEvents { get; set; } = Array.Empty<SecurityEventEntry>();
}
