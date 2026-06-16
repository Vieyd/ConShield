namespace ConShield.Application.Models;

public class CorrelationRunResult
{
    public int CreatedAlerts { get; set; }
    public int CreatedIncidents { get; set; }
    public List<string> TriggeredRules { get; set; } = new();
}
