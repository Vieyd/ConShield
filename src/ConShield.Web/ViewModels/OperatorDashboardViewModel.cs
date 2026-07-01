using ConShield.Contracts.Enums;

namespace ConShield.Web.ViewModels;

public sealed class OperatorDashboardViewModel
{
    public string PostureStatus { get; init; } = "Demo data missing";
    public string PostureSummary { get; init; } = "Not available in local demo data";
    public IReadOnlyList<OperatorDashboardStatusCardViewModel> StatusCards { get; init; } =
        Array.Empty<OperatorDashboardStatusCardViewModel>();
    public IReadOnlyList<OperatorDashboardAlertViewModel> LatestAlerts { get; init; } =
        Array.Empty<OperatorDashboardAlertViewModel>();
    public IReadOnlyList<OperatorDashboardIncidentViewModel> LatestIncidents { get; init; } =
        Array.Empty<OperatorDashboardIncidentViewModel>();
    public OperatorDashboardSensorSummaryViewModel SensorSummary { get; init; } = new();
    public IReadOnlyList<OperatorDashboardWorkflowTileViewModel> WorkflowTiles { get; init; } =
        Array.Empty<OperatorDashboardWorkflowTileViewModel>();
    public IReadOnlyList<OperatorDashboardDocLinkViewModel> DocumentationLinks { get; init; } =
        Array.Empty<OperatorDashboardDocLinkViewModel>();
}

public sealed record OperatorDashboardStatusCardViewModel(
    string Label,
    string Value,
    string Status,
    string Description,
    string? Controller = null,
    string? Action = null,
    string? RouteValue = null);

public sealed record OperatorDashboardAlertViewModel(
    long Id,
    DateTime CreatedAtUtc,
    string RuleCode,
    string RuleName,
    EventSeverity Severity,
    string Status,
    long? IncidentId);

public sealed record OperatorDashboardIncidentViewModel(
    long Id,
    DateTime CreatedAtUtc,
    string Name,
    EventSeverity Severity,
    string Status,
    long? SourceEventId);

public sealed class OperatorDashboardSensorSummaryViewModel
{
    public int TrustedSensors { get; init; }
    public int UnknownSensors { get; init; }
    public int RevokedOrDisabledSensors { get; init; }
    public int ValidSignatures { get; init; }
    public int MissingSignatures { get; init; }
    public int InvalidOrUnknownKeySignatures { get; init; }
    public int StaleOrReplaySignatures { get; init; }
    public int SignatureFailures { get; init; }
    public int RuntimeSources { get; init; }
    public DateTime? LatestRuntimeEventUtc { get; init; }
}

public sealed record OperatorDashboardWorkflowTileViewModel(
    string Name,
    string Purpose,
    string Command,
    string DocPath,
    string? Controller = null,
    string? Action = null);

public sealed record OperatorDashboardDocLinkViewModel(string Label, string Path);
