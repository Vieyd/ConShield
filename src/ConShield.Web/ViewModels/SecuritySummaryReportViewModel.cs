using ConShield.Contracts.Enums;

namespace ConShield.Web.ViewModels;

public sealed class SecuritySummaryReportViewModel
{
    public DateTime GeneratedAtUtc { get; init; }
    public string RangeKey { get; init; } = "24h";
    public string RangeLabel { get; init; } = "24 hours";
    public DateTime RangeStartUtc { get; init; }
    public DateTime RangeEndUtc { get; init; }
    public string OverallStatus { get; init; } = SecuritySummaryStatus.NoData;
    public SecuritySummarySensorSection Sensors { get; init; } = new();
    public SecuritySummaryEventSection SecurityEvents { get; init; } = new();
    public SecuritySummarySiemSection Siem { get; init; } = new();
    public SecuritySummaryPipelineSection Pipeline { get; init; } = new();
    public IReadOnlyList<string> OperatorChecklist { get; init; } = [];
    public string Markdown { get; init; } = string.Empty;
}

public sealed class SecuritySummarySensorSection
{
    public int Total { get; init; }
    public int Active { get; init; }
    public int Revoked { get; init; }
    public int Online { get; init; }
    public int Warning { get; init; }
    public int Offline { get; init; }
    public int NeverSeen { get; init; }
    public DateTime? LatestHeartbeatAtUtc { get; init; }
}

public sealed class SecuritySummaryEventSection
{
    public int EventsInRange { get; init; }
    public DateTime? LatestEventAtUtc { get; init; }
    public IReadOnlyDictionary<EventSeverity, int> SeverityCounts { get; init; } =
        new Dictionary<EventSeverity, int>();
    public int LifecycleAuditEvents { get; init; }
}

public sealed class SecuritySummarySiemSection
{
    public int ActiveAlerts { get; init; }
    public int LifecycleAlertsInRange { get; init; }
    public int Life001AlertsInRange { get; init; }
    public int Life002AlertsInRange { get; init; }
    public int IncidentsInRange { get; init; }
}

public sealed class SecuritySummaryPipelineSection
{
    public int OutboxPending { get; init; }
    public int OutboxProcessing { get; init; }
    public int OutboxDeadLetter { get; init; }
    public int InboxTotal { get; init; }
    public int InboxInRange { get; init; }
    public int InboxRedelivered { get; init; }
    public int InboxDeliveryCountOverOne { get; init; }
    public DateTime? LatestInboxReceivedAtUtc { get; init; }
    public DateTime? LatestInboxProcessedAtUtc { get; init; }
}

public static class SecuritySummaryStatus
{
    public const string Ok = "OK";
    public const string NeedsAttention = "Needs attention";
    public const string NoData = "No data";

    public static string CssClass(string status) => status switch
    {
        Ok => "bg-success",
        NeedsAttention => "bg-danger",
        _ => "bg-secondary"
    };
}
