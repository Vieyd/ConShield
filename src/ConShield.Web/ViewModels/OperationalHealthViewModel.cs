namespace ConShield.Web.ViewModels;

public sealed class OperationalHealthViewModel
{
    public DateTime GeneratedAtUtc { get; init; }
    public SensorHealthSummary Sensors { get; init; } = new();
    public SecurityEventHealthSummary SecurityEvents { get; init; } = new();
    public OutboxHealthSummary Outbox { get; init; } = new();
    public InboxHealthSummary Inbox { get; init; } = new();
}

public sealed class SensorHealthSummary
{
    public int Total { get; init; }
    public int Active { get; init; }
    public int Revoked { get; init; }
    public int NeverSeen { get; init; }
    public int Online { get; init; }
    public int Warning { get; init; }
    public int Offline { get; init; }
    public DateTime? LatestHeartbeatAtUtc { get; init; }
    public string StatusLabel { get; init; } = "No data";
}

public sealed class SecurityEventHealthSummary
{
    public int Total { get; init; }
    public int LastHour { get; init; }
    public int Last24Hours { get; init; }
    public DateTime? LatestEventAtUtc { get; init; }
    public int LifecycleLast24Hours { get; init; }
    public string StatusLabel { get; init; } = "No data";
}

public sealed class OutboxHealthSummary
{
    public int Total { get; init; }
    public int Pending { get; init; }
    public int Processing { get; init; }
    public int NotDispatched { get; init; }
    public int Delivered { get; init; }
    public int DeadLetter { get; init; }
    public DateTime? OldestPendingAtUtc { get; init; }
    public DateTime? LatestCreatedAtUtc { get; init; }
    public string StatusLabel { get; init; } = "No data";
}

public sealed class InboxHealthSummary
{
    public int Total { get; init; }
    public int Last24Hours { get; init; }
    public DateTime? LatestReceivedAtUtc { get; init; }
    public DateTime? LatestProcessedAtUtc { get; init; }
    public int Redelivered { get; init; }
    public int DeliveryCountOverOne { get; init; }
    public string StatusLabel { get; init; } = "No data";
}

public static class OperationalHealthStatus
{
    public const string Ok = "OK";
    public const string Warning = "Warning";
    public const string Attention = "Attention";
    public const string NoData = "No data";

    public static string CssClass(string statusLabel) => statusLabel switch
    {
        Ok => "bg-success",
        Warning => "bg-warning text-dark",
        Attention => "bg-danger",
        _ => "bg-secondary"
    };
}
