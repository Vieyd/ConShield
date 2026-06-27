using ConShield.Contracts.Enums;

namespace ConShield.Application.Models;

public static class RuntimeSensorHealthStatuses
{
    public const string Active = "Active";
    public const string Stale = "Stale";
    public const string NoData = "NoData";
}

public sealed record RuntimeSensorHealthOptions(DateTime NowUtc, TimeSpan ActiveWindow)
{
    public static RuntimeSensorHealthOptions Default(DateTime? nowUtc = null) =>
        new(DateTime.SpecifyKind(nowUtc ?? DateTime.UtcNow, DateTimeKind.Utc), TimeSpan.FromHours(24));
}

public sealed record RuntimeSensorHealthRow(
    string SourceSystem,
    string DisplayName,
    DateTime? LastSeenUtc,
    int EventCount,
    long? LatestEventId,
    string? LatestEventType,
    EventSeverity? LatestSeverity,
    int RelatedRteAlertCount,
    int RelatedIncidentCount,
    string Status);

public sealed record RuntimeSensorHealthSummary(
    int RuntimeSourcesCount,
    int ActiveSourcesCount,
    int StaleOrNoDataSourcesCount,
    DateTime? LatestRuntimeEventUtc);

public sealed record RuntimeSensorHealthResult(
    RuntimeSensorHealthSummary Summary,
    IReadOnlyList<RuntimeSensorHealthRow> Sources);
