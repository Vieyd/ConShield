using System.Text.Json;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Application;

public sealed class RuntimeSensorHealthService : IRuntimeSensorHealthService
{
    private const string ContainerRuntimeSourceSystem = "conshield.container-runtime";
    private static readonly string[] SuggestedSourceSystems =
    [
        SecuritySourceSystems.FalcoLinuxSensor,
        SecuritySourceSystems.FalcoRuntimeCollector,
        ContainerRuntimeSourceSystem
    ];

    private readonly ApplicationDbContext _dbContext;
    private readonly SensorTrustRegistry _sensorTrustRegistry;

    public RuntimeSensorHealthService(ApplicationDbContext dbContext)
        : this(dbContext, LoadRegistrySafely())
    {
    }

    public RuntimeSensorHealthService(ApplicationDbContext dbContext, SensorTrustRegistry sensorTrustRegistry)
    {
        _dbContext = dbContext;
        _sensorTrustRegistry = sensorTrustRegistry;
    }

    public async Task<RuntimeSensorHealthResult> GetAsync(
        RuntimeSensorHealthOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var healthOptions = options ?? RuntimeSensorHealthOptions.Default();
        var activeThresholdUtc = healthOptions.NowUtc.Subtract(healthOptions.ActiveWindow);

        var runtimeEvents = await _dbContext.SecurityEvents
            .Where(x => x.SourceSystem != null && SuggestedSourceSystems.Contains(x.SourceSystem)
                || (x.SourceSystem != null && (x.SourceSystem.ToLower().Contains("runtime") || x.SourceSystem.ToLower().Contains("falco")))
                || (x.ExternalEventType != null && (x.ExternalEventType.ToLower().Contains("runtime") || x.ExternalEventType.ToLower().Contains("falco"))))
            .Select(x => new RuntimeEventProjection(
                x.Id,
                x.OccurredAtUtc,
                x.SourceSystem ?? "unknown-runtime-source",
                x.ExternalEventType,
                x.Severity))
            .ToListAsync(cancellationToken);

        var eventIdsBySource = runtimeEvents
            .GroupBy(x => x.SourceSystem, StringComparer.Ordinal)
            .ToDictionary(
                x => x.Key,
                x => x.Select(e => e.Id).ToHashSet(),
                StringComparer.Ordinal);

        var sourceSystems = SuggestedSourceSystems
            .Concat(_sensorTrustRegistry.Sensors.Select(x => x.SourceSystem))
            .Concat(runtimeEvents.Select(x => x.SourceSystem))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        var rteAlerts = await _dbContext.SiemAlerts
            .Where(x => x.RuleCode == "RTE-001")
            .Select(x => new RuntimeAlertProjection(x.Id, x.SourceEventIdsJson, x.IncidentId))
            .ToListAsync(cancellationToken);

        var incidents = await _dbContext.Incidents
            .Where(x => x.SourceEventId.HasValue)
            .Select(x => new RuntimeIncidentProjection(x.Id, x.SourceEventId!.Value))
            .ToListAsync(cancellationToken);

        var rows = new List<RuntimeSensorHealthRow>();
        foreach (var sourceSystem in sourceSystems)
        {
            var registrySensor = _sensorTrustRegistry.FindBySourceSystem(sourceSystem);
            var eventsForSource = runtimeEvents
                .Where(x => string.Equals(x.SourceSystem, sourceSystem, StringComparison.Ordinal))
                .OrderByDescending(x => x.OccurredAtUtc)
                .ThenByDescending(x => x.Id)
                .ToList();

            var latest = eventsForSource.FirstOrDefault();
            eventIdsBySource.TryGetValue(sourceSystem, out var sourceEventIds);
            sourceEventIds ??= new HashSet<long>();

            var relatedAlertIds = new HashSet<long>();
            var relatedIncidentIds = new HashSet<long>();
            foreach (var alert in rteAlerts)
            {
                var alertEventIds = ReadSourceEventIds(alert.SourceEventIdsJson);
                if (!alertEventIds.Overlaps(sourceEventIds))
                    continue;

                relatedAlertIds.Add(alert.Id);
                if (alert.IncidentId.HasValue)
                    relatedIncidentIds.Add(alert.IncidentId.Value);
            }

            foreach (var incident in incidents)
            {
                if (sourceEventIds.Contains(incident.SourceEventId))
                    relatedIncidentIds.Add(incident.Id);
            }

            rows.Add(new RuntimeSensorHealthRow(
                registrySensor?.SensorId ?? "-",
                sourceSystem,
                registrySensor?.DisplayName ?? DisplayName(sourceSystem),
                registrySensor?.Environment ?? "-",
                registrySensor?.Status ?? SensorTrustStatuses.Unknown,
                registrySensor?.ExpectedEventTypes ?? Array.Empty<string>(),
                latest?.OccurredAtUtc,
                eventsForSource.Count,
                latest?.Id,
                latest?.ExternalEventType,
                latest?.Severity,
                relatedAlertIds.Count,
                relatedIncidentIds.Count,
                Status(latest?.OccurredAtUtc, activeThresholdUtc)));
        }

        var summary = new RuntimeSensorHealthSummary(
            RuntimeSourcesCount: rows.Count,
            ActiveSourcesCount: rows.Count(x => x.Status == RuntimeSensorHealthStatuses.Active),
            StaleOrNoDataSourcesCount: rows.Count(x => x.Status is RuntimeSensorHealthStatuses.Stale or RuntimeSensorHealthStatuses.NoData),
            LatestRuntimeEventUtc: rows.Max(x => x.LastSeenUtc));

        return new RuntimeSensorHealthResult(summary, rows);
    }

    private static string Status(DateTime? lastSeenUtc, DateTime activeThresholdUtc)
    {
        if (!lastSeenUtc.HasValue)
            return RuntimeSensorHealthStatuses.NoData;

        return lastSeenUtc.Value >= activeThresholdUtc
            ? RuntimeSensorHealthStatuses.Active
            : RuntimeSensorHealthStatuses.Stale;
    }

    private static string DisplayName(string sourceSystem) => sourceSystem switch
    {
        SecuritySourceSystems.FalcoLinuxSensor => "Falco Linux replay sensor",
        SecuritySourceSystems.FalcoRuntimeCollector => "Falco enrolled runtime collector",
        ContainerRuntimeSourceSystem => "Container runtime launch monitor",
        _ => sourceSystem
    };

    private static SensorTrustRegistry LoadRegistrySafely()
    {
        try
        {
            return SensorTrustRegistryLoader.LoadDefault();
        }
        catch
        {
            return SensorTrustRegistry.Empty;
        }
    }

    private static HashSet<long> ReadSourceEventIds(string? sourceEventIdsJson)
    {
        var ids = new HashSet<long>();
        if (string.IsNullOrWhiteSpace(sourceEventIdsJson))
            return ids;

        try
        {
            using var document = JsonDocument.Parse(sourceEventIdsJson);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                return ids;

            foreach (var item in document.RootElement.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Number && item.TryGetInt64(out var id) && id > 0)
                    ids.Add(id);
            }
        }
        catch (JsonException)
        {
            return ids;
        }

        return ids;
    }

    private sealed record RuntimeEventProjection(
        long Id,
        DateTime OccurredAtUtc,
        string SourceSystem,
        string? ExternalEventType,
        EventSeverity Severity);

    private sealed record RuntimeAlertProjection(long Id, string? SourceEventIdsJson, long? IncidentId);
    private sealed record RuntimeIncidentProjection(long Id, long SourceEventId);
}
