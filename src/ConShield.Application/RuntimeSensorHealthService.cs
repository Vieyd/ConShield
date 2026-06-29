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
                x.Severity,
                x.AdditionalDataJson))
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

        var sensorTrustAlerts = await _dbContext.SiemAlerts
            .Where(x => x.RuleCode == "SENSOR-001" || x.RuleCode == "SENSOR-002")
            .Select(x => new RuntimeAlertProjection(x.Id, x.SourceEventIdsJson, x.IncidentId))
            .ToListAsync(cancellationToken);

        var signatureAlerts = await _dbContext.SiemAlerts
            .Where(x => x.RuleCode == "SIGN-001" || x.RuleCode == "SIGN-002" || x.RuleCode == "SIGN-003")
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
            var relatedSensorTrustAlertIds = new HashSet<long>();
            var relatedSignatureAlertIds = new HashSet<long>();
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

            foreach (var alert in sensorTrustAlerts)
            {
                var alertEventIds = ReadSourceEventIds(alert.SourceEventIdsJson);
                if (!alertEventIds.Overlaps(sourceEventIds))
                    continue;

                relatedSensorTrustAlertIds.Add(alert.Id);
                if (alert.IncidentId.HasValue)
                    relatedIncidentIds.Add(alert.IncidentId.Value);
            }

            foreach (var alert in signatureAlerts)
            {
                var alertEventIds = ReadSourceEventIds(alert.SourceEventIdsJson);
                if (!alertEventIds.Overlaps(sourceEventIds))
                    continue;

                relatedSignatureAlertIds.Add(alert.Id);
                if (alert.IncidentId.HasValue)
                    relatedIncidentIds.Add(alert.IncidentId.Value);
            }

            foreach (var incident in incidents)
            {
                if (sourceEventIds.Contains(incident.SourceEventId))
                    relatedIncidentIds.Add(incident.Id);
            }

            var latestSignature = eventsForSource
                .Select(ReadSignatureData)
                .FirstOrDefault(x => x is not null);

            rows.Add(new RuntimeSensorHealthRow(
                registrySensor?.SensorId ?? "-",
                sourceSystem,
                registrySensor?.DisplayName ?? DisplayName(sourceSystem),
                registrySensor?.Environment ?? "-",
                registrySensor?.Status ?? SensorTrustStatuses.Unknown,
                SensorTrustEnforcement.ActionFor(registrySensor?.Status ?? SensorTrustStatuses.Unknown),
                registrySensor?.ExpectedEventTypes ?? Array.Empty<string>(),
                latest?.OccurredAtUtc,
                eventsForSource.Count,
                latest?.Id,
                latest?.ExternalEventType,
                latest?.Severity,
                relatedAlertIds.Count,
                relatedSensorTrustAlertIds.Count,
                relatedSignatureAlertIds.Count,
                latestSignature?.Status ?? "NotRequired",
                latestSignature?.KeyId,
                latestSignature?.TimestampUtc,
                latestSignature is not null && latestSignature.Status is not "Valid" and not "NotRequired"
                    ? latestSignature.Reason
                    : null,
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

    private static SignatureProjection? ReadSignatureData(RuntimeEventProjection runtimeEvent)
    {
        if (string.IsNullOrWhiteSpace(runtimeEvent.AdditionalDataJson))
            return null;

        try
        {
            using var document = JsonDocument.Parse(runtimeEvent.AdditionalDataJson);
            if (!document.RootElement.TryGetProperty("signature", out var signature) || signature.ValueKind != JsonValueKind.Object)
                return null;

            var status = ReadString(signature, "signatureStatus", 32);
            if (string.IsNullOrWhiteSpace(status))
                return null;

            return new SignatureProjection(
                status,
                ReadString(signature, "signatureKeyId", 128),
                ReadDateTime(signature, "eventTimestampUtc"),
                ReadString(signature, "signatureVerificationReason", 160));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? ReadString(JsonElement element, string propertyName, int maxLength)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
            return null;

        var value = property.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var safe = new string(value.Where(ch => !char.IsControl(ch)).ToArray());
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }

    private static DateTime? ReadDateTime(JsonElement element, string propertyName)
    {
        var value = ReadString(element, propertyName, 64);
        return DateTime.TryParse(value, out var parsed)
            ? DateTime.SpecifyKind(parsed.ToUniversalTime(), DateTimeKind.Utc)
            : null;
    }

    private sealed record RuntimeEventProjection(
        long Id,
        DateTime OccurredAtUtc,
        string SourceSystem,
        string? ExternalEventType,
        EventSeverity Severity,
        string? AdditionalDataJson);

    private sealed record RuntimeAlertProjection(long Id, string? SourceEventIdsJson, long? IncidentId);
    private sealed record RuntimeIncidentProjection(long Id, long SourceEventId);
    private sealed record SignatureProjection(string Status, string? KeyId, DateTime? TimestampUtc, string? Reason);
}
