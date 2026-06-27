using System.Text.Json;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace ConShield.Application;

public class SiemCorrelationService : ISiemCorrelationService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ISecurityEventWriter _eventWriter;

    public SiemCorrelationService(ApplicationDbContext dbContext, ISecurityEventWriter eventWriter)
    {
        _dbContext = dbContext;
        _eventWriter = eventWriter;
    }

    public async Task<CorrelationRunResult> RunAsync(CancellationToken cancellationToken = default)
    {
        var result = new CorrelationRunResult();
        var now = DateTime.UtcNow;

        var recentLoginFailures = await _dbContext.SecurityEvents
            .Where(x => x.EventType == SecurityEventType.LoginFailure && x.OccurredAtUtc >= now.AddMinutes(-2))
            .ToListAsync(cancellationToken);

        var created1 = await ProcessRuleAsync(
            ruleCode: "BF-001",
            ruleName: "Повторные неуспешные попытки входа",
            severity: EventSeverity.High,
            descriptionFactory: group => $"Зафиксировано {group.Count} неуспешных попыток входа для учетной записи {group.Key} за последние 2 минуты.",
            eventIdsFactory: group => group.EventIds,
            groups: recentLoginFailures
                .GroupBy(x => string.IsNullOrWhiteSpace(x.UserName) ? "unknown-user" : x.UserName!)
                .Select(g => new RuleCandidate
                {
                    Key = g.Key,
                    Count = g.Count(),
                    EventIds = g.OrderBy(x => x.Id).Select(x => x.Id).ToList()
                })
                .Where(x => x.Count >= 3)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created1);

        var recentUserExceptionChanges = await _dbContext.SecurityEvents
            .Where(x => (x.EventType == SecurityEventType.UserExceptionUpdated || x.EventType == SecurityEventType.UserExceptionDeleted)
                        && x.OccurredAtUtc >= now.AddSeconds(-30))
            .ToListAsync(cancellationToken);

        var created2 = await ProcessRuleAsync(
            ruleCode: "UE-001",
            ruleName: "Массовые изменения записей UserExceptions",
            severity: EventSeverity.Critical,
            descriptionFactory: group => $"Пользователь {group.Key} выполнил {group.Count} операций изменения или удаления UserExceptions за последние 30 секунд.",
            eventIdsFactory: group => group.EventIds,
            groups: recentUserExceptionChanges
                .GroupBy(x => string.IsNullOrWhiteSpace(x.UserName) ? "unknown-user" : x.UserName!)
                .Select(g => new RuleCandidate
                {
                    Key = g.Key,
                    Count = g.Count(),
                    EventIds = g.OrderBy(x => x.Id).Select(x => x.Id).ToList()
                })
                .Where(x => x.Count >= 5)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created2);

        var recentCriticalEvents = await _dbContext.SecurityEvents
            .Where(x => x.Severity == EventSeverity.Critical
                        && x.OccurredAtUtc >= now.AddMinutes(-5)
                        && x.SourceIp != null
                        && x.SourceIp.Trim() != string.Empty
                        && x.EventType != SecurityEventType.CorrelationAlert
                        && x.EventType != SecurityEventType.IncidentCreated
                        && x.EventType != SecurityEventType.IncidentUpdated)
            .ToListAsync(cancellationToken);

        var created3 = await ProcessRuleAsync(
            ruleCode: "CR-001",
            ruleName: "Повторные критические события с одного источника",
            severity: EventSeverity.Critical,
            descriptionFactory: group => $"С источника {group.Key} зарегистрировано {group.Count} критических события за последние 5 минут.",
            eventIdsFactory: group => group.EventIds,
            groups: recentCriticalEvents
                .GroupBy(x => x.SourceIp!.Trim())
                .Select(g => new RuleCandidate
                {
                    Key = g.Key,
                    Count = g.Count(),
                    EventIds = g.OrderBy(x => x.Id).Select(x => x.Id).ToList()
                })
                .Where(x => x.Count >= 2)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created3);

        var recentImageScanEvents = await _dbContext.SecurityEvents
            .Where(x => x.EventType == SecurityEventType.ExternalEvent
                        && x.ExternalEventType == "container.image.scan.completed"
                        && x.Severity == EventSeverity.Critical
                        && x.OccurredAtUtc >= now.AddHours(-24))
            .ToListAsync(cancellationToken);

        var created4 = await ProcessRuleAsync(
            ruleCode: "IMG-001",
            ruleName: "Критические уязвимости в контейнерном образе",
            severity: EventSeverity.Critical,
            descriptionFactory: group => group.Description,
            eventIdsFactory: group => group.EventIds,
            groups: recentImageScanEvents
                .Select(TryCreateImageScanCandidate)
                .Where(x => x is not null)
                .Select(x => x!)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created4);

        var recentPolicyEvents = await _dbContext.SecurityEvents
            .Where(x => x.EventType == SecurityEventType.ExternalEvent
                        && x.ExternalEventType == "container.image.policy.evaluated"
                        && x.OccurredAtUtc >= now.AddHours(-24))
            .ToListAsync(cancellationToken);

        var created5 = await ProcessRuleAsync(
            ruleCode: "POL-001",
            ruleName: "Блокировка контейнерного образа политикой",
            severity: EventSeverity.Critical,
            descriptionFactory: group => group.Description,
            eventIdsFactory: group => group.EventIds,
            groups: recentPolicyEvents
                .Select(TryCreatePolicyGateCandidate)
                .Where(x => x is not null)
                .Select(x => x!)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created5);

        var recentRuntimeEvents = await _dbContext.SecurityEvents
            .Where(x => x.EventType == SecurityEventType.ExternalEvent
                        && (x.SourceSystem == SecuritySourceSystems.FalcoRuntimeCollector
                            || x.SourceSystem == SecuritySourceSystems.FalcoLinuxSensor)
                        && (x.Severity == EventSeverity.High || x.Severity == EventSeverity.Critical)
                        && x.OccurredAtUtc >= now.AddMinutes(-10))
            .ToListAsync(cancellationToken);

        var created6 = await ProcessRuleAsync(
            ruleCode: "RTE-001",
            ruleName: "Container runtime threat detected",
            severity: EventSeverity.High,
            descriptionFactory: group => group.Description,
            eventIdsFactory: group => group.EventIds,
            groups: recentRuntimeEvents
                .Select(TryCreateRuntimeCandidate)
                .Where(x => x is not null)
                .Select(x => x!)
                .GroupBy(x => x.Key, StringComparer.Ordinal)
                .Select(group =>
                {
                    var candidates = group.ToList();
                    var mostSevere = candidates.MaxBy(x => x.Severity) ?? candidates[0];
                    return new RuleCandidate
                    {
                        Key = group.Key,
                        Count = candidates.Count,
                        Description = mostSevere.Description,
                        EventIds = candidates.SelectMany(x => x.EventIds).Distinct().Order().ToList(),
                        Severity = candidates.Max(x => x.Severity)
                    };
                })
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created6);

        var recentSensorRevocations = await _dbContext.SecurityEvents
            .Where(x => x.EventType == SecurityEventType.ExternalEvent
                        && x.SourceSystem == SecuritySourceSystems.SensorLifecycle
                        && x.ExternalEventType == SensorLifecycleEventTypes.SensorRevoked
                        && x.OccurredAtUtc >= now.AddHours(-24))
            .ToListAsync(cancellationToken);

        var created7 = await ProcessRuleAsync(
            ruleCode: "LIFE-001",
            ruleName: "Sensor identity revoked",
            severity: EventSeverity.Warning,
            descriptionFactory: group => group.Description,
            eventIdsFactory: group => group.EventIds,
            groups: recentSensorRevocations
                .Select(TryCreateSensorRevokedCandidate)
                .Where(x => x is not null)
                .Select(x => x!)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created7);

        var recentCredentialLifecycleEvents = await _dbContext.SecurityEvents
            .Where(x => x.EventType == SecurityEventType.ExternalEvent
                        && x.SourceSystem == SecuritySourceSystems.SensorLifecycle
                        && (x.ExternalEventType == SensorLifecycleEventTypes.SensorCredentialRotated
                            || x.ExternalEventType == SensorLifecycleEventTypes.SensorCredentialRevoked)
                        && x.OccurredAtUtc >= now.AddMinutes(-15))
            .ToListAsync(cancellationToken);

        var created8 = await ProcessRuleAsync(
            ruleCode: "LIFE-002",
            ruleName: "Repeated sensor credential lifecycle changes",
            severity: EventSeverity.Warning,
            descriptionFactory: group => group.Description,
            eventIdsFactory: group => group.EventIds,
            groups: recentCredentialLifecycleEvents
                .Select(TryCreateCredentialLifecycleCandidate)
                .Where(x => x is not null)
                .Select(x => x!)
                .GroupBy(x => x.Key, StringComparer.Ordinal)
                .Select(group =>
                {
                    var candidates = group.OrderBy(x => x.EventIds.Min()).ToList();
                    var displayName = candidates
                        .Select(x => x.DisplayName)
                        .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
                    return new RuleCandidate
                    {
                        Key = group.Key,
                        Count = candidates.Count,
                        Description = $"Sensor credential lifecycle changed {candidates.Count} times in 15 minutes for sensor {group.Key}{FormatDisplayName(displayName)}. Source events: {string.Join(", ", candidates.SelectMany(x => x.EventIds).Distinct().Order())}.",
                        EventIds = candidates.SelectMany(x => x.EventIds).Distinct().Order().ToList()
                    };
                })
                .Where(x => x.Count >= 3)
                .ToList(),
            createIncident: true,
            cancellationToken: cancellationToken);

        Merge(result, created8);
        return result;
    }

    private async Task<CorrelationRunResult> ProcessRuleAsync(
        string ruleCode,
        string ruleName,
        EventSeverity severity,
        Func<RuleCandidate, string> descriptionFactory,
        Func<RuleCandidate, List<long>> eventIdsFactory,
        List<RuleCandidate> groups,
        bool createIncident,
        CancellationToken cancellationToken)
    {
        var result = new CorrelationRunResult();

        foreach (var group in groups)
        {
            var triggerKey = $"{ruleCode}:{group.Key}";
            await using var transaction = await BeginCorrelationTransactionAsync(triggerKey, cancellationToken);
            var exists = await _dbContext.SiemAlerts.AnyAsync(x => x.RuleCode == ruleCode
                && x.TriggerKey == triggerKey
                && x.CreatedAtUtc >= DateTime.UtcNow.AddMinutes(-10)
                && x.Status != AlertStatuses.Closed, cancellationToken);

            if (exists)
            {
                if (transaction is not null)
                    await transaction.CommitAsync(cancellationToken);
                continue;
            }

            var effectiveSeverity = group.Severity ?? severity;

            var alert = new SiemAlertRecord
            {
                CreatedAtUtc = DateTime.UtcNow,
                RuleCode = ruleCode,
                RuleName = ruleName,
                TriggerKey = triggerKey,
                Severity = effectiveSeverity,
                Status = AlertStatuses.New,
                Description = descriptionFactory(group),
                SourceEventIdsJson = JsonSerializer.Serialize(eventIdsFactory(group))
            };

            _dbContext.SiemAlerts.Add(alert);
            await _dbContext.SaveChangesAsync(cancellationToken);
            result.CreatedAlerts++;
            result.TriggeredRules.Add(ruleCode);

            await _eventWriter.WriteAsync(new SecurityEventWriteRequest
            {
                EventType = SecurityEventType.CorrelationAlert,
                Severity = effectiveSeverity,
                UserName = "siem-engine",
                Description = $"Сработало правило корреляции {ruleCode}: {ruleName}.",
                AdditionalData = new { alert.Id, alert.RuleCode, alert.TriggerKey }
            });

            if (createIncident)
            {
                var incident = new IncidentRecord
                {
                    CreatedAtUtc = DateTime.UtcNow,
                    Name = $"[{ruleCode}] {ruleName}",
                    Severity = effectiveSeverity,
                    Status = IncidentStatuses.New,
                    SourceEventId = group.EventIds.FirstOrDefault(),
                    Notes = alert.Description
                };

                _dbContext.Incidents.Add(incident);
                await _dbContext.SaveChangesAsync(cancellationToken);
                alert.IncidentId = incident.Id;
                await _dbContext.SaveChangesAsync(cancellationToken);
                result.CreatedIncidents++;

                await _eventWriter.WriteAsync(new SecurityEventWriteRequest
                {
                    EventType = SecurityEventType.IncidentCreated,
                    Severity = effectiveSeverity,
                    UserName = "siem-engine",
                    Description = $"По правилу {ruleCode} автоматически создан инцидент #{incident.Id}.",
                    AdditionalData = new
                    {
                        IncidentId = incident.Id,
                        incident.SourceEventId,
                        AlertId = alert.Id
                    }
                });
            }

            if (transaction is not null)
                await transaction.CommitAsync(cancellationToken);
        }

        return result;
    }

    private async Task<IDbContextTransaction?> BeginCorrelationTransactionAsync(
        string triggerKey,
        CancellationToken cancellationToken)
    {
        if (!_dbContext.Database.IsRelational())
            return null;

        var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
        if (_dbContext.Database.ProviderName?.Contains("Npgsql", StringComparison.Ordinal) == true)
        {
            await using var command = _dbContext.Database.GetDbConnection().CreateCommand();
            command.Transaction = transaction.GetDbTransaction();
            command.CommandText = "SELECT pg_advisory_xact_lock(hashtextextended(@key, 0));";
            var parameter = command.CreateParameter();
            parameter.ParameterName = "key";
            parameter.Value = triggerKey;
            command.Parameters.Add(parameter);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return transaction;
    }

    private static void Merge(CorrelationRunResult target, CorrelationRunResult source)
    {
        target.CreatedAlerts += source.CreatedAlerts;
        target.CreatedIncidents += source.CreatedIncidents;
        target.TriggeredRules.AddRange(source.TriggeredRules);
    }

    private sealed class RuleCandidate
    {
        public string Key { get; set; } = string.Empty;
        public int Count { get; set; }
        public string Description { get; set; } = string.Empty;
        public List<long> EventIds { get; set; } = new();
        public EventSeverity? Severity { get; set; }
        public string? DisplayName { get; set; }
    }

    private static RuleCandidate? TryCreateImageScanCandidate(SecurityEventEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.AdditionalDataJson))
            return null;

        try
        {
            using var document = JsonDocument.Parse(entry.AdditionalDataJson);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;

            var criticalCount = ReadNonNegativeInt(root, "criticalCount");
            if (criticalCount < 1)
                return null;

            var imageReference = ReadString(root, "imageReference", 512);
            if (string.IsNullOrWhiteSpace(imageReference))
                return null;

            var imageDigest = ReadString(root, "imageDigest", 512);
            var triggerEntity = !string.IsNullOrWhiteSpace(imageDigest)
                ? imageDigest
                : NormalizeTriggerValue(imageReference);

            if (string.IsNullOrWhiteSpace(triggerEntity))
                return null;

            var highCount = ReadNonNegativeInt(root, "highCount");
            var totalCount = ReadNonNegativeInt(root, "totalCount");

            return new RuleCandidate
            {
                Key = triggerEntity,
                Count = 1,
                Description = $"Trivy обнаружил критические уязвимости в контейнерном образе {imageReference}: critical={criticalCount}, high={highCount}, total={totalCount}. Source event #{entry.Id}.",
                EventIds = [entry.Id]
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static RuleCandidate? TryCreatePolicyGateCandidate(SecurityEventEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.AdditionalDataJson))
            return null;

        try
        {
            using var document = JsonDocument.Parse(entry.AdditionalDataJson);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;

            if (ReadNonNegativeInt(root, "schemaVersion") != 1)
                return null;

            var decision = ReadString(root, "decision", 32);
            if (!string.Equals(decision, "Block", StringComparison.OrdinalIgnoreCase))
                return null;

            var policyId = ReadString(root, "policyId", 128);
            var policyVersion = ReadString(root, "policyVersion", 128);
            var policySha256 = ReadString(root, "policySha256", 64);
            var imageReference = ReadString(root, "imageReference", 512);
            if (string.IsNullOrWhiteSpace(policyId)
                || string.IsNullOrWhiteSpace(policyVersion)
                || string.IsNullOrWhiteSpace(imageReference)
                || !IsLowercaseSha256(policySha256))
            {
                return null;
            }

            var imageDigest = ReadString(root, "imageDigest", 512);
            var imageIdentity = !string.IsNullOrWhiteSpace(imageDigest)
                ? imageDigest
                : NormalizeTriggerValue(imageReference);
            if (string.IsNullOrWhiteSpace(imageIdentity))
                return null;

            var criticalCount = ReadNonNegativeInt(root, "criticalCount");
            var highCount = ReadNonNegativeInt(root, "highCount");
            var totalCount = ReadNonNegativeInt(root, "totalCount");
            var key = $"{policyId}:{policyVersion}:{imageIdentity}";

            return new RuleCandidate
            {
                Key = key,
                Count = 1,
                Description = $"Container policy {policyId}/{policyVersion} blocked image {imageReference}: critical={criticalCount}, high={highCount}, total={totalCount}. Source event #{entry.Id}.",
                EventIds = [entry.Id]
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static RuleCandidate? TryCreateRuntimeCandidate(SecurityEventEntry entry)
    {
        var approved = new HashSet<string>(StringComparer.Ordinal)
        {
            "container.runtime.shell_spawned",
            "container.runtime.binary_path_write",
            "container.runtime.etc_write",
            "container.runtime.setuid_change",
            "container.runtime.suspicious_network_tool",
            "container.runtime.privileged_container_started"
        };
        if (entry.ExternalEventType is null || !approved.Contains(entry.ExternalEventType))
            return null;
        if (string.IsNullOrWhiteSpace(entry.AdditionalDataJson))
            return null;

        try
        {
            using var document = JsonDocument.Parse(entry.AdditionalDataJson);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;
            if (ReadNonNegativeInt(root, "schemaVersion") != 1)
                return null;
            if (!string.Equals(ReadString(root, "provider", 64), "falco-compatible", StringComparison.Ordinal))
                return null;
            if (!ReadBool(root, "correlate"))
                return null;
            var mappingId = ReadString(root, "mappingId", 128);
            var mappingVersion = ReadString(root, "mappingVersion", 64);
            var mappingSha = ReadString(root, "mappingSha256", 64);
            var mappingKey = ReadString(root, "mappingKey", 128);
            var falcoRule = ReadString(root, "falcoRule", 256);
            if (string.IsNullOrWhiteSpace(mappingId)
                || string.IsNullOrWhiteSpace(mappingVersion)
                || !IsLowercaseSha256(mappingSha)
                || string.IsNullOrWhiteSpace(mappingKey)
                || string.IsNullOrWhiteSpace(falcoRule))
            {
                return null;
            }

            var containerId = ReadString(root, "containerId", 512);
            var containerName = ReadString(root, "containerName", 512);
            var imageDigest = ReadString(root, "imageDigest", 512);
            var imageReference = ReadString(root, "imageReference", 512);
            var processName = ReadString(root, "processName", 128);
            var host = entry.SourceHost;
            var identity = !string.IsNullOrWhiteSpace(containerId)
                ? containerId
                : !string.IsNullOrWhiteSpace(containerName) && !string.IsNullOrWhiteSpace(imageDigest ?? imageReference)
                    ? $"{containerName}:{imageDigest ?? imageReference}"
                    : host;
            if (string.IsNullOrWhiteSpace(identity))
                return null;

            var key = $"{NormalizeTriggerValue(identity)}:{mappingKey}:{NormalizeTriggerValue(processName ?? "unknown-process")}";
            return new RuleCandidate
            {
                Key = key,
                Count = 1,
                Description = $"Runtime threat {mappingKey} detected for {identity}: rule={falcoRule}, process={processName ?? "unknown"}. Source event #{entry.Id}.",
                EventIds = [entry.Id],
                Severity = entry.Severity
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static RuleCandidate? TryCreateSensorRevokedCandidate(SecurityEventEntry entry)
    {
        var lifecycleData = TryReadLifecycleData(entry);
        var sensorIdentity = lifecycleData?.SensorId ?? $"source-event-{entry.Id}";
        var displayName = lifecycleData?.DisplayName;
        var requestedBy = lifecycleData?.RequestedBy;
        var revokedCredentialCount = lifecycleData?.RevokedCredentialCount;
        var revokedCredentialText = revokedCredentialCount is null
            ? "unknown revoked credential count"
            : $"revokedCredentialCount={revokedCredentialCount.Value}";

        return new RuleCandidate
        {
            Key = NormalizeTriggerValue(sensorIdentity),
            Count = 1,
            Description = $"Sensor identity was revoked for sensor {sensorIdentity}{FormatDisplayName(displayName)}; requestedBy={SafeUnknown(requestedBy)}; {revokedCredentialText}. Source event #{entry.Id}.",
            EventIds = [entry.Id],
            DisplayName = displayName
        };
    }

    private static RuleCandidate? TryCreateCredentialLifecycleCandidate(SecurityEventEntry entry)
    {
        var lifecycleData = TryReadLifecycleData(entry);
        if (lifecycleData?.SensorId is null)
            return null;

        return new RuleCandidate
        {
            Key = NormalizeTriggerValue(lifecycleData.SensorId),
            Count = 1,
            Description = entry.ExternalEventType ?? "sensor credential lifecycle event",
            EventIds = [entry.Id],
            DisplayName = lifecycleData.DisplayName
        };
    }

    private static LifecycleAuditData? TryReadLifecycleData(SecurityEventEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.AdditionalDataJson))
            return null;

        try
        {
            using var document = JsonDocument.Parse(entry.AdditionalDataJson);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;

            return new LifecycleAuditData(
                ReadGuidString(root, "sensorId"),
                ReadString(root, "displayName", 256),
                ReadString(root, "requestedBy", 128),
                ReadNonNegativeIntOrNull(root, "revokedCredentialCount"));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static int ReadNonNegativeInt(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value))
            return 0;

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
            return Math.Max(0, number);

        return 0;
    }

    private static int? ReadNonNegativeIntOrNull(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value))
            return null;

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
            return Math.Max(0, number);

        return null;
    }

    private static string? ReadString(JsonElement root, string propertyName, int maxLength)
    {
        if (!root.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.String)
            return null;

        var text = value.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(text))
            return null;

        text = new string(text.Where(x => !char.IsControl(x)).ToArray());
        return text.Length <= maxLength ? text : text[..maxLength];
    }

    private static string? ReadGuidString(JsonElement root, string propertyName)
    {
        var text = ReadString(root, propertyName, 64);
        return Guid.TryParse(text, out var guid) ? guid.ToString("D") : null;
    }

    private static bool ReadBool(JsonElement root, string propertyName)
    {
        return root.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.True;
    }

    private static string NormalizeTriggerValue(string value)
    {
        var normalized = value.Trim().ToLowerInvariant();
        normalized = new string(normalized.Where(x => !char.IsControl(x)).ToArray());
        return normalized.Length <= 512 ? normalized : normalized[..512];
    }

    private static bool IsLowercaseSha256(string? value)
    {
        return value is { Length: 64 }
            && value.All(x => x is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static string FormatDisplayName(string? displayName) =>
        string.IsNullOrWhiteSpace(displayName) ? string.Empty : $" ({displayName})";

    private static string SafeUnknown(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "unknown" : value;

    private sealed record LifecycleAuditData(
        string? SensorId,
        string? DisplayName,
        string? RequestedBy,
        int? RevokedCredentialCount);
}
