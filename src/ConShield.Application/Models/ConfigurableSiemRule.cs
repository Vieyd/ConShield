using System.Text.Json;
using System.Text.Json.Serialization;
using ConShield.Contracts.Enums;

namespace ConShield.Application.Models;

public sealed class SiemRulesConfiguration
{
    [JsonPropertyName("version")]
    public int Version { get; init; }

    [JsonPropertyName("rules")]
    public List<ConfigurableSiemRule> Rules { get; init; } = new();

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}

public sealed class ConfigurableSiemRule
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("enabled")]
    public bool? Enabled { get; init; }

    [JsonPropertyName("sourceSystem")]
    public string? SourceSystem { get; init; }

    [JsonPropertyName("sourceSystems")]
    public List<string> SourceSystems { get; init; } = new();

    [JsonPropertyName("eventType")]
    public string? EventType { get; init; }

    [JsonPropertyName("eventTypes")]
    public List<string> EventTypes { get; init; } = new();

    [JsonPropertyName("severity")]
    public string? Severity { get; init; }

    [JsonPropertyName("minimumSeverity")]
    public string? MinimumSeverity { get; init; }

    [JsonPropertyName("threshold")]
    public int Threshold { get; init; } = 1;

    [JsonPropertyName("timeWindowMinutes")]
    public int TimeWindowMinutes { get; init; } = 60;

    [JsonPropertyName("groupingKey")]
    public string GroupingKey { get; init; } = string.Empty;

    [JsonPropertyName("alertSeverity")]
    public string AlertSeverity { get; init; } = string.Empty;

    [JsonPropertyName("incident")]
    public ConfigurableSiemIncidentRule Incident { get; init; } = new();

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }

    [JsonIgnore]
    public bool IsEnabled => Enabled ?? true;

    [JsonIgnore]
    public IReadOnlyCollection<string> EffectiveSourceSystems =>
        NormalizeSingleAndMany(SourceSystem, SourceSystems);

    [JsonIgnore]
    public IReadOnlyCollection<string> EffectiveEventTypes =>
        NormalizeSingleAndMany(EventType, EventTypes);

    [JsonIgnore]
    public EventSeverity EffectiveMinimumSeverity =>
        ParseSeverity(MinimumSeverity ?? Severity ?? "Info");

    [JsonIgnore]
    public EventSeverity EffectiveAlertSeverity =>
        ParseSeverity(AlertSeverity);

    [JsonIgnore]
    public EventSeverity EffectiveIncidentSeverity =>
        ParseSeverity(Incident.Severity ?? AlertSeverity);

    private static IReadOnlyCollection<string> NormalizeSingleAndMany(string? single, IEnumerable<string> many)
    {
        var values = many
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .ToList();

        if (!string.IsNullOrWhiteSpace(single))
            values.Insert(0, single.Trim());

        return values
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static EventSeverity ParseSeverity(string? value) =>
        Enum.TryParse<EventSeverity>(value, ignoreCase: true, out var severity)
            ? severity
            : EventSeverity.Info;
}

public sealed class ConfigurableSiemIncidentRule
{
    [JsonPropertyName("create")]
    public bool Create { get; init; } = true;

    [JsonPropertyName("severity")]
    public string? Severity { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}

public sealed class SiemRulesValidationResult
{
    public SiemRulesValidationResult(IReadOnlyList<string> errors)
    {
        Errors = errors;
    }

    public bool IsValid => Errors.Count == 0;

    public IReadOnlyList<string> Errors { get; }
}

public sealed class SiemRuleSet
{
    public SiemRuleSet(string configSource, IReadOnlyCollection<ConfigurableSiemRule> rules, bool usedFallback)
    {
        ConfigSource = configSource;
        Rules = rules;
        UsedFallback = usedFallback;
        ById = rules.ToDictionary(x => x.Id, StringComparer.Ordinal);
    }

    public string ConfigSource { get; }

    public IReadOnlyCollection<ConfigurableSiemRule> Rules { get; }

    public bool UsedFallback { get; }

    public int EnabledCount => Rules.Count(x => x.IsEnabled);

    public int DisabledCount => Rules.Count(x => !x.IsEnabled);

    private IReadOnlyDictionary<string, ConfigurableSiemRule> ById { get; }

    public ConfigurableSiemRule? GetEnabledRule(string id) =>
        ById.TryGetValue(id, out var rule) && rule.IsEnabled ? rule : null;
}
