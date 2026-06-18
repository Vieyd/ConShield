using System.Text.Json;
using ConShield.Contracts.Enums;

namespace ConShield.RuntimeDetection;

public sealed record FalcoMappingPolicy(
    int SchemaVersion,
    string MappingId,
    string Version,
    string UnmappedAction,
    IReadOnlyList<FalcoMappingRule> Rules,
    string Sha256);

public sealed record FalcoMappingRule(
    string MappingKey,
    IReadOnlyList<string> MatchRuleNames,
    IReadOnlyList<string> RequiredTags,
    string EventType,
    EventSeverity Severity,
    bool Correlate);

public sealed record MappingLoadResult(FalcoMappingPolicy? Policy, string? Error)
{
    public bool Success => Policy is not null;
    public static MappingLoadResult Ok(FalcoMappingPolicy policy) => new(policy, null);
    public static MappingLoadResult Fail(string error) => new(null, error);
}

public static class FalcoMappingPolicyLoader
{
    private static readonly HashSet<string> TopLevelProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion",
        "mappingId",
        "version",
        "unmappedAction",
        "rules"
    };

    private static readonly HashSet<string> RuleProperties = new(StringComparer.Ordinal)
    {
        "mappingKey",
        "matchRuleNames",
        "requiredTags",
        "eventType",
        "severity",
        "correlate"
    };

    public static MappingLoadResult Load(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return MappingLoadResult.Fail("Mapping path is required.");
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
            return MappingLoadResult.Fail("Mapping file was not found.");
        var info = new FileInfo(fullPath);
        if (info.Length > RuntimeDetectionConstants.MaxPolicyBytes)
            return MappingLoadResult.Fail("Mapping file is too large.");
        var bytes = File.ReadAllBytes(fullPath);
        return Load(bytes);
    }

    public static MappingLoadResult Load(byte[] bytes)
    {
        if (bytes.Length > RuntimeDetectionConstants.MaxPolicyBytes)
            return MappingLoadResult.Fail("Mapping file is too large.");
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 12 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return MappingLoadResult.Fail("Mapping must be a JSON object.");
            foreach (var property in root.EnumerateObject())
            {
                if (!TopLevelProperties.Contains(property.Name))
                    return MappingLoadResult.Fail($"Unknown mapping property '{property.Name}'.");
            }
            if (!root.TryGetProperty("schemaVersion", out var schema) || !schema.TryGetInt32(out var schemaVersion) || schemaVersion != 1)
                return MappingLoadResult.Fail("Mapping schemaVersion must be 1.");
            var mappingId = ReadRequiredString(root, "mappingId", 128);
            var version = ReadRequiredString(root, "version", 64);
            var unmappedAction = ReadRequiredString(root, "unmappedAction", 64);
            if (mappingId is null || version is null || unmappedAction is null)
                return MappingLoadResult.Fail("Mapping id, version, and unmappedAction are required.");
            if (!string.Equals(unmappedAction, "IngestWithoutCorrelation", StringComparison.Ordinal))
                return MappingLoadResult.Fail("Only IngestWithoutCorrelation is supported for unmappedAction.");
            if (!root.TryGetProperty("rules", out var rulesElement) || rulesElement.ValueKind != JsonValueKind.Array)
                return MappingLoadResult.Fail("Mapping rules must be an array.");

            var keys = new HashSet<string>(StringComparer.Ordinal);
            var ruleNames = new HashSet<string>(StringComparer.Ordinal);
            var rules = new List<FalcoMappingRule>();
            foreach (var item in rulesElement.EnumerateArray())
            {
                var rule = ReadRule(item);
                if (rule.Error is not null)
                    return MappingLoadResult.Fail(rule.Error);
                var parsed = rule.Rule!;
                if (!keys.Add(parsed.MappingKey))
                    return MappingLoadResult.Fail("Duplicate mappingKey.");
                foreach (var name in parsed.MatchRuleNames)
                {
                    if (!ruleNames.Add(name))
                        return MappingLoadResult.Fail("Same Falco rule is mapped more than once.");
                }
                rules.Add(parsed);
            }
            if (rules.Count == 0)
                return MappingLoadResult.Fail("At least one mapping rule is required.");

            return MappingLoadResult.Ok(new FalcoMappingPolicy(
                schemaVersion,
                mappingId,
                version,
                unmappedAction,
                rules,
                SafeRuntimeText.Sha256Hex(bytes)));
        }
        catch (JsonException)
        {
            return MappingLoadResult.Fail("Mapping JSON is malformed.");
        }
    }

    private static (FalcoMappingRule? Rule, string? Error) ReadRule(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return (null, "Mapping rule must be an object.");
        foreach (var property in element.EnumerateObject())
        {
            if (!RuleProperties.Contains(property.Name))
                return (null, $"Unknown mapping rule property '{property.Name}'.");
        }
        var mappingKey = ReadRequiredString(element, "mappingKey", 128);
        var names = ReadStringArray(element, "matchRuleNames", 16, 256);
        var requiredTags = ReadStringArray(element, "requiredTags", 16, 64, required: false);
        var eventType = ReadRequiredString(element, "eventType", 128);
        var severityText = ReadRequiredString(element, "severity", 32);
        if (mappingKey is null || names.Count == 0 || eventType is null || severityText is null)
            return (null, "Mapping rule has missing required values.");
        if (!eventType.StartsWith("container.runtime.", StringComparison.Ordinal) || eventType == RuntimeDetectionConstants.UnmappedEventType)
            return (null, "Mapping rule eventType must use container.runtime. prefix and cannot be unmapped.");
        if (!Enum.TryParse<EventSeverity>(severityText, ignoreCase: true, out var severity) || !Enum.IsDefined(severity) || int.TryParse(severityText, out _))
            return (null, "Mapping rule severity is invalid.");
        var correlate = element.TryGetProperty("correlate", out var correlateElement)
            && correlateElement.ValueKind == JsonValueKind.True;
        return (new FalcoMappingRule(mappingKey, names, requiredTags, eventType, severity, correlate), null);
    }

    private static string? ReadRequiredString(JsonElement root, string name, int maxLength)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            return null;
        return SafeRuntimeText.Clean(value.GetString(), maxLength);
    }

    private static List<string> ReadStringArray(JsonElement root, string name, int maxCount, int maxLength, bool required = true)
    {
        if (!root.TryGetProperty(name, out var value))
            return required ? new List<string>() : new List<string>();
        if (value.ValueKind != JsonValueKind.Array)
            return new List<string>();
        return value.EnumerateArray()
            .Where(x => x.ValueKind == JsonValueKind.String)
            .Select(x => SafeRuntimeText.Clean(x.GetString(), maxLength))
            .Where(x => x is not null)
            .Select(x => x!)
            .Take(maxCount)
            .ToList();
    }
}
