using System.Text.Json;
using ConShield.Application.Models;

namespace ConShield.Application;

public interface ISiemRuleProvider
{
    SiemRuleSet GetRules();
}

public sealed class FileSystemSiemRuleProvider : ISiemRuleProvider
{
    private readonly string _basePath;

    public FileSystemSiemRuleProvider(string basePath)
    {
        _basePath = basePath;
    }

    public SiemRuleSet GetRules()
    {
        var configRoot = FindConfigRoot(_basePath);
        if (configRoot is not null)
        {
            var localPath = Path.Combine(configRoot, "siem-rules.local.json");
            var defaultPath = Path.Combine(configRoot, "siem-rules.default.json");
            var selectedPath = File.Exists(localPath)
                ? localPath
                : File.Exists(defaultPath)
                    ? defaultPath
                    : null;

            if (selectedPath is not null)
            {
                var loadResult = SiemRulesConfigurationLoader.TryLoadFile(selectedPath);
                if (loadResult.Validation.IsValid && loadResult.Configuration is not null)
                    return SiemRulesConfigurationLoader.ToRuleSet(
                        loadResult.Configuration,
                        ToDisplayPath(selectedPath),
                        usedFallback: false);
            }
        }

        return SiemRulesConfigurationLoader.BuiltInDefaults("built-in defaults", usedFallback: true);
    }

    private static string? FindConfigRoot(string startPath)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(startPath));
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "config");
            if (Directory.Exists(candidate))
                return candidate;

            directory = directory.Parent;
        }

        return null;
    }

    private static string ToDisplayPath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = new DirectoryInfo(Path.GetDirectoryName(fullPath)!);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
                return Path.GetRelativePath(directory.FullName, fullPath).Replace('\\', '/');

            directory = directory.Parent;
        }

        return Path.GetFileName(fullPath);
    }
}

public static class SiemRulesConfigurationLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = false
    };

    private static readonly HashSet<string> SupportedRuleIds = new(StringComparer.Ordinal)
    {
        "IMG-001",
        "POL-001",
        "RTE-001",
        "LIFE-001",
        "LIFE-002"
    };

    public static (SiemRulesConfiguration? Configuration, SiemRulesValidationResult Validation) TryLoadFile(string path)
    {
        try
        {
            var configuration = JsonSerializer.Deserialize<SiemRulesConfiguration>(
                File.ReadAllText(path),
                JsonOptions);
            return (configuration, Validate(configuration));
        }
        catch (JsonException ex)
        {
            return (null, new SiemRulesValidationResult([$"Config JSON is invalid: {ex.Message}"]));
        }
        catch (IOException ex)
        {
            return (null, new SiemRulesValidationResult([$"Config file cannot be read: {ex.Message}"]));
        }
    }

    public static SiemRulesValidationResult Validate(SiemRulesConfiguration? configuration)
    {
        var errors = new List<string>();
        if (configuration is null)
            return new SiemRulesValidationResult(["Config document is empty or invalid."]);

        if (configuration.ExtensionData is { Count: > 0 })
            errors.Add($"Unknown root field: {configuration.ExtensionData.Keys.Order(StringComparer.Ordinal).First()}.");

        if (configuration.Version != 1)
            errors.Add("Version must be 1.");

        if (configuration.Rules.Count == 0)
            errors.Add("At least one rule is required.");

        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < configuration.Rules.Count; index++)
        {
            var rule = configuration.Rules[index];
            var label = string.IsNullOrWhiteSpace(rule.Id) ? $"index {index}" : rule.Id;

            if (rule.ExtensionData is { Count: > 0 })
                errors.Add($"{label}: unknown field {rule.ExtensionData.Keys.Order(StringComparer.Ordinal).First()}.");
            if (rule.Incident.ExtensionData is { Count: > 0 })
                errors.Add($"{label}: unknown incident field {rule.Incident.ExtensionData.Keys.Order(StringComparer.Ordinal).First()}.");
            if (string.IsNullOrWhiteSpace(rule.Id))
                errors.Add($"{label}: id is required.");
            else if (!seenIds.Add(rule.Id))
                errors.Add($"{label}: id must be unique.");
            else if (!SupportedRuleIds.Contains(rule.Id))
                errors.Add($"{label}: rule id is not supported by configurable SIEM rules v1.");
            if (string.IsNullOrWhiteSpace(rule.Name))
                errors.Add($"{label}: name is required.");
            if (rule.Threshold <= 0)
                errors.Add($"{label}: threshold must be positive.");
            if (rule.TimeWindowMinutes <= 0)
                errors.Add($"{label}: timeWindowMinutes must be positive.");
            if (string.IsNullOrWhiteSpace(rule.GroupingKey))
                errors.Add($"{label}: groupingKey is required.");
            if (rule.EffectiveSourceSystems.Count == 0)
                errors.Add($"{label}: at least one exact source system is required.");
            if (rule.EffectiveEventTypes.Count == 0)
                errors.Add($"{label}: at least one exact event type is required.");
            foreach (var value in rule.EffectiveSourceSystems.Concat(rule.EffectiveEventTypes))
            {
                if (value.Contains('*', StringComparison.Ordinal) || string.Equals(value, "all", StringComparison.OrdinalIgnoreCase))
                    errors.Add($"{label}: wildcard source/event matching is not allowed.");
            }

            ValidateSeverity(rule.MinimumSeverity ?? rule.Severity ?? "Info", $"{label}: minimumSeverity", errors);
            ValidateSeverity(rule.AlertSeverity, $"{label}: alertSeverity", errors);
            if (!string.IsNullOrWhiteSpace(rule.Incident.Severity))
                ValidateSeverity(rule.Incident.Severity, $"{label}: incident.severity", errors);
        }

        return new SiemRulesValidationResult(errors);
    }

    public static SiemRuleSet ToRuleSet(SiemRulesConfiguration configuration, string configSource, bool usedFallback) =>
        new(configSource, configuration.Rules, usedFallback);

    public static SiemRuleSet BuiltInDefaults(string configSource, bool usedFallback) =>
        ToRuleSet(CreateBuiltInDefaultConfiguration(), configSource, usedFallback);

    public static SiemRulesConfiguration CreateBuiltInDefaultConfiguration() => new()
    {
        Version = 1,
        Rules =
        [
            new ConfigurableSiemRule
            {
                Id = "IMG-001",
                Name = "Critical image scan finding",
                Description = "Creates a SIEM alert when a deterministic image scan event contains critical findings.",
                Enabled = true,
                SourceSystems = ["conshield.image-scanner"],
                EventTypes = ["container.image.scan.completed"],
                MinimumSeverity = "Critical",
                Threshold = 1,
                TimeWindowMinutes = 1440,
                GroupingKey = "image",
                AlertSeverity = "Critical",
                Incident = new ConfigurableSiemIncidentRule { Create = true, Severity = "Critical" }
            },
            new ConfigurableSiemRule
            {
                Id = "POL-001",
                Name = "Container image blocked by policy",
                Description = "Creates a SIEM alert when the protected container policy gate blocks an image.",
                Enabled = true,
                SourceSystems = ["conshield.container-guard"],
                EventTypes = ["container.image.policy.evaluated"],
                MinimumSeverity = "Warning",
                Threshold = 1,
                TimeWindowMinutes = 1440,
                GroupingKey = "policy-image",
                AlertSeverity = "Critical",
                Incident = new ConfigurableSiemIncidentRule { Create = true, Severity = "Critical" }
            },
            new ConfigurableSiemRule
            {
                Id = "RTE-001",
                Name = "Container runtime threat detected",
                Description = "Creates a SIEM alert for approved Falco-compatible runtime mappings with high or critical severity.",
                Enabled = true,
                SourceSystems =
                [
                    "conshield.falco-runtime-collector",
                    "conshield.falco-linux-sensor"
                ],
                EventTypes =
                [
                    "container.runtime.shell_spawned",
                    "container.runtime.binary_path_write",
                    "container.runtime.etc_write",
                    "container.runtime.setuid_change",
                    "container.runtime.suspicious_network_tool",
                    "container.runtime.privileged_container_started"
                ],
                MinimumSeverity = "High",
                Threshold = 1,
                TimeWindowMinutes = 10,
                GroupingKey = "runtime-container-mapping-process",
                AlertSeverity = "High",
                Incident = new ConfigurableSiemIncidentRule { Create = true, Severity = "High" }
            },
            new ConfigurableSiemRule
            {
                Id = "LIFE-001",
                Name = "Sensor identity revoked",
                Description = "Creates a SIEM alert when a runtime sensor identity is revoked.",
                Enabled = true,
                SourceSystems = ["conshield.sensor-lifecycle"],
                EventTypes = ["sensor.revoked"],
                MinimumSeverity = "Info",
                Threshold = 1,
                TimeWindowMinutes = 1440,
                GroupingKey = "sensor-id",
                AlertSeverity = "Warning",
                Incident = new ConfigurableSiemIncidentRule { Create = true, Severity = "Warning" }
            },
            new ConfigurableSiemRule
            {
                Id = "LIFE-002",
                Name = "Repeated sensor credential lifecycle changes",
                Description = "Creates a SIEM alert when a sensor has repeated credential lifecycle changes in a short window.",
                Enabled = true,
                SourceSystems = ["conshield.sensor-lifecycle"],
                EventTypes =
                [
                    "sensor.credential.rotated",
                    "sensor.credential.revoked"
                ],
                MinimumSeverity = "Info",
                Threshold = 3,
                TimeWindowMinutes = 15,
                GroupingKey = "sensor-id",
                AlertSeverity = "Warning",
                Incident = new ConfigurableSiemIncidentRule { Create = true, Severity = "Warning" }
            }
        ]
    };

    private static void ValidateSeverity(string? value, string fieldName, List<string> errors)
    {
        if (!Enum.TryParse<ConShield.Contracts.Enums.EventSeverity>(value, ignoreCase: true, out _))
            errors.Add($"{fieldName} must be one of Info, Warning, High, Critical.");
    }
}
