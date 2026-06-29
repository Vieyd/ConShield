using System.Text.Json;
using ConShield.Application.Models;

namespace ConShield.Application;

public static class SensorTrustRegistryLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static SensorTrustRegistry LoadDefault()
    {
        var repoRoot = FindRepositoryRoot();
        if (repoRoot is null)
            return SensorTrustRegistry.Empty;

        var defaultPath = Path.Combine(repoRoot, "config", "sensor-registry.default.json");
        var localPath = Path.Combine(repoRoot, "config", "sensor-registry.local.json");
        var selectedPath = File.Exists(localPath) ? localPath : defaultPath;

        return File.Exists(selectedPath)
            ? LoadFromFile(selectedPath, repoRoot)
            : SensorTrustRegistry.Empty;
    }

    public static SensorTrustRegistry LoadFromFile(string path, string? repoRoot = null)
    {
        var fullPath = Path.GetFullPath(path);
        var json = File.ReadAllText(fullPath);
        using var document = JsonDocument.Parse(json);
        ValidateAllowedProperties(document.RootElement, ["version", "sensors"], "root");

        var dto = JsonSerializer.Deserialize<SensorTrustRegistryDto>(json, JsonOptions)
            ?? throw new InvalidDataException("Sensor registry JSON is invalid.");

        if (dto.Version != 1)
            throw new InvalidDataException("root: version must be 1");

        if (dto.Sensors is null || dto.Sensors.Count == 0)
            throw new InvalidDataException("root: at least one sensor is required");

        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        var sensors = new List<SensorTrustRegistryEntry>();
        for (var index = 0; index < dto.Sensors.Count; index++)
        {
            var jsonSensor = document.RootElement.GetProperty("sensors")[index];
            ValidateAllowedProperties(
                jsonSensor,
                ["sensorId", "displayName", "sourceSystem", "environment", "status", "expectedEventTypes", "fingerprintSha256", "notes"],
                $"sensor[{index}]");

            var sensor = dto.Sensors[index];
            var sensorId = SafeRequired(sensor.SensorId, $"sensor[{index}]: sensorId is required");
            if (!seenIds.Add(sensorId))
                throw new InvalidDataException($"{sensorId}: sensorId must be unique");

            var sourceSystem = SafeRequired(sensor.SourceSystem, $"{sensorId}: sourceSystem is required");
            var displayName = string.IsNullOrWhiteSpace(sensor.DisplayName)
                ? sourceSystem
                : Safe(sensor.DisplayName!, 128);
            var environment = string.IsNullOrWhiteSpace(sensor.Environment)
                ? "unspecified"
                : Safe(sensor.Environment!, 64);
            var status = SafeRequired(sensor.Status, $"{sensorId}: status is required");
            if (!SensorTrustStatuses.All.Contains(status))
                throw new InvalidDataException($"{sensorId}: status must be Trusted, Unknown, Revoked, or Disabled");

            var expectedEventTypes = (sensor.ExpectedEventTypes ?? [])
                .Select(value => SafeRequired(value, $"{sensorId}: expectedEventTypes must contain non-empty strings"))
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            var fingerprint = string.IsNullOrWhiteSpace(sensor.FingerprintSha256)
                ? null
                : Safe(sensor.FingerprintSha256!, 128);
            if (fingerprint is not null && LooksLikeCertificateMaterial(fingerprint))
                throw new InvalidDataException($"{sensorId}: fingerprintSha256 must not contain certificate or private key material");

            var notes = string.IsNullOrWhiteSpace(sensor.Notes) ? null : Safe(sensor.Notes!, 256);
            sensors.Add(new SensorTrustRegistryEntry(
                sensorId,
                displayName,
                sourceSystem,
                environment,
                status,
                expectedEventTypes,
                fingerprint,
                notes));
        }

        var displayPath = repoRoot is null
            ? Path.GetFileName(fullPath)
            : Path.GetRelativePath(repoRoot, fullPath).Replace('\\', '/');

        return new SensorTrustRegistry(dto.Version, displayPath, sensors);
    }

    private static string? FindRepositoryRoot()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            var directory = new DirectoryInfo(start);
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
                    return directory.FullName;

                directory = directory.Parent;
            }
        }

        return null;
    }

    private static void ValidateAllowedProperties(JsonElement element, IReadOnlyCollection<string> allowed, string label)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (!allowed.Contains(property.Name))
                throw new InvalidDataException($"{label}: unknown field {property.Name}");
        }
    }

    private static string SafeRequired(string? value, string message)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException(message);

        return Safe(value, 128);
    }

    private static string Safe(string value, int maxLength)
    {
        var cleaned = new string(value.Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        if (cleaned.Length == 0)
            throw new InvalidDataException("registry field is empty after sanitization");

        return cleaned.Length <= maxLength ? cleaned : cleaned[..maxLength];
    }

    private static bool LooksLikeCertificateMaterial(string value) =>
        value.Contains("-----BEGIN", StringComparison.OrdinalIgnoreCase)
        || value.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase)
        || value.Contains("CERTIFICATE", StringComparison.OrdinalIgnoreCase);

    private sealed record SensorTrustRegistryDto(int Version, List<SensorTrustRegistrySensorDto>? Sensors);

    private sealed record SensorTrustRegistrySensorDto(
        string? SensorId,
        string? DisplayName,
        string? SourceSystem,
        string? Environment,
        string? Status,
        List<string>? ExpectedEventTypes,
        string? FingerprintSha256,
        string? Notes);
}
