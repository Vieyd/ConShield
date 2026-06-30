using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ConShield.Cli;

internal static class DockerLifecycleCollector
{
    public const string SourceSystem = "conshield.docker-lifecycle-collector";
    public const string CollectorName = "docker-lifecycle-collector";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static IReadOnlyList<DockerLifecycleEvent> ParseFixture(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip
            });

            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
                return root.EnumerateArray().Select(ParseEvent).ToList();

            if (root.ValueKind == JsonValueKind.Object)
                return [ParseEvent(root)];

            throw new DockerLifecycleException("Docker events fixture must be a JSON object or array.");
        }
        catch (JsonException)
        {
            throw new DockerLifecycleException("Docker events fixture is not valid JSON.");
        }
        catch (IOException ex)
        {
            throw new DockerLifecycleException($"Docker events fixture could not be read: {ex.Message}");
        }
    }

    public static IReadOnlyList<NormalizedDockerLifecycleEvent> Normalize(IReadOnlyList<DockerLifecycleEvent> events)
    {
        var normalized = events
            .Where(x => string.Equals(x.Type, "container", StringComparison.OrdinalIgnoreCase))
            .Select(TryNormalize)
            .Where(x => x is not null)
            .Select(x => x!)
            .ToList();

        if (normalized.Count == 0)
            throw new DockerLifecycleException("No supported Docker container lifecycle events were found.");

        return normalized;
    }

    public static async Task<SubmitSummary> SubmitAsync(
        IReadOnlyList<NormalizedDockerLifecycleEvent> events,
        string baseUrl,
        string apiKey,
        CancellationToken cancellationToken = default)
    {
        using var httpClient = new HttpClient
        {
            BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(30)
        };
        httpClient.DefaultRequestHeaders.Add("X-ConShield-Api-Key", apiKey);

        var accepted = 0;
        var duplicate = 0;
        var failed = 0;

        foreach (var lifecycleEvent in events)
        {
            using var response = await httpClient.PostAsJsonAsync(
                "api/v1/security-events",
                lifecycleEvent.ToIngestRequest(),
                JsonOptions,
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                failed++;
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));
                var created = document.RootElement.TryGetProperty("created", out var createdElement)
                    && createdElement.ValueKind == JsonValueKind.True;
                if (created)
                    accepted++;
                else
                    duplicate++;
            }
            catch (JsonException)
            {
                accepted++;
            }
        }

        return new SubmitSummary(accepted, duplicate, failed);
    }

    public static async Task<bool> TestWebAsync(string baseUrl, CancellationToken cancellationToken = default)
    {
        try
        {
            using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            using var response = await httpClient.GetAsync(baseUrl.TrimEnd('/') + "/Operations/Health", cancellationToken);
            return (int)response.StatusCode is >= 200 and < 500;
        }
        catch
        {
            return false;
        }
    }

    public static string? ReadLocalApiKey(string repoRoot)
    {
        var external = Environment.GetEnvironmentVariable("CONSHIELD_EXTERNAL_EVENT_API_KEY");
        if (!string.IsNullOrWhiteSpace(external))
            return external;

        var generic = Environment.GetEnvironmentVariable("CONSHIELD_API_KEY");
        if (!string.IsNullOrWhiteSpace(generic))
            return generic;

        var localEnv = Path.Combine(repoRoot, ".conshield.local.env");
        if (!File.Exists(localEnv))
            return null;

        foreach (var rawLine in File.ReadLines(localEnv))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var match = Regex.Match(line, "^([A-Za-z_][A-Za-z0-9_]*)=(.*)$");
            if (!match.Success)
                continue;

            var name = match.Groups[1].Value;
            if (!name.Equals("CONSHIELD_EXTERNAL_EVENT_API_KEY", StringComparison.Ordinal)
                && !name.Equals("CONSHIELD_API_KEY", StringComparison.Ordinal))
            {
                continue;
            }

            var value = match.Groups[2].Value.Trim();
            if ((value.StartsWith('"') && value.EndsWith('"')) || (value.StartsWith('\'') && value.EndsWith('\'')))
                value = value[1..^1];

            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        return null;
    }

    private static NormalizedDockerLifecycleEvent? TryNormalize(DockerLifecycleEvent dockerEvent)
    {
        var eventType = MapEventType(dockerEvent.Action, dockerEvent.HealthStatus);
        if (eventType is null)
            return null;

        var containerIdShort = ShortContainerId(dockerEvent.ContainerId);
        var occurredAtUtc = dockerEvent.OccurredAtUtc ?? DateTime.UtcNow;
        var severity = eventType switch
        {
            DockerLifecycleEventTypes.AbnormalExit => "Warning",
            DockerLifecycleEventTypes.ExecStarted => "Warning",
            _ => "Info"
        };

        var externalEventId = DeterministicGuid(string.Join(
            "|",
            SourceSystem,
            eventType,
            occurredAtUtc.ToString("O", CultureInfo.InvariantCulture),
            dockerEvent.Action,
            containerIdShort,
            dockerEvent.ImageReference ?? "-",
            dockerEvent.ContainerName ?? "-"));

        var safeAction = SafeValue(dockerEvent.Action, 64);
        var safeName = SafeValue(dockerEvent.ContainerName, 128);
        var safeImage = SafeValue(dockerEvent.ImageReference, 256);
        var safeStatus = SafeValue(dockerEvent.HealthStatus, 64);
        var safeExitCode = dockerEvent.ExitCode;

        var description = eventType == DockerLifecycleEventTypes.AbnormalExit
            ? $"Docker lifecycle abnormal event action={safeAction}, container={safeName ?? "-"}, image={safeImage ?? "-"}, exitCode={safeExitCode?.ToString(CultureInfo.InvariantCulture) ?? "-"}."
            : $"Docker lifecycle event action={safeAction}, container={safeName ?? "-"}, image={safeImage ?? "-"}.";

        return new NormalizedDockerLifecycleEvent(
            externalEventId,
            occurredAtUtc,
            eventType,
            severity,
            "local-docker-lifecycle-cli",
            description,
            new DockerLifecycleAdditionalData(
                1,
                CollectorName,
                safeAction,
                eventType,
                containerIdShort,
                safeName,
                safeImage,
                safeExitCode,
                safeStatus,
                dockerEvent.EventSequence));
    }

    private static DockerLifecycleEvent ParseEvent(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
            throw new DockerLifecycleException("Docker event entry must be a JSON object.");

        var actor = TryGetObject(element, "Actor");
        var attributes = actor is null ? null : TryGetObject(actor.Value, "Attributes");

        var action = ReadString(element, "Action", 64)
            ?? ReadString(element, "status", 64)
            ?? ReadString(element, "Status", 64);
        if (string.IsNullOrWhiteSpace(action))
            throw new DockerLifecycleException("Docker event action is required.");

        var containerId = ReadString(element, "id", 128)
            ?? ReadString(actor, "ID", 128)
            ?? ReadString(element, "ID", 128);

        var name = ReadString(attributes, "name", 128)
            ?? ReadString(attributes, "container", 128);

        var image = ReadString(attributes, "image", 256)
            ?? ReadString(attributes, "from", 256);

        var exitCode = ReadInt(attributes, "exitCode")
            ?? ReadInt(attributes, "exit_code");

        var healthStatus = action.StartsWith("health_status", StringComparison.OrdinalIgnoreCase)
            ? action.Split(':', 2).LastOrDefault()?.Trim()
            : ReadString(attributes, "health_status", 64);

        return new DockerLifecycleEvent(
            ReadString(element, "Type", 64) ?? "container",
            action.Trim(),
            containerId,
            name,
            image,
            exitCode,
            healthStatus,
            ReadOccurredAtUtc(element),
            ReadString(element, "timeNano", 64) ?? ReadString(element, "time", 64));
    }

    private static string? MapEventType(string action, string? healthStatus)
    {
        var normalized = action.Trim().ToLowerInvariant();
        return normalized switch
        {
            "create" => DockerLifecycleEventTypes.Created,
            "start" => DockerLifecycleEventTypes.Started,
            "restart" => DockerLifecycleEventTypes.Started,
            "destroy" => DockerLifecycleEventTypes.Destroyed,
            "stop" => DockerLifecycleEventTypes.Stopped,
            "die" => DockerLifecycleEventTypes.AbnormalExit,
            "kill" => DockerLifecycleEventTypes.AbnormalExit,
            "oom" => DockerLifecycleEventTypes.AbnormalExit,
            "exec_start" => DockerLifecycleEventTypes.ExecStarted,
            "exec_create" => DockerLifecycleEventTypes.ExecStarted,
            _ when normalized.StartsWith("health_status", StringComparison.Ordinal)
                && string.Equals(healthStatus, "unhealthy", StringComparison.OrdinalIgnoreCase) => DockerLifecycleEventTypes.AbnormalExit,
            _ => null
        };
    }

    private static DateTime? ReadOccurredAtUtc(JsonElement element)
    {
        var timeText = ReadString(element, "time", 64);
        if (timeText is not null
            && DateTimeOffset.TryParse(timeText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsedText))
        {
            return parsedText.UtcDateTime;
        }

        if (element.TryGetProperty("timeNano", out var timeNano)
            && timeNano.ValueKind == JsonValueKind.Number
            && timeNano.TryGetInt64(out var nano))
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(nano / 1_000_000).UtcDateTime;
        }

        if (element.TryGetProperty("time", out var unixTime)
            && unixTime.ValueKind == JsonValueKind.Number
            && unixTime.TryGetInt64(out var seconds))
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime;
        }

        return null;
    }

    private static JsonElement? TryGetObject(JsonElement element, string propertyName)
    {
        if (element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.Object)
        {
            return property;
        }

        return null;
    }

    private static string? ReadString(JsonElement? element, string propertyName, int maxLength)
    {
        if (element is null
            || element.Value.ValueKind != JsonValueKind.Object
            || !element.Value.TryGetProperty(propertyName, out var property))
        {
            return null;
        }

        var value = property.ValueKind switch
        {
            JsonValueKind.String => property.GetString(),
            JsonValueKind.Number => property.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };

        return SafeValue(value, maxLength);
    }

    private static int? ReadInt(JsonElement? element, string propertyName)
    {
        var value = ReadString(element, propertyName, 32);
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
    }

    private static string? SafeValue(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var safe = value.Trim();
        safe = Regex.Replace(safe, "(?i)(password|secret|token|api[_ -]?key|authorization|bearer|cookie|credential)\\s*[:=]\\s*[^;\\s,]+", "$1=[redacted]");
        safe = Regex.Replace(safe, @"(?i)([A-Za-z]:\\[^,\s]+|/(?:home|root|var|etc|mnt|Users)/[^,\s]+)", "[path-redacted]");
        safe = Regex.Replace(safe, @"[\r\n\t]+", " ");
        safe = safe.Length <= maxLength ? safe : safe[..Math.Max(0, maxLength - 3)] + "...";
        return safe;
    }

    private static string ShortContainerId(string? value)
    {
        var safe = SafeValue(value, 128);
        if (string.IsNullOrWhiteSpace(safe))
            return "unknown";

        var cleaned = Regex.Replace(safe, "[^a-zA-Z0-9]", string.Empty).ToLowerInvariant();
        if (cleaned.Length == 0)
            return "unknown";

        return cleaned.Length <= 12 ? cleaned : cleaned[..12];
    }

    private static Guid DeterministicGuid(string seed)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var bytes = hash[..16];
        bytes[7] = (byte)((bytes[7] & 0x0F) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes);
    }
}

internal static class DockerLifecycleEventTypes
{
    public const string Created = "container.lifecycle.created";
    public const string Started = "container.lifecycle.started";
    public const string Stopped = "container.lifecycle.stopped";
    public const string Destroyed = "container.lifecycle.destroyed";
    public const string AbnormalExit = "container.lifecycle.abnormal_exit";
    public const string ExecStarted = "container.lifecycle.exec_started";
}

internal sealed record DockerLifecycleEvent(
    string Type,
    string Action,
    string? ContainerId,
    string? ContainerName,
    string? ImageReference,
    int? ExitCode,
    string? HealthStatus,
    DateTime? OccurredAtUtc,
    string? EventSequence);

internal sealed record DockerLifecycleAdditionalData(
    int SchemaVersion,
    string Collector,
    string? DockerAction,
    string LifecycleEventType,
    string ContainerIdShort,
    string? ContainerName,
    string? ImageReference,
    int? ExitCode,
    string? HealthStatus,
    string? EventSequence);

internal sealed record NormalizedDockerLifecycleEvent(
    Guid ExternalEventId,
    DateTime OccurredAtUtc,
    string EventType,
    string Severity,
    string SourceHost,
    string Description,
    DockerLifecycleAdditionalData AdditionalData)
{
    public object ToIngestRequest() => new
    {
        externalEventId = ExternalEventId,
        occurredAtUtc = OccurredAtUtc.ToString("O", CultureInfo.InvariantCulture),
        sourceSystem = DockerLifecycleCollector.SourceSystem,
        eventType = EventType,
        severity = Severity,
        userName = (string?)null,
        sourceHost = SourceHost,
        description = Description,
        additionalData = new
        {
            schemaVersion = AdditionalData.SchemaVersion,
            collector = AdditionalData.Collector,
            dockerAction = AdditionalData.DockerAction,
            lifecycleEventType = AdditionalData.LifecycleEventType,
            containerIdShort = AdditionalData.ContainerIdShort,
            containerName = AdditionalData.ContainerName,
            imageReference = AdditionalData.ImageReference,
            exitCode = AdditionalData.ExitCode,
            healthStatus = AdditionalData.HealthStatus,
            eventSequence = AdditionalData.EventSequence
        }
    };
}

internal sealed record SubmitSummary(int Accepted, int Duplicate, int Failed);

internal sealed class DockerLifecycleException : Exception
{
    public DockerLifecycleException(string message) : base(message)
    {
    }
}
