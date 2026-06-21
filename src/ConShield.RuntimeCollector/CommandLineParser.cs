namespace ConShield.RuntimeCollector;

public static class CommandLineParser
{
    private static readonly HashSet<string> ValueOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "endpoint",
        "api-key-env",
        "mapping",
        "file",
        "max-line-bytes",
        "read-timeout-seconds",
        "submit-timeout-seconds",
        "max-retries"
    };

    private static readonly HashSet<string> FlagOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "stdin",
        "follow",
        "no-submit"
    };

    public static ParseResult Parse(string[] args)
    {
        if (args.Length == 0 || !string.Equals(args[0], "collect", StringComparison.OrdinalIgnoreCase))
            return ParseResult.Invalid("Usage: ConShield.RuntimeCollector collect --stdin|--file <path> --mapping <path> [options]");

        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
                return ParseResult.Invalid($"Unexpected positional argument '{Safe(args[i])}'.");
            var key = args[i][2..];
            if (key.Length == 0 || key.Contains('=', StringComparison.Ordinal))
                return ParseResult.Invalid("Options must use '--name value' syntax.");
            if (!ValueOptions.Contains(key) && !FlagOptions.Contains(key))
                return ParseResult.Invalid($"Unknown option '--{Safe(key)}'.");
            if (values.ContainsKey(key))
                return ParseResult.Invalid($"Duplicate option '--{Safe(key)}'.");
            if (FlagOptions.Contains(key))
            {
                values[key] = null;
                continue;
            }
            if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                return ParseResult.Invalid($"Option '--{Safe(key)}' requires a value.");
            values[key] = args[++i];
        }

        var stdin = values.ContainsKey("stdin");
        var file = Get(values, "file");
        if (stdin == !string.IsNullOrWhiteSpace(file))
            return ParseResult.Invalid("Specify exactly one input source: --stdin or --file.");
        if (values.ContainsKey("follow") && string.IsNullOrWhiteSpace(file))
            return ParseResult.Invalid("--follow requires --file.");
        var mapping = Get(values, "mapping");
        if (string.IsNullOrWhiteSpace(mapping))
            return ParseResult.Invalid("--mapping is required.");
        var noSubmit = values.ContainsKey("no-submit");
        var endpoint = Get(values, "endpoint")
            ?? Environment.GetEnvironmentVariable("CONSHIELD_ENDPOINT")
            ?? Environment.GetEnvironmentVariable("CONSHIELD_BASE_URL");
        if (!noSubmit)
        {
            if (string.IsNullOrWhiteSpace(endpoint))
                return ParseResult.Invalid("--endpoint, CONSHIELD_ENDPOINT, or CONSHIELD_BASE_URL is required unless --no-submit is used.");
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
                return ParseResult.Invalid("--endpoint must be an absolute http/https URL.");
        }

        var sensorIdValue = Environment.GetEnvironmentVariable("CONSHIELD_SENSOR_ID");
        var credentialIdValue = Environment.GetEnvironmentVariable("CONSHIELD_SENSOR_CREDENTIAL_ID");
        if (string.IsNullOrWhiteSpace(sensorIdValue) != string.IsNullOrWhiteSpace(credentialIdValue))
            return ParseResult.Invalid("CONSHIELD_SENSOR_ID and CONSHIELD_SENSOR_CREDENTIAL_ID must be configured together.");
        Guid? sensorId = null;
        Guid? sensorCredentialId = null;
        if (!string.IsNullOrWhiteSpace(sensorIdValue))
        {
            if (!Guid.TryParse(sensorIdValue, out var parsedSensorId) || parsedSensorId == Guid.Empty
                || !Guid.TryParse(credentialIdValue, out var parsedCredentialId) || parsedCredentialId == Guid.Empty)
            {
                return ParseResult.Invalid("Sensor identity environment variables must contain non-empty UUIDs.");
            }
            sensorId = parsedSensorId;
            sensorCredentialId = parsedCredentialId;
        }

        var heartbeatInterval = 60;
        var heartbeatValue = Environment.GetEnvironmentVariable("CONSHIELD_HEARTBEAT_INTERVAL_SECONDS");
        if (!string.IsNullOrWhiteSpace(heartbeatValue)
            && (!int.TryParse(heartbeatValue, out heartbeatInterval) || heartbeatInterval is < 15 or > 3600))
        {
            return ParseResult.Invalid("CONSHIELD_HEARTBEAT_INTERVAL_SECONDS must be between 15 and 3600.");
        }

        return ParseResult.Valid(new RuntimeCollectorOptions
        {
            Stdin = stdin,
            FilePath = file,
            Follow = values.ContainsKey("follow"),
            Endpoint = endpoint?.TrimEnd('/'),
            ApiKeyEnv = Get(values, "api-key-env") ?? "CONSHIELD_RUNTIME_COLLECTOR_API_KEY",
            SensorId = sensorId,
            SensorCredentialId = sensorCredentialId,
            HeartbeatIntervalSeconds = heartbeatInterval,
            MappingPath = mapping!,
            NoSubmit = noSubmit,
            MaxLineBytes = ReadInt(values, "max-line-bytes", 4096, 1048576, 262144),
            ReadTimeoutSeconds = ReadInt(values, "read-timeout-seconds", 1, 3600, 30),
            SubmitTimeoutSeconds = ReadInt(values, "submit-timeout-seconds", 1, 300, 30),
            MaxRetries = ReadInt(values, "max-retries", 1, 10, 3)
        });
    }

    private static int ReadInt(Dictionary<string, string?> values, string key, int min, int max, int fallback)
    {
        var value = Get(values, key);
        if (value is null)
            return fallback;
        return int.TryParse(value, out var parsed) && parsed >= min && parsed <= max ? parsed : fallback;
    }

    private static string? Get(Dictionary<string, string?> values, string key) =>
        values.TryGetValue(key, out var value) ? value : null;

    private static string Safe(string value)
    {
        var safe = new string(value.Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        return safe.Length <= 64 ? safe : safe[..64];
    }
}

public sealed record ParseResult(RuntimeCollectorOptions? Options, string? Error)
{
    public bool IsValid => Options is not null;
    public static ParseResult Valid(RuntimeCollectorOptions options) => new(options, null);
    public static ParseResult Invalid(string error) => new(null, error);
}
