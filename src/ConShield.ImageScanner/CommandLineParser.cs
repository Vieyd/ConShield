namespace ConShield.ImageScanner;

public static class CommandLineParser
{
    private static readonly HashSet<string> ScanValueOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "image",
        "base-url",
        "api-key",
        "trivy-path",
        "external-event-id",
        "timeout-seconds",
        "source-system"
    };

    private static readonly HashSet<string> ScanFlagOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "no-submit"
    };

    private static readonly HashSet<string> GateValueOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "image",
        "policy",
        "base-url",
        "api-key",
        "trivy-path",
        "docker-path",
        "external-event-id",
        "timeout-seconds",
        "run-timeout-seconds"
    };

    private static readonly HashSet<string> GateFlagOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "no-submit",
        "execute",
        "accept-warning"
    };

    public static ParseResult Parse(string[] args)
    {
        if (args.Length == 0)
            return ParseResult.Invalid("Usage: ConShield.ImageScanner scan|gate --image <image-reference> [options]");

        var command = args[0].ToLowerInvariant();
        if (command is not ("scan" or "gate"))
            return ParseResult.Invalid("Usage: ConShield.ImageScanner scan|gate --image <image-reference> [options]");

        var read = ReadArgs(
            args.Skip(1).ToArray(),
            command == "scan" ? ScanValueOptions : GateValueOptions,
            command == "scan" ? ScanFlagOptions : GateFlagOptions);
        if (!read.IsValid)
            return ParseResult.Invalid(read.Error!);

        var values = read.Values!;
        var image = GetValue(values, "image");
        if (!IsValidImageReference(image, out var imageError))
            return ParseResult.Invalid(imageError);

        var noSubmit = values.ContainsKey("no-submit");
        var execute = values.ContainsKey("execute");
        var acceptWarning = values.ContainsKey("accept-warning");
        var policyPath = GetValue(values, "policy");
        if (command == "gate" && string.IsNullOrWhiteSpace(policyPath))
            return ParseResult.Invalid("--policy is required for gate.");

        if (command == "gate" && acceptWarning && !execute)
            return ParseResult.Invalid("--accept-warning requires --execute.");

        var baseUrl = GetValue(values, "base-url") ?? Environment.GetEnvironmentVariable("CONSHIELD_BASE_URL");
        if (!noSubmit)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))
                return ParseResult.Invalid("CONSHIELD_BASE_URL or --base-url is required unless --no-submit is used.");

            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
                return ParseResult.Invalid("Base URL must be an absolute URL.");

            if (baseUri.Scheme is not ("http" or "https"))
                return ParseResult.Invalid("Base URL must use http or https.");
        }

        var apiKey = GetValue(values, "api-key") ?? Environment.GetEnvironmentVariable("CONSHIELD_API_KEY");
        if (!noSubmit && string.IsNullOrWhiteSpace(apiKey))
            return ParseResult.Invalid("CONSHIELD_API_KEY or --api-key is required unless --no-submit is used.");

        var externalEventIdValue = GetValue(values, "external-event-id");
        if (externalEventIdValue is not null && !Guid.TryParse(externalEventIdValue, out _))
            return ParseResult.Invalid("--external-event-id must be a valid UUID.");

        var timeout = ScannerOptions.DefaultTimeoutSeconds;
        var timeoutValue = GetValue(values, "timeout-seconds");
        if (timeoutValue is not null)
        {
            if (!int.TryParse(timeoutValue, out timeout)
                || timeout < ScannerOptions.MinTimeoutSeconds
                || timeout > ScannerOptions.MaxTimeoutSeconds)
            {
                return ParseResult.Invalid($"--timeout-seconds must be between {ScannerOptions.MinTimeoutSeconds} and {ScannerOptions.MaxTimeoutSeconds}.");
            }
        }

        var runTimeout = ScannerOptions.DefaultRunTimeoutSeconds;
        var runTimeoutValue = GetValue(values, "run-timeout-seconds");
        if (runTimeoutValue is not null)
        {
            if (!int.TryParse(runTimeoutValue, out runTimeout)
                || runTimeout < ScannerOptions.MinRunTimeoutSeconds
                || runTimeout > ScannerOptions.MaxRunTimeoutSeconds)
            {
                return ParseResult.Invalid($"--run-timeout-seconds must be between {ScannerOptions.MinRunTimeoutSeconds} and {ScannerOptions.MaxRunTimeoutSeconds}.");
            }
        }

        var sourceSystem = command == "gate"
            ? ScannerConstants.SourceSystem
            : GetValue(values, "source-system") ?? ScannerConstants.SourceSystem;
        if (string.IsNullOrWhiteSpace(sourceSystem) || sourceSystem.Trim().Length > 128)
            return ParseResult.Invalid("--source-system must be between 1 and 128 characters.");

        return ParseResult.Valid(new ScannerOptions
        {
            Command = command,
            ImageReference = image!.Trim(),
            BaseUrl = baseUrl?.TrimEnd('/'),
            ApiKey = apiKey,
            TrivyPath = GetValue(values, "trivy-path") ?? Environment.GetEnvironmentVariable("CONSHIELD_TRIVY_PATH"),
            DockerPath = GetValue(values, "docker-path") ?? Environment.GetEnvironmentVariable("CONSHIELD_DOCKER_PATH"),
            PolicyPath = policyPath,
            ExternalEventId = externalEventIdValue is null ? Guid.NewGuid() : Guid.Parse(externalEventIdValue),
            TimeoutSeconds = timeout,
            RunTimeoutSeconds = runTimeout,
            SourceSystem = sourceSystem.Trim(),
            NoSubmit = noSubmit,
            Execute = execute,
            AcceptWarning = acceptWarning
        });
    }

    public static bool IsValidImageReference(string? imageReference, out string error)
    {
        if (string.IsNullOrWhiteSpace(imageReference))
        {
            error = "--image is required.";
            return false;
        }

        var value = imageReference.Trim();
        if (value.Length > ScannerOptions.MaxImageReferenceLength)
        {
            error = $"--image length must be at most {ScannerOptions.MaxImageReferenceLength} characters.";
            return false;
        }

        if (value.Any(char.IsControl))
        {
            error = "--image must not contain control characters.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static ArgReadResult ReadArgs(
        string[] args,
        HashSet<string> valueOptions,
        HashSet<string> flagOptions)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
                return ArgReadResult.Invalid($"Unexpected positional argument '{SafeArg(args[i])}'.");

            var key = args[i][2..];
            if (string.IsNullOrWhiteSpace(key))
                return ArgReadResult.Invalid("Empty option name is not allowed.");

            if (key.Contains('=', StringComparison.Ordinal))
                return ArgReadResult.Invalid($"Option '--{SafeArg(key.Split('=')[0])}' must not use '=' syntax.");

            if (!valueOptions.Contains(key) && !flagOptions.Contains(key))
                return ArgReadResult.Invalid($"Unknown option '--{SafeArg(key)}'.");

            if (values.ContainsKey(key))
                return ArgReadResult.Invalid($"Duplicate option '--{SafeArg(key)}'.");

            if (flagOptions.Contains(key))
            {
                values[key] = null;
                continue;
            }

            var next = i + 1 < args.Length ? args[i + 1] : null;
            if (next is null || next.StartsWith("--", StringComparison.Ordinal))
                return ArgReadResult.Invalid($"Option '--{SafeArg(key)}' requires a value.");

            values[key] = next;
            i++;
        }

        return ArgReadResult.Valid(values);
    }

    private static string? GetValue(Dictionary<string, string?> values, string key)
    {
        return values.TryGetValue(key, out var value) ? value : null;
    }

    private static string SafeArg(string value)
    {
        var safe = new string(value.Where(x => !char.IsControl(x)).ToArray()).Trim();
        return safe.Length <= 64 ? safe : safe[..64];
    }
}

internal sealed class ArgReadResult
{
    private ArgReadResult(Dictionary<string, string?>? values, string? error)
    {
        Values = values;
        Error = error;
    }

    public bool IsValid => Values is not null;
    public Dictionary<string, string?>? Values { get; }
    public string? Error { get; }

    public static ArgReadResult Valid(Dictionary<string, string?> values) => new(values, null);
    public static ArgReadResult Invalid(string error) => new(null, error);
}

public sealed class ParseResult
{
    private ParseResult(ScannerOptions? options, string? error)
    {
        Options = options;
        Error = error;
    }

    public bool IsValid => Options is not null;
    public ScannerOptions? Options { get; }
    public string? Error { get; }

    public static ParseResult Valid(ScannerOptions options) => new(options, null);
    public static ParseResult Invalid(string error) => new(null, error);
}
