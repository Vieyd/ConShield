namespace ConShield.ImageScanner;

public static class CommandLineParser
{
    public static ParseResult Parse(string[] args)
    {
        if (args.Length == 0 || !args[0].Equals("scan", StringComparison.OrdinalIgnoreCase))
            return ParseResult.Invalid("Usage: ConShield.ImageScanner scan --image <image-reference> [options]");

        var values = ReadArgs(args.Skip(1).ToArray());
        var image = GetValue(values, "image");
        if (!IsValidImageReference(image, out var imageError))
            return ParseResult.Invalid(imageError);

        var baseUrl = GetValue(values, "base-url") ?? Environment.GetEnvironmentVariable("CONSHIELD_BASE_URL");
        var noSubmit = values.ContainsKey("no-submit");
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

        var sourceSystem = GetValue(values, "source-system") ?? ScannerConstants.SourceSystem;
        if (string.IsNullOrWhiteSpace(sourceSystem) || sourceSystem.Trim().Length > 128)
            return ParseResult.Invalid("--source-system must be between 1 and 128 characters.");

        return ParseResult.Valid(new ScannerOptions
        {
            ImageReference = image!.Trim(),
            BaseUrl = baseUrl?.TrimEnd('/'),
            ApiKey = apiKey,
            TrivyPath = GetValue(values, "trivy-path") ?? Environment.GetEnvironmentVariable("CONSHIELD_TRIVY_PATH"),
            ExternalEventId = externalEventIdValue is null ? Guid.NewGuid() : Guid.Parse(externalEventIdValue),
            TimeoutSeconds = timeout,
            SourceSystem = sourceSystem.Trim(),
            NoSubmit = noSubmit
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

    private static Dictionary<string, string?> ReadArgs(string[] args)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
                continue;

            var key = args[i][2..];
            var next = i + 1 < args.Length ? args[i + 1] : null;
            if (next is not null && !next.StartsWith("--", StringComparison.Ordinal))
            {
                values[key] = next;
                i++;
            }
            else
            {
                values[key] = null;
            }
        }

        return values;
    }

    private static string? GetValue(Dictionary<string, string?> values, string key)
    {
        return values.TryGetValue(key, out var value) ? value : null;
    }
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
