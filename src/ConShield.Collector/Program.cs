using System.Net.Http.Json;
using System.Text.Json;

var options = CollectorOptions.Parse(args);
if (!options.IsValid)
{
    Console.Error.WriteLine(options.ErrorMessage);
    Console.Error.WriteLine("Usage: dotnet run --project src/ConShield.Collector -- --generate [--external-event-id <uuid>] [--base-url <url>] or --file <path>");
    return 2;
}

using var httpClient = new HttpClient
{
    BaseAddress = new Uri(options.BaseUrl!),
    Timeout = TimeSpan.FromSeconds(10)
};

httpClient.DefaultRequestHeaders.Add("X-ConShield-Api-Key", options.ApiKey);

try
{
    using var content = JsonContent.Create(options.EventPayload);
    var response = await httpClient.PostAsync("/api/v1/security-events", content);
    var body = await response.Content.ReadAsStringAsync();

    Console.WriteLine($"HTTP {(int)response.StatusCode} {response.ReasonPhrase}");

    if (response.IsSuccessStatusCode)
    {
        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        var id = root.TryGetProperty("securityEventId", out var idElement)
            ? idElement.GetRawText()
            : "unknown";
        var created = root.TryGetProperty("created", out var createdElement)
            && createdElement.ValueKind == JsonValueKind.True;

        Console.WriteLine(created
            ? $"Event accepted. securityEventId={id}"
            : $"Event already exists. securityEventId={id}");
        return 0;
    }

    Console.Error.WriteLine("Request failed. Response body:");
    Console.Error.WriteLine(TrimForOutput(body));
    return 1;
}
catch (TaskCanceledException)
{
    Console.Error.WriteLine("Request timed out.");
    return 1;
}
catch (HttpRequestException ex)
{
    Console.Error.WriteLine($"HTTP request failed: {ex.Message}");
    return 1;
}
catch (JsonException ex)
{
    Console.Error.WriteLine($"Invalid JSON: {ex.Message}");
    return 1;
}

static string TrimForOutput(string value)
{
    const int maxLength = 1000;
    return value.Length <= maxLength ? value : value[..maxLength] + "...";
}

internal sealed class CollectorOptions
{
    public string? BaseUrl { get; private init; }
    public string? ApiKey { get; private init; }
    public object? EventPayload { get; private init; }
    public bool IsValid { get; private init; }
    public string ErrorMessage { get; private init; } = string.Empty;

    public static CollectorOptions Parse(string[] args)
    {
        var values = ReadArgs(args);
        var localConfig = ReadLocalConfig(GetValue(values, "config") ?? "collector.local.json");
        var baseUrl = GetValue(values, "base-url")
            ?? Environment.GetEnvironmentVariable("CONSHIELD_BASE_URL")
            ?? GetValue(localConfig, "baseUrl");
        var apiKey = GetValue(values, "api-key")
            ?? Environment.GetEnvironmentVariable("CONSHIELD_API_KEY")
            ?? GetValue(localConfig, "apiKey");

        if (string.IsNullOrWhiteSpace(baseUrl))
            return Invalid("CONSHIELD_BASE_URL or --base-url is required.");

        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out _))
            return Invalid("Base URL must be an absolute URL.");

        if (string.IsNullOrWhiteSpace(apiKey))
            return Invalid("CONSHIELD_API_KEY or --api-key is required.");

        var payload = CreatePayload(values);
        if (payload is null)
            return Invalid("Use --generate or --file <path>.");

        return new CollectorOptions
        {
            BaseUrl = baseUrl.TrimEnd('/'),
            ApiKey = apiKey,
            EventPayload = payload,
            IsValid = true
        };
    }

    private static object? CreatePayload(Dictionary<string, string?> values)
    {
        if (values.ContainsKey("generate"))
        {
            var id = GetValue(values, "external-event-id");
            return new
            {
                externalEventId = Guid.TryParse(id, out var parsedId) ? parsedId : Guid.NewGuid(),
                occurredAtUtc = DateTime.UtcNow,
                sourceSystem = "ConShield.Collector",
                eventType = "CollectorTestEvent",
                severity = "Info",
                userName = "collector",
                sourceHost = Environment.MachineName,
                description = "Test event from ConShield Collector.",
                additionalData = new
                {
                    collector = "ConShield.Collector",
                    mode = "generate"
                }
            };
        }

        var file = GetValue(values, "file");
        if (string.IsNullOrWhiteSpace(file))
            return null;

        using var stream = File.OpenRead(file);
        using var document = JsonDocument.Parse(stream);
        return JsonSerializer.Deserialize<object>(document.RootElement.GetRawText());
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

    private static Dictionary<string, string?> ReadLocalConfig(string path)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(path))
            return values;

        using var stream = File.OpenRead(path);
        using var document = JsonDocument.Parse(stream);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            return values;

        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.String)
                values[property.Name] = property.Value.GetString();
        }

        return values;
    }

    private static string? GetValue(Dictionary<string, string?> values, string key)
    {
        return values.TryGetValue(key, out var value) ? value : null;
    }

    private static CollectorOptions Invalid(string message) => new()
    {
        IsValid = false,
        ErrorMessage = message
    };
}
