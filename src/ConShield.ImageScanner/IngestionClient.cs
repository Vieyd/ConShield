using System.Net.Http.Json;
using System.Text.Json;

namespace ConShield.ImageScanner;

public interface IIngestionClient
{
    Task<IngestionSubmitResult> SubmitAsync(
        ScannerOptions options,
        ImageScanIngestRequest request,
        CancellationToken cancellationToken);
}

public sealed class IngestionClient : IIngestionClient
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public async Task<IngestionSubmitResult> SubmitAsync(
        ScannerOptions options,
        ImageScanIngestRequest request,
        CancellationToken cancellationToken)
    {
        using var httpClient = new HttpClient
        {
            BaseAddress = new Uri(options.BaseUrl!),
            Timeout = TimeSpan.FromSeconds(Math.Min(options.TimeoutSeconds, 120))
        };

        httpClient.DefaultRequestHeaders.Add("X-ConShield-Api-Key", options.ApiKey);

        using var content = JsonContent.Create(request, options: SerializerOptions);
        using var response = await httpClient.PostAsync("/api/v1/security-events", content, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return IngestionSubmitResult.Rejected(
                (int)response.StatusCode,
                Redaction.TrimForSafeOutput(body, ScannerConstants.StderrDisplayLimit));
        }

        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var id = root.TryGetProperty("securityEventId", out var idElement)
                ? idElement.GetRawText()
                : "unknown";
            var created = root.TryGetProperty("created", out var createdElement)
                && createdElement.ValueKind == JsonValueKind.True;

            return IngestionSubmitResult.Accepted((int)response.StatusCode, id, created);
        }
        catch (JsonException)
        {
            return IngestionSubmitResult.Rejected((int)response.StatusCode, "API response was not valid JSON.");
        }
    }
}

public sealed class IngestionSubmitResult
{
    private IngestionSubmitResult(
        bool success,
        int statusCode,
        string? securityEventId,
        bool created,
        string? error)
    {
        Success = success;
        StatusCode = statusCode;
        SecurityEventId = securityEventId;
        Created = created;
        Error = error;
    }

    public bool Success { get; }
    public int StatusCode { get; }
    public string? SecurityEventId { get; }
    public bool Created { get; }
    public string? Error { get; }

    public static IngestionSubmitResult Accepted(int statusCode, string securityEventId, bool created) =>
        new(true, statusCode, securityEventId, created, null);

    public static IngestionSubmitResult Rejected(int statusCode, string error) =>
        new(false, statusCode, null, false, error);
}
