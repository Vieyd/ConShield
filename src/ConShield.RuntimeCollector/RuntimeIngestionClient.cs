using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ConShield.RuntimeDetection;

namespace ConShield.RuntimeCollector;

public sealed class RuntimeIngestionClient
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;

    public RuntimeIngestionClient(HttpClient httpClient, string apiKey)
    {
        _httpClient = httpClient;
        _apiKey = apiKey;
    }

    public async Task<SubmitResult> SubmitAsync(RuntimeSecurityEvent runtimeEvent, int maxRetries, CancellationToken cancellationToken)
    {
        var request = new
        {
            externalEventId = runtimeEvent.ExternalEventId,
            occurredAtUtc = runtimeEvent.OccurredAtUtc,
            sourceSystem = runtimeEvent.SourceSystem,
            eventType = runtimeEvent.EventType,
            severity = runtimeEvent.Severity.ToString(),
            sourceHost = runtimeEvent.SourceHost,
            description = runtimeEvent.Description,
            additionalData = runtimeEvent.AdditionalData
        };

        for (var attempt = 1; attempt <= maxRetries; attempt++)
        {
            using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/security-events");
            httpRequest.Headers.Add("X-ConShield-Api-Key", _apiKey);
            httpRequest.Content = JsonContent.Create(request, options: SerializerOptions);
            try
            {
                using var response = await _httpClient.SendAsync(httpRequest, cancellationToken);
                if (response.StatusCode is HttpStatusCode.Created or HttpStatusCode.OK)
                    return SubmitResult.AcceptedResult(response.StatusCode == HttpStatusCode.Created);
                if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized or HttpStatusCode.RequestEntityTooLarge)
                    return response.StatusCode == HttpStatusCode.Unauthorized
                        ? SubmitResult.AuthFailureResult()
                        : SubmitResult.PermanentFailureResult();
                if ((int)response.StatusCode == 429 || (int)response.StatusCode >= 500)
                {
                    if (attempt == maxRetries)
                        return SubmitResult.TransientExhausted();
                    await DelayAsync(attempt, response.Headers.RetryAfter?.Delta, cancellationToken);
                    continue;
                }
                return SubmitResult.PermanentFailureResult();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                if (attempt == maxRetries)
                    return SubmitResult.TransientExhausted();
                await DelayAsync(attempt, null, cancellationToken);
            }
        }
        return SubmitResult.TransientExhausted();
    }

    private static Task DelayAsync(int attempt, TimeSpan? retryAfter, CancellationToken cancellationToken)
    {
        var delay = retryAfter.HasValue && retryAfter.Value > TimeSpan.Zero && retryAfter.Value <= TimeSpan.FromSeconds(30)
            ? retryAfter.Value
            : TimeSpan.FromSeconds(Math.Min(30, Math.Pow(2, attempt - 1)));
        return Task.Delay(delay, cancellationToken);
    }
}

public sealed record SubmitResult(bool Accepted, bool Created, bool AuthFailure, bool PermanentFailure)
{
    public bool Duplicate => Accepted && !Created;
    public static SubmitResult AcceptedResult(bool created) => new(true, created, false, false);
    public static SubmitResult AuthFailureResult() => new(false, false, true, true);
    public static SubmitResult PermanentFailureResult() => new(false, false, false, true);
    public static SubmitResult TransientExhausted() => new(false, false, false, false);
}
