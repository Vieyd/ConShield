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
    private readonly Guid? _sensorId;
    private readonly Guid? _credentialId;

    public RuntimeIngestionClient(HttpClient httpClient, string apiKey, Guid? sensorId = null, Guid? credentialId = null)
    {
        _httpClient = httpClient;
        _apiKey = apiKey;
        _sensorId = sensorId;
        _credentialId = credentialId;
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
            AddAuthenticationHeaders(httpRequest);
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

    public async Task<SubmitResult> SendHeartbeatAsync(int maxRetries, CancellationToken cancellationToken)
    {
        if (!_sensorId.HasValue || !_credentialId.HasValue)
            return SubmitResult.PermanentFailureResult();

        for (var attempt = 1; attempt <= maxRetries; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/sensors/heartbeat");
            AddAuthenticationHeaders(request);
            request.Content = JsonContent.Create(new { }, options: SerializerOptions);
            try
            {
                using var response = await _httpClient.SendAsync(request, cancellationToken);
                if (response.StatusCode == HttpStatusCode.NoContent)
                    return SubmitResult.AcceptedResult(created: true);
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

    public async Task RunHeartbeatLoopAsync(
        TimeSpan interval,
        int maxRetries,
        CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval);
        while (!cancellationToken.IsCancellationRequested)
        {
            var result = await SendHeartbeatAsync(maxRetries, cancellationToken);
            if (result.AuthFailure || result.PermanentFailure)
                return;
            if (!await timer.WaitForNextTickAsync(cancellationToken))
                return;
        }
    }

    private void AddAuthenticationHeaders(HttpRequestMessage request)
    {
        request.Headers.Add("X-ConShield-Api-Key", _apiKey);
        if (_sensorId.HasValue && _credentialId.HasValue)
        {
            request.Headers.Add("X-ConShield-Sensor-Id", _sensorId.Value.ToString("D"));
            request.Headers.Add("X-ConShield-Credential-Id", _credentialId.Value.ToString("D"));
        }
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
