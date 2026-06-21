using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Web.Options;
using ConShield.Web.Security;
using ConShield.Contracts.Constants;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace ConShield.Web.Controllers;

[ApiController]
[EnableRateLimiting("ExternalEventIngestion")]
[ExternalEventIngestionEndpoint]
[Route("api/v1/security-events")]
public sealed class ApiV1SecurityEventsController : ControllerBase
{
    private readonly IExternalSecurityEventIngestionService _ingestionService;
    private readonly IOptions<ExternalEventIngestionOptions> _options;
    private readonly ISensorIdentityService _sensorIdentityService;

    public ApiV1SecurityEventsController(
        IExternalSecurityEventIngestionService ingestionService,
        IOptions<ExternalEventIngestionOptions> options,
        ISensorIdentityService sensorIdentityService)
    {
        _ingestionService = ingestionService;
        _options = options;
        _sensorIdentityService = sensorIdentityService;
    }

    [HttpPost]
    public async Task<IActionResult> Post(
        [FromBody] ExternalSecurityEventIngestRequest? request,
        CancellationToken cancellationToken)
    {
        if (request is null)
            return BadRequest(new { error = "invalid_request" });

        var providedApiKey = Request.Headers[SensorRequestIdentity.ApiKeyHeader].FirstOrDefault();
        if (SensorRequestIdentity.HasAnySensorHeader(Request))
        {
            if (!SensorRequestIdentity.TryRead(Request, out var sensorId, out var credentialId, out var credential)
                || await _sensorIdentityService.AuthenticateAsync(
                    sensorId,
                    credentialId,
                    credential,
                    request.SourceSystem,
                    cancellationToken) is null)
            {
                return Unauthorized(new { error = "unauthorized" });
            }
        }
        else
        {
            var isRuntimeSource = string.Equals(
                request.SourceSystem?.Trim(),
                SecuritySourceSystems.FalcoRuntimeCollector,
                StringComparison.Ordinal);
            var expectedApiKey = isRuntimeSource
                ? _options.Value.AllowLegacyRuntimeCollectorCredential
                    ? _options.Value.RuntimeCollectorApiKey
                    : string.Empty
                : _options.Value.ApiKey;
            if (!ExternalEventApiKeyValidator.IsValid(providedApiKey, expectedApiKey))
                return Unauthorized(new { error = "unauthorized" });
        }

        var validation = _ingestionService.Validate(
            request,
            TimeSpan.FromMinutes(Math.Max(0, _options.Value.AllowedFutureClockSkewMinutes)));

        if (!validation.IsValid)
            return BadRequest(new { error = "validation_failed", errors = validation.Errors });

        var result = await _ingestionService.IngestAsync(
            request,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);

        var response = new
        {
            securityEventId = result.SecurityEventId,
            created = result.Created
        };

        return result.Created ? StatusCode(StatusCodes.Status201Created, response) : Ok(response);
    }
}
