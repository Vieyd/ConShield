using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Web.Options;
using ConShield.Web.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace ConShield.Web.Controllers;

[ApiController]
[EnableRateLimiting("ExternalEventIngestion")]
[Route("api/v1/security-events")]
public sealed class ApiV1SecurityEventsController : ControllerBase
{
    private const string ApiKeyHeader = "X-ConShield-Api-Key";

    private readonly IExternalSecurityEventIngestionService _ingestionService;
    private readonly IOptions<ExternalEventIngestionOptions> _options;

    public ApiV1SecurityEventsController(
        IExternalSecurityEventIngestionService ingestionService,
        IOptions<ExternalEventIngestionOptions> options)
    {
        _ingestionService = ingestionService;
        _options = options;
    }

    [HttpPost]
    public async Task<IActionResult> Post(
        [FromBody] ExternalSecurityEventIngestRequest? request,
        CancellationToken cancellationToken)
    {
        var options = _options.Value;
        if (!options.Enabled)
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "external_event_ingestion_disabled" });

        var providedApiKey = Request.Headers[ApiKeyHeader].FirstOrDefault();
        if (!ExternalEventApiKeyValidator.IsValid(providedApiKey, options.ApiKey))
            return Unauthorized(new { error = "unauthorized" });

        if (request is null)
            return BadRequest(new { error = "invalid_request" });

        var validation = _ingestionService.Validate(
            request,
            TimeSpan.FromMinutes(Math.Max(0, options.AllowedFutureClockSkewMinutes)));

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

        return result.Created
            ? Created($"/api/v1/security-events/{result.SecurityEventId}", response)
            : Ok(response);
    }
}
