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
        if (request is null)
            return BadRequest(new { error = "invalid_request" });

        var providedApiKey = Request.Headers["X-ConShield-Api-Key"].FirstOrDefault();
        var expectedApiKey = string.Equals(
            request.SourceSystem?.Trim(),
            SecuritySourceSystems.FalcoRuntimeCollector,
            StringComparison.Ordinal)
            ? _options.Value.RuntimeCollectorApiKey
            : _options.Value.ApiKey;
        if (!ExternalEventApiKeyValidator.IsValid(providedApiKey, expectedApiKey))
            return Unauthorized(new { error = "unauthorized" });

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
