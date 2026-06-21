using System.Text.Json;
using ConShield.Application;
using ConShield.Web.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace ConShield.Web.Controllers;

[ApiController]
[EnableRateLimiting("SensorHeartbeat")]
[ExternalEventIngestionEndpoint]
[Route("api/v1/sensors")]
public sealed class ApiV1SensorsController : ControllerBase
{
    private readonly ISensorIdentityService _sensorIdentityService;

    public ApiV1SensorsController(ISensorIdentityService sensorIdentityService)
    {
        _sensorIdentityService = sensorIdentityService;
    }

    [HttpPost("heartbeat")]
    public async Task<IActionResult> Heartbeat(
        [FromBody] JsonElement? payload,
        CancellationToken cancellationToken)
    {
        if (!payload.HasValue || payload.Value.ValueKind != JsonValueKind.Object)
            return BadRequest(new { error = "invalid_request" });

        if (!SensorRequestIdentity.TryRead(Request, out var sensorId, out var credentialId, out var credential))
            return Unauthorized(new { error = "unauthorized" });

        var identity = await _sensorIdentityService.AuthenticateAsync(
            sensorId,
            credentialId,
            credential,
            requiredSourceSystem: null,
            cancellationToken);
        if (identity is null
            || !await _sensorIdentityService.RecordHeartbeatAsync(identity, cancellationToken))
        {
            return Unauthorized(new { error = "unauthorized" });
        }

        return NoContent();
    }
}
