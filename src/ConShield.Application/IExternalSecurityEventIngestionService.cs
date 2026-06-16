using ConShield.Application.Models;

namespace ConShield.Application;

public interface IExternalSecurityEventIngestionService
{
    ExternalSecurityEventValidationResult Validate(
        ExternalSecurityEventIngestRequest request,
        TimeSpan allowedFutureClockSkew);

    Task<ExternalSecurityEventIngestResult> IngestAsync(
        ExternalSecurityEventIngestRequest request,
        string? transportIp,
        CancellationToken cancellationToken = default);
}
