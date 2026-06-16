namespace ConShield.Application.Models;

public sealed class ExternalSecurityEventIngestResult
{
    public long SecurityEventId { get; init; }
    public bool Created { get; init; }

    public static ExternalSecurityEventIngestResult New(long securityEventId) => new()
    {
        SecurityEventId = securityEventId,
        Created = true
    };

    public static ExternalSecurityEventIngestResult Existing(long securityEventId) => new()
    {
        SecurityEventId = securityEventId,
        Created = false
    };
}
