using ConShield.SecurityEvents.Models;

namespace ConShield.SecurityEvents;

public interface ISecurityEventWriter
{
    Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default);
}
