using ConShield.Application.Models;

namespace ConShield.Application;

public interface ISiemCorrelationService
{
    Task<CorrelationRunResult> RunAsync(CancellationToken cancellationToken = default);
}
