using ConShield.Application.Models;

namespace ConShield.Application;

public interface IRuntimeSensorHealthService
{
    Task<RuntimeSensorHealthResult> GetAsync(
        RuntimeSensorHealthOptions? options = null,
        CancellationToken cancellationToken = default);
}
