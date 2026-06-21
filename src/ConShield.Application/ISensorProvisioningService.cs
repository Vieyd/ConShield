using ConShield.Application.Models;

namespace ConShield.Application;

public interface ISensorProvisioningService
{
    Task<SensorProvisioningResult> ProvisionAsync(
        SensorProvisioningRequest request,
        CancellationToken cancellationToken = default);
}
