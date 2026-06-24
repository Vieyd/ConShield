using ConShield.Application.Models;

namespace ConShield.Application;

public interface ISensorCredentialLifecycleService
{
    Task<SensorCredentialRotationResult> RotateCredentialAsync(
        Guid sensorId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken = default);
}
