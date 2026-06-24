using ConShield.Application.Models;

namespace ConShield.Application;

public interface ISensorCredentialLifecycleService
{
    Task<SensorCredentialRotationResult> RotateCredentialAsync(
        Guid sensorId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken = default);

    Task<SensorCredentialRevocationResult> RevokeCredentialAsync(
        Guid sensorId,
        Guid credentialId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken = default);

    Task<SensorRevocationResult> RevokeSensorAsync(
        Guid sensorId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken = default);
}
