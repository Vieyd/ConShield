using ConShield.Application.Models;

namespace ConShield.Application;

public interface ISensorIdentityService
{
    Task<AuthenticatedSensorIdentity?> AuthenticateAsync(
        Guid sensorId,
        Guid credentialId,
        string? credential,
        string? requiredSourceSystem,
        CancellationToken cancellationToken = default);

    Task<bool> RecordHeartbeatAsync(
        AuthenticatedSensorIdentity identity,
        CancellationToken cancellationToken = default);
}
