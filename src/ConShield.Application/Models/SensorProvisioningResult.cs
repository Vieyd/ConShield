namespace ConShield.Application.Models;

public sealed record SensorProvisioningResult(
    Guid SensorId,
    Guid CredentialId,
    string Credential,
    int HeartbeatIntervalSeconds);
