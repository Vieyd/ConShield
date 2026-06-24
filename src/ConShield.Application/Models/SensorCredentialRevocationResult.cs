namespace ConShield.Application.Models;

public sealed record SensorCredentialRevocationResult(
    Guid SensorId,
    Guid CredentialId,
    string DisplayName,
    string SourceSystem,
    DateTime RevokedAtUtc,
    bool WasAlreadyRevoked);
