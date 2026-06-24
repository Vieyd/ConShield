namespace ConShield.Application.Models;

public sealed record SensorRevocationResult(
    Guid SensorId,
    string DisplayName,
    string SourceSystem,
    DateTime RevokedAtUtc,
    int RevokedCredentialCount,
    bool WasAlreadyRevoked);
