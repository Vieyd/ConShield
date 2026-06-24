namespace ConShield.Application.Models;

public sealed record SensorCredentialRotationResult(
    Guid SensorId,
    Guid CredentialId,
    string Credential,
    string DisplayName,
    string SourceSystem,
    DateTime RotatedAtUtc);
