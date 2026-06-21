namespace ConShield.Application.Models;

public sealed record AuthenticatedSensorIdentity(
    long SensorRecordId,
    long CredentialRecordId,
    Guid SensorId,
    Guid CredentialId,
    string SourceSystem);
