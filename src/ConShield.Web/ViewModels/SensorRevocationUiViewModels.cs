using ConShield.Application.Models;

namespace ConShield.Web.ViewModels;

public sealed class SensorRevocationUiResultViewModel
{
    public string Action { get; init; } = string.Empty;
    public Guid SensorId { get; init; }
    public Guid? CredentialId { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string SourceSystem { get; init; } = string.Empty;
    public DateTime RevokedAtUtc { get; init; }
    public int? RevokedCredentialCount { get; init; }
    public bool WasAlreadyRevoked { get; init; }

    public static SensorRevocationUiResultViewModel FromCredential(SensorCredentialRevocationResult result) =>
        new()
        {
            Action = "Credential revoked",
            SensorId = result.SensorId,
            CredentialId = result.CredentialId,
            DisplayName = result.DisplayName,
            SourceSystem = result.SourceSystem,
            RevokedAtUtc = result.RevokedAtUtc,
            WasAlreadyRevoked = result.WasAlreadyRevoked
        };

    public static SensorRevocationUiResultViewModel FromSensor(SensorRevocationResult result) =>
        new()
        {
            Action = "Sensor revoked",
            SensorId = result.SensorId,
            DisplayName = result.DisplayName,
            SourceSystem = result.SourceSystem,
            RevokedAtUtc = result.RevokedAtUtc,
            RevokedCredentialCount = result.RevokedCredentialCount,
            WasAlreadyRevoked = result.WasAlreadyRevoked
        };
}

public sealed class SensorRevocationFailureViewModel
{
    public Guid SensorId { get; init; }
    public Guid? CredentialId { get; init; }
    public string Message { get; init; } = string.Empty;
}
