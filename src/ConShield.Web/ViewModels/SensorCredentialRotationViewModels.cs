using ConShield.Application.Models;

namespace ConShield.Web.ViewModels;

public sealed class SensorCredentialRotationResultViewModel
{
    public Guid SensorId { get; init; }
    public Guid CredentialId { get; init; }
    public string OneTimeCredential { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string SourceSystem { get; init; } = string.Empty;
    public DateTime RotatedAtUtc { get; init; }

    public static SensorCredentialRotationResultViewModel From(SensorCredentialRotationResult result) =>
        new()
        {
            SensorId = result.SensorId,
            CredentialId = result.CredentialId,
            OneTimeCredential = result.Credential,
            DisplayName = result.DisplayName,
            SourceSystem = result.SourceSystem,
            RotatedAtUtc = result.RotatedAtUtc
        };
}

public sealed class SensorCredentialRotationFailureViewModel
{
    public Guid SensorId { get; init; }
    public string Message { get; init; } = string.Empty;
}
