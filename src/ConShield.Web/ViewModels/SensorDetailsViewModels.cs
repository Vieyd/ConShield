namespace ConShield.Web.ViewModels;

public sealed class SensorDetailsViewModel
{
    public Guid SensorId { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string SourceSystem { get; init; } = string.Empty;
    public DateTime? LastSeenAtUtc { get; init; }
    public DateTime CreatedAtUtc { get; init; }
    public DateTime UpdatedAtUtc { get; init; }
    public DateTime? RevokedAtUtc { get; init; }
    public bool HasCertificateFingerprint { get; init; }
    public string Status { get; init; } = string.Empty;
    public string StatusCssClass { get; init; } = string.Empty;
    public string HeartbeatAgeText { get; init; } = string.Empty;
    public bool CanRevokeSensor { get; init; }
    public IReadOnlyList<SensorCredentialDetailsViewModel> Credentials { get; init; } = [];

    public static SensorDetailsViewModel Create(
        Guid sensorId,
        string displayName,
        string sourceSystem,
        DateTime? lastSeenAtUtc,
        DateTime createdAtUtc,
        DateTime updatedAtUtc,
        DateTime? revokedAtUtc,
        bool hasCertificateFingerprint,
        IEnumerable<SensorCredentialDetailsViewModel> credentials,
        DateTime nowUtc)
    {
        var (status, cssClass) = SensorFleetItemViewModel.CalculateStatus(lastSeenAtUtc, revokedAtUtc, nowUtc);

        return new SensorDetailsViewModel
        {
            SensorId = sensorId,
            DisplayName = displayName,
            SourceSystem = sourceSystem,
            LastSeenAtUtc = lastSeenAtUtc,
            CreatedAtUtc = createdAtUtc,
            UpdatedAtUtc = updatedAtUtc,
            RevokedAtUtc = revokedAtUtc,
            HasCertificateFingerprint = hasCertificateFingerprint,
            Status = status,
            StatusCssClass = cssClass,
            HeartbeatAgeText = SensorFleetItemViewModel.FormatHeartbeatAge(lastSeenAtUtc, nowUtc),
            CanRevokeSensor = revokedAtUtc is null,
            Credentials = credentials.ToArray()
        };
    }
}

public sealed class SensorCredentialDetailsViewModel
{
    public Guid CredentialId { get; init; }
    public DateTime CreatedAtUtc { get; init; }
    public DateTime? RotatedAtUtc { get; init; }
    public DateTime? RevokedAtUtc { get; init; }
    public string Status { get; init; } = string.Empty;
    public string StatusCssClass { get; init; } = string.Empty;
    public bool CanRevokeCredential { get; init; }

    public static SensorCredentialDetailsViewModel Create(
        Guid credentialId,
        DateTime createdAtUtc,
        DateTime? rotatedAtUtc,
        DateTime? revokedAtUtc)
    {
        var (status, cssClass) = CalculateStatus(rotatedAtUtc, revokedAtUtc);

        return new SensorCredentialDetailsViewModel
        {
            CredentialId = credentialId,
            CreatedAtUtc = createdAtUtc,
            RotatedAtUtc = rotatedAtUtc,
            RevokedAtUtc = revokedAtUtc,
            Status = status,
            StatusCssClass = cssClass,
            CanRevokeCredential = rotatedAtUtc is null && revokedAtUtc is null
        };
    }

    public static (string Status, string CssClass) CalculateStatus(DateTime? rotatedAtUtc, DateTime? revokedAtUtc)
    {
        if (revokedAtUtc is not null)
            return ("Revoked", "bg-secondary");

        if (rotatedAtUtc is not null)
            return ("Rotated", "bg-warning text-dark");

        return ("Active", "bg-success");
    }
}
