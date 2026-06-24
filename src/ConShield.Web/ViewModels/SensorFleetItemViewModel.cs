namespace ConShield.Web.ViewModels;

public sealed class SensorFleetItemViewModel
{
    public Guid SensorId { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string SourceSystem { get; init; } = string.Empty;
    public DateTime? LastSeenAtUtc { get; init; }
    public DateTime CreatedAtUtc { get; init; }
    public DateTime UpdatedAtUtc { get; init; }
    public DateTime? RevokedAtUtc { get; init; }
    public bool HasCertificateFingerprint { get; init; }
    public int CredentialCount { get; init; }
    public int ActiveCredentialCount { get; init; }
    public DateTime? OldestCredentialCreatedAtUtc { get; init; }
    public DateTime? NewestCredentialCreatedAtUtc { get; init; }
    public string Status { get; init; } = string.Empty;
    public string StatusCssClass { get; init; } = string.Empty;
    public string HeartbeatAgeText { get; init; } = string.Empty;

    public static SensorFleetItemViewModel Create(
        Guid sensorId,
        string displayName,
        string sourceSystem,
        DateTime? lastSeenAtUtc,
        DateTime createdAtUtc,
        DateTime updatedAtUtc,
        DateTime? revokedAtUtc,
        bool hasCertificateFingerprint,
        int credentialCount,
        int activeCredentialCount,
        DateTime? oldestCredentialCreatedAtUtc,
        DateTime? newestCredentialCreatedAtUtc,
        DateTime nowUtc)
    {
        var (status, cssClass) = CalculateStatus(lastSeenAtUtc, revokedAtUtc, nowUtc);

        return new SensorFleetItemViewModel
        {
            SensorId = sensorId,
            DisplayName = displayName,
            SourceSystem = sourceSystem,
            LastSeenAtUtc = lastSeenAtUtc,
            CreatedAtUtc = createdAtUtc,
            UpdatedAtUtc = updatedAtUtc,
            RevokedAtUtc = revokedAtUtc,
            HasCertificateFingerprint = hasCertificateFingerprint,
            CredentialCount = credentialCount,
            ActiveCredentialCount = activeCredentialCount,
            OldestCredentialCreatedAtUtc = oldestCredentialCreatedAtUtc,
            NewestCredentialCreatedAtUtc = newestCredentialCreatedAtUtc,
            Status = status,
            StatusCssClass = cssClass,
            HeartbeatAgeText = FormatHeartbeatAge(lastSeenAtUtc, nowUtc)
        };
    }

    public static (string Status, string CssClass) CalculateStatus(
        DateTime? lastSeenAtUtc,
        DateTime? revokedAtUtc,
        DateTime nowUtc)
    {
        if (revokedAtUtc is not null)
            return ("Revoked", "bg-secondary");

        if (lastSeenAtUtc is null)
            return ("Never seen", "bg-info text-dark");

        var age = nowUtc - lastSeenAtUtc.Value;
        if (age < TimeSpan.Zero)
            age = TimeSpan.Zero;

        if (age <= TimeSpan.FromMinutes(2))
            return ("Online", "bg-success");

        if (age <= TimeSpan.FromMinutes(5))
            return ("Warning", "bg-warning text-dark");

        return ("Offline", "bg-danger");
    }

    public static string FormatHeartbeatAge(DateTime? lastSeenAtUtc, DateTime nowUtc)
    {
        if (lastSeenAtUtc is null)
            return "—";

        var age = nowUtc - lastSeenAtUtc.Value;
        if (age < TimeSpan.Zero)
            age = TimeSpan.Zero;

        if (age < TimeSpan.FromMinutes(1))
            return $"{Math.Max(0, (int)age.TotalSeconds)}s";

        if (age < TimeSpan.FromHours(1))
            return $"{(int)age.TotalMinutes}m";

        if (age < TimeSpan.FromDays(1))
            return $"{(int)age.TotalHours}h";

        return $"{(int)age.TotalDays}d";
    }
}
