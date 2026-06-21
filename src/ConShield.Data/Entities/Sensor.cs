namespace ConShield.Data.Entities;

public sealed class Sensor
{
    public long Id { get; set; }
    public Guid SensorId { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public string SourceSystem { get; set; } = string.Empty;
    public DateTime? LastSeenAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    public string? CertificateFingerprintSha256 { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    public ICollection<SensorCredential> Credentials { get; set; } = new List<SensorCredential>();
}
