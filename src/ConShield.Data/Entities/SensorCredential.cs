namespace ConShield.Data.Entities;

public sealed class SensorCredential
{
    public long Id { get; set; }
    public Guid CredentialId { get; set; }
    public long SensorId { get; set; }
    public byte[] VerifierSha256 { get; set; } = Array.Empty<byte>();
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? RotatedAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    public Sensor Sensor { get; set; } = null!;
}
