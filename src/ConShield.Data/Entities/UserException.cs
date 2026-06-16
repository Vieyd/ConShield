namespace ConShield.Data.Entities;

public class UserException
{
    public int Id { get; set; }
    public string UserLogin { get; set; } = string.Empty;
    public string SourceSystem { get; set; } = string.Empty;
    public string ExceptionType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAtUtc { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
}
