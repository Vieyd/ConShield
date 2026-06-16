namespace ConShield.Contracts.Models;

public class UserExceptionDto
{
    public int Id { get; set; }
    public string UserLogin { get; set; } = string.Empty;
    public string SourceSystem { get; set; } = string.Empty;
    public string ExceptionType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
}
