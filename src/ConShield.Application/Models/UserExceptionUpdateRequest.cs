namespace ConShield.Application.Models;

public class UserExceptionUpdateRequest
{
    public int Id { get; set; }
    public string UserLogin { get; set; } = string.Empty;
    public string SourceSystem { get; set; } = string.Empty;
    public string ExceptionType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTime? ExpiresAtUtc { get; set; }
    public string ChangedBy { get; set; } = string.Empty;
}
