using System.Text.Json;

namespace ConShield.Application.Models;

public sealed class ExternalSecurityEventIngestRequest
{
    public Guid ExternalEventId { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    public string SourceSystem { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string? UserName { get; set; }
    public string? SourceHost { get; set; }
    public string Description { get; set; } = string.Empty;
    public JsonElement? AdditionalData { get; set; }
}
