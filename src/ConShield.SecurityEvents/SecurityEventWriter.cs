using System.Text.Json;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents.Models;

namespace ConShield.SecurityEvents;

public class SecurityEventWriter : ISecurityEventWriter
{
    private readonly ApplicationDbContext _dbContext;
    private readonly string _logDirectory;

    public SecurityEventWriter(ApplicationDbContext dbContext, string contentRootPath)
    {
        _dbContext = dbContext;
        _logDirectory = Path.Combine(contentRootPath, "logs");
    }

    public async Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default)
    {
        var entry = new SecurityEventEntry
        {
            OccurredAtUtc = request.OccurredAtUtc ?? DateTime.UtcNow,
            EventType = request.EventType,
            Severity = request.Severity,
            Description = request.Description,
            UserName = request.UserName,
            SourceIp = request.SourceIp,
            ExternalEventId = request.ExternalEventId,
            SourceSystem = request.SourceSystem,
            ExternalEventType = request.ExternalEventType,
            SourceHost = request.SourceHost,
            AdditionalDataJson = request.AdditionalData is null
                ? null
                : JsonSerializer.Serialize(request.AdditionalData)
        };

        _dbContext.SecurityEvents.Add(entry);
        await _dbContext.SaveChangesAsync(cancellationToken);

        Directory.CreateDirectory(_logDirectory);

        var line = JsonSerializer.Serialize(new
        {
            entry.Id,
            entry.OccurredAtUtc,
            entry.EventType,
            entry.Severity,
            entry.UserName,
            entry.SourceIp,
            entry.ExternalEventId,
            entry.SourceSystem,
            entry.ExternalEventType,
            entry.SourceHost,
            entry.Description,
            entry.AdditionalDataJson
        });

        await File.AppendAllTextAsync(
            Path.Combine(_logDirectory, "security-events.jsonl"),
            line + Environment.NewLine,
            cancellationToken);
    }
}
