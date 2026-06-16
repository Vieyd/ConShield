using System.Text.Json;
using ConShield.Application.Models;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Application;

public sealed class ExternalSecurityEventIngestionService : IExternalSecurityEventIngestionService
{
    public const int SourceSystemMaxLength = 128;
    public const int EventTypeMaxLength = 128;
    public const int UserNameMaxLength = 128;
    public const int SourceHostMaxLength = 256;
    public const int DescriptionMaxLength = 2000;

    private readonly ApplicationDbContext _dbContext;
    private readonly ISecurityEventWriter _eventWriter;

    public ExternalSecurityEventIngestionService(ApplicationDbContext dbContext, ISecurityEventWriter eventWriter)
    {
        _dbContext = dbContext;
        _eventWriter = eventWriter;
    }

    public ExternalSecurityEventValidationResult Validate(
        ExternalSecurityEventIngestRequest request,
        TimeSpan allowedFutureClockSkew)
    {
        var result = new ExternalSecurityEventValidationResult();

        if (request.ExternalEventId == Guid.Empty)
            result.Add(nameof(request.ExternalEventId), "externalEventId is required.");

        if (request.OccurredAtUtc.Kind != DateTimeKind.Utc)
            result.Add(nameof(request.OccurredAtUtc), "occurredAtUtc must be a UTC timestamp.");

        if (request.OccurredAtUtc > DateTime.UtcNow.Add(allowedFutureClockSkew))
            result.Add(nameof(request.OccurredAtUtc), "occurredAtUtc is too far in the future.");

        ValidateRequiredString(result, nameof(request.SourceSystem), request.SourceSystem, 1, SourceSystemMaxLength);
        ValidateRequiredString(result, nameof(request.EventType), request.EventType, 1, EventTypeMaxLength);
        ValidateRequiredString(result, nameof(request.Description), request.Description, 1, DescriptionMaxLength);
        ValidateOptionalString(result, nameof(request.UserName), request.UserName, UserNameMaxLength);
        ValidateOptionalString(result, nameof(request.SourceHost), request.SourceHost, SourceHostMaxLength);

        if (!TryParsePublishedSeverity(request.Severity, out _))
            result.Add(nameof(request.Severity), "severity is not supported.");

        if (request.AdditionalData.HasValue && request.AdditionalData.Value.ValueKind != JsonValueKind.Object)
            result.Add(nameof(request.AdditionalData), "additionalData must be a JSON object.");

        return result;
    }

    public async Task<ExternalSecurityEventIngestResult> IngestAsync(
        ExternalSecurityEventIngestRequest request,
        string? transportIp,
        CancellationToken cancellationToken = default)
    {
        var sourceSystem = request.SourceSystem.Trim();
        var existing = await FindExistingAsync(sourceSystem, request.ExternalEventId, cancellationToken);
        if (existing is not null)
            return ExternalSecurityEventIngestResult.Existing(existing.Id);

        if (!TryParsePublishedSeverity(request.Severity, out var severity))
            throw new InvalidOperationException("External event severity was not validated before ingest.");

        try
        {
            await _eventWriter.WriteAsync(new SecurityEventWriteRequest
            {
                OccurredAtUtc = DateTime.SpecifyKind(request.OccurredAtUtc, DateTimeKind.Utc),
                EventType = SecurityEventType.ExternalEvent,
                Severity = severity,
                UserName = NormalizeOptional(request.UserName),
                SourceIp = NormalizeOptional(transportIp),
                ExternalEventId = request.ExternalEventId,
                SourceSystem = sourceSystem,
                ExternalEventType = request.EventType.Trim(),
                SourceHost = NormalizeOptional(request.SourceHost),
                Description = request.Description.Trim(),
                AdditionalData = request.AdditionalData.HasValue
                    ? JsonSerializer.Deserialize<object>(request.AdditionalData.Value.GetRawText())
                    : null
            }, cancellationToken);
        }
        catch (DbUpdateException)
        {
            var duplicate = await FindExistingAsync(sourceSystem, request.ExternalEventId, cancellationToken);
            if (duplicate is not null)
                return ExternalSecurityEventIngestResult.Existing(duplicate.Id);

            throw;
        }

        var created = await FindExistingAsync(sourceSystem, request.ExternalEventId, cancellationToken)
            ?? throw new InvalidOperationException("External security event was not found after write.");

        return ExternalSecurityEventIngestResult.New(created.Id);
    }

    private async Task<Data.Entities.SecurityEventEntry?> FindExistingAsync(
        string sourceSystem,
        Guid externalEventId,
        CancellationToken cancellationToken)
    {
        return await _dbContext.SecurityEvents
            .FirstOrDefaultAsync(x => x.SourceSystem == sourceSystem && x.ExternalEventId == externalEventId, cancellationToken);
    }

    private static void ValidateRequiredString(
        ExternalSecurityEventValidationResult result,
        string field,
        string? value,
        int minLength,
        int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            result.Add(field, $"{field} is required.");
            return;
        }

        var length = value.Trim().Length;
        if (length < minLength || length > maxLength)
            result.Add(field, $"{field} length must be between {minLength} and {maxLength}.");
    }

    private static void ValidateOptionalString(
        ExternalSecurityEventValidationResult result,
        string field,
        string? value,
        int maxLength)
    {
        if (value is not null && value.Trim().Length > maxLength)
            result.Add(field, $"{field} length must be at most {maxLength}.");
    }

    private static string? NormalizeOptional(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static bool TryParsePublishedSeverity(string? value, out EventSeverity severity)
    {
        severity = default;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        return Enum.TryParse(value.Trim(), ignoreCase: true, out severity)
            && Enum.IsDefined(severity)
            && !int.TryParse(value.Trim(), out _);
    }
}
