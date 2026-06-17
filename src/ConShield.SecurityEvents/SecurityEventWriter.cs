using System.Text.Json;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore.Storage;

namespace ConShield.SecurityEvents;

public class SecurityEventWriter : ISecurityEventWriter
{
    public const string SecurityEventCreatedMessageType = "security.event.created";
    private const int EnvelopeSchemaVersion = 1;
    private const int MaxEnvelopeBytes = 65536;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly ApplicationDbContext _dbContext;

    public SecurityEventWriter(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default)
    {
        var messageId = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var additionalDataJson = request.AdditionalData is null
            ? null
            : JsonSerializer.Serialize(request.AdditionalData, SerializerOptions);

        var entry = new SecurityEventEntry
        {
            OccurredAtUtc = EnsureUtc(request.OccurredAtUtc ?? now),
            EventType = request.EventType,
            Severity = request.Severity,
            Description = request.Description,
            UserName = request.UserName,
            SourceIp = request.SourceIp,
            ExternalEventId = request.ExternalEventId,
            SourceSystem = request.SourceSystem,
            ExternalEventType = request.ExternalEventType,
            SourceHost = request.SourceHost,
            AdditionalDataJson = additionalDataJson
        };

        var ownedTransaction = _dbContext.Database.CurrentTransaction is null
            ? await _dbContext.Database.BeginTransactionAsync(cancellationToken)
            : null;
        try
        {
            _dbContext.SecurityEvents.Add(entry);
            await _dbContext.SaveChangesAsync(cancellationToken);

            var payloadJson = BuildEnvelopeJson(messageId, now, entry, additionalDataJson);
            if (System.Text.Encoding.UTF8.GetByteCount(payloadJson) > MaxEnvelopeBytes)
                throw new InvalidOperationException("Security event outbox envelope exceeded the maximum allowed size.");

            _dbContext.SecurityEventOutboxMessages.Add(new SecurityEventOutboxMessage
            {
                MessageId = messageId,
                SecurityEventId = entry.Id,
                MessageType = SecurityEventCreatedMessageType,
                SchemaVersion = EnvelopeSchemaVersion,
                PayloadJson = payloadJson,
                Status = SecurityEventOutboxStatus.Pending,
                CreatedAtUtc = now,
                AvailableAtUtc = now
            });

            await _dbContext.SaveChangesAsync(cancellationToken);

            if (ownedTransaction is not null)
                await ownedTransaction.CommitAsync(cancellationToken);
        }
        catch
        {
            if (ownedTransaction is not null)
                await RollBackQuietlyAsync(ownedTransaction);

            throw;
        }
        finally
        {
            if (ownedTransaction is not null)
                await ownedTransaction.DisposeAsync();
        }
    }

    private static string BuildEnvelopeJson(
        Guid messageId,
        DateTime createdAtUtc,
        SecurityEventEntry entry,
        string? additionalDataJson)
    {
        using var additionalDataDocument = TryParseObject(additionalDataJson);
        var additionalData = additionalDataDocument?.RootElement.Clone();
        var envelope = new SecurityEventEnvelope(
            SchemaVersion: EnvelopeSchemaVersion,
            MessageId: messageId,
            MessageType: SecurityEventCreatedMessageType,
            CreatedAtUtc: EnsureUtc(createdAtUtc),
            SecurityEvent: new SecurityEventEnvelopeData(
                Id: entry.Id,
                OccurredAtUtc: EnsureUtc(entry.OccurredAtUtc),
                EventType: entry.EventType.ToString(),
                Severity: entry.Severity.ToString(),
                UserName: entry.UserName,
                SourceIp: entry.SourceIp,
                ExternalEventId: entry.ExternalEventId,
                SourceSystem: entry.SourceSystem,
                ExternalEventType: entry.ExternalEventType,
                SourceHost: entry.SourceHost,
                Description: entry.Description,
                AdditionalData: additionalData));

        return JsonSerializer.Serialize(envelope, SerializerOptions);
    }

    private static JsonDocument? TryParseObject(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;

        var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            return null;
        }

        return document;
    }

    private static DateTime EnsureUtc(DateTime value)
    {
        if (value.Kind == DateTimeKind.Utc)
            return value;

        return DateTime.SpecifyKind(value, DateTimeKind.Utc);
    }

    private static async Task RollBackQuietlyAsync(IDbContextTransaction transaction)
    {
        try
        {
            await transaction.RollbackAsync();
        }
        catch
        {
        }
    }
}

internal sealed record SecurityEventEnvelope(
    int SchemaVersion,
    Guid MessageId,
    string MessageType,
    DateTime CreatedAtUtc,
    SecurityEventEnvelopeData SecurityEvent);

internal sealed record SecurityEventEnvelopeData(
    long Id,
    DateTime OccurredAtUtc,
    string EventType,
    string Severity,
    string? UserName,
    string? SourceIp,
    Guid? ExternalEventId,
    string? SourceSystem,
    string? ExternalEventType,
    string? SourceHost,
    string Description,
    JsonElement? AdditionalData);
