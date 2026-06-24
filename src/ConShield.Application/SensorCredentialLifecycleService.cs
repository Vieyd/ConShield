using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace ConShield.Application;

public sealed class SensorCredentialLifecycleService : ISensorCredentialLifecycleService
{
    private const int RequestedByMaxLength = 256;
    private readonly ApplicationDbContext _dbContext;
    private readonly ISecurityEventWriter _eventWriter;

    public SensorCredentialLifecycleService(ApplicationDbContext dbContext, ISecurityEventWriter eventWriter)
    {
        _dbContext = dbContext;
        _eventWriter = eventWriter;
    }

    public async Task<SensorCredentialRotationResult> RotateCredentialAsync(
        Guid sensorId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken = default)
    {
        if (sensorId == Guid.Empty)
            throw new SensorCredentialLifecycleException("Sensor was not found.");

        var normalizedRequestedBy = NormalizeRequestedBy(requestedBy);
        var reasonProvided = IsReasonProvided(reason);

        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var sensor = await _dbContext.Sensors
            .Include(x => x.Credentials)
            .SingleOrDefaultAsync(x => x.SensorId == sensorId, cancellationToken);

        if (sensor is null)
            throw new SensorCredentialLifecycleException("Sensor was not found.");

        if (sensor.RevokedAtUtc is not null)
            throw new SensorCredentialLifecycleException("Sensor is revoked.");

        var now = DateTime.UtcNow;
        foreach (var credential in sensor.Credentials.Where(x => x.RotatedAtUtc is null && x.RevokedAtUtc is null))
            credential.RotatedAtUtc = now;

        var secret = SensorCredentialSecret.Create();
        var newCredential = new SensorCredential
        {
            CredentialId = Guid.NewGuid(),
            VerifierSha256 = secret.VerifierSha256,
            CreatedAtUtc = now
        };
        sensor.Credentials.Add(newCredential);
        sensor.UpdatedAtUtc = now;

        await _dbContext.SaveChangesAsync(cancellationToken);
        await WriteLifecycleAuditEventAsync(
            SensorLifecycleEventTypes.SensorCredentialRotated,
            $"Sensor credential rotated for {sensor.DisplayName}.",
            "rotateCredential",
            sensor,
            newCredential.CredentialId,
            normalizedRequestedBy,
            reasonProvided,
            now,
            revokedCredentialCount: null,
            cancellationToken);

        if (transaction is not null)
            await transaction.CommitAsync(cancellationToken);

        return new SensorCredentialRotationResult(
            sensor.SensorId,
            newCredential.CredentialId,
            secret.Credential,
            sensor.DisplayName,
            sensor.SourceSystem,
            now);
    }

    public async Task<SensorCredentialRevocationResult> RevokeCredentialAsync(
        Guid sensorId,
        Guid credentialId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken = default)
    {
        if (sensorId == Guid.Empty)
            throw new SensorCredentialLifecycleException("Sensor was not found.");
        if (credentialId == Guid.Empty)
            throw new SensorCredentialLifecycleException("Credential was not found.");

        var normalizedRequestedBy = NormalizeRequestedBy(requestedBy);
        var reasonProvided = IsReasonProvided(reason);

        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var sensor = await _dbContext.Sensors
            .Include(x => x.Credentials)
            .SingleOrDefaultAsync(x => x.SensorId == sensorId, cancellationToken);

        if (sensor is null)
            throw new SensorCredentialLifecycleException("Sensor was not found.");

        var credential = sensor.Credentials.SingleOrDefault(x => x.CredentialId == credentialId);
        if (credential is null)
            throw new SensorCredentialLifecycleException("Credential was not found.");

        var wasAlreadyRevoked = credential.RevokedAtUtc is not null;
        var revokedAtUtc = credential.RevokedAtUtc ?? DateTime.UtcNow;
        if (!wasAlreadyRevoked)
        {
            credential.RevokedAtUtc = revokedAtUtc;
            sensor.UpdatedAtUtc = revokedAtUtc;
            await _dbContext.SaveChangesAsync(cancellationToken);
            await WriteLifecycleAuditEventAsync(
                SensorLifecycleEventTypes.SensorCredentialRevoked,
                $"Sensor credential revoked for {sensor.DisplayName}.",
                "revokeCredential",
                sensor,
                credential.CredentialId,
                normalizedRequestedBy,
                reasonProvided,
                revokedAtUtc,
                revokedCredentialCount: null,
                cancellationToken);
        }

        if (transaction is not null)
            await transaction.CommitAsync(cancellationToken);

        return new SensorCredentialRevocationResult(
            sensor.SensorId,
            credential.CredentialId,
            sensor.DisplayName,
            sensor.SourceSystem,
            revokedAtUtc,
            wasAlreadyRevoked);
    }

    public async Task<SensorRevocationResult> RevokeSensorAsync(
        Guid sensorId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken = default)
    {
        if (sensorId == Guid.Empty)
            throw new SensorCredentialLifecycleException("Sensor was not found.");

        var normalizedRequestedBy = NormalizeRequestedBy(requestedBy);
        var reasonProvided = IsReasonProvided(reason);

        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var sensor = await _dbContext.Sensors
            .Include(x => x.Credentials)
            .SingleOrDefaultAsync(x => x.SensorId == sensorId, cancellationToken);

        if (sensor is null)
            throw new SensorCredentialLifecycleException("Sensor was not found.");

        var wasAlreadyRevoked = sensor.RevokedAtUtc is not null;
        var revokedAtUtc = sensor.RevokedAtUtc ?? DateTime.UtcNow;
        var credentialsRevoked = 0;

        if (!wasAlreadyRevoked)
        {
            sensor.RevokedAtUtc = revokedAtUtc;
            sensor.UpdatedAtUtc = revokedAtUtc;
        }

        foreach (var credential in sensor.Credentials.Where(x => x.RevokedAtUtc is null))
        {
            credential.RevokedAtUtc = revokedAtUtc;
            credentialsRevoked++;
        }

        if (!wasAlreadyRevoked || credentialsRevoked > 0)
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
            await WriteLifecycleAuditEventAsync(
                SensorLifecycleEventTypes.SensorRevoked,
                $"Sensor revoked for {sensor.DisplayName}.",
                "revokeSensor",
                sensor,
                credentialId: null,
                normalizedRequestedBy,
                reasonProvided,
                revokedAtUtc,
                credentialsRevoked,
                cancellationToken);
        }

        if (transaction is not null)
            await transaction.CommitAsync(cancellationToken);

        return new SensorRevocationResult(
            sensor.SensorId,
            sensor.DisplayName,
            sensor.SourceSystem,
            revokedAtUtc,
            credentialsRevoked,
            wasAlreadyRevoked);
    }

    private async Task<IDbContextTransaction?> BeginTransactionAsync(CancellationToken cancellationToken) =>
        _dbContext.Database.IsRelational()
            ? await _dbContext.Database.BeginTransactionAsync(cancellationToken)
            : null;

    private Task WriteLifecycleAuditEventAsync(
        string externalEventType,
        string description,
        string action,
        Sensor sensor,
        Guid? credentialId,
        string requestedBy,
        bool reasonProvided,
        DateTime occurredAtUtc,
        int? revokedCredentialCount,
        CancellationToken cancellationToken)
    {
        object additionalData = credentialId is null
            ? new
            {
                sensorId = sensor.SensorId,
                sensor.DisplayName,
                sourceSystem = sensor.SourceSystem,
                lifecycleSourceSystem = SecuritySourceSystems.SensorLifecycle,
                requestedBy,
                action,
                reasonProvided,
                revokedCredentialCount
            }
            : new
            {
                sensorId = sensor.SensorId,
                credentialId,
                sensor.DisplayName,
                sourceSystem = sensor.SourceSystem,
                lifecycleSourceSystem = SecuritySourceSystems.SensorLifecycle,
                requestedBy,
                action,
                reasonProvided
            };

        return _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            OccurredAtUtc = occurredAtUtc,
            EventType = SecurityEventType.ExternalEvent,
            Severity = EventSeverity.Info,
            UserName = requestedBy,
            SourceSystem = SecuritySourceSystems.SensorLifecycle,
            ExternalEventType = externalEventType,
            Description = description,
            AdditionalData = additionalData
        }, cancellationToken);
    }

    private static string NormalizeRequestedBy(string requestedBy)
    {
        var normalized = requestedBy?.Trim() ?? string.Empty;
        if (normalized.Length is < 1 or > RequestedByMaxLength || normalized.Any(char.IsControl))
            throw new SensorCredentialLifecycleException($"RequestedBy must contain 1 to {RequestedByMaxLength} printable characters.");
        return normalized;
    }

    private static bool IsReasonProvided(string? reason) => !string.IsNullOrWhiteSpace(reason);
}

public sealed class SensorCredentialLifecycleException : Exception
{
    public SensorCredentialLifecycleException(string message)
        : base(message)
    {
    }
}
