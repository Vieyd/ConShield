using ConShield.Application.Models;
using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace ConShield.Application;

public sealed class SensorCredentialLifecycleService : ISensorCredentialLifecycleService
{
    private const int RequestedByMaxLength = 256;
    private readonly ApplicationDbContext _dbContext;

    public SensorCredentialLifecycleService(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<SensorCredentialRotationResult> RotateCredentialAsync(
        Guid sensorId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken = default)
    {
        if (sensorId == Guid.Empty)
            throw new SensorCredentialLifecycleException("Sensor was not found.");

        _ = NormalizeRequestedBy(requestedBy);
        _ = reason?.Trim();

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

    private async Task<IDbContextTransaction?> BeginTransactionAsync(CancellationToken cancellationToken) =>
        _dbContext.Database.IsRelational()
            ? await _dbContext.Database.BeginTransactionAsync(cancellationToken)
            : null;

    private static string NormalizeRequestedBy(string requestedBy)
    {
        var normalized = requestedBy?.Trim() ?? string.Empty;
        if (normalized.Length is < 1 or > RequestedByMaxLength || normalized.Any(char.IsControl))
            throw new SensorCredentialLifecycleException($"RequestedBy must contain 1 to {RequestedByMaxLength} printable characters.");
        return normalized;
    }
}

public sealed class SensorCredentialLifecycleException : Exception
{
    public SensorCredentialLifecycleException(string message)
        : base(message)
    {
    }
}
