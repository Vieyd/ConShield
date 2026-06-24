using System.Security.Cryptography;
using System.Text;
using ConShield.Application.Models;
using ConShield.Data;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Application;

public sealed class SensorIdentityService : ISensorIdentityService
{
    private readonly ApplicationDbContext _dbContext;

    public SensorIdentityService(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<AuthenticatedSensorIdentity?> AuthenticateAsync(
        Guid sensorId,
        Guid credentialId,
        string? credential,
        string? requiredSourceSystem,
        CancellationToken cancellationToken = default)
    {
        if (sensorId == Guid.Empty || credentialId == Guid.Empty || string.IsNullOrWhiteSpace(credential))
            return null;

        var match = await _dbContext.SensorCredentials
            .AsNoTracking()
            .Where(x => x.CredentialId == credentialId
                && x.RevokedAtUtc == null
                && x.RotatedAtUtc == null
                && x.Sensor.SensorId == sensorId
                && x.Sensor.RevokedAtUtc == null)
            .Select(x => new
            {
                SensorRecordId = x.Sensor.Id,
                CredentialRecordId = x.Id,
                x.Sensor.SensorId,
                x.CredentialId,
                x.Sensor.SourceSystem,
                x.VerifierSha256
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (match is null
            || match.VerifierSha256.Length != 32
            || (!string.IsNullOrWhiteSpace(requiredSourceSystem)
                && !string.Equals(match.SourceSystem, requiredSourceSystem.Trim(), StringComparison.Ordinal)))
        {
            return null;
        }

        var providedHash = SHA256.HashData(Encoding.UTF8.GetBytes(credential));
        if (!CryptographicOperations.FixedTimeEquals(providedHash, match.VerifierSha256))
            return null;

        return new AuthenticatedSensorIdentity(
            match.SensorRecordId,
            match.CredentialRecordId,
            match.SensorId,
            match.CredentialId,
            match.SourceSystem);
    }

    public async Task<bool> RecordHeartbeatAsync(
        AuthenticatedSensorIdentity identity,
        CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var updated = await _dbContext.Sensors
            .Where(x => x.Id == identity.SensorRecordId
                && x.SensorId == identity.SensorId
                && x.RevokedAtUtc == null
                && x.Credentials.Any(c => c.Id == identity.CredentialRecordId
                    && c.CredentialId == identity.CredentialId
                    && c.RevokedAtUtc == null
                    && c.RotatedAtUtc == null))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.LastSeenAtUtc, now)
                .SetProperty(x => x.UpdatedAtUtc, now), cancellationToken);

        return updated == 1;
    }
}
