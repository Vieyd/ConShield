using System.Security.Cryptography;
using System.Text;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace ConShield.Application;

public sealed class SensorProvisioningService : ISensorProvisioningService
{
    public const int CredentialEntropyBytes = 32;
    public const int DisplayNameMaxLength = 128;
    public const int MinimumHeartbeatIntervalSeconds = 15;
    public const int MaximumHeartbeatIntervalSeconds = 3600;

    private readonly ApplicationDbContext _dbContext;

    public SensorProvisioningService(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<SensorProvisioningResult> ProvisionAsync(
        SensorProvisioningRequest request,
        CancellationToken cancellationToken = default)
    {
        var displayName = NormalizeDisplayName(request.DisplayName);
        if (request.HeartbeatIntervalSeconds is < MinimumHeartbeatIntervalSeconds or > MaximumHeartbeatIntervalSeconds)
        {
            throw new SensorProvisioningException(
                $"Heartbeat interval must be between {MinimumHeartbeatIntervalSeconds} and {MaximumHeartbeatIntervalSeconds} seconds.");
        }

        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var duplicate = await _dbContext.Sensors.AnyAsync(
            x => x.SourceSystem == SecuritySourceSystems.FalcoRuntimeCollector
                && x.DisplayName == displayName,
            cancellationToken);
        if (duplicate)
            throw new SensorProvisioningException("A runtime sensor with this display name already exists.");

        var credentialBytes = RandomNumberGenerator.GetBytes(CredentialEntropyBytes);
        var credential = Base64UrlEncode(credentialBytes);
        CryptographicOperations.ZeroMemory(credentialBytes);
        var now = DateTime.UtcNow;
        var sensor = new Sensor
        {
            SensorId = Guid.NewGuid(),
            DisplayName = displayName,
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            Credentials =
            [
                new SensorCredential
                {
                    CredentialId = Guid.NewGuid(),
                    VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(credential)),
                    CreatedAtUtc = now
                }
            ]
        };

        _dbContext.Sensors.Add(sensor);
        await _dbContext.SaveChangesAsync(cancellationToken);
        if (transaction is not null)
            await transaction.CommitAsync(cancellationToken);

        return new SensorProvisioningResult(
            sensor.SensorId,
            sensor.Credentials.Single().CredentialId,
            credential,
            request.HeartbeatIntervalSeconds);
    }

    private async Task<IDbContextTransaction?> BeginTransactionAsync(CancellationToken cancellationToken) =>
        _dbContext.Database.IsRelational()
            ? await _dbContext.Database.BeginTransactionAsync(cancellationToken)
            : null;

    private static string NormalizeDisplayName(string displayName)
    {
        var normalized = displayName?.Trim() ?? string.Empty;
        if (normalized.Length is < 1 or > DisplayNameMaxLength || normalized.Any(char.IsControl))
            throw new SensorProvisioningException($"Display name must contain 1 to {DisplayNameMaxLength} printable characters.");
        return normalized;
    }

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public sealed class SensorProvisioningException : Exception
{
    public SensorProvisioningException(string message)
        : base(message)
    {
    }
}
