using System.Security.Cryptography;
using System.Text;
using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class SensorCredentialLifecycleServiceTests
{
    private const string OriginalCredential = "original-sensor-credential-with-high-entropy-placeholder";

    [Fact]
    public async Task RotateCredential_CreatesNewCredentialAndStoresOnlyVerifier()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var service = new SensorCredentialLifecycleService(db);

        var result = await service.RotateCredentialAsync(sensorId, "adminib", "scheduled rotation");

        var credentials = await db.SensorCredentials.OrderBy(x => x.CreatedAtUtc).ToListAsync();
        var newCredential = Assert.Single(credentials, x => x.CredentialId == result.CredentialId);
        var expectedVerifier = SHA256.HashData(Encoding.UTF8.GetBytes(result.Credential));

        Assert.Equal(sensorId, result.SensorId);
        Assert.Equal(SecuritySourceSystems.FalcoRuntimeCollector, result.SourceSystem);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", result.Credential);
        Assert.Equal(32, newCredential.VerifierSha256.Length);
        Assert.True(CryptographicOperations.FixedTimeEquals(expectedVerifier, newCredential.VerifierSha256));
        Assert.DoesNotContain(
            typeof(SensorCredential).GetProperties(),
            property => property.PropertyType == typeof(string));
        Assert.DoesNotContain(
            typeof(ConShield.Application.Models.SensorCredentialRotationResult).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RotateCredential_MarksPreviousActiveCredentialRotated()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var service = new SensorCredentialLifecycleService(db);

        var result = await service.RotateCredentialAsync(sensorId, "adminib", reason: null);

        var credentials = await db.SensorCredentials.OrderBy(x => x.CreatedAtUtc).ToListAsync();
        Assert.Equal(2, credentials.Count);
        Assert.NotNull(credentials.Single(x => x.CredentialId != result.CredentialId).RotatedAtUtc);
        var active = credentials.Single(x => x.CredentialId == result.CredentialId);
        Assert.Null(active.RotatedAtUtc);
        Assert.Null(active.RevokedAtUtc);
        Assert.True((await db.Sensors.SingleAsync()).UpdatedAtUtc >= result.RotatedAtUtc);
    }

    [Fact]
    public async Task RotateCredential_RevokedSensorFails()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db, sensorRevokedAtUtc: DateTime.UtcNow);
        var service = new SensorCredentialLifecycleService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RotateCredentialAsync(sensorId, "adminib", reason: null));

        Assert.Equal(1, await db.SensorCredentials.CountAsync());
    }

    [Fact]
    public async Task RotateCredential_UnknownSensorFails()
    {
        await using var db = CreateDbContext();
        var service = new SensorCredentialLifecycleService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RotateCredentialAsync(Guid.NewGuid(), "adminib", reason: null));

        Assert.Empty(await db.SensorCredentials.ToListAsync());
    }

    [Fact]
    public async Task RevokeCredential_MarksCredentialRevoked()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var credentialId = await db.SensorCredentials.Select(x => x.CredentialId).SingleAsync();
        var service = new SensorCredentialLifecycleService(db);
        var before = DateTime.UtcNow;

        var result = await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", "compromised");

        var credential = await db.SensorCredentials.SingleAsync();
        Assert.Equal(sensorId, result.SensorId);
        Assert.Equal(credentialId, result.CredentialId);
        Assert.False(result.WasAlreadyRevoked);
        Assert.NotNull(credential.RevokedAtUtc);
        Assert.True(credential.RevokedAtUtc >= before);
        Assert.True((await db.Sensors.SingleAsync()).UpdatedAtUtc >= result.RevokedAtUtc);
    }

    [Fact]
    public async Task RevokeCredential_DoesNotDeleteCredential()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var credentialId = await db.SensorCredentials.Select(x => x.CredentialId).SingleAsync();
        var service = new SensorCredentialLifecycleService(db);

        await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", reason: null);
        var second = await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", reason: null);

        Assert.True(second.WasAlreadyRevoked);
        Assert.Equal(1, await db.SensorCredentials.CountAsync());
        Assert.NotNull((await db.SensorCredentials.SingleAsync()).RevokedAtUtc);
    }

    [Fact]
    public async Task RevokeCredential_UnknownSensorFails()
    {
        await using var db = CreateDbContext();
        var service = new SensorCredentialLifecycleService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RevokeCredentialAsync(Guid.NewGuid(), Guid.NewGuid(), "adminib", reason: null));
    }

    [Fact]
    public async Task RevokeCredential_UnknownCredentialFails()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var service = new SensorCredentialLifecycleService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RevokeCredentialAsync(sensorId, Guid.NewGuid(), "adminib", reason: null));

        Assert.Null((await db.SensorCredentials.SingleAsync()).RevokedAtUtc);
    }

    [Fact]
    public async Task RevokeSensor_MarksSensorRevoked()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var service = new SensorCredentialLifecycleService(db);
        var before = DateTime.UtcNow;

        var result = await service.RevokeSensorAsync(sensorId, "adminib", "retired");

        var sensor = await db.Sensors.SingleAsync();
        Assert.Equal(sensorId, result.SensorId);
        Assert.False(result.WasAlreadyRevoked);
        Assert.NotNull(sensor.RevokedAtUtc);
        Assert.True(sensor.RevokedAtUtc >= before);
        Assert.True(sensor.UpdatedAtUtc >= result.RevokedAtUtc);
    }

    [Fact]
    public async Task RevokeSensor_MarksAllCredentialsRevoked()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db, credentialCount: 2);
        var service = new SensorCredentialLifecycleService(db);

        var result = await service.RevokeSensorAsync(sensorId, "adminib", reason: null);
        var second = await service.RevokeSensorAsync(sensorId, "adminib", reason: null);

        Assert.Equal(2, result.RevokedCredentialCount);
        Assert.True(second.WasAlreadyRevoked);
        Assert.Equal(0, second.RevokedCredentialCount);
        Assert.Equal(2, await db.SensorCredentials.CountAsync());
        Assert.All(await db.SensorCredentials.ToArrayAsync(), credential => Assert.NotNull(credential.RevokedAtUtc));
    }

    [Fact]
    public async Task RevokeSensor_UnknownSensorFails()
    {
        await using var db = CreateDbContext();
        var service = new SensorCredentialLifecycleService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RevokeSensorAsync(Guid.NewGuid(), "adminib", reason: null));
    }

    [Fact]
    public void RevocationResultModels_DoNotExposeVerifierOrPlaintextCredential()
    {
        Assert.DoesNotContain(
            typeof(ConShield.Application.Models.SensorCredentialRevocationResult).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase)
                || property.Name.Equals("Credential", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            typeof(ConShield.Application.Models.SensorRevocationResult).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase)
                || property.Name.Equals("Credential", StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<Guid> SeedSensorAsync(
        ApplicationDbContext db,
        DateTime? sensorRevokedAtUtc = null,
        int credentialCount = 1)
    {
        var now = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        var credentials = Enumerable.Range(0, credentialCount)
            .Select(index => new SensorCredential
            {
                CredentialId = Guid.NewGuid(),
                CreatedAtUtc = now.AddMinutes(-10 - index),
                VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes($"{OriginalCredential}-{index}"))
            })
            .ToList();

        db.Sensors.Add(new Sensor
        {
            SensorId = sensorId,
            DisplayName = "fedora-runtime-01",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            RevokedAtUtc = sensorRevokedAtUtc,
            CreatedAtUtc = now.AddMinutes(-10),
            UpdatedAtUtc = now.AddMinutes(-10),
            Credentials = credentials
        });
        await db.SaveChangesAsync();
        return sensorId;
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"sensor-credential-lifecycle-{Guid.NewGuid():N}")
            .Options;
        return new ApplicationDbContext(options);
    }
}
