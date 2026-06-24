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

    private static async Task<Guid> SeedSensorAsync(ApplicationDbContext db, DateTime? sensorRevokedAtUtc = null)
    {
        var now = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        db.Sensors.Add(new Sensor
        {
            SensorId = sensorId,
            DisplayName = "fedora-runtime-01",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            RevokedAtUtc = sensorRevokedAtUtc,
            CreatedAtUtc = now.AddMinutes(-10),
            UpdatedAtUtc = now.AddMinutes(-10),
            Credentials =
            [
                new SensorCredential
                {
                    CredentialId = Guid.NewGuid(),
                    CreatedAtUtc = now.AddMinutes(-10),
                    VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(OriginalCredential))
                }
            ]
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
