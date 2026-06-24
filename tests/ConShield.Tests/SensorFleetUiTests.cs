using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using ConShield.Contracts.Constants;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.Web.Controllers;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class SensorFleetUiTests
{
    [Fact]
    public void SensorsController_IsRestrictedToAdminIB()
    {
        var attribute = typeof(SensorsController).GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(AppRoles.AdminIB, attribute.Roles);
    }

    [Fact]
    public async Task Index_ProjectsSensorMetadataAndCredentialCountsWithoutVerifier()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        await SeedSensorAsync(db, sensorId, nowUtc);

        var result = await new SensorsController(db).Index(CancellationToken.None);
        var view = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<SensorFleetIndexViewModel>(view.Model);
        var sensor = Assert.Single(model.Sensors);

        Assert.Equal(sensorId, sensor.SensorId);
        Assert.Equal("fedora-runtime-01", sensor.DisplayName);
        Assert.Equal(SecuritySourceSystems.FalcoRuntimeCollector, sensor.SourceSystem);
        Assert.Equal("Online", sensor.Status);
        Assert.Equal(2, sensor.CredentialCount);
        Assert.Equal(1, sensor.ActiveCredentialCount);
        Assert.True(sensor.HasCertificateFingerprint);
        Assert.DoesNotContain(
            typeof(SensorFleetItemViewModel).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(null, false, "Never seen")]
    [InlineData(1, false, "Online")]
    [InlineData(4, false, "Warning")]
    [InlineData(6, false, "Offline")]
    [InlineData(1, true, "Revoked")]
    public void CalculateStatus_ReturnsExpectedFleetStatus(int? heartbeatAgeMinutes, bool revoked, string expected)
    {
        var nowUtc = new DateTime(2026, 6, 24, 12, 0, 0, DateTimeKind.Utc);
        var lastSeenAtUtc = heartbeatAgeMinutes is null
            ? (DateTime?)null
            : nowUtc.AddMinutes(-heartbeatAgeMinutes.Value);
        var revokedAtUtc = revoked ? nowUtc.AddMinutes(-1) : (DateTime?)null;

        var (status, _) = SensorFleetItemViewModel.CalculateStatus(lastSeenAtUtc, revokedAtUtc, nowUtc);

        Assert.Equal(expected, status);
    }

    private static async Task SeedSensorAsync(ApplicationDbContext db, Guid sensorId, DateTime nowUtc)
    {
        db.Sensors.Add(new Sensor
        {
            SensorId = sensorId,
            DisplayName = "fedora-runtime-01",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            LastSeenAtUtc = nowUtc.AddSeconds(-30),
            CertificateFingerprintSha256 = new string('a', 64),
            CreatedAtUtc = nowUtc.AddHours(-2),
            UpdatedAtUtc = nowUtc.AddSeconds(-30),
            Credentials =
            [
                new SensorCredential
                {
                    CredentialId = Guid.NewGuid(),
                    CreatedAtUtc = nowUtc.AddHours(-2),
                    VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes("active-test-secret"))
                },
                new SensorCredential
                {
                    CredentialId = Guid.NewGuid(),
                    CreatedAtUtc = nowUtc.AddHours(-3),
                    RevokedAtUtc = nowUtc.AddHours(-1),
                    VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes("revoked-test-secret"))
                }
            ]
        });

        await db.SaveChangesAsync();
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"sensor-fleet-ui-{Guid.NewGuid():N}")
            .Options;
        return new ApplicationDbContext(options);
    }
}
