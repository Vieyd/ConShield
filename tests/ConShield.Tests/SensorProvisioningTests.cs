using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SensorProvisioning;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class SensorProvisioningTests
{
    [Fact]
    public async Task Provisioning_CreatesSensorAndSensorCredential()
    {
        await using var db = CreateDbContext();
        var service = new SensorProvisioningService(db);

        var result = await service.ProvisionAsync(new SensorProvisioningRequest("fedora-runtime-01"));

        var sensor = await db.Sensors.Include(x => x.Credentials).SingleAsync();
        Assert.Equal(result.SensorId, sensor.SensorId);
        Assert.Equal("fedora-runtime-01", sensor.DisplayName);
        Assert.Equal(SecuritySourceSystems.FalcoRuntimeCollector, sensor.SourceSystem);
        Assert.Equal(result.CredentialId, sensor.Credentials.Single().CredentialId);
        Assert.Null(sensor.RevokedAtUtc);
        Assert.Null(sensor.Credentials.Single().RevokedAtUtc);
    }

    [Fact]
    public async Task Provisioning_StoresVerifierWithoutPlaintextCredential()
    {
        await using var db = CreateDbContext();
        var result = await new SensorProvisioningService(db)
            .ProvisionAsync(new SensorProvisioningRequest("fedora-runtime-01"));
        db.ChangeTracker.Clear();

        var stored = await db.SensorCredentials.SingleAsync();
        var expectedVerifier = SHA256.HashData(Encoding.UTF8.GetBytes(result.Credential));

        Assert.True(CryptographicOperations.FixedTimeEquals(expectedVerifier, stored.VerifierSha256));
        Assert.Equal(SensorProvisioningService.CredentialEntropyBytes, stored.VerifierSha256.Length);
        Assert.DoesNotContain(typeof(SensorCredential).GetProperties(), property => property.PropertyType == typeof(string));
    }

    [Fact]
    public async Task Provisioning_GeneratesAtLeast256BitBase64UrlCredential()
    {
        await using var db = CreateDbContext();
        var result = await new SensorProvisioningService(db)
            .ProvisionAsync(new SensorProvisioningRequest("fedora-runtime-01"));

        Assert.True(Regex.IsMatch(result.Credential, "^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant));
        Assert.Equal(SensorProvisioningService.CredentialEntropyBytes, DecodeBase64Url(result.Credential).Length);
    }

    [Fact]
    public async Task ProvisioningEnvironmentOutput_ContainsOnlyExpectedKeysAndCredentialOnce()
    {
        await using var db = CreateDbContext();
        var result = await new SensorProvisioningService(db)
            .ProvisionAsync(new SensorProvisioningRequest("fedora-runtime-01", 90));

        var lines = ProvisioningEnvironmentOutput.Format(result)
            .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        var keys = lines.Select(line => line.Split('=', 2)[0]).ToArray();

        Assert.Equal(4, lines.Length);
        Assert.Equal(
            [
                "CONSHIELD_SENSOR_ID",
                "CONSHIELD_SENSOR_CREDENTIAL_ID",
                "CONSHIELD_RUNTIME_COLLECTOR_API_KEY",
                "CONSHIELD_HEARTBEAT_INTERVAL_SECONDS"
            ],
            keys);
        Assert.Equal(1, lines.Count(line => line.EndsWith(result.Credential, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Provisioning_DuplicateRuntimeDisplayNameIsRejectedDeterministically()
    {
        await using var db = CreateDbContext();
        var service = new SensorProvisioningService(db);
        await service.ProvisionAsync(new SensorProvisioningRequest("fedora-runtime-01"));

        var exception = await Assert.ThrowsAsync<SensorProvisioningException>(() =>
            service.ProvisionAsync(new SensorProvisioningRequest("  fedora-runtime-01  ")));

        Assert.Equal("A runtime sensor with this display name already exists.", exception.Message);
        Assert.Equal(1, await db.Sensors.CountAsync());
        Assert.Equal(1, await db.SensorCredentials.CountAsync());
    }

    [Theory]
    [InlineData(14)]
    [InlineData(3601)]
    public async Task Provisioning_InvalidHeartbeatIntervalIsRejected(int interval)
    {
        await using var db = CreateDbContext();

        await Assert.ThrowsAsync<SensorProvisioningException>(() =>
            new SensorProvisioningService(db).ProvisionAsync(
                new SensorProvisioningRequest("fedora-runtime-01", interval)));

        Assert.Empty(await db.Sensors.ToListAsync());
    }

    [Fact]
    public void ProvisioningCommand_DoesNotAcceptCredentialArgument()
    {
        var parsed = ProvisioningCommandOptions.Parse(
            ["provision", "--display-name", "fedora-runtime-01", "--credential", "not-accepted"]);

        Assert.False(parsed.IsValid);
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"sensor-provisioning-{Guid.NewGuid():N}")
            .Options;
        return new ApplicationDbContext(options);
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}
