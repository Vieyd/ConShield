using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using ConShield.Application;
using ConShield.Data;
using ConShield.Data.Entities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ConShield.Tests;

[Collection("PostgreSql")]
public sealed class SensorEnrollmentApiTests
{
    private const string SensorSecret = "sensor-test-credential-with-high-entropy-placeholder";
    private const string LegacySecret = "legacy-runtime-test-credential";
    private static readonly Guid SensorId = Guid.Parse("11111111-2222-4333-8444-555555555555");
    private static readonly Guid CredentialId = Guid.Parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");

    [PostgreSqlFact]
    public async Task ValidSensorHeartbeat_UpdatesLastSeenAtUtc()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);
        var before = DateTime.UtcNow;

        var response = await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var sensor = await db.Sensors.SingleAsync();
        Assert.True(sensor.LastSeenAtUtc >= before);
        Assert.True(sensor.UpdatedAtUtc >= before);
    }

    [PostgreSqlFact]
    public async Task Heartbeat_DoesNotCreateSecurityEventAlertOrIncident()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { })).StatusCode);

        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Empty(await db.SecurityEvents.ToListAsync());
        Assert.Empty(await db.SecurityEventOutboxMessages.ToListAsync());
        Assert.Empty(await db.SiemAlerts.ToListAsync());
        Assert.Empty(await db.Incidents.ToListAsync());
    }

    [PostgreSqlFact]
    public async Task RevokedSensorCredential_IsRejected()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory, credentialRevokedAtUtc: DateTime.UtcNow);
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { })).StatusCode);
    }

    [PostgreSqlFact]
    public async Task RevokedSensor_IsRejected()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory, sensorRevokedAtUtc: DateTime.UtcNow);
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { })).StatusCode);
    }

    [PostgreSqlFact]
    public async Task CredentialCannotSpoofAnotherSensorId()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, Guid.NewGuid(), CredentialId, SensorSecret);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { })).StatusCode);
    }

    [PostgreSqlFact]
    public async Task UnknownSensorId_ReturnsUnauthorized()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, Guid.NewGuid(), CredentialId, SensorSecret);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { })).StatusCode);
    }

    [PostgreSqlFact]
    public async Task UnknownCredentialId_ReturnsUnauthorized()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, SensorId, Guid.NewGuid(), SensorSecret);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { })).StatusCode);
    }

    [PostgreSqlFact]
    public async Task SensorSourceSystemMismatch_IsRejected()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", RuntimePayload("different.source"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task RuntimeSource_WithSensorCredential_IsAccepted()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);

        var response = await client.PostAsJsonAsync(
            "/api/v1/security-events",
            RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task RotatedCredential_CannotSubmitRuntimeEvent()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<ISensorCredentialLifecycleService>();
        await service.RotateCredentialAsync(SensorId, "adminib", "test rotation");
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);

        var response = await client.PostAsJsonAsync(
            "/api/v1/security-events",
            RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task NewCredential_CanSubmitRuntimeEvent()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<ISensorCredentialLifecycleService>();
        var rotation = await service.RotateCredentialAsync(SensorId, "adminib", "test rotation");
        using var client = SensorClient(factory, SensorId, rotation.CredentialId, rotation.Credential);

        var response = await client.PostAsJsonAsync(
            "/api/v1/security-events",
            RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task FallbackDisabled_AllowsMissingRuntimeCollectorApiKey()
    {
        await using var factory = await CreateFactoryAsync(allowLegacy: false, runtimeApiKey: null);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/Account/Login");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task FallbackDisabled_SensorBoundRuntimeRequestAccepted()
    {
        await using var factory = await CreateFactoryAsync(allowLegacy: false, runtimeApiKey: null);
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);

        var response = await client.PostAsJsonAsync(
            "/api/v1/security-events",
            RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task RevokedSensorCredential_CannotSubmitSecurityEvent()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory, credentialRevokedAtUtc: DateTime.UtcNow);
        using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);

        var response = await client.PostAsJsonAsync(
            "/api/v1/security-events",
            RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task InvalidSensorCredential_DoesNotFallBackToLegacyKey()
    {
        await using var factory = await CreateFactoryAsync(allowLegacy: true);
        await ProvisionSensorAsync(factory);
        using var client = SensorClient(factory, SensorId, Guid.NewGuid(), LegacySecret);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task LegacyRuntimeCredential_RemainsCompatibleWhenFallbackEnabled()
    {
        await using var factory = await CreateFactoryAsync(allowLegacy: true);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-ConShield-Api-Key", LegacySecret);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task LegacyRuntimeCredential_IsRejectedWhenFallbackDisabled()
    {
        await using var factory = await CreateFactoryAsync(allowLegacy: false, runtimeApiKey: null);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-ConShield-Api-Key", LegacySecret);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task FallbackDisabled_GeneralKeyStillCannotSubmitReservedRuntimeSource()
    {
        await using var factory = await CreateFactoryAsync(allowLegacy: false, runtimeApiKey: null);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-ConShield-Api-Key", "general-test-key");

        var response = await client.PostAsJsonAsync(
            "/api/v1/security-events",
            RuntimePayload("conshield.falco-runtime-collector"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task SensorCredential_IsNotReturnedInResponse()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        const string invalidCredential = "credential-value-that-must-not-be-returned";
        using var client = SensorClient(factory, SensorId, CredentialId, invalidCredential);

        var response = await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { });
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(invalidCredential, body, StringComparison.Ordinal);
    }

    [PostgreSqlFact]
    public async Task ConcurrentHeartbeats_UpdateSingleSensorWithoutErrors()
    {
        await using var factory = await CreateFactoryAsync();
        await ProvisionSensorAsync(factory);
        var tasks = Enumerable.Range(0, 5).Select(async _ =>
        {
            using var client = SensorClient(factory, SensorId, CredentialId, SensorSecret);
            return await client.PostAsJsonAsync("/api/v1/sensors/heartbeat", new { });
        });

        var responses = await Task.WhenAll(tasks);

        Assert.All(responses, x => Assert.Equal(HttpStatusCode.NoContent, x.StatusCode));
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(1, await db.Sensors.CountAsync());
        Assert.NotNull((await db.Sensors.SingleAsync()).LastSeenAtUtc);
    }

    private static async Task<WebApplicationFactory<Program>> CreateFactoryAsync(
        bool allowLegacy = true,
        string? runtimeApiKey = LegacySecret)
    {
        var connectionString = Environment.GetEnvironmentVariable("CONSHIELD_TEST_POSTGRES_CONNECTION")
            ?? throw new InvalidOperationException("CONSHIELD_TEST_POSTGRES_CONNECTION is required.");
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = connectionString,
                    ["ExternalEventIngestion:Enabled"] = "true",
                    ["ExternalEventIngestion:ApiKey"] = "general-test-key",
                    ["ExternalEventIngestion:AllowLegacyRuntimeCollectorCredential"] = allowLegacy.ToString(),
                    ["ExternalEventIngestion:MaxRequestBodyBytes"] = "32768"
                };
                if (runtimeApiKey is not null)
                    values["ExternalEventIngestion:RuntimeCollectorApiKey"] = runtimeApiKey;
                configuration.AddInMemoryCollection(values);
            });
        });
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.MigrateAsync();
        return factory;
    }

    private static async Task ProvisionSensorAsync(
        WebApplicationFactory<Program> factory,
        DateTime? sensorRevokedAtUtc = null,
        DateTime? credentialRevokedAtUtc = null)
    {
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        db.Sensors.Add(new Sensor
        {
            SensorId = SensorId,
            DisplayName = "Test Fedora sensor",
            SourceSystem = "conshield.falco-runtime-collector",
            RevokedAtUtc = sensorRevokedAtUtc,
            Credentials =
            [
                new SensorCredential
                {
                    CredentialId = CredentialId,
                    VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(SensorSecret)),
                    RevokedAtUtc = credentialRevokedAtUtc
                }
            ]
        });
        await db.SaveChangesAsync();
    }

    private static HttpClient SensorClient(
        WebApplicationFactory<Program> factory,
        Guid sensorId,
        Guid credentialId,
        string credential)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-ConShield-Sensor-Id", sensorId.ToString("D"));
        client.DefaultRequestHeaders.Add("X-ConShield-Credential-Id", credentialId.ToString("D"));
        client.DefaultRequestHeaders.Add("X-ConShield-Api-Key", credential);
        return client;
    }

    private static object RuntimePayload(string sourceSystem) => new
    {
        externalEventId = Guid.NewGuid(),
        occurredAtUtc = DateTime.UtcNow,
        sourceSystem,
        eventType = "container.runtime.shell_spawned",
        severity = "High",
        sourceHost = "runtime-node",
        description = "Mapped runtime event.",
        additionalData = new { schemaVersion = 1 }
    };
}
